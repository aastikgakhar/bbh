"""Scope patterns and the scope check. Stdlib only.

Grammar of one pattern (comma or whitespace separated in prompt.md):

    *.example.com            any subdomain of example.com (not the apex)
    example.com              exactly that host, any port
    example.com:8443         that host and port
    https://example.com/app  scheme + host (+ port) + path prefix
    127.0.0.1:5057, [::1]:8000, 10.0.0.0/24 (IP literals and CIDRs)

Matching is by name only, never by DNS resolution. Out-of-scope patterns win
over in-scope ones. URLs whose authority is ambiguous (backslash, whitespace,
control characters, more than one '@') are refused outright, because two
parsers can disagree about where such a URL goes.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit

DEFAULT_PORTS = {"http": 80, "https": 443, "ws": 80, "wss": 443}

_HOST_RE = re.compile(r"^(\*\.)?[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*\.?$")
_BAD_AUTHORITY = re.compile(r"[\\\s\x00-\x1f\x7f]")


class ScopeError(ValueError):
    """Raised when a URL or host is out of scope or cannot be judged safely."""


@dataclass(frozen=True)
class Pattern:
    raw: str
    host: str  # lowercase; may start with "*."; empty when network is set
    port: int | None = None
    scheme: str | None = None
    path_prefix: str | None = None
    network: ipaddress.IPv4Network | ipaddress.IPv6Network | None = None

    def matches(self, scheme: str, host: str, port: int, path: str) -> bool:
        if self.scheme and self.scheme != scheme:
            return False
        if self.port is not None and self.port != port:
            return False
        if self.network is not None:
            try:
                ip = ipaddress.ip_address(host)
            except ValueError:
                return False
            if ip.version != self.network.version or ip not in self.network:
                return False
        elif self.host.startswith("*."):
            base = self.host[2:]
            if not host.endswith("." + base):
                return False
        elif host != self.host:
            return False
        if self.path_prefix:
            prefix = self.path_prefix.rstrip("/")
            if not (path == prefix or path.startswith(prefix + "/") or prefix == ""):
                return False
        return True


def _normalise_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    return host


def parse_pattern(token: str) -> Pattern | None:
    """Parse one scope token. Returns None when it is not machine-readable."""
    raw = token.strip().strip("`").strip()
    if not raw or raw in {"*", "*.*"}:
        return None
    if "://" in raw:
        parts = urlsplit(raw)
        if not parts.hostname:
            return None
        if _BAD_AUTHORITY.search(parts.netloc or ""):
            return None
        host = _normalise_host(parts.hostname)
        try:
            port = parts.port
        except ValueError:
            return None
        scheme = parts.scheme.lower() or None
        path = parts.path or None
        if path in ("", "/"):
            path = None
        return _build(raw, host, port, scheme, path)
    # host[:port] or CIDR or [v6]:port
    try:
        net = ipaddress.ip_network(raw, strict=False)
        if "/" in raw:
            return Pattern(raw=raw, host="", network=net)
    except ValueError:
        pass
    m = re.match(r"^\[([0-9a-fA-F:.]+)\](?::(\d+))?$", raw)
    if m:
        return _build(raw, m.group(1).lower(), int(m.group(2)) if m.group(2) else None, None, None)
    host, port = raw, None
    if raw.count(":") == 1:
        host, _, port_s = raw.partition(":")
        if not port_s.isdigit():
            return None
        port = int(port_s)
    if "/" in host:
        host, _, rest = host.partition("/")
        return _build(raw, _normalise_host(host), port, None, "/" + rest)
    return _build(raw, _normalise_host(host), port, None, None)


def _build(raw: str, host: str, port: int | None, scheme: str | None, path: str | None) -> Pattern | None:
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        is_ip = False
    if not is_ip and not _HOST_RE.match(host):
        return None
    if host.startswith("*.") and host.count(".") < 2:
        # "*.com" style wildcards are too broad to be a real scope
        return None
    return Pattern(raw=raw, host=host, port=port, scheme=scheme, path_prefix=path)


def split_tokens(text: str) -> list[str]:
    return [t for t in re.split(r"[,\s]+", text or "") if t.strip()]


def _hostlike(token: str) -> Pattern | None:
    """A pattern only when the token is unmistakably a host, URL, IP or CIDR
    (has a dot, a scheme, or is an IP), so prose words never become patterns."""
    p = parse_pattern(token)
    if p is None:
        return None
    if p.network is not None or "://" in token or "." in p.host or p.host == "localhost":
        return p
    try:
        ipaddress.ip_address(p.host)
        return p
    except ValueError:
        return None


@dataclass
class Scope:
    include: list[Pattern]
    exclude: list[Pattern]
    unparsed_exclude: list[str]

    @classmethod
    def from_text(cls, scope_text: str, oos_text: str = "") -> "Scope":
        include = [p for p in (parse_pattern(t) for t in split_tokens(scope_text)) if p]
        exclude: list[Pattern] = []
        unparsed: list[str] = []
        # Out-of-scope entries are often prose ("the marketing site"). Tokens that
        # are clearly hosts/URLs/IPs become patterns; any chunk that also holds
        # prose is kept verbatim so the agent sees it in status and next_task.
        for chunk in [c.strip() for c in re.split(r"[,;\n]+", oos_text or "") if c.strip()]:
            tokens = split_tokens(chunk)
            pats = [_hostlike(t) for t in tokens]
            exclude.extend(p for p in pats if p)
            if not all(pats):
                unparsed.append(chunk)
        return cls(include=include, exclude=exclude, unparsed_exclude=unparsed)

    @classmethod
    def from_lists(cls, include: list[str], exclude: list[str] | None = None, unparsed: list[str] | None = None) -> "Scope":
        inc = [p for p in (parse_pattern(t) for t in include) if p]
        exc = [p for p in (parse_pattern(t) for t in (exclude or [])) if p]
        return cls(include=inc, exclude=exc, unparsed_exclude=list(unparsed or []))

    def to_json(self) -> dict:
        return {
            "include": [p.raw for p in self.include],
            "exclude": [p.raw for p in self.exclude],
            "unparsed_exclude": list(self.unparsed_exclude),
        }

    @property
    def empty(self) -> bool:
        return not self.include

    # -- checks ---------------------------------------------------------------

    def check_url(self, url: str) -> None:
        """Raise ScopeError unless `url` is unambiguous and in scope."""
        scheme, host, port, path = split_url(url)
        self._check(scheme, host, port, path, url)

    def check_host(self, host: str, port: int | None = None, scheme: str = "https") -> None:
        host = _normalise_host(host)
        if not host:
            raise ScopeError("empty host")
        p = port if port is not None else DEFAULT_PORTS.get(scheme, 443)
        self._check(scheme, host, p, "/", f"{scheme}://{host}:{p}/")

    def in_scope(self, url: str) -> bool:
        try:
            self.check_url(url)
            return True
        except ScopeError:
            return False

    def _check(self, scheme: str, host: str, port: int, path: str, shown: str) -> None:
        if self.empty:
            raise ScopeError("no in-scope patterns are configured; fill Scope in prompt.md")
        for pat in self.exclude:
            if pat.matches(scheme, host, port, path):
                raise ScopeError(f"{shown} matches out-of-scope pattern {pat.raw!r}")
        for pat in self.include:
            if pat.matches(scheme, host, port, path):
                return
        raise ScopeError(f"{shown} is not in scope ({', '.join(p.raw for p in self.include)})")


def split_url(url: str) -> tuple[str, str, int, str]:
    """Split a URL into (scheme, host, port, path), refusing ambiguous ones."""
    if not isinstance(url, str) or not url:
        raise ScopeError("empty URL")
    if _BAD_AUTHORITY.search(url.split("?", 1)[0].split("#", 1)[0]):
        raise ScopeError(f"{url!r} contains a backslash, whitespace or control character before the query; refused")
    parts = urlsplit(url)
    scheme = (parts.scheme or "").lower()
    if scheme not in DEFAULT_PORTS:
        raise ScopeError(f"{url!r}: scheme {scheme!r} is not http(s)/ws(s)")
    if parts.netloc.count("@") > 1:
        raise ScopeError(f"{url!r}: more than one '@' in the authority; refused")
    host = _normalise_host(parts.hostname or "")
    if not host:
        raise ScopeError(f"{url!r}: no host")
    try:
        port = parts.port or DEFAULT_PORTS[scheme]
    except ValueError as exc:
        raise ScopeError(f"{url!r}: bad port ({exc})") from exc
    return scheme, host, port, parts.path or "/"


def host_of(url: str) -> str | None:
    try:
        return split_url(url)[1]
    except ScopeError:
        return None


def registrable_domain(host: str) -> str:
    """Rough eTLD+1 without a suffix list: last two labels, or three for common
    two-level public suffixes. Used only to spot target-adjacent hosts."""
    host = _normalise_host(host)
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level = {"co.uk", "com.au", "co.jp", "com.br", "co.in", "co.nz", "com.mx", "co.za", "com.sg", "com.tr", "org.uk", "ac.uk", "gov.uk"}
    if ".".join(labels[-2:]) in two_level:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])
