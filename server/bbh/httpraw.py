"""Raw HTTP requests/responses and the capture file format. Stdlib only.

A capture file holds one exchange, verbatim:

    ### bbh-capture v1
    ### meta {"cell": 12, "case_no": 3, "technique": "...", "principal": "A", "route": "sender", "elapsed_ms": 81, ...}
    ### request
    GET /search?q=x HTTP/1.1
    Host: 127.0.0.1:5057
    ...

    <body bytes>
    ### response
    HTTP/1.1 200 OK
    Content-Type: text/html
    ...

    <body bytes>
    ### end

The "### " marker lines are written with \\n line endings; HTTP sections keep
their own \\r\\n. Bodies are written as raw bytes, so binary content survives.
The file name contains no "bbh" string that reaches the target: it is local only.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, urlunsplit

MARK_START = b"### bbh-capture v1\n"
MARK_META = b"### meta "
MARK_REQ = b"### request\n"
MARK_RESP = b"### response\n"
MARK_END = b"### end\n"


@dataclass
class Request:
    method: str
    url: str  # absolute
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "HTTP/1.1"

    def header(self, name: str, default: str | None = None) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default

    def set_header(self, name: str, value: str) -> None:
        n = name.lower()
        out, done = [], False
        for k, v in self.headers:
            if k.lower() == n:
                if not done:
                    out.append((name if k == name else k, value))
                    done = True
            else:
                out.append((k, v))
        if not done:
            out.append((name, value))
        self.headers = out

    def remove_header(self, name: str) -> None:
        n = name.lower()
        self.headers = [(k, v) for k, v in self.headers if k.lower() != n]

    @property
    def content_type(self) -> str:
        return (self.header("Content-Type") or "").split(";")[0].strip().lower()

    @property
    def path_qs(self) -> str:
        p = urlsplit(self.url)
        return (p.path or "/") + (("?" + p.query) if p.query else "")

    @property
    def host(self) -> str:
        return (urlsplit(self.url).hostname or "").lower()

    @property
    def origin(self) -> str:
        p = urlsplit(self.url)
        return urlunsplit((p.scheme, p.netloc.split("@")[-1], "", "", ""))

    def copy(self) -> "Request":
        return Request(self.method, self.url, list(self.headers), bytes(self.body), self.http_version)

    def to_bytes(self) -> bytes:
        lines = [f"{self.method} {self.path_qs} {self.http_version}"]
        has_host = any(k.lower() == "host" for k, _ in self.headers)
        if not has_host:
            lines.append(f"Host: {urlsplit(self.url).netloc.split('@')[-1]}")
        lines += [f"{k}: {v}" for k, v in self.headers]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + (self.body or b"")


@dataclass
class Response:
    status: int
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: bytes = b""
    http_version: str = "HTTP/1.1"

    def header(self, name: str, default: str | None = None) -> str | None:
        n = name.lower()
        for k, v in self.headers:
            if k.lower() == n:
                return v
        return default

    def headers_all(self, name: str) -> list[str]:
        n = name.lower()
        return [v for k, v in self.headers if k.lower() == n]

    @property
    def text(self) -> str:
        charset = "utf-8"
        m = re.search(r"charset=([\w-]+)", self.header("Content-Type") or "", re.I)
        if m:
            charset = m.group(1)
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def content_type(self) -> str:
        return (self.header("Content-Type") or "").split(";")[0].strip().lower()

    def to_bytes(self) -> bytes:
        lines = [f"{self.http_version} {self.status} {self.reason}".rstrip()]
        lines += [f"{k}: {v}" for k, v in self.headers]
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1", "replace") + (self.body or b"")


@dataclass
class Exchange:
    request: Request
    response: Response | None
    elapsed_ms: int = 0
    error: str | None = None  # transport error text when response is None
    meta: dict = field(default_factory=dict)

    @property
    def status(self) -> int:
        return self.response.status if self.response else 0

    @property
    def body_text(self) -> str:
        return self.response.text if self.response else ""

    @property
    def length(self) -> int:
        return len(self.response.body) if self.response else 0


# --- parsing raw text ------------------------------------------------------------------

def _split_head(raw: bytes) -> tuple[bytes, bytes]:
    for sep in (b"\r\n\r\n", b"\n\n"):
        idx = raw.find(sep)
        if idx != -1:
            return raw[:idx], raw[idx + len(sep):]
    return raw, b""


def _parse_headers(lines: list[str]) -> list[tuple[str, str]]:
    out = []
    for line in lines:
        if not line.strip() or ":" not in line:
            continue
        k, _, v = line.partition(":")
        out.append((k.strip(), v.strip()))
    return out


def parse_request(raw: bytes | str, *, default_scheme: str = "https", host_hint: str | None = None) -> Request:
    """Parse a raw HTTP/1.x request (as Burp shows it) into a Request with an absolute URL."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    head, body = _split_head(raw)
    lines = head.decode("latin-1").replace("\r\n", "\n").split("\n")
    first = lines[0].strip()
    parts = first.split(" ")
    if len(parts) < 2:
        raise ValueError(f"not an HTTP request line: {first[:80]!r}")
    method, target = parts[0].upper(), parts[1]
    version = parts[2] if len(parts) > 2 else "HTTP/1.1"
    headers = _parse_headers(lines[1:])
    host = next((v for k, v in headers if k.lower() == "host"), None) or host_hint or ""
    if target.startswith("http://") or target.startswith("https://"):
        url = target
    else:
        scheme = default_scheme
        if host.endswith(":80"):
            scheme = "http"
        url = f"{scheme}://{host}{target if target.startswith('/') else '/' + target}"
    # HTTP/2 pseudo-headers that Burp sometimes shows as normal headers
    headers = [(k, v) for k, v in headers if not k.startswith(":")]
    return Request(method=method, url=url, headers=headers, body=body, http_version=version)


def parse_response(raw: bytes | str) -> Response:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "surrogateescape")
    head, body = _split_head(raw)
    lines = head.decode("latin-1").replace("\r\n", "\n").split("\n")
    first = lines[0].strip()
    m = re.match(r"^(HTTP/[\d.]+)\s+(\d{3})\s*(.*)$", first)
    if not m:
        raise ValueError(f"not an HTTP status line: {first[:80]!r}")
    headers = _parse_headers(lines[1:])
    te = next((v for k, v in headers if k.lower() == "transfer-encoding"), "")
    if "chunked" in te.lower():
        body = _dechunk(body)
    return Response(status=int(m.group(2)), reason=m.group(3), headers=headers, body=body, http_version=m.group(1))


def _dechunk(body: bytes) -> bytes:
    out, i = bytearray(), 0
    try:
        while i < len(body):
            j = body.index(b"\r\n", i)
            size = int(body[i:j].split(b";")[0], 16)
            if size == 0:
                break
            out += body[j + 2:j + 2 + size]
            i = j + 2 + size + 2
        return bytes(out)
    except (ValueError, IndexError):
        return body


# --- capture files --------------------------------------------------------------------------

def write_capture(path, exchange: Exchange, meta: dict | None = None) -> None:
    from pathlib import Path

    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    m = dict(exchange.meta)
    m.update(meta or {})
    m.setdefault("elapsed_ms", exchange.elapsed_ms)
    if exchange.error:
        m["error"] = exchange.error
    chunks = [MARK_START, MARK_META + json.dumps(m, sort_keys=True, default=str).encode() + b"\n", MARK_REQ,
              exchange.request.to_bytes(), b"\n", MARK_RESP]
    if exchange.response is not None:
        chunks.append(exchange.response.to_bytes())
    else:
        chunks.append(f"[no response: {exchange.error or 'unknown error'}]".encode())
    chunks += [b"\n", MARK_END]
    p.write_bytes(b"".join(chunks))


def read_capture(path) -> Exchange:
    from pathlib import Path

    data = Path(path).read_bytes()
    if not data.startswith(MARK_START):
        raise ValueError(f"{path} is not a bbh capture file")
    meta: dict = {}
    mi = data.find(MARK_META)
    if mi != -1:
        line_end = data.index(b"\n", mi)
        try:
            meta = json.loads(data[mi + len(MARK_META):line_end])
        except ValueError:
            meta = {}
    ri = data.index(MARK_REQ) + len(MARK_REQ)
    si = data.rindex(MARK_RESP)
    ei = data.rindex(MARK_END)
    req_raw = data[ri:si]
    if req_raw.endswith(b"\n"):
        req_raw = req_raw[:-1]
    resp_raw = data[si + len(MARK_RESP):ei]
    if resp_raw.endswith(b"\n"):
        resp_raw = resp_raw[:-1]
    scheme = meta.get("scheme", "https")
    req = parse_request(req_raw, default_scheme=scheme)
    if meta.get("url"):
        req.url = meta["url"]
    resp = None
    if resp_raw and not resp_raw.startswith(b"[no response"):
        try:
            resp = parse_response(resp_raw)
        except ValueError:
            resp = None
    return Exchange(request=req, response=resp, elapsed_ms=int(meta.get("elapsed_ms") or 0),
                    error=meta.get("error"), meta=meta)


def ua_family(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    ua = user_agent
    if "Firefox/" in ua:
        return "firefox"
    if "Edg/" in ua:
        return "edge"
    if "Chrome/" in ua or "Chromium/" in ua:
        return "chrome"
    if "Safari/" in ua:
        return "safari"
    if ua.lower().startswith(("curl/", "python", "wget")):
        return "script"
    return "other"
