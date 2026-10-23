"""Parse prompt.md, the per-target brief. Stdlib only.

Only the part above a "# Worked example" heading is read, so the template's
example values can never become real configuration. Values still holding
<placeholders> count as unfilled. Credentials are never stored anywhere.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .scope import Scope, parse_pattern, split_tokens

DEFAULT_RATE = 2.0
MAX_RATE = 50.0
DEFAULT_TESTERS = 2
HARD_CAP_TESTERS = 10
DEFAULT_BURP_PROXY = "127.0.0.1:8080"
DEFAULT_BURP_MCP = "http://127.0.0.1:9876"
DEFAULT_OOB_PORT = 7731
DEFAULT_POC_PORT = 7732
DEFAULT_DASHBOARD_PORT = 7733
# bbh never listens on these (inventory.md Section 4)
RESERVED_PORTS = {8080, 8765, 8766, 9222, *range(9876, 9896)}

_FIELD_RE = re.compile(r"^\s*[-*]\s*\*\*(?P<key>[^*:]+?)\s*:?\s*\*\*\s*:?\s*(?P<value>.*)$")
# Hand-filled briefs often drop the bold: `- Asset: Name`. Accepted as a fallback only.
_PLAIN_FIELD_RE = re.compile(r"^\s*[-*]\s*(?P<key>[A-Za-z][A-Za-z0-9 _/-]{0,40}?)\s*:\s*(?P<value>.*)$")
_STOP_RE = re.compile(r"^#\s+(worked\s+example|example)\b", re.IGNORECASE)
_PLACEHOLDER_RE = re.compile(r"<[^<>]{1,120}>")

# Mail and identity hosts implied by the login method or account domains.
_MAIL_HOSTS = {
    "gmail.com": ["mail.google.com", "accounts.google.com"],
    "googlemail.com": ["mail.google.com", "accounts.google.com"],
    "outlook.com": ["outlook.live.com", "login.live.com"],
    "hotmail.com": ["outlook.live.com", "login.live.com"],
    "live.com": ["outlook.live.com", "login.live.com"],
    "yahoo.com": ["mail.yahoo.com", "login.yahoo.com"],
    "proton.me": ["mail.proton.me", "account.proton.me"],
    "protonmail.com": ["mail.proton.me", "account.proton.me"],
}
_ALWAYS_SUPPORT = ["localhost", "127.0.0.1", "::1", "*.ngrok-free.app", "*.ngrok.app", "*.ngrok.io"]


@dataclass
class Account:
    label: str
    role_text: str
    account: str
    browser: str
    mcp: str


@dataclass
class EngagementConfig:
    target: str | None = None
    scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    out_of_scope_notes: list[str] = field(default_factory=list)
    programme: str | None = None
    marker_header: tuple[str, str] | None = None
    login_method: str | None = None
    login_notes: str | None = None
    accounts: list[Account] = field(default_factory=list)
    rate_limit_rps: float = DEFAULT_RATE
    oob: dict = field(default_factory=lambda: {"mode": "none"})
    burp_proxy: str | None = DEFAULT_BURP_PROXY
    burp_mcp_url: str | None = DEFAULT_BURP_MCP
    max_testers: int = DEFAULT_TESTERS
    support_hosts: list[str] = field(default_factory=list)
    target_notes: str | None = None
    problems: list[str] = field(default_factory=list)
    prompt_hash: str | None = None

    @property
    def configured(self) -> bool:
        return not self.problems

    def scope_obj(self) -> Scope:
        return Scope.from_lists(self.scope, self.out_of_scope, self.out_of_scope_notes)

    def to_json(self) -> dict:
        d = asdict(self)
        d["configured"] = self.configured
        return d


def _clean_value(raw: str) -> str:
    """`value` (guidance) -> value. Prefer the first backticked span."""
    raw = raw.strip()
    ticks = re.findall(r"`([^`]*)`", raw)
    if ticks:
        return ticks[0].strip()
    raw = re.sub(r"\s*\([^()]*\)\s*$", "", raw)  # trailing guidance in parentheses
    return raw.strip()


def _is_placeholder(value: str | None) -> bool:
    if value is None:
        return True
    v = value.strip()
    return not v or bool(_PLACEHOLDER_RE.search(v))


def _sections(text: str) -> list[str]:
    lines = []
    for line in text.splitlines():
        if _STOP_RE.match(line.strip()):
            break
        lines.append(line)
    return lines


def _parse_tables(lines: list[str]) -> list[list[dict]]:
    tables: list[list[dict]] = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("|") and i + 1 < len(lines) and re.match(r"^\|?\s*:?-{2,}", lines[i + 1].strip()):
            header = [c.strip().lower() for c in line.strip("|").split("|")]
            rows = []
            j = i + 2
            while j < len(lines) and lines[j].strip().startswith("|"):
                cells = [c.strip() for c in lines[j].strip().strip("|").split("|")]
                rows.append(dict(zip(header, cells)))
                j += 1
            tables.append(rows)
            i = j
        else:
            i += 1
    return tables


def _label_from_role(role: str) -> str:
    first = re.split(r"[,\s]+", role.strip().strip("`"), maxsplit=1)[0]
    first = re.sub(r"[^A-Za-z0-9_-]", "", first)
    return first or "A"


def parse_prompt_text(text: str) -> EngagementConfig:
    cfg = EngagementConfig()
    cfg.prompt_hash = hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()[:16]
    lines = _sections(text)
    fields: dict[str, str] = {}
    for line in lines:
        m = _FIELD_RE.match(line) or _PLAIN_FIELD_RE.match(line)
        if m:
            key = re.sub(r"\s+", "_", m.group("key").strip().lower())
            fields.setdefault(key, _clean_value(m.group("value")))

    # Target -----------------------------------------------------------------
    asset = fields.get("asset")
    if _is_placeholder(asset):
        cfg.problems.append("Asset is not filled in prompt.md")
    else:
        cfg.target = asset

    scope_v = fields.get("scope")
    if _is_placeholder(scope_v):
        cfg.problems.append("Scope is not filled in prompt.md")
    else:
        tokens = split_tokens(scope_v or "")
        good = [t for t in tokens if parse_pattern(t)]
        bad = [t for t in tokens if not parse_pattern(t)]
        cfg.scope = good
        if not good:
            cfg.problems.append(f"Scope has no machine-readable host pattern: {scope_v!r}")
        if bad:
            cfg.problems.append(f"Scope tokens not understood (fix or remove): {', '.join(bad)}")

    oos_v = fields.get("out_of_scope")
    if oos_v and not _is_placeholder(oos_v) and oos_v.lower() not in {"none", "n/a", "-"}:
        sc = Scope.from_text("", oos_v)
        cfg.out_of_scope = [p.raw for p in sc.exclude]
        cfg.out_of_scope_notes = sc.unparsed_exclude

    prog = fields.get("programme") or fields.get("program")
    if prog and not _is_placeholder(prog):
        cfg.programme = prog.split("|")[0].strip().lower()

    marker = fields.get("marker_header")
    if marker and not _is_placeholder(marker) and marker.strip().lower() not in {"none", "n/a", "-", ""}:
        name, sep, val = marker.partition(":")
        if not sep or not re.match(r"^[A-Za-z0-9-]+$", name.strip()):
            cfg.problems.append(f"Marker header must be 'Name: value' or 'none', got {marker!r}")
        else:
            cfg.marker_header = (name.strip(), val.strip())

    # Login (method and notes only; credentials are never read) --------------
    method = fields.get("method")
    if method and not _is_placeholder(method):
        cfg.login_method = method
    notes = fields.get("notes")
    if notes and not _is_placeholder(notes):
        cfg.login_notes = notes

    # Accounts -----------------------------------------------------------------
    for table in _parse_tables(lines):
        for row in table:
            role = row.get("role", "")
            acct = row.get("account", "")
            if not role or "account" not in row:
                continue
            acct_clean = acct.strip().strip("`")
            if _is_placeholder(acct_clean):
                continue
            label = _label_from_role(role)
            if any(a.label == label for a in cfg.accounts):
                continue
            cfg.accounts.append(
                Account(
                    label=label,
                    role_text=role.strip(),
                    account=acct_clean,
                    browser=row.get("browser", "").strip().strip("`"),
                    mcp=row.get("mcp", "").strip().strip("`"),
                )
            )
    if not cfg.accounts:
        cfg.problems.append("Accounts table has no filled row in prompt.md")

    # Harness fields ---------------------------------------------------------------
    rate = fields.get("rate_limit")
    if rate and not _is_placeholder(rate):
        m = re.search(r"\d+(\.\d+)?", rate)
        if m:
            value = float(m.group(0))
            if value <= 0:
                cfg.problems.append("Rate limit must be > 0")
            else:
                cfg.rate_limit_rps = min(value, MAX_RATE)

    oob = fields.get("oob_callback")
    if oob and not _is_placeholder(oob):
        cfg.oob = parse_oob(oob)
        if cfg.oob.get("mode") == "invalid":
            cfg.problems.append(f"OOB callback not understood: {oob!r}")

    proxy = fields.get("burp_proxy")
    if proxy and not _is_placeholder(proxy):
        cfg.burp_proxy = None if proxy.strip().lower() in {"none", "off", "direct"} else proxy.strip()

    mcp_url = fields.get("burp_mcp")
    if mcp_url and not _is_placeholder(mcp_url):
        cfg.burp_mcp_url = None if mcp_url.strip().lower() in {"none", "off"} else mcp_url.strip()

    testers = fields.get("max_concurrent_testers")
    if testers and not _is_placeholder(testers):
        m = re.search(r"\d+", testers)
        if m:
            cfg.max_testers = max(1, min(HARD_CAP_TESTERS, int(m.group(0))))

    support = fields.get("support_hosts")
    explicit = []
    if support and not _is_placeholder(support) and support.strip().lower() not in {"none", "-"}:
        explicit = split_tokens(support)
    cfg.support_hosts = _derive_support_hosts(cfg, explicit)

    # Free text the agent should see ---------------------------------------------
    m = re.search(r"^##\s+Anything specific to this target\s*$(?P<body>.*?)(^#|\Z)", "\n".join(lines), re.M | re.S)
    if m:
        body = m.group("body").strip()
        if body and not _is_placeholder(body.strip("` \n")) and not body.startswith("---"):
            cfg.target_notes = body[:2000]
    return cfg


def parse_oob(value: str) -> dict:
    v = value.strip()
    low = v.lower()
    if low in {"none", "off", "-", ""}:
        return {"mode": "none"}
    parts = v.split()
    kind = parts[0].lower()
    if kind == "local":
        # 8765/8766 belong to ClaudeCodeBrowser and 9876-9895 to browser-mcp (inventory.md Section 4)
        port = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else DEFAULT_OOB_PORT
        base = f"http://127.0.0.1:{port}"
        return {"mode": "listener", "base": base, "poll": f"{base}/__poll", "local_port": port}
    if kind == "listener" and len(parts) >= 3:
        return {"mode": "listener", "base": parts[1].rstrip("/"), "poll": parts[2]}
    if kind == "interactsh" and len(parts) >= 2:
        return {"mode": "interactsh", "server": parts[1].rstrip("/")}
    return {"mode": "invalid", "raw": v}


def _derive_support_hosts(cfg: EngagementConfig, explicit: list[str]) -> list[str]:
    hosts: list[str] = list(_ALWAYS_SUPPORT)
    if cfg.login_method and "google" in cfg.login_method.lower():
        hosts += ["accounts.google.com", "mail.google.com"]
    for acct in cfg.accounts:
        domain = acct.account.rsplit("@", 1)[-1].lower() if "@" in acct.account else ""
        hosts += _MAIL_HOSTS.get(domain, [])
    hosts += explicit
    out: list[str] = []
    for h in hosts:
        if h not in out:
            out.append(h)
    return out


def load(prompt_path: str | Path) -> EngagementConfig:
    path = Path(prompt_path)
    if not path.exists():
        cfg = EngagementConfig()
        cfg.problems.append(f"{path} does not exist; copy the template and fill the fields at the top")
        return cfg
    return parse_prompt_text(path.read_text(encoding="utf-8", errors="replace"))
