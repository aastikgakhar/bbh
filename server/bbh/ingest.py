"""Ingest observed traffic into endpoints and inputs.

Sources: Burp proxy history (through Burp's own MCP endpoint, SSE), HAR files
exported from a browser (full bodies, the fallback when Burp is down), browser
MCP network logs (metadata only), and the harness's own recon sends.

Burp facts this module is built around (measured, docs/inventory.md 2.1): one
text blob per call of {"request","response","notes"} records separated by blank
lines; every record cut at 5,000 characters with "... (truncated)", which breaks
its JSON; offset 0 is the oldest; "Reached end of items" past the end. Only
in-scope hosts are ever pulled (history regex on Host), so foreign traffic never
reaches the ledger.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

from . import session as sess
from .httpraw import Exchange, Request, Response, parse_request, parse_response, ua_family, write_capture
from .normalise import normalise
from .scope import ScopeError

TRUNC = "... (truncated)"
REQ_MARK = '{"request":"'
RESP_MARK = '","response":"'
NOTES_MARK = '","notes":"'


class IngestError(RuntimeError):
    pass


@dataclass
class IngestReport:
    source: str
    records_seen: int = 0
    in_scope: int = 0
    foreign_skipped: int = 0
    duplicates: int = 0
    truncated: int = 0
    new_endpoints: list[int] = field(default_factory=list)
    new_inputs: list[int] = field(default_factory=list)
    request_ids: list[int] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def summary(self) -> dict:
        return {"source": self.source, "records_seen": self.records_seen, "in_scope": self.in_scope,
                "foreign_skipped": self.foreign_skipped, "duplicates": self.duplicates, "truncated": self.truncated,
                "new_endpoints": len(self.new_endpoints), "new_inputs": len(self.new_inputs), "errors": self.errors[:5]}


# --- Burp record parsing ------------------------------------------------------------------------

def _unescape(s: str) -> str:
    try:
        return json.loads('"' + s + '"')
    except ValueError:
        pass
    out, i = [], 0
    while i < len(s):
        ch = s[i]
        if ch == "\\" and i + 1 < len(s):
            nxt = s[i + 1]
            if nxt == "u" and i + 5 < len(s) and re.match(r"[0-9a-fA-F]{4}", s[i + 2:i + 6]):
                out.append(chr(int(s[i + 2:i + 6], 16)))
                i += 6
                continue
            out.append({"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\", "/": "/", "b": "\b", "f": "\f"}.get(nxt, nxt))
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_records(blob: str) -> list[str]:
    if not blob or blob.startswith("Reached end"):
        return []
    parts = re.split(r"\n\n(?=\{\"request\":\")", blob.strip())
    return [p for p in parts if p.startswith(REQ_MARK)]


def parse_record(rec: str) -> tuple[str, str | None, bool]:
    """Return (raw_request, raw_response_or_None, truncated)."""
    truncated = rec.rstrip().endswith(TRUNC)
    body = rec[len(REQ_MARK):]
    ri = body.find(RESP_MARK)
    if ri == -1:
        req_esc = body[:-len(TRUNC)] if truncated else body
        return _unescape(req_esc.rstrip('"}')), None, True
    req_esc = body[:ri]
    rest = body[ri + len(RESP_MARK):]
    ni = rest.rfind(NOTES_MARK)
    if ni != -1:
        resp_esc = rest[:ni]
    else:
        resp_esc = rest[:-len(TRUNC)] if truncated else rest
        truncated = True
    return _unescape(req_esc), _unescape(resp_esc), truncated


# --- scheme inference ----------------------------------------------------------------------------

def infer_scheme(raw_request: str, scope, host_scheme: dict | None = None) -> str:
    host = ""
    m = re.search(r"^Host:\s*(\S+)", raw_request, re.M | re.I)
    if m:
        host = m.group(1).strip().lower()
    # 1. a same-host Origin/Referer on THIS record reveals the scheme directly
    for hdr in ("Origin", "Referer"):
        mm = re.search(rf"^{hdr}:\s*(https?)://([^/\s]+)", raw_request, re.M | re.I)
        if mm and mm.group(2).lower() == host:
            return mm.group(1).lower()
    # 2. a scheme learned for this host elsewhere in the same ingest batch
    if host_scheme and host in host_scheme:
        return host_scheme[host]
    hostname, _, port = host.partition(":")
    # 3. scope that admits only one scheme for this host
    for scheme in ("https", "http"):
        try:
            scope.check_url(f"{scheme}://{host}/")
        except ScopeError:
            continue
        other = "http" if scheme == "https" else "https"
        try:
            scope.check_url(f"{other}://{host}/")
        except ScopeError:
            return scheme
    if port == "443":
        return "https"
    if port in ("80", "8080", "8000", "5000", "3000") or re.match(r"^(\d+\.){3}\d+$|^localhost$", hostname):
        return "http"
    return "https"


def host_scheme_hints(records: list[tuple[int, str]]) -> dict:
    """Scan a batch of raw records for same-host Origin/Referer lines that reveal each host's
    scheme, so an ambiguous record (e.g. a GET whose Referer is cross-site) still gets it right."""
    hints: dict[str, str] = {}
    for _, rec in records:
        raw = rec
        host_m = re.search(r'"request":"((?:[^"\\]|\\.)*)"', rec)
        raw_req = _unescape(host_m.group(1)) if host_m else rec
        hm = re.search(r"(?:\\r\\n|\r\n|\n)?Host:\s*(\S+)", raw_req, re.I)
        host = hm.group(1).strip().lower() if hm else None
        if not host or host in hints:
            continue
        for hdr in ("Origin", "Referer"):
            mm = re.search(rf"{hdr}:\s*(https?)://{re.escape(host)}\b", raw_req, re.I)
            if mm:
                hints[host] = mm.group(1).lower()
                break
    return hints


def scope_host_regex(scope) -> str | None:
    """A Burp history regex matching the Host header of every in-scope pattern."""
    alts = []
    for p in scope.include:
        if p.network is not None:
            return None  # CIDR scopes cannot be expressed as a Host regex; fetch unfiltered
        host = re.escape(p.host[2:]) if p.host.startswith("*.") else re.escape(p.host)
        prefix = r"[a-z0-9.-]+\." if p.host.startswith("*.") else ""
        port = rf":{p.port}" if p.port else r"(:\d+)?"
        alts.append(prefix + host + port)
    if not alts:
        return None
    # Burp applies this regex to the real message (lines end with a real CR), so terminate on \r.
    # It is only a fast pre-filter; ingest.record_exchange scope-checks every record precisely,
    # so a loose match here can never let an out-of-scope request into the ledger.
    return r"Host: (" + "|".join(alts) + r")(:\d+)?\r"


# --- Burp MCP client ----------------------------------------------------------------------------------

async def _burp_page(url: str, regex: str | None, offset: int, count: int, timeout: float) -> tuple[str, str]:
    from mcp import ClientSession
    from mcp.client.sse import sse_client

    async with sse_client(url, timeout=timeout, sse_read_timeout=max(30.0, timeout)) as (r, w):
        async with ClientSession(r, w) as s:
            info = await s.initialize()
            name = getattr(info.serverInfo, "name", "")
            if name != "burp-suite":
                raise IngestError(f"the MCP server at {url} reports serverInfo.name={name!r}, not 'burp-suite' (port collision?)")
            if regex:
                res = await s.call_tool("get_proxy_http_history_regex", {"count": count, "offset": offset, "regex": regex})
            else:
                res = await s.call_tool("get_proxy_http_history", {"count": count, "offset": offset})
            text = "".join(getattr(c, "text", "") for c in res.content or [])
            return name, text


async def _burp_fetch(url: str, regex: str | None, start: int, max_records: int, page: int, deadline: float) -> list[tuple[int, str]]:
    out: list[tuple[int, str]] = []
    offset = start
    while len(out) < max_records and time.monotonic() < deadline:
        _, text = await _burp_page(url, regex, offset, page, timeout=10.0)
        recs = split_records(text)
        if not recs:
            break
        for rec in recs:
            out.append((offset, rec))
            offset += 1  # advance by records decoded, never by the requested count
    return out


def fetch_burp(url: str, regex: str | None, start: int, *, max_records: int = 500, page: int = 50, budget_s: float = 60.0) -> list[tuple[int, str]]:
    coro = lambda: _burp_fetch(url, regex, start, max_records, page, time.monotonic() + budget_s)
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro())
    # Called from inside a running event loop (the MCP server): run in a private thread with its own loop.
    import concurrent.futures

    def _run():
        return asyncio.new_event_loop().run_until_complete(coro())
    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
        return ex.submit(_run).result(timeout=budget_s + 30)


# --- recording -------------------------------------------------------------------------------------------------

def attribute_principal(ledger, req: Request) -> int | None:
    cookie = req.header("Cookie") or ""
    auth = req.header("Authorization") or ""
    principals = ledger.principals()
    for p in principals:
        if p["kind"] == "unauth" or not p.get("session_file"):
            continue
        material = sess.read(ledger.paths.abs(p["session_file"]))
        for k, v in material:
            if k.lower() == "cookie":
                pairs = [c.strip() for c in v.split(";") if c.strip()]
                if pairs and all(pair in cookie for pair in pairs):
                    return p["id"]
            elif k.lower() == "authorization" and v and v == auth:
                return p["id"]
    if not cookie and not auth:
        return ledger.principal("unauth")["id"]
    fam = ua_family(req.header("User-Agent"))
    if fam:
        for p in principals:
            if p["kind"] == "account" and (p.get("browser") or "").lower().startswith(fam[:4]):
                return p["id"]
    return None


def record_exchange(ledger, ex: Exchange, *, source: str, principal_id: int | None = None, burp_offset: int | None = None,
                    truncated: bool = False, create_endpoints: bool = True, report: IngestReport | None = None) -> int | None:
    report = report or IngestReport(source)
    scope = ledger.scope()
    try:
        scope.check_url(ex.request.url)
    except ScopeError:
        report.foreign_skipped += 1
        return None
    report.in_scope += 1
    raw = ex.request.to_bytes() + b"\n" + (ex.response.to_bytes() if ex.response else b"")
    digest = hashlib.sha256(raw).hexdigest()
    path = ledger.paths.traffic / f"{digest[:20]}.http"
    if not path.exists():
        write_capture(path, ex, {"source": source, "burp_offset": burp_offset, "truncated": truncated,
                                 "scheme": ex.request.url.split("://", 1)[0]})
    if principal_id is None:
        principal_id = attribute_principal(ledger, ex.request)
    rid, created = ledger.add_request(
        source=source, method=ex.request.method, url=ex.request.url, host=ex.request.host,
        raw_path=ledger.paths.rel(path), content_hash=digest, principal_id=principal_id,
        status=ex.status or None, content_type=ex.response.content_type if ex.response else None,
        resp_len=ex.length if ex.response else None, ua_family=ua_family(ex.request.header("User-Agent")),
        truncated=truncated, burp_offset=burp_offset)
    if not created:
        report.duplicates += 1
        return rid
    report.request_ids.append(rid)
    if truncated:
        report.truncated += 1
    if create_endpoints:
        files = sorted(ledger.paths.captures.glob("session-*.txt")) if ledger.paths.captures.exists() else []
        auth_headers = sess.all_auth_header_names(files)
        auth_cookies: set[str] = set()
        for f in files:
            auth_cookies |= sess.cookie_names(sess.read(f))
        n = normalise(ex.request, auth_header_names=auth_headers, auth_cookie_names=auth_cookies)
        if n.flags.get("static_asset"):
            return rid
        eid, new_ep = ledger.upsert_endpoint(origin=n.origin, method=n.method, path_template=n.path_template,
                                             source="traffic", first_seen_request_id=rid, family=n.family,
                                             feature=n.feature, auth_required=n.flags.get("auth_required"),
                                             content_type=n.content_type, flags=n.flags)
        ledger.link_request(rid, eid)
        if new_ep:
            report.new_endpoints.append(eid)
        for spec in n.inputs:
            iid, new_in = ledger.upsert_input(endpoint_id=eid, name=spec.name, location=spec.location,
                                              json_path=spec.json_path, sample_value=spec.sample, value_type=spec.vtype)
            if new_in:
                report.new_inputs.append(iid)
        if ex.response is not None:
            from .planner import scan_canaries

            scan_canaries(ledger, ex, request_id=rid, endpoint_id=eid, principal_id=principal_id)
    return rid


# --- sync entry points ---------------------------------------------------------------------------------------

def sync_burp(ledger, *, max_records: int = 500, budget_s: float = 60.0, fetcher=None) -> IngestReport:
    report = IngestReport("burp")
    eng = ledger.require_configured()
    url = eng.get("burp_mcp_url")
    if not url:
        raise IngestError("Burp MCP is set to none in prompt.md")
    scope = ledger.scope()
    regex = scope_host_regex(scope)
    key = "burp_cursor:" + hashlib.sha1((regex or "*").encode()).hexdigest()[:12]
    cursor = ledger.kv_get(key, {"offset": 0, "last_hash": None}) or {"offset": 0, "last_hash": None}
    fetch = fetcher or fetch_burp
    start = int(cursor.get("offset", 0))
    if start and cursor.get("last_hash"):
        # verify the history was not cleared: the record before the cursor must still match
        probe = fetch(url, regex, start - 1, max_records=1, page=1, budget_s=15)
        if not probe or hashlib.sha1(probe[0][1].encode()).hexdigest() != cursor["last_hash"]:
            report.errors.append("Burp history changed below the cursor (cleared or new project); re-reading from offset 0")
            start = 0
    records = fetch(url, regex, start, max_records=max_records, page=50, budget_s=budget_s)
    scheme_hints = host_scheme_hints(records)
    for offset, rec in records:
        report.records_seen += 1
        try:
            raw_req, raw_resp, truncated = parse_record(rec)
            scheme = infer_scheme(raw_req, scope, scheme_hints)
            req = parse_request(raw_req.encode("utf-8", "surrogateescape"), default_scheme=scheme)
            resp = None
            if raw_resp:
                try:
                    resp = parse_response(raw_resp.encode("utf-8", "surrogateescape"))
                except ValueError:
                    resp = None
            record_exchange(ledger, Exchange(request=req, response=resp), source="burp", burp_offset=offset,
                            truncated=truncated or resp is None, report=report)
        except Exception as exc:  # noqa: BLE001 - one bad record never stops a sync
            report.errors.append(f"offset {offset}: {type(exc).__name__}: {str(exc)[:120]}")
    if records:
        last_off, last_rec = records[-1]
        ledger.kv_set(key, {"offset": last_off + 1, "last_hash": hashlib.sha1(last_rec.encode()).hexdigest()})
    ledger.kv_set("last_ingest", {"ts": time.time(), "source": "burp", **report.summary()})
    if report.new_endpoints or report.new_inputs:
        ledger.event("ingest.sync", "ingest", None, detail=report.summary())
    return report


def ingest_har(ledger, har_path: str | Path) -> IngestReport:
    report = IngestReport("har")
    ledger.require_configured()
    data = json.loads(Path(har_path).read_text(encoding="utf-8", errors="replace"))
    for entry in (data.get("log") or {}).get("entries") or []:
        report.records_seen += 1
        try:
            rq, rs = entry["request"], entry.get("response") or {}
            headers = [(h["name"], h["value"]) for h in rq.get("headers", []) if not h["name"].startswith(":")]
            body = (rq.get("postData") or {}).get("text") or ""
            req = Request(method=rq["method"], url=rq["url"], headers=headers, body=body.encode("utf-8", "replace"),
                          http_version="HTTP/2" if str(rq.get("httpVersion", "")).lower().startswith(("http/2", "h2")) else "HTTP/1.1")
            content = rs.get("content") or {}
            text = content.get("text") or ""
            rbody = base64.b64decode(text) if content.get("encoding") == "base64" else text.encode("utf-8", "replace")
            resp = Response(status=int(rs.get("status") or 0), reason=rs.get("statusText") or "",
                            headers=[(h["name"], h["value"]) for h in rs.get("headers", []) if not h["name"].startswith(":")],
                            body=rbody) if rs.get("status") else None
            record_exchange(ledger, Exchange(request=req, response=resp), source="import", report=report)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"entry {report.records_seen}: {type(exc).__name__}: {str(exc)[:120]}")
    ledger.kv_set("last_ingest", {"ts": time.time(), "source": "har", **report.summary()})
    return report


def ingest_browser_log(ledger, entries: list[dict]) -> IngestReport:
    """Entries from a browser MCP network log: {method, url, request_headers?, request_body?,
    status?, response_headers?, response_body?}. Bodies there are partial at best."""
    report = IngestReport("browser")
    ledger.require_configured()
    for e in entries:
        report.records_seen += 1
        try:
            req = Request(method=str(e.get("method") or "GET").upper(), url=e["url"],
                          headers=list((e.get("request_headers") or {}).items()),
                          body=str(e.get("request_body") or "").encode())
            resp = None
            if e.get("status"):
                resp = Response(status=int(e["status"]), headers=list((e.get("response_headers") or {}).items()),
                                body=str(e.get("response_body") or "").encode())
            record_exchange(ledger, Exchange(request=req, response=resp), source="browser", truncated=True, report=report)
        except Exception as exc:  # noqa: BLE001
            report.errors.append(f"entry {report.records_seen}: {type(exc).__name__}: {str(exc)[:120]}")
    return report
