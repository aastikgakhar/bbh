"""The only path to the network for bbh and its agents.

Per send: kill switch -> configured engagement -> scope (checked on the URL as
httpx will parse it) -> Rule 0 lock -> principal session material -> marker
header (only if prompt.md sets one) -> rate limit -> kill switch again -> send
through the Burp proxy -> block detection (inconclusive, never negative) ->
Rule 0 guard (redact before anything is written) -> verbatim capture -> ledger.
"""

from __future__ import annotations

import hashlib
import itertools
import json
import ssl
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import httpx

from . import blocks, guard
from . import session as sess
from .httpraw import Exchange, Request, Response, ua_family, write_capture
from .normalise import normalise
from .ratelimit import MAX_BURST, RateLimiter
from .scope import ScopeError, split_url

_UNSET = object()
_SEQ = itertools.count(1)
HOP_HEADERS = ("Content-Length", "Transfer-Encoding", "Connection", "Keep-Alive", "Proxy-Connection", "TE", "Upgrade",
               "Proxy-Authorization")


class KillSwitchError(RuntimeError):
    pass


class NoSessionError(RuntimeError):
    pass


class LockedError(RuntimeError):
    pass


@dataclass
class SendResult:
    exchange: Exchange
    capture: str | None
    blocked: blocks.BlockVerdict
    guard: guard.GuardResult
    request_id: int | None
    redacted: bool = False
    attempts: int = 1
    extra: dict = field(default_factory=dict)


def _ssl_context() -> ssl.SSLContext:
    try:
        import truststore

        return truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    except Exception:  # noqa: BLE001 - fall back to the default store
        return ssl.create_default_context()


def _supported_encodings() -> set[str]:
    enc = {"gzip", "deflate", "identity"}
    try:
        import brotli  # noqa: F401

        enc.add("br")
    except ImportError:
        try:
            import brotlicffi  # noqa: F401

            enc.add("br")
        except ImportError:
            pass
    try:
        import zstandard  # noqa: F401

        enc.add("zstd")
    except ImportError:
        pass
    return enc


_ENCODINGS = _supported_encodings()


def _transport_error(exc: Exception) -> str:
    """Fixed factual phrases: raw OS messages contain words the hedge check bans."""
    name = type(exc).__name__
    if isinstance(exc, httpx.TimeoutException):
        return f"timeout ({name})"
    if isinstance(exc, httpx.ProxyError):
        return f"proxy refused or failed ({name})"
    if isinstance(exc, httpx.ConnectError):
        return f"connection failed: refused or unreachable ({name})"
    if isinstance(exc, httpx.RemoteProtocolError):
        return f"protocol error ({name})"
    if isinstance(exc, httpx.DecodingError):
        return f"response body decoding failed ({name})"
    if isinstance(exc, httpx.LocalProtocolError):
        return f"request refused by the client before sending, invalid header or line ({name})"
    return f"transport error ({name})"


class Sender:
    def __init__(self, ledger, *, transport: httpx.BaseTransport | None = None, clock=time.time, sleep=time.sleep,
                 proxy=_UNSET):
        self.ledger = ledger
        self.paths = ledger.paths
        eng = ledger.engagement()
        self.limiter = RateLimiter(ledger, float(eng.get("rate_limit_rps") or 2.0), clock=clock, sleep=sleep)
        self.proxy = eng.get("burp_proxy") if proxy is _UNSET else proxy
        self.marker = eng.get("marker_header")
        self._transport = transport
        self._local = threading.local()
        self.clock = clock

    # -- clients --------------------------------------------------------------------------------

    def _client(self, http2: bool) -> httpx.Client:
        key = "h2" if http2 else "h1"
        client = getattr(self._local, key, None)
        if client is None:
            kwargs: dict = dict(follow_redirects=False, http2=http2, trust_env=False,
                                timeout=httpx.Timeout(connect=10.0, read=45.0, write=20.0, pool=10.0))
            if self._transport is not None:
                kwargs["transport"] = self._transport
            else:
                kwargs["verify"] = _ssl_context()
                if self.proxy:
                    kwargs["proxy"] = self.proxy if "://" in self.proxy else f"http://{self.proxy}"
            client = httpx.Client(**kwargs)
            # The headers setter re-adds httpx's defaults (python-httpx User-Agent, Accept,
            # Accept-Encoding, Connection), so delete them from the live map instead: a
            # request carries only what the application itself sent.
            for name in list(client.headers.keys()):
                del client.headers[name]
            setattr(self._local, key, client)
        client.cookies.clear()  # never carry Set-Cookie between sends or principals
        return client

    # -- checks --------------------------------------------------------------------------------------

    def check_kill(self) -> None:
        if self.paths.stop_requested():
            raise KillSwitchError(f"{self.paths.rel(self.paths.stop_file)} exists: every send is refused (kill switch)")

    def check_scope(self, url: str) -> tuple[str, str, int, str]:
        scope = self.ledger.scope()
        scope.check_url(url)  # raises ScopeError
        parsed = split_url(url)
        try:
            hx = httpx.URL(url)
        except Exception as exc:  # noqa: BLE001
            raise ScopeError(f"{url!r} cannot be parsed by the HTTP client ({type(exc).__name__}); refused") from exc
        if (hx.host or "").lower().strip("[]") != parsed[1] or (hx.port or {"http": 80, "https": 443}.get(hx.scheme)) != parsed[2]:
            raise ScopeError(f"{url!r}: the scope parser and the HTTP client disagree about the destination; refused")
        return parsed

    def check_lock(self, req: Request, *, endpoint_id: int | None, vuln_class: str | None) -> None:
        eid = endpoint_id
        if eid is None:
            n = normalise(req)
            row = self.ledger.q1("SELECT id FROM endpoints WHERE origin = ? AND method = ? AND path_template = ?",
                                 (n.origin, n.method, n.path_template))
            eid = row["id"] if row else None
        if eid is None:
            return
        row = self.ledger.q1("SELECT third_party_lock FROM endpoints WHERE id = ?", (eid,))
        if not row or not row["third_party_lock"]:
            return
        params = dict(parse_qsl(urlsplit(req.url).query, keep_blank_values=True))
        if req.content_type.endswith("x-www-form-urlencoded"):
            params.update(dict(parse_qsl(req.body.decode("utf-8", "replace"), keep_blank_values=True)))
        elif "json" in req.content_type:
            try:
                d = json.loads(req.body)
                if isinstance(d, dict):
                    params.update({k: str(v) for k, v in d.items()})
            except ValueError:
                pass
        if vuln_class == "mass_dump" or guard.has_paging(params):
            raise LockedError(
                "Rule 0: this endpoint already returned data outside the test accounts. The harness refuses to page "
                "further or repeat the mass-dump probe. Report the recorded count and proving field; do not widen it.")

    # -- principals ------------------------------------------------------------------------------------

    def _session_files(self) -> list[Path]:
        return sorted(self.paths.captures.glob("session-*.txt")) if self.paths.captures.exists() else []

    def apply_principal(self, req: Request, principal: str | None, *, base_principal: str | None = None) -> None:
        files = self._session_files()
        auth_names = sess.all_auth_header_names(files)
        session_cookie_names: set[str] = set()
        for f in files:
            session_cookie_names |= sess.cookie_names(sess.read(f))
        if principal in (None, "", "unauth"):
            for name in auth_names:
                req.remove_header(name)
            req.remove_header("Cookie")
            return
        p = self.ledger.principal(principal)
        sf = self.paths.abs(p["session_file"]) if p.get("session_file") else self.paths.session_file(principal)
        material = sess.read(sf)
        if not material:
            if base_principal == principal:
                return  # the captured request already carries this principal's material
            raise NoSessionError(
                f"no session material for principal {principal}: write {self.paths.rel(sf)} with Cookie/Authorization "
                f"lines, or call add_principal(label='{principal}', session_from_request_id=<a request made as {principal}>)")
        # keep non-auth cookies from the request, replace every auth cookie and header
        keep = []
        for chunk in (req.header("Cookie") or "").split(";"):
            if "=" in chunk:
                k = chunk.strip().split("=", 1)[0]
                if k not in session_cookie_names:
                    keep.append(chunk.strip())
        for name in auth_names:
            req.remove_header(name)
        cookie_parts = list(keep)
        for k, v in material:
            if k.lower() == "cookie":
                cookie_parts += [c.strip() for c in v.split(";") if c.strip()]
            else:
                req.set_header(k, v)
        if cookie_parts:
            req.set_header("Cookie", "; ".join(cookie_parts))

    # -- send ---------------------------------------------------------------------------------------------

    def _prepare(self, req: Request, principal: str | None, base_principal: str | None) -> Request:
        out = req.copy()
        self.apply_principal(out, principal, base_principal=base_principal)
        if self.marker:
            out.set_header(self.marker[0], self.marker[1])
        for h in HOP_HEADERS:
            out.remove_header(h)
        ae = out.header("Accept-Encoding")
        if ae:
            kept = [p.strip() for p in ae.split(",") if p.strip().split(";")[0].strip().lower() in _ENCODINGS]
            if kept:
                out.set_header("Accept-Encoding", ", ".join(kept))
            else:
                out.remove_header("Accept-Encoding")
        return out

    def _transmit(self, out: Request, http2: bool) -> Exchange:
        client = self._client(http2)
        t0 = time.perf_counter()
        hreq = client.build_request(out.method, out.url, headers=out.headers, content=out.body or None)
        sent = Request(method=hreq.method, url=str(hreq.url),
                       headers=[(k.decode("latin-1"), v.decode("latin-1")) for k, v in hreq.headers.raw],
                       body=out.body or b"", http_version="HTTP/2" if http2 else "HTTP/1.1")
        try:
            resp = client.send(hreq)
            content = resp.content
        except httpx.HTTPError as exc:
            return Exchange(request=sent, response=None, elapsed_ms=int((time.perf_counter() - t0) * 1000), error=_transport_error(exc))
        elapsed = int((time.perf_counter() - t0) * 1000)
        if resp.http_version.upper().startswith("HTTP/2"):
            sent.http_version = "HTTP/2"
        response = Response(status=resp.status_code, reason=resp.reason_phrase or "",
                            headers=[(k.decode("latin-1"), v.decode("latin-1")) for k, v in resp.headers.raw],
                            body=content, http_version=resp.http_version)
        meta = {}
        if resp.headers.get("content-encoding"):
            meta["body_decoded_from"] = resp.headers.get("content-encoding")
        return Exchange(request=sent, response=response, elapsed_ms=elapsed, meta=meta)

    def send(self, req: Request, *, principal: str | None, capture: str | Path | None = None, cell_id: int | None = None,
             case_no: int | None = None, technique: str | None = None, route: str = "sender", meta: dict | None = None,
             endpoint_id: int | None = None, vuln_class: str | None = None, base_principal: str | None = None,
             browser_baseline_status: int | None = None, max_attempts: int = 3) -> SendResult:
        self.check_kill()
        self.ledger.require_configured()
        _, host, _, _ = self.check_scope(req.url)
        self.check_lock(req, endpoint_id=endpoint_id, vuln_class=vuln_class)
        out = self._prepare(req, principal, base_principal)
        http2 = req.http_version.upper().startswith("HTTP/2")
        attempts = 0
        while True:
            attempts += 1
            self.limiter.wait(host)
            self.check_kill()
            ex = self._transmit(out, http2)
            verdict = blocks.detect(ex, browser_baseline_status=browser_baseline_status, http_version_hint=req.http_version)
            if verdict.throttle:
                self.limiter.throttled(host, verdict.retry_after_s)
            else:
                self.limiter.ok(host)
            retryable = verdict.blocked and (ex.status == 429 or (ex.response is None and "reset" in (ex.error or "").lower()))
            if not retryable or attempts >= max_attempts:
                break
        return self._finish(ex, verdict, principal=principal, capture=capture, cell_id=cell_id, case_no=case_no,
                            technique=technique, route=route, meta=meta, endpoint_id=endpoint_id,
                            vuln_class=vuln_class, attempts=attempts)

    def _finish(self, ex: Exchange, verdict, *, principal, capture, cell_id, case_no, technique, route, meta,
                endpoint_id, vuln_class, attempts) -> SendResult:
        known = self.ledger.known_identifiers()
        known_ids = None
        ids = [str(i) for p in self.ledger.principals() for i in p["identifiers"] if str(i).isdigit() or len(str(i)) in (32, 36)]
        if ids:
            known_ids = set(ids)
        if ex.response is not None:
            header_text = "\n".join(f"{k}: {v}" for k, v in ex.response.headers)
            g = guard.scan(ex.body_text, known, known_ids=known_ids, header_text=header_text)
        else:
            g = guard.GuardResult()
        redacted = False
        if g.third_party:
            redacted = True
            scrubbed_headers = [(k, guard.scrub_headers_value(v, known)) for k, v in ex.response.headers
                                if k.lower() not in ("content-length", "content-encoding")]
            ex.response = Response(status=ex.response.status, reason=ex.response.reason,
                                   headers=scrubbed_headers, body=guard.redaction_body(g),
                                   http_version=ex.response.http_version)
            eid = endpoint_id
            if eid is None:
                n = normalise(ex.request)
                row = self.ledger.q1("SELECT id FROM endpoints WHERE origin = ? AND method = ? AND path_template = ?",
                                     (n.origin, n.method, n.path_template))
                eid = row["id"] if row else None
            if eid is not None:  # any third-party hit locks the endpoint (design Section 8)
                self.ledger.lock_third_party(eid, {"count": g.count, "proving_field": g.proving_field, "cell": cell_id})
        cap_path = Path(capture) if capture else self.paths.captures / "_recon" / f"{next(_SEQ):05d}-{ex.request.method}-{ex.request.host or 'host'}.http"
        cap_path = self.paths.abs(cap_path)
        m = {"cell": cell_id, "case_no": case_no, "technique": technique, "principal": principal or "unauth",
             "route": route, "proxy": self.proxy or "direct", "url": ex.request.url,
             "scheme": urlsplit(ex.request.url).scheme, "sent_at": round(self.clock(), 3)}
        if verdict.blocked:
            m["blocked"] = verdict.reason
        if redacted:
            m["redacted"] = g.summary()
        m.update(meta or {})
        write_capture(cap_path, ex, m)
        rel = self.paths.rel(cap_path)
        pid = None
        if principal not in (None, "", "unauth"):
            try:
                pid = self.ledger.principal(principal)["id"]
            except Exception:  # noqa: BLE001
                pid = None
        else:
            pid = self.ledger.principal("unauth")["id"]
        h = hashlib.sha256(cap_path.read_bytes() + str(next(_SEQ)).encode()).hexdigest()
        rid, _ = self.ledger.add_request(
            source="sender", method=ex.request.method, url=ex.request.url, host=ex.request.host, raw_path=rel,
            content_hash=h, principal_id=pid, status=ex.status or None,
            content_type=ex.response.content_type if ex.response else None, resp_len=ex.length,
            ua_family=ua_family(ex.request.header("User-Agent")))
        return SendResult(exchange=ex, capture=rel, blocked=verdict, guard=g, request_id=rid, redacted=redacted,
                          attempts=attempts)

    # -- race bursts -------------------------------------------------------------------------------------

    def send_burst(self, req: Request, *, principal: str | None, n: int, capture_dir: str | Path, cell_id: int | None = None,
                   case_no: int | None = None, technique: str | None = None, endpoint_id: int | None = None,
                   base_principal: str | None = None) -> list[SendResult]:
        """Up to MAX_BURST parallel copies released together. The burst reserves n
        rate-limit slots, so the quiet period that follows repays it."""
        if not 1 <= n <= MAX_BURST:
            raise ValueError(f"burst size must be 1..{MAX_BURST}")
        self.check_kill()
        self.ledger.require_configured()
        _, host, _, _ = self.check_scope(req.url)
        self.check_lock(req, endpoint_id=endpoint_id, vuln_class="race")
        out = self._prepare(req, principal, base_principal)
        http2 = req.http_version.upper().startswith("HTTP/2")
        self.limiter.wait(host, slots=n)
        self.check_kill()
        barrier = threading.Barrier(n)
        results: list[Exchange | None] = [None] * n

        def worker(i: int) -> None:
            client = self._client(http2)
            hreq = client.build_request(out.method, out.url, headers=out.headers, content=out.body or None)
            try:
                barrier.wait(timeout=30)
            except threading.BrokenBarrierError:
                pass
            t0 = time.perf_counter()
            try:
                resp = client.send(hreq)
                content = resp.content
                results[i] = Exchange(request=out, response=Response(status=resp.status_code, reason=resp.reason_phrase or "",
                                      headers=[(k.decode("latin-1"), v.decode("latin-1")) for k, v in resp.headers.raw],
                                      body=content, http_version=resp.http_version),
                                      elapsed_ms=int((time.perf_counter() - t0) * 1000))
            except httpx.HTTPError as exc:
                results[i] = Exchange(request=out, response=None, elapsed_ms=int((time.perf_counter() - t0) * 1000), error=_transport_error(exc))

        threads = [threading.Thread(target=worker, args=(i,), daemon=True) for i in range(n)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=90)
        out_results = []
        cap_dir = self.paths.abs(capture_dir)
        for i, ex in enumerate(results):
            if ex is None:
                ex = Exchange(request=out, response=None, error="burst member did not finish")
            verdict = blocks.detect(ex)
            out_results.append(self._finish(ex, verdict, principal=principal, capture=cap_dir / f"{i:02d}.http", cell_id=cell_id,
                                            case_no=case_no, technique=technique, route="race", meta={"burst_index": i, "burst_size": n},
                                            endpoint_id=endpoint_id, vuln_class="race", attempts=1))
        return out_results
