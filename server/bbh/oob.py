"""Out-of-band callback service for SSRF/XXE confirmation. Stdlib only.

Modes (from prompt.md "OOB callback"):
  none                      -> SSRF/XXE cells are blocked: no_oob_listener
  local <port>              -> a built-in loopback HTTP listener bbh runs itself
  listener <base> <poll>    -> an external listener the researcher runs
  interactsh <server>       -> an interactsh server (polling not implemented here;
                               the researcher polls, or configures a local listener)

oob_url(cell_id, case_no) mints a unique token and returns a URL whose host or
path carries it; oob_check(cell_id) reports interactions seen for that cell's
tokens. The local listener records every request (method, path, remote) to the
ledger's oob_hits so a blind SSRF is confirmed by a real callback, never by a
status code.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def mint_token() -> str:
    tok = secrets.token_hex(6)
    while "bbh" in tok:
        tok = secrets.token_hex(6)
    return tok


def oob_url(ledger, cell_id: int | None, case_no: int | None = None) -> dict:
    eng = ledger.engagement()
    cfg = eng.get("oob") or {"mode": "none"}
    mode = cfg.get("mode")
    if mode in (None, "none", "invalid"):
        return {"configured": False, "reason": "no OOB service is configured; set 'OOB callback' in prompt.md "
                "(e.g. 'local 7731' for the built-in listener). Until then SSRF/XXE cells are blocked: no_oob_listener."}
    if cell_id is not None:
        ledger.cell(cell_id)  # raises LedgerError for a nonexistent or out-of-range cell; no orphan token
    token = mint_token()
    if mode == "listener":
        base = cfg["base"].rstrip("/")
        url = f"{base}/{token}"
    elif mode == "interactsh":
        server = cfg["server"]
        host = urlsplit(server if "://" in server else "https://" + server).hostname or server
        url = f"http://{token}.{host}/"
    else:
        return {"configured": False, "reason": f"OOB mode {mode!r} not understood"}
    ledger.add_oob(token, cell_id, url)
    host = urlsplit(url if "://" in url else "http://" + url).hostname or url
    return {"configured": True, "token": token, "url": url, "host": host, "mode": mode}


def oob_check(ledger, cell_id: int) -> dict:
    try:
        cid = int(cell_id)
    except (TypeError, ValueError):
        cid = None
    if cid is None or not (-(2 ** 63) <= cid <= 2 ** 63 - 1):
        return {"tokens": 0, "hits": [], "received": False}
    tokens = [r["token"] for r in ledger.q("SELECT token FROM oob WHERE cell_id = ?", (cid,))]
    hits = []
    for t in tokens:
        for h in ledger.q("SELECT * FROM oob_hits WHERE token = ? ORDER BY ts", (t,)):
            hits.append({"token": t, "protocol": h["protocol"], "method": h["method"], "remote": h["remote"], "ts": h["ts"]})
    return {"tokens": len(tokens), "hits": hits, "received": bool(hits)}


class _Handler(BaseHTTPRequestHandler):
    ledger = None

    def _record(self):
        try:
            token = self.path.strip("/").split("/", 1)[0].split("?", 1)[0]
            host_token = (self.headers.get("Host", "") or "").split(".", 1)[0]
            tok = token or host_token
            if tok:
                self.ledger.add_oob_hit(tok, protocol="http", method=self.command,
                                        remote=self.client_address[0] if self.client_address else None,
                                        raw=f"{self.command} {self.path} Host:{self.headers.get('Host','')}")
        except Exception:  # noqa: BLE001
            pass
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def do_GET(self):
        self._record()

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", 0) or 0)
            if length:
                self.rfile.read(min(length, 65536))
        except Exception:  # noqa: BLE001
            pass
        self._record()

    do_PUT = do_POST
    do_HEAD = do_GET

    def log_message(self, *a):  # silence
        return


class LocalOOBListener:
    """A loopback HTTP listener the harness can run for SSRF confirmation. Bound to
    127.0.0.1 only; it receives callbacks that the TARGET makes (the target reaches
    the researcher's host, so in a real engagement this is a public listener; the
    built-in one is for the lab and for same-host targets)."""

    def __init__(self, ledger, port: int):
        self.ledger = ledger
        self.port = port
        handler = type("H", (_Handler,), {"ledger": ledger})
        self.server = ThreadingHTTPServer(("127.0.0.1", port), handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def stop(self):
        self.server.shutdown()
        self.server.server_close()
