"""Private headless browser for cases that need real rendering (XSS execution,
CSTI, DOM XSS, postMessage, cross-site PoCs).

A fresh Chrome/Edge with its own --user-data-dir in temp and an unused
--remote-debugging-port, driven over raw CDP. It NEVER touches the researcher's
real Chrome or Firefox, and it kills only the PID it started. It carries a
principal's session by setting cookies from captures/session-*.txt before
navigating. Records console messages, dialog texts (auto-dismissed), the final
title and body text; those feed browser_marker / browser_text_contains.

If no Chromium-family binary is available the driver reports unavailable and the
case is recorded inconclusive (route requires_browser), never negative.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from . import session as sess

CANDIDATE_BINARIES = [
    os.path.expandvars(r"%LOCALAPPDATA%\ms-playwright\chromium-1224\chrome-win64\chrome.exe"),
    r"C:\Program Files\Google\Chrome\Application\chrome.exe",
    r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
    shutil.which("chromium") or "", shutil.which("google-chrome") or "", shutil.which("chrome") or "",
]


def find_browser() -> str | None:
    env = os.environ.get("BBH_HEADLESS_BROWSER")
    if env and Path(env).exists():
        return env
    for p in CANDIDATE_BINARIES:
        if p and Path(p).exists():
            return p
    return None


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    # avoid the reserved ranges
    from .config import RESERVED_PORTS

    while port in RESERVED_PORTS:
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
    return port


@dataclass
class BrowserResult:
    available: bool
    console: list[str] = field(default_factory=list)
    dialogs: list[str] = field(default_factory=list)
    title: str = ""
    text: str = ""
    final_url: str = ""
    error: str | None = None
    screenshot: str | None = None

    def as_dict(self) -> dict:
        return {"console": self.console, "dialogs": self.dialogs, "title": self.title,
                "text": self.text[:20000], "final_url": self.final_url, "error": self.error}


class _CDP:
    """Minimal CDP client over the DevTools WebSocket (websocket-client)."""

    def __init__(self, ws_url: str):
        import websocket

        self.ws = websocket.create_connection(ws_url, timeout=20)
        self._id = 0

    def send(self, method: str, params: dict | None = None, timeout: float = 20.0) -> dict:
        self._id += 1
        mid = self._id
        self.ws.send(json.dumps({"id": mid, "method": method, "params": params or {}}))
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            self.ws.settimeout(max(0.1, deadline - time.monotonic()))
            try:
                msg = json.loads(self.ws.recv())
            except Exception:  # noqa: BLE001
                break
            if msg.get("id") == mid:
                return msg.get("result", {})
        return {}

    def drain_events(self) -> list[dict]:
        events = []
        self.ws.settimeout(0.2)
        try:
            while True:
                events.append(json.loads(self.ws.recv()))
        except Exception:  # noqa: BLE001
            pass
        return events

    def close(self):
        try:
            self.ws.close()
        except Exception:  # noqa: BLE001
            pass


class Browser:
    def __init__(self, binary: str | None = None):
        self.binary = binary or find_browser()
        self.proc = None
        self.profile = None
        self.port = None

    @property
    def available(self) -> bool:
        return bool(self.binary)

    def __enter__(self):
        if not self.available:
            return self
        self.port = _free_port()
        self.profile = tempfile.mkdtemp(prefix="bbh-headless-")
        args = [self.binary, "--headless=new", f"--remote-debugging-port={self.port}",
                f"--user-data-dir={self.profile}", "--no-first-run", "--no-default-browser-check",
                "--disable-gpu", "--disable-extensions", "--disable-sync", "--no-sandbox",
                "--disable-background-networking", "--window-size=1280,900", "about:blank"]
        self.proc = subprocess.Popen(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self._wait_devtools()
        return self

    def __exit__(self, *exc):
        if self.proc is not None:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=5)
            except Exception:  # noqa: BLE001
                try:
                    self.proc.kill()
                except Exception:  # noqa: BLE001
                    pass
        if self.profile:
            shutil.rmtree(self.profile, ignore_errors=True)

    def _wait_devtools(self, timeout=15):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/version", timeout=1) as r:
                    json.load(r)
                    return True
            except Exception:  # noqa: BLE001
                time.sleep(0.2)
        return False

    def _new_target(self) -> _CDP | None:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/new", timeout=5, data=b"") as r:
                target = json.load(r)
        except Exception:
            try:
                with urllib.request.urlopen(f"http://127.0.0.1:{self.port}/json/list", timeout=5) as r:
                    targets = [t for t in json.load(r) if t.get("type") == "page"]
                target = targets[0] if targets else None
            except Exception:  # noqa: BLE001
                return None
        if not target or not target.get("webSocketDebuggerUrl"):
            return None
        return _CDP(target["webSocketDebuggerUrl"])

    def visit(self, url: str, *, cookies: list[dict] | None = None, fragment: str | None = None,
              messages: list[dict] | None = None, wait_ms: int = 1500) -> BrowserResult:
        if not self.available:
            return BrowserResult(available=False, error="no Chromium-family browser found for the private headless instance")
        cdp = self._new_target()
        if cdp is None:
            return BrowserResult(available=False, error="could not open a CDP target on the private browser")
        res = BrowserResult(available=True)
        try:
            cdp.send("Page.enable")
            cdp.send("Runtime.enable")
            cdp.send("Log.enable")
            cdp.send("Console.enable")
            cdp.send("Network.enable")
            cdp.send("Page.setDownloadBehavior", {"behavior": "deny"})
            # auto-dismiss dialogs (never block the session on a modal)
            cdp.send("Page.setBypassCSP", {"enabled": False})
            if cookies:
                cdp.send("Network.setCookies", {"cookies": cookies})
            target_url = url + (("#" + fragment) if fragment else "")
            cdp.send("Page.navigate", {"url": target_url}, timeout=20)
            time.sleep(min(wait_ms, 8000) / 1000)
            for ev in cdp.drain_events():
                m = ev.get("method")
                p = ev.get("params", {})
                if m == "Runtime.consoleAPICalled":
                    res.console.append(" ".join(str(a.get("value", a.get("description", ""))) for a in p.get("args", [])))
                elif m == "Log.entryAdded":
                    res.console.append(str(p.get("entry", {}).get("text", "")))
                elif m == "Page.javascriptDialogOpening":
                    res.dialogs.append(str(p.get("message", "")))
                    cdp.send("Page.handleJavaScriptDialog", {"accept": True})
            if messages:
                for msg in messages:
                    data = json.dumps(msg.get("data"))
                    origin = json.dumps(msg.get("origin", "*"))
                    cdp.send("Runtime.evaluate", {"expression": f"window.postMessage({data}, {origin})", "awaitPromise": True})
                time.sleep(0.6)
                for ev in cdp.drain_events():
                    if ev.get("method") == "Runtime.consoleAPICalled":
                        res.console.append(" ".join(str(a.get("value", "")) for a in ev["params"].get("args", [])))
                    elif ev.get("method") == "Page.javascriptDialogOpening":
                        res.dialogs.append(str(ev["params"].get("message", "")))
                        cdp.send("Page.handleJavaScriptDialog", {"accept": True})
            res.title = cdp.send("Runtime.evaluate", {"expression": "document.title", "returnByValue": True}).get("result", {}).get("value", "") or ""
            res.text = cdp.send("Runtime.evaluate", {"expression": "document.body ? document.body.innerText : ''", "returnByValue": True}).get("result", {}).get("value", "") or ""
            res.final_url = cdp.send("Runtime.evaluate", {"expression": "location.href", "returnByValue": True}).get("result", {}).get("value", "") or ""
        except Exception as exc:  # noqa: BLE001
            res.error = f"{type(exc).__name__}: {str(exc)[:120]}"
        finally:
            cdp.close()
        return res


def cookies_for(ledger, principal: str, url: str) -> list[dict]:
    """Build a CDP cookie list for a principal from its session file."""
    if principal in (None, "", "unauth"):
        return []
    try:
        p = ledger.principal(principal)
    except Exception:  # noqa: BLE001
        return []
    sf = ledger.paths.abs(p["session_file"]) if p.get("session_file") else None
    out = []
    from urllib.parse import urlsplit

    host = urlsplit(url).hostname or ""
    for k, v in (sess.read(sf) if sf else []):
        if k.lower() == "cookie":
            for chunk in v.split(";"):
                if "=" in chunk:
                    name, _, val = chunk.strip().partition("=")
                    out.append({"name": name, "value": val, "domain": host, "path": "/"})
    return out
