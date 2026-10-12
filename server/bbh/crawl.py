"""Bounded recon crawl: fetch a page through the sender, follow same-origin,
in-scope, GET links only, skip logout/delete/destructive-shaped links, cap the
number of pages. Every fetch is scope-checked and rate-limited by the sender, and
each response is ingested so endpoints and inputs land in the ledger. Stdlib +
the sender. No forms are submitted; nothing is mutated.
"""

from __future__ import annotations

import re
from urllib.parse import urljoin, urlsplit

from .httpraw import Request
from .ingest import record_exchange
from .planner import plan
from .scope import ScopeError

SKIP_LINK = re.compile(r"(logout|signout|sign-out|logoff|delete|destroy|remove|revoke|cancel|deactivate|/api/|\.(png|jpe?g|gif|svg|ico|css|js|woff2?|ttf|map|pdf|zip|mp4)(\?|$))", re.I)
HREF = re.compile(r"""<a\b[^>]*?\bhref\s*=\s*["']?([^"'\s>]+)""", re.I)


def crawl(ledger, sender, start_url: str, *, max_pages: int = 40, principal: str = "A") -> dict:
    scope = ledger.scope()
    try:
        scope.check_url(start_url)
    except ScopeError as exc:
        return {"ok": False, "error": f"start url refused: {exc}"}
    origin = _origin(start_url)
    seen: set[str] = set()
    queue = [start_url]
    fetched = 0
    new_endpoints: list[int] = []
    opened: dict[str, int] = {}
    errors: list[str] = []
    while queue and fetched < max_pages:
        if ledger.paths.stop_requested():
            errors.append("kill switch set; crawl stopped")
            break
        url = queue.pop(0)
        key = url.split("#", 1)[0]
        if key in seen:
            continue
        seen.add(key)
        try:
            res = sender.send(Request("GET", url, headers=[("Host", urlsplit(url).netloc)]),
                              principal=principal if principal != "unauth" else None, route="sender")
        except ScopeError:
            continue
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {type(exc).__name__}")
            continue
        fetched += 1
        ex = res.exchange
        if ex.response is None:
            continue
        # crawl fetches through the sender, so the request source is "sender" (the
        # requests table CHECK allows burp/sender/browser/import; the endpoint source is
        # "traffic", set inside record_exchange). record_exchange is what creates the
        # endpoint and inputs; the sender has already written its own capture row.
        rid = record_exchange(ledger, ex, source="sender", principal_id=_pid(ledger, principal))
        r = ledger.request(rid)
        if r.get("endpoint_id"):
            pr = plan(ledger, r["endpoint_id"])
            if pr.cell_ids:
                new_endpoints.append(r["endpoint_id"])
            for k, v in pr.opened.items():
                opened[k] = opened.get(k, 0) + v
        if "html" in (ex.response.content_type or ""):
            for href in HREF.findall(ex.body_text):
                nxt = urljoin(url, href)
                if nxt.split("#", 1)[0] in seen or SKIP_LINK.search(nxt):
                    continue
                if _origin(nxt) != origin:
                    continue
                if scope.in_scope(nxt) and nxt not in queue:
                    queue.append(nxt)
    return {"ok": True, "pages_fetched": fetched, "new_endpoints": len(set(new_endpoints)),
            "cells_opened": opened, "queued_remaining": len(queue), "errors": errors[:5]}


def _origin(url: str) -> str:
    p = urlsplit(url)
    return f"{p.scheme}://{p.netloc}"


def _pid(ledger, principal):
    try:
        return ledger.principal(principal)["id"]
    except Exception:  # noqa: BLE001
        return None
