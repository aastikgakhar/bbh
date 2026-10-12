"""Finding verification: replay a finding's assertion from a clean state. Uses the
sender (no cached client, fresh session material re-read from captures/session-*).

A finding becomes verified only after two passing runs at least 60 s apart AND
the verifier agent's sign-off (recorded separately). verify_finding records one
run; it refuses to run the second before 60 s have passed since the first pass.
"""

from __future__ import annotations

import time
from pathlib import Path

from . import evaluate as ev
from .httpraw import Exchange, Request, read_capture
from .ledger import VERIFY_GAP_S
from .sender import Sender


def _request_for_step(ledger, step: dict, base_origin: str) -> Request | None:
    req = step.get("request")
    if not req:
        return None
    if req.get("capture"):
        p = ledger.paths.abs(req["capture"])
        if p.is_file():
            return read_capture(p).request
        return None
    if req.get("same_as_base") and step.get("_base_capture"):
        return read_capture(ledger.paths.abs(step["_base_capture"])).request
    method = req.get("method", "GET")
    url = req["url"] if req.get("url", "").startswith("http") else base_origin.rstrip("/") + "/" + req.get("path", "").lstrip("/")
    headers = list((req.get("headers") or {}).items())
    body = (req.get("body") or "").encode() if isinstance(req.get("body"), str) else (req.get("body") or b"")
    r = Request(method=method, url=url, headers=headers, body=body)
    if req.get("content_type"):
        r.set_header("Content-Type", req["content_type"])
    return r


def verify_finding(ledger, finding_id: int, *, sender: Sender | None = None, now=time.time, browser_factory=None) -> dict:
    f = ledger.finding(finding_id)
    rung = max((r for r in f["rungs"] if r["status"] in ("draft", "verified")), key=lambda r: r["rung_index"], default=None)
    if rung is None:
        return {"ok": False, "error": "finding has no rung to verify"}
    assertion = rung["assertion"]
    # gate: do not run the second attempt before 60 s have passed since the last pass
    vs = ledger.verification_state(finding_id, rung["rung"])
    if vs.get("next_run_not_before") and now() < vs["next_run_not_before"]:
        wait = int(vs["next_run_not_before"] - now())
        return {"ok": False, "waiting": True, "seconds_remaining": wait,
                "detail": f"the previous run passed; the second verification run must be at least {VERIFY_GAP_S}s later (wait {wait}s)"}

    sender = sender or Sender(ledger)  # a fresh sender re-reads session files on every send
    run_no = vs["runs"] + 1
    run_dir = ledger.paths.captures / "verify" / f"finding-{finding_id}" / f"run-{run_no}"
    run_dir.mkdir(parents=True, exist_ok=True)
    started = now()

    base_origin = ""
    first_cap = next((s.get("request", {}).get("capture") for s in assertion.get("steps", []) if s.get("request", {}).get("capture")), None)
    if first_cap and ledger.paths.abs(first_cap).is_file():
        base_origin = read_capture(ledger.paths.abs(first_cap)).request.origin

    ctx = ev.EvalContext(this_case=0)
    step_exchanges: dict[str, Exchange] = {}
    detail_lines = []
    ok_transport = True
    for i, step in enumerate(assertion.get("steps", [])):
        sid = step.get("id", str(i))
        principal = step.get("principal", "A")
        if step.get("browser"):
            browser_factory = browser_factory or _default_browser
            b = browser_factory()
            from .browser import cookies_for

            url = step["browser"].get("url") or (base_origin.rstrip("/") + "/" + str(step["browser"].get("open", "")).lstrip("/"))
            with b as drv:
                if not drv.available:
                    detail_lines.append(f"step {sid}: browser unavailable")
                    ctx.browser = {"error": "browser unavailable"}
                    ok_transport = False
                    continue
                r = drv.visit(url, cookies=cookies_for(ledger, principal, url), wait_ms=step["browser"].get("wait_ms", 1500))
                ctx.browser = r.as_dict()
                detail_lines.append(f"step {sid}: browser visited {url}, title={r.title[:40]!r}")
            continue
        req = _request_for_step(ledger, step, base_origin)
        if req is None:
            detail_lines.append(f"step {sid}: no request could be built")
            ok_transport = False
            continue
        repeats = int(step.get("repeat", 1))
        exchanges = []
        for _ in range(repeats):
            res = sender.send(req, principal=principal, capture=run_dir / f"{sid}.http", route="sender",
                              meta={"verify": finding_id, "run": run_no, "step": sid})
            exchanges.append(res.exchange)
            if res.blocked.blocked:
                ok_transport = False
                detail_lines.append(f"step {sid}: {res.blocked.reason}")
        step_exchanges[sid] = exchanges[0]
        if step.get("counter") or step.get("counter_read"):
            cr = _request_for_step(ledger, {"request": step.get("counter") or step.get("counter_read")}, base_origin)
            if cr is not None:
                crp = (step.get("counter") or step.get("counter_read")).get("principal", principal)
                cres = sender.send(cr, principal=crp, capture=run_dir / f"{sid}-counter.http", route="counter_read")
                ctx.counter = cres.exchange
        # index for conditions: by step id and by position
        ctx.exchanges[i] = exchanges
        ctx.exchanges[sid] = exchanges
    # OOB
    oob_tokens = ledger.q("SELECT token FROM oob WHERE cell_id = ?", (f["cell_id"],))
    if oob_tokens:
        from .oob import oob_check

        hits = oob_check(ledger, f["cell_id"])["hits"]
        ctx.oob_hits = hits

    # evaluate the checks
    results = []
    for i, check in enumerate(assertion.get("checks", [])):
        local = ev.EvalContext(this_case=check.get("step", 0), exchanges=ctx.exchanges, counter=ctx.counter,
                               browser=ctx.browser, oob_hits=ctx.oob_hits, third_party=ctx.third_party)
        r, d = ev.evaluate(check, local)
        results.append((r, d))
        detail_lines.append(f"check {i} ({check.get('type')}): {'PASS' if r else ('INCONCLUSIVE' if r is None else 'FAIL')} - {d}")
    passed = ok_transport and bool(results) and all(r is True for r, _ in results)
    finished = now()
    detail = "; ".join(detail_lines)[:1000]
    ledger.record_verification(finding_id, rung["rung"], passed, detail, ledger.paths.rel(run_dir), started, finished)
    out_vs = ledger.verification_state(finding_id, rung["rung"])
    f2 = ledger.finding(finding_id)
    return {"ok": passed, "rung": rung["rung"], "run": run_no, "detail": detail,
            "runs": out_vs["runs"], "two_passes_60s_apart": out_vs["satisfied"],
            "finding_status": f2["status"], "cell_state": ledger.cell(f["cell_id"])["state"],
            "note": None if passed else "this run did not pass; see detail"}


def _default_browser():
    from .browser import Browser

    return Browser()
