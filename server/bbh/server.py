"""The bbh MCP server. Small, explicit tool surface over the ledger.

The agent works on what next_task() returns. Every tool that changes state goes
through the ledger, which refuses invalid transitions and says what is missing.
Run with: python -m bbh.server  (stdio). The engagement dir is discovered from
BBH_ENGAGEMENT_DIR / CLAUDE_PROJECT_DIR / cwd.
"""

from __future__ import annotations

import importlib
import json
import os
from typing import Any

from mcp.server.fastmcp import FastMCP

from . import codehash, config, render, tasks
from .cases import generate as generate_cases
from .cases.base import Ctx
from .ingest import ingest_har, sync_burp
from .ledger import Ledger, LedgerError
from .paths import Paths
from .planner import plan as plan_endpoint
from .planner import probe_reflection as probe_reflection_impl

# The source fingerprint at import time. status() compares it to a fresh read of disk so a stale
# long-running server (disk edited, or a fresh worker storing plans this process cannot evaluate)
# is visible instead of silently stalling; reload() refreshes both the modules and this value.
_LOADED_FP = codehash.fingerprint()

mcp = FastMCP("bbh", instructions=(
    "bbh is the discipline ledger for this authorized bug bounty engagement. Call status() and next_task() first. "
    "Work on what next_task() returns. Every vuln class on every input is its own verdict; a negative needs 10 "
    "executed cases over 5 techniques plus a control. Reports come from render_report(). The ledger refuses invalid "
    "transitions and tells you exactly what is missing."))

_LEDGER: Ledger | None = None


def L() -> Ledger:
    global _LEDGER
    if _LEDGER is None:
        paths = Paths.discover().ensure()
        _LEDGER = Ledger(paths)
        cfg = config.load(paths.prompt)
        _LEDGER.sync_engagement(cfg)
    return _LEDGER


def _err(exc: Exception) -> dict:
    if isinstance(exc, LedgerError):
        return {"ok": False, "error": str(exc), "missing": exc.missing}
    return {"ok": False, "error": f"{type(exc).__name__}: {exc}"}


def _sender():
    from .sender import Sender
    return Sender(L())


# --- status / tasks ---------------------------------------------------------------------------

@mcp.tool()
def status() -> dict:
    """Coverage counts by state, class and feature; findings by status; depth queue length; the single next task. Compact."""
    try:
        led = L()
        eng = led.engagement()
        counts = led.counts()
        work = tasks.open_work(led)
        nxt = tasks.next_task(led, peek=True)
        disk_fp = codehash.fingerprint()
        stale = disk_fp != _LOADED_FP
        warnings = []
        if stale:
            warnings.append("SERVER CODE IS STALE: the bbh source on disk has changed since this server started. "
                            "It is still running the OLD code. Call reload(), or restart `python -m bbh.server`, "
                            "before trusting any result.")
        su = led.kv_get("stale_code_suspected", None)
        if su:
            warnings.append(f"A plan used a condition this server could not evaluate ({su.get('detail','')[:120]}). "
                            "This is the stale-code symptom; reload() or restart, then re-run those cases.")
        out = {
            "engagement": {"target": eng.get("target"), "configured": eng.get("configured"),
                           "scope": eng.get("scope"), "programme": eng.get("programme"),
                           "rate_limit_rps": eng.get("rate_limit_rps"), "problems": eng.get("problems")},
            "cells": counts["cells"], "cells_total": counts["cells_total"], "findings": counts["findings"],
            "depth": counts["depth"], "endpoints": counts["endpoints"], "inputs": counts["inputs"],
            "requests_seen": counts["requests"], "cases_run": counts["cases"],
            "open_work": work, "kill_switch": led.paths.stop_requested(),
            "code": {"loaded": _LOADED_FP, "disk": disk_fp, "stale": stale},
            "next_task": nxt.to_dict() if nxt else None,
        }
        if warnings:
            out["warnings"] = warnings
        return out
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


_RELOAD_ORDER = [
    "bbh.hedge", "bbh.httpraw", "bbh.normalise", "bbh.scope", "bbh.blocks", "bbh.guard",
    "bbh.evaluate", "bbh.mutate", "bbh.classes", "bbh.assertions",
    "bbh.cases.base", "bbh.cases.authz", "bbh.cases.injection", "bbh.cases.markup", "bbh.cases.files",
    "bbh.cases.misc", "bbh.cases.race", "bbh.cases.redirect", "bbh.cases.ssrf", "bbh.cases.graphql",
    "bbh.cases.csrf", "bbh.cases",
    "bbh.planner", "bbh.runner", "bbh.verify", "bbh.ingest", "bbh.render", "bbh.crawl", "bbh.tasks",
]


@mcp.tool()
def reload() -> dict:
    """Reload the generator/evaluator code from disk WITHOUT restarting the server, so a hand edit or
    a fresh worker's plan no longer runs against stale code. Reports the new fingerprint; if it is
    still stale or any module failed, restart `python -m bbh.server` for a guaranteed clean reset."""
    global _LEDGER, _LOADED_FP, generate_cases, plan_endpoint, probe_reflection_impl, tasks, render, config
    import sys

    reloaded, errors = [], []
    for name in _RELOAD_ORDER:
        mod = sys.modules.get(name)
        if mod is None:
            continue
        try:
            importlib.reload(mod)
            reloaded.append(name)
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{name}: {type(exc).__name__}: {exc}")
    try:
        cases_mod = importlib.import_module("bbh.cases")
        planner_mod = importlib.import_module("bbh.planner")
        generate_cases = cases_mod.generate
        plan_endpoint = planner_mod.plan
        probe_reflection_impl = planner_mod.probe_reflection
        tasks = importlib.import_module("bbh.tasks")
        render = importlib.import_module("bbh.render")
        config = importlib.import_module("bbh.config")
    except Exception as exc:  # noqa: BLE001
        errors.append(f"rebind: {type(exc).__name__}: {exc}")
    _LEDGER = None  # rebuilt by the next L() with the reloaded classes
    _LOADED_FP = codehash.fingerprint()
    try:
        L().kv_set("stale_code_suspected", None)
    except Exception:  # noqa: BLE001
        pass
    disk_fp = codehash.fingerprint()
    stale = disk_fp != _LOADED_FP
    note = ("reloaded; code now matches disk" if not stale and not errors else
            "reload did not fully take — restart `python -m bbh.server` for a clean reset")
    return {"ok": not errors and not stale, "reloaded": reloaded, "errors": errors,
            "code": {"loaded": _LOADED_FP, "disk": disk_fp, "stale": stale}, "note": note}


@mcp.tool()
def chains() -> dict:
    """List the cross-class attack chains currently viable: capabilities from candidate/confirmed
    cells composed with signals seen in traffic (e.g. an open redirect + a token observed in a URL
    = token exfiltration). Each carries the contributing cell ids, any missing precondition, and a
    concrete test plan. Chains are also queued as depth tasks; this is the at-a-glance view."""
    try:
        from . import chains as chain_engine
        led = L()
        return {"ok": True, "chains": chain_engine.detect_chains(led),
                "capabilities": {k: v for k, v in chain_engine.available_capabilities(led).items()}}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def next_task(agent: str = "") -> dict:
    """Claim and return the next unit of work: the cell/finding/depth item, its context, the generated cases, the class recipe excerpt, and the exact completion criteria. Work on THIS, not on what you prefer."""
    try:
        led = L()
        t = tasks.next_task(led, claim_as=agent or None)
        if t is None:
            return {"ok": True, "task": None, "note": "no work; hit the kill switch to stop"}
        out = t.to_dict()
        if t.cell_id is not None:
            out["cases"] = _ensure_plan(led, t.cell_id)
        return {"ok": True, "task": out}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def show(cell_id: int = 0, finding_id: int = 0) -> dict:
    """Show one cell (with its cases, captures and evidence status) or one finding (with its rungs, verifications and triage)."""
    try:
        led = L()
        if finding_id:
            return {"ok": True, "finding": led.finding(finding_id),
                    "triage": [dict(r) for r in led.q("SELECT * FROM triage WHERE finding_id=? ORDER BY round", (finding_id,))]}
        if cell_id:
            return {"ok": True, "cell": led.cell(cell_id), "evidence": led.evidence_status(cell_id),
                    "planned_cases": led.plan_for(cell_id), "cases": led.latest_cases(cell_id)}
        return {"ok": False, "error": "pass cell_id or finding_id"}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --- ingest / plan / recon --------------------------------------------------------------------

@mcp.tool()
def ingest(source: str = "burp", har_path: str = "", max_records: int = 500) -> dict:
    """Pull new traffic into the ledger. source='burp' syncs Burp proxy history (requests + headers; bodies are re-fetched by the sender when needed). source='har' imports a browser HAR export (full bodies). Both only keep in-scope hosts."""
    try:
        led = L()
        if source == "har":
            if not har_path:
                return {"ok": False, "error": "har_path is required for source=har"}
            rep = ingest_har(led, har_path)
        else:
            rep = sync_burp(led, max_records=max_records)
        # plan new endpoints
        opened = {}
        for eid in rep.new_endpoints:
            pr = plan_endpoint(led, eid)
            for k, v in pr.opened.items():
                opened[k] = opened.get(k, 0) + v
        return {"ok": True, "ingest": rep.summary(), "cells_opened": opened}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def plan(endpoint_id: int) -> dict:
    """Open the cells an endpoint's request/response shape calls for (deterministic rules). Idempotent."""
    try:
        pr = plan_endpoint(L(), endpoint_id)
        return {"ok": True, "endpoint_id": endpoint_id, "opened": pr.opened, "cells": pr.cell_ids, "n_a": pr.na}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def probe_reflection(request_id: int) -> dict:
    """Resend a captured request once per input with a unique canary and record every context each canary lands in, then open the reflection-driven cells. One request per input at the engagement rate limit."""
    try:
        return {"ok": True, "contexts": probe_reflection_impl(L(), _sender(), request_id)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def add_endpoint(method: str, url: str, source: str = "guess", feature: str = "", content_type: str = "") -> dict:
    """Add an endpoint found in JS, a spec, or by guessing (one the UI never called). It is scope-checked and then planned."""
    try:
        led = L()
        from urllib.parse import urlsplit
        from .httpraw import Request
        from .normalise import normalise
        p = urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        n = normalise(Request(method=method.upper(), url=url, headers=[("Host", p.netloc)]))
        eid, created = led.upsert_endpoint(origin=n.origin, method=n.method, path_template=n.path_template,
                                           source=source, feature=feature or None,
                                           content_type=content_type or None, flags=n.flags)
        for spec in n.inputs:  # path params and query inputs from the URL
            led.upsert_input(endpoint_id=eid, name=spec.name, location=spec.location, json_path=spec.json_path,
                             sample_value=spec.sample, value_type=spec.vtype)
        pr = plan_endpoint(led, eid)
        return {"ok": True, "endpoint_id": eid, "created": created, "inputs": len(n.inputs), "opened": pr.opened}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def set_feature(endpoint_ids: list[int], feature: str) -> dict:
    """Name the feature a set of endpoints belongs to (groups rows in the matrix)."""
    try:
        return {"ok": True, "updated": L().set_feature(endpoint_ids, feature)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def fetch(url: str, method: str = "GET", principal: str = "A", body: str = "", content_type: str = "") -> dict:
    """Scoped, rate-limited recon fetch through the sender (full body captured, lands in Burp). For reading JS, specs, and endpoints the UI never calls. Not for test cases (use send_case)."""
    try:
        from .httpraw import Request
        req = Request(method=method.upper(), url=url, body=body.encode() if body else b"")
        if content_type:
            req.set_header("Content-Type", content_type)
        res = _sender().send(req, principal=principal if principal != "unauth" else None, route="sender")
        ex = res.exchange
        return {"ok": True, "status": ex.status, "capture": res.capture, "blocked": res.blocked.reason or None,
                "redacted": res.redacted, "length": ex.length, "content_type": ex.response.content_type if ex.response else None,
                "body_preview": ex.body_text[:2000]}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --- case execution ---------------------------------------------------------------------------

def _ensure_plan(led: Ledger, cell_id: int) -> list[dict]:
    existing = led.plan_for(cell_id)
    if existing:
        return existing
    from .runner import build_ctx
    ctx, *_ = build_ctx(led, cell_id)
    cases = generate_cases(ctx, strict=False)
    led.store_plan(cell_id, [c.to_dict() for c in cases])
    return led.plan_for(cell_id)


@mcp.tool()
def crawl(start_url: str, max_pages: int = 40, principal: str = "A") -> dict:
    """Bounded recon crawl from start_url: follow same-origin, in-scope, GET links only (never logout/delete/destructive or static assets), capped at max_pages. Every fetch is scoped, rate-limited and ingested, so endpoints and inputs land in the ledger. Submits no forms."""
    try:
        from .crawl import crawl as do_crawl
        return do_crawl(L(), _sender(), start_url, max_pages=max_pages, principal=principal)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def send_case(cell_id: int, case_no: int, principal: str = "", value: str = "") -> dict:
    """Execute one generated case for a cell through the sender (or the private browser / OOB / counter-read, as the case specifies), evaluate its condition, and record the result. `value` overrides the payload for an ad-hoc probe."""
    try:
        led = L()
        _ensure_plan(led, cell_id)
        from .runner import run_case
        overrides = {"value": value} if value else None
        return {"ok": True, **run_case(led, cell_id, case_no, principal=principal or None, overrides=overrides)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def run_cases(cell_id: int, principal: str = "") -> dict:
    """Execute every generated case for a cell in order (control first), recording each. Returns the per-case outcomes and the resulting cell state. Stops early if the kill switch is set."""
    try:
        led = L()
        plan_cases = _ensure_plan(led, cell_id)
        from .runner import run_case
        out = []
        for pc in plan_cases:
            if led.paths.stop_requested():
                out.append({"case_no": pc["case_no"], "outcome": "skipped", "observation": "kill switch set"})
                break
            try:
                out.append(run_case(led, cell_id, pc["case_no"], principal=principal or None))
            except Exception as exc:  # noqa: BLE001
                out.append({"case_no": pc["case_no"], "outcome": "error", "observation": f"{type(exc).__name__}: {str(exc)[:160]}"})
        return {"ok": True, "cell_id": cell_id, "results": out, "cell_state": led.cell(cell_id)["state"],
                "evidence": led.evidence_status(cell_id)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def record_case(cell_id: int, case_no: int, technique: str, outcome: str, observation: str,
                request_capture: str = "", response_capture: str = "", principal: str = "",
                counter_capture: str = "", route: str = "browser") -> dict:
    """Record a case executed OUTSIDE the sender (through a browser MCP). Provide the saved capture file paths. outcome is positive/negative/inconclusive/control_pass/control_fail; observation states what the response showed, with the filename."""
    try:
        return {"ok": True, **L().record_case(cell_id=cell_id, case_no=case_no, technique=technique, outcome=outcome,
                                               observation=observation, request_capture=request_capture or None,
                                               response_capture=response_capture or None, principal=principal or None,
                                               counter_capture=counter_capture or None, route=route)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --- cell transitions -------------------------------------------------------------------------

@mcp.tool()
def close_cell(cell_id: int, state: str, reason: str = "", reason_request_id: int = 0, unblock: str = "", note: str = "") -> dict:
    """Close a cell: state='negative' (needs the full evidence threshold), 'n_a' (enum reason + a proving request id), or 'blocked' (enum reason + what would unblock it). The ledger lists exactly what is missing if it refuses."""
    try:
        return {"ok": True, "cell": L().close_cell(cell_id, state, reason=reason or None,
                                                   reason_request_id=reason_request_id or None,
                                                   unblock=unblock or None, note=note or None)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def release_cell(cell_id: int, note: str = "") -> dict:
    """Release a claimed cell back to open (e.g. switching tasks). Does not close it."""
    try:
        return {"ok": True, "cell": L().release_cell(cell_id, note or None)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def reopen_cell(cell_id: int, reason: str) -> dict:
    """Reopen a negative/n_a/blocked cell (depth re-test, unblocked, new evidence)."""
    try:
        return {"ok": True, "cell": L().reopen_cell(cell_id, reason)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def set_cell_context(cell_id: int, updates: dict) -> dict:
    """Attach context a case needs, e.g. {"other_object_id": "7"} for an IDOR, {"render_endpoint": "GET /people", "viewer": "B"} for a stored class, or {"limit_exceeded_marker": "..."} for a race."""
    try:
        return {"ok": True, "context": L().update_cell_context(cell_id, updates)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def verifier_signoff(target: str, target_id: int, verdict: str, rationale: str, rung: str = "") -> dict:
    """Verifier-only: record a sign-off. For a candidate cell going negative: target='cell', verdict='refuted'. For a finding: target='finding', verdict='upheld'|'refuted'. Rationale states what in the evidence decided it, with filenames."""
    try:
        return {"ok": True, "result": L().verifier_signoff(target=target, target_id=target_id, verdict=verdict,
                                                           rationale=rationale, rung=rung or None)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --- findings ---------------------------------------------------------------------------------

@mcp.tool()
def open_finding(cell_id: int, rung: str, assertion: dict, title: str, severity: str,
                 summary: str = "", root_cause: str = "", impact: list[str] | None = None) -> dict:
    """Open (or raise) a finding on a candidate/confirmed cell at a ladder rung. The assertion is the machine-checkable proof the harness will replay (see repro/finding-N.json shape). Severity: info/low/medium/high/critical."""
    try:
        return {"ok": True, "finding": L().open_finding(cell_id=cell_id, rung=rung, assertion=assertion, title=title,
                                                        severity=severity, summary=summary or None,
                                                        root_cause=root_cause or None, impact=impact or [])}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def escalation_blocked(finding_id: int, attempted_rung: str, blocked_by: str) -> dict:
    """Record that a higher rung could not be reached, as observed (e.g. 'CSP script-src self blocks inline script; dangling markup confirmed'). Never lowers the confirmed rung."""
    try:
        return {"ok": True, "finding": L().escalation_blocked(finding_id, attempted_rung, blocked_by)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def verify_finding(finding_id: int) -> dict:
    """Replay the finding's assertion from a clean state (fresh session material, no cached client). Two passing runs at least 60 s apart plus the verifier sign-off make it verified."""
    try:
        from .verify import verify_finding as vf
        return vf(L(), finding_id)
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def render_report(finding_id: int) -> dict:
    """Draft report-N.md in the house format from the finding's captures, plus repro/finding-N.sh and repro/finding-N.json. Runs the report lint and returns any problems."""
    try:
        return {"ok": True, **render.render_report(L(), finding_id)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def record_triage(finding_id: int, verdict: str, objection: str = "", required_evidence: str = "") -> dict:
    """Record a triage-gate round. verdict ACCEPT gates the finding; a REJECT must name the exact evidence that would fix it; three REJECTs kill it."""
    try:
        return {"ok": True, "finding": L().record_triage(finding_id, verdict, objection or None, required_evidence or None)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


# --- principals / depth / oob -----------------------------------------------------------------

@mcp.tool()
def add_principal(label: str, kind: str, account: str = "", browser: str = "", identifiers: list[str] | None = None,
                  notes: str = "", session_from_request_id: int = 0) -> dict:
    """Register a principal (kind: account/unauth/role/token/share_link/other). If session_from_request_id is given, its auth headers are written to the principal's session file."""
    try:
        led = L()
        pid = led.add_principal(label, kind, account=account or None, browser=browser or None,
                                identifiers=identifiers or [], notes=notes or None)
        if session_from_request_id:
            from . import session as sess
            from .httpraw import read_capture
            row = led.q1("SELECT raw_path FROM requests WHERE id=?", (session_from_request_id,))
            if row and row["raw_path"] and led.paths.abs(row["raw_path"]).is_file():
                req = read_capture(led.paths.abs(row["raw_path"])).request
                material = sess.from_request_headers(req.headers)
                sess.write(led.paths.session_file(label), material, note=f"from request {session_from_request_id}")
        return {"ok": True, "principal_id": pid, "session_file": led.paths.rel(led.paths.session_file(label))}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def add_depth_item(kind: int, title: str, test_plan: str = "", detail: dict | None = None, source: str = "model") -> dict:
    """Add a depth-queue item (Layer 6). A model hypothesis (source='model') needs a concrete test_plan before it is accepted."""
    try:
        did, created = L().add_depth_item(kind=kind, title=title, test_plan=test_plan or None, detail=detail or {}, source=source)
        return {"ok": True, "depth_id": did, "created": created}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def complete_depth_item(item_id: int, state: str, result: str) -> dict:
    """Mark a depth item done or blocked with a factual result (what was done, what it showed, cells opened)."""
    try:
        return {"ok": True, "item": L().complete_depth_item(item_id, state, result)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def oob_url(cell_id: int, case_no: int = 0) -> dict:
    """Mint a unique out-of-band URL registered to this cell (for SSRF/XXE). Returns {configured:false,...} when no OOB service is set in prompt.md."""
    try:
        from .oob import oob_url as ou
        return {"ok": True, **ou(L(), cell_id, case_no)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def oob_check(cell_id: int) -> dict:
    """Poll the OOB service for interactions on this cell's tokens. No callback, no confirmation."""
    try:
        from .oob import oob_check as oc
        return {"ok": True, **oc(L(), cell_id)}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


@mcp.tool()
def render_views() -> dict:
    """Regenerate state.csv, feature-matrix.md, progress.log and findings-summary.md from the ledger."""
    try:
        return {"ok": True, "views": render.render_views(L())}
    except Exception as exc:  # noqa: BLE001
        return _err(exc)


def main():
    L()  # fail fast if the engagement cannot load
    mcp.run()


if __name__ == "__main__":
    main()
