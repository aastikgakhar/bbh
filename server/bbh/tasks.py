"""next_task priority, depth-queue refill, and the stop-gate computation. Stdlib only.

Priority (build spec Layer 7): candidates first, then findings needing
verification/report/triage, then open cells on high-value surfaces, then the
rest of the open cells, then depth items, then a recon refresh. The agent works
on what this returns, not on what it prefers.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field

from . import classes as C

HIGH_VALUE_CLASSES = {c for c, v in C.CLASSES.items() if v.cross_principal}


@dataclass
class Task:
    kind: str                      # candidate | verify | report | triage | cell | depth | recon
    title: str
    detail: dict = field(default_factory=dict)
    cell_id: int | None = None
    finding_id: int | None = None
    depth_id: int | None = None
    priority: int = 0

    def to_dict(self) -> dict:
        d = {"kind": self.kind, "title": self.title, "priority": self.priority}
        for k in ("cell_id", "finding_id", "depth_id"):
            if getattr(self, k) is not None:
                d[k] = getattr(self, k)
        d.update(self.detail)
        return d


def _high_value(ledger, cell: dict) -> int:
    score = cell["priority"]
    if cell["vuln_class"] in HIGH_VALUE_CLASSES:
        score += 15
    try:
        ep = ledger.endpoint(cell["endpoint_id"])
        flags = ep["flags"]
        if flags.get("state_changing"):
            score += 10
        if flags.get("list_endpoint"):
            score += 8
        if not flags.get("auth_required"):
            score += 6  # public/pre-auth surface
    except Exception:  # noqa: BLE001
        pass
    if cell["source"] in ("depth", "model"):
        score += 3
    return score


def open_work(ledger) -> dict:
    """Everything that keeps the session from stopping (stop-gate input)."""
    ledger.expire_claims()
    cells = ledger.q("SELECT COUNT(*) AS n FROM cells WHERE state IN ('open','in_progress')")[0]["n"]
    candidates = ledger.q("SELECT COUNT(*) AS n FROM cells WHERE state='candidate'")[0]["n"]
    unverified = ledger.q("SELECT COUNT(*) AS n FROM findings WHERE status='draft'")[0]["n"]
    verified_no_report = ledger.q("SELECT COUNT(*) AS n FROM findings WHERE status='verified' AND report_path IS NULL")[0]["n"]
    reports_untriaged = ledger.q(
        "SELECT COUNT(*) AS n FROM findings WHERE status='verified' AND report_path IS NOT NULL "
        "AND id NOT IN (SELECT finding_id FROM triage WHERE verdict='ACCEPT')")[0]["n"]
    depth = ledger.q("SELECT COUNT(*) AS n FROM depth_queue WHERE state IN ('open','in_progress')")[0]["n"]
    total = cells + candidates + unverified + verified_no_report + reports_untriaged + depth
    return {"open_cells": cells, "candidates": candidates, "draft_findings": unverified,
            "verified_without_report": verified_no_report, "reports_untriaged": reports_untriaged,
            "open_depth": depth, "total": total}


def next_task(ledger, *, claim_as: str | None = None, peek: bool = False) -> Task | None:
    ledger.expire_claims()

    # 1. candidates: a signal was seen; confirm or refute it first
    row = ledger.q1("SELECT * FROM cells WHERE state='candidate' ORDER BY priority DESC, id LIMIT 1")
    if row:
        c = ledger.cell(row["id"])
        return _finish(ledger, Task("candidate", f"Resolve candidate: {c['vuln_class']} on endpoint {c['endpoint_id']}",
                                     cell_id=c["id"], priority=1000, detail={"vuln_class": c["vuln_class"]}), claim_as, peek)

    # 2a. verified findings without a report
    row = ledger.q1("SELECT id FROM findings WHERE status='verified' AND report_path IS NULL ORDER BY id LIMIT 1")
    if row:
        return Task("report", f"Render the report for finding {row['id']}", finding_id=row["id"], priority=950)
    # 2b. draft findings needing verification
    row = ledger.q1("SELECT id FROM findings WHERE status='draft' ORDER BY id LIMIT 1")
    if row:
        return Task("verify", f"Verify finding {row['id']} (two clean replays 60 s apart + verifier sign-off)",
                    finding_id=row["id"], priority=940)
    # 2c. reports not through triage
    row = ledger.q1("SELECT id FROM findings WHERE status='verified' AND report_path IS NOT NULL "
                    "AND id NOT IN (SELECT finding_id FROM triage WHERE verdict='ACCEPT') ORDER BY id LIMIT 1")
    if row:
        return Task("triage", f"Run triage-gate on finding {row['id']}'s report", finding_id=row["id"], priority=930)

    # 3+4. open cells, highest-value first
    best = None
    best_score = -1
    for row in ledger.q("SELECT * FROM cells WHERE state='open' ORDER BY id"):
        c = ledger.cell(row["id"])
        score = _high_value(ledger, c)
        if score > best_score:
            best, best_score = c, score
    if best:
        return _finish(ledger, Task("cell", f"Test {best['vuln_class']} on endpoint {best['endpoint_id']}"
                                    + (f" input {best['input_id']}" if best["input_id"] else ""),
                                    cell_id=best["id"], priority=best_score, detail={"vuln_class": best["vuln_class"]}), claim_as, peek)

    # 5. depth items
    refill_depth(ledger)
    row = ledger.q1("SELECT * FROM depth_queue WHERE state='open' ORDER BY kind, id LIMIT 1")
    if row:
        d = ledger.depth_item(row["id"])
        t = Task("depth", f"Depth {d['kind']}: {d['title']}", depth_id=d["id"], priority=200, detail={"test_plan": d.get("test_plan")})
        if claim_as and not peek:
            ledger.claim_depth(d["id"], claim_as)
        return t

    # 6. recon refresh (the app changes; the researcher browses in parallel)
    return Task("recon", "Re-sync Burp, re-read new JS/hosts, and plan any new endpoints (recon refresh)", priority=10,
                detail={"note": "base and depth work are exhausted; refresh recon or hit the kill switch to stop"})


def _finish(ledger, task: Task, claim_as, peek) -> Task:
    if claim_as and not peek and task.cell_id is not None:
        try:
            ledger.claim_cell(task.cell_id, claim_as)
        except Exception:  # noqa: BLE001 - a lost claim just means the agent re-reads
            pass
    # attach the recipe anchor and completion criteria for the agent
    if task.cell_id is not None:
        c = ledger.cell(task.cell_id)
        vc = C.get(c["vuln_class"])
        ev = ledger.evidence_status(task.cell_id)
        task.detail["recipe_section"] = C.RECIPES.get(vc.recipe, vc.recipe)
        task.detail["completion"] = {
            "to_close_negative": ev["missing"] or ["evidence threshold already met; close_cell negative, or open a finding if a case went positive"],
            "min_cases": ev["requirements"]["min_cases"],
            "min_techniques": ev["requirements"]["min_techniques"],
            "required_families": ev["requirements"]["required_families"],
            "ladder": list(vc.ladder),
            "min_reportable_rung": vc.min_rung,
        }
    return task


# --- Layer 6: depth queue -------------------------------------------------------------------

def refill_depth(ledger) -> int:
    """Add depth items in the build-spec order. Each is deduplicated; returns how many added."""
    added = 0
    added += _depth_untouched_js_endpoints(ledger)
    added += _depth_other_principals(ledger)
    added += _depth_alt_versions(ledger)
    added += _depth_second_order(ledger)
    added += _depth_chains(ledger)
    added += _depth_retest_inconclusive(ledger)
    return added


def _add(ledger, kind, title, detail, key, source="rule", test_plan=None):
    _, created = ledger.add_depth_item(kind=kind, title=title, detail=detail, source=source, test_plan=test_plan, dedupe_key=key)
    return 1 if created else 0


def _depth_untouched_js_endpoints(ledger) -> int:
    n = 0
    for row in ledger.q("SELECT id, method, path_template, source FROM endpoints WHERE source IN ('js','spec','guess') "
                        "AND id NOT IN (SELECT DISTINCT endpoint_id FROM requests WHERE endpoint_id IS NOT NULL)"):
        n += _add(ledger, 1, f"Call {row['method']} {row['path_template']} (found in {row['source']}, never called by the UI)",
                  {"endpoint_id": row["id"]}, f"js_endpoint:{row['id']}")
    return n


def _depth_other_principals(ledger) -> int:
    n = 0
    principals = [p["label"] for p in ledger.principals()]
    for row in ledger.q("SELECT id, method, path_template FROM endpoints WHERE auth_required = 1 ORDER BY id LIMIT 200"):
        n += _add(ledger, 2, f"Replay {row['method']} {row['path_template']} as every other principal ({', '.join(principals)})",
                  {"endpoint_id": row["id"], "principals": principals}, f"other_principals:{row['id']}")
    return n


def _depth_alt_versions(ledger) -> int:
    n = 0
    import re
    for row in ledger.q("SELECT id, origin, method, path_template FROM endpoints"):
        m = re.search(r"/v(\d+)/", row["path_template"])
        if m:
            cur = int(m.group(1))
            for other in (cur - 1, cur + 1):
                if other < 1:
                    continue
                alt = row["path_template"].replace(f"/v{cur}/", f"/v{other}/", 1)
                n += _add(ledger, 3, f"Try {row['method']} {alt} (version pivot from v{cur})",
                          {"origin": row["origin"], "method": row["method"], "path_template": alt},
                          f"altver:{row['origin']}:{row['method']}:{alt}")
    return n


def _depth_second_order(ledger) -> int:
    """Pair every store endpoint (state-changing, with text inputs) with every render/query
    endpoint of the same object type, with canaries."""
    n = 0
    stores = ledger.q("SELECT DISTINCT e.id, e.feature FROM endpoints e JOIN inputs i ON i.endpoint_id = e.id "
                      "WHERE i.location IN ('json','form','multipart') AND e.method != 'GET'")
    renders = ledger.q("SELECT id, feature FROM endpoints WHERE method = 'GET'")
    for st in stores:
        for rd in renders:
            if st["id"] == rd["id"]:
                continue
            if st["feature"] and rd["feature"] and st["feature"] == rd["feature"]:
                n += _add(ledger, 4, f"Second-order: store via endpoint {st['id']} ({st['feature']}), read back via endpoint {rd['id']}",
                          {"store_endpoint": st["id"], "render_endpoint": rd["id"], "feature": st["feature"]},
                          f"second_order:{st['id']}:{rd['id']}")
    return n


def _depth_chains(ledger) -> int:
    n = 0
    # cross-class chaining engine: compose the capabilities of candidate/confirmed cells with signals
    # seen in traffic into concrete multi-step chains, and queue each with its test plan.
    from bbh import chains as chain_engine

    for ch in chain_engine.detect_chains(ledger):
        cells = ",".join(str(c) for c in ch["from_cells"])
        tag = "high" if ch["confidence"] == "high" else "hypothesis"
        title = f"Chain ({tag}): {ch['name']}"
        if ch["missing_preconditions"]:
            title += f" -- needs: {', '.join(ch['missing_preconditions'])}"
        n += _add(ledger, 5, title, ch, f"chain:{ch['name']}:{cells}", test_plan=ch["test_plan"])
    # low-value confirmed findings and candidates are also chain material
    for row in ledger.q("SELECT id, cell_id, rung, severity FROM findings WHERE severity IN ('info','low')"):
        n += _add(ledger, 5, f"Chain attempt from low finding {row['id']} (rung {row['rung']})",
                  {"finding_id": row["id"]}, f"chain_finding:{row['id']}")
    # bug-name-chain.md entries
    chain_md = ledger.paths.root / "bug-name-chain.md"
    if chain_md.is_file():
        import hashlib
        h = hashlib.sha1(chain_md.read_bytes()).hexdigest()[:10]
        n += _add(ledger, 5, "Review bug-name-chain.md entries and check each chain's preconditions",
                  {"file": "bug-name-chain.md"}, f"chain_md:{h}")
    return n


def _depth_retest_inconclusive(ledger) -> int:
    n = 0
    for row in ledger.q("SELECT DISTINCT cell_id FROM test_cases WHERE outcome='inconclusive'"):
        cid = row["cell_id"]
        cell = ledger.cell(cid)
        if cell["state"] == "negative":
            n += _add(ledger, 6, f"Re-test negative cell {cid} by the other route (its evidence holds an inconclusive case)",
                      {"cell_id": cid}, f"retest_inconclusive:{cid}")
    return n
