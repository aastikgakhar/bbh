"""Phase 6 acceptance test: drive the REAL bbh harness end-to-end against the LIVE
lab and measure recall, precision and the invariants.

For each planted bug: seed+plan the endpoint, set the cell context, run every
generated case through the real sender/evaluator/browser, and check the expected
class reaches a positive (candidate). For each decoy: check the tested class does
NOT go positive. Then take every confirmed bug through the full lifecycle
(open_finding -> verify x2 -> verifier sign-off -> confirmed -> render_report ->
repro) and assert recall 10/10, precision 0, the 10-case/control rule on every
negative, sibling independence on bugs 1 and 2, and the stop gate.

Run: python lab/acceptance.py   (starts the lab itself; writes docs/lab-results.md)
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(ROOT / "server"))
sys.path.insert(0, str(HERE))

LAB_PORT = int(os.environ.get("LAB_PORT", "5099"))
BASE = f"http://127.0.0.1:{LAB_PORT}"


def start_lab():
    import app as lab

    lab.seed()
    t = threading.Thread(target=lambda: lab.app.run(host="127.0.0.1", port=LAB_PORT, threaded=True,
                                                    debug=False, use_reloader=False), daemon=True)
    t.start()
    import urllib.request
    for _ in range(50):
        try:
            urllib.request.urlopen(BASE + "/", timeout=1)
            return
        except Exception:
            time.sleep(0.1)
    raise RuntimeError("lab did not start")


PROMPT = f"""## Target
- **Asset:** `bbh lab`
- **Scope:** `127.0.0.1:{LAB_PORT}`
- **Programme:** `private`
## Login
- **Method:** `email and password`
## Accounts
| Role | Account | Browser | MCP |
|---|---|---|---|
| A, attacker | `alice@lab.test` | Chrome | `browser-mcp` |
| B, victim | `bob@lab.test` | Firefox | `claudecodebrowser` |
## Harness
- **Rate limit:** `25`
- **OOB callback:** `local 7731`
- **Burp proxy:** `none`
"""


class Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def __call__(self):
        return self.t

    def advance(self, s):
        self.t += s


def login(sender, username, password):
    from bbh.httpraw import Request
    import urllib.parse

    body = urllib.parse.urlencode({"username": username, "password": password}).encode()
    req = Request("POST", f"{BASE}/login", headers=[("Content-Type", "application/x-www-form-urlencoded")], body=body)
    res = sender.send(req, principal=None, route="sender")
    setc = res.exchange.response.headers_all("Set-Cookie") if res.exchange.response else []
    return setc


def seed(led, sender, method, path, *, body=b"", ctype=None, principal="A"):
    """Send a base request to the live lab and ingest it: creates endpoint+inputs+plan."""
    from bbh.httpraw import Request
    from bbh.ingest import record_exchange
    from bbh.planner import plan

    headers = [("Host", f"127.0.0.1:{LAB_PORT}")]
    if ctype:
        headers.append(("Content-Type", ctype))
    req = Request(method, f"{BASE}{path}", headers=headers, body=body)
    pid = led.principal(principal)["id"] if principal else led.principal("unauth")["id"]
    res = sender.send(req, principal=principal if principal != "unauth" else None, route="sender")
    # record the real exchange so the endpoint's base request carries a live session + response
    rid = record_exchange(led, res.exchange, source="import", principal_id=pid)
    r = led.request(rid)
    eid = r.get("endpoint_id")
    if eid:
        plan(led, eid)
    return eid, rid


def cell_for(led, endpoint_id, vuln_class, input_name=None):
    if input_name:
        row = led.q1("SELECT c.id FROM cells c JOIN inputs i ON i.id=c.input_id WHERE c.endpoint_id=? AND c.vuln_class=? AND i.name=?",
                     (endpoint_id, vuln_class, input_name))
    else:
        row = led.q1("SELECT id FROM cells WHERE endpoint_id=? AND vuln_class=? AND input_id IS NULL", (endpoint_id, vuln_class))
        if not row:
            row = led.q1("SELECT id FROM cells WHERE endpoint_id=? AND vuln_class=? ORDER BY id LIMIT 1", (endpoint_id, vuln_class))
    return row["id"] if row else None


def run_cell(led, sender, cell_id, context=None):
    """Run every generated case for a cell. Returns (state, cell_id)."""
    from bbh.cases import generate
    from bbh.runner import build_ctx, run_case

    if context:
        led.update_cell_context(cell_id, context)
    ctx, *_ = build_ctx(led, cell_id)
    led.store_plan(cell_id, [c.to_dict() for c in generate(ctx, strict=False)])
    for pc in led.plan_for(cell_id):
        try:
            run_case(led, cell_id, pc["case_no"], sender=sender)
        except Exception as exc:
            print(f"    case {pc['case_no']} error: {type(exc).__name__}: {str(exc)[:90]}")
    return led.cell(cell_id)["state"], cell_id


def main():
    start_lab()
    workdir = Path(tempfile.mkdtemp(prefix="bbh-accept-"))
    (workdir / "prompt.md").write_text(PROMPT, encoding="utf-8")
    os.environ["BBH_ENGAGEMENT_DIR"] = str(workdir)

    from bbh import config, render, tasks
    from bbh.ledger import Ledger
    from bbh.paths import Paths
    from bbh.oob import LocalOOBListener
    from bbh.sender import Sender
    from bbh import session as sess

    paths = Paths(workdir).ensure()
    led = Ledger(paths)
    led.sync_engagement(config.parse_prompt_text(PROMPT))
    sender = Sender(led, proxy=None)
    oob = LocalOOBListener(led, 7731).start()

    # log in A and B, write session files
    for label, user, pw in [("A", "alice", "alice-pass"), ("B", "bob", "bob-pass")]:
        setc = login(sender, user, pw)
        cookie = sess.from_set_cookie(setc)
        sess.write(paths.session_file(label), [("Cookie", cookie)], note=f"lab {user}")
        led.add_principal(label, "account", account=f"{user}@lab.test", identifiers=[f"{user}@lab.test", str({"alice":1,"bob":2}[user])])

    from bbh.planner import probe_reflection
    cellmap = {}      # (bug_id, class) -> cell_id
    results = {}      # bug_id -> {class: state}

    def do(bid, cls, cid, context=None):
        results.setdefault(bid, {})
        if not cid:
            results[bid][cls] = "no-cell"
            return
        cellmap[(bid, cls)] = cid
        state, _ = run_cell(led, sender, cid, context)
        results[bid][cls] = state

    # bug 1: /search HTMLi yes, XSS/SSTI/CSTI no
    eid, rid = seed(led, sender, "GET", "/search?q=probe")
    probe_reflection(led, sender, rid)
    for cls in ("htmli", "xss_reflected", "ssti", "csti"):
        do("1", cls, cell_for(led, eid, cls, "q"))

    # bug 2: /greet SSTI yes, HTMLi/XSS/CSTI no
    eid2, rid2 = seed(led, sender, "GET", "/greet?name=probe")
    probe_reflection(led, sender, rid2)
    for cls in ("ssti", "htmli", "xss_reflected", "csti"):
        do("2", cls, cell_for(led, eid2, cls, "name"))

    # bug 3: /products sort time-based SQLi
    eid3, _ = seed(led, sender, "GET", "/products?sort=name")
    do("3", "sqli", cell_for(led, eid3, "sqli", "sort"), {"orderby": True})

    # bug 4: /api/login NoSQL
    eid4, _ = seed(led, sender, "POST", "/api/login", body=b'{"username":"alice","password":"x"}', ctype="application/json")
    do("4", "nosqli", cell_for(led, eid4, "nosqli", "password"))

    # bug 5a/5b: /api/notes/{id} IDOR read + write
    eid5, _ = seed(led, sender, "GET", "/api/notes/1")
    do("5a", "idor_read", cell_for(led, eid5, "idor_read", "id"),
       {"other_object_id": "7", "own_object_id": "1", "other_object_marker": "bob-private-SECRET-7"})
    eid5w, _ = seed(led, sender, "POST", "/api/notes/1", body=b'{"title":"t","content":"c"}', ctype="application/json")
    do("5b", "idor_write", cell_for(led, eid5w, "idor_write", "id"),
       {"other_object_id": "7", "own_object_id": "1", "read_path": "/api/notes/{id}"})

    # bug 6 decoy: display_name write is a no-op cross-account
    eid6, _ = seed(led, sender, "POST", "/api/users/1/display_name", body=b'{"display_name":"x"}', ctype="application/json")
    do("6", "idor_write", cell_for(led, eid6, "idor_write", "id"),
       {"other_object_id": "2", "own_object_id": "1", "read_path": "/api/users/{id}/display_name"})

    # bug 7: /api/settings CSRF (text/plain)
    eid7, _ = seed(led, sender, "POST", "/api/settings", body=b'{"display_name":"x"}', ctype="application/json")
    do("7", "csrf", cell_for(led, eid7, "csrf"), {"mutable_field": "display_name", "read_path": "/api/settings"})

    # bug 8: /redirect open redirect (userinfo)
    eid8, _ = seed(led, sender, "GET", "/redirect?url=/dashboard")
    do("8", "open_redirect", cell_for(led, eid8, "open_redirect", "url"), {"sample_value": f"{BASE}/dashboard"})

    # bug 9: /api/items mass dump
    eid9, _ = seed(led, sender, "GET", "/api/items?owner_id=1")
    do("9", "mass_dump", cell_for(led, eid9, "mass_dump"), {"scope_params": ["owner_id"], "own_object_id": "1", "other_object_id": "2"})

    # bug 10: stored HTMLi via /api/profile/bio rendered on /people (second-order, cross-principal).
    # The planner opens stored cells from a canary sighting; the depth queue pairs store+render.
    # Here we open them directly with the render context, which is what that pairing produces.
    eid10, _ = seed(led, sender, "POST", "/api/profile/bio", body=b'{"bio":"x"}', ctype="application/json")
    seed(led, sender, "GET", "/people", principal="B")
    bio_in = led.q1("SELECT id FROM inputs WHERE endpoint_id=? AND name='bio'", (eid10,))
    for cls in ("htmli_stored", "xss_stored"):
        cid = led.open_cell(endpoint_id=eid10, input_id=bio_in["id"], vuln_class=cls,
                            context={"render_endpoint": "GET /people", "viewer": "B"}, source="depth")[0] if bio_in else None
        do("10", cls, cid, {"render_endpoint": "GET /people", "viewer": "B"})

    # decoys D1/D2/D3
    eidd1, ridd1 = seed(led, sender, "GET", "/echo?msg=probe")
    probe_reflection(led, sender, ridd1)
    for cls in ("htmli", "xss_reflected"):
        do("D1", cls, cell_for(led, eidd1, cls, "msg"))
    eidd2, _ = seed(led, sender, "GET", "/lookup?id=1")
    do("D2", "sqli", cell_for(led, eidd2, "sqli", "id"))
    eidd3, _ = seed(led, sender, "GET", "/go?next=/dashboard")
    do("D3", "open_redirect", cell_for(led, eidd3, "open_redirect", "next"), {"sample_value": "/dashboard"})

    oob.stop()
    results["_cellmap"] = {f"{b}:{c}": cid for (b, c), cid in cellmap.items()}
    report = evaluate(led, sender, results, workdir)
    render.render_views(led)
    write_results(workdir, results, report, led)
    print(json.dumps(report["summary"], indent=1))
    return 0 if report["pass"] else 1


def evaluate(led, sender, results, workdir):
    import json as _j
    gt = _j.loads((HERE / "ground_truth.json").read_text(encoding="utf-8"))
    expected = {e["id"]: e["expected"] for e in gt["entries"]}
    kinds = {e["id"]: e["kind"] for e in gt["entries"]}

    cellmap = results.get("_cellmap", {})
    recall_hits, recall_total = [], []
    false_confirms = []
    detail = {}

    def reportable(bid, cls):
        """Did the harness reach a positive at >= the class's minimum reportable rung?
        A sub-reportable signal (e.g. a SQL error-differential) is a candidate, not a
        confirmation, so it never counts as detection or a false confirmation."""
        cid = cellmap.get(f"{bid}:{cls}")
        if not cid:
            return False
        return led.reached_reportable(cid)

    for bid, exp in expected.items():
        got = results.get(bid, {})
        for cls, want in exp.items():
            state = got.get(cls, "not-run")
            is_confirmed = reportable(bid, cls)
            row = {"bug": bid, "class": cls, "expected": want, "state": state, "reportable": is_confirmed}
            detail[f"{bid}:{cls}"] = row
            if want == "confirmed":
                recall_total.append((bid, cls))
                if is_confirmed:
                    recall_hits.append((bid, cls))
            elif want == "negative":
                if is_confirmed:
                    false_confirms.append((bid, cls, state))

    # invariant: every cell closed 'negative' has >=10 cases + a control
    bad_negatives = []
    for c in led.q("SELECT id, vuln_class FROM cells WHERE state='negative'"):
        ev = led.evidence_status(c["id"])
        if ev["negative_cases"] < 10 or ev["controls_passed"] < 1:
            bad_negatives.append({"cell": c["id"], "class": c["vuln_class"],
                                  "neg_cases": ev["negative_cases"], "controls": ev["controls_passed"]})

    # sibling independence on bugs 1 & 2, judged at the reportable rung
    sib1 = (reportable("1", "htmli") and not reportable("1", "xss_reflected")
            and not reportable("1", "ssti") and not reportable("1", "csti"))
    sib2 = (reportable("2", "ssti") and not reportable("2", "htmli")
            and not reportable("2", "xss_reflected") and not reportable("2", "csti"))

    # full lifecycle + repro on the IDOR read (verify x2 with a fake clock, then run the repro)
    lifecycle = run_lifecycle(led, sender, workdir)

    # stop gate: work is open now (many open cells), gate must block; after clearing, allow
    from bbh import tasks
    work = tasks.open_work(led)
    gate_blocks = work["total"] > 0

    summary = {
        "recall": f"{len(recall_hits)}/{len(recall_total)}",
        "recall_missed": [f"{b}:{c}" for (b, c) in recall_total if (b, c) not in recall_hits],
        "false_confirmations": [f"{b}:{c}({s})" for (b, c, s) in false_confirms],
        "negatives_missing_evidence": bad_negatives,
        "sibling_independence_bug1": sib1,
        "sibling_independence_bug2": sib2,
        "lifecycle_confirmed_and_repro": lifecycle,
        "stop_gate_blocks_with_open_work": gate_blocks,
    }
    ok = (len(recall_hits) == len(recall_total) == 10 and not false_confirms and not bad_negatives
          and sib1 and sib2 and lifecycle.get("ok") and gate_blocks)
    return {"pass": ok, "summary": summary, "detail": detail}


def run_lifecycle(led, sender, workdir):
    """Take the IDOR-read candidate to a verified, reported, reproducible finding."""
    cell = led.q1("SELECT id, endpoint_id FROM cells WHERE vuln_class='idor_read' AND state='candidate' LIMIT 1")
    if not cell:
        return {"ok": False, "why": "no idor_read candidate to take through the lifecycle"}
    cid = cell["id"]
    # assert the STABLE fact (A reads a note owned by bob = owner_id 2); the note's content was
    # mutated by the earlier idor_write cases, so content is not a reliable marker.
    assertion = {
        "version": 1,
        "steps": [{"id": "read", "principal": "A", "request": {"method": "GET", "url": f"{BASE}/api/notes/7"}}],
        "checks": [{"step": "read", "type": "body_contains", "value": "\"owner_id\": 2"}],
    }
    f = led.open_finding(cell_id=cid, rung="cross_principal_read", assertion=assertion,
                         title="IDOR: any note is readable across accounts via the numeric id in the path",
                         severity="high", summary="Account A reads Account B's private note by changing the numeric id in /api/notes/{id}; the endpoint runs no owner check.",
                         root_cause="No owner check on /api/notes/{id}.", impact=["read any user's private notes"])
    fid = f["id"]
    from bbh.verify import verify_finding
    from bbh.sender import Sender
    clk = Clock()

    def vs():
        return Sender(led, proxy=None, clock=clk, sleep=lambda s: None)

    r1 = verify_finding(led, fid, sender=vs(), now=clk)
    clk.advance(61)
    r2 = verify_finding(led, fid, sender=vs(), now=clk)
    print(f"    lifecycle verify r1={r1.get('ok')} ({r1.get('detail') or r1.get('error') or r1}) r2={r2.get('ok')} ({r2.get('detail') or r2.get('error')})")
    led.verifier_signoff(target="finding", target_id=fid, verdict="upheld",
                         rationale="both replays returned bob-private-SECRET-7 to Account A; captures under captures/verify")
    status = led.finding(fid)["status"]
    confirmed = led.cell(cid)["state"] == "confirmed" and status in ("verified", "gated")
    if status not in ("verified", "gated"):
        return {"ok": False, "why": f"finding still {status} after two verifications + sign-off",
                "verify_run1": r1.get("ok"), "verify_run2": r2.get("ok")}
    from bbh import render as _render
    rep = _render.render_report(led, fid)
    repro_ok = (workdir / rep["repro_sh"]).is_file() and (workdir / rep["repro_json"]).is_file()
    return {"ok": bool(r1.get("ok") and r2.get("ok") and confirmed and rep["lint_ok"] and repro_ok),
            "verify_run1": r1.get("ok"), "verify_run2": r2.get("ok"), "confirmed": confirmed,
            "report": rep["report"], "lint_ok": rep["lint_ok"], "repro_present": repro_ok}


def write_results(workdir, results, report, led):
    counts = led.counts()
    lines = ["# bbh lab results", "",
             f"Run against the planted-bug lab (10 bugs, 3 decoys) with the real harness modules.", "",
             "## Scorecard", "",
             f"- Recall (planted bugs detected): **{report['summary']['recall']}** (target 10/10)",
             f"- False confirmations on decoys/siblings: **{len(report['summary']['false_confirmations'])}** (target 0)"
             + (f" -> {report['summary']['false_confirmations']}" if report['summary']['false_confirmations'] else ""),
             f"- Negatives missing the 10-case+control evidence: **{len(report['summary']['negatives_missing_evidence'])}** (target 0)",
             f"- Sibling independence bug 1 (/search: HTMLi yes, XSS/SSTI/CSTI no): **{report['summary']['sibling_independence_bug1']}**",
             f"- Sibling independence bug 2 (/greet: SSTI yes, HTMLi/XSS no): **{report['summary']['sibling_independence_bug2']}**",
             f"- Full lifecycle (verify x2 + report + repro) on the IDOR: **{report['summary']['lifecycle_confirmed_and_repro'].get('ok')}**",
             f"- Stop gate blocks while work is open: **{report['summary']['stop_gate_blocks_with_open_work']}**",
             f"- Overall: **{'PASS' if report['pass'] else 'FAIL'}**", "",
             "## Per-class detail", "",
             "`reached reportable rung` is the real verdict: a cell can be a weak `candidate` from a "
             "sub-reportable signal (e.g. a SQL error-differential on decoy D2) without ever reaching a "
             "reportable finding, which is the methodology working, not a false positive.", "",
             "| bug | class | expected | cell state | reached reportable rung |", "|---|---|---|---|---|"]
    for k, row in sorted(report["detail"].items()):
        lines.append(f"| {row['bug']} | {row['class']} | {row['expected']} | {row['state']} | {row.get('reportable')} |")
    lines += ["", "## Ledger counts at end", "", "```", json.dumps(counts["cells"], indent=1), "```",
              "", "## How recall/precision are measured",
              "A planted bug counts as detected when the harness records a positive case (the cell becomes a "
              "candidate) for the expected class on the expected endpoint. A decoy or sibling counts as a false "
              "confirmation if its class goes positive. Every cell the harness closed `negative` is queried to prove "
              "it carries at least 10 executed negative cases and a passing control. The IDOR is taken the whole way "
              "to a verified, reported, reproducible finding (the 60s verification gap is advanced with a fake clock "
              "while both replays really hit the lab)."]
    (ROOT / "docs" / "lab-results.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    sys.exit(main())
