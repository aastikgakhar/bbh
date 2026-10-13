"""End-to-end over the real modules against a tiny in-process app via MockTransport.

Covers: ingest from captures, planner opening sibling cells, run_cases driving the
sender and evaluator, a confirmed finding (candidate -> verify x2 60s apart +
verifier sign-off -> confirmed), render_report + lint, triage gating, and the
generated views. No network, no real browser.
"""

import re
import time

import httpx
import pytest

from bbh import render, tasks
from bbh.cases import generate
from bbh.httpraw import Request
from bbh.ingest import record_exchange
from bbh.httpraw import Exchange, Response
from bbh.planner import plan, probe_reflection
from bbh.runner import run_case
from bbh.sender import Sender
from bbh.ledger import VERIFY_GAP_S

from conftest import make_capture


# --- a tiny vulnerable app: /search reflects q raw; /api/notes/<id> is an IDOR ---------------

def app(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    q = request.url.params
    if path == "/search":
        val = q.get("q", "")
        # raw reflection (HTMLi), but no script execution modelled here
        return httpx.Response(200, text=f"<html><body>Results for {val}</body></html>", headers={"Content-Type": "text/html"})
    if path.startswith("/api/notes/"):
        nid = path.rsplit("/", 1)[-1]
        owner = "alice" if nid in ("1", "2") else "bob"
        secret = "alice-private" if owner == "alice" else "bob-private-SECRET"
        return httpx.Response(200, json={"id": int(nid) if nid.isdigit() else 0, "owner": owner, "content": secret})
    if path == "/api/settings":
        return httpx.Response(200, json={"display_name": _state.get("name", "default"), "owner": "A"})
    if path == "/settings":
        return httpx.Response(200, json={"display_name": _state.get("name", "default")})
    return httpx.Response(404, text="nope")


_state = {}


def post_app(request: httpx.Request) -> httpx.Response:
    if request.url.path == "/api/settings" and request.method == "POST":
        import json
        try:
            body = json.loads(request.content)
        except Exception:
            body = dict(p.split("=", 1) for p in request.content.decode().split("&") if "=" in p)
        _state["name"] = body.get("display_name", _state.get("name"))
        return httpx.Response(200, json={"ok": True})
    return app(request)


def handler(request):
    if request.method == "POST":
        return post_app(request)
    return app(request)


def mk_sender(ledger):
    ft = _Clock()
    return Sender(ledger, transport=httpx.MockTransport(handler), clock=ft.clock, sleep=ft.sleep, proxy=None)


class _Clock:
    def __init__(self):
        self.t = 1_800_000_000.0

    def clock(self):
        return self.t

    def sleep(self, s):
        self.t += s


def seed_endpoint(ledger, method, path, body=b"", ctype=None, principal="A"):
    """Record a base request as a capture and ingest it so an endpoint+inputs exist."""
    headers = [("Host", "127.0.0.1:5057"), ("Cookie", "lab_session=AAA")]
    if ctype:
        headers.append(("Content-Type", ctype))
    req = Request(method=method, url=f"http://127.0.0.1:5057{path}", headers=headers, body=body)
    resp = Response(200, "OK", [("Content-Type", "text/html")], b"<html>ok</html>")
    rid = record_exchange(ledger, Exchange(request=req, response=resp), source="import",
                          principal_id=ledger.principal(principal)["id"])
    # plan the endpoint this request belongs to, so its cells exist
    r = ledger.request(rid)
    if r.get("endpoint_id"):
        plan(ledger, r["endpoint_id"])
    return rid


def test_options_preflight_records_request_but_creates_no_endpoint(ledger, eng):
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    before = len(ledger.q("SELECT id FROM endpoints"))
    # a CORS preflight the harness's own cors cell would send
    req = Request(method="OPTIONS", url="http://127.0.0.1:5057/_api/x/do",
                  headers=[("Host", "127.0.0.1:5057"), ("Access-Control-Request-Method", "POST")], body=b"")
    resp = Response(200, "OK", [("Allow", "POST,OPTIONS")], b"")
    rid = record_exchange(ledger, Exchange(request=req, response=resp), source="import",
                          principal_id=ledger.principal("A")["id"])
    assert rid is not None  # the request row is kept as evidence
    assert ledger.request(rid).get("endpoint_id") in (None, 0)  # but it spawned no endpoint
    assert len(ledger.q("SELECT id FROM endpoints")) == before
    # a real POST to the same path still creates an endpoint
    req2 = Request(method="POST", url="http://127.0.0.1:5057/_api/x/do",
                   headers=[("Host", "127.0.0.1:5057"), ("Content-Type", "application/json")], body=b"{}")
    rid2 = record_exchange(ledger, Exchange(request=req2, response=Response(200, "OK", [("Content-Type", "application/json")], b"{}")),
                           source="import", principal_id=ledger.principal("A")["id"])
    assert ledger.request(rid2).get("endpoint_id")


def test_plan_opens_independent_sibling_cells(ledger, eng):
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    rid = seed_endpoint(ledger, "GET", "/search?q=hi")
    ep = ledger.q1("SELECT id FROM endpoints WHERE path_template='/search'")
    # reflect probe via the mock sender
    s = mk_sender(ledger)
    contexts = probe_reflection(ledger, s, rid)
    assert "query:q" in contexts and "html_text" in contexts["query:q"]
    classes = {r["vuln_class"] for r in ledger.q("SELECT vuln_class FROM cells WHERE endpoint_id=?", (ep["id"],))}
    assert {"htmli", "xss_reflected", "ssti", "csti"} <= classes
    # each is its own open cell
    for c in ("htmli", "xss_reflected", "ssti", "csti"):
        cell = ledger.q1("SELECT state FROM cells WHERE endpoint_id=? AND vuln_class=?", (ep["id"], c))
        assert cell["state"] == "open"


def test_run_cases_confirms_htmli_and_leaves_siblings_independent(ledger, eng):
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    rid = seed_endpoint(ledger, "GET", "/search?q=hi")
    s = mk_sender(ledger)
    probe_reflection(ledger, s, rid)
    ep = ledger.q1("SELECT id FROM endpoints WHERE path_template='/search'")
    htmli = ledger.q1("SELECT id FROM cells WHERE endpoint_id=? AND vuln_class='htmli'", (ep["id"],))["id"]
    ssti = ledger.q1("SELECT id FROM cells WHERE endpoint_id=? AND vuln_class='ssti'", (ep["id"],))["id"]
    # generate + store the plan, then run every case through the real runner + sender + evaluator
    from bbh.runner import build_ctx
    ctx, *_ = build_ctx(ledger, htmli)
    ledger.store_plan(htmli, [c.to_dict() for c in generate(ctx, strict=False)])
    results = []
    for pc in ledger.plan_for(htmli):
        if pc["route"] in ("oob", "browser"):
            continue  # those need a listener/browser; this app reflects raw, so sender-route tag cases confirm
        results.append(run_case(ledger, htmli, pc["case_no"], sender=s))
    # at least one tag-render case is positive (raw reflection) -> candidate
    assert ledger.cell(htmli)["state"] == "candidate", [r for r in results if r["outcome"] == "positive"]
    # ssti stays open and untouched
    assert ledger.cell(ssti)["state"] == "open"


def test_full_idor_finding_lifecycle(ledger, eng, monkeypatch):
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    (eng.captures / "session-B.txt").write_text("Cookie: lab_session=BBB\n")
    # base request: A reads its own note 1
    rid = seed_endpoint(ledger, "GET", "/api/notes/1")
    ep = ledger.q1("SELECT id FROM endpoints WHERE path_template='/api/notes/{id}'")
    cell = ledger.q1("SELECT id FROM cells WHERE endpoint_id=? AND vuln_class='idor_read'", (ep["id"],))
    assert cell, "planner opened idor_read on the object-id path"
    cid = cell["id"]
    # the other principal's object id + a marker only their object holds
    ledger.update_cell_context(cid, {"other_object_id": "3", "own_object_id": "1", "other_object_marker": "bob-private-SECRET"})
    s = mk_sender(ledger)
    from bbh.runner import build_ctx
    ctx, *_ = build_ctx(ledger, cid)
    ledger.store_plan(cid, [c.to_dict() for c in generate(ctx, strict=False)])
    for pc in ledger.plan_for(cid):
        run_case(ledger, cid, pc["case_no"], sender=s)
    # A read B's note content -> candidate
    assert ledger.cell(cid)["state"] == "candidate"
    # open a finding with an assertion the harness can replay
    assertion = {
        "version": 1,
        "steps": [{"id": "read", "principal": "A", "request": {"method": "GET", "url": "http://127.0.0.1:5057/api/notes/3"}}],
        "checks": [{"step": "read", "type": "body_contains", "value": "bob-private-SECRET"}],
    }
    f = ledger.open_finding(cell_id=cid, rung="cross_principal_read", assertion=assertion,
                            title="IDOR: any note readable across accounts via the numeric id",
                            severity="high", summary="Account A reads Account B's private note by changing the numeric id in /api/notes/{id}.",
                            root_cause="No owner check on /api/notes/{id}.", impact=["read any user's private notes"])
    fid = f["id"]
    # verify twice, 60s apart, with a fresh sender each time
    clk = _Clock()

    def vsender():
        return Sender(ledger, transport=httpx.MockTransport(handler), clock=clk.clock, sleep=clk.sleep, proxy=None)

    from bbh.verify import verify_finding
    r1 = verify_finding(ledger, fid, sender=vsender(), now=clk.clock)
    assert r1["ok"], r1
    # second run too soon is refused
    r_too_soon = verify_finding(ledger, fid, sender=vsender(), now=clk.clock)
    assert r_too_soon.get("waiting")
    clk.t += VERIFY_GAP_S + 1
    r2 = verify_finding(ledger, fid, sender=vsender(), now=clk.clock)
    assert r2["ok"]
    # still draft until the verifier signs off
    assert ledger.finding(fid)["status"] == "draft"
    ledger.verifier_signoff(target="finding", target_id=fid, verdict="upheld",
                            rationale="the replay returns bob-private-SECRET to Account A, captures under captures/verify")
    assert ledger.finding(fid)["status"] == "verified"
    assert ledger.cell(cid)["state"] == "confirmed"
    # render the report + repro, then lint
    out = render.render_report(ledger, fid)
    assert out["report_no"] >= 1
    report = (eng.root / out["report"]).read_text(encoding="utf-8")
    assert "Step 1:" in report and "**As the attacker**" in report
    assert (eng.root / out["repro_sh"]).is_file() and (eng.root / out["repro_json"]).is_file()
    assert out["lint_ok"], out["lint_problems"]
    # triage: two rejects then accept gates it
    ledger.record_triage(fid, "REJECT", "show the owner's own read", "re-read note 3 as B and show the same content")
    assert ledger.finding(fid)["status"] == "verified"
    ledger.record_triage(fid, "ACCEPT", "", "")
    assert ledger.finding(fid)["status"] == "gated"


def test_render_views_write_all_four(ledger, eng):
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    seed_endpoint(ledger, "GET", "/search?q=hi")
    views = render.render_views(ledger)
    for name in ("state.csv", "feature-matrix.md", "progress.log", "findings-summary.md"):
        assert (eng.root / name).is_file()
    assert "Feature coverage matrix" in (eng.root / "feature-matrix.md").read_text(encoding="utf-8")
    assert "search" in (eng.root / "state.csv").read_text(encoding="utf-8")


def test_next_task_prioritises_candidates_then_high_value(ledger, eng):
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    seed_endpoint(ledger, "GET", "/api/notes/1")
    seed_endpoint(ledger, "GET", "/search?q=hi")
    # with only open cells, next_task returns a cell (high value first)
    t = tasks.next_task(ledger, peek=True)
    assert t.kind in ("cell", "depth", "recon")
    # make a candidate; it must take priority
    cell = ledger.q1("SELECT id FROM cells WHERE vuln_class='idor_read' LIMIT 1")
    cap = make_capture(eng, "cand.http")
    ledger.record_case(cell_id=cell["id"], case_no=99, technique="idor_read.cross.direct", outcome="positive",
                       observation="A read B's content (captures/cand.http)", request_capture=cap, response_capture=cap)
    t2 = tasks.next_task(ledger, peek=True)
    assert t2.kind == "candidate" and t2.cell_id == cell["id"]


# --- regression: crawl must actually record the pages it fetches ----------------------------

def crawl_app(request: httpx.Request) -> httpx.Response:
    path = request.url.path
    if path == "/":
        return httpx.Response(200, headers={"Content-Type": "text/html"},
                              text="<html><body><a href='/search?q=hi'>s</a> "
                                   "<a href='/logout'>out</a> "
                                   "<a href='http://off.site/x'>off</a></body></html>")
    if path == "/search":
        return httpx.Response(200, headers={"Content-Type": "text/html"}, text="<html>ok</html>")
    return httpx.Response(404, text="nope")


def test_crawl_records_pages_and_creates_endpoints(ledger, eng):
    """crawl once passed source='traffic' to record_exchange, which the requests
    CHECK (burp/sender/browser/import) rejected, so no page was ever recorded."""
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    from bbh.crawl import crawl
    clk = _Clock()
    s = Sender(ledger, transport=httpx.MockTransport(crawl_app), clock=clk.clock, sleep=clk.sleep, proxy=None)
    out = crawl(ledger, s, "http://127.0.0.1:5057/", max_pages=5, principal="A")
    assert out["ok"] is True, out
    assert out["pages_fetched"] >= 2, out            # root + /search, both recorded, no CHECK error
    assert out["new_endpoints"] >= 1, out
    assert ledger.q1("SELECT id FROM endpoints WHERE path_template='/search'") is not None
    srcs = {r["source"] for r in ledger.q("SELECT DISTINCT source FROM requests")}
    assert srcs and srcs <= {"sender"}, srcs         # every recorded request has a valid source
    assert not ledger.q1("SELECT 1 FROM requests WHERE url LIKE '%logout%'")  # destructive link skipped
    assert not ledger.q1("SELECT 1 FROM requests WHERE url LIKE '%off.site%'")  # off-origin link skipped


def test_out_of_range_ids_report_not_found_not_overflow(ledger):
    """An absurd id (10**30) must answer a clean 'does not exist', not leak a SQLite
    OverflowError up through the tool wrapper."""
    from bbh.ledger import LedgerError
    for name in ("cell", "finding", "endpoint", "input", "request", "depth_item"):
        with pytest.raises(LedgerError) as exc:
            getattr(ledger, name)(10 ** 30)
        assert "does not exist" in str(exc.value)
    assert ledger.set_feature([10 ** 30], "x") == 0          # out-of-range ids are skipped, not bound
    from bbh.oob import oob_check
    assert oob_check(ledger, 10 ** 30) == {"tokens": 0, "hits": [], "received": False}
