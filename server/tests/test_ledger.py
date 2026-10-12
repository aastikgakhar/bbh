"""Layer 1 invariants. One or more tests per invariant in build-harness.md."""

import sqlite3

import pytest

from bbh import classes as C
from bbh.ledger import CLAIM_TTL_S, VERIFY_GAP_S, LedgerError

from conftest import fill_negative, make_capture

ASSERTION = {"steps": [{"id": "s1", "principal": "A", "request": {"method": "GET", "url": "http://127.0.0.1:5057/search?q=x"}}],
             "checks": [{"step": "s1", "type": "body_contains", "value": "<b>x</b>"}]}


def open_cells(ledger, eid, iid, names):
    return {n: ledger.open_cell(endpoint_id=eid, input_id=iid if C.get(n).level == "input" else None, vuln_class=n)[0] for n in names}


def snapshot(ledger, exclude):
    return {r["id"]: tuple(r) for r in ledger.q("SELECT * FROM cells WHERE id != ? ORDER BY id", (exclude,))}


# --- Invariant 1: ten-case minimum ----------------------------------------------------------------

def test_negative_refused_below_ten_cases(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    fill_negative(ledger, cid, cap, klass="htmli", n=9)
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    assert any("1 more executed negative case" in m for m in e.value.missing)
    ledger.record_case(cell_id=cid, case_no=10, technique="htmli.e.v10", outcome="negative",
                       observation="status 200, tag encoded (captures/c.http)", request_capture=cap, response_capture=cap)
    assert ledger.close_cell(cid, "negative")["state"] == "negative"


def test_negative_needs_five_distinct_technique_ids(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    # ten variants of only four families: still fails (a technique id is <class>.<family>)
    fill_negative(ledger, cid, cap, klass="htmli", families=("a", "b", "c", "d"), n=12)
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    assert any("technique id" in m for m in e.value.missing)


def test_inconclusive_cases_never_count(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    fill_negative(ledger, cid, cap, klass="htmli", n=9)
    for k in range(20, 30):
        ledger.record_case(cell_id=cid, case_no=k, technique="htmli.f.v", outcome="inconclusive",
                           observation="connection reset by peer (captures/c.http)", request_capture=cap, response_capture=None)
    ev = ledger.evidence_status(cid)
    assert ev["negative_cases"] == 9 and not ev["ok"]
    assert len(ev["inconclusive_cases"]) == 10


def test_latest_attempt_wins(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    fill_negative(ledger, cid, cap, klass="htmli", n=10)
    # case 3 re-run comes back inconclusive: it no longer counts
    ledger.record_case(cell_id=cid, case_no=3, technique="htmli.c.v3", outcome="inconclusive",
                       observation="status 0 from client (captures/c.http)", request_capture=cap, response_capture=None)
    assert ledger.evidence_status(cid)["negative_cases"] == 9


def test_capture_must_exist_and_be_non_empty(ledger, endpoint, eng, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    with pytest.raises(LedgerError):
        ledger.record_case(cell_id=cid, case_no=1, technique="htmli.a.v1", outcome="negative",
                           observation="status 200 (captures/missing.http)", request_capture="captures/missing.http",
                           response_capture="captures/missing.http")
    empty = eng.captures / "empty.http"
    empty.write_text("")
    with pytest.raises(LedgerError):
        ledger.record_case(cell_id=cid, case_no=1, technique="htmli.a.v1", outcome="negative",
                           observation="status 200 (captures/empty.http)", request_capture="captures/empty.http",
                           response_capture="captures/empty.http")
    # a capture deleted after recording stops counting
    gone = make_capture(eng, "gone.http")
    fill_negative(ledger, cid, cap, klass="htmli", n=9)
    ledger.record_case(cell_id=cid, case_no=10, technique="htmli.e.v10", outcome="negative",
                       observation="status 200 (captures/gone.http)", request_capture=gone, response_capture=gone)
    (eng.root / gone).unlink()
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "negative")


# --- Invariant 2: positive control ----------------------------------------------------------------------

def test_negative_needs_control_pass(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    fill_negative(ledger, cid, cap, klass="htmli", n=12, control=False)
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    assert any("control_pass" in m for m in e.value.missing)


def test_control_fail_blocks_negative_and_reopens(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.claim_cell(cid, "tester-1")
    fill_negative(ledger, cid, cap, klass="htmli", n=12, control=False)
    ledger.record_case(cell_id=cid, case_no=0, technique="htmli.control.canary", outcome="control_fail",
                       observation="canary absent from the baseline response (captures/c.http)", request_capture=cap, response_capture=cap)
    cell = ledger.cell(cid)
    assert cell["state"] == "open" and cell["note"].startswith("tooling: control case 0 failed")
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "negative")
    # the control is fixed and re-run: now it closes
    ledger.record_case(cell_id=cid, case_no=0, technique="htmli.control.canary", outcome="control_pass",
                       observation="canary reflected raw (captures/c.http)", request_capture=cap, response_capture=cap)
    assert ledger.close_cell(cid, "negative")["state"] == "negative"


# --- Invariant 3: siblings are independent ----------------------------------------------------------------

def test_siblings_untouched_by_every_transition(ledger, endpoint, cap, clock):
    eid, iid = endpoint
    names = ["htmli", "xss_reflected", "ssti", "csti", "crlf", "sqli"]
    cells = open_cells(ledger, eid, iid, names)
    target = cells["xss_reflected"]

    def check(fn):
        before = snapshot(ledger, target)
        fn()
        assert snapshot(ledger, target) == before

    check(lambda: ledger.claim_cell(target, "t1"))
    check(lambda: ledger.release_cell(target, "context switch"))
    check(lambda: fill_negative(ledger, target, cap, klass="xss_reflected", n=10))
    check(lambda: ledger.close_cell(target, "negative"))
    check(lambda: ledger.reopen_cell(target, "depth re-test by browser route"))
    check(lambda: ledger.record_case(cell_id=target, case_no=50, technique="xss_reflected.tag.img", outcome="positive",
                                     observation="img onerror rendered raw (captures/c.http)", request_capture=cap, response_capture=cap))
    check(lambda: ledger.verifier_signoff(target="cell", target_id=target, verdict="upheld", rationale="payload rendered raw in captures/c.http"))
    check(lambda: ledger.open_finding(cell_id=target, rung="script_executes", assertion=ASSERTION, title="Reflected XSS on search", severity="medium"))
    fid = ledger.finding_for_cell(target)["id"]
    check(lambda: ledger.verifier_signoff(target="finding", target_id=fid, verdict="upheld", rationale="replay matched captures/c.http"))
    check(lambda: ledger.record_verification(fid, "script_executes", True, "ok", None, clock(), clock()))
    clock.advance(VERIFY_GAP_S + 1)
    check(lambda: ledger.record_verification(fid, "script_executes", True, "ok", None, clock(), clock()))
    assert ledger.cell(target)["state"] == "confirmed"
    # and every sibling is still exactly open
    for n, cid in cells.items():
        if cid != target:
            assert ledger.cell(cid)["state"] == "open", n


def test_confirming_xss_leaves_htmli_and_ssti_to_their_own_verdicts(ledger, endpoint, cap):
    eid, iid = endpoint
    cells = open_cells(ledger, eid, iid, ["htmli", "xss_reflected", "ssti"])
    ledger.record_case(cell_id=cells["htmli"], case_no=1, technique="htmli.tag.b", outcome="positive",
                       observation="<b> rendered raw (captures/c.http)", request_capture=cap, response_capture=cap)
    fill_negative(ledger, cells["xss_reflected"], cap, klass="xss_reflected")
    ledger.close_cell(cells["xss_reflected"], "negative")
    assert ledger.cell(cells["htmli"])["state"] == "candidate"
    assert ledger.cell(cells["ssti"])["state"] == "open"


# --- Invariant 4: ladders never downgrade ------------------------------------------------------------------

def _confirm(ledger, clock, cid, rung, cap):
    f = ledger.open_finding(cell_id=cid, rung=rung, assertion=ASSERTION, title="HTML injection in search", severity="low")
    ledger.verifier_signoff(target="finding", target_id=f["id"], verdict="upheld", rationale="markup rendered in captures/c.http", rung=rung)
    ledger.record_verification(f["id"], rung, True, "ok", None, clock(), clock())
    clock.advance(VERIFY_GAP_S + 1)
    return ledger.record_verification(f["id"], rung, True, "ok", None, clock(), clock())


def test_ladder_never_downgrades(ledger, endpoint, cap, clock):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.record_case(cell_id=cid, case_no=1, technique="htmli.tag.b", outcome="positive",
                       observation="<b> rendered raw (captures/c.http)", request_capture=cap, response_capture=cap)
    f = _confirm(ledger, clock, cid, "dangling_markup", cap)
    assert f["rung"] == "dangling_markup" and f["status"] == "verified"
    # confirming a lower rung later never lowers the finding
    f = _confirm(ledger, clock, cid, "tag_renders", cap)
    assert f["rung"] == "dangling_markup"
    # a failed climb is recorded and keeps the confirmed rung
    f = ledger.escalation_blocked(f["id"], "script_executes", "CSP script-src 'self' blocks inline script (captures/c.http)")
    assert f["rung"] == "dangling_markup"
    assert f["escalation_blocked_by"][0]["rung"] == "script_executes"
    # even raw SQL cannot lower it
    with pytest.raises(sqlite3.DatabaseError):
        ledger.conn.execute("UPDATE findings SET rung_index = 0 WHERE id = ?", (f["id"],))


def test_signal_rungs_are_not_findings(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.record_case(cell_id=cid, case_no=1, technique="htmli.tag.b", outcome="positive",
                       observation="canary reflected (captures/c.http)", request_capture=cap, response_capture=cap)
    with pytest.raises(LedgerError) as e:
        ledger.open_finding(cell_id=cid, rung="canary_reflects", assertion=ASSERTION, title="Reflection", severity="info")
    assert "signal, not a finding" in str(e.value)


def test_finding_needs_two_passes_60s_apart_and_verifier(ledger, endpoint, cap, clock):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.record_case(cell_id=cid, case_no=1, technique="htmli.tag.b", outcome="positive",
                       observation="<b> rendered raw (captures/c.http)", request_capture=cap, response_capture=cap)
    f = ledger.open_finding(cell_id=cid, rung="tag_renders", assertion=ASSERTION, title="HTML injection", severity="low")
    ledger.record_verification(f["id"], "tag_renders", True, "ok", None, clock(), clock())
    clock.advance(30)
    f = ledger.record_verification(f["id"], "tag_renders", True, "ok", None, clock(), clock())
    assert f["status"] == "draft"  # 30 s apart is not enough
    clock.advance(VERIFY_GAP_S)
    f = ledger.record_verification(f["id"], "tag_renders", True, "ok", None, clock(), clock())
    assert f["status"] == "draft"  # replays satisfied, verifier has not signed off
    f = ledger.verifier_signoff(target="finding", target_id=f["id"], verdict="upheld", rationale="tag renders in captures/c.http")
    assert f["status"] == "verified" and ledger.cell(cid)["state"] == "confirmed"


def test_a_failed_run_resets_verification(ledger, endpoint, cap, clock):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.record_case(cell_id=cid, case_no=1, technique="htmli.tag.b", outcome="positive",
                       observation="<b> rendered raw (captures/c.http)", request_capture=cap, response_capture=cap)
    f = ledger.open_finding(cell_id=cid, rung="tag_renders", assertion=ASSERTION, title="HTML injection", severity="low")
    ledger.verifier_signoff(target="finding", target_id=f["id"], verdict="upheld", rationale="tag renders in captures/c.http")
    ledger.record_verification(f["id"], "tag_renders", True, "ok", None, clock(), clock())
    clock.advance(VERIFY_GAP_S + 1)
    f = ledger.record_verification(f["id"], "tag_renders", False, "body did not contain marker", None, clock(), clock())
    assert f["status"] == "draft"


# --- Invariant 5: candidates cannot silently die --------------------------------------------------------------

def test_candidate_to_negative_needs_verifier_refutation(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.record_case(cell_id=cid, case_no=11, technique="htmli.tag.b", outcome="positive",
                       observation="<b> appears in body (captures/c.http)", request_capture=cap, response_capture=cap)
    assert ledger.cell(cid)["state"] == "candidate"
    fill_negative(ledger, cid, cap, klass="htmli")
    # the positive is still the latest outcome of case 11
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    assert any("positive" in m for m in e.value.missing) and any("verifier" in m for m in e.value.missing)
    ledger.record_case(cell_id=cid, case_no=11, technique="htmli.tag.b", outcome="negative",
                       observation="re-run: <b> is HTML-encoded as &lt;b&gt; (captures/c.http)", request_capture=cap, response_capture=cap)
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "negative")  # still no sign-off
    ledger.verifier_signoff(target="cell", target_id=cid, verdict="refuted", rationale="the first response was a cached error page, captures/c.http")
    assert ledger.close_cell(cid, "negative")["state"] == "negative"


def test_candidate_cannot_become_na_and_blocked_needs_signoff(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="sqli")[0]
    ledger.record_case(cell_id=cid, case_no=1, technique="sqli.time.sleep", outcome="positive",
                       observation="5012 ms vs 80 ms baseline (captures/c.http)", request_capture=cap, response_capture=cap)
    rid, _ = ledger.add_request(source="sender", method="GET", url="http://127.0.0.1:5057/search", host="127.0.0.1",
                                raw_path=None, content_hash="h1")
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "n_a", reason="no_datastore_reach", reason_request_id=rid)
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "blocked", reason="waf_block", unblock="browser route")
    ledger.verifier_signoff(target="cell", target_id=cid, verdict="blocked", rationale="WAF 403 block page on every route, captures/c.http")
    assert ledger.close_cell(cid, "blocked", reason="waf_block", unblock="rerun through the browser once the WAF ban lifts")["state"] == "blocked"


# --- Invariant 6: scope ---------------------------------------------------------------------------------------

@pytest.mark.parametrize("origin,path", [
    ("http://127.0.0.1:8080", "/x"),          # wrong port
    ("https://admin.lab.test", "/x"),         # explicit out of scope
    ("https://lab.test", "/x"),               # apex is not covered by *.lab.test
    ("https://evil.test", "/x"),
])
def test_scope_refuses_endpoints(ledger, origin, path):
    with pytest.raises(LedgerError):
        ledger.upsert_endpoint(origin=origin, method="GET", path_template=path)


def test_scope_accepts_in_scope(ledger):
    eid, created = ledger.upsert_endpoint(origin="https://app.lab.test", method="GET", path_template="/api/x/{id}")
    assert created


def test_unconfigured_engagement_refuses_everything(eng, clock):
    from bbh.config import parse_prompt_text
    from bbh.ledger import Ledger
    L = Ledger(eng, now=clock)
    L.sync_engagement(parse_prompt_text("# Target brief\n- **Asset:** `<name>`\n"))
    with pytest.raises(LedgerError) as e:
        L.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/x")
    assert "prompt.md is not filled" in str(e.value)


# --- Invariant 7: hedge text ------------------------------------------------------------------------------------

@pytest.mark.parametrize("word", ["maybe", "might", "probably", "likely", "possibly", "potential", "seems",
                                  "appears to", "could", "may allow", "theoretically", "should be"])
def test_hedge_words_rejected_in_observation(ledger, endpoint, cap, word):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    with pytest.raises(ValueError) as e:
        ledger.record_case(cell_id=cid, case_no=1, technique="htmli.a.v", outcome="negative",
                           observation=f"the filter {word} strip it", request_capture=cap, response_capture=cap)
    assert "State what the response showed, with the capture filename." in str(e.value)


def test_hedge_words_rejected_in_reason_note_and_finding(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    with pytest.raises(ValueError):
        ledger.close_cell(cid, "blocked", reason="other", unblock="this might work later")
    with pytest.raises(ValueError):
        ledger.release_cell(cid, "probably nothing here")
    ledger.record_case(cell_id=cid, case_no=1, technique="htmli.tag.b", outcome="positive",
                       observation="<b> rendered (captures/c.http)", request_capture=cap, response_capture=cap)
    with pytest.raises(ValueError):
        ledger.open_finding(cell_id=cid, rung="tag_renders", assertion=ASSERTION, title="Potential HTML injection", severity="low")


# --- state vocabulary, append-only, claims ---------------------------------------------------------------------

def test_no_free_text_states(ledger, endpoint):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    for bad in ("skipped", "unlikely", "probably_safe", "tested"):
        with pytest.raises(sqlite3.DatabaseError):
            ledger.conn.execute("UPDATE cells SET state = ? WHERE id = ?", (bad, cid))
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "skipped")


def test_events_and_cases_are_append_only(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.record_case(cell_id=cid, case_no=1, technique="htmli.a.v", outcome="negative",
                       observation="200 encoded (captures/c.http)", request_capture=cap, response_capture=cap)
    for sql in ("UPDATE events SET kind = 'x'", "DELETE FROM events",
                "UPDATE test_cases SET outcome = 'positive'", "DELETE FROM test_cases", "DELETE FROM cells"):
        with pytest.raises(sqlite3.DatabaseError):
            ledger.conn.execute(sql)


def test_claims_expire_after_30_minutes(ledger, endpoint, clock):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.claim_cell(cid, "tester-1")
    assert ledger.cell(cid)["state"] == "in_progress"
    clock.advance(CLAIM_TTL_S - 5)
    assert ledger.expire_claims() == 0
    clock.advance(10)
    assert ledger.expire_claims() == 1
    assert ledger.cell(cid)["state"] == "open" and ledger.cell(cid)["claimed_by"] is None


def test_n_a_requires_enum_reason_and_real_request(ledger, endpoint):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="sqli")[0]
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "n_a", reason="looks safe", reason_request_id=1)
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "n_a", reason="no_datastore_reach", reason_request_id=999)
    with pytest.raises(LedgerError):  # not a valid n_a reason for sqli
        ledger.close_cell(cid, "n_a", reason="no_file_input", reason_request_id=1)
    rid, _ = ledger.add_request(source="sender", method="GET", url="http://127.0.0.1:5057/search", host="127.0.0.1",
                                raw_path=None, content_hash="h2")
    assert ledger.close_cell(cid, "n_a", reason="no_datastore_reach", reason_request_id=rid)["state"] == "n_a"


def test_blocked_requires_reason_and_unblock(ledger, endpoint):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "blocked", reason="no_second_account")
    with pytest.raises(LedgerError):
        ledger.close_cell(cid, "blocked", reason="busy", unblock="later")
    assert ledger.close_cell(cid, "blocked", reason="no_second_account", unblock="create Account B via signup")["state"] == "blocked"


# --- class-specific minimums --------------------------------------------------------------------------------------

def test_sqli_needs_time_bool_and_timing_control(ledger, endpoint, cap):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="sqli")[0]
    fill_negative(ledger, cid, cap, klass="sqli", families=("err", "union", "stack", "quote", "comment"), n=12)
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    text = " ".join(e.value.missing)
    assert "sqli.bool" in text and "sqli.time" in text


def test_sqli_sort_parameter_requires_orderby_family(ledger, endpoint, cap):
    eid, _ = endpoint
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="sort", location="query", sample_value="name")
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="sqli", context={"orderby": True})[0]
    fill_negative(ledger, cid, cap, klass="sqli", families=("bool", "time", "err", "quote", "comment"), n=12)
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    assert any("sqli.orderby" in m for m in e.value.missing)
    for k, fam in ((40, "orderby"),):
        ledger.record_case(cell_id=cid, case_no=k, technique=f"sqli.{fam}.case", outcome="negative",
                           observation="ordering unchanged (captures/c.http)", request_capture=cap, response_capture=cap)
    assert ledger.close_cell(cid, "negative")["state"] == "negative"


def test_idor_write_cases_need_counter_reads(ledger, cap):
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="POST", path_template="/api/notes/{id}")
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="id", location="path", sample_value="7")
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="idor_write")[0]
    fill_negative(ledger, cid, cap, klass="idor_write", families=("cross", "method", "format", "pollution", "role"), n=10)
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    assert any("counter-read" in p for p in ledger.evidence_status(cid)["problems"])
    fill_negative(ledger, cid, cap, klass="idor_write", families=("cross", "method", "format", "pollution", "role"), n=10, counter=True)
    assert ledger.close_cell(cid, "negative")["state"] == "negative"


def test_ssrf_cannot_go_negative_without_oob(ledger, cap):
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/fetch")
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="url", location="query", sample_value="https://x.test")
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="ssrf")[0]
    fill_negative(ledger, cid, cap, klass="ssrf", families=("oob", "redir", "enc", "scheme", "port"), n=10)
    with pytest.raises(LedgerError) as e:
        ledger.close_cell(cid, "negative")
    assert any("no_oob_listener" in m for m in e.value.missing)
    assert ledger.close_cell(cid, "blocked", reason="no_oob_listener", unblock="set OOB callback in prompt.md")["state"] == "blocked"


# --- triage and depth --------------------------------------------------------------------------------------------------

def _verified_finding(ledger, endpoint, cap, clock):
    eid, iid = endpoint
    cid = ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")[0]
    ledger.record_case(cell_id=cid, case_no=1, technique="htmli.tag.b", outcome="positive",
                       observation="<b> rendered raw (captures/c.http)", request_capture=cap, response_capture=cap)
    return _confirm(ledger, clock, cid, "tag_renders", cap)


def test_triage_three_rejects_kill_and_accept_gates(ledger, endpoint, cap, clock, eng):
    f = _verified_finding(ledger, endpoint, cap, clock)
    with pytest.raises(LedgerError):
        ledger.record_triage(f["id"], "ACCEPT", None, None)  # no report yet
    (eng.root / "report-1.md").write_text("# r", encoding="utf-8")
    ledger.set_report(f["id"], str(eng.root / "report-1.md"), 1)
    with pytest.raises(LedgerError):
        ledger.record_triage(f["id"], "REJECT", "no impact", "")  # a reject must name the evidence
    for i in range(2):
        f = ledger.record_triage(f["id"], "REJECT", "no gain no loss", "show B's data in A's response")
        assert f["status"] == "verified"
    f = ledger.record_triage(f["id"], "REJECT", "no gain no loss", "show B's data in A's response")
    assert f["status"] == "killed"


def test_triage_accept_gates(ledger, endpoint, cap, clock, eng):
    f = _verified_finding(ledger, endpoint, cap, clock)
    (eng.root / "report-1.md").write_text("# r", encoding="utf-8")
    ledger.set_report(f["id"], str(eng.root / "report-1.md"), 1)
    assert ledger.record_triage(f["id"], "ACCEPT", None, None)["status"] == "gated"


def test_model_depth_items_need_a_test_plan(ledger):
    with pytest.raises(LedgerError):
        ledger.add_depth_item(kind=8, title="maybe the export leaks", source="model")
    with pytest.raises(ValueError):
        ledger.add_depth_item(kind=8, title="export might leak", source="model", test_plan="send export as B")
    did, created = ledger.add_depth_item(kind=8, title="export endpoint scoping", source="model",
                                         test_plan="GET /api/export without owner_id as A; count rows not owned by A")
    assert created
    _, again = ledger.add_depth_item(kind=8, title="export endpoint scoping", source="model", test_plan="x y z")
    assert not again
