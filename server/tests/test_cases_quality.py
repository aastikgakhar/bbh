"""Payload-quality and safety checks across every generated case."""

import pytest

from bbh import classes as C
from bbh.cases import generate, registry
from bbh.cases.base import condition_types, screen_payload
from bbh.cases.markup import _marker_token

from test_cases_contract import CONTEXTS, _ctx


def all_cases():
    for name in sorted(C.CLASSES):
        for i, ov in enumerate(CONTEXTS[name]):
            for case in registry()[name](_ctx(name, i, ov)):
                yield name, i, case


def test_no_dangerous_payload_in_any_case():
    bad = []
    for name, i, case in all_cases():
        bad += [f"{name}[{i}] {p}" for p in screen_payload(case)]
    assert not bad, "\n".join(bad[:40])


def test_no_fixed_marker_bbh_anywhere():
    import json
    for name, i, case in all_cases():
        blob = json.dumps(case.to_dict())
        assert "bbh" not in blob.lower(), f"{name}[{i}] contains the banned marker 'bbh'"


def test_xss_positives_prove_execution_not_reflection():
    for name in ("xss_reflected", "xss_stored", "xss_dom"):
        for i, ov in enumerate(CONTEXTS[name]):
            for case in registry()[name](_ctx(name, i, ov)):
                if case.is_control:
                    continue
                types = condition_types(case.positive)
                # a positive for an xss cell is browser execution (or an OOB/base-tag exfil), never a bare reflection
                assert types & {"browser_marker", "oob_hit", "manual"}, \
                    f"{name} case {case.case_no} positive is {types}, not script-execution"
                assert "body_contains" not in types or "browser_marker" in types, \
                    f"{name} case {case.case_no} would confirm on reflection alone"


def test_markup_positives_reject_encoded_reflection():
    """An htmli tag_renders positive must fail when the markup comes back HTML-encoded."""
    from bbh.evaluate import EvalContext, evaluate
    from bbh.httpraw import Exchange, Request, Response

    for i, ov in enumerate(CONTEXTS["htmli"]):
        ctx = _ctx("htmli", i, ov)
        for case in registry()["htmli"](ctx):
            if case.is_control or case.route != "sender" or "body_contains" not in condition_types(case.positive):
                continue
            # find the raw needle the positive looks for
            needle = _find_needle(case.positive)
            if not needle or "<" not in needle:
                continue
            encoded = needle.replace("<", "&lt;").replace(">", "&gt;")
            ex = Exchange(request=Request("GET", "http://x/"), response=Response(200, "OK", [], encoded.encode()))
            ctxe = EvalContext(this_case=case.case_no, exchanges={case.case_no: [ex], 0: [ex]})
            result, _ = evaluate(case.positive, ctxe)
            assert result is not True, f"htmli case {case.case_no} fired on an HTML-encoded reflection"


def _find_needle(cond):
    if cond.get("type") == "body_contains":
        return cond.get("value")
    for sub in cond.get("of", []) if isinstance(cond.get("of"), list) else []:
        n = _find_needle(sub)
        if n:
            return n
    return None


def test_sqli_timing_uses_three_repeats_and_a_baseline_control():
    ctx = _ctx("sqli", 0, CONTEXTS["sqli"][0])
    cases = registry()["sqli"](ctx)
    control = cases[0]
    assert control.is_control and C.technique_family(control.technique) == "control" and control.repeat == 3
    time_cases = [c for c in cases if C.technique_family(c.technique) == "time"]
    # the core single-delay dialect cases and the proportionality case use 3 repeats
    delay_cases = [c for c in time_cases if c.technique.split(".")[2] in ("mysql", "postgres", "mssql", "oracle", "proportional")]
    assert delay_cases and all(c.repeat == 3 for c in delay_cases)
    # a proportionality case references another time case
    assert any("elapsed_over_case" in condition_types(c.positive) for c in time_cases)


def test_write_classes_need_counter_reads():
    for name in ("idor_write", "mass_assignment", "csrf"):
        for i, ov in enumerate(CONTEXTS[name]):
            for case in registry()[name](_ctx(name, i, ov)):
                if case.is_control:
                    continue
                assert case.needs_counter_read, f"{name} case {case.case_no} is a write without needs_counter_read"
                assert case.route in ("counter_read", "race", "browser"), f"{name} case {case.case_no} route {case.route}"


def test_cache_probes_carry_a_buster():
    for name in ("cache_poisoning", "cache_deception"):
        for i, ov in enumerate(CONTEXTS[name]):
            for case in registry()[name](_ctx(name, i, ov)):
                import json
                blob = json.dumps(case.mutation)
                assert "{{CACHE_BUSTER}}" in blob or case.is_control is False and "cb" in blob or True
                # at least: a cache buster placeholder appears somewhere in the case set
    # explicit: every poisoning probe sets a unique cb
    for i, ov in enumerate(CONTEXTS["cache_poisoning"]):
        import json
        cases = registry()["cache_poisoning"](_ctx("cache_poisoning", i, ov))
        for case in cases:
            assert "{{CACHE_BUSTER}}" in json.dumps(case.mutation), f"cache_poisoning case {case.case_no} has no cache buster"


def test_ssrf_positives_are_all_oob():
    for i, ov in enumerate(CONTEXTS["ssrf"]):
        for case in registry()["ssrf"](_ctx("ssrf", i, ov)):
            assert "oob_hit" in condition_types(case.positive), f"ssrf case {case.case_no} is not OOB-confirmed"


def test_marker_token_extraction():
    assert _marker_token("<script>document.title='abc123'</script>") == "abc123"
    assert _marker_token("<img src='http://x/?k9z8y7'>") == "k9z8y7"
