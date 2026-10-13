"""Mutation ops on the wire format, and condition evaluation."""

import json

import pytest

from bbh.evaluate import EvalContext, evaluate, location_host
from bbh.httpraw import Exchange, Request, Response, parse_request
from bbh.mutate import InputRef, apply, quote_value

BASE = parse_request(b"GET /search?q=hello&lang=en HTTP/1.1\r\nHost: 127.0.0.1:5057\r\nCookie: s=1; theme=dark\r\n\r\n", default_scheme="http")
JSON = parse_request(b'POST /api/login HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\n\r\n{"username":"alice","password":"pw","meta":{"tags":["a"]}}', default_scheme="http")
FORM = parse_request(b"POST /login HTTP/1.1\r\nHost: x\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nusername=alice&password=p%2Bw&next=%2Fhome", default_scheme="http")


def test_quote_value_preserves_existing_escapes():
    assert quote_value("<b>") == "%3Cb%3E"
    assert quote_value("%0d%0aX: y") == "%0d%0aX%3A%20y"
    assert quote_value("%253C") == "%253C"
    assert quote_value("100%") == "100%25"
    assert quote_value("a b#c", raw=True) == "a%20b%23c"


def test_untouched_parameters_keep_their_wire_bytes():
    r, _ = apply(FORM, [{"op": "set_input", "value": "x"}], InputRef("username", "form"))
    assert r.body == b"username=x&password=p%2Bw&next=%2Fhome"


def test_json_paths_and_operator_injection():
    r, _ = apply(JSON, [{"op": "set_input_json", "value": {"$ne": None}}], InputRef("password", "json", "password"))
    assert json.loads(r.body)["password"] == {"$ne": None}
    r, _ = apply(JSON, [{"op": "set_input", "value": "x"}], InputRef("meta.tags[0]", "json", "meta.tags[0]"))
    assert json.loads(r.body)["meta"]["tags"] == ["x"]
    r, _ = apply(FORM, [{"op": "set_input_json", "value": {"$ne": ""}}], InputRef("password", "form"))
    assert b"password[$ne]=" in r.body and b"password=p" not in r.body


def test_pollution_move_remove_and_principal_ops():
    r, _ = apply(BASE, [{"op": "duplicate_input", "value": "7", "position": "before"}], InputRef("q", "query"))
    assert r.url.endswith("?q=7&q=hello&lang=en")
    r, _ = apply(BASE, [{"op": "remove_input"}], InputRef("q", "query"))
    assert "q=" not in r.url
    r, _ = apply(BASE, [{"op": "move_input", "to": "header"}], InputRef("q", "query"))
    assert r.header("q") == "hello" and "q=" not in r.url
    r, p = apply(BASE, [{"op": "as_principal", "principal": "B"}], InputRef("q", "query"))
    assert p == "B"
    r, p = apply(BASE, [{"op": "strip_auth"}], InputRef("q", "query"))
    assert p == "unauth" and r.header("Cookie") is None


def test_content_type_swap_keeps_json_for_text_plain_and_reencodes_form():
    r, _ = apply(JSON, [{"op": "set_content_type", "value": "text/plain"}], InputRef(None, None))
    assert r.header("Content-Type") == "text/plain" and json.loads(r.body)["username"] == "alice"
    r, _ = apply(JSON, [{"op": "set_content_type", "value": "application/x-www-form-urlencoded"}], InputRef(None, None))
    assert r.body.startswith(b"username=alice&password=pw")


def test_placeholder_substitution_hook():
    r, _ = apply(BASE, [{"op": "set_input", "value": "{{OOB}}x"}], InputRef("q", "query"),
                 substitute=lambda v: v.replace("{{OOB}}", "http://k3.oob.test/") if isinstance(v, str) else v)
    assert "k3.oob.test" in r.url


# --- evaluate -----------------------------------------------------------------------------------

def ex(status=200, body="", headers=None, ms=50, url="http://x/a"):
    return Exchange(request=Request("GET", url), response=Response(status, "OK", headers or [], body.encode()), elapsed_ms=ms)


def test_body_conditions_over_repeats():
    ctx = EvalContext(this_case=1, exchanges={1: [ex(body="<b>k1</b>"), ex(body="<b>k1</b>")]})
    assert evaluate({"type": "body_contains", "value": "<b>k1</b>"}, ctx)[0] is True
    ctx.exchanges[1].append(ex(body="&lt;b&gt;k1"))
    assert evaluate({"type": "body_contains", "value": "<b>k1</b>"}, ctx)[0] is False  # every repeat must hold


def test_timing_against_baseline_median_and_proportionality():
    ctx = EvalContext(this_case=2, exchanges={0: [ex(ms=80), ex(ms=120), ex(ms=100)], 1: [ex(ms=2100)] * 3, 2: [ex(ms=4150)] * 3})
    assert evaluate({"type": "elapsed_over_baseline", "min_ms": 3600, "baseline_case": 0}, ctx)[0] is True
    assert evaluate({"type": "elapsed_over_case", "case": 1, "min_ms": 1500}, ctx)[0] is True
    ctx.exchanges[2] = [ex(ms=4150), ex(ms=150), ex(ms=4100)]
    assert evaluate({"type": "elapsed_over_baseline", "min_ms": 3600, "baseline_case": 0}, ctx)[0] is False


def test_min_len_gates_on_a_referenced_case_body():
    # min_len on the authenticated control (case 0): empty control -> not a verdict pass; real body -> pass.
    empty = EvalContext(this_case=1, exchanges={0: [ex(body="")], 1: [ex(body="")]})
    assert evaluate({"type": "min_len", "case": 0, "min": 8}, empty)[0] is False
    data = EvalContext(this_case=1, exchanges={0: [ex(body='{"balance":12345}')], 1: [ex(body='{"balance":12345}')]})
    assert evaluate({"type": "min_len", "case": 0, "min": 8}, data)[0] is True
    assert evaluate({"type": "min_len", "case": 5, "min": 8}, data)[0] is None  # missing case -> no verdict


def test_unauth_replay_read_is_not_positive_on_an_empty_200_control():
    # The real false-positive shape: an anonymous beacon returns an empty 200 with and without auth.
    # same_as_case(0) is vacuously true, but min_len(case 0) must defeat it so no candidate is raised.
    from bbh.cases import generate
    from bbh.cases.base import Ctx
    cases = generate(Ctx(cell_id=1, vuln_class="unauth_replay", salt="s", method="POST", url="http://x/_api/a/log",
                         path_template="/_api/a/log", flags={"state_changing": True}, body_kind="json",
                         acting_principal="A"), strict=False)
    read = next(c for c in cases if c.technique == "unauth_replay.strip.full")
    empty = EvalContext(this_case=read.case_no, exchanges={0: [ex(status=200, body="")], read.case_no: [ex(status=200, body="")]})
    assert evaluate(read.positive, empty)[0] is False
    leak = ex(status=200, body='{"ssn":"900101-1234","name":"Bob"}')
    data = EvalContext(this_case=read.case_no, exchanges={0: [leak], read.case_no: [leak]})
    assert evaluate(read.positive, data)[0] is True


def test_boolean_pair():
    ctx = EvalContext(this_case=2, exchanges={0: [ex(body="x" * 500)], 1: [ex(body="x" * 502)], 2: [ex(body="x" * 40)]})
    cond = {"type": "all", "of": [{"type": "same_as_case", "a": 1, "case": 0, "max_len_diff": 5},
                                  {"type": "len_diff", "a": "this", "b": 1, "min_bytes": 20}]}
    assert evaluate(cond, ctx)[0] is True
    ctx.exchanges[2] = [ex(body="x" * 499)]
    assert evaluate(cond, ctx)[0] is False


@pytest.mark.parametrize("loc,host", [
    ("https://lab.test@evil.test/", "evil.test"), ("//evil.test", "evil.test"), ("https:/\\evil.test", "evil.test"),
    ("/\\/evil.test", "evil.test"), ("/home", "x"), ("https://lab.test.evil.test", "lab.test.evil.test"),
    ("https://evil.test%23@lab.test", "lab.test"), (" \thttps://evil.test", "evil.test"),
])
def test_location_host_is_browser_like(loc, host):
    assert location_host(loc, "http://x/redirect") == host


def test_manual_and_missing_inputs_are_none():
    ctx = EvalContext(this_case=1, exchanges={1: [ex()]})
    assert evaluate({"type": "manual", "describe": "diff vs UI"}, ctx)[0] is None
    assert evaluate({"type": "counter_read_contains", "value": "x"}, ctx)[0] is None
    assert evaluate({"type": "browser_marker", "token": "k"}, ctx)[0] is None


def test_matches_base():
    base = ex(body="x" * 1000)
    ctx = EvalContext(this_case=0, exchanges={0: [ex(body="x" * 1100)]}, base=base)
    assert evaluate({"type": "matches_base"}, ctx)[0] is True
    ctx.exchanges[0] = [ex(status=302, body="")]
    assert evaluate({"type": "matches_base"}, ctx)[0] is False
