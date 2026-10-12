"""Regression tests for the Rule-0 / scope fixes from the adversarial review."""

import httpx
import pytest

from bbh import guard
from bbh.httpraw import parse_request
from bbh.mutate import InputRef, apply
from bbh.sender import Sender, LockedError

from test_sender import make_sender, req


KNOWN = {"alice@lab.test", "1", "alice"}


# --- C1: own data keyed by an owner field is NOT third-party --------------------------------

def test_c1_own_email_in_owner_field_not_foreign():
    rows = [{"id": 1, "owner": "alice@lab.test"}, {"id": 2, "created_by": "alice@lab.test"}]
    import json
    g = guard.scan(json.dumps(rows), KNOWN, known_ids={"1", "2"})
    assert not g.third_party, g.proving_field


def test_c1_own_handle_in_owner_field_not_foreign():
    import json
    g = guard.scan(json.dumps([{"id": 1, "created_by": "alice"}]), KNOWN, known_ids={"1"})
    assert not g.third_party


def test_c1_foreign_owner_email_still_caught():
    import json
    g = guard.scan(json.dumps([{"id": 9, "owner": "carol@lab.test"}]), KNOWN, known_ids={"1"})
    # detected, and the proving field is MASKED (Rule 0 keeps only one masked field)
    assert g.third_party and g.proving_field.startswith("owner=c***@") and "carol@lab.test" not in g.proving_field


def test_c1_foreign_owner_id_still_caught():
    import json
    g = guard.scan(json.dumps([{"id": 9, "owner_id": 999}]), KNOWN, known_ids={"1"})
    assert g.third_party


# --- C2: third-party data in headers ------------------------------------------------------

def test_c2_header_email_detected():
    g = guard.scan("ok", KNOWN, header_text="X-Owner-Email: victim@real.test\nLocation: /u?e=victim@real.test")
    assert g.third_party and "header" in g.proving_field


def test_c2_header_email_scrubbed_from_capture(ledger, eng):
    s, _ = make_sender(ledger, lambda r: httpx.Response(200, text="ok",
                        headers={"X-Owner-Email": "victim@real.test", "Location": "/u?e=leak@real.test"}))
    res = s.send(req(), principal="unauth", capture="captures/h/1.http", cell_id=1, case_no=1, technique="info_leak.x.y")
    assert res.redacted and res.guard.third_party
    text = (eng.root / res.capture).read_text(encoding="utf-8", errors="replace")
    assert "victim@real.test" not in text and "leak@real.test" not in text


# --- C3 is a hook test (test_hooks.py); here the guard/sender pieces it relies on ---------

def test_s2_nested_rows_detected():
    import json
    body = json.dumps({"data": {"rows": [{"owner_id": 1}, {"owner_id": 999}]}})
    g = guard.scan(body, KNOWN, known_ids={"1"})
    assert g.third_party


def test_s3_single_foreign_record_locks_endpoint(ledger, eng):
    s, _ = make_sender(ledger, lambda r: httpx.Response(200, json=[{"id": 1, "owner_email": "carol@lab.test"}]))
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/api/x")
    r = req("http://127.0.0.1:5057/api/x")
    res = s.send(r, principal="unauth", endpoint_id=eid, vuln_class="info_leak", capture="captures/s3/1.http")
    assert res.redacted and ledger.endpoint(eid)["third_party_lock"] == 1
    with pytest.raises(LockedError):
        s.send(req("http://127.0.0.1:5057/api/x?page=2"), principal="unauth", endpoint_id=eid)


# --- S5: standalone strip_auth removes custom auth headers --------------------------------

def test_s5_strip_auth_removes_custom_headers():
    base = parse_request(b"GET /x HTTP/1.1\r\nHost: h\r\nCookie: s=1\r\nAuthorization: Bearer t\r\n"
                         b"X-Api-Key: k\r\nX-Csrf-Token: c\r\nX-Amz-Security-Token: z\r\nAccept: */*\r\n\r\n",
                         default_scheme="http")
    out, principal = apply(base, [{"op": "strip_auth"}], InputRef(None, None))
    assert principal == "unauth"
    names = {k.lower() for k, _ in out.headers}
    assert not ({"cookie", "authorization", "x-api-key", "x-csrf-token", "x-amz-security-token"} & names)
    assert "accept" in names  # non-auth headers survive
