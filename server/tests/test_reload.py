"""Reload-safety: the stale-server detector (the field report's #1 pain).

A long-running server runs the code it imported; a hand edit or a fresh detached
worker can leave it executing old code that silently stalls every plan. These
prove the three guards: a disk fingerprint, a loud (never-negative) unknown
condition, and status() surfacing staleness so the agent reloads or restarts.
"""

from bbh import codehash
from bbh.evaluate import EvalContext, evaluate


def test_fingerprint_is_stable_and_hex():
    a = codehash.fingerprint()
    b = codehash.fingerprint()
    assert a == b and len(a) == 16 and all(c in "0123456789abcdef" for c in a)


def test_unknown_condition_is_loud_and_never_a_negative():
    r, detail = evaluate({"type": "no_such_condition_xyz"}, EvalContext(this_case=0))
    assert r is None  # None is inconclusive, never a negative: stale code can't fabricate a close
    assert detail.startswith("UNKNOWN_CONDITION") and "stale" in detail.lower()


def test_status_surfaces_stale_code(eng, monkeypatch):
    import bbh.server as srv

    srv._LEDGER = None  # rebuild against the eng fixture's engagement dir
    monkeypatch.setattr(srv, "_LOADED_FP", "0000deadbeef0000")  # pretend the server loaded other code
    out = srv.status()
    assert out["code"]["disk"] == codehash.fingerprint()
    assert out["code"]["stale"] is True
    assert any("STALE" in w for w in out.get("warnings", []))
    srv._LEDGER = None  # don't leak the tmp ledger into other tests
