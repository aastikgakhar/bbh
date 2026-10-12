"""Layer 4: the sender. No network: httpx.MockTransport stands in for the target."""

import json
import threading

import httpx
import pytest

from bbh.httpraw import parse_request, read_capture
from bbh.ledger import Ledger
from bbh.ratelimit import MAX_BURST, RateLimiter
from bbh.scope import ScopeError
from bbh.sender import KillSwitchError, LockedError, NoSessionError, Sender


class FakeTime:
    def __init__(self):
        self.t = 1_800_000_000.0
        self.sleeps = []
        self.lock = threading.Lock()

    def clock(self):
        with self.lock:
            return self.t

    def sleep(self, s):
        with self.lock:
            self.sleeps.append(s)
            self.t += s


def req(url="http://127.0.0.1:5057/search?q=hi", method="GET", headers=None, body=b""):
    raw = f"{method} {url.split('5057', 1)[1] or '/'} HTTP/1.1\r\nHost: 127.0.0.1:5057\r\n"
    for k, v in (headers or {}).items():
        raw += f"{k}: {v}\r\n"
    r = parse_request(raw.encode() + b"\r\n" + body, default_scheme="http")
    return r


def make_sender(ledger, handler, ft=None):
    ft = ft or FakeTime()
    return Sender(ledger, transport=httpx.MockTransport(handler), clock=ft.clock, sleep=ft.sleep, proxy=None), ft


def ok_handler(request):
    return httpx.Response(200, text="<html>ok " + request.url.params.get("q", "") + "</html>", headers={"Content-Type": "text/html"})


# --- scope and kill switch --------------------------------------------------------------------

@pytest.mark.parametrize("url", ["http://127.0.0.1:8080/x", "https://admin.lab.test/x", "https://evil.test/",
                                 "http://127.0.0.1:5057\\@evil.test/", "https://app.lab.test@evil.test/"])
def test_out_of_scope_is_a_hard_error_and_nothing_is_sent(ledger, url):
    calls = []
    s, _ = make_sender(ledger, lambda r: calls.append(r) or httpx.Response(200))
    r = req()
    r.url = url
    with pytest.raises(ScopeError):
        s.send(r, principal="unauth")
    assert calls == []


def test_kill_switch_refuses_every_send(ledger, eng):
    calls = []
    s, _ = make_sender(ledger, lambda r: calls.append(r) or httpx.Response(200))
    eng.stop_file.write_text("stop")
    with pytest.raises(KillSwitchError):
        s.send(req(), principal="unauth")
    with pytest.raises(KillSwitchError):
        s.send_burst(req(method="POST"), principal="unauth", n=5, capture_dir="captures/b")
    assert calls == []
    eng.stop_file.unlink()
    assert s.send(req(), principal="unauth").exchange.status == 200


def test_kill_switch_checked_again_after_the_rate_limit_wait(ledger, eng):
    calls = []
    ft = FakeTime()

    def sleeper(sec):
        ft.sleep(sec)
        eng.stop_file.write_text("stop")  # researcher hits the switch while we wait

    s = Sender(ledger, transport=httpx.MockTransport(lambda r: calls.append(r) or httpx.Response(200)),
               clock=ft.clock, sleep=sleeper, proxy=None)
    s.send(req(), principal="unauth")  # first send: no wait
    with pytest.raises(KillSwitchError):
        s.send(req(), principal="unauth")
    assert len(calls) == 1


# --- rate limiter -------------------------------------------------------------------------------

def test_rate_limit_never_exceeded(ledger):
    ft = FakeTime()
    rl = RateLimiter(ledger, 2.0, clock=ft.clock, sleep=ft.sleep)
    starts = [rl.wait("127.0.0.1") for _ in range(10)]
    gaps = [b - a for a, b in zip(starts, starts[1:])]
    assert all(g >= 0.5 - 1e-9 for g in gaps)


def test_rate_limit_shared_across_limiter_instances(ledger):
    """Two limiters (two testers, or two processes) on one ledger share one budget."""
    ft = FakeTime()
    a = RateLimiter(ledger, 2.0, clock=ft.clock, sleep=ft.sleep)
    b = RateLimiter(Ledger(ledger.paths, now=ft.clock), 2.0, clock=ft.clock, sleep=ft.sleep)
    starts = sorted([a.reserve("h"), b.reserve("h"), a.reserve("h"), b.reserve("h")])
    assert [round(y - x, 6) for x, y in zip(starts, starts[1:])] == [0.5, 0.5, 0.5]


def test_burst_reserves_its_slots_and_is_capped(ledger):
    ft = FakeTime()
    rl = RateLimiter(ledger, 2.0, clock=ft.clock, sleep=ft.sleep)
    s0 = rl.reserve("h", slots=20)
    s1 = rl.reserve("h")
    assert s1 - s0 == pytest.approx(10.0)  # 20 slots at 2/s are repaid before the next send
    with pytest.raises(ValueError):
        rl.reserve("h", slots=MAX_BURST + 1)


def test_burst_api_refuses_more_than_30(ledger):
    s, _ = make_sender(ledger, ok_handler)
    with pytest.raises(ValueError):
        s.send_burst(req(method="POST"), principal="unauth", n=31, capture_dir="captures/b")


def test_burst_sends_n_and_counts_against_the_limit(ledger):
    calls = []
    lock = threading.Lock()

    def h(r):
        with lock:
            calls.append(r)
        return httpx.Response(200, text="ok")
    s, ft = make_sender(ledger, h)
    res = s.send_burst(req(method="POST"), principal="unauth", n=20, capture_dir="captures/7/1-race.burst.x")
    assert len(res) == 20 and len(calls) == 20
    s.send(req(), principal="unauth")
    assert ft.sleeps and max(ft.sleeps) >= 20 * 0.05 - 1e-6  # rate 20/s from the test prompt: 20 slots = 1 s


def test_backoff_on_429_and_retry_after(ledger):
    n = {"c": 0}

    def h(r):
        n["c"] += 1
        return httpx.Response(429, headers={"Retry-After": "7"}, text="slow down")
    s, ft = make_sender(ledger, h)
    res = s.send(req(), principal="unauth")
    assert res.blocked.blocked and "429" in res.blocked.reason
    assert n["c"] == 3  # retried, then recorded as blocked
    assert s.limiter.penalty("127.0.0.1") >= 4
    assert any(x >= 7 for x in ft.sleeps)


@pytest.mark.parametrize("status,body", [
    (403, "<title>Attention Required! | Cloudflare</title>"),
    (403, "Access Denied ... Reference #18.2f3c"),
    (403, "Request unsuccessful. Incapsula incident ID"),
])
def test_waf_block_pages_are_inconclusive(ledger, status, body):
    s, _ = make_sender(ledger, lambda r: httpx.Response(status, text=body))
    res = s.send(req(), principal="unauth")
    assert res.blocked.blocked
    assert s.limiter.penalty("127.0.0.1") > 1


def test_standing_403_vs_browser_baseline_is_inconclusive(ledger):
    s, _ = make_sender(ledger, lambda r: httpx.Response(403, text="forbidden"))
    res = s.send(req(), principal="unauth", browser_baseline_status=200)
    assert res.blocked.blocked and "browser" in res.blocked.reason


def test_transport_errors_are_inconclusive_with_hedge_free_text(ledger):
    from bbh.hedge import find_hedges

    def h(r):
        raise httpx.ConnectError("[WinError 10061] No connection could be made because the target machine actively refused it")
    s, _ = make_sender(ledger, h)
    res = s.send(req(), principal="unauth")
    assert res.blocked.blocked and res.exchange.response is None
    assert not find_hedges(res.blocked.reason) and not find_hedges(res.exchange.error)


# --- capture fidelity ----------------------------------------------------------------------------

def test_capture_is_verbatim_and_large_bodies_are_kept(ledger, eng):
    big = "A" * 300_000 + "END"
    s, _ = make_sender(ledger, lambda r: httpx.Response(200, text=big, headers={"Content-Type": "text/plain", "X-Test": "1"}))
    r = req(method="POST", headers={"Content-Type": "application/json"}, body=b'{"a": 1}')
    res = s.send(r, principal="unauth", capture="captures/12/3-sqli.time.sleep.http", cell_id=12, case_no=3, technique="sqli.time.sleep")
    assert res.capture == "captures/12/3-sqli.time.sleep.http"
    ex = read_capture(eng.root / res.capture)
    assert ex.request.method == "POST" and ex.request.body == b'{"a": 1}'
    assert ex.response.status == 200 and ex.response.header("X-Test") == "1"
    assert ex.response.body.decode().endswith("END") and len(ex.response.body) == len(big)
    assert ex.meta["technique"] == "sqli.time.sleep" and ex.meta["case_no"] == 3
    assert ledger.request(res.request_id)["raw_path"] == res.capture


def test_no_default_user_agent_or_identifying_header(ledger):
    seen = {}

    def h(r):
        seen.update({k.lower(): v for k, v in r.headers.items()})
        return httpx.Response(200)
    s, _ = make_sender(ledger, h)
    s.send(req(), principal="unauth")
    assert "user-agent" not in seen
    assert not any("bbh" in (k + v).lower() for k, v in seen.items())


def test_marker_header_only_when_configured(eng, clock):
    from bbh.config import parse_prompt_text
    from conftest import PROMPT
    seen = []
    L = Ledger(eng, now=clock)
    L.sync_engagement(parse_prompt_text(PROMPT.replace("`none`\n## Login", "`X-HackerOne-Research: r1`\n## Login")))
    s, _ = make_sender(L, lambda r: seen.append(dict(r.headers)) or httpx.Response(200))
    s.send(req(), principal="unauth")
    assert seen[-1].get("x-hackerone-research") == "r1"


# --- principals ---------------------------------------------------------------------------------

def test_principal_session_material_applied_and_unauth_strips(ledger, eng):
    seen = []
    s, _ = make_sender(ledger, lambda r: seen.append(dict(r.headers)) or httpx.Response(200))
    (eng.captures / "session-A.txt").write_text("# A\nCookie: lab_session=AAA\nX-CSRF-Token: tokA\n")
    (eng.captures / "session-B.txt").write_text("Cookie: lab_session=BBB\n")
    r = req(headers={"Cookie": "lab_session=BBB; theme=dark", "X-CSRF-Token": "old"})
    s.send(r, principal="A")
    assert "lab_session=AAA" in seen[-1]["cookie"] and "theme=dark" in seen[-1]["cookie"]
    assert "BBB" not in seen[-1]["cookie"] and seen[-1]["x-csrf-token"] == "tokA"
    s.send(r, principal="unauth")
    assert "cookie" not in seen[-1] and "x-csrf-token" not in seen[-1]


def test_missing_session_material_is_refused(ledger):
    s, _ = make_sender(ledger, ok_handler)
    with pytest.raises(NoSessionError):
        s.send(req(), principal="A")
    # but a request captured from A itself may be replayed as A
    assert s.send(req(headers={"Cookie": "lab_session=AAA"}), principal="A", base_principal="A").exchange.status == 200


# --- Rule 0 ----------------------------------------------------------------------------------

def test_third_party_data_is_redacted_and_paging_refused(ledger, eng):
    rows = [{"id": 1, "owner_id": 1, "owner_email": "alice@lab.test", "name": "a"},
            {"id": 9, "owner_id": 3, "owner_email": "carol@lab.test", "name": "secret-of-carol"}]
    s, _ = make_sender(ledger, lambda r: httpx.Response(200, json=rows))
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/api/items")
    r = req("http://127.0.0.1:5057/api/items")
    res = s.send(r, principal="unauth", endpoint_id=eid, vuln_class="mass_dump", capture="captures/40/1-mass_dump.filter.absent.http")
    assert res.guard.third_party and res.guard.count == 1 and res.redacted
    text = (eng.root / res.capture).read_text(encoding="utf-8", errors="replace")
    assert "carol" not in text and "secret-of-carol" not in text and "records_outside_test_accounts" in text
    assert "carol" not in res.exchange.body_text
    assert ledger.endpoint(eid)["third_party_lock"] == 1
    with pytest.raises(LockedError):
        s.send(r, principal="unauth", endpoint_id=eid, vuln_class="mass_dump")
    with pytest.raises(LockedError):
        s.send(req("http://127.0.0.1:5057/api/items?page=2"), principal="unauth", endpoint_id=eid)


def test_role_addresses_and_test_accounts_are_not_third_party(ledger):
    s, _ = make_sender(ledger, lambda r: httpx.Response(200, text="contact support@lab.test or alice@lab.test"))
    res = s.send(req(), principal="unauth")
    assert not res.guard.third_party and not res.redacted
