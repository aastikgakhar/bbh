"""The scope grammar/refusals and the planner rule table."""

import pytest

from bbh import classes as C
from bbh.planner import plan
from bbh.scope import Scope, ScopeError, split_url


# --- scope grammar -----------------------------------------------------------------------

def S(inc, exc=None):
    return Scope.from_lists(inc, exc or [])


@pytest.mark.parametrize("pat,url,ok", [
    ("example.com", "https://example.com/x", True),
    ("example.com", "https://sub.example.com/x", False),       # apex pattern, not wildcard
    ("*.example.com", "https://a.example.com/x", True),
    ("*.example.com", "https://example.com/x", False),         # wildcard excludes apex
    ("*.example.com", "https://a.b.example.com/x", True),
    ("example.com:8443", "https://example.com:8443/x", True),
    ("example.com:8443", "https://example.com/x", False),      # wrong port
    ("https://example.com/app", "https://example.com/app/y", True),
    ("https://example.com/app", "https://example.com/other", False),
    ("10.0.0.0/24", "http://10.0.0.5:8080/x", True),
    ("10.0.0.0/24", "http://10.0.1.5/x", False),
    ("127.0.0.1:5057", "http://127.0.0.1:5057/x", True),
])
def test_scope_matching(pat, url, ok):
    assert S([pat]).in_scope(url) is ok


def test_exclude_wins_over_include():
    sc = S(["*.example.com"], ["admin.example.com"])
    assert sc.in_scope("https://app.example.com/") and not sc.in_scope("https://admin.example.com/")


@pytest.mark.parametrize("url", [
    "https://good.test\\@evil.test/",        # backslash in authority
    "https://good.test\t/",                  # control char
    "https://a@b@evil.test/",                # two '@'
    "ftp://good.test/",                      # non-http scheme
    "https:// good.test/",                   # space
])
def test_ambiguous_or_bad_urls_refused(url):
    with pytest.raises(ScopeError):
        split_url(url)


def test_empty_scope_refuses_everything():
    assert not Scope.from_lists([]).in_scope("https://anything.test/")


def test_userinfo_host_resolves_to_real_host():
    sc = S(["app.test"])
    # the host is evil.test, not app.test, despite the userinfo
    assert not sc.in_scope("https://app.test@evil.test/")


def test_prose_out_of_scope_kept_as_notes():
    sc = Scope.from_text("*.example.com", "the marketing site, status.example.com")
    assert "status.example.com" in [p.raw for p in sc.exclude]
    assert any("marketing" in n for n in sc.unparsed_exclude)


# --- planner rules -----------------------------------------------------------------------

@pytest.fixture
def L(ledger):
    return ledger


def _ep(L, method, path, body=b"", ctype=None):
    from bbh.httpraw import Request
    from bbh.ingest import record_exchange
    from bbh.httpraw import Exchange, Response
    headers = [("Host", "127.0.0.1:5057")]
    if ctype:
        headers.append(("Content-Type", ctype))
    req = Request(method, f"http://127.0.0.1:5057{path}", headers=headers, body=body)
    rid = record_exchange(L, Exchange(req, Response(200, "OK", [("Content-Type", "application/json")], b"{}")), source="import")
    return L.request(rid)["endpoint_id"]


def classes_opened(L, eid):
    return {r["vuln_class"] for r in L.q("SELECT vuln_class FROM cells WHERE endpoint_id=?", (eid,))}


def test_object_id_opens_idor_and_injection(L):
    eid = _ep(L, "GET", "/api/notes/7")
    plan(L, eid)
    opened = classes_opened(L, eid)
    assert {"idor_read", "sqli", "nosqli", "unauth_replay", "info_leak"} <= opened


def test_state_changing_opens_csrf_family(L):
    eid = _ep(L, "POST", "/api/settings", body=b'{"a":1}', ctype="application/json")
    plan(L, eid)
    opened = classes_opened(L, eid)
    assert {"csrf", "method_swap", "mass_assignment", "content_type_swap"} <= opened


def test_list_endpoint_opens_mass_dump(L):
    eid = _ep(L, "GET", "/api/items?owner_id=1")
    plan(L, eid)
    assert "mass_dump" in classes_opened(L, eid)


def test_url_shaped_input_opens_redirect_and_ssrf(L):
    eid = _ep(L, "GET", "/go?next=https://x.test/a")
    plan(L, eid)
    assert {"open_redirect", "ssrf"} <= classes_opened(L, eid)


def test_sort_param_marks_orderby(L):
    eid = _ep(L, "GET", "/products?sort=name")
    plan(L, eid)
    cell = L.q1("SELECT c.context_json FROM cells c JOIN inputs i ON i.id=c.input_id WHERE c.vuln_class='sqli' AND i.name='sort' AND c.endpoint_id=?", (eid,))
    import json
    assert json.loads(cell["context_json"]).get("orderby") is True


def test_login_csrf_closed_programme_excluded(L):
    eid = _ep(L, "POST", "/login", body=b"u=a&p=b", ctype="application/x-www-form-urlencoded")
    plan(L, eid)
    cell = L.q1("SELECT state, reason FROM cells WHERE endpoint_id=? AND vuln_class='csrf'", (eid,))
    assert cell["state"] == "n_a" and cell["reason"] == "programme_excluded"


def test_family_once_classes_open_on_first_endpoint_only(L):
    e1 = _ep(L, "GET", "/api/a/1")       # template /api/a/{id}, family /api/a
    e2 = _ep(L, "GET", "/api/a")         # template /api/a, same family, different endpoint
    assert e1 != e2
    plan(L, e1)
    plan(L, e2)
    # cors/cache are family-once: opened on the family's first planned endpoint, not the second
    assert "cors" in classes_opened(L, e1)
    assert "cors" not in classes_opened(L, e2)


def test_plan_is_idempotent(L):
    eid = _ep(L, "GET", "/api/notes/7")
    plan(L, eid)
    n1 = L.q1("SELECT COUNT(*) c FROM cells WHERE endpoint_id=?", (eid,))["c"]
    plan(L, eid)
    n2 = L.q1("SELECT COUNT(*) c FROM cells WHERE endpoint_id=?", (eid,))["c"]
    assert n1 == n2 and n1 > 0


def test_every_class_has_a_recipe_and_na_reasons():
    for name, vc in C.CLASSES.items():
        assert vc.recipe in C.RECIPES, name
        assert vc.na_reasons, name
        assert vc.min_rung in vc.ladder, name
