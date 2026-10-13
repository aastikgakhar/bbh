"""The case-count and safety contract for every class generator (Layer 3)."""

import pytest

from bbh import classes as C
from bbh.cases import generate, registry
from bbh.cases.base import Ctx, TestCase, check_contract, screen_payload

# Representative contexts per class. Every generator must satisfy the contract in each.
CONTEXTS = {
    "htmli": [dict(contexts=["html_text"]), dict(contexts=["html_attr"]), dict(contexts=["html_text", "url"])],
    "htmli_stored": [dict(method="POST", body_kind="form", input_location="form", contexts=["html_text"],
                          extra={"render_endpoint": "GET /people", "viewer": "B"})],
    "xss_reflected": [dict(contexts=["html_text"]), dict(contexts=["html_attr"]), dict(contexts=["js_string"]),
                      dict(contexts=["js_block"]), dict(contexts=["url"]), dict(contexts=["html_text"], csp="script-src 'self'")],
    "xss_stored": [dict(method="POST", body_kind="json", input_location="json", json_path="bio", contexts=["html_text"],
                        extra={"render_endpoint": "GET /people", "viewer": "B"})],
    "xss_dom": [dict(extra={"source": "location.hash", "sink": "innerHTML", "page": "/app"})],
    "ssti": [dict(contexts=["html_text"]), dict(method="POST", body_kind="json", input_location="json", json_path="name", contexts=["json"])],
    "csti": [dict(contexts=["html_text"]), dict(contexts=["html_attr"])],
    "crlf": [dict(contexts=["response_header"], input_name="next", value_type="path")],
    "header_injection": [dict(contexts=["response_header"], input_name="lang", value_type="string")],
    "open_redirect": [dict(input_name="url", value_type="url", sample_value="https://lab.test/home"),
                      dict(input_name="next", value_type="path", sample_value="/home")],
    "ssrf": [dict(input_name="url", value_type="url", sample_value="https://example.test/a.png", oob_configured=True),
             dict(input_name="callback", value_type="url", sample_value="https://example.test/", oob_configured=False)],
    "sqli": [dict(input_name="id", input_location="query", value_type="int", sample_value="7"),
             dict(input_name="sort", input_location="query", value_type="string", sample_value="name", flags={"orderby": True}),
             dict(method="POST", input_name="q", input_location="json", json_path="filter.q", body_kind="json", value_type="string", sample_value="abc"),
             dict(input_name="X-Tenant", input_location="header", value_type="string", sample_value="acme")],
    "nosqli": [dict(method="POST", input_name="password", input_location="json", json_path="password", body_kind="json", value_type="string", sample_value="pw"),
               dict(method="POST", input_name="user", input_location="form", body_kind="form", value_type="string", sample_value="alice")],
    "command_injection": [dict(input_name="host", input_location="query", value_type="string", sample_value="localhost"),
                          dict(method="POST", input_name="name", input_location="json", json_path="name", body_kind="json", value_type="string", sample_value="x")],
    "idor_read": [dict(input_name="id", input_location="path", value_type="int", sample_value="3", extra={"other_object_id": "7"}),
                  dict(input_name="noteId", input_location="query", value_type="uuid", sample_value="0b6c2f8e-3e0f-4a8e-9d1c-6b7f2a1e9c3d")],
    "idor_write": [dict(method="POST", input_name="id", input_location="path", value_type="int", sample_value="3",
                        body_kind="json", flags={"state_changing": True}, extra={"other_object_id": "7"})],
    "unauth_replay": [dict(method="GET"), dict(method="POST", body_kind="json", flags={"state_changing": True})],
    "mass_dump": [dict(flags={"list_endpoint": True}, extra={"scope_params": ["owner_id"]}),
                  dict(method="POST", body_kind="json", flags={"list_endpoint": True, "graphql": True})],
    "csrf": [dict(method="POST", body_kind="form", flags={"state_changing": True}),
             dict(method="POST", body_kind="json", flags={"state_changing": True})],
    "mass_assignment": [dict(method="POST", body_kind="json", flags={"state_changing": True}),
                        dict(method="PUT", body_kind="form", flags={"state_changing": True})],
    "method_swap": [dict(method="POST", body_kind="json", flags={"state_changing": True}), dict(method="GET")],
    "content_type_swap": [dict(method="POST", body_kind="json", flags={"state_changing": True})],
    "upload": [dict(method="POST", body_kind="multipart", input_name="file", input_location="filename",
                    sample_value="avatar.png", flags={"upload": True})],
    "race": [dict(method="POST", body_kind="json", flags={"state_changing": True, "limit": True},
                  extra={"counter_read": {"method": "GET", "path": "/api/credits"}, "limit_exceeded_marker": "\"redemptions\": 2"})],
    "path_traversal": [dict(input_name="file", input_location="query", value_type="path", sample_value="report.pdf"),
                       dict(input_name="name", input_location="path", value_type="string", sample_value="logo.png")],
    "xxe": [dict(method="POST", body_kind="xml", content_type="application/xml"),
            dict(method="POST", body_kind="json", content_type="application/json")],
    "graphql_introspection": [dict(method="POST", body_kind="json", flags={"graphql": True})],
    "graphql_batching": [dict(method="POST", body_kind="json", flags={"graphql": True})],
    "info_leak": [dict(method="GET"), dict(method="POST", body_kind="json")],
    "cache_deception": [dict(method="GET", path_template="/settings")],
    "cache_poisoning": [dict(method="GET", path_template="/")],
    "cors": [dict(method="GET", path_template="/api/me")],
    "postmessage": [dict(extra={"page": "/dashboard", "listener": "window.addEventListener('message', ...)"})],
}


def _ctx(name, i, overrides):
    base = dict(cell_id=100 + i, vuln_class=name, salt=f"salt{i:02d}", url="http://127.0.0.1:5057/x",
                input_name="q", input_location="query", sample_value="hello", value_type="string")
    base.update(overrides)
    if C.get(name).level != "input" and "input_name" not in overrides:
        base["input_name"] = None
        base["input_location"] = None
    return Ctx(**base)


def _cases():
    for name in sorted(C.CLASSES):
        for i, ov in enumerate(CONTEXTS.get(name, [{}])):
            yield pytest.param(name, i, ov, id=f"{name}-{i}")


def test_every_class_has_a_context_and_a_generator():
    assert set(CONTEXTS) == set(C.CLASSES), set(C.CLASSES) ^ set(CONTEXTS)
    missing = sorted(set(C.CLASSES) - set(registry()))
    assert not missing, f"classes without a generator: {missing}"


@pytest.mark.parametrize("name,i,ov", list(_cases()))
def test_contract(name, i, ov):
    ctx = _ctx(name, i, ov)
    cases = registry()[name](ctx)
    problems = check_contract(ctx, cases)
    assert not problems, "\n".join(problems)


@pytest.mark.parametrize("name,i,ov", list(_cases()))
def test_deterministic(name, i, ov):
    a = [c.to_dict() for c in generate(_ctx(name, i, ov))]
    b = [c.to_dict() for c in generate(_ctx(name, i, ov))]
    assert a == b


def test_tokens_have_no_fixed_prefix():
    toks = [Ctx(cell_id=n, vuln_class="htmli", salt=f"s{n}").token(0) for n in range(200)]
    assert len({t[:2] for t in toks}) > 50
    assert all(t[0].isalpha() and "bbh" not in t for t in toks)


@pytest.mark.parametrize("payload", [
    "1; DROP TABLE users--", "x' ; DELETE FROM notes--", "1 UPDATE users SET role='admin'", "INSERT INTO t VALUES(1)",
    "'; EXEC xp_cmdshell 'dir'--", "1 UNION SELECT load_file('/etc/passwd')", "file:///etc/passwd",
    "..\\..\\windows\\system32\\config\\sam", "../../etc/shadow",
    "{{ ''.__class__.__mro__[1].__subclasses__() }}{{ __import__('os').system('id') }}", "<!ENTITY x SYSTEM \"file:///c:/x\">",
    "http://169.254.169.254/latest/meta-data/", "; cat /etc/hosts", "$(whoami)", "bbhcanary",
])
def test_screen_rejects_dangerous(payload):
    case = TestCase(case_no=1, technique="sqli.x.y", payload=payload, mutation=[{"op": "set_input", "value": payload}],
                    positive={"type": "body_contains", "value": "x"}, negative="n")
    assert screen_payload(case), payload


@pytest.mark.parametrize("payload", [
    "1 AND SLEEP(5)", "1;SELECT pg_sleep(5)--", "' OR '1'='1", "1 ORDER BY 1--", "{{7*7}}", "${7*7}",
    "<script>console.log('k3j2')</script>", "https://lab.test@evil.test", "{\"$ne\": null}", "%0d%0aSet-Cookie:%20a=b",
    "{{OOB}}", "1)) AND (SELECT 1 FROM (SELECT(SLEEP(2)))a)--",
    # the two canonical read-only LFI proofs are allowed deliberately (see the safety screen)
    "../../../../../../etc/passwd", "..\\..\\..\\..\\windows\\win.ini",
])
def test_screen_accepts_safe(payload):
    case = TestCase(case_no=1, technique="sqli.x.y", payload=payload, mutation=[{"op": "set_input", "value": payload}],
                    positive={"type": "body_contains", "value": "x"}, negative="n")
    assert not screen_payload(case), screen_payload(case)
