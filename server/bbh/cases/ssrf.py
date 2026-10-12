"""SSRF and XXE generators.

SSRF is confirmed ONLY by an out-of-band callback the researcher controls
({{OOB}}); there are no internal, loopback, metadata or file targets anywhere.
XXE uses an internal entity whose replacement is a unique token, or an OOB
parameter-entity fetch; it never reads a file and never expands recursively.
If no OOB service is configured the cases are still generated so the harness can
record them inconclusive and close the cell as blocked: no_oob_listener.
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


@_gen("ssrf")
def gen_ssrf(ctx: Ctx) -> list[TestCase]:
    sample = ctx.sample_value or "https://example.test/a.png"
    cases: list[TestCase] = []
    # control: a benign public URL the researcher controls is fetched (proves the fetcher runs)
    cases.append(TestCase(case_no=0, technique="ssrf.control.benign_oob", payload="{{OOB}}ctrl",
                          mutation=[{"op": "set_input", "value": "{{OOB}}ctrl", "raw": True}], is_control=True,
                          route="oob", positive={"type": "oob_hit"},
                          negative="the server never fetches a benign URL we supply, so it is not a fetcher (or no OOB service is configured)",
                          description="control: the server fetches an attacker-supplied benign URL (OOB)"))
    n = 1
    shapes = [
        ("oob", "plain_https", "https://{{OOB_HOST}}/"),
        ("oob", "plain_http", "http://{{OOB_HOST}}/"),
        ("oob", "path", "{{OOB}}p"),
        ("oob", "query", "https://{{OOB_HOST}}/?q={{OOB}}"),
        ("oob", "userinfo", "https://user@{{OOB_HOST}}/"),
        ("oob", "uppercase_scheme", "HTTPS://{{OOB_HOST}}/"),
        ("redir", "listener_302", "{{OOB}}r302?to={{OOB}}x"),
        ("dns", "bare_host", "{{OOB_HOST}}"),
        ("enc", "url_encoded", "https%3A%2F%2F{{OOB_HOST}}%2F"),
        ("scheme", "no_scheme_slashes", "//{{OOB_HOST}}/"),
    ]
    for family, variant, payload in shapes:
        cases.append(TestCase(case_no=n, technique=f"ssrf.{family}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "oob_hit", "within_s": 30}, route="oob",
                              negative=f"no OOB interaction arrives for the {variant} payload",
                              rung="oob_http_request" if family in ("oob", "redir") else "oob_callback",
                              description=f"SSRF {family}: {variant}"))
        n += 1
    # location variants: the URL in a JSON field / header / webhook-shaped body
    if ctx.body_kind == "json" or ctx.input_location == "json":
        cases.append(TestCase(case_no=n, technique="ssrf.oob.json_field", payload="https://{{OOB_HOST}}/",
                              mutation=[{"op": "set_input_json", "value": "https://{{OOB_HOST}}/"}],
                              positive={"type": "oob_hit", "within_s": 30}, route="oob",
                              negative="no OOB interaction from the JSON URL field",
                              rung="oob_http_request", description="SSRF from a JSON body URL field"))
        n += 1
    cases.append(TestCase(case_no=n, technique="ssrf.enc.double_encoded", payload="https%253A%252F%252F{{OOB_HOST}}%252F",
                          mutation=[{"op": "set_input", "value": "https%253A%252F%252F{{OOB_HOST}}%252F", "raw": True}],
                          positive={"type": "oob_hit", "within_s": 30}, route="oob",
                          negative="no OOB interaction from the double-encoded URL",
                          rung="oob_callback", description="SSRF with a double-encoded URL"))
    n += 1
    # response-reflected rung: the fetched body comes back in the response (stronger than blind)
    cases.append(TestCase(case_no=n, technique="ssrf.reflect.body", payload="{{OOB}}reflect",
                          mutation=[{"op": "set_input", "value": "{{OOB}}reflect", "raw": True}],
                          positive={"type": "all", "of": [{"type": "oob_hit", "within_s": 30}]}, route="oob",
                          negative="no OOB interaction, so there is nothing to reflect",
                          rung="response_reflected", description="SSRF where the fetched content may be reflected"))
    n += 1
    return cases


@_gen("xxe")
def gen_xxe(ctx: Ctx) -> list[TestCase]:
    tok = ctx.token("e")
    is_xml = ctx.body_kind == "xml" or (ctx.content_type or "").endswith("xml")
    cases: list[TestCase] = []
    # control: a well-formed XML body is accepted (so a rejection is distinguishable from a block)
    ctrl = f'<?xml version="1.0"?><root><a>{tok}ctl</a></root>'
    ctrl_mut = ([{"op": "replace_body", "body": ctrl, "content_type": "application/xml"}]
                if is_xml else [{"op": "set_content_type", "value": "application/xml"}, {"op": "replace_body", "body": ctrl, "content_type": "application/xml"}])
    cases.append(TestCase(case_no=0, technique="xxe.control.wellformed", payload=ctrl, mutation=ctrl_mut, is_control=True,
                          positive={"type": "any", "of": [{"type": "status_in", "values": [200, 201, 202, 204, 400, 422]},
                                                         {"type": "body_contains", "value": f"{tok}ctl"}]},
                          negative="a well-formed XML body is not processed, so the endpoint does not parse XML here",
                          description="control: a well-formed XML document is parsed"))
    n = 1
    internal = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "{tok}">]>'
                f'<root><a>&x;</a></root>')
    variants = [
        ("internal", "text_node", internal, {"type": "all", "of": [{"type": "body_contains", "value": tok},
                                                                  {"type": "body_not_contains", "value": "&x;"}]}, "entity_expanded"),
        ("attr", "attribute_value", f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "{tok}">]><root a="&x;"><b>1</b></root>',
         {"type": "body_contains", "value": tok}, "entity_expanded"),
        ("encoding", "utf16_decl", f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE r [<!ENTITY x "{tok}">]><root>&x;</root>',
         {"type": "body_contains", "value": tok}, "entity_expanded"),
        ("param", "oob_param_entity", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "{{OOB}}dtd"> %p;]><root>1</root>',
         {"type": "oob_hit", "within_s": 30}, "oob_entity_fetch"),
        ("external", "oob_general_entity", '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "{{OOB}}ent">]><root>&x;</root>',
         {"type": "oob_hit", "within_s": 30}, "oob_entity_fetch"),
        ("xinclude", "oob_text", '<?xml version="1.0"?><root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="{{OOB}}xi" parse="text"/></root>',
         {"type": "oob_hit", "within_s": 30}, "oob_entity_fetch"),
    ]
    for family, variant, body, cond, rung in variants:
        route = "oob" if family == "oob" else "sender"
        muts = [{"op": "replace_body", "body": body, "content_type": "application/xml"}]
        if not is_xml:
            muts = [{"op": "set_content_type", "value": "application/xml"}] + muts
        cases.append(TestCase(case_no=n, technique=f"xxe.{family}.{variant}", payload=body, mutation=muts,
                              positive=cond, route=route, negative=f"the {variant} entity is not processed",
                              rung=rung, description=f"XXE {family}: {variant}"))
        n += 1
    # more internal-entity shapes (non-recursive, no file access)
    for family, variant, body in [
        ("nested", "two_levels", f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "{tok}"><!ENTITY b "pre-&a;-post">]><root>&b;</root>'),
        ("cdata", "entity_outside_cdata", f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "{tok}">]><root><![CDATA[literal]]>&x;</root>'),
    ]:
        muts = [{"op": "replace_body", "body": body, "content_type": "application/xml"}]
        if not is_xml:
            muts = [{"op": "set_content_type", "value": "application/xml"}] + muts
        cases.append(TestCase(case_no=n, technique=f"xxe.{family}.{variant}", payload=body, mutation=muts,
                              positive={"type": "all", "of": [{"type": "body_contains", "value": tok}, {"type": "body_not_contains", "value": "&a;" if family == "nested" else "&x;"}]},
                              negative=f"the {family}/{variant} entity is not expanded", rung="entity_expanded",
                              description=f"XXE {family}: {variant}"))
        n += 1

    # content-type swap families on a JSON endpoint (xml and text/xml)
    for variant, ctype in [("application_xml", "application/xml"), ("text_xml", "text/xml")]:
        body = f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x "{tok}">]><root>&x;</root>'
        cases.append(TestCase(case_no=n, technique=f"xxe.swap.{variant}", payload=body,
                              mutation=[{"op": "set_content_type", "value": ctype}, {"op": "replace_body", "body": body, "content_type": ctype}],
                              positive={"type": "all", "of": [{"type": "body_contains", "value": tok}, {"type": "body_not_contains", "value": "&x;"}]},
                              negative=f"the endpoint does not parse the body as {ctype}",
                              rung="entity_expanded", description=f"XXE via content-type swap to {ctype}"))
        n += 1
    return cases
