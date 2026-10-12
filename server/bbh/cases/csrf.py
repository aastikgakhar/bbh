"""CSRF, content-type swap, and CORS generators.

Every CSRF case is confirmed by a counter-read showing the state actually
changed (or, for the hosted cross-origin cases, by the private browser plus a
counter-read). SameSite/Secure must be read first: without SameSite=None the
credentialed cross-origin read is dead. Forced login and forced logout are out
of scope and are never generated here (the planner marks those n_a).
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


EVIL = "evil.test"


def _counter(ctx: Ctx) -> dict:
    return {"method": "GET", "path": ctx.extra.get("read_path", "/api/settings"), "principal": ctx.acting_principal}


def _marker_mut(ctx: Ctx, tok: str) -> list[dict]:
    loc = "json" if ctx.body_kind == "json" else "form"
    field = ctx.extra.get("mutable_field", "display_name")
    return [{"op": "set_param", "location": loc, "name": field, "value": f"csrf-{tok}"}]


@_gen("csrf")
def gen_csrf(ctx: Ctx) -> list[TestCase]:
    counter = _counter(ctx)
    tokc = ctx.token("ctrl")
    cases: list[TestCase] = []
    # control: a legitimate same-session state change works and the counter-read shows it
    cases.append(TestCase(case_no=0, technique="csrf.control.legit", payload=f"csrf-{tokc}",
                          mutation=_marker_mut(ctx, tokc) + [{"op": "as_principal", "principal": ctx.acting_principal}],
                          is_control=True, principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"csrf-{tokc}"},
                          negative="a legitimate state change is not visible on the counter-read, so the tooling is broken",
                          extra={"counter_read": counter},
                          description="control: a normal state change is confirmed by a counter-read"))
    n = 1
    # token family: remove / empty / swap / mangle the CSRF token, then counter-read
    token_field = ctx.extra.get("csrf_field", "csrf_token")
    token_header = ctx.extra.get("csrf_header", "X-CSRF-Token")
    for variant, muts in [
        ("removed", [{"op": "remove_param", "location": "form", "name": token_field}, {"op": "remove_header", "name": token_header}]),
        ("empty", [{"op": "set_param", "location": "form", "name": token_field, "value": ""}, {"op": "set_header", "name": token_header, "value": ""}]),
        ("mangled", [{"op": "set_header", "name": token_header, "value": "0" * 16}]),
        ("foreign", [{"op": "set_header", "name": token_header, "value": "{{OTHER_CSRF}}"}]),
    ]:
        tok = ctx.token(n)
        cases.append(TestCase(case_no=n, technique=f"csrf.token.{variant}", payload=f"csrf-{tok}",
                              mutation=_marker_mut(ctx, tok) + muts + [{"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": f"csrf-{tok}"},
                              negative=f"with the CSRF token {variant}, the state change is rejected (counter-read unchanged)",
                              rung="cross_origin_state_change", extra={"counter_read": counter},
                              description=f"CSRF token {variant}: does the change still land"))
        n += 1
    # content-type family: a JSON body parser that also accepts text/plain or form is CSRF-able
    for variant, ctype in [("text_plain", "text/plain"), ("form", "application/x-www-form-urlencoded"), ("multipart", "multipart/form-data")]:
        tok = ctx.token(n)
        cases.append(TestCase(case_no=n, technique=f"csrf.ctype.{variant}", payload=f"csrf-{tok}",
                              mutation=_marker_mut(ctx, tok) + [{"op": "set_content_type", "value": ctype}, {"op": "remove_header", "name": token_header}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": f"csrf-{tok}"},
                              negative=f"the body sent as {ctype} is not parsed into a state change",
                              rung="cross_origin_state_change", extra={"counter_read": counter},
                              description=f"CSRF via {ctype} body (no token)"))
        n += 1
    # hosted cross-origin families: top-level form POST (beats cookie partitioning) and fetch
    tok = ctx.token("form")
    cases.append(TestCase(case_no=n, technique="csrf.form.top_level", payload=f"csrf-{tok}",
                          mutation=_marker_mut(ctx, tok) + [{"op": "set_content_type", "value": "text/plain"}, {"op": "remove_header", "name": token_header}],
                          route="browser", principal=ctx.acting_principal, needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"csrf-{tok}"},
                          negative="the hosted top-level form POST does not change the victim's state",
                          rung="cross_origin_state_change",
                          extra={"browser": {"open": "poc", "poc_kind": "form_text_plain", "principal": ctx.acting_principal, "wait_ms": 2000},
                                 "counter_read": counter},
                          description="CSRF: hosted top-level form POST (text/plain), confirmed by counter-read"))
    n += 1
    tok = ctx.token("fetch")
    cases.append(TestCase(case_no=n, technique="csrf.fetch.credentials", payload=f"csrf-{tok}",
                          mutation=_marker_mut(ctx, tok) + [{"op": "remove_header", "name": token_header}],
                          route="browser", principal=ctx.acting_principal, needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"csrf-{tok}"},
                          negative="the cross-origin credentialed fetch does not change state (CORS or SameSite blocks it)",
                          rung="cross_origin_state_change",
                          extra={"browser": {"open": "poc", "poc_kind": "fetch_credentials", "principal": ctx.acting_principal, "wait_ms": 2000},
                                 "counter_read": counter},
                          description="CSRF: cross-origin fetch with credentials, confirmed by counter-read"))
    n += 1
    # SPA route that mutates on mount from query params alone (defeats SameSite=Lax)
    cases.append(TestCase(case_no=n, technique="csrf.mount.query_only", payload=f"csrf-{ctx.token('mnt')}",
                          mutation=[{"op": "as_principal", "principal": ctx.acting_principal}],
                          route="browser", principal=ctx.acting_principal, needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"csrf-{ctx.token('mnt')}"},
                          negative="no mount-time mutation route exists that a top-level navigation can trigger",
                          rung="cross_origin_state_change",
                          extra={"browser": {"open": "path", "path": ctx.extra.get("mount_path", "/"), "principal": ctx.acting_principal, "wait_ms": 2000},
                                 "counter_read": counter, "note": "look for an onMounted mutation driven by route query params"},
                          description="CSRF: SPA route mutating on mount from query params"))
    n += 1
    return cases


@_gen("content_type_swap")
def gen_content_type_swap(ctx: Ctx) -> list[TestCase]:
    counter = _counter(ctx)
    tokc = ctx.token("ctrl")
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="content_type_swap.control.json", payload=f"ct-{tokc}",
                          mutation=_marker_mut(ctx, tokc) + [{"op": "as_principal", "principal": ctx.acting_principal}],
                          is_control=True, principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"ct-{tokc}"},
                          negative="the normal JSON request does not change state, so the tooling is broken",
                          extra={"counter_read": counter},
                          description="control: the endpoint's normal content type changes state"))
    n = 1
    for family, variant, ctype in [("text", "plain", "text/plain"), ("form", "urlencoded", "application/x-www-form-urlencoded"),
                                  ("multipart", "form_data", "multipart/form-data"), ("xml", "application_xml", "application/xml"),
                                  ("none", "stripped", None), ("wrong", "octet_stream", "application/octet-stream")]:
        tok = ctx.token(n)
        muts = _marker_mut(ctx, tok)
        if ctype is None:
            muts = muts + [{"op": "remove_header", "name": "Content-Type"}]
        else:
            muts = muts + [{"op": "set_content_type", "value": ctype}]
        muts.append({"op": "as_principal", "principal": ctx.acting_principal})
        cases.append(TestCase(case_no=n, technique=f"content_type_swap.{family}.{variant}", payload=f"ct-{tok}",
                              mutation=muts, principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": f"ct-{tok}"},
                              negative=f"the body sent as {ctype or 'no content-type'} is not parsed into a state change",
                              rung="control_bypassed", extra={"counter_read": counter},
                              description=f"content-type swap to {ctype or 'none'}"))
        n += 1
    # charset and boundary tricks
    for family, variant, ctype in [("charset", "json_utf7", "application/json; charset=utf-7"),
                                  ("suffix", "json_suffix", "application/vnd.api+json"),
                                  ("case", "upper", "APPLICATION/JSON"),
                                  ("space", "leading", " application/json")]:
        tok = ctx.token(n)
        cases.append(TestCase(case_no=n, technique=f"content_type_swap.{family}.{variant}", payload=f"ct-{tok}",
                              mutation=_marker_mut(ctx, tok) + [{"op": "set_content_type", "value": ctype, "reencode": False}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": f"ct-{tok}"},
                              negative=f"the {variant} content type is not accepted as JSON",
                              rung="parsed_as_alternate", extra={"counter_read": counter},
                              description=f"content-type parsing quirk: {variant}"))
        n += 1
    return cases


@_gen("cors")
def gen_cors(ctx: Ctx) -> list[TestCase]:
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="cors.control.same_origin", payload="(same origin)",
                          mutation=[{"op": "as_principal", "principal": ctx.acting_principal}], is_control=True,
                          principal=ctx.acting_principal, positive={"type": "status_in", "values": [200]},
                          negative="the same-origin request does not succeed, so the tooling is broken",
                          description="control: the endpoint returns data to its own origin"))
    n = 1
    origins = [
        ("reflect", "attacker", f"https://{EVIL}"),
        ("null", "null_origin", "null"),
        ("subdomain", "attacker_sub", f"https://x.{EVIL}"),
        ("suffix", "origin_suffix", None),            # https://<target>.evil.test
        ("prefix", "origin_prefix", None),            # https://evil.test.<target>? (built below)
        ("scheme", "http_origin", "http://" + EVIL),
        ("port", "attacker_port", f"https://{EVIL}:8443"),
        ("case", "mixed_case_host", f"https://{EVIL.upper()}"),
    ]
    from urllib.parse import urlsplit

    target_host = urlsplit(ctx.url).hostname or "lab.test"
    for family, variant, origin in origins:
        if origin is None:
            origin = f"https://{target_host}.{EVIL}" if variant == "origin_suffix" else f"https://{EVIL}.{target_host}"
        cases.append(TestCase(case_no=n, technique=f"cors.{family}.{variant}", payload=origin,
                              mutation=[{"op": "set_header", "name": "Origin", "value": origin}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal,
                              positive={"type": "all", "of": [{"type": "header_contains", "name": "Access-Control-Allow-Origin", "value": EVIL if EVIL in origin else "null"},
                                                             {"type": "header_contains", "name": "Access-Control-Allow-Credentials", "value": "true"}]},
                              negative=f"the {variant} Origin is not reflected with credentials allowed",
                              rung="origin_reflected_with_credentials", description=f"CORS: {variant} origin reflection"))
        n += 1
    # preflight and a credentialed-read confirmation
    cases.append(TestCase(case_no=n, technique="cors.preflight.options", payload="OPTIONS preflight",
                          mutation=[{"op": "set_method", "method": "OPTIONS"}, {"op": "set_header", "name": "Origin", "value": f"https://{EVIL}"},
                                    {"op": "set_header", "name": "Access-Control-Request-Method", "value": "GET"}],
                          principal=ctx.acting_principal,
                          positive={"type": "header_contains", "name": "Access-Control-Allow-Origin", "value": EVIL},
                          negative="the preflight does not allow the attacker origin",
                          rung="origin_reflected_with_credentials", description="CORS preflight reflection"))
    n += 1
    cases.append(TestCase(case_no=n, technique="cors.read.credentialed", payload="(hosted fetch read)",
                          mutation=[{"op": "set_header", "name": "Origin", "value": f"https://{EVIL}"}],
                          route="browser", principal=ctx.acting_principal,
                          positive={"type": "browser_text_contains", "value": ctx.extra.get("secret_marker", "@")},
                          negative="a hosted cross-origin credentialed fetch cannot read the response body",
                          rung="credentialed_read_confirmed",
                          extra={"browser": {"open": "poc", "poc_kind": "fetch_credentials", "principal": ctx.other_principal or "B", "wait_ms": 2000}},
                          description="CORS: confirm a credentialed cross-origin read of private data"))
    n += 1
    return cases
