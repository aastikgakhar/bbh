"""Authorization generators: idor_read, idor_write, unauth_replay, mass_dump,
mass_assignment, method_swap.

Writes are confirmed by a counter-read as the owner (a 200 can be a no-op), never
by the write's own status. Reads compare against the owner's own read of the same
object. Mass-dump positives are the Rule 0 third-party signal or a size
differential, and the sender refuses to page once third-party data is seen.
No data belonging to anyone but the test accounts is ever collected.
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


def _owner_read(ctx: Ctx) -> dict:
    """Counter-read spec: the other principal reads the object by its own id."""
    other = ctx.other_principal or "B"
    return {"same_as_base": True, "principal": other}


@_gen("idor_read")
def gen_idor_read(ctx: Ctx) -> list[TestCase]:
    acting = ctx.acting_principal
    other = ctx.other_principal or "B"
    marker = ctx.extra.get("other_object_marker")  # content that only the other object holds
    cases: list[TestCase] = []
    # control: the owner (other principal) reads their own object successfully
    cases.append(TestCase(case_no=0, technique="idor_read.control.owner", payload="{{OTHER_ID}}",
                          mutation=[{"op": "set_input", "value": "{{OTHER_ID}}"}, {"op": "as_principal", "principal": other}],
                          is_control=True, principal=other,
                          positive={"type": "status_in", "values": [200]},
                          negative="the owner cannot read their own object, so the tooling or id is wrong",
                          description="control: the owner reads the target object"))
    n = 1

    def pos_for(case_self):
        if marker:
            return {"type": "body_contains", "value": marker}
        # without a known marker: the attacker's read matches the owner's control read
        return {"type": "same_as_case", "a": "this", "case": 0, "max_len_diff": 48}

    # family = the technique used to reach the other object
    techniques = [
        ("cross", "direct", [{"op": "set_input", "value": "{{OTHER_ID}}"}]),
        ("format", "neighbour", [{"op": "set_input", "value": "{{OTHER_ID}}"}]),  # id variants handled by {{OTHER_ID}}
        ("method", "post_override", [{"op": "set_input", "value": "{{OTHER_ID}}"}, {"op": "set_method", "method": "POST"}]),
        ("method", "head", [{"op": "set_input", "value": "{{OTHER_ID}}"}, {"op": "set_method", "method": "HEAD"}]),
        ("pollution", "query_dup", [{"op": "set_input", "value": "{{OWN_ID}}"}, {"op": "duplicate_input", "value": "{{OTHER_ID}}", "position": "after"}]),
        ("pollution", "own_then_other", [{"op": "set_input", "value": "{{OTHER_ID}}"}, {"op": "duplicate_input", "value": "{{OWN_ID}}", "position": "before"}]),
        ("override", "x_original_url", [{"op": "set_input", "value": "{{OWN_ID}}"}, {"op": "set_header", "name": "X-Original-URL", "value": "{{OTHER_ID}}"}]),
    ]
    for family, variant, muts in techniques:
        full = list(muts) + [{"op": "as_principal", "principal": acting}]
        cases.append(TestCase(case_no=n, technique=f"idor_read.{family}.{variant}", payload="{{OTHER_ID}}",
                              mutation=full, principal=acting, positive=pos_for(n),
                              negative=f"as {acting}, the {family}/{variant} read of the other object is refused or empty",
                              rung="cross_principal_read", description=f"IDOR read {family}: {variant}"))
        n += 1
    # unauth read
    cases.append(TestCase(case_no=n, technique="idor_read.unauth.strip", payload="{{OTHER_ID}}",
                          mutation=[{"op": "set_input", "value": "{{OTHER_ID}}"}, {"op": "strip_auth"}], principal="unauth",
                          positive=pos_for(n), negative="unauthenticated, the object cannot be read",
                          rung="cross_principal_read", description="IDOR read: unauthenticated"))
    n += 1
    # object-type confusion and format variants
    for family, variant, val in [("format", "zero_pad", "{{OTHER_ID}}"), ("format", "trailing_slash_suffix", "{{OTHER_ID}}")]:
        cases.append(TestCase(case_no=n, technique=f"idor_read.{family}.{variant}", payload=val,
                              mutation=[{"op": "set_input", "value": val}, {"op": "as_principal", "principal": acting}],
                              principal=acting, positive=pos_for(n),
                              negative=f"the {variant} id form is not honoured", rung="cross_principal_read",
                              description=f"IDOR read id format: {variant}"))
        n += 1
    return cases


def _write_body_marker(ctx: Ctx, tok: str) -> list[dict]:
    """Mutations that set a recognisable value the counter-read can look for."""
    if ctx.body_kind == "json" or ctx.method in ("POST", "PUT", "PATCH"):
        return [{"op": "set_param", "location": "json", "name": "title", "value": f"edited-{tok}"},
                {"op": "set_param", "location": "json", "name": "content", "value": f"edited-{tok}"}]
    return [{"op": "set_param", "location": "form", "name": "title", "value": f"edited-{tok}"}]


@_gen("idor_write")
def gen_idor_write(ctx: Ctx) -> list[TestCase]:
    acting = ctx.acting_principal
    other = ctx.other_principal or "B"
    counter = {"method": "GET", "path": ctx.extra.get("read_path", ctx.path_template).replace("{id}", "{{OTHER_ID}}"), "principal": other}
    cases: list[TestCase] = []
    tokc = ctx.token("ctrl")
    # control: the owner edits their own object and the counter-read shows it (write path works)
    cases.append(TestCase(case_no=0, technique="idor_write.control.owner", payload=f"owner-{tokc}",
                          mutation=[{"op": "set_input", "value": "{{OTHER_ID}}"}] + _write_body_marker(ctx, tokc) + [{"op": "as_principal", "principal": other}],
                          is_control=True, principal=other, route="counter_read", needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"edited-{tokc}"},
                          negative="the owner's own edit does not show on the counter-read, so the write path or tooling is broken",
                          extra={"counter_read": counter},
                          description="control: the owner edits the object and the change is visible"))
    n = 1
    techniques = [
        ("cross", "direct"),
        ("method", "put"),
        ("method", "patch"),
        ("format", "id_variant"),
        ("pollution", "dup_id"),
        ("override", "method_override"),
        ("mass", "owner_field"),
        ("ctype", "text_plain"),
    ]
    for family, variant in techniques:
        tok = ctx.token(n)
        muts: list[dict] = [{"op": "set_input", "value": "{{OTHER_ID}}"}] + _write_body_marker(ctx, tok)
        if family == "method" and variant in ("put", "patch"):
            muts.append({"op": "set_method", "method": variant.upper()})
        elif family == "pollution":
            muts.append({"op": "duplicate_input", "value": "{{OWN_ID}}", "position": "before"})
        elif family == "override":
            muts.append({"op": "set_header", "name": "X-HTTP-Method-Override", "value": "PUT"})
        elif family == "mass":
            muts.append({"op": "set_param", "location": "json" if ctx.body_kind == "json" else "form", "name": "owner_id", "value": "{{OWN_ID}}"})
        elif family == "ctype":
            muts.append({"op": "set_content_type", "value": "text/plain"})
        muts.append({"op": "as_principal", "principal": acting})
        cases.append(TestCase(case_no=n, technique=f"idor_write.{family}.{variant}", payload=f"edited-{tok}",
                              mutation=muts, principal=acting, route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": f"edited-{tok}"},
                              negative=f"after the {family}/{variant} write as {acting}, the owner's counter-read does not show the change (a 200 is not enough)",
                              rung="cross_principal_write_counter_read", extra={"counter_read": counter},
                              description=f"IDOR write {family}: {variant}, confirmed by counter-read"))
        n += 1
    # unauth write
    tok = ctx.token(n)
    cases.append(TestCase(case_no=n, technique="idor_write.unauth.strip", payload=f"edited-{tok}",
                          mutation=[{"op": "set_input", "value": "{{OTHER_ID}}"}] + _write_body_marker(ctx, tok) + [{"op": "strip_auth"}],
                          principal="unauth", route="counter_read", needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"edited-{tok}"},
                          negative="an unauthenticated write does not land on the owner's object",
                          rung="cross_principal_write_counter_read", extra={"counter_read": counter},
                          description="IDOR write: unauthenticated, confirmed by counter-read"))
    n += 1
    # delete (only between test accounts, confirmed by counter-read showing absence)
    cases.append(TestCase(case_no=n, technique="idor_write.cross.delete", payload="DELETE {{OTHER_ID}}",
                          mutation=[{"op": "set_input", "value": "{{OTHER_ID}}"}, {"op": "set_method", "method": "DELETE"}, {"op": "as_principal", "principal": acting}],
                          principal=acting, route="counter_read", needs_counter_read=True,
                          positive={"type": "counter_read_not_contains", "value": "edited-"},
                          negative="the cross-account delete did not remove the object (the owner still reads it)",
                          rung="cross_principal_write_counter_read", extra={"counter_read": counter},
                          description="IDOR cross-account delete (test accounts only), confirmed by counter-read"))
    n += 1
    return cases


@_gen("unauth_replay")
def gen_unauth_replay(ctx: Ctx) -> list[TestCase]:
    state = bool(ctx.flags.get("state_changing"))
    cases: list[TestCase] = []
    # control: the authenticated request returns its normal response
    cases.append(TestCase(case_no=0, technique="unauth_replay.control.authed", payload="(as owner)",
                          mutation=[{"op": "as_principal", "principal": ctx.acting_principal}], is_control=True,
                          principal=ctx.acting_principal, positive={"type": "status_in", "values": [200, 201, 204]},
                          negative="the authenticated request does not succeed, so the tooling is broken",
                          description="control: the request works authenticated"))
    n = 1
    strips = [
        ("strip", "no_cookies", [{"op": "remove_header", "name": "Cookie"}]),
        ("strip", "no_auth_header", [{"op": "remove_header", "name": "Authorization"}]),
        ("strip", "full", [{"op": "strip_auth"}]),
        ("strip", "empty_cookie", [{"op": "set_header", "name": "Cookie", "value": ""}]),
        ("token", "junk_bearer", [{"op": "strip_auth"}, {"op": "set_header", "name": "Authorization", "value": "Bearer x"}]),
    ]
    for family, variant, muts in strips:
        cases.append(TestCase(case_no=n, technique=f"unauth_replay.{family}.{variant}", payload=variant,
                              mutation=muts, principal="unauth",
                              positive={"type": "all", "of": [{"type": "same_as_case", "a": "this", "case": 0, "max_len_diff": 64},
                                                             {"type": "body_not_contains", "value": "<form"}]},
                              negative=f"stripping auth ({variant}) no longer returns the authenticated data",
                              rung="unauth_read", description=f"unauthenticated replay: {variant}"))
        n += 1
    # more auth-shape families
    for family, variant, muts in [
        ("cookie", "drop_session_only", [{"op": "remove_cookie", "name": "session"}]),
        ("cookie", "drop_lab_session", [{"op": "remove_cookie", "name": "lab_session"}]),
        ("token", "alt_auth_name", [{"op": "strip_auth"}, {"op": "set_header", "name": "X-Auth-Token", "value": ""}]),
        ("method", "options", [{"op": "strip_auth"}, {"op": "set_method", "method": "OPTIONS"}]),
        ("spoof", "forwarded_for", [{"op": "strip_auth"}, {"op": "set_header", "name": "X-Forwarded-For", "value": "127.0.0.1"}]),
        ("spoof", "original_url", [{"op": "strip_auth"}, {"op": "set_header", "name": "X-Original-URL", "value": "/"}]),
    ]:
        cases.append(TestCase(case_no=n, technique=f"unauth_replay.{family}.{variant}", payload=variant,
                              mutation=muts, principal="unauth",
                              positive={"type": "same_as_case", "a": "this", "case": 0, "max_len_diff": 64},
                              negative=f"the {variant} variant does not return the authenticated response",
                              rung="unauth_read", description=f"unauthenticated replay: {family} {variant}"))
        n += 1
    if state:
        tok = ctx.token("w")
        cases.append(TestCase(case_no=n, technique="unauth_replay.write.counter_read", payload=f"w-{tok}",
                              mutation=[{"op": "set_param", "location": "json" if ctx.body_kind == "json" else "form", "name": "title", "value": f"w-{tok}"}, {"op": "strip_auth"}],
                              principal="unauth", route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": f"w-{tok}"},
                              negative="the unauthenticated write does not land (the owner's read does not show it)",
                              rung="unauth_write_counter_read",
                              extra={"counter_read": {"same_as_base": True, "principal": ctx.acting_principal}},
                              description="unauthenticated write confirmed by the owner's counter-read"))
        n += 1
    return cases


@_gen("mass_dump")
def gen_mass_dump(ctx: Ctx) -> list[TestCase]:
    scope_params = ctx.extra.get("scope_params") or ["owner_id", "user_id", "account_id", "tenant_id", "workspace_id"]
    primary = scope_params[0] if scope_params else "owner_id"
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="mass_dump.control.scoped", payload="(own scope)",
                          mutation=[{"op": "as_principal", "principal": ctx.acting_principal}], is_control=True,
                          principal=ctx.acting_principal, positive={"type": "status_in", "values": [200]},
                          negative="the normal scoped list does not return, so the tooling is broken",
                          description="control: the list returns the acting principal's own rows"))
    n = 1
    # family = how the scope is widened. Positive = Rule 0 third-party signal, or a size jump.
    widen = [
        ("filter", "absent", [{"op": "remove_param", "location": _loc(ctx), "name": primary}]),
        ("filter", "empty", [{"op": "set_param", "location": _loc(ctx), "name": primary, "value": ""}]),
        ("filter", "null", [{"op": "set_param", "location": _loc(ctx), "name": primary, "value": "null"}]),
        ("filter", "zero", [{"op": "set_param", "location": _loc(ctx), "name": primary, "value": "0"}]),
        ("filter", "wildcard", [{"op": "set_param", "location": _loc(ctx), "name": primary, "value": "*"}]),
        ("filter", "other_principal", [{"op": "set_param", "location": _loc(ctx), "name": primary, "value": "{{OTHER_ID}}"}]),
        ("pollution", "other_scope", [{"op": "set_param", "location": "query", "name": primary, "value": "{{OTHER_ID}}"}]),
        ("limit", "huge", [{"op": "set_param", "location": "query", "name": "limit", "value": "99999"}]),
        ("limit", "negative", [{"op": "set_param", "location": "query", "name": "limit", "value": "-1"}]),
        ("cursor", "walk", [{"op": "set_param", "location": "query", "name": "offset", "value": "0"}, {"op": "set_param", "location": "query", "name": "limit", "value": "99999"}]),
        ("sort", "reverse", [{"op": "set_param", "location": "query", "name": "sort", "value": "id"}, {"op": "set_param", "location": "query", "name": "order", "value": "desc"}, {"op": "remove_param", "location": _loc(ctx), "name": primary}]),
    ]
    for family, variant, muts in widen:
        full = list(muts) + [{"op": "as_principal", "principal": ctx.acting_principal}]
        cases.append(TestCase(case_no=n, technique=f"mass_dump.{family}.{variant}", payload=variant,
                              mutation=full, principal=ctx.acting_principal,
                              positive={"type": "any", "of": [{"type": "third_party_seen"},
                                                             {"type": "len_diff", "a": "this", "b": 0, "min_bytes": 200}]},
                              negative=f"widening the scope ({family}/{variant}) returns no records outside the acting principal",
                              rung="scope_filter_bypassed_count", description=f"mass dump {family}: {variant}"))
        n += 1
    if ctx.flags.get("graphql"):
        cases.append(TestCase(case_no=n, technique="mass_dump.graphql.root_collection", payload="{ users { id email } }",
                              mutation=[{"op": "set_param", "location": "json", "name": "query", "value": "{ users { id email } }"}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal,
                              positive={"type": "third_party_seen"},
                              negative="the unscoped root collection returns no third-party rows",
                              rung="scope_filter_bypassed_count", description="mass dump: GraphQL root collection without scoping"))
        n += 1
    return cases


def _loc(ctx: Ctx) -> str:
    if ctx.body_kind == "json":
        return "json"
    if ctx.method in ("POST", "PUT", "PATCH"):
        return "form"
    return "query"


@_gen("mass_assignment")
def gen_mass_assignment(ctx: Ctx) -> list[TestCase]:
    loc = _loc(ctx)
    counter = {"same_as_base": True, "principal": ctx.acting_principal}
    cases: list[TestCase] = []
    tokc = ctx.token("ctrl")
    cases.append(TestCase(case_no=0, technique="mass_assignment.control.known_field", payload=f"name-{tokc}",
                          mutation=[{"op": "set_param", "location": loc, "name": ctx.extra.get("known_field", "display_name"), "value": f"name-{tokc}"}, {"op": "as_principal", "principal": ctx.acting_principal}],
                          is_control=True, principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                          positive={"type": "counter_read_contains", "value": f"name-{tokc}"},
                          negative="a legitimate field update does not show on the counter-read, so the tooling is broken",
                          extra={"counter_read": counter},
                          description="control: a normal field update is visible on the counter-read"))
    n = 1
    # family = the privilege category of the injected field (each is a distinct technique)
    fields = [
        ("field", "role", "admin"), ("field", "is_admin", True), ("field", "isAdmin", True),
        ("privilege", "owner_id", "{{OWN_ID}}"), ("privilege", "tenant_id", "x"),
        ("flag", "verified", True), ("flag", "status", "active"),
        ("commercial", "plan", "enterprise"), ("commercial", "price", "0"),
        ("acl", "permissions", "admin"), ("acl", "visibility", "public"),
    ]
    for family, field_name, value in fields:
        is_json = loc == "json"
        setter = {"op": "set_param", "location": loc, "name": field_name, "value": value if (is_json and not isinstance(value, str)) else str(value)}
        cases.append(TestCase(case_no=n, technique=f"mass_assignment.{family}.{field_name}", payload=f"{field_name}={value}",
                              mutation=[setter, {"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": str(value)},
                              negative=f"the injected {field_name} field does not take effect on the counter-read",
                              rung="field_accepted_counter_read", extra={"counter_read": counter},
                              description=f"mass assignment {family}: {field_name}"))
        n += 1
    # nested and array shapes
    if loc == "json":
        tok = ctx.token(n)
        cases.append(TestCase(case_no=n, technique="mass_assignment.nested.role_object", payload="account.role=admin",
                              mutation=[{"op": "set_param", "location": "json", "name": "account", "value": {"role": "admin"}}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal, route="counter_read", needs_counter_read=True,
                              positive={"type": "counter_read_contains", "value": "admin"},
                              negative="the nested role object does not take effect",
                              rung="field_accepted_counter_read", extra={"counter_read": counter},
                              description="mass assignment: nested object"))
        n += 1
    return cases


@_gen("method_swap")
def gen_method_swap(ctx: Ctx) -> list[TestCase]:
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="method_swap.control.original", payload=ctx.method,
                          mutation=[{"op": "as_principal", "principal": ctx.acting_principal}], is_control=True,
                          principal=ctx.acting_principal, positive={"type": "status_in", "values": [200, 201, 204, 302, 303]},
                          negative="the original method does not work, so the tooling is broken",
                          description="control: the endpoint's normal method works"))
    n = 1
    # family = the method (swapping to GET vs DELETE are genuinely different tests)
    methods = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE"]
    for m in methods:
        if m == ctx.method:
            continue
        cases.append(TestCase(case_no=n, technique=f"method_swap.{m.lower()}.swap", payload=m,
                              mutation=[{"op": "set_method", "method": m}, {"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal,
                              positive={"type": "not", "of": {"type": "status_in", "values": [400, 401, 403, 404, 405, 501]}},
                              negative=f"the {m} method is refused as expected",
                              rung="alternate_method_bypasses_control", description=f"method swap: {m}"))
        n += 1
    for family, variant, hdr, val in [("override", "x_http_method_override", "X-HTTP-Method-Override", "PUT"),
                                     ("override", "x_method_override", "X-Method-Override", "DELETE"),
                                     ("override", "method_param", "_method", "PUT")]:
        if variant == "method_param":
            muts = [{"op": "set_param", "location": "query", "name": "_method", "value": "PUT"}]
        else:
            muts = [{"op": "set_header", "name": hdr, "value": val}]
        cases.append(TestCase(case_no=n, technique=f"method_swap.{family}.{variant}", payload=f"{hdr}:{val}",
                              mutation=muts + [{"op": "as_principal", "principal": ctx.acting_principal}],
                              principal=ctx.acting_principal,
                              positive={"type": "not", "of": {"type": "same_as_case", "case": 0, "max_len_diff": 32}},
                              negative=f"the {variant} override changes nothing",
                              rung="alternate_method_bypasses_control", description=f"method override: {variant}"))
        n += 1
    return cases
