"""GraphQL generators: graphql_introspection, graphql_batching.

Read-only probes: an introspection query, field-suggestion error oracles when
introspection is disabled (validation runs before auth), and batching against a
limit. No mutations, no data beyond schema names, no third-party rows (the Rule 0
guard still redacts any that appear).
"""

from __future__ import annotations

import json

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


INTROSPECTION = "query{__schema{queryType{name} types{name kind fields{name}}}}"


def _set_query(q, extra_fields=None):
    body = {"query": q}
    if extra_fields:
        body.update(extra_fields)
    return {"op": "replace_body", "body": json.dumps(body), "content_type": "application/json"}


@_gen("graphql_introspection")
def gen_graphql_introspection(ctx: Ctx) -> list[TestCase]:
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="graphql_introspection.control.typename", payload="{__typename}",
                          mutation=[_set_query("{__typename}")], is_control=True,
                          positive={"type": "body_contains", "value": "__typename"},
                          negative="a trivial GraphQL query does not respond, so this is not a GraphQL endpoint or the tooling is broken",
                          description="control: a trivial GraphQL query works"))
    n = 1
    probes = [
        ("schema", "full", INTROSPECTION, {"type": "body_contains", "value": "queryType"}),
        ("schema", "types_only", "query{__schema{types{name}}}", {"type": "body_contains", "value": "__schema"}),
        ("type", "query_type", "query{__type(name:\"Query\"){fields{name}}}", {"type": "body_contains", "value": "fields"}),
        ("get", "query_param", INTROSPECTION, {"type": "body_contains", "value": "queryType"}),
        ("suggest", "field_typo", "query{uuser{id}}", {"type": "body_regex", "pattern": r"(?i)did you mean|Cannot query field"}),
        ("suggest", "root_typo", "query{__schemaa{types{name}}}", {"type": "body_regex", "pattern": r"(?i)did you mean|Cannot query field"}),
        ("ctype", "application_graphql", INTROSPECTION, {"type": "body_contains", "value": "queryType"}),
        ("alias", "aliased_schema", "query{a:__schema{queryType{name}}}", {"type": "body_contains", "value": "queryType"}),
        ("mutation", "mutation_type", "query{__schema{mutationType{fields{name}}}}", {"type": "body_contains", "value": "mutationType"}),
        ("directive", "directives", "query{__schema{directives{name args{name}}}}", {"type": "body_contains", "value": "directives"}),
    ]
    for family, variant, q, cond in probes:
        if family == "get":
            mut = [{"op": "set_method", "method": "GET"}, {"op": "set_param", "location": "query", "name": "query", "value": q}]
        elif family == "ctype":
            mut = [{"op": "replace_body", "body": q, "content_type": "application/graphql"}]
        else:
            mut = [_set_query(q)]
        rung = "schema_via_suggestions" if family == "suggest" else "introspection_enabled"
        cases.append(TestCase(case_no=n, technique=f"graphql_introspection.{family}.{variant}", payload=q[:60],
                              mutation=mut, positive=cond,
                              negative=f"the {family}/{variant} probe does not reveal schema names",
                              rung=rung, description=f"GraphQL introspection: {family} {variant}"))
        n += 1
    return cases


@_gen("graphql_batching")
def gen_graphql_batching(ctx: Ctx) -> list[TestCase]:
    op = ctx.extra.get("limited_operation", "__typename")
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="graphql_batching.control.single", payload="{__typename}",
                          mutation=[_set_query("{__typename}")], is_control=True,
                          positive={"type": "body_contains", "value": "__typename"},
                          negative="a single operation does not respond, so the tooling is broken",
                          description="control: a single operation works"))
    n = 1
    # array batching
    for family, variant, size in [("array", "batch_5", 5), ("array", "batch_20", 20), ("array", "batch_50", 50)]:
        batch = json.dumps([{"query": "{__typename}"} for _ in range(size)])
        cases.append(TestCase(case_no=n, technique=f"graphql_batching.{family}.{variant}", payload=f"{size} ops",
                              mutation=[{"op": "replace_body", "body": batch, "content_type": "application/json"}],
                              positive={"type": "body_regex", "pattern": r"(\{[^{}]*__typename[^{}]*\}.*){2,}"},
                              negative=f"the server does not process a {size}-operation array batch",
                              rung="batching_accepted", description=f"GraphQL array batching: {size}"))
        n += 1
    # alias batching (many aliases of one field in a single operation)
    for family, variant, size in [("alias", "alias_10", 10), ("alias", "alias_50", 50), ("alias", "alias_100", 100)]:
        q = "query{" + " ".join(f"a{i}:__typename" for i in range(size)) + "}"
        cases.append(TestCase(case_no=n, technique=f"graphql_batching.{family}.{variant}", payload=f"{size} aliases",
                              mutation=[_set_query(q)],
                              positive={"type": "body_regex", "pattern": r"a\d+.*a\d+"},
                              negative=f"the server rejects {size} aliases in one operation",
                              rung="batching_accepted", description=f"GraphQL alias batching: {size}"))
        n += 1
    # operation-name batching and a directive-overload family (distinct families)
    for family, variant, body in [
        ("named", "two_named_ops", json.dumps({"query": "query A{__typename} query B{__typename}", "operationName": "A"})),
        ("directive", "repeated_skip", json.dumps({"query": "query{" + " ".join(f"a{i}:__typename @skip(if:false)" for i in range(10)) + "}"})),
    ]:
        cases.append(TestCase(case_no=n, technique=f"graphql_batching.{family}.{variant}", payload=variant,
                              mutation=[{"op": "replace_body", "body": body, "content_type": "application/json"}],
                              positive={"type": "body_contains", "value": "__typename"},
                              negative=f"the {variant} shape is rejected", rung="batching_accepted",
                              description=f"GraphQL {family} batching: {variant}"))
        n += 1
    # batching to bypass a limit on the sensitive operation (e.g. login attempts, OTP checks)
    for family, variant, size in [("bypass", "aliased_limited_10", 10), ("bypass", "aliased_limited_30", 30)]:
        q = "query{" + " ".join(f"a{i}:{op}" for i in range(size)) + "}"
        cases.append(TestCase(case_no=n, technique=f"graphql_batching.{family}.{variant}", payload=f"{size}x {op}",
                              mutation=[_set_query(q)],
                              positive={"type": "manual", "describe": f"confirm the limit on {op} was applied once for the whole batch, not per alias (compare the post-batch state or rate-limit counter)"},
                              negative=f"the {size} aliased calls to {op} are each limited",
                              rung="batching_bypasses_limit", description=f"GraphQL batching bypass of a limit on {op}"))
        n += 1
    return cases
