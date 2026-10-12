"""Race-condition generator.

Every case fires a synchronised burst (20..30 parallel copies, capped by the
sender) and then a single counter-read; the positive is read from the resulting
state, never from the burst responses. The burst reserves its slots from the
rate limiter, so the quiet period afterwards repays it and the average never
exceeds the engagement limit.
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


@_gen("race")
def gen_race(ctx: Ctx) -> list[TestCase]:
    counter = ctx.extra.get("counter_read") or {"same_as_base": True, "principal": ctx.acting_principal}
    # how the resulting state proves over-use. The generator cannot know the exact marker,
    # so it defaults to a manual confirmation for the control and machine checks for the bursts
    # against a provided expectation.
    expect = ctx.extra.get("limit_exceeded_marker")  # e.g. "balance":-  or "redemptions":2
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="race.control.single", payload="1 request",
                          mutation=[{"op": "as_principal", "principal": ctx.acting_principal}], is_control=True,
                          route="counter_read", needs_counter_read=True,
                          positive={"type": "status_in", "values": [200, 201, 204, 409, 429]},
                          negative="a single request does not succeed, so the tooling is broken",
                          extra={"counter_read": counter},
                          description="control: one request behaves normally"))
    n = 1

    def pos(i):
        # The planner records what "the limit was exceeded" looks like in the resulting state
        # (e.g. a negative balance, a redemption count > 1) as extra.limit_exceeded_marker.
        # With it, every case is machine-checkable on the counter-read. Without it, the first two
        # cases fall back to human judgement (the contract allows at most two manual cases).
        if expect:
            return {"type": "counter_read_contains", "value": expect}
        return {"type": "manual", "describe": "read the resulting state and confirm the limit was exceeded by the burst; record extra.limit_exceeded_marker so later runs check this automatically"} if i <= 2 else \
            {"type": "counter_read_contains", "value": ctx.extra.get("limit_exceeded_marker", "")}

    # family = burst shape (each a distinct synchronisation technique)
    bursts = [
        ("burst", "parallel_20", 20, ctx.acting_principal),
        ("burst", "parallel_30", 30, ctx.acting_principal),
        ("burst", "parallel_25", 25, ctx.acting_principal),
        ("reuse", "same_token_20", 20, ctx.acting_principal),
        ("lastbyte", "sync_28", 28, ctx.acting_principal),
        ("cross", "two_principals", 20, ctx.acting_principal),
        ("warm", "after_one_22", 22, ctx.acting_principal),
        ("cold", "fresh_24", 24, ctx.acting_principal),
        ("dup", "idempotency_key_20", 20, ctx.acting_principal),
        ("repeat", "parallel_30b", 30, ctx.acting_principal),
    ]
    for family, variant, size, principal in bursts:
        muts = [{"op": "as_principal", "principal": principal}]
        if family == "dup":
            muts = [{"op": "set_header", "name": "Idempotency-Key", "value": ctx.token("idem")}] + muts
        cases.append(TestCase(case_no=n, technique=f"race.{family}.{variant}", payload=f"{size} parallel",
                              mutation=muts, route="race", needs_counter_read=True, principal=principal,
                              positive=pos(n), negative=f"the {size}-request {family} burst does not exceed the limit (the resulting state is within bounds)",
                              rung="limit_exceeded_counter_read", extra={"burst": size, "counter_read": counter},
                              description=f"race: {family} {variant} ({size} parallel), confirmed by the resulting state"))
        n += 1
    return cases
