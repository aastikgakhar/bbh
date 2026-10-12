"""Class generators. One module per family; each exports GENERATORS = {class: fn}.

Use `generate(ctx)` to get validated cases for any class. A class with no
generator raises, which the contract test turns into a failure.
"""

from __future__ import annotations

import importlib

from .base import Ctx, TestCase, check_contract  # noqa: F401

FAMILY_MODULES = (
    "markup",     # htmli, htmli_stored, xss_reflected, xss_stored, xss_dom
    "template",   # ssti, csti
    "injection",  # sqli, nosqli
    "redirect",   # open_redirect, crlf, header_injection
    "ssrf",       # ssrf, xxe
    "authz",      # idor_read, idor_write, unauth_replay, mass_dump, mass_assignment, method_swap
    "csrf",       # csrf, content_type_swap, cors
    "files",      # upload, path_traversal
    "race",       # race
    "graphql",    # graphql_introspection, graphql_batching
    "misc",       # info_leak, cache_deception, cache_poisoning, postmessage
)


def registry() -> dict:
    gens: dict = {}
    for mod in FAMILY_MODULES:
        try:
            m = importlib.import_module(f"{__name__}.{mod}")
        except ModuleNotFoundError as exc:
            if exc.name == f"{__name__}.{mod}":
                continue
            raise
        gens.update(getattr(m, "GENERATORS", {}))
    return gens


def generate(ctx: Ctx, *, strict: bool = True) -> list[TestCase]:
    gens = registry()
    fn = gens.get(ctx.vuln_class)
    if fn is None:
        raise KeyError(f"no generator for class {ctx.vuln_class!r}")
    cases = fn(ctx)
    if strict:
        problems = check_contract(ctx, cases)
        if problems:
            raise ValueError("generator contract violated:\n" + "\n".join(problems))
    return cases
