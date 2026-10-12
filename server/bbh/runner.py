"""Execute one planned case: build the request, substitute placeholders, send it
(sender / race burst / counter-read / OOB / private browser), evaluate the
case's condition, and record the result in the ledger.

This is what `send_case` and `run_cases` call. Cases executed through a browser
MCP instead go through `record_case` directly.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from . import evaluate as ev
from .cases.base import Ctx
from .httpraw import Exchange, Request, read_capture
from .mutate import InputRef, apply
from .normalise import normalise
from .planner import register_store_canary
from .sender import Sender


class RunnerError(RuntimeError):
    pass


def build_ctx(ledger, cell_id: int) -> tuple[Ctx, Request, dict, InputRef, str | None]:
    cell = ledger.cell(cell_id)
    ep = ledger.endpoint(cell["endpoint_id"])
    base = _base_request(ledger, ep, cell)
    inp = ledger.input(cell["input_id"]) if cell["input_id"] else None
    ctx_kwargs = dict(
        cell_id=cell_id, vuln_class=cell["vuln_class"], salt=cell["salt"], method=ep["method"],
        url=base.url, path_template=ep["path_template"], content_type=ep["content_type"],
        body_kind=normalise(base).body_kind, flags=ep["flags"], csp=_csp_of(ledger, ep),
        oob_configured=(ledger.engagement().get("oob") or {}).get("mode") not in (None, "none", "invalid"),
        extra=dict(cell["context"] or {}),
    )
    acting = "A" if any(p["label"] == "A" for p in ledger.principals()) else "unauth"
    other = "B" if any(p["label"] == "B" for p in ledger.principals()) else None
    ctx_kwargs["acting_principal"] = acting
    ctx_kwargs["other_principal"] = other
    ctx_kwargs["principals"] = [p["label"] for p in ledger.principals()]
    ref = InputRef(inp["name"], inp["location"], inp.get("json_path"), _path_index(ledger, ep, inp)) if inp else InputRef(None, None)
    if inp:
        ctx_kwargs.update(input_name=inp["name"], input_location=inp["location"], json_path=inp.get("json_path"),
                          sample_value=inp.get("sample_value"), value_type=inp.get("value_type"),
                          contexts=inp.get("reflection_contexts") or [])
    base_principal = None
    if ep.get("first_seen_request_id"):
        rr = ledger.q1("SELECT principal_id FROM requests WHERE id=?", (ep["first_seen_request_id"],))
        if rr and rr["principal_id"]:
            pr = ledger.q1("SELECT label FROM principals WHERE id=?", (rr["principal_id"],))
            base_principal = pr["label"] if pr else None
    return Ctx(**ctx_kwargs), base, cell, ref, base_principal


def _base_request(ledger, ep, cell) -> Request:
    rid = ep.get("first_seen_request_id")
    if rid:
        row = ledger.q1("SELECT raw_path FROM requests WHERE id=?", (rid,))
        if row and row["raw_path"] and ledger.paths.abs(row["raw_path"]).is_file():
            try:
                return read_capture(ledger.paths.abs(row["raw_path"])).request
            except Exception:  # noqa: BLE001
                pass
    # synthesize a minimal request from the template
    url = ep["origin"].rstrip("/") + ep["path_template"].replace("{id}", (cell["context"].get("own_object_id") or "1")).replace("{date}", "2020-01-01")
    return Request(method=ep["method"], url=url, headers=[("Host", ep["host"])])


def _path_index(ledger, ep, inp) -> int | None:
    if inp["location"] != "path":
        return None
    segs = [s for s in ep["path_template"].split("/")[1:]]
    for i, s in enumerate(segs):
        if s == "{id}":
            return i
    return None


def _csp_of(ledger, ep) -> str | None:
    rid = ep.get("first_seen_request_id")
    if rid:
        row = ledger.q1("SELECT raw_path FROM requests WHERE id=?", (rid,))
        if row and row["raw_path"] and ledger.paths.abs(row["raw_path"]).is_file():
            try:
                resp = read_capture(ledger.paths.abs(row["raw_path"])).response
                if resp:
                    return resp.header("Content-Security-Policy")
            except Exception:  # noqa: BLE001
                pass
    return None


def _substituter(ledger, cell_id: int, case_no: int, ctx: Ctx):
    """Return (substitute_fn, cleanup) resolving {{OOB}}, {{OTHER_ID}}, etc."""
    state = {}

    def sub(value):
        if not isinstance(value, str):
            return value
        out = value
        if "{{CACHE_BUSTER}}" in out:
            out = out.replace("{{CACHE_BUSTER}}", ctx.token(f"cb{case_no}"))
        if "{{OWN_ID}}" in out:
            own = ctx.extra.get("own_object_id") or "1"
            out = out.replace("{{OWN_ID}}", str(own))
        if "{{OTHER_ID}}" in out:
            other = ctx.extra.get("other_object_id")
            if other is None:
                raise RunnerError("this case needs the other principal's object id; set the cell context 'other_object_id' first")
            out = out.replace("{{OTHER_ID}}", str(other))
        if "{{OTHER_CSRF}}" in out:
            out = out.replace("{{OTHER_CSRF}}", ctx.extra.get("other_csrf", "0" * 24))
        if "{{OOB}}" in out or "{{OOB_HOST}}" in out:
            from .oob import oob_url

            if "oob" not in state:
                state["oob"] = oob_url(ledger, cell_id, case_no)
            o = state["oob"]
            if not o.get("configured"):
                raise RunnerError("no OOB listener configured: set 'OOB callback' in prompt.md, or close this cell blocked: no_oob_listener")
            out = out.replace("{{OOB}}", o["url"]).replace("{{OOB_HOST}}", o["host"])
        return out

    return sub, state


def run_case(ledger, cell_id: int, case_no: int, *, principal: str | None = None, sender: Sender | None = None,
             overrides: dict | None = None, browser_factory=None, now=time.time) -> dict:
    planned = ledger.planned_case(cell_id, case_no)
    if planned is None:
        raise RunnerError(f"cell {cell_id} has no planned case {case_no}; call plan/generate first")
    ctx, base, cell, ref, base_principal = build_ctx(ledger, cell_id)
    sender = sender or Sender(ledger)
    sub, state = _substituter(ledger, cell_id, case_no, ctx)
    technique = planned["technique"]
    route = planned["route"]
    case_principal = principal or planned.get("principal") or ctx.acting_principal
    cap_dir = ledger.paths.captures / str(cell_id)
    stem = f"{case_no}-{technique}"

    # build the mutated request
    try:
        mutated, principal_override = apply(base, planned["mutation"], ref, substitute=sub)
    except RunnerError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise RunnerError(f"mutation failed for case {case_no}: {type(exc).__name__}: {exc}")
    if principal_override:
        case_principal = principal_override
    if overrides and overrides.get("value") is not None and ref.location:
        mutated, _ = apply(mutated, [{"op": "set_input", "value": overrides["value"], "raw": overrides.get("raw", True)}], ref, substitute=sub)

    # register a store canary for stored classes so the next render-page read links it
    if cell["vuln_class"] in ("htmli_stored", "xss_stored") and planned.get("extra", {}).get("stores_token"):
        tok = planned["extra"]["stores_token"]
        if cell["input_id"]:
            register_store_canary(ledger, input_id=cell["input_id"], endpoint_id=cell["endpoint_id"], token=tok,
                                  principal_id=_pid(ledger, case_principal))

    eval_ctx = ev.EvalContext(this_case=case_no)
    counter_ex = None

    if route == "oob":
        res = sender.send(mutated, principal=case_principal, capture=cap_dir / f"{stem}.http", cell_id=cell_id,
                          case_no=case_no, technique=technique, route="oob", endpoint_id=cell["endpoint_id"],
                          vuln_class=cell["vuln_class"], base_principal=base_principal)
        eval_ctx.exchanges[case_no] = [res.exchange]
        # poll the OOB service briefly
        within = _within_s(planned["positive"])
        from .oob import oob_check

        deadline = now() + within
        hits = []
        while now() < deadline:
            hits = oob_check(ledger, cell_id)["hits"]
            if hits:
                break
            time.sleep(min(2.0, max(0.5, within / 10)))
        eval_ctx.oob_hits = hits
        exchange_for_block = res.exchange
    elif route == "race":
        burst = int(planned.get("extra", {}).get("burst", 20))
        results = sender.send_burst(mutated, principal=case_principal, n=burst, capture_dir=cap_dir / stem,
                                    cell_id=cell_id, case_no=case_no, technique=technique, endpoint_id=cell["endpoint_id"],
                                    base_principal=base_principal)
        eval_ctx.exchanges[case_no] = [r.exchange for r in results]
        exchange_for_block = results[0].exchange if results else None
        counter_ex = _counter_read(ledger, sender, planned, ctx, sub, cap_dir, stem, base)
        eval_ctx.counter = counter_ex
    elif route == "browser":
        return _run_browser_case(ledger, cell_id, case_no, planned, ctx, base, ref, sub, case_principal,
                                 sender, cap_dir, stem, base_principal, browser_factory, now)
    elif route == "counter_read":
        res = sender.send(mutated, principal=case_principal, capture=cap_dir / f"{stem}.http", cell_id=cell_id,
                          case_no=case_no, technique=technique, route="counter_read", endpoint_id=cell["endpoint_id"],
                          vuln_class=cell["vuln_class"], base_principal=base_principal)
        eval_ctx.exchanges[case_no] = [res.exchange]
        exchange_for_block = res.exchange
        counter_ex = _counter_read(ledger, sender, planned, ctx, sub, cap_dir, stem, base)
        eval_ctx.counter = counter_ex
    else:  # sender
        repeats = int(planned.get("repeat", 1))
        exchanges = []
        last = None
        for _ in range(max(1, repeats)):
            res = sender.send(mutated, principal=case_principal, capture=cap_dir / f"{stem}.http", cell_id=cell_id,
                              case_no=case_no, technique=technique, route="sender", endpoint_id=cell["endpoint_id"],
                              vuln_class=cell["vuln_class"], base_principal=base_principal)
            exchanges.append(res.exchange)
            last = res
        eval_ctx.exchanges[case_no] = exchanges
        exchange_for_block = last.exchange if last else None
        eval_ctx.third_party = bool(last and last.guard.third_party)

    # make lower-numbered cases' exchanges available to conditions that reference them
    _load_prior_exchanges(ledger, cell_id, case_no, eval_ctx)
    eval_ctx.base = _load_base_exchange(ledger, cell_id)

    outcome, observation = _decide(ledger, planned, eval_ctx, exchange_for_block, cap_dir, stem)
    counter_cap = ledger.paths.rel(cap_dir / f"{stem}-counter.http") if counter_ex is not None else None
    rec = ledger.record_case(cell_id=cell_id, case_no=case_no, technique=technique, outcome=outcome,
                             observation=observation, request_capture=ledger.paths.rel(cap_dir / f"{stem}.http") if route != "race" else ledger.paths.rel(cap_dir / stem / "00.http"),
                             response_capture=ledger.paths.rel(cap_dir / f"{stem}.http") if route != "race" else ledger.paths.rel(cap_dir / stem / "00.http"),
                             counter_capture=counter_cap, payload=planned.get("payload"),
                             principal=case_principal, route=route,
                             status=exchange_for_block.status if exchange_for_block else None,
                             elapsed_ms=exchange_for_block.elapsed_ms if exchange_for_block else None)
    return {"case_no": case_no, "technique": technique, "outcome": outcome, "observation": observation,
            "cell_state": rec["cell_state"], "route": route}


def _run_browser_case(ledger, cell_id, case_no, planned, ctx, base, ref, sub, principal, sender, cap_dir, stem,
                      base_principal, browser_factory, now) -> dict:
    bspec = planned.get("extra", {}).get("browser", {})
    # optional precheck: send the mutated request first; skip the browser if it is false
    precheck = bspec.get("precheck")
    exchange_for_block = None
    if bspec.get("open") in ("request", None) or precheck:
        mutated, _ = apply(base, planned["mutation"], ref, substitute=sub)
        res = sender.send(mutated, principal=principal, capture=cap_dir / f"{stem}.http", cell_id=cell_id,
                          case_no=case_no, technique=planned["technique"], route="browser", endpoint_id=cell_id and ledger.cell(cell_id)["endpoint_id"],
                          vuln_class=ledger.cell(cell_id)["vuln_class"], base_principal=base_principal)
        exchange_for_block = res.exchange
        if precheck:
            pc = ev.EvalContext(this_case=case_no, exchanges={case_no: [res.exchange]})
            r, _ = ev.evaluate(precheck, pc)
            if r is not True:
                return _record_browser(ledger, cell_id, case_no, planned, "negative",
                                       f"precheck false: the raw payload did not reflect ({ev.summarise(res.exchange)}); no browser opened", cap_dir, stem, principal)
    # launch the private browser
    from .browser import Browser, cookies_for

    url = ctx.url
    open_kind = bspec.get("open")
    fragment = None
    if open_kind == "path":
        url = base.origin.rstrip("/") + "/" + str(bspec.get("path", "")).lstrip("/")
    elif open_kind in ("request", None):
        mutated, _ = apply(base, planned["mutation"], ref, substitute=sub)
        url = mutated.url
    bviewer = bspec.get("principal", principal)
    where = None
    for key in ("fragment", "query"):
        if key in bspec:
            fragment = sub(bspec[key])
    messages = None
    if bspec.get("messages"):
        messages = [{"data": m.get("data"), "origin": m.get("origin", "*")} for m in bspec["messages"]]
    browser = (browser_factory or Browser)()
    with browser as drv:
        if not drv.available:
            return _record_browser(ledger, cell_id, case_no, planned, "inconclusive",
                                   "no private headless browser available; rerun via a browser MCP with record_case, or install one (route requires_browser)",
                                   cap_dir, stem, principal, need_cap=False)
        r = drv.visit(url, cookies=cookies_for(ledger, bviewer, url), fragment=fragment, messages=messages,
                      wait_ms=bspec.get("wait_ms", 1500))
    bres = r.as_dict()
    # counter-read for stored/csrf browser cases
    counter_ex = _counter_read(ledger, sender, planned, ctx, sub, cap_dir, stem, base)
    eval_ctx = ev.EvalContext(this_case=case_no, browser=bres, counter=counter_ex)
    if exchange_for_block is not None:
        eval_ctx.exchanges[case_no] = [exchange_for_block]
    _load_prior_exchanges(ledger, cell_id, case_no, eval_ctx)
    result, detail = ev.evaluate(planned["positive"], eval_ctx)
    if result is True:
        outcome, obs = ("control_pass" if planned["is_control"] else "positive"), f"browser: {detail}"
    elif result is None:
        outcome, obs = "inconclusive", f"browser inconclusive: {detail}"
    else:
        outcome, obs = ("control_fail" if planned["is_control"] else "negative"), f"browser: {detail} (title={bres.get('title','')[:40]!r})"
    # write a small browser-result capture so the evidence file exists
    bcap = cap_dir / f"{stem}.http"
    bcap.parent.mkdir(parents=True, exist_ok=True)
    if exchange_for_block is None:
        bcap.write_text("### bbh-browser-case\n" + json.dumps(bres, indent=1), encoding="utf-8")
    counter_cap = ledger.paths.rel(cap_dir / f"{stem}-counter.http") if counter_ex is not None else None
    rec = ledger.record_case(cell_id=cell_id, case_no=case_no, technique=planned["technique"], outcome=outcome,
                             observation=obs[:500], request_capture=ledger.paths.rel(bcap),
                             response_capture=ledger.paths.rel(bcap), counter_capture=counter_cap,
                             payload=planned.get("payload"), principal=principal, route="browser")
    return {"case_no": case_no, "technique": planned["technique"], "outcome": outcome, "observation": obs[:500],
            "cell_state": rec["cell_state"], "route": "browser"}


def _record_browser(ledger, cell_id, case_no, planned, outcome, obs, cap_dir, stem, principal, need_cap=True):
    bcap = cap_dir / f"{stem}.http"
    bcap.parent.mkdir(parents=True, exist_ok=True)
    bcap.write_text("### bbh-browser-case\n" + obs, encoding="utf-8")
    rc = None if outcome == "inconclusive" and not need_cap else ledger.paths.rel(bcap)
    rec = ledger.record_case(cell_id=cell_id, case_no=case_no, technique=planned["technique"], outcome=outcome,
                             observation=obs[:500], request_capture=rc, response_capture=rc,
                             payload=planned.get("payload"), principal=principal, route="browser")
    return {"case_no": case_no, "technique": planned["technique"], "outcome": outcome, "observation": obs[:500],
            "cell_state": rec["cell_state"], "route": "browser"}


def _counter_read(ledger, sender, planned, ctx, sub, cap_dir, stem, base) -> Exchange | None:
    spec = planned.get("extra", {}).get("counter_read")
    if not spec:
        return None
    principal = spec.get("principal", ctx.other_principal or "B")
    if spec.get("same_as_base"):
        req = base.copy()
    else:
        method = spec.get("method", "GET")
        path = sub(spec.get("path", "/"))
        url = path if path.startswith("http") else base.origin.rstrip("/") + "/" + path.lstrip("/")
        req = Request(method=method, url=url, headers=[("Host", base.host)])
        if spec.get("body"):
            req.body = sub(spec["body"]).encode()
        if spec.get("content_type"):
            req.set_header("Content-Type", spec["content_type"])
    res = sender.send(req, principal=principal, capture=cap_dir / f"{stem}-counter.http", route="counter_read",
                      endpoint_id=None)
    return res.exchange


def _decide(ledger, planned, eval_ctx, exchange_for_block, cap_dir, stem) -> tuple[str, str]:
    from . import blocks

    if exchange_for_block is not None:
        verdict = blocks.detect(exchange_for_block)
        if verdict.blocked:
            return "inconclusive", f"{verdict.reason} ({ledger.paths.rel(cap_dir / (stem + '.http'))})"
    result, detail = ev.evaluate(planned["positive"], eval_ctx)
    loc = ledger.paths.rel(cap_dir / f"{stem}.http")
    if result is True:
        return ("control_pass" if planned["is_control"] else "positive"), f"{detail} ({loc})"
    if result is None:
        return "inconclusive", f"could not evaluate: {detail} ({loc})"
    return ("control_fail" if planned["is_control"] else "negative"), f"{detail} ({loc})"


def _within_s(positive: dict) -> int:
    def walk(c):
        if c.get("type") == "oob_hit":
            return int(c.get("within_s", 20))
        for sub in c.get("of", []) if isinstance(c.get("of"), list) else ([c["of"]] if c.get("of") else []):
            w = walk(sub)
            if w:
                return w
        return 0
    return walk(positive) or 20


def _load_prior_exchanges(ledger, cell_id, case_no, eval_ctx):
    """Load lower-numbered cases' latest exchange so cross-case conditions can resolve."""
    for r in ledger.latest_cases(cell_id):
        if r["case_no"] >= case_no or r["case_no"] in eval_ctx.exchanges:
            continue
        cap = r.get("response_capture")
        if cap and ledger.paths.abs(cap).is_file():
            try:
                eval_ctx.exchanges[r["case_no"]] = [read_capture(ledger.paths.abs(cap))]
            except Exception:  # noqa: BLE001
                pass


def _load_base_exchange(ledger, cell_id) -> Exchange | None:
    ep = ledger.endpoint(ledger.cell(cell_id)["endpoint_id"])
    rid = ep.get("first_seen_request_id")
    if rid:
        row = ledger.q1("SELECT raw_path FROM requests WHERE id=?", (rid,))
        if row and row["raw_path"] and ledger.paths.abs(row["raw_path"]).is_file():
            try:
                return read_capture(ledger.paths.abs(row["raw_path"]))
            except Exception:  # noqa: BLE001
                pass
    return None


def _pid(ledger, principal):
    try:
        return ledger.principal(principal)["id"]
    except Exception:  # noqa: BLE001
        return None
