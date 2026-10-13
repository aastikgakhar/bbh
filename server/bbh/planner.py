"""Deterministic rules first, model second: open cells from request/response shape,
probe reflection with a canary, and detect stored/second-order sightings. Stdlib
plus the sender (for probe_reflection). No model calls."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field

from . import classes as C
from .httpraw import Exchange, Request
from .normalise import InputSpec, input_roles, normalise

REFLECT_CONTEXTS = ("html_text", "html_attr", "js_string", "js_block", "url", "css", "json", "response_header", "none", "unknown")


@dataclass
class PlanReport:
    endpoint_id: int
    opened: dict[str, int] = field(default_factory=dict)  # class -> count
    cell_ids: list[int] = field(default_factory=list)
    na: list[tuple[int, str]] = field(default_factory=list)

    def note(self, cls: str, cid: int) -> None:
        self.opened[cls] = self.opened.get(cls, 0) + 1
        self.cell_ids.append(cid)


def _open(ledger, report, *, endpoint_id, input_id, cls, context=None, source="rule"):
    cid, created = ledger.open_cell(endpoint_id=endpoint_id, input_id=input_id, vuln_class=cls,
                                    context=context or {}, source=source)
    if created:
        report.note(cls, cid)
    elif context:
        ledger.update_cell_context(cid, context)
    return cid


def _close_na(ledger, report, cid, reason, request_id):
    try:
        ledger.close_cell(cid, "n_a", reason=reason, reason_request_id=request_id)
        report.na.append((cid, reason))
    except Exception:  # noqa: BLE001 - a cell already past open stays as it is
        pass


def plan(ledger, endpoint_id: int) -> PlanReport:
    """Open every cell the endpoint's shape calls for. Idempotent."""
    ep = ledger.endpoint(endpoint_id)
    report = PlanReport(endpoint_id)
    flags = ep["flags"]
    first_req = ep.get("first_seen_request_id")
    inputs = [dict(r) for r in ledger.q("SELECT * FROM inputs WHERE endpoint_id = ? ORDER BY id", (endpoint_id,))]
    state_changing = bool(flags.get("state_changing"))
    is_login = bool(flags.get("login"))
    is_logout = bool(flags.get("logout"))

    # endpoint-level classes
    _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls="unauth_replay")
    _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls="info_leak")
    if flags.get("list_endpoint"):
        _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls="mass_dump",
              context={"scope_params": [i["name"] for i in inputs if re.search(r"owner|user|account|tenant|workspace|org|team|group", i["name"], re.I)]})
    if flags.get("graphql"):
        for cls in ("graphql_introspection", "graphql_batching", "mass_dump"):
            _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls=cls)
    if state_changing:
        if is_login:
            cid = _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls="csrf")
            if first_req:
                _close_na(ledger, report, cid, "programme_excluded", first_req)  # forced login, CLAUDE.md
        elif is_logout:
            for cls in ("csrf", "method_swap"):
                cid = _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls=cls)
                if first_req:
                    _close_na(ledger, report, cid, "programme_excluded", first_req)  # forced logout
        else:
            for cls in ("csrf", "method_swap"):
                _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls=cls)
        if flags.get("json_body"):
            for cls in ("mass_assignment", "content_type_swap"):
                _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls=cls)
        if flags.get("limit"):
            _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls="race")
    elif flags.get("mutating_get"):
        for cls in ("csrf", "method_swap", "idor_write"):
            _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls=cls)
    if flags.get("xml_body"):
        _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls="xxe")

    # family-once classes
    fam_key = f"family_planned:{ep['origin']}:{ep['family']}"
    if not ledger.kv_get(fam_key):
        for cls in ("cache_deception", "cache_poisoning", "cors"):
            _open(ledger, report, endpoint_id=endpoint_id, input_id=None, cls=cls)
        ledger.kv_set(fam_key, True)

    # input-level classes
    for spec_row in inputs:
        iid = spec_row["id"]
        spec = InputSpec(name=spec_row["name"], location=spec_row["location"], sample=spec_row["sample_value"],
                         json_path=spec_row["json_path"], vtype=spec_row["value_type"] or "string")
        roles = input_roles(spec)
        ctxs = _u_list(spec_row["reflection_contexts"])
        ctx = {"contexts": ctxs, "value_type": spec.vtype, "location": spec.location}

        if ctxs and any(c in ("html_text", "html_attr", "url", "css") for c in ctxs):
            for cls in ("htmli", "xss_reflected", "ssti", "csti"):
                _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls=cls, context=ctx)
        if ctxs and any(c in ("js_string", "js_block") for c in ctxs):
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="xss_reflected", context=ctx)
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="ssti", context=ctx)
        if ctxs and "response_header" in ctxs:
            for cls in ("crlf", "header_injection"):
                _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls=cls, context=ctx)
        if "url_like" in roles:
            for cls in ("open_redirect", "ssrf"):
                _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls=cls, context=ctx)
        if "datastore" in roles:
            sqli_ctx = dict(ctx, orderby="orderby" in roles)
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="sqli", context=sqli_ctx)
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="nosqli", context=ctx)
        if "object_id" in roles:
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="idor_read", context=ctx)
            if state_changing or flags.get("mutating_get"):
                _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="idor_write", context=ctx)
        if "file_like" in roles:
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="path_traversal", context=ctx)
        if "command_like" in roles:
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="command_injection", context=ctx)
        if spec.location == "filename":
            _open(ledger, report, endpoint_id=endpoint_id, input_id=iid, cls="upload", context=ctx)

    if report.opened or report.na:
        ledger.event("plan", "endpoint", endpoint_id, detail={"opened": report.opened, "na": len(report.na)})
    return report


def plan_all(ledger) -> list[PlanReport]:
    reports = []
    for row in ledger.q("SELECT id FROM endpoints ORDER BY id"):
        reports.append(plan(ledger, row["id"]))
    return reports


# --- reflection detection --------------------------------------------------------------------------

def classify_contexts(body: str, token: str, *, headers: list[tuple[str, str]] | None = None) -> list[str]:
    """Where does `token` land in this response? A small tokenizer, not a full parser."""
    found: set[str] = set()
    for _, v in headers or []:
        if token in v:
            found.add("response_header")
    if token not in body and html.escape(token) not in body:
        return sorted(found) or ["none"]
    # strip <script>/<style> blocks to classify them separately
    for m in re.finditer(r"<script\b[^>]*>(.*?)</script>", body, re.S | re.I):
        block = m.group(1)
        if token in block:
            if re.search(r"""(['"])(?:(?!\1).)*""" + re.escape(token), block[:block.find(token) + len(token)], re.S):
                found.add("js_string")
            else:
                found.add("js_block")
    for m in re.finditer(r"<style\b[^>]*>(.*?)</style>", body, re.S | re.I):
        if token in m.group(1):
            found.add("css")
    # attribute vs text: look at each occurrence's surrounding tag context
    for occ in [m.start() for m in re.finditer(re.escape(token), body)]:
        before = body[max(0, occ - 400):occ]
        last_open = before.rfind("<")
        last_close = before.rfind(">")
        in_tag = last_open > last_close
        if in_tag:
            attr = re.search(r"(\w[\w-]*)\s*=\s*(['\"]?)[^'\">]*$", before[last_open:])
            name = attr.group(1).lower() if attr else ""
            if name in ("href", "src", "action", "formaction", "data", "poster", "cite", "background", "longdesc"):
                found.add("url")
            else:
                found.add("html_attr")
        else:
            seg = body[max(0, occ - 400):occ]
            if "<script" in seg.lower() and "</script" not in seg.lower():
                found.add("js_block")
            else:
                found.add("html_text")
    # JSON response that reflects the token
    bt = body.lstrip()[:1]
    if bt in ("{", "[") and token in body:
        found.add("json")
    return sorted(found) or ["unknown"]


def probe_reflection(ledger, sender, request_id: int) -> dict:
    """Resend the request once per input with a unique canary, record every context
    the canary lands in. One request per input at the engagement rate limit."""
    from .mutate import InputRef, apply

    rid = ledger.request(request_id)
    base = _load_request(ledger, rid)
    if base is None:
        raise ValueError(f"request {request_id} has no stored raw request to replay")
    n = normalise(base)
    row = ledger.q1("SELECT id FROM endpoints WHERE origin=? AND method=? AND path_template=?", (n.origin, n.method, n.path_template))
    endpoint_id = row["id"] if row else None
    out: dict[str, list[str]] = {}
    base_principal = None
    if rid.get("principal_id"):
        try:
            base_principal = ledger.q1("SELECT label FROM principals WHERE id=?", (rid["principal_id"],))["label"]
        except Exception:  # noqa: BLE001
            base_principal = None
    for i, spec in enumerate(n.inputs):
        if spec.location in ("cookie",) or spec.name.lower() in ("csrf", "xsrf", "_token"):
            continue
        canary = _canary(ledger, endpoint_id, i)
        ref = InputRef(spec.name, spec.location, spec.json_path, spec.path_index)
        try:
            mutated, _ = apply(base, [{"op": "set_input", "value": canary, "raw": True}], ref)
        except Exception:  # noqa: BLE001
            continue
        res = sender.send(mutated, principal=base_principal, base_principal=base_principal,
                          capture=ledger.paths.captures / "_recon" / f"reflect-{request_id}-{i}.http",
                          endpoint_id=endpoint_id, route="sender", meta={"probe": "reflection", "canary": canary})
        if res.exchange.response is None:
            continue
        contexts = classify_contexts(res.exchange.body_text, canary, headers=res.exchange.response.headers)
        iid = None
        if endpoint_id is not None:
            r = ledger.q1("SELECT id FROM inputs WHERE endpoint_id=? AND location=? AND name=?", (endpoint_id, spec.location, spec.name))
            iid = r["id"] if r else None
        if iid is not None:
            ledger.add_reflection_contexts(iid, contexts)
            ledger.add_canary(canary, kind="reflection", input_id=iid, endpoint_id=endpoint_id, request_id=request_id,
                              principal_id=rid.get("principal_id"))
        out[f"{spec.location}:{spec.name}"] = contexts
    if endpoint_id is not None:
        plan(ledger, endpoint_id)
    return out


def _canary(ledger, endpoint_id, i) -> str:
    import secrets

    tok = secrets.choice("abcdefghijklmnopqrstuvwxyz") + secrets.token_hex(5)
    while "bbh" in tok:
        tok = secrets.choice("abcdefghijklmnopqrstuvwxyz") + secrets.token_hex(5)
    return tok


def _load_request(ledger, rid: dict) -> Request | None:
    from .httpraw import read_capture

    if rid.get("raw_path"):
        p = ledger.paths.abs(rid["raw_path"])
        if p.is_file():
            try:
                return read_capture(p).request
            except Exception:  # noqa: BLE001
                pass
    return None


def scan_canaries(ledger, ex: Exchange, *, request_id: int, endpoint_id: int, principal_id: int | None) -> int:
    """A stored canary seen on a different endpoint or by a different principal is a
    second-order sighting: open stored cells on the input that stored it."""
    if ex.response is None:
        return 0
    body = ex.body_text
    hits = 0
    for row in ledger.q("SELECT token, input_id, endpoint_id, principal_id FROM canaries WHERE kind IN ('reflection','store')"):
        token = row["token"]
        if token not in body:
            continue
        same_ep = row["endpoint_id"] == endpoint_id
        same_pr = row["principal_id"] == principal_id
        if same_ep and same_pr:
            continue
        if ledger.add_sighting(token, request_id=request_id, endpoint_id=endpoint_id, principal_id=principal_id,
                               context="cross_endpoint" if not same_ep else "cross_principal"):
            hits += 1
            if row["input_id"]:
                inp = ledger.input(row["input_id"])
                ctx = {"render_endpoint": f"{ex.request.method} {ex.request.path_qs.split('?')[0]}",
                       "render_endpoint_id": endpoint_id, "viewer_principal_id": principal_id,
                       "stored_contexts": classify_contexts(body, token)}
                for cls in ("htmli_stored", "xss_stored", "ssti"):
                    _open(ledger, PlanReport(inp["endpoint_id"]), endpoint_id=inp["endpoint_id"], input_id=row["input_id"],
                          cls=cls, context=ctx, source="depth")
    return hits


def register_store_canary(ledger, *, input_id: int, endpoint_id: int, token: str, principal_id: int | None) -> None:
    ledger.add_canary(token, kind="store", input_id=input_id, endpoint_id=endpoint_id, principal_id=principal_id)


def _u_list(text):
    import json

    try:
        v = json.loads(text) if text else []
        return v if isinstance(v, list) else []
    except (TypeError, ValueError):
        return []
