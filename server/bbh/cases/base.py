"""The test-case contract every class generator implements. Stdlib only.

A generator is `generate(ctx: Ctx) -> list[TestCase]`. The contract (enforced by
`check_contract` and tests/test_cases_contract.py for every class):

  * case 0 is the positive control (is_control=True); then >= 10 non-control
    cases numbered 1..n with no gaps;
  * the non-control cases span >= 5 distinct technique ids, where a technique
    id is "<class>.<family>" and every technique string is
    "<class>.<family>.<variant>";
  * the class's required families (classes.REQUIRED_FAMILIES, plus "orderby"
    for sort inputs and "attr"/"js" for those reflection contexts) are present;
  * every case carries a machine-checkable `positive` condition (at most two
    cases per class may be `manual`);
  * every payload passes `screen_payload` (non-destructive, no stable marker);
  * generation is deterministic for a given ctx.salt.

MUTATION OPS (list of dicts, applied in order to a copy of the base request):
  set_input        {value}                      replace the cell's input value (string)
  set_input_json   {value}                      replace the cell's JSON input with any JSON value (object/array/number/bool/null)
  append_input     {value}                      original value + value
  prepend_input    {value}                      value + original value
  remove_input     {}                           drop the input entirely
  duplicate_input  {value, position}            parameter pollution: add a second copy ("before"/"after")
  move_input       {to, value?}                 move the input to query|form|json|header|cookie (value defaults to current)
  set_param        {location, name, value}      add/replace any parameter (query|form|json|header|cookie); json value may be any JSON
  remove_param     {location, name}             remove any parameter
  set_header       {name, value}
  remove_header    {name}
  set_method       {method}
  set_content_type {value, reencode=true}       re-encode the body as text/plain | application/x-www-form-urlencoded | multipart/form-data | application/json | application/xml
  replace_body     {body, content_type?}
  set_path         {path}                       replace the whole path (query kept)
  append_path      {suffix}                     append to the path (e.g. "/x.css", ";.js")
  set_path_segment {index, value}               replace one path segment (0-based, after the leading "/")
  set_query_raw    {query}                      replace the raw query string
  as_principal     {principal}                  send as another principal label (A, B, unauth, ...)
  strip_auth       {}                           remove Cookie, Authorization and every header named in any session file
  set_cookie       {name, value}
  remove_cookie    {name}

PLACEHOLDERS inside any string value, substituted by the sender per case:
  {{OOB}}        a fresh out-of-band URL registered to this cell and case (http://<token>.<oob-base>/ or <base>/<token>)
  {{OOB_HOST}}   the host part of that URL
  {{OTHER_ID}}   the other principal's object id (cell context "other_object_id"); refused until it is set
  {{OWN_ID}}     the acting principal's own object id (cell context "own_object_id")
  {{CACHE_BUSTER}} a fresh random query value (every cache probe must use one)

CONDITIONS (dicts; `positive` of a case; evaluated by bbh.evaluate):
  body_contains {value} | body_not_contains {value} | body_regex {pattern}
  header_contains {name, value} | header_present {name} | header_regex {name, pattern}
  status_in {values} | location_host {host}
  elapsed_over_baseline {min_ms, baseline_case=0, all_repeats=true}
  len_diff {min_bytes, a="this", b=<case_no>}          |len(body a) - len(body b)| >= min_bytes
  same_as_case {case, max_len_diff=0}                   status equal and length within max_len_diff
  oob_hit {within_s=20}                                 any OOB interaction for this case's tokens
  counter_read_contains {value} | counter_read_not_contains {value}   on the counter-read exchange (route counter_read/race)
  browser_marker {token}                                private headless browser saw the token (console, dialog or title)
  third_party_seen {}                                   the Rule 0 guard saw records outside the test accounts
  all {of: [...]} | any {of: [...]} | not {of: {...}}
  manual {describe}                                     cannot be machine-checked: the agent must record_case it

  matches_base {max_len_ratio=0.25}                     status equals the captured base response and body length within the ratio (controls)
  browser_text_contains {value}                         the private browser's rendered document.body.innerText contains value
  elapsed_over_case {case, min_ms}                      every repeat of this case is >= min_ms slower than the median of case k
  same_as_case {case, a="this", max_len_diff=0}         (a is optional: compare case a, not this one, with case k)

ROUTES: sender (default) | counter_read (extra.counter_read = request spec, run after
the main request) | race (extra.burst = 20..30 parallel copies, then counter read) |
oob (payload uses {{OOB}}; poll after sending) | browser (private headless browser;
extra.browser = {"open": "url"|"poc"}) | manual.

EXACT SEMANTICS (the sender and evaluator implement precisely this):
  * Cases run in case_no order; a condition may only reference lower case numbers.
  * repeat=N sends the mutated request N times; a condition holds only if it holds
    for every repeat (elapsed_over_baseline compares each repeat with the MEDIAN
    elapsed of the baseline case's repeats).
  * "this" is the current case's exchange. len_diff {a: "this"|<case_no>, b: <case_no>}.
    same_as_case {case: k, max_len_diff: n} = same status and |len diff| <= n.
  * The control (case 0) is evaluated like any case: condition true -> control_pass,
    false -> control_fail. Its exchange is the baseline other cases compare against.
  * Request spec (extra.counter_read, also used by assertions):
      {"method": "GET", "path": "/api/notes/{{OTHER_ID}}", "principal": "B"}
      or {"same_as_base": true, "principal": "A"}  (re-send the unmodified base request)
      optional "body", "headers", "content_type". "path" is relative to the base origin.
  * counter_read route: send the mutated request, then the counter-read request; the
    counter_read_* conditions look at the counter-read exchange, all others at the
    main exchange. Its capture is saved as the case's counter capture.
  * Stored / second-order classes: the main request stores the payload as the acting
    principal; the counter read fetches ctx.extra["render_endpoint"] ("GET /path")
    as ctx.extra["viewer"] (default ctx.other_principal).
  * race route: extra.burst copies of the mutated request are sent with last-byte
    synchronisation (capped at 30 and counted against the rate limit), then
    extra.counter_read is sent once; conditions look at the counter read.
  * oob route: {{OOB}}/{{OOB_HOST}} are replaced with a unique URL for this case;
    after sending, the OOB service is polled for up to oob_hit.within_s seconds.
    If the engagement has no OOB service the case is recorded inconclusive.
  * browser route: extra.browser =
      {"open": "request"}                 navigate to the mutated request (GET) or auto-submit it (form POST)
      {"open": "path", "path": "/people"} send the mutated request first, then navigate to path
      {"open": "poc", "poc_kind": "form_urlencoded"|"form_text_plain"|"form_multipart"|"fetch_credentials"}
                                          serve a PoC page from the PoC origin that replays the mutated request cross-site
    plus optional "principal" (whose session the private browser carries), "wait_ms",
    and "precheck" (a condition evaluated on a plain sender exchange of the mutated
    request first; when it is false the case is negative and no browser is launched;
    use it so XSS cases only open a browser when the raw payload actually reflected).
    The browser records console messages, dialog texts (auto-dismissed), the final
    document.title and document.body.innerText; browser_marker {token} holds if the
    token appears in console, dialogs or title. Payloads that prove script execution
    must surface the token there, e.g. console.log('<token>') or document.title='<token>'.
  * XSS classes (xss_reflected, xss_stored, xss_dom) prove script EXECUTION, so their
    positive conditions are browser_marker (route browser). A raw reflection alone is
    a signal for the sibling htmli cell, never a positive for an xss cell.
  * Set TestCase.rung to the ladder rung a positive on that case demonstrates (see
    classes.CLASSES[name].ladder), e.g. "tag_renders", "arithmetic_evaluates",
    "engine_identified", "time_based", "boolean_pair", "redirect_to_attacker".
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from .. import classes as C

MUTATION_OPS: dict[str, tuple[str, ...]] = {
    "set_input": ("value",),
    "set_input_json": ("value",),
    "append_input": ("value",),
    "prepend_input": ("value",),
    "remove_input": (),
    "duplicate_input": ("value",),
    "move_input": ("to",),
    "set_param": ("location", "name", "value"),
    "remove_param": ("location", "name"),
    "set_header": ("name", "value"),
    "remove_header": ("name",),
    "set_method": ("method",),
    "set_content_type": ("value",),
    "replace_body": ("body",),
    "set_path": ("path",),
    "append_path": ("suffix",),
    "set_path_segment": ("index", "value"),
    "set_query_raw": ("query",),
    "as_principal": ("principal",),
    "strip_auth": (),
    "set_cookie": ("name", "value"),
    "remove_cookie": ("name",),
}

CONDITIONS: dict[str, tuple[str, ...]] = {
    "body_contains": ("value",),
    "body_not_contains": ("value",),
    "body_regex": ("pattern",),
    "header_contains": ("name", "value"),
    "header_present": ("name",),
    "header_regex": ("name", "pattern"),
    "status_in": ("values",),
    "location_host": ("host",),
    "elapsed_over_baseline": ("min_ms",),
    "len_diff": ("min_bytes", "b"),
    "min_len": ("min",),
    "same_as_case": ("case",),
    "oob_hit": (),
    "counter_read_contains": ("value",),
    "counter_read_not_contains": ("value",),
    "browser_marker": ("token",),
    "browser_text_contains": ("value",),
    "elapsed_over_case": ("case", "min_ms"),
    "third_party_seen": (),
    "matches_base": (),
    "all": ("of",),
    "any": ("of",),
    "not": ("of",),
    "manual": ("describe",),
}

ROUTES = ("sender", "counter_read", "race", "oob", "browser", "manual")
LOCATIONS = ("query", "path", "form", "json", "header", "cookie", "multipart", "filename")
MAX_BURST = 30


@dataclass
class Ctx:
    """Everything a generator may use. Built by the planner from the ledger."""

    cell_id: int
    vuln_class: str
    salt: str
    method: str = "GET"
    url: str = "http://127.0.0.1/"
    path_template: str = "/"
    input_name: str | None = None
    input_location: str | None = None
    json_path: str | None = None
    sample_value: str | None = None
    value_type: str | None = None  # int|uuid|email|url|host|path|bool|json|base64|string|empty
    contexts: list[str] = field(default_factory=list)
    content_type: str | None = None
    body_kind: str | None = None  # json|form|multipart|xml|text|none
    csp: str | None = None
    flags: dict = field(default_factory=dict)  # state_changing, list_endpoint, graphql, upload, orderby, auth_required, accepts_locations[...]
    principals: list[str] = field(default_factory=lambda: ["A", "B", "unauth"])
    acting_principal: str = "A"
    other_principal: str | None = "B"
    oob_configured: bool = False
    base_status: int | None = None  # status of the captured base response, when known
    base_length: int | None = None  # body length of the captured base response, when known
    extra: dict = field(default_factory=dict)  # cell context (render endpoint, other_object_id, ...)

    def token(self, n: int | str, length: int = 10) -> str:
        """Deterministic per cell and n. A letter then letters/digits, no fixed
        prefix, so no stable marker links tests across targets. Never contains
        'bbh' (the one banned marker), re-rolled with a counter until it does not."""
        alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
        salt = 0
        while True:
            h = hashlib.sha256(f"{self.salt}:{self.cell_id}:{n}:{salt}".encode()).hexdigest()
            num = int(h, 16)
            out = [alphabet[num % 26]]
            num //= 26
            while len(out) < length:
                out.append(alphabet[num % 36])
                num //= 36
            tok = "".join(out)
            if "bbh" not in tok:
                return tok
            salt += 1

    def number(self, n: int | str, lo: int = 100, hi: int = 999) -> int:
        h = hashlib.sha256(f"{self.salt}:num:{self.cell_id}:{n}".encode()).hexdigest()
        return lo + int(h, 16) % (hi - lo + 1)


@dataclass
class TestCase:
    __test__ = False  # not a pytest class

    case_no: int
    technique: str
    payload: str
    mutation: list[dict]
    positive: dict
    negative: str
    is_control: bool = False
    route: str = "sender"
    principal: str | None = None
    repeat: int = 1
    needs_counter_read: bool = False
    description: str = ""
    rung: str | None = None
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


Generator = Callable[[Ctx], list[TestCase]]

# --- validation --------------------------------------------------------------------------

def validate_mutation(ops: list[dict]) -> list[str]:
    problems: list[str] = []
    if not isinstance(ops, list):
        return ["mutation must be a list of op dicts"]
    for i, op in enumerate(ops):
        name = op.get("op") if isinstance(op, dict) else None
        if name not in MUTATION_OPS:
            problems.append(f"mutation[{i}]: unknown op {name!r}")
            continue
        for key in MUTATION_OPS[name]:
            if key not in op:
                problems.append(f"mutation[{i}] ({name}) needs {key!r}")
        if name in ("move_input",) and op.get("to") not in LOCATIONS:
            problems.append(f"mutation[{i}] move_input.to must be one of {LOCATIONS}")
        if name in ("set_param", "remove_param") and op.get("location") not in LOCATIONS:
            problems.append(f"mutation[{i}] {name}.location must be one of {LOCATIONS}")
    return problems


def validate_condition(cond: Any, path: str = "positive") -> list[str]:
    if not isinstance(cond, dict):
        return [f"{path} must be a dict"]
    t = cond.get("type")
    if t not in CONDITIONS:
        return [f"{path}: unknown condition type {t!r}"]
    problems = [f"{path} ({t}) needs {k!r}" for k in CONDITIONS[t] if k not in cond]
    if t in ("all", "any"):
        subs = cond.get("of") or []
        if not subs:
            problems.append(f"{path}.of must be non-empty")
        for j, sub in enumerate(subs):
            problems += validate_condition(sub, f"{path}.of[{j}]")
    elif t == "not":
        problems += validate_condition(cond.get("of"), f"{path}.of")
    return problems


def condition_types(cond: dict) -> set[str]:
    out = {cond.get("type")}
    if cond.get("type") in ("all", "any"):
        for sub in cond.get("of") or []:
            out |= condition_types(sub)
    elif cond.get("type") == "not":
        out |= condition_types(cond.get("of") or {})
    return out


# --- safety screen ---------------------------------------------------------------------------

_DESTRUCTIVE = [
    (re.compile(r"\b(drop|truncate|alter)\s+(table|database|schema|user|index)\b", re.I), "destructive SQL DDL"),
    (re.compile(r"\bdelete\s+from\b", re.I), "SQL DELETE"),
    (re.compile(r"\bupdate\s+\w+\s+set\b", re.I), "SQL UPDATE"),
    (re.compile(r"\binsert\s+into\b", re.I), "SQL INSERT"),
    (re.compile(r"\b(exec|execute)\s*(\(|\s+\w)", re.I), "SQL EXEC"),
    (re.compile(r"xp_cmdshell|sp_oacreate|into\s+(out|dump)file|load_file\s*\(|pg_read_file|lo_import|copy\s+\w+\s+(from|to)\s+program", re.I), "file/command primitive in SQL"),
    (re.compile(r"\b(shutdown|kill)\b\s*(;|$)", re.I), "server control statement"),
    (re.compile(r"(/etc/(passwd|shadow|hosts)|win\.ini|boot\.ini|/proc/self|system32|\\windows\\)", re.I), "system file path"),
    (re.compile(r"\b(file|gopher|dict|ldap|jar|netdoc|expect|php)://", re.I), "dangerous URL scheme"),
    (re.compile(r"\b(__import__|subprocess|popen|os\.system|getRuntime|ProcessBuilder|child_process|Runtime\.exec)\b", re.I), "code/command execution primitive"),
    (re.compile(r"(\$\((?!\s*\d)|`\s*(id|whoami|uname|cat|ls|curl|wget|ping|nslookup)\b|;\s*(id|whoami|uname|cat|ls|curl|wget|ping|nslookup)\b|\|\s*(nc|bash|sh|cmd|powershell)\b|\b(bash|sh)\s+-c\b|cmd(\.exe)?\s+/c|powershell\s+-)", re.I), "shell command"),
    (re.compile(r"<!ENTITY\s+%?\s*\w+\s+SYSTEM\s+[\"']file:", re.I), "file entity"),
    (re.compile(r"(<!ENTITY\s+\w+\s+\"(&\w+;){2,})", re.I), "recursive entity expansion"),
    (re.compile(r"\b(rm\s+-rf|mkfs|dd\s+if=|format\s+c:)", re.I), "destructive shell"),
    (re.compile(r"169\.254\.169\.254|metadata\.google\.internal|100\.100\.100\.200", re.I), "cloud metadata address"),
    (re.compile(r"bbh", re.I), "stable marker 'bbh' (identity hygiene)"),
]


def _strings(value: Any) -> list[str]:
    out: list[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, dict):
        for k, v in value.items():
            out += _strings(k) + _strings(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            out += _strings(v)
    return out


def screen_payload(case: TestCase) -> list[str]:
    """Return safety problems in a case's payload, mutation values and extra."""
    problems: list[str] = []
    texts = _strings(case.payload) + _strings(case.mutation) + _strings(case.extra.get("counter_read"))
    for text in texts:
        for rx, label in _DESTRUCTIVE:
            if rx.search(text):
                problems.append(f"case {case.case_no} ({case.technique}): {label} in {text[:80]!r}")
    if case.route == "race":
        burst = int(case.extra.get("burst", 0))
        if not (20 <= burst <= MAX_BURST):
            problems.append(f"case {case.case_no}: race burst must be 20..{MAX_BURST}, got {burst}")
    if case.repeat < 1 or case.repeat > 5:
        problems.append(f"case {case.case_no}: repeat must be 1..5")
    return problems


# --- contract ---------------------------------------------------------------------------------

def required_families_for(ctx: Ctx) -> list[str]:
    req = C.requirements(ctx.vuln_class, {"orderby": ctx.flags.get("orderby"), "contexts": ctx.contexts})
    return req["required_families"]


def check_contract(ctx: Ctx, cases: list[TestCase]) -> list[str]:
    problems: list[str] = []
    name = ctx.vuln_class
    if not cases:
        return [f"{name}: no cases generated"]
    if not cases[0].is_control or cases[0].case_no != 0:
        problems.append(f"{name}: case 0 must be the control")
    nums = [c.case_no for c in cases]
    if nums != list(range(len(cases))):
        problems.append(f"{name}: case numbers must be 0..{len(cases) - 1} without gaps, got {nums}")
    controls = [c for c in cases if c.is_control]
    if len(controls) > 3:
        problems.append(f"{name}: at most 3 control cases")
    body = [c for c in cases if not c.is_control]
    if len(body) < 10:
        problems.append(f"{name}: {len(body)} non-control cases, need >= 10")
    ids = {C.technique_id(c.technique) for c in body}
    if len(ids) < 5:
        problems.append(f"{name}: {len(ids)} technique ids {sorted(ids)}, need >= 5")
    for c in cases:
        if not c.technique.startswith(name + ".") or c.technique.count(".") < 2:
            problems.append(f"{name}: technique {c.technique!r} must be '{name}.<family>.<variant>'")
        if c.route not in ROUTES:
            problems.append(f"{name}: case {c.case_no} route {c.route!r} unknown")
        problems += [f"{name} case {c.case_no}: {p}" for p in validate_mutation(c.mutation)]
        problems += [f"{name} case {c.case_no}: {p}" for p in validate_condition(c.positive)]
        if not c.negative or not c.negative.strip():
            problems.append(f"{name}: case {c.case_no} needs a negative criterion")
        problems += screen_payload(c)
        if c.route == "counter_read" and "counter_read" not in c.extra:
            problems.append(f"{name}: case {c.case_no} route counter_read needs extra.counter_read")
        if c.route == "race" and "counter_read" not in c.extra:
            problems.append(f"{name}: case {c.case_no} route race needs extra.counter_read")
    manual = [c for c in body if "manual" in condition_types(c.positive)]
    if len(manual) > 2:
        problems.append(f"{name}: {len(manual)} manual cases; at most 2 may be manual")
    fams = {C.technique_family(c.technique) for c in body}
    for fam in required_families_for(ctx):
        if fam not in fams:
            problems.append(f"{name}: required family {name}.{fam}.* missing")
    for fam in C.REQUIRED_CONTROLS.get(name, ()):
        if not any(C.technique_family(c.technique) == fam for c in controls):
            problems.append(f"{name}: required control family {name}.{fam}.* missing")
    return problems
