"""Vulnerability class registry: ladders, evidence minimums, n_a reasons,
matrix columns, recipe anchors and red-team prompts. Stdlib only."""

from __future__ import annotations

from dataclasses import dataclass, field

# --- reasons ---------------------------------------------------------------------

NA_REASONS = {
    "no_datastore_reach": "the input never reaches a query (proved by the cited request)",
    "no_command_reach": "the input never reaches a shell or OS command (proved by the cited request)",
    "no_url_input": "no input takes a URL, host or path",
    "not_state_changing": "the endpoint does not change state",
    "no_render_path": "the stored value is never rendered to any principal",
    "no_reflection": "the canary does not appear in any response",
    "no_header_reflection": "no input value reaches a response header",
    "no_object_identifier": "the request carries no object identifier",
    "not_list_endpoint": "the endpoint returns one object, not a collection",
    "no_file_input": "the endpoint accepts no file",
    "no_xml_parsing": "the endpoint never parses XML",
    "not_graphql": "the endpoint is not GraphQL",
    "no_json_body": "the endpoint takes no JSON body",
    "no_limit_or_counter": "no limit, counter, one-time token or uniqueness constraint",
    "no_cache_layer": "responses carry no shared-cache behaviour",
    "no_cors_headers": "no CORS headers are returned for any Origin",
    "no_message_listener": "no postMessage listener exists on the page",
    "static_asset": "the endpoint is a static asset",
    "programme_excluded": "the class is excluded for this endpoint (forced login/logout, CLAUDE.md)",
}

BLOCKED_REASONS = {
    "no_second_account": "needs a second principal that does not exist yet",
    "no_oob_listener": "needs an out-of-band listener; set OOB callback in prompt.md",
    "paid_tier": "feature is behind a paid tier",
    "geo_block": "feature is geo-restricted",
    "waf_block": "a WAF blocks every route the harness can drive",
    "feature_flag": "feature is behind a flag not enabled for the test accounts",
    "session_unavailable": "the principal's session cannot be established",
    "requires_browser": "needs a real browser step the harness cannot drive",
    "requires_researcher": "needs a human action (CAPTCHA, payment, KYC, phone)",
    "kill_switch": ".bbh/STOP is present",
    "verifier_unavailable": "the verifier agent/MCP is unreachable; the candidate is parked with its evidence for later verification (not confirmed, not refuted)",
    "other": "see unblock text",
}

# --- matrix columns (coverage-matrix skill) -----------------------------------------

COLUMNS = [
    "IDOR", "Mass-dump", "SQLi", "RCE", "XSS", "HTMLi", "CSRF", "Open-redirect",
    "CRLF", "SSRF", "Upload", "Race", "Info-leak",
]

# Section headings in coverage-matrix/references/classes.md
RECIPES = {
    "idor": "IDOR and broken authorization",
    "mass": "Mass data exposure",
    "sqli": "SQLi and NoSQLi",
    "rce": "Command injection (RCE)",
    "xss": "XSS and HTML injection",
    "csrf": "CSRF (test in Chrome)",
    "redirect": "Open redirect, CRLF, header injection",
    "ssrf": "SSRF",
    "file": "File handling",
    "race": "Race conditions",
    "cache": "Cache poisoning and deception",
    "info": "Information disclosure",
}

GENERIC_REDTEAM = [
    "Which evidence rule could explain this negative as a tooling artefact (silent client throttle, WAF on the scripted client, protocol mismatch, stale session)?",
    "Did you test the endpoint itself, or only the UI path that reaches it?",
    "Did you vary method, auth state, content type and parameter shape, or only the value?",
    "Is there a second principal (role, token, share link, unauthenticated) you did not try?",
    "Did you read the response body, or only the status?",
]


@dataclass(frozen=True)
class VulnClass:
    name: str
    column: str
    level: str  # "input" | "endpoint" | "family"
    ladder: tuple[str, ...]
    min_rung: str
    recipe: str
    cwe: str
    na_reasons: tuple[str, ...]
    redteam: str
    min_cases: int = 10
    min_techniques: int = 5
    cross_principal: bool = False
    needs_oob: bool = False
    base_priority: int = 50
    description: str = ""
    extra: dict = field(default_factory=dict)

    def rung_index(self, rung: str) -> int:
        try:
            return self.ladder.index(rung)
        except ValueError as exc:
            raise KeyError(f"{rung!r} is not a rung of {self.name}; rungs: {', '.join(self.ladder)}") from exc

    @property
    def min_rung_index(self) -> int:
        return self.ladder.index(self.min_rung)


def _c(name, column, level, ladder, min_rung, recipe, cwe, na, redteam, **kw) -> VulnClass:
    return VulnClass(name, column, level, tuple(ladder), min_rung, recipe, cwe, tuple(na), redteam, **kw)


MARKUP_NA = ("no_reflection", "no_render_path", "static_asset")

CLASSES: dict[str, VulnClass] = {c.name: c for c in [
    _c("htmli", "HTMLi", "input",
       ["canary_reflects", "raw_angle_brackets", "tag_renders", "dangling_markup"], "tag_renders",
       "xss", "CWE-80", MARKUP_NA,
       "Did you try every reflection context (text, attribute, script, URL) and dangling markup where script is blocked?",
       base_priority=60, description="HTML injection, reflected"),
    _c("htmli_stored", "HTMLi", "input",
       ["canary_reflects", "raw_angle_brackets", "tag_renders", "dangling_markup"], "tag_renders",
       "xss", "CWE-80", MARKUP_NA,
       "Did you view the stored value from every surface that renders it, as the principal who would see it?",
       cross_principal=True, base_priority=80, description="HTML injection, stored / second-order"),
    _c("xss_reflected", "XSS", "input",
       ["canary_reflects", "raw_angle_brackets", "tag_renders", "script_executes"], "script_executes",
       "xss", "CWE-79", MARKUP_NA,
       "Did you read the CSP first, and try attribute, JS-string and URL contexts rather than only <script> tags?",
       base_priority=60, description="Cross-site scripting, reflected"),
    _c("xss_stored", "XSS", "input",
       ["canary_reflects", "raw_angle_brackets", "tag_renders", "script_executes"], "script_executes",
       "xss", "CWE-79", MARKUP_NA,
       "Did you view the payload from the surface that renders it, as the principal who would see it?",
       cross_principal=True, base_priority=85, description="Cross-site scripting, stored / second-order"),
    _c("xss_dom", "XSS", "endpoint",
       ["source_reaches_sink", "script_executes"], "script_executes",
       "xss", "CWE-79", ("no_render_path", "static_asset"),
       "Did you trace the source to the sink in the JS rather than guessing, and drive the sink without synthetic clicks on javascript: URLs?",
       base_priority=55, description="DOM-based XSS from a traced source/sink"),
    _c("ssti", "XSS", "input",
       ["syntax_probe", "arithmetic_evaluates", "engine_identified"], "arithmetic_evaluates",
       "xss", "CWE-1336", ("no_reflection", "no_render_path", "static_asset"),
       "Did you probe every engine family's syntax, including the ones whose delimiters the app does not use elsewhere?",
       base_priority=60, description="Server-side template injection"),
    _c("csti", "XSS", "input",
       ["syntax_probe", "expression_evaluates", "framework_identified"], "expression_evaluates",
       "xss", "CWE-1336", ("no_reflection", "no_render_path", "static_asset"),
       "Did you check which client framework actually renders this region (Angular, Vue, Alpine) before closing?",
       base_priority=45, description="Client-side template injection"),
    _c("crlf", "CRLF", "input",
       ["encoded_crlf_reflects", "header_injected", "response_split"], "header_injected",
       "redirect", "CWE-93", ("no_header_reflection",),
       "Did you try every CRLF encoding (raw, %0d%0a, double-encoded, unicode line separators) in every header-reflected input and filename?",
       base_priority=45, description="CRLF / response splitting"),
    _c("header_injection", "CRLF", "input",
       ["reflects_in_header", "header_semantics_altered"], "header_semantics_altered",
       "redirect", "CWE-113", ("no_header_reflection",),
       "Did you test separators that alter header meaning without CRLF (semicolons in Set-Cookie, commas in Link, parameters in Content-Type)?",
       base_priority=40, description="Header value injection without line breaks"),
    _c("open_redirect", "Open-redirect", "input",
       ["redirect_to_attacker", "token_carried"], "redirect_to_attacker",
       "redirect", "CWE-601", ("no_url_input",),
       "Did you try every bypass shape from classes.md, and check whether the redirect carries a token?",
       base_priority=55, description="Open redirect"),
    _c("ssrf", "SSRF", "input",
       ["oob_callback", "oob_http_request", "response_reflected"], "oob_callback",
       "ssrf", "CWE-918", ("no_url_input",),
       "Does your listener accept the method the target actually sends, and did you try the redirect-through-listener case?",
       needs_oob=True, base_priority=65, description="Server-side request forgery (OOB only)"),
    _c("sqli", "SQLi", "input",
       ["error_differential", "boolean_pair", "time_based", "dbms_identified", "data_extraction"], "boolean_pair",
       "sqli", "CWE-89", ("no_datastore_reach", "static_asset"),
       "Did you measure a timing baseline before the delay payloads, and test sort/order parameters, JSON fields and headers?",
       min_cases=12, base_priority=70, description="SQL injection"),
    _c("command_injection", "RCE", "input",
       ["blind_timing", "command_output"], "blind_timing",
       "rce", "CWE-78", ("no_command_reach", "static_asset"),
       "Did you try every separator (; | & $() backtick newline), prove output with id/whoami, and prove blind execution with a measured sleep against the baseline?",
       min_cases=10, base_priority=92, description="OS command injection (RCE), non-destructive proof"),
    _c("nosqli", "SQLi", "input",
       ["operator_injection", "type_juggling", "boolean_differential"], "operator_injection",
       "sqli", "CWE-943", ("no_datastore_reach", "no_json_body", "static_asset"),
       "Did you send operators as JSON objects and as bracketed form keys, and juggle string to array and object?",
       base_priority=65, description="NoSQL operator injection"),
    _c("idor_read", "IDOR", "input",
       ["cross_principal_read"], "cross_principal_read",
       "idor", "CWE-639", ("no_object_identifier",),
       "Did you read the body as the other principal, vary the ID format, and try method swap and parameter pollution?",
       cross_principal=True, base_priority=90, description="Broken object-level authorization, read"),
    _c("idor_write", "IDOR", "input",
       ["cross_principal_write_counter_read"], "cross_principal_write_counter_read",
       "idor", "CWE-639", ("no_object_identifier", "not_state_changing"),
       "Did you counter-read as the owner after every cross-principal write, since a 200 can be a no-op?",
       cross_principal=True, base_priority=95, description="Broken object-level authorization, write"),
    _c("unauth_replay", "IDOR", "endpoint",
       ["unauth_read", "unauth_write_counter_read"], "unauth_read",
       "idor", "CWE-306", ("static_asset",),
       "Did you strip every cookie and auth header (including custom ones), and compare the body to the authenticated one?",
       cross_principal=True, base_priority=85, description="Unauthenticated replay of an authenticated request"),
    _c("mass_dump", "Mass-dump", "endpoint",
       ["scope_filter_bypassed_count"], "scope_filter_bypassed_count",
       "mass", "CWE-200", ("not_list_endpoint", "static_asset"),
       "Did you remove the scoping filter itself (absent, empty, null, 0, *, the other principal's value), not just the page size?",
       cross_principal=True, base_priority=90, description="Mass data exposure by widening scope"),
    _c("csrf", "CSRF", "endpoint",
       ["cross_origin_state_change"], "cross_origin_state_change",
       "csrf", "CWE-352", ("not_state_changing", "programme_excluded"),
       "Did you test token removed vs empty vs swapped separately, and text/plain, form and multipart bodies, after recording SameSite and Secure?",
       cross_principal=True, base_priority=80, description="Cross-site request forgery"),
    _c("mass_assignment", "IDOR", "endpoint",
       ["field_accepted_counter_read"], "field_accepted_counter_read",
       "idor", "CWE-915", ("not_state_changing", "no_json_body"),
       "Did you use the exact field and permission names seen in responses and JS, and counter-read to see whether any took effect?",
       base_priority=70, description="Mass assignment of fields the UI never sends"),
    _c("method_swap", "IDOR", "endpoint",
       ["alternate_method_bypasses_control"], "alternate_method_bypasses_control",
       "idor", "CWE-650", ("programme_excluded", "static_asset"),
       "Did you try every method and the override headers, and compare bodies rather than statuses?",
       base_priority=50, description="HTTP method swap bypassing a control"),
    _c("content_type_swap", "CSRF", "endpoint",
       ["parsed_as_alternate", "control_bypassed"], "control_bypassed",
       "csrf", "CWE-436", ("no_json_body", "not_state_changing"),
       "Did you confirm by the resulting state that the swapped body was parsed, not just that the status stayed 200?",
       base_priority=50, description="Content-type swap changing parsing or bypassing a control"),
    _c("upload", "Upload", "input",
       ["extension_bypass", "served_inline_same_origin", "script_executes"], "served_inline_same_origin",
       "file", "CWE-434", ("no_file_input",),
       "Did you identify the serving origin and Content-Disposition, and try extension, MIME and magic-byte bypasses independently?",
       base_priority=70, description="File upload handling"),
    _c("race", "Race", "endpoint",
       ["limit_exceeded_counter_read"], "limit_exceeded_counter_read",
       "race", "CWE-362", ("no_limit_or_counter", "not_state_changing"),
       "Did you confirm by reading the resulting state rather than the responses, with 20 or more synchronised requests?",
       base_priority=60, description="Race condition on a limit, counter or one-time token"),
    _c("path_traversal", "Upload", "input",
       ["normalisation_differential", "traversal_reads_app_file", "lfi_reads_system_file"], "traversal_reads_app_file",
       "file", "CWE-22", ("no_url_input", "no_file_input"),
       "Did you vary the encoding of the dot-dot sequences and the separator, compare against the normalisation baseline, and try the /etc/passwd and win.ini read-only proofs?",
       base_priority=55, description="Path traversal / LFI (app-owned files, plus the /etc/passwd and win.ini read-only proofs)"),
    _c("xxe", "SSRF", "endpoint",
       ["entity_expanded", "oob_entity_fetch"], "entity_expanded",
       "ssrf", "CWE-611", ("no_xml_parsing",),
       "Did you try the XML content type on JSON endpoints too, and an OOB parameter entity when inline expansion is invisible?",
       base_priority=55, description="XML external entity (no file entities)"),
    _c("graphql_introspection", "Mass-dump", "endpoint",
       ["introspection_enabled", "schema_via_suggestions"], "introspection_enabled",
       "mass", "CWE-200", ("not_graphql",),
       "Did you try field-suggestion and validation errors when introspection is disabled, since validation runs before auth?",
       base_priority=50, description="GraphQL schema exposure"),
    _c("graphql_batching", "Mass-dump", "endpoint",
       ["batching_accepted", "batching_bypasses_limit"], "batching_bypasses_limit",
       "mass", "CWE-799", ("not_graphql",),
       "Did you test array batching and alias batching separately against the limit you are trying to bypass?",
       base_priority=50, description="GraphQL batching against a limit"),
    _c("info_leak", "Info-leak", "endpoint",
       ["overfetch_field", "debug_output", "secret_reachable"], "overfetch_field",
       "info", "CWE-200", ("static_asset",),
       "Did you diff the API response against what the UI renders, and try the debug parameters from classes.md?",
       base_priority=55, description="Information disclosure / over-fetching"),
    _c("cache_deception", "Info-leak", "family",
       ["cached_private_response"], "cached_private_response",
       "cache", "CWE-524", ("no_cache_layer", "static_asset"),
       "Did you read Cache-Control, Age, X-Cache and Vary on every response before theorising?",
       base_priority=45, description="Web cache deception"),
    _c("cache_poisoning", "Info-leak", "family",
       ["unkeyed_input_reflected", "poisoned_entry_cache_busted"], "poisoned_entry_cache_busted",
       "cache", "CWE-444", ("no_cache_layer", "static_asset"),
       "Did every probe carry its own cache buster, so no shared entry was ever poisoned?",
       base_priority=40, description="Web cache poisoning (cache-busted probes only)"),
    _c("cors", "CSRF", "family",
       ["origin_reflected_with_credentials", "credentialed_read_confirmed"], "credentialed_read_confirmed",
       "csrf", "CWE-942", ("no_cors_headers", "static_asset"),
       "Did you check Secure and SameSite on the session cookie first, since without SameSite=None the credentialed read is dead?",
       cross_principal=True, base_priority=55, description="CORS misconfiguration with a credentialed read"),
    _c("postmessage", "XSS", "endpoint",
       ["listener_accepts_any_origin", "data_out_or_identity_honoured"], "data_out_or_identity_honoured",
       "xss", "CWE-346", ("no_message_listener",),
       "Does data go out, or does an injected identity get honoured? An inbound-only listener is worth nothing.",
       base_priority=50, description="postMessage listener without a working origin check"),
]}

# Technique ids are "<class>.<family>.<variant>". A negative needs at least one
# executed negative case from every family listed here (on top of 10 cases /
# 5 techniques). Generators must emit these families; the contract test checks it.
REQUIRED_FAMILIES: dict[str, tuple[str, ...]] = {
    "sqli": ("bool", "time"),
    "nosqli": ("op", "juggle"),
    "idor_read": ("cross",),
    "idor_write": ("cross",),
    "unauth_replay": ("strip",),
    "mass_dump": ("filter",),
    "csrf": ("token", "ctype"),
    "open_redirect": ("userinfo",),
    "crlf": ("newline",),
    "race": ("burst",),
    "ssrf": ("oob",),
    "mass_assignment": ("field",),
}
# Control families whose latest attempt must be control_pass.
REQUIRED_CONTROLS: dict[str, tuple[str, ...]] = {
    "sqli": ("control",),
}
# Classes whose cross-principal write cases only count with a counter-read.
COUNTER_READ_CLASSES = {"idor_write", "mass_assignment", "race", "csrf", "unauth_replay"}

ORDERBY_FAMILY = "orderby"


def get(name: str) -> VulnClass:
    try:
        return CLASSES[name]
    except KeyError as exc:
        raise KeyError(f"unknown vuln class {name!r}; known: {', '.join(sorted(CLASSES))}") from exc


def technique_family(technique: str) -> str:
    parts = technique.split(".")
    return parts[1] if len(parts) > 1 else ""


def technique_id(technique: str) -> str:
    """'sqli.time.pg_sleep' -> 'sqli.time'. The unit counted by the 5-technique rule."""
    return ".".join(technique.split(".")[:2])


def requirements(name: str, context: dict | None) -> dict:
    """Evidence minimums for closing a cell of this class negative."""
    vc = get(name)
    ctx = context or {}
    families = list(REQUIRED_FAMILIES.get(name, ()))
    if name == "sqli" and ctx.get("orderby"):
        families.append(ORDERBY_FAMILY)
    if name in ("xss_reflected", "xss_stored", "htmli", "htmli_stored"):
        ctxs = set(ctx.get("contexts") or [])
        if "html_attr" in ctxs:
            families.append("attr")
        if ctxs & {"js_string", "js_block"} and name.startswith("xss"):
            families.append("js")
    return {
        "min_cases": max(10, vc.min_cases),
        "min_techniques": max(5, vc.min_techniques),
        "required_families": families,
        "required_control_families": list(REQUIRED_CONTROLS.get(name, ())),
        "counter_read_required": name in COUNTER_READ_CLASSES,
        "needs_oob": vc.needs_oob,
    }


def redteam_prompt(name: str, nth: int = 0) -> str:
    vc = CLASSES.get(name)
    if vc is None:
        return GENERIC_REDTEAM[nth % len(GENERIC_REDTEAM)]
    if nth % 2 == 0:
        return vc.redteam
    return GENERIC_REDTEAM[(nth // 2) % len(GENERIC_REDTEAM)]


def column_classes() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {c: [] for c in COLUMNS}
    for vc in CLASSES.values():
        out[vc.column].append(vc.name)
    return out
