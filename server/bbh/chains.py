"""Cross-class chaining engine.

A single finding is often only worth a chain: an open redirect is informational
until it carries a victim's OAuth code to the attacker; an XSS is worth more once
you can reach a non-HttpOnly session cookie with it. This module composes the
*capabilities* that confirmed or candidate cells grant with *signals* observed in
the recorded traffic, and reports the concrete multi-step chains that become
viable, each with a test plan. It only DETECTS and QUEUES chains; the chain itself
is built and proven by the agent (usually a hosted PoC + the browser), because a
chain's payoff is an outbound exfiltration or a cross-site effect that the ledger
cannot assert on its own. Stdlib only.

`detect_chains(ledger)` returns one entry per chain whose hard preconditions are
met, newest evidence first, marking which were satisfied by a positive result and
which still need a precondition the agent must establish.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# A positive result (candidate or confirmed) in a class grants these capability tags.
CLASS_CAPS: dict[str, set[str]] = {
    "open_redirect": {"attacker_redirect"},
    "ssrf": {"server_fetch"},
    "xss_reflected": {"js_execution"},
    "xss_stored": {"js_execution", "stored_js"},
    "xss_dom": {"js_execution"},
    "csti": {"js_execution"},
    "csrf": {"cross_site_write"},
    "cors": {"cross_origin_read"},
    "idor_read": {"reads_foreign_object"},
    "idor_write": {"writes_foreign_object"},
    "mass_dump": {"reads_foreign_object"},
    "info_leak": {"leaks_secret"},
    "mass_assignment": {"sets_foreign_field"},
    "sqli": {"db_read"},
    "nosqli": {"db_read"},
    "command_injection": {"rce"},
    "path_traversal": {"reads_server_file"},
    "crlf": {"response_splitting"},
    "header_injection": {"response_splitting"},
    "upload": {"stores_file"},
    "cache_poisoning": {"shared_cache_write"},
    "cache_deception": {"shared_cache_write"},
}


@dataclass
class ChainRule:
    name: str
    needs: set[str]                 # hard preconditions; the chain is listed only when all are present
    boost: set[str] = field(default_factory=set)  # signals that raise it from hypothesis to high-confidence
    severity: str = "medium"
    test_plan: str = ""


# Ordered most-impactful first. Each `needs`/`boost` token is a capability (from CLASS_CAPS) or a
# traffic signal (from _signals). A chain whose needs are met but whose boosts are absent is still
# listed, as a hypothesis whose missing precondition the agent must establish.
CHAINS: list[ChainRule] = [
    ChainRule("Credential/token exfiltration via open redirect",
              needs={"attacker_redirect"}, boost={"token_in_url", "oauth_flow"}, severity="high",
              test_plan=("Host a collector (python -m http.server + ngrok https). Point the redirect parameter at it and "
                         "drive the login / OAuth / SSO flow that this host runs. Confirm the victim's code / access_token "
                         "/ session identifier arrives at the collector (in the path, query, or Referer). A redirect that "
                         "forwards no secret is informational only, so prove the secret actually leaves.")),
    ChainRule("SSRF by chaining a server-side fetcher through the open redirect",
              needs={"attacker_redirect", "server_fetch"}, severity="high",
              test_plan=("Give the server-side fetcher a URL on the open-redirect endpoint whose target is the internal "
                         "resource. If the fetcher follows the 3xx, it reaches a host its own allowlist forbade. Confirm "
                         "with the OOB listener or a readback; stay within scope and never touch cloud-metadata addresses.")),
    ChainRule("Account takeover: session/token theft via XSS",
              needs={"js_execution"}, boost={"token_in_url", "cookie_js_readable"}, severity="high",
              test_plan=("From the proven JS execution, read the session material the app exposes to script (a non-HttpOnly "
                         "cookie, a token in localStorage/sessionStorage, a CSRF token) and send it to your collector. Then "
                         "show that material authenticates as the victim. If every cookie is HttpOnly and no token is "
                         "script-readable, record that as the missing precondition rather than claiming ATO.")),
    ChainRule("CSRF-driven state change executed from XSS (same-site)",
              needs={"js_execution", "cross_site_write"}, severity="medium",
              test_plan=("Use the JS execution to issue the state-changing request in the victim's session, defeating any "
                         "SameSite defence the cross-site form could not. Counter-read as the victim to prove the state changed.")),
    ChainRule("Cross-origin data theft via permissive CORS",
              needs={"cross_origin_read"}, boost={"reads_foreign_object", "leaks_secret"}, severity="medium",
              test_plan=("From an attacker origin, issue the credentialed fetch the CORS policy wrongly allows and read a "
                         "response that carries the victim's data or a secret. Confirm SameSite/Secure do not already block "
                         "the credentialed cross-site request (verify before claiming exfiltration).")),
    ChainRule("Privilege escalation from a leaked credential or identifier",
              needs={"leaks_secret"}, boost={"reads_foreign_object"}, severity="high",
              test_plan=("Take the leaked token/key/identifier and use it against the endpoint it authorises. Prove it grants "
                         "access the test account should not have (a cross-account read/write), with a counter-read. Never use "
                         "a real third party's credential; demonstrate with the test principals only.")),
    ChainRule("Cache poisoning via response splitting / header injection",
              needs={"response_splitting"}, boost={"shared_cache_write"}, severity="medium",
              test_plan=("Inject a header/body via the splitting vector and show a shared cache stores and serves it to a "
                         "second request that carries a unique cache-buster, so the poisoned entry reaches another viewer.")),
    ChainRule("Stored-XSS worm / cross-principal impact",
              needs={"stored_js"}, boost={"reads_foreign_object"}, severity="high",
              test_plan=("Confirm the stored script executes in a DIFFERENT principal's session on the render page (not just "
                         "your own), then chain it to an action in that victim's session. Self-XSS with no cross-principal "
                         "render is out of scope.")),
    ChainRule("RCE pivot: read a secret off disk, then use it",
              needs={"rce"}, boost={"leaks_secret", "reads_server_file"}, severity="high",
              test_plan=("From the proven command execution (id/whoami), read a config/credential file the app owns (not "
                         "/etc/shadow) only far enough to prove access, then show the recovered secret grants further access. "
                         "Keep every command read-only; do not modify, delete or exfiltrate beyond the single proof.")),
]

_TOKEN_IN_URL = re.compile(r"[?&#/=](?:access_token|id_token|refresh_token|code|token|jwt|id_token|"
                           r"sessionid|session|sid|ticket|SAMLResponse|SAPISIDHASH|auth|api[_-]?key)=?[A-Za-z0-9._%-]{6,}", re.I)
_OAUTH_FLOW = re.compile(r"(?:/oauth|/authorize|/connect/authorize|/sso|/saml|/openid|response_type=|redirect_uri=|returnurl=)", re.I)


def _signals(ledger) -> set[str]:
    """Signals observed in recorded request URLs that complete a chain. Bounded, URL-only (the agent
    verifies Location headers and storage by hand per the test plan)."""
    sigs: set[str] = set()
    for row in ledger.q("SELECT url FROM requests ORDER BY id DESC LIMIT 4000"):
        u = row["url"] or ""
        if _TOKEN_IN_URL.search(u):
            sigs.add("token_in_url")
        if _OAUTH_FLOW.search(u):
            sigs.add("oauth_flow")
        if "token_in_url" in sigs and "oauth_flow" in sigs:
            break
    return sigs


def available_capabilities(ledger) -> dict[str, list[int]]:
    """Capability tag -> the cell ids (candidate or confirmed) that grant it."""
    caps: dict[str, list[int]] = {}
    for row in ledger.q("SELECT id, vuln_class FROM cells WHERE state IN ('candidate', 'confirmed')"):
        for cap in CLASS_CAPS.get(row["vuln_class"], ()):  # noqa: B007
            caps.setdefault(cap, []).append(row["id"])
    return caps


def detect_chains(ledger) -> list[dict]:
    """Chains whose hard preconditions (needs) are met. Each entry carries the contributing cell ids,
    which boosts are present, and whether it is high-confidence or a hypothesis missing a precondition."""
    caps = available_capabilities(ledger)
    cap_tags = set(caps)
    signals = _signals(ledger)
    have = cap_tags | signals
    out: list[dict] = []
    for rule in CHAINS:
        if not rule.needs <= have:
            continue
        contributing = sorted({cid for tag in rule.needs for cid in caps.get(tag, [])})
        boosts_present = sorted(rule.boost & have)
        missing = sorted(rule.boost - have)
        high_conf = bool(rule.boost) and bool(boosts_present)
        out.append({
            "name": rule.name,
            "severity": rule.severity,
            "needs": sorted(rule.needs),
            "from_cells": contributing,
            "boosts_present": boosts_present,
            "missing_preconditions": missing,
            "confidence": "high" if high_conf else "hypothesis",
            "test_plan": rule.test_plan,
        })
    return out
