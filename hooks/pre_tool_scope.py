"""PreToolUse scope + kill-switch + real-browser-safety + report-lint guard.

Denies: anything while .bbh/STOP exists; out-of-scope or target-adjacent hosts on
navigation/fetch/Burp/curl/WebFetch; non-http schemes on navigation; real-browser
tools to subagents and the dangerous browser tools to anyone; Firefox tools the
installed extension does not implement; verifier_signoff from a non-verifier;
claude.ai connectors to subagents; and any report-*.md write that fails the lint.
Allows support hosts (mail/IdP/ngrok/loopback) for navigation and WebFetch only.
"""

from __future__ import annotations

import os
import re
import sys

import _hooklib as h

BROWSER_PREFIXES = ("mcp__browser-mcp__", "mcp__claudecodebrowser__", "mcp__claude-in-chrome__")
NAV_TOOLS = {"browser_navigate", "navigate", "browser_create_tab", "tabs_create_mcp", "browser_get_new_tab"}
FETCH_TOOLS = {"browser_fetch"}
DANGEROUS_BROWSER = {"browser_provide_feedback", "browser_about", "browser_extract_token", "browser_solve_captcha",
                     "browser_reload_all", "browser_screenshot_all_tabs"}
FIREFOX_UNIMPLEMENTED = {"browser_get_value", "browser_set_value", "browser_select_option", "browser_hover",
                         "browser_wait_for_change", "browser_wait_for_network_idle", "browser_observe_element",
                         "browser_stop_observing", "browser_scroll_and_capture", "browser_click_and_wait",
                         "browser_start_logging", "browser_stop_logging", "browser_get_console_logs",
                         "browser_get_network_logs", "browser_clear_logs", "browser_eval_chain",
                         "browser_wait_and_act", "browser_inject_observer"}
FIREFOX_TAB_SCOPED = {"browser_close_tab", "browser_focus_tab", "browser_click", "browser_type", "browser_scroll",
                      "browser_get_elements", "browser_get_page_info", "browser_execute_script", "browser_screenshot",
                      "browser_select_option", "browser_set_value", "browser_highlight"}
URL_SCHEME_BAD = re.compile(r"^\s*(file|data|javascript|chrome|about|blob|ftp|view-source):", re.I)
CMD_URL = re.compile(r"""(?:curl|wget|http|https|Invoke-WebRequest|iwr|Invoke-RestMethod)\b[^\n|;]*?(https?://[^\s'"]+)""", re.I)


def _tool_name(data) -> str:
    return data.get("tool_name", "")


def _bare(name: str) -> str:
    return name.split("__")[-1]


def _urls_in(text: str):
    return re.findall(r"https?://[^\s'\"<>|]+", text or "")


def body(data, root):
    tool = _tool_name(data)
    ti = data.get("tool_input") or {}
    in_subagent = bool(data.get("agent_id") or data.get("agent_type"))

    # kill switch: refuse every network-capable tool and every bbh send tool
    if (root / ".bbh" / "STOP").exists():
        if (tool.startswith(BROWSER_PREFIXES) or tool.startswith("mcp__burp__")
                or tool in ("WebFetch",) or tool in ("Bash", "PowerShell")
                or any(s in tool for s in ("send_case", "run_cases", "fetch", "probe_reflection", "verify_finding"))):
            h.deny(".bbh/STOP is present (kill switch): this send is refused. Remove the file to resume.")
            return

    # verifier sign-off: only the verifier subagent may cast it (a candidate never dies on the
    # tester's own say-so). The main session acting solo is allowed.
    if tool.endswith("__verifier_signoff") and in_subagent and data.get("agent_type") not in ("bbh:verifier", "verifier"):
        h.deny("bbh: only the verifier agent may call verifier_signoff. A candidate going negative needs the verifier's "
               "independent refutation, not the tester's own sign-off.")
        return

    # claude.ai connectors never see captures/session material from a subagent
    if tool.startswith("mcp__claude_ai_") and in_subagent:
        h.deny("bbh: subagents must not call claude.ai connectors; captures and session material stay on this machine (Rule 0).")
        return

    # real-browser safety
    if tool.startswith(BROWSER_PREFIXES):
        bare = _bare(tool)
        if in_subagent:
            h.deny("bbh: subagents must never drive the researcher's real Chrome or Firefox. Use the private headless "
                   "browser (send_case route browser) or hand browser steps back to the main session.")
            return
        if bare in DANGEROUS_BROWSER:
            h.deny(f"bbh: {bare} is blocked (it posts to a public issue tracker, navigates to the researcher's own "
                   "dashboards, or acts on tabs the session does not own). Do the action another way.")
            return
        if tool.startswith("mcp__claudecodebrowser__"):
            if bare in FIREFOX_UNIMPLEMENTED:
                h.deny(f"bbh: {bare} returns 'Unknown action' on the installed Firefox extension (v1.0.0); it is not a "
                       "negative result. Use browser_execute_script or Burp instead.")
                return
            if bare in FIREFOX_TAB_SCOPED and not (ti.get("tab_id") or ti.get("tabId")):
                h.deny(f"bbh: {bare} needs an explicit tab_id on Firefox; without one it acts on the researcher's active "
                       "tab. Pass the tab_id of a tab the session created.")
                return

    # scope + scheme checks on URLs
    led = None
    scope_unavailable = False
    try:
        led = h.open_ledger(root)
        scope = led.scope()
        eng = led.engagement()
    except Exception as exc:  # noqa: BLE001
        scope = None
        eng = {}
        scope_unavailable = True
        h.log(root, "pre_tool_scope", f"ledger unavailable, failing closed for http(s) sends: {exc}")
    support = set((eng.get("support_hosts") or []))

    urls, is_nav, is_fetch, is_burp_host = [], False, False, None
    if tool in NAV_TOOLS or tool.endswith("__navigate") or _bare(tool) in NAV_TOOLS:
        is_nav = True
        urls = [ti[k] for k in ("url", "href") if ti.get(k)]
    elif _bare(tool) in FETCH_TOOLS or tool == "WebFetch":
        is_fetch = True
        urls = [ti[k] for k in ("url",) if ti.get(k)]
    elif tool.startswith("mcp__burp__"):
        host = ti.get("targetHostname")
        if host:
            https = ti.get("usesHttps", True)
            port = ti.get("targetPort") or (443 if https else 80)
            urls = [f"{'https' if https else 'http'}://{host}:{port}/"]
    elif tool in ("Bash", "PowerShell"):
        cmd = ti.get("command", "")
        urls = _urls_in(" ".join(m for m in CMD_URL.findall(cmd))) or []
        if not urls and re.search(r"\b(curl|wget|Invoke-WebRequest|Invoke-RestMethod)\b", cmd):
            urls = _urls_in(cmd)

    for u in urls:
        if is_nav and URL_SCHEME_BAD.match(u):
            h.deny(f"bbh: navigation to {u.split(':',1)[0]}: scheme is blocked (local-file/script/data access).")
            return
        if scope is None:
            # Fail CLOSED: the one guard that keeps the browser on-target must not let an
            # http(s) send through just because the ledger could not be read. (C3)
            if scope_unavailable and u.lower().startswith(("http://", "https://")):
                h.deny("bbh: the engagement ledger could not be read, so scope cannot be checked right now. "
                       "This send is refused until it is readable again (retry in a moment). Touch .bbh/STOP to stop entirely.")
                return
            continue
        try:
            scope.check_url(u)
            continue  # in scope
        except Exception as exc:  # ScopeError
            from urllib.parse import urlsplit

            host = (urlsplit(u).hostname or "").lower()
            # support hosts: allow navigation/WebFetch (mail, IdP, ngrok, loopback), never test traffic
            if host and _host_matches(host, support):
                if is_nav or tool == "WebFetch":
                    continue
                h.deny(f"bbh: {host} is a support host (mail/identity/PoC); navigate there, but do not send test traffic to it.")
                return
            # target-adjacent host (same registrable domain as an in-scope pattern) -> deny loudly
            adjacent = _adjacent(host, scope)
            extra = " It shares a registrable domain with the target but is not in scope; add it to prompt.md if the programme covers it." if adjacent else ""
            h.deny(f"bbh: {u} is out of scope ({exc}).{extra} Allowed: {', '.join(p.raw for p in scope.include)}. "
                   f"Support hosts you may navigate to: {', '.join(sorted(support)[:6])}.")
            return

    # report lint on report-*.md writes
    if tool in ("Write", "Edit"):
        fp = ti.get("file_path", "")
        if re.search(r"report-[^/\\]*\.md$", fp or ""):
            new_text = ti.get("content")
            if new_text is None:
                new_text = _apply_edit_preview(fp, ti)
            if new_text is not None:
                try:
                    from bbh.lint import lint_pending_edit

                    res = lint_pending_edit(fp, new_text, root)
                    if not res.ok:
                        h.deny("bbh report lint failed; fix these before writing the report:\n" + "\n".join(f"  - {p}" for p in res.problems[:12]))
                        return
                except Exception:  # noqa: BLE001
                    pass


def _apply_edit_preview(fp, ti):
    try:
        from pathlib import Path

        old = Path(fp).read_text(encoding="utf-8", errors="replace") if Path(fp).exists() else ""
        if ti.get("old_string") is not None and ti.get("new_string") is not None:
            return old.replace(ti["old_string"], ti["new_string"])
    except Exception:  # noqa: BLE001
        return None
    return None


def _host_matches(host: str, hosts: set) -> bool:
    for h_ in hosts:
        h_ = h_.lower()
        if h_.startswith("*."):
            if host == h_[2:] or host.endswith("." + h_[2:]):
                return True
        elif host == h_:
            return True
    return False


def _adjacent(host: str, scope) -> bool:
    if not host:
        return False
    try:
        from bbh.scope import registrable_domain
    except Exception:  # noqa: BLE001
        return False
    rd = registrable_domain(host)
    for p in scope.include:
        base = p.host[2:] if p.host.startswith("*.") else p.host
        if base and registrable_domain(base) == rd:
            return True
    return False


h.run("pre_tool_scope", body)
