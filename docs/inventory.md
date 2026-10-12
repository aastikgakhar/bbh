# Inventory

Written 2026-10-12 before any harness code, from a read-only audit by five agents (two of them independent, for the egress question) plus measurements and a probe plugin run by me. The full per-tool tables with argument shapes, file:line evidence and the commands run are in `docs/inventory-raw/`:

| Raw note | Covers |
|---|---|
| `inventory-raw/chrome-browser-mcp.md` | Agent360 Browser MCP: Chrome extension 1.30.1 and its npx server; 40 tools with argument shapes (section 2) |
| `inventory-raw/firefox-claudecodebrowser.md` | ClaudeCodeBrowser: Firefox extension 1.0.0, MCP server HEAD d5f6bbe, native host; 39 tools with argument shapes (section 3) |
| `inventory-raw/mcp-and-config.md` | Burp MCP (24 tools), claude-in-chrome (22), claude.ai connectors, Claude Code config, Burp project options, environment |
| `inventory-raw/egress-redteam.md` | Independent adversarial audit: every path that sends data off the machine or opens a listener |

## 1. The methodology that is the behaviour spec

Read in full: `.claude/CLAUDE.md`, `prompt.md` (still the unfilled template), `.claude/settings.local.json` (one allow rule: `mcp__claudecodebrowser__browser_get_tabs`), and the four skills with their references:

| Skill | Files |
|---|---|
| `recon` | `SKILL.md`, `references/js-audit.md`, `references/source-recovery.md` |
| `coverage-matrix` | `SKILL.md`, `references/classes.md`, `references/evidence-rules.md` |
| `report-writer` | `SKILL.md`, `references/template.md` |
| `triage-gate` | `SKILL.md`, `references/agent-brief.md` |

Contradictions between these and the build spec are listed in `design.md` Section 13.

## 2. MCP servers and what each can do

| Server | Scope / transport | Tools | Network requests? | Full response bodies? | JS in page | Tab identity |
|---|---|---|---|---|---|---|
| `burp` | local scope, project `C:/Tools/burp-mcp` only; SSE `http://127.0.0.1:9876` (PortSwigger `burp-suite` 1.1.2, inside BurpSuite.exe, which also owns proxy `127.0.0.1:8080`) | 24 | yes: full proxy history and WebSocket history, by offset | **no**: every history record is cut at 5,000 characters total (measured, see 2.1) | none | n/a; records identified by offset only |
| `browser-mcp` (Chrome) | user scope, stdio `npx @agent360/browser-mcp@latest` (1.30.1) | 40 | no history tool; `browser_wait_for_network` returns one future response, body cut to 5,000 chars, no headers, unreliable method | no | yes, page main world (MAIN `new Function`, then CDP `Runtime.evaluate`, which bypasses page CSP) | Chrome tab ids, scoped per server port into a "Claude N" tab group |
| `claudecodebrowser` (Firefox) | local scope, project `C:/Tools/burp-mcp` only; stdio wrapper to HTTP `127.0.0.1:8765` | 39 (19 return "Unknown action" against the installed extension) | no: no `webRequest`; the logging tools are not implemented by the installed extension | no | yes, isolated content-script world (page globals invisible; `fetch` from there is extension-privileged, not page-equivalent) | raw Firefox tab ids, no ownership; omitted `tab_id` = the researcher's active tab |
| `claude-in-chrome` | built into Claude Code (account bridge); the extension is not installed in any local profile | 22 | `read_network_requests`: metadata only, no bodies promised | no | yes, `javascript_tool` (page context) | `tabId` inside its MCP tab group |
| claude.ai Claude Docs | remote connector | 8 | n/a | n/a | n/a | n/a |
| claude.ai Gmail, Google Drive | remote connectors, unauthenticated | 2 each | n/a | n/a | n/a | n/a |

Exact tool names and argument shapes: Burp in Section 2.1 below; browser-mcp in `inventory-raw/chrome-browser-mcp.md` Section 2; claudecodebrowser in `inventory-raw/firefox-claudecodebrowser.md` Section 3; claude-in-chrome and the connectors in `inventory-raw/mcp-and-config.md` Sections 3.4 and 3.5.

**Conclusion for ingest:** Burp is the only source of complete request/response pairs, and even Burp truncates over MCP. Neither browser MCP can serve as a body-bearing fallback. bbh therefore (a) ingests requests and headers from Burp, (b) captures every exchange it sends itself in full, and (c) re-fetches through its own sender whenever a full body matters.

### 2.1 Burp MCP, measured

Tool shapes (`*` required): `send_http1_request(content*, targetHostname*, targetPort*: int, usesHttps*: bool)`, `send_http2_request(headers*: map, pseudoHeaders*: map, requestBody*, targetHostname*, targetPort*, usesHttps*)`, `create_repeater_tab(content*, tabName, targetHostname*, targetPort*, usesHttps*)`, `create_repeater_tab_http2(...)`, `send_to_intruder(content*, tabName, targetHostname*, targetPort*, usesHttps*)`, `get_proxy_http_history(count*, offset*)`, `get_proxy_http_history_regex(count*, offset*, regex*)`, `get_proxy_websocket_history(count*, offset*)`, `get_proxy_websocket_history_regex(...)`, `get_organizer_items(count*, offset*)`, `get_organizer_items_regex(...)`, `output_project_options()`, `output_user_options()`, `set_project_options(json*)`, `set_user_options(json*)`, `set_proxy_intercept_state(intercepting*)`, `set_task_execution_engine_state(running*)`, `get_active_editor_contents()`, `set_active_editor_contents(text*)`, `url_encode/url_decode/base64_encode/base64_decode(content*)`, `generate_random_string(characterSet*, length*)`.

Measured on this machine (masked output, no history content printed):

- Python reaches Burp's MCP directly with `mcp.client.sse.sse_client("http://127.0.0.1:9876")`: initialize about 1.2 s, a history call about 0.08 s at low offsets.
- One text content per call, holding `{"request": raw, "response": raw, "notes": ""}` records separated by blank lines.
- **Every record is cut at 5,000 characters total** with the suffix `... (truncated)`; 42 of 94 records in the current history were cut, and every cut record fails `json.loads`. The request comes first, so request lines and headers usually survive; response bodies usually do not. Binary bodies arrive mangled.
- Offset 0 is the oldest record. Past the end the tool returns `Reached end of items`. There are no ids or timestamps.
- `send_http1_request` / `send_http2_request` return Burp's `HttpRequestResponse{httpRequest=..., httpResponse=...}` text, not a raw pair.
- Burp's own target scope is empty and out-of-scope traffic is not dropped (from `output_project_options`, called once, read-only). bbh enforces scope itself and does not write Burp settings.
- Proxy listener: one, `127.0.0.1:8080`, loopback only. Burp's CA is trusted in the Windows CurrentUser store, not in Python's certifi; `truststore` 0.10.4 is installed, so the sender verifies TLS through Burp with the system store instead of disabling verification.

### 2.2 Permissions (manifests, verbatim summary)

- **Agent360 (Chrome 1.30.1):** `tabs`, `tabGroups`, `cookies`, `scripting`, `activeTab`, `storage`, `alarms`, `offscreen`, `notifications`, `webNavigation`, `debugger`; host `<all_urls>`; extension CSP `connect-src 'self' ws://127.0.0.1:* http://127.0.0.1:*`; no content scripts, no `externally_connectable`, no `web_accessible_resources`; CWS `update_url`. Runtime grants in Profile 4: file URL access ON, incognito ON, site access all sites.
- **ClaudeCodeBrowser (Firefox 1.0.0, MV2):** `activeTab`, `tabs`, `nativeMessaging`, `storage`, `<all_urls>`, `webNavigation`, `contextMenus`; content script on `<all_urls>`, all frames, `document_end`; `web_accessible_resources: icons/*`; no `cookies`, no `webRequest`; native host `claudecodebrowser` allowed only for `claudecodebrowser@ligandal.com`; private browsing not allowed.

## 3. Anything that sends data off localhost (both audits agree)

Neither stack has telemetry, crash reporting, analytics SDKs, remote script loading, AI-API calls, or obfuscated URLs. Every programmatic endpoint is loopback. What does leave the machine, or can:

| Severity | Component | What and when |
|---|---|---|
| Medium (supply chain) | browser-mcp server | `npx @agent360/browser-mcp@latest` fetches and runs the newest npm release at every session start, with no pin. |
| Medium (supply chain) | both extensions | Chrome Web Store and AMO auto-updates silently replace code that already holds `<all_urls>` (plus `debugger` and `cookies` on Chrome, `nativeMessaging` on Firefox). |
| Medium | browser-mcp `browser_provide_feedback`, `browser_about` | Build a pre-filled **public GitHub issue** link carrying the target origin and path, error text and environment details; the server's injected instructions tell the agent to call them without asking. Nothing is sent unless the link is opened. |
| Medium (agent-mediated) | navigate / execute_script / fetch / upload tools in both | No URL scope or scheme check anywhere: `file://`, `data:` and any third-party URL are accepted, and Chrome has file URL access ON. Prompt injection from a page can steer these. |
| Medium | browser-mcp `browser_ask_user` (1.30.1) | The overlay is drawn in the target page's main world, so the page and its third-party scripts can read what the researcher types. Fixed in 1.30.2 (not installed). |
| By design | every tool | Results (page text, cookies, screenshots) go to the MCP client and the model provider. |

Local trust problems (not egress, but the same threat model; both audits flagged them):

1. **High:** the Agent360 extension connects to and obeys any process that answers HTTP 426 on `127.0.0.1:9876-9895`, with no authentication, scanning every 2 s. Any local process can take full control of the logged-in Chrome profile. Burp's MCP already sits on 9876, inside that range.
2. **High:** the installed Firefox extension forwards `runtime.onMessageExternal` from any other installed extension into its command handler with no sender check. Eight third-party extensions are active in that profile, including a free VPN. The workspace 1.4.0 build fixes this but is not installed.
3. **Low today:** the ClaudeCodeBrowser WebSocket on `127.0.0.1:8766` has no auth and no Origin check; command dispatch to it is currently broken by an asyncio bug, so it is latent.
4. Local data at rest: `native_host.log` stores typed text, scripts and results in clear; `mcp_server.log` is 405 MB with no rotation; 215 screenshots of logged-in pages sit in world-readable `C:\tmp\claudecodebrowser\screenshots`; the Chrome extension's legacy LevelDB still holds 308 old action-log entries.

Recommendations for the researcher (none applied; each is a change to their environment): pin `@agent360/browser-mcp` to a version; set `BROWSER_MCP_EXTENSION_ID=jdehgalffmffhfhmmhaokfbfnafnmgcl`; move either Burp MCP or browser-mcp out of the shared 9876-9895 range (for example `BROWSER_MCP_BASE_PORT=9900`); turn off "Allow access to file URLs" for the Chrome extension; upgrade or remove the Firefox extension's `onMessageExternal` path; review the free VPN extension in the testing Firefox profile; purge `C:\tmp\claudecodebrowser\screenshots` and the old logs.

## 4. Ports in use (bbh must avoid all of these)

| Port | Owner |
|---|---|
| 8080 | Burp proxy |
| 8765, 8766 | ClaudeCodeBrowser server (open whenever Firefox runs) |
| 9222 | conventional CDP port (free now; avoided) |
| 9876 | Burp MCP (SSE) |
| 9876-9895 | Agent360 extension scan range: bbh must never listen here, or the extension connects and obeys it |

bbh defaults: lab `5057`, OOB listener `7731`, PoC server `7732`, dashboard `7733`, private headless browser debugging ports chosen dynamically outside the ranges above.

## 5. Claude Code: verified behaviour (docs plus an empirical probe)

A docs-reading agent produced a first answer; several of its claims were wrong or garbled, so every detail bbh depends on was then checked empirically with a throwaway probe plugin run in headless `claude -p` 2.1.287 on this machine (scratch folder, no researcher MCP servers, all real-browser tools denied).

| Detail | Verified fact | Source |
|---|---|---|
| Plugin layout | `.claude-plugin/plugin.json`, `.mcp.json` at plugin root auto-registered, `hooks/hooks.json`, `agents/`, `skills/` | docs + probe |
| Validation | `claude plugin validate <dir>` exists and passed the probe | probe |
| Loading for development / headless | `--plugin-dir <dir>` loads hooks, MCP server, agents and skills | probe |
| Plugin MCP tool names | `mcp__plugin_<plugin>_<server>__<tool>`: bbh tools are `mcp__plugin_bbh_bbh__<tool>` | probe (`mcp__plugin_probe_probe__ping`) |
| MCP server cwd and env | cwd is the session's project directory; `${CLAUDE_PROJECT_DIR}` expands in `.mcp.json` `env`, and `CLAUDE_PROJECT_DIR` is also set in the server's environment | probe |
| Hook shell on Windows | hook commands ran under Git Bash (`MSYSTEM=MINGW64`); `python "${CLAUDE_PLUGIN_ROOT}/hooks/x.py"` works; substituted paths use forward slashes. The docs agent's "cmd.exe" claim was wrong for this install. | probe |
| Hook env | `CLAUDE_PROJECT_DIR`, `CLAUDE_PLUGIN_ROOT`, `CLAUDE_PLUGIN_DATA` | probe |
| SessionStart | input `source` (`startup`, `resume`, `clear`, `compact`), `cwd`, `session_id`, `transcript_path`; `hookSpecificOutput.additionalContext` reaches the model | probe |
| PreToolUse | input `tool_name`, `tool_input`, `tool_use_id`, `permission_mode`, `cwd`; `{"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": ...}}` blocks the call **even in bypassPermissions mode**, and the model sees the reason | probe |
| PostToolUse | input has **`tool_response`** (an object for MCP tools), not `tool_output` as the docs agent said; `hookSpecificOutput.additionalContext` reaches the model | probe |
| Subagent tool calls | Pre/PostToolUse fire for tool calls inside subagents and carry **`agent_id` and `agent_type`** (`probe:probe-agent`); main-thread calls carry neither | probe |
| Stop | input `stop_hook_active`, `last_assistant_message`; `{"decision": "block", "reason": ...}` makes the model continue, and the next Stop arrives with `stop_hook_active: true` | probe |
| SubagentStop | input `agent_id`, `agent_type`, `agent_transcript_path`, `last_assistant_message`, `stop_hook_active` | probe |
| Agent `tools:` frontmatter | accepts full MCP tool names (`mcp__plugin_probe_probe__ping`); the subagent could call it. The docs agent's claim that MCP names are not accepted was wrong. Wildcards untested, so bbh lists tools explicitly. | probe |
| Plugin agent names | `<plugin>:<name>`, e.g. `bbh:class-tester` | probe |
| Plugin skill names | `<plugin>:<skill>` (`bbh:recon`); project `.claude/skills/<name>` keeps the bare name, so both can coexist | docs |
| Excluding a server for one run | `--settings '{"deniedMcpServers":[{"serverName":"browser-mcp"}]}'` excluded the user-scope browser-mcp while keeping the plugin server; `--strict-mcp-config` also drops plugin servers | probe |
| PreCompact | matchers `manual`, `auto`; cannot block compaction | docs |
| Hook `timeout` | seconds | docs |

Differences from `build-harness.md`: none of substance. The spec says "SessionStart (startup, resume, and after compaction)": the matcher values are `startup`, `resume`, `compact` (plus `clear`), and bbh registers all four. The spec's `stop_hook_active` guidance is honoured as described in `design.md` Section 12.

## 6. Environment

Windows 11 Pro; Claude Code 2.1.287; Python 3.12.10 as `python` (the `py` launcher points at a Store 3.13 without `mcp`, so hooks and `.mcp.json` call `python`); `mcp` 1.30.0 installed for this build (2.x renamed FastMCP), `httpx` 0.28.1, `h2`, `flask` 3.1.3, `websocket-client` 1.9.0, `cryptography` 46, `truststore` 0.10.4, `pytest` 9.1.1; git 2.49; node 24; Chrome 154 and Edge 155 (usable as a private headless browser with a fresh profile); ngrok present (Store alias, hangs non-interactively, so always wrap it in a timeout); no interactsh client; no `uv`.

Stale statements found elsewhere: `.claude/CLAUDE.md` calls `claude-in-chrome` "Playwright Chrome" (it is the Claude in Chrome extension, which is not installed locally); a memory note's `C:/Tools/burp-mcp/mcp-proxy.jar` path no longer exists (the jar is at `%APPDATA%/BurpSuite/mcp-proxy/mcp-proxy-all.jar`); nothing listens on 9222.

Other extensions share the logged-in testing profiles (not audited in depth): Chrome Profile 4 has MaxAI and TryWebKits Helper Kit; Firefox has a free VPN, FoxyProxy, Wappalyzer, AdBlock, Multi-Account Containers and others. Browser traffic reaches Burp through FoxyProxy (inferred; the system proxy is off).
