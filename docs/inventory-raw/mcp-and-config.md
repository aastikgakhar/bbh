# Raw inventory: MCP servers and Claude Code configuration

Collected 2026-10-12 between 20:55 and 21:10 local time by a read-only subagent working in `C:/Tools/burp-mcp/bbh`. This is input for `docs/inventory.md`, not the final document.

## 0. Method and limits

- No browser tool was invoked. The schemas of `mcp__claude-in-chrome__*`, `mcp__browser-mcp__*`, `mcp__claudecodebrowser__*` and `mcp__claude_ai_*` were loaded with ToolSearch only. What their network tools actually return at runtime is therefore taken from the tool descriptions, the source on disk and the researcher's memory notes, and each such claim says where it came from.
- Burp: exactly one call, `mcp__burp__output_project_options`. Only listener, scope, upstream proxy and TLS settings are recorded (section 4).
- `~/.claude.json` and every settings file were read through a redacting script (`scratchpad/read_cfg.py`). It never printed env values with secret-like names, header values, URL query strings or long opaque strings. Permission rules that embed shell commands were summarised by their first word only.
- Browser profile FILES were read for the extension inventory only: id, name, version, and whether the extension holds `proxy`, `debugger`, `nativeMessaging`, `webRequest` or `<all_urls>`. Nothing attached to, launched or messaged a running browser. Processes and ports were read with Get-Process, Get-NetTCPConnection and Win32_Process, all read-only.
- One side effect: `ngrok version` (the Microsoft Store alias) had not returned after 120 s, so I stopped the background task with TaskStop. Afterwards no `ngrok.exe` process existed, so nothing the researcher had started was touched.

## 1. Summary

| Server | Registered where | Transport | Live at ~21:05 | Captured traffic | Full response bodies | JS in page | Tab identity |
|---|---|---|---|---|---|---|---|
| `burp` | local scope, project `C:/Tools/burp-mcp` | SSE `http://127.0.0.1:9876` (BurpSuite pid 13068) | yes | yes: proxy history, WebSocket history, Organizer | no: every history record is cut at 5000 chars | n/a | none: history offset only, offset 0 = oldest |
| `browser-mcp` (Agent360 Browser MCP 1.30.1, Chrome) | user scope (`~/.claude.json` mcpServers) | stdio `npx @agent360/browser-mcp@latest`; the node bridge listens on `ws://127.0.0.1:<first free port in 9876..9895>` and the Chrome extension connects to it | NO: no node process for it, nothing listening on 9877..9895 | no list tool. `browser_wait_for_network` waits for one matching request (return shape undocumented) | only for requests it issues itself: `browser_fetch` (extension background, no CORS) or `fetch` inside `browser_execute_script` | yes: page world via CDP `Runtime.evaluate` | numeric Chrome `tab_id` from `browser_list_tabs` (own tab group only). Most tools take no tab id and act on the session's active tab |
| `claudecodebrowser` (ClaudeCodeBrowser 1.0.0, Firefox) | local scope, project `C:/Tools/burp-mcp` | stdio `python C:/Tools/ClaudeCodeBrowser/mcp-server/stdio_wrapper.py` to HTTP `127.0.0.1:8765` (header `X-API-Key`) plus WS `127.0.0.1:8766`, then the native host, then the Firefox extension | yes: server.py pid 30084, native host pid 3008, wrapper pid 29668 | yes: `browser_start_logging` then `browser_get_network_logs` (fetch/XHR only) | the description claims "request/response data". Completeness and any size cap are NOT verified | yes, but in the isolated content-script world: page globals are invisible | integer Firefox `tab_id`, optional. The default is the active tab of the researcher's real Firefox, and `browser_get_tabs` lists ALL of its tabs |
| `claude-in-chrome` | built into Claude Code (`claudeInChromeDefaultEnabled=true`) | Claude in Chrome extension, reached through the account bridge | unknown: the extension is not installed in any local Chrome or Edge profile | `read_network_requests` (metadata. Bodies are not promised) | no, per the description | yes: page context, top-level await | numeric `tabId` inside the session's MCP tab group (`tabs_context_mcp`). The browser is chosen by `deviceId` |
| claude.ai Claude Docs | claude.ai connector | remote (claudeai-proxy) | connected | n/a | n/a | n/a | n/a |
| claude.ai Gmail, Google Drive | claude.ai connectors | remote (`gmailmcp.googleapis.com`, `drivemcp.googleapis.com`) | not authenticated: only `authenticate` and `complete_authentication` are exposed | n/a | n/a | n/a | n/a |

No Playwright MCP server is registered anywhere. The project `CLAUDE.md` labels `claude-in-chrome` as "Playwright Chrome". The loaded schemas show tab groups, `deviceId`, `switch_browser` and shortcuts, which are Claude in Chrome extension features, not Playwright. Leftover Playwright MCP profile folders (`%LOCALAPPDATA%\ms-playwright\mcp-chrome-4d54786`, `mcp-chrome-for-testing-138709b`) show that a Playwright MCP was used in the past. Those folders are browser profiles that may hold sessions, and no agent should reuse them. The memory note "Playwright is CDP-attach on 9222" is stale: nothing listens on 9222.

## 2. Registration, processes, ports

### 2.1 `~/.claude.json` (redacted read, 74 top-level keys)

- `mcpServers` (user scope), 1 entry: `browser-mcp` = `{type: stdio, command: npx, args: ["@agent360/browser-mcp@latest"], env: {}}`. Because of `@latest`, npx re-resolves the package on every launch, so the server is unpinned. It currently resolves to the npx cache copy 1.30.1 at `C:/Users/Aastik/AppData/Local/npm-cache/_npx/3a1945bdadeae2b9/node_modules/@agent360/browser-mcp` (repo `github.com/Agent360dk/browser-mcp`, homepage `browsermcp.dev`, deps `@modelcontextprotocol/sdk ^1.30.0`, `ws ^8.21.3`).
- `projects["C:/Tools/burp-mcp"].mcpServers` (local scope):
  - `claudecodebrowser` = `{command: python, args: ["C:/Tools/ClaudeCodeBrowser/mcp-server/stdio_wrapper.py"]}`. It has no `type` (so stdio) and no env.
  - `burp` = `{type: sse, url: http://127.0.0.1:9876}`
  - Other fields of that entry: `allowedTools []`, `enabledMcpjsonServers []`, `disabledMcpjsonServers []`, `disabledMcpServers []`, `mcpContextUris []`, `hasTrustDialogAccepted true`, `hasClaudeMdExternalIncludesApproved false`.
- `projects["C:/Tools/burp-mcp/6sensebbp"]` and `projects["C:/Tools/burp-mcp/deep-audit-gitHub-copilot"]` are separate entries with 0 local servers each.
- Other keys: `claudeAiMcpEverConnected: ["claude.ai Claude Docs"]`, `claudeInChromeDefaultEnabled: true`, `hasCompletedClaudeInChromeOnboarding: true`, `installMethod: native`, `autoUpdates: false`, `officialMarketplaceAutoInstalled: true`, `pluginUsage` keys `agents-md@builtin`, `cc-plugin-diff@builtin`, `cc-plugin-plugin-authoring@builtin`, `telemetry@builtin`.
- No `.mcp.json` exists in `C:/Tools/burp-mcp` or `C:/Tools/burp-mcp/bbh`. No `managed-mcp.json` or `managed-settings.json` exists under `C:/ProgramData/ClaudeCode` or `C:/Program Files/ClaudeCode`.

Implication: `burp` and `claudecodebrowser` load only for sessions whose project is `C:/Tools/burp-mcp`. `C:/Tools/burp-mcp` is not a git repo, and the two engagement subfolders already have their own project entries with no servers. A session started inside an engagement folder would therefore most likely get `browser-mcp` only. Verify with `claude mcp list` from such a folder. The bbh plugin's `.mcp.json` should register bbh alone, must not assume `burp` or `claudecodebrowser` are loaded, and can reach Burp directly from Python over SSE.

### 2.2 Live listeners and processes (read at 21:03 to 21:06)

| Listener | Owner |
|---|---|
| 127.0.0.1:8080 | BurpSuite.exe pid 13068 (proxy listener) |
| 127.0.0.1:9876 | BurpSuite.exe pid 13068 (Burp MCP SSE) |
| 127.0.0.1:8765 | python pid 30084 = `C:\Tools\ClaudeCodeBrowser\mcp-server\server.py` (HTTP API), started 19:36 |
| 127.0.0.1:8766 | python pid 30084 (WebSocket) |
| 9877..9895 | nothing |
| 9222 | nothing |

- python pid 3008 = `C:\Tools\ClaudeCodeBrowser\native-host\claudecodebrowser_host.py` (Firefox native messaging host), started 19:36.
- python pid 29668 = `stdio_wrapper.py` (this session's claudecodebrowser client), started 20:43.
- No `node.exe` has `browser-mcp` or `agent360` on its command line. The browser-mcp server is not running, even though its tool names are listed as deferred tools in this session. It was not invoked to confirm. Re-probe before relying on it.
- Running browsers: chrome.exe pid 14236, msedge.exe pid 28048, firefox.exe pid 6328. None has `--remote-debugging-port`, `--proxy-server`, `--user-data-dir`, `--headless` or `--load-extension` on its browser-process command line.
- Burp: `BurpSuite.exe` from `C:\Users\Aastik\AppData\Local\Programs\BurpSuite` (unified installer). Older `BurpSuiteCommunity` and `BurpSuitePro` install folders also exist. In `%APPDATA%\BurpSuite`, `UserConfig.json` and `WorkspaceConfig.json` were modified 2026-10-12 18:24, `UserConfigPro.json` on 2026-02-20 and `UserConfigCommunity.json` on 2026-05-09. The edition was not determined.

### 2.3 Port 9876 collision and an unauthenticated bridge

- Agent360 `index.js` lines 45-46: `BASE_PORT = Number(process.env.BROWSER_MCP_BASE_PORT) || 9876`, `MAX_PORT = Number(process.env.BROWSER_MCP_MAX_PORT) || 9895`. The server listens on `ws://127.0.0.1:${port}` (line 447). Burp MCP SSE is also on 127.0.0.1:9876, so whichever process starts first owns 9876. If browser-mcp starts while Burp is closed, Burp's MCP server cannot bind 9876 afterwards. That is one plausible cause of the memory note "Burp MCP may not load into a session at all" (not verified).
- Agent360 `index.js` around lines 133-145: `BROWSER_MCP_TOKEN` is ignored as of 1.30.1. The server's own stderr message says pairing was withdrawn because it did not keep other local programs out, and that the bridge is local and unauthenticated. The Chrome extension connects to whatever answers on 9876..9895. Any local process listening in that range is therefore offered a logged-in Chrome profile with `debugger` and `<all_urls>`. Flag this for the extension audit.
- Options, for the researcher to decide (nothing was changed): set `BROWSER_MCP_BASE_PORT=9900` and `BROWSER_MCP_MAX_PORT=9919` in the env of the user-scope `browser-mcp` entry, or move the Burp MCP listener. bbh's own SSE client should check `serverInfo.name == "burp-suite"` after `initialize` rather than trusting the port number.

## 3. Tool tables (`*` = required)

### 3.1 `burp`: 24 tools. Schemas loaded; only `output_project_options` was invoked.

| Tool | Arguments | Notes |
|---|---|---|
| send_http1_request | content*: str (raw request, CRLF), targetHostname*: str, targetPort*: int, usesHttps*: bool | returns Burp's `HttpRequestResponse{httpRequest=..., httpResponse=..., messageAnnotations=...}` toString (memory) |
| send_http2_request | headers*: map str->str, pseudoHeaders*: map str->str, requestBody*: str, targetHostname*, targetPort*, usesHttps* | headers must not go in the body |
| create_repeater_tab | content*, tabName, targetHostname*, targetPort*, usesHttps* | HTTP/1.1 tab |
| create_repeater_tab_http2 | headers*, pseudoHeaders*, requestBody*, tabName, targetHostname*, targetPort*, usesHttps* | |
| send_to_intruder | content*, tabName, targetHostname*, targetPort*, usesHttps* | |
| get_proxy_http_history | count*: int, offset*: int | |
| get_proxy_http_history_regex | count*, offset*, regex*: str | |
| get_proxy_websocket_history | count*, offset* | |
| get_proxy_websocket_history_regex | count*, offset*, regex* | |
| get_organizer_items | count*, offset* | |
| get_organizer_items_regex | count*, offset*, regex* | |
| output_project_options | none | called once, see section 4 |
| output_user_options | none | not called |
| set_project_options | json*: str (merged into existing config) | the description says to use a top-level `user_options` object, but the memory recipe that worked used top-level `project_options`. The two set_* descriptions look swapped |
| set_user_options | json*: str | the description says top-level `project_options` |
| set_proxy_intercept_state | intercepting*: bool | |
| set_task_execution_engine_state | running*: bool | |
| get_active_editor_contents | none | |
| set_active_editor_contents | text*: str | |
| url_encode, url_decode, base64_encode, base64_decode | content*: str | |
| generate_random_string | characterSet*: str, length*: int | |

The tool list has no scanner-issue tool and no Collaborator tool. From recollection, not verified here: PortSwigger's server registers the scanner-issue tool only on Professional, which would fit Community mode. Either way, Collaborator is not reachable through MCP, so OOB must come from interactsh or the researcher's own listener.

Measured earlier (parent brief, not re-measured): `get_proxy_http_history` returns one text block of `{"request","response","notes"}` records separated by blank lines. Each record is cut at 5000 chars total with the suffix `... (truncated)`, which breaks that record's JSON. Offsets are the only identifier, and `Reached end of items` is returned past the end. The bbh Python process can reach the server directly with `mcp.client.sse.sse_client` (init about 1.2 s, a call about 0.08 s).

From the researcher's memory notes (`tooling_gotchas.md`), relevant to ingest and the sender:
- Offset 0 is the OLDEST record and the newest has the highest offset. Cost grows with offset: offset 5000 took about 73 s and offset 11000 about 107 s. A page is also cut by total size (about 300 KB), so advance the offset by the records actually decoded, never by the count requested.
- Regex search matches decoded (decompressed) bodies and returns results oldest-first. A date-scoped regex (`Date: <Day>, <DD> <Mon> <YYYY> <HH>:`) is the fast way to read recent traffic. A zero-match regex is a sound negative. A truncated result is not.
- The history "JSON" is not valid JSON (unescaped quotes, raw control characters), and CRLF is stored as the literal 4 characters `\r\n`. Parse on the literal markers `{"request":"`, `","response":"`, `","notes":"`.
- `curl --proxy http://127.0.0.1:8080` gives full untruncated bodies and still lands in Burp history. That is the right primitive for the bbh sender.
- Burp's HTTP/2 upstream fingerprint has triggered Cloudflare blocks, which `project_options.http.http2.enable_http2=false` fixed. Burp also broke an SSE streaming endpoint: proxied it returned 200 with no body, while direct worked. Keep a direct-vs-proxied switch.
- Stdio fallback when the SSE server does not load into a session: `java -jar <jar> --sse-url http://127.0.0.1:9876`, then JSON-RPC `initialize`, `notifications/initialized`, `tools/call`. The jar is no longer at `C:\Tools\burp-mcp\mcp-proxy.jar` (the memory path is stale). Copies exist at `C:\Users\Aastik\AppData\Roaming\BurpSuite\mcp-proxy\mcp-proxy-all.jar` and `C:\Tools\codex\mcp-proxy.jar`, both dated 2026-02-26. Java 21 is installed.

### 3.2 `browser-mcp` (Agent360 Browser MCP 1.30.1, Chrome): 40 tools

| Tool | Arguments | Notes |
|---|---|---|
| browser_navigate | url*, new_tab, eget_vindue, fokuser, vindue_x, vindue_y, vindue_bredde, vindue_hoejde | reuses the session's current tab by default. The Danish-named params open a separate window |
| browser_list_tabs | none | the server instructions say it lists only this session's tabs |
| browser_switch_tab | tab_id*: number | |
| browser_close_tab | tab_id*: number | only tabs owned by the session |
| browser_get_new_tab | none | the most recently opened tab (popups, OAuth) |
| browser_click | selector*: CSS or `text=` / `tag:text()` | trusted CDP mouse events |
| browser_click_xy | x*, y*: number (viewport CSS px) | |
| browser_double_click | selector* | |
| browser_right_click | selector* | |
| browser_hover | selector*, duration | |
| browser_fill | selector*, value* | via the debugger API |
| browser_press_key | key*, code, ctrl, alt, shift, meta | |
| browser_select_option | selector*, option*, wait | |
| browser_set_combobox | selector*, value, values[], multi, query_chars, wait_ms | |
| browser_set_date | selector*, date* (YYYY-MM-DD), skip_picker | |
| browser_scroll | selector, x, y | |
| browser_wait | selector*, timeout | |
| browser_wait_for_network | url_pattern, timeout | waits for one request to complete (CDP). The return shape is undocumented, and the description does not promise bodies |
| browser_execute_script | code*: a JS expression (use an IIFE) | page world via CDP `Runtime.evaluate`. Memory: the result reports `"method": "debugger"` |
| browser_list_frames | none | |
| browser_select_frame | frame_index*, code | runs JS in an iframe |
| browser_get_page_content | format (text or html), max_chars (default 30000), selector | flags truncation with `total_chars` |
| browser_extract_list | selector*, container, max_rows (500, max 5000), scroll_step, stable_rounds, wait_ms | |
| browser_screenshot | path | the session's own tab, taken via the debugger without activating it |
| browser_console_logs | count | installs an interceptor on first call |
| browser_get_cookies | domain* | only for domains open in one of the session's tabs |
| browser_set_cookies | name*, value*, domain, url, path, secure, httpOnly, sameSite, cookies[] | |
| browser_get_local_storage | key | |
| browser_set_local_storage | key*, value* | |
| browser_fetch | url*, method, headers{}, body | issued from the extension background, not subject to CORS |
| browser_upload_file | files*[], file, selector | files must be inside the server's working directory |
| browser_drop_file | selector*, file, files[] | same restriction |
| browser_handle_dialog | action, text, timeout, wait | arm it before the click |
| browser_dismiss_overlays | max_passes, scope (non_critical or aggressive) | |
| browser_reattach_debugger | none | recovery |
| browser_ask_user | message*, fields[{name*, label*, type}], title, timeout | draws an overlay in the researcher's page |
| browser_solve_captcha | action (detect, click_checkbox, click_grid, ask_human), cells[] | solving a CAPTCHA is prohibited in this environment. The harness must never call it |
| browser_extract_token | provider* | navigates to a provider's API-settings page |
| browser_about | intent, title, body | returns GitHub and browsermcp.dev links |
| browser_provide_feedback | what_happened*, kind, tool, url, attempted | local self-diagnosis. `~/.browser-mcp/feedback.jsonl` exists (656 bytes, not read) |

- Installed extension: Chrome **Profile 4**, id `jdehgalffmffhfhmmhaokfbfnafnmgcl`, v1.30.1. Permissions in the manifest bundled with the npm package: `tabs, tabGroups, cookies, scripting, activeTab, storage, alarms, offscreen, notifications, webNavigation, debugger`, host `<all_urls>`.
- Profile 4 also holds FoxyProxy 9.7, plus the VeePN and Private Internet Access proxy extensions. FoxyProxy is the likely route from this Chrome to Burp, but its settings were not read.
- Server env knobs: `BROWSER_MCP_BASE_PORT`, `BROWSER_MCP_MAX_PORT`, `BROWSER_MCP_EXTENSION_ID` (pin one extension), `BROWSER_MCP_TOKEN` (ignored since 1.30.1), `BROWSER_MCP_CHECK_NPM` (unset; when set it compares against the npm registry), `BROWSER_MCP_EXTENSION_UPDATED`.
- Non-local URL strings referenced in the server code: github.com, browsermcp.dev, chromewebstore.google.com, plus provider dashboards used by `browser_extract_token` (stripe, slack, hubspot, shopify, google cloud console, mailchimp, pipedrive, calendly, linkedin). Whether any of these are contacted without a tool call was not audited here.

### 3.3 `claudecodebrowser` (ClaudeCodeBrowser 1.0.0, Firefox): 39 tools

| Tool | Arguments | Notes |
|---|---|---|
| browser_get_tabs | none | ALL open Firefox tabs, with URL, title, active, loading, window and audio state |
| browser_find_tabs | url, url_pattern, title, active, audible | |
| browser_get_tab_info | tab_id* | |
| browser_create_tab | url (about:blank), active (true) | |
| browser_focus_tab | tab_id* | changes the researcher's visible tab |
| browser_close_tab | tab_id* | any tab. No ownership check is described |
| browser_navigate | url*, new_tab, tab_id | "Creates new tab if not specified" |
| browser_refresh | tab_id, bypass_cache, wait_for_load | |
| browser_hard_refresh | tab_id | |
| browser_reload_all | url_pattern, bypass_cache (true) | reloads every matching tab in the real Firefox |
| browser_reload_by_url | url, url_pattern, bypass_cache | |
| browser_click | selector, xpath, text, x, y, double_click, right_click, tab_id | memory: unreliable on Polymer pages, use `element.click()` from a script |
| browser_click_and_wait | selector, xpath, text, wait_for_change, wait_for_selector, wait_timeout (5000), tab_id | |
| browser_hover | selector*, tab_id | |
| browser_type | text*, selector, id, name, placeholder, clear, delay, press_enter, tab_id | |
| browser_set_value | selector*, value*, tab_id | |
| browser_get_value | selector*, tab_id | |
| browser_select_option | selector*, index, text, value, tab_id | |
| browser_scroll | direction, amount, selector, to_element, tab_id | |
| browser_scroll_and_capture | delay, max_scrolls, restore, scroll_step, tab_id | |
| browser_get_elements | selector*, limit (50), tab_id | |
| browser_get_page_info | tab_id | URL, title, interactive elements, forms, headings |
| browser_highlight | selector*, duration, label, tab_id | |
| browser_screenshot | filename, full_page, save_to_file (true), tab_id | |
| browser_screenshot_all_tabs | include_data, url_pattern | cycles focus through every tab, then restores it |
| browser_execute_script | script*, tab_id | isolated content-script world (memory). Wrap in an IIFE. Promises are awaited |
| browser_eval_chain | steps*[{script*, label, capture_console, stop_on_error}], tab_id | `$prev` carries the previous result |
| browser_wait_and_act | condition*, action_script*, poll_interval_ms, timeout_ms, tab_id | |
| browser_wait_for_element | selector*, timeout, visible, tab_id | |
| browser_wait_for_change | selector, change_type, subtree, timeout, tab_id | |
| browser_wait_for_network_idle | idle_time, timeout, tab_id | |
| browser_inject_observer | selector, observe_attributes, observe_child_list, observe_subtree, tab_id | |
| browser_observe_element | selector*, observer_id, tab_id | |
| browser_stop_observing | observer_id*, tab_id | |
| browser_start_logging | clear_existing, tab_id | starts console and network capture |
| browser_stop_logging | tab_id | |
| browser_get_network_logs | errors_only, limit (100), method, status, tab_id, url_pattern (regex) | "captured network requests and responses (fetch/XHR)". Documents, scripts and images are not covered. Body completeness is unverified |
| browser_get_console_logs | level, limit (100), search, tab_id | |
| browser_clear_logs | console, network, tab_id | |

- JS world (memory `browser_mcp_js_worlds.md`): DOM, `document.cookie`, `fetch` and `crypto.subtle` work, but page globals are invisible. `window.fetch` and XHR hooks installed from this world capture nothing. To reach the page world, inject a `<script>` whose src is a `blob:` URL and pass results back through a DOM attribute. Firefox host permission is per tab and is lost on navigation.
- Transport: `stdio_wrapper.py` starts `server.py` if `GET http://127.0.0.1:8765/health` fails, then forwards tool calls. HTTP routes: `GET /health`, `/mcp/tools`, `/screenshots`, `/browser/poll`; `POST /mcp/call`, `/browser/command`, `/browser/response`. The auth header is `X-API-Key`, read from `C:/Users/Aastik/.claudecodebrowser/api_token` (the file exists and was not read). There is also a WebSocket on 8766. The extension talks through the native host `claudecodebrowser_host.py` (nativeMessaging). Env overrides: `CLAUDE_BROWSER_HOST`, `CLAUDE_BROWSER_HTTP_PORT`, `CLAUDE_BROWSER_WS_PORT`, `CLAUDE_BROWSER_SCREENSHOTS_DIR` (default `/tmp/claudecodebrowser/screenshots`), and `CLAUDE_BROWSER_HEADLESS=1` (a headless Playwright backend, which needs the Python `playwright` package, and that is NOT installed).
- Design option: bbh's Python could `POST http://127.0.0.1:8765/mcp/call` with `X-API-Key`, exactly as `stdio_wrapper.py` does, and pull Firefox network logs without the model in the loop. It would still act on the real Firefox, so at most read-only calls would be appropriate. `start_logging` injects into pages, so the researcher should decide.
- Source: `C:/Tools/ClaudeCodeBrowser` (git `d5f6bbe`, 2026-05-11, "feat: headless Playwright mode + multi-turn eval chain + console observer", origin `github.com/nanogenomic/ClaudeCodeBrowser`), extension manifest 1.0.0. `mcp-server/mcp_config.json` is an unused Linux sample (`/home/dre/...`).
- Installed in Firefox profile `ynj26p0v.default-release` as `claudecodebrowser@ligandal.com` v1.0.0: active, permissions `nativeMessaging, tabs, <all_urls>`. FoxyProxy 9.8 is active in the same profile (it has the proxy permission) and is the likely route to Burp, but its settings were not read. Multi-Account Containers and VeePN also hold the proxy permission.

### 3.4 `claude-in-chrome`: 22 tools

| Tool | Arguments | Notes |
|---|---|---|
| tabs_context_mcp | createIfEmpty | tab ids in this session's MCP tab group. Can create a window and a group |
| tabs_create_mcp | none | new tab in the group |
| tabs_close_mcp | tabId*: integer | group tabs only |
| navigate | url* (or "back"/"forward"), tabId | a standalone call without tabId auto-creates a tab via tabs_context_mcp |
| computer | action* (left_click, right_click, double_click, triple_click, type, key, screenshot, wait, scroll, scroll_to, left_click_drag, zoom, hover), tabId*, coordinate, start_coordinate, text, duration, scroll_direction, scroll_amount, region, ref, modifiers, repeat, scale, save_to_disk, action_summary | |
| browser_batch | actions*[{name*, input*}] | sequential, stops at the first error |
| find | query*, tabId* | natural-language element search that returns refs |
| read_page | tabId*, filter (interactive or all), depth, ref_id, max_chars (50000) | accessibility tree |
| get_page_text | tabId* | |
| form_input | ref*, value*, tabId*, action_summary | |
| file_upload | paths*[], ref*, tabId* | only files shared with the session |
| upload_image | imageId*, tabId*, ref, coordinate, filename | |
| javascript_tool | action* = "javascript_exec", text*, tabId* | page context, REPL semantics, top-level await |
| read_network_requests | tabId*, urlPattern, limit (100), clear | requests made by the current page, cleared on cross-domain navigation. No headers or bodies are promised |
| read_console_messages | tabId*, pattern, onlyErrors, limit, clear | |
| resize_window | width*, height*, tabId* | |
| gif_creator | action*, tabId*, download, filename, options | |
| shortcuts_list | tabId* | |
| shortcuts_execute | tabId*, shortcutId, command | runs in a side panel |
| list_connected_browsers | none | deviceId, name, isLocal, onThisComputer, inUse |
| select_browser | deviceId* | |
| switch_browser | none | broadcasts a connect request to every extension |

- The Claude in Chrome extension (Web Store id `fcoeoabgfenejglbffodgkkbkcdhcgfn`) has no extension files in any local Chrome profile (Default, Profile 1, 4, 5, 6, 7, 8) or in Edge. The id survives only as references in 5 Chrome prefs files. Unless a browser is connected from somewhere else through the account, this server has nothing local to drive. Not invoked, so this is unconfirmed.
- This server acts in a real Chrome with the person's sign-ins, so the CLAUDE.md agent browser rule applies to it in full.

### 3.5 claude.ai connectors (remote: data leaves the machine)

| Server | Tool | Arguments |
|---|---|---|
| Claude Docs (connected) | batch | container{kind*, id, create}, batch[], opId, verbose |
| | create | object* (file, node, utterance, enum, blob), payload*, container{kind*, id*, version}, artifact, engine, opId, verbose |
| | read | ref*{object*, id*}, container, payload, engine |
| | update | ref*, payload*, container, answering, engine, opId, verbose |
| | delete | ref*, container, payload, engine, opId, verbose |
| | export | container*, file*, format* (markdown, text, html, docx, pdf, notion), maxBytes, paper |
| | query | container, object (utterance), payload |
| | guide | items[] |
| Gmail (not authenticated) | authenticate | none |
| | complete_authentication | callback_url* |
| Google Drive (not authenticated) | authenticate | none |
| | complete_authentication | callback_url* |

None of these is a traffic source. Because they are remote, bbh agents must never route captures, session material or target data into them (Rule 0). The PreToolUse hook can deny them for class-tester and verifier agents.

## 4. Burp project options extract (`output_project_options`, called once)

- **Proxy listeners:** exactly one: `listener_port 8080`, `listen_mode loopback_only` (127.0.0.1), `running true`, `certificate_mode per_host`, `enable_http2 true`, `use_custom_tls_protocols false`, `custom_tls_protocols []`.
- **Target scope:** `target.scope = {advanced_mode: false, include: [], exclude: []}`, which is EMPTY. `connections.out_of_scope_requests = {advanced_mode: false, drop_all_out_of_scope: false, include: [], exclude: [], scope_option: "suite"}`, so nothing is dropped. Burp's "in scope" filters match nothing. bbh must enforce scope itself. It could also push the engagement scope into Burp with `set_project_options`, but that is a config write the researcher should approve.
- **Upstream proxy:** `connections.upstream_proxy = {servers: [], use_user_options: true}`. This defers to user options, which were not read.
- **SOCKS:** `use_proxy false`, `use_user_options true`, `dns_over_socks false`, `host ""`, `port 0`. Credential fields were not recorded.
- **Platform authentication:** `credentials []`, `do_platform_authentication true`, `use_user_options true`.
- **TLS:** `ssl.client_certificates = {certificates: [], use_user_options: true}`. `ssl.negotiation = {tls_negotiation_behavior: "use_all_supported", enabled_protocols: [], enabled_ciphers: [], allow_unsafe_renegotiation: false, disable_ssl_session_resume: false, enforce_upstream_trust: false}`. `proxy.ssl_pass_through = {rules: [], apply_to_out_of_scope_items: true, automatically_add_entries_on_client_ssl_negotiation_failure: false}`.
- **HTTP/2 and ALPN:** `project_options.http.http2.enable_http2 true`, `http1.enable_keep_alive false`, `repeater.allow_http2_alpn_override false`, `repeater.enable_http2_connection_reuse true`.
- **CA trust (local check, not from Burp):** the PortSwigger CA is in the Windows `CurrentUser\Root` store and expires 2036-07-10. Schannel clients (Git's curl 8.12.1, Chrome, Edge) trust Burp-intercepted TLS. Python certifi (2026.6.17) does NOT contain it. `truststore` 0.10.4 is installed, so the sender can use `truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)` with httpx to trust the Windows store, which avoids `verify=False`.
- Deliberately not recorded: logger, match/replace, intercept rules, session handling, macros, cookie jar, Collaborator config.

## 5. Claude Code configuration and how it interacts with a new plugin

- `C:/Users/Aastik/.claude/settings.json`: `permissions.defaultMode "auto"`, `skipDangerousModePermissionPrompt true`, `model "opus"`, `effortLevel "high"`, `modelSettings {claude-sonnet-5-5: {effortLevel: xhigh}}`, `autoCompactEnabled true`, `tui "fullscreen"`, `askUserQuestionTimeout "60s"`, `autoUpdatesChannel "stable"`, `agentPushNotifEnabled true`, `switchModelsOnFlag true`, `theme "dark"`. No `hooks`, `env`, `enabledPlugins`, `extraKnownMarketplaces`, `statusLine`, `disableAllHooks` or `allowManagedHooksOnly`.
- `C:/Users/Aastik/.claude/settings.local.json`: 2 allow rules, `mcp__claudecodebrowser__browser_get_tabs` and one `PowerShell(Get-Process ...)`.
- `C:/Tools/burp-mcp/.claude/settings.local.json`: 1 allow rule, `mcp__claudecodebrowser__browser_get_tabs`. There is no project `settings.json`.
- `C:/Tools/burp-mcp/bbh/.claude/`: absent. There are no managed settings.
- This session runs with bypass-permissions mode active (stated in the session's system context), and the user default is `auto`. Permission rules therefore gate nothing, and the plugin's PreToolUse hooks are the only enforcement layer. Re-check against the current Claude Code docs that hook deny decisions apply under bypassPermissions before relying on it.
- **Hooks in effect today:** none from any settings file. No plugin is installed or enabled: there is no `installed_plugins.json`, `plugins/cache` is empty, and no settings file has `enabledPlugins`. `plugins/store` holds only `cc-plugin-diff_builtin-*.json`. Built-in plugins seen in `pluginUsage` are `agents-md`, `cc-plugin-diff`, `cc-plugin-plugin-authoring` and `telemetry` (all `@builtin`). Whether any built-in registers hooks is unknown.
- **Known marketplace:** `claude-plugins-official` (github `anthropics/claude-plugins-official`). Its catalogue checkout contains hook-bearing plugins, none installed: `hookify` (PreToolUse, PostToolUse, Stop and UserPromptSubmit on `*`), `ralph-loop` (Stop), `security-guidance` (SessionStart, UserPromptSubmit, PostToolUse, Stop), `code-modernization` (UserPromptSubmit, Stop, SessionStart, PostToolUseFailure, StopFailure), `claude-security` (UserPromptExpansion, PostToolUse on Bash, PostToolUseFailure, PermissionRequest), and `explanatory-output-style` / `learning-output-style` (SessionStart). If the researcher ever enables `ralph-loop` or `hookify`, their Stop hooks would compete with the bbh stop gate. Document this in `docs/usage.md`.
- `plugins/blocklist.json` has 2 test entries (`code-review@claude-plugins-official`, `fizz@testmkt-marketplace`). Neither collides with `bbh`.
- Skills: the project skills `coverage-matrix`, `recon`, `report-writer` and `triage-gate` are in `C:/Tools/burp-mcp/.claude/skills`. Plugin skills are namespaced (`bbh:<name>`), so shipping updated copies in the plugin leaves two same-named skills unless the project copies are retired. That is a design decision. `~/.claude/skills` holds only `synced`. There are no `~/.claude/hooks`, `agents` or `commands` folders.
- Claude Code CLI 2.1.287, native install, auto-updates off.

## 6. Environment and versions

- **Python:** `python` = 3.12.10 at `C:\Users\Aastik\AppData\Local\Programs\Python\Python312\python.exe`, first on PATH in both PowerShell and Git Bash. The `py` launcher defaults to 3.13 (Microsoft Store build), which does NOT have `mcp`. Hooks and `.mcp.json` should call `python` or the absolute 3.12 path, never `py`. WindowsApps `python`/`python3` aliases sit later on PATH.
- **Packages (3.12):** mcp 1.30.0 (FastMCP is available as `mcp.server.fastmcp`; the standalone `fastmcp` package is MISSING), httpx 0.28.1, h2 4.4.0 (httpx HTTP/2 works), httpx-sse 0.4.3, sse-starlette 3.5.0, starlette 1.7.0, uvicorn 0.54.0, anyio 4.14.0, pydantic 2.13.4, pytest 9.1.1 (pytest-asyncio MISSING), flask 3.1.3, werkzeug 3.1.6, jinja2 3.1.6, fastapi MISSING, websocket-client 1.9.0, websockets 13.1, cryptography 46.0.7, requests 2.34.2, truststore 0.10.4, certifi 2026.6.17, playwright MISSING, socksio MISSING, pip 26.0.1.
- **Toolchain:** git 2.49.0.windows.1. node v24.11.1 (`C:\Program Files\nodejs`), npm 11.10.0. java "21" 2023-09-19 LTS. go 1.25.6. curl 8.12.1 (`C:\Program Files\Git\mingw64\bin\curl.exe`, Schannel). uv not installed.
- **Browsers (versions read from file metadata, no browser launched):**
  - Chrome 154.0.8037.99 at `C:\Program Files\Google\Chrome\Application\chrome.exe`, with profiles Default, Profile 1, 4, 5, 6, 7, 8. Agent360 is in Profile 4.
  - Edge 155.0.4283.45 at `C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`.
  - Firefox 157.0.1 at `C:\Program Files\Mozilla Firefox\firefox.exe`, profile `ynj26p0v.default-release`.
- **Private headless browser for agents:** Playwright Chromium 149.0.7827.3 at `C:\Users\Aastik\AppData\Local\ms-playwright\chromium-1224\chrome-win64\chrome.exe`, and a headless shell at `...\chromium_headless_shell-1224\chrome-headless-shell-win64\chrome-headless-shell.exe` (no version resource). These are separate from the real Chrome. Launch with a fresh `--user-data-dir` in temp and an unused `--remote-debugging-port`, and drive over raw CDP (Node 24 has a global WebSocket; Python has `websocket-client`).
- **How browsers reach Burp:** the Windows system proxy is off (`ProxyEnable=0`, no PAC). Firefox `prefs.js` has no `network.proxy.*` entries. No browser process carries `--proxy-server`. Routing must therefore come from extensions: FoxyProxy is in Chrome Profile 1, Chrome Profile 4 and Firefox. This is inferred, and the researcher should confirm. The `User-Agent` tail (`Chrome/154` vs `Firefox/157`) remains the way to tell the two apart in history.
- **ngrok:** Microsoft Store package `ngrok.ngrok` 3.39.9.0, reached through the alias `C:\Users\Aastik\AppData\Local\Microsoft\WindowsApps\ngrok.exe`. A config file exists at `%LOCALAPPDATA%\ngrok\ngrok.yml` (not read). `ngrok version` from a non-interactive shell did not return within 120 s, so the harness must never shell out to ngrok without a hard timeout.
- **interactsh-client:** absent. It is not on PATH and not in `~/go/bin`, scoop, chocolatey, WinGet links, `C:\Tools` or Downloads. With Go 1.25.6 installed, `go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest` would work, but that is a download, so it needs the researcher's OK. Burp Collaborator is not exposed via MCP. Until one of these exists, SSRF cells are `blocked: no_oob_listener` by the brief's own rule.
- **Process env:** `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, `REQUESTS_CA_BUNDLE`, `SSL_CERT_FILE`, `CURL_CA_BUNDLE`, `NODE_EXTRA_CA_CERTS`, `NODE_TLS_REJECT_UNAUTHORIZED` and `BROWSER_MCP_CHECK_NPM` are all unset. httpx's `trust_env` will not inject a proxy, so the sender must set `proxy="http://127.0.0.1:8080"` explicitly.

## 7. Open points for the design step

1. Which edition the running Burp is (this decides Collaborator) is unknown. bbh should not depend on Collaborator.
2. What `browser_get_network_logs` (Firefox) and `browser_wait_for_network` (Chrome) actually return: body completeness, size caps and headers. Measure against the local lab only, never against a target.
3. browser-mcp was down at check time and claude-in-chrome has no local extension. Per CLAUDE.md, assume they come back and re-probe when needed.
4. The port 9876 overlap between Burp MCP and Agent360. Recommend the env change in `docs/usage.md`, and do not apply it without the researcher.
5. burp and claudecodebrowser are local-scope to `C:/Tools/burp-mcp`. Decide whether `docs/usage.md` tells the researcher to move them to user scope, or whether bbh's Python reaches Burp directly regardless.
6. The `set_project_options` and `set_user_options` descriptions look swapped. Verify the top-level key on the lab Burp project before any bbh code writes Burp config.
