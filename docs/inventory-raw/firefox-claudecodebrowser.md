# Firefox ClaudeCodeBrowser: raw inventory (extension, MCP server, native host)

Audit date: 2026-10-12. Read-only source audit. No browser tool was invoked (tool schemas were only loaded with ToolSearch). No live website was touched. The only live interactions were loopback HTTP probes of the local MCP server (`GET /health`, plus three requests that were expected to be refused: `GET /mcp/tools` without a token, an `OPTIONS` preflight, and `/health` with a foreign Origin and Host). No WebSocket connection was opened to 8766, because that would register a fake "browser" in the live server. The Firefox profile was only read, never modified: the XPI was copied and extracted to the scratchpad, and `extensions.json`, `prefs.js` and `application.ini` were read.

Path prefixes used below:

- `xpi:` the installed extension, extracted copy at `C:/Users/Aastik/AppData/Local/Temp/claude/C--Tools-burp-mcp/c28dd141-9d65-442b-990f-d465b45e9d7e/scratchpad/ff-xpi/`
- `repo:` `C:/Tools/ClaudeCodeBrowser` (git HEAD `d5f6bbe`, the code the MCP server and native host actually run). Files are CRLF on disk; line numbers are unchanged.
- `ws:` workspace copy `C:/Tools/burp-mcp/ClaudeCodeBrowser-main/ClaudeCodeBrowser-main/` (v1.4.0, newer, NOT installed)

---

## 0. Key facts

1. **The installed extension is OLDER than the MCP server it talks to.** The XPI is AMO-signed v1.0.0. Its `background.js` matches git blob `1370f4e` (commits `c3cfd10`/`c246197`, 2025-12-08/22) and its `content.js` matches blob `d43965e` (same era). The MCP server and native host run repo HEAD `d5f6bbe` (2026-05-11). Version strings cannot tell these apart, because the HEAD manifest also says "1.0.0"; use the file hashes.
2. **19 of the 39 MCP tools return `{"success": false, "error": "Unknown action: <x>"}`** with this pairing, because the installed `background.js` has no `case` for them. That includes every network and console logging tool. This was confirmed empirically in `~/.claudecodebrowser/logs/native_host.log*`, which shows `Unknown action: getNetworkLogs` x6, `getConsoleLogs` x4 and `clickAndWait` x4.
3. **There is no network capture and no response-body capture of any kind.** No version of the manifest declares `webRequest`, nothing uses `filterResponseData`, and nothing uses devtools. Even the newer builds' "network logs" wrap `fetch`/XHR inside the Firefox content-script sandbox, which does not see page-initiated requests. Burp is the only source of Firefox request and response bodies.
4. **JS execution happens in the isolated content-script world.** `tabs.executeScript({code})` runs in the top frame only and returns the value of the last expression (structured clone; a returned Promise is awaited). Page globals are reachable only through `window.wrappedJSObject`. A plain `fetch()` there is extension-privileged: CORS is bypassed and Origin/Referer are not set as they would be for a page request. It is never valid CORS or CSRF evidence; use `content.fetch()`.
5. **Tabs are raw Firefox integer IDs with no ownership.** An omitted `tab_id` means the active tab of the last-focused window, i.e. the researcher's own tab. `browser_navigate` without `tab_id` replaces that tab (the `new_tab` argument is ignored, despite the schema text). `browser_close_tab` closes ANY tab. `browser_reload_all` and `browser_screenshot_all_tabs` act on EVERY tab, because their filters are silently ignored.
6. **snake_case vs camelCase bug.** HEAD sends MCP arguments unchanged (`repo:mcp-server/server.py:955`), but the installed extension reads camelCase. So every multi-word option is ignored: `press_enter`, `double_click`, `right_click` (both become a plain LEFT click), `full_page`, `url_pattern`, `include_data`, `bypass_cache`, `wait_for_load`, `to_element`, `new_tab`.
7. **Egress is loopback only from all runtime code.** The only off-host traffic is Firefox's own AMO update check for this add-on: it was installed from AMO, and auto-update is on. The workspace v1.4.0 adds an `update_url` pointing at GitHub releases.
8. **There are two local listeners.**
   - `127.0.0.1:8765` (HTTP) requires a 64-hex `X-API-Key` on everything except `/health`. It sends no CORS headers, answers OPTIONS with 403, and does not check the Host header.
   - `127.0.0.1:8766` (WebSocket) has NO auth and NO Origin check in the installed HEAD. Any local client can connect and register as "the browser", and so can any web page if the browser allows public-to-loopback WebSocket connections (not verified live).
   - Commands are never routed to a WebSocket client, because of an asyncio bug (verified). However, a client can resolve any in-flight HTTP-polling request whose `requestId` it guesses. That would forge tool results. Practical likelihood on this machine is low; this was not demonstrated.
9. **The installed `background.js` forwards `runtime.onMessageExternal` from ANY co-installed extension straight to `handleCommand`.** That gives such an extension `executeScript` on any tab, screenshots, the full tab list, and close/navigate. Nine other extensions are active, two of them with no host permissions of their own. This is fixed in the workspace.
10. **Secrets are stored at rest in clear.**
    - `native_host.log` (DEBUG level) holds typed text, scripts, script results and base64 screenshots.
    - `mcp_server.log` is 404,938,800 bytes and has no rotation.
    - 215 screenshots of logged-in pages sit in `C:\tmp\claudecodebrowser\screenshots`, readable by every local user.

---

## 1. What actually runs (evidence)

| Item | Evidence |
|---|---|
| Firefox | `C:\Program Files\Mozilla Firefox\application.ini`: Version=157.0.1, BuildID=20261005135250. Profile `ynj26p0v.default-release`. |
| Extension file | `...\extensions\claudecodebrowser@ligandal.com.xpi`, 31,361 bytes, sha256 `89cab784bd9f556939f5f7cfb81258cf4314a2d70c7b5f2cf9a50b0f7b5e701c`. AMO-signed: `META-INF/cose.sig`, `mozilla.rsa`, `manifest.mf`. |
| Install metadata (`extensions.json`) | version 1.0.0, active, location app-profile. `sourceURI` = `https://addons.mozilla.org/firefox/downloads/file/4641779/claudecodebrowser-1.0.0.xpi`. `installTelemetryInfo` = `{source: amo, method: amWebAPI}`. `updateURL` null, so Firefox uses the AMO update service. `applyBackgroundUpdates` 1 (default, so auto-update is on). `signedState` 2. `userPermissions.permissions` = `[nativeMessaging, activeTab, contextMenus, storage, tabs, webNavigation]`, `origins` = `[<all_urls>]`, `data_collection` = `[none]`. There is no `internal:privateBrowsingAllowed`, so the extension is NOT active in private windows. |
| Add-on update prefs | `prefs.js` does not override `extensions.update.*`, so Firefox defaults apply: auto-update enabled. |
| Code identity | `xpi:background.js` matches git blob `1370f4e` (= `c3cfd10`, `c246197`). `xpi:content.js` matches blob `d43965e` (= `0f00c33` .. `c246197`). `xpi:manifest.json` matches no commit: it is the 1.0.0 manifest reformatted, plus `data_collection_permissions: {required:[none]}`. `content.css`, `popup/*` and `icons/*` are identical to repo and ws once CRLF is normalised. |
| Native host registration | `HKCU\Software\Mozilla\NativeMessagingHosts\claudecodebrowser` points to `C:\Tools\ClaudeCodeBrowser\native-host\claudecodebrowser.json`, whose path is `C:\Tools\ClaudeCodeBrowser\native-host\claudecodebrowser_host.bat`. That runs `python "%~dp0claudecodebrowser_host.py"` with `allowed_extensions: [claudecodebrowser@ligandal.com]`. The only uncommitted repo change is this JSON (the Windows path). The HKLM keys hold only the Windows Defender host. |
| MCP registration | `~/.claude.json`, `projects["C:/Tools/burp-mcp"].mcpServers.claudecodebrowser` = `{"command":"python","args":["C:/Tools/ClaudeCodeBrowser/mcp-server/stdio_wrapper.py"]}`. It is project-scoped to `C:/Tools/burp-mcp` only, with no env overrides. No `CLAUDE_BROWSER_*` or `CLAUDE_MCP_*` variables are set in the shell. |
| Live process tree (2026-10-12) | `firefox.exe` PID 6328 starts `cmd.exe /s/c ...claudecodebrowser_host.bat ...json claudecodebrowser@ligandal.com` (PID 23780). That starts `python claudecodebrowser_host.py` (PID 3008), which starts `Python312\python.exe C:\Tools\ClaudeCodeBrowser\mcp-server\server.py` (PID 30084, LISTENING on 127.0.0.1:8765 and 127.0.0.1:8766). Separately, Claude Code (`claude.exe`, PID 24232) starts `python C:/Tools/ClaudeCodeBrowser/mcp-server/stdio_wrapper.py` (PID 29668), which found `/health` up and proxies to PID 30084. |
| Python | Server Python is 3.12.10 (`C:\Users\Aastik\AppData\Local\Programs\Python\Python312\python.exe`) with `websockets` 13.1 (legacy `websockets.serve`). `playwright` is NOT installed, so headless mode is inert. Py 3.13.14 also exists. |
| Live `/health` | `{"status":"ok","version":"1.0.0","browsers_connected":0}`, so no WebSocket client is registered right now. |

---

## 2. Data path (installed configuration)

```
Claude Code --stdio JSON-RPC--> stdio_wrapper.py
  --HTTP POST 127.0.0.1:8765/mcp/call (X-API-Key)--> server.py execute_tool()
  -> (WebSocket branch: dead, see section 10) -> HTTP-polling branch:
     command {action, tabId, data:<raw MCP args minus tab_id>, requestId:str(time.time())}
     appended to server._pending_commands, waiter = threading.Event (30 s)
native host poll thread: GET /browser/poll every 0.5 s (X-API-Key), pops ONE command
  --native messaging stdout--> background.js handleNativeMessage -> handleCommand(action)
  -> tabs API | tabs.sendMessage(tabId, ...) to content.js in ALL frames | tabs.executeScript (top frame)
  --> postMessage({requestId, ...result}) --> native host main loop
  --> POST /browser/response (X-API-Key) --> connection_manager.handle_response -> event.set()
server returns result JSON -> stdio_wrapper wraps json.dumps(result, indent=2) in ONE text block
```

Key code: `repo:mcp-server/stdio_wrapper.py:102-115` (call, 30 s timeout at :111), `:177-196` (text block), `repo:mcp-server/server.py:837-982` (`execute_tool`), `:951` (requestId), `:955` (raw snake_case data), `:969` (30 s wait), `repo:native-host/claudecodebrowser_host.py:471-501` (poll every 0.5 s), `:388-423` (process_message), `:426-446` (POST /browser/response), `xpi:background.js:90-106` and `:182-268` (dispatch).

---

## 3. Tool inventory (39 tools, live schemas = repo HEAD `server.py` `MCP_TOOLS`)

The live schemas were loaded via `ToolSearch "+claudecodebrowser"` and none were invoked. They match HEAD exactly: for example `browser_get_tabs` has an empty `properties` object, whereas the workspace version adds 4 properties. The MCP name is `mcp__claudecodebrowser__<tool>`. The tool-to-action map is at `repo:mcp-server/server.py:844-887`.

"Installed" = behaviour with the installed v1.0.0 extension. UNKNOWN = returns `{"success":false,"error":"Unknown action: <action>"}`.

| # | Tool | Arguments (type, default) | Action | Installed |
|---|---|---|---|---|
| 1 | browser_screenshot | tab_id int?, full_page bool=false, save_to_file bool=true, filename str? | screenshot | WORKS (visible viewport only; `full_page` ignored). If `tab_id` is not the active tab it ACTIVATES that tab for 150 ms, then restores (`xpi:background.js:271-322`). Returns `{success, filepath:"\\tmp\\claudecodebrowser\\screenshots\\<name>.png" (drive-relative, i.e. C:\tmp\...), filename, size, tab:{id,url,title}, message}`. `save_to_file:false` returns the whole base64 data URL inline (huge). |
| 2 | browser_click | selector?, xpath?, text?, x num?, y num?, tab_id?, double_click=false, right_click=false | click | WORKS; `double_click`/`right_click` ignored, so a plain LEFT click happens. Synthetic mousedown/mouseup/click events plus `element.click()` (`xpi:content.js:119-194`), all `isTrusted=false`. Sent to all frames. |
| 3 | browser_type | text (req), selector?, placeholder?, name?, id?, tab_id?, clear=false, press_enter=false, delay int=50 | type | WORKS; `press_enter` ignored. Character-by-character synthetic key events; value is appended directly (`xpi:content.js:197-291`). Text is logged in clear by the native host. |
| 4 | browser_scroll | direction (up/down/left/right/top/bottom)?, amount int=300, selector?, to_element?, tab_id? | scroll | WORKS; `to_element` ignored. |
| 5 | browser_navigate | url (req), tab_id?, new_tab=false | navigate | WORKS; `new_tab` ignored. With no `tab_id` it navigates the ACTIVE tab of the last-focused window (`xpi:background.js:434-459`); the schema text "Creates new tab if not specified" is false. It returns the REQUESTED url, not the final one after redirects. Waits for `status=complete` or 30 s. |
| 6 | browser_get_page_info | tab_id? | getPageInfo | WORKS. Any frame may answer (broadcast). Up to 100 interactive elements; `interactiveElements[].value` (100 chars) is NOT masked for password inputs (`xpi:content.js:388`), while `forms[].fields[].value` is masked `***` (`:425`). Also forms (up to 20 fields each) and headings (up to 20). |
| 7 | browser_get_elements | selector (req), limit int=50, tab_id? | getElements | WORKS. `getElementInfo` returns tag/id/classes/name/type/text(200)/value(200, passwords included, `xpi:content.js:1108`)/href/src/position/selector. |
| 8 | browser_wait_for_element | selector (req), timeout int=10000, visible bool=true, tab_id? | waitForElement | WORKS (polls every 100 ms). |
| 9 | browser_highlight | selector (req), duration int=3000, label?, tab_id? | highlight | WORKS; inserts a page-visible `div.claude-highlight-overlay`. |
| 10 | browser_execute_script | script (req), tab_id? | executeScript | WORKS. See section 5. |
| 11 | browser_get_tabs | (none) | getTabs | WORKS. Returns ALL non-private tabs in all windows with url/title/favIconUrl etc., unbounded (`xpi:background.js:544-585`). |
| 12 | browser_get_tab_info | tab_id (req) | getTabInfo | WORKS. Tab, window and pageInfo (broadcast). |
| 13 | browser_find_tabs | url? (prefix), url_pattern?, title?, active bool?, audible bool? | findTabs | WORKS except `url_pattern`, which is ignored. If `url_pattern` is the only filter, EVERY tab is returned. |
| 14 | browser_screenshot_all_tabs | url_pattern?, include_data=false | screenshotAllTabs | DESTRUCTIVE NO-OP. Both arguments are ignored, so it activates EVERY tab in every window, returns metadata only, and saves nothing (`xpi:background.js:325-383`). |
| 15 | browser_create_tab | url="about:blank", active=true | createTab | WORKS. Returns `{tab:{id,url,title}}`. Opens in the default container (no `cookieStoreId`). `active` defaults to true, so it steals focus. |
| 16 | browser_close_tab | tab_id (req) | closeTab | WORKS on ANY tab: `browser.tabs.remove(tabId)` with no ownership check (`xpi:background.js:686-693`). |
| 17 | browser_focus_tab | tab_id (req) | focusTab | WORKS; also focuses the window. |
| 18 | browser_get_value | selector (req), tab_id? | getValue | UNKNOWN |
| 19 | browser_set_value | selector (req), value (req), tab_id? | setValue | UNKNOWN |
| 20 | browser_select_option | selector (req), value?, text?, index int?, tab_id? | selectOption | UNKNOWN |
| 21 | browser_hover | selector (req), tab_id? | hover | UNKNOWN |
| 22 | browser_refresh | tab_id?, bypass_cache=false, wait_for_load=true | refresh | WORKS; both options ignored (normal reload, waits). |
| 23 | browser_hard_refresh | tab_id? | hardRefresh | WORKS (`bypassCache` is true internally). |
| 24 | browser_reload_all | url_pattern?, bypass_cache=true | reloadAll | RELOADS EVERY TAB (pattern ignored; cache not bypassed). Skips `about:` and `moz-extension:` only (`xpi:background.js:749-781`). |
| 25 | browser_reload_by_url | url? (prefix), url_pattern?, bypass_cache=true | reloadByUrl | `url` works. `url_pattern` alone gives the error "Must provide url or urlPattern". Always bypasses cache. |
| 26 | browser_wait_for_change | selector="body", timeout int=10000, change_type (childList/attributes/text)?, subtree=true, tab_id? | waitForChange | UNKNOWN |
| 27 | browser_wait_for_network_idle | timeout int=10000, idle_time int=500, tab_id? | waitForNetworkIdle | UNKNOWN. Even if routed, its fetch/XHR hooks only see content-script requests (`xpi:content.js:603-671`). |
| 28 | browser_observe_element | selector (req), observer_id?, tab_id? | observeElement | UNKNOWN |
| 29 | browser_stop_observing | observer_id (req), tab_id? | stopObserving | UNKNOWN |
| 30 | browser_scroll_and_capture | scroll_step int?, delay int=500, max_scrolls int=20, restore=true, tab_id? | scrollAndCapture | UNKNOWN |
| 31 | browser_click_and_wait | selector?, xpath?, text?, wait_timeout int=5000, wait_for_selector?, wait_for_change=true, tab_id? | clickAndWait | UNKNOWN (confirmed in log) |
| 32 | browser_start_logging | clear_existing=false, tab_id? | startLogging | UNKNOWN |
| 33 | browser_stop_logging | tab_id? | stopLogging | UNKNOWN |
| 34 | browser_get_console_logs | level (log/warn/error/info/debug)?, search?, limit int=100, tab_id? | getConsoleLogs | UNKNOWN (confirmed in log) |
| 35 | browser_get_network_logs | url_pattern?, method?, status int?, errors_only=false, limit int=100, tab_id? | getNetworkLogs | UNKNOWN (confirmed in log) |
| 36 | browser_clear_logs | console=true, network=true, tab_id? | clearLogs | UNKNOWN |
| 37 | browser_eval_chain | steps [{script (req), label?, capture_console=true, stop_on_error=true}] (req), tab_id? | evalChain | UNKNOWN at EVERY extension version (implemented only in headless Playwright). |
| 38 | browser_wait_and_act | condition (req), action_script (req), poll_interval_ms=200, timeout_ms=15000, tab_id? | waitAndAct | UNKNOWN at every extension version (headless only) |
| 39 | browser_inject_observer | selector="body", observe_attributes=true, observe_child_list=true, observe_subtree=true, tab_id? | injectObserver | UNKNOWN at every extension version (headless only) |

Result envelope: `{"content":[{"type":"text","text": json.dumps(result, indent=2)}]}` (`repo:mcp-server/stdio_wrapper.py:185-196`). `isError` is never set; a failure is `"success": false` plus `"error"`. Typical errors:

- `Unknown action: X` (unsupported by the installed extension)
- `Command X timed out waiting for browser response after 30s`
- `Element not found with options: {...}`
- `MCP server is not available...` (native host)
- wrapper urllib errors, e.g. `timed out`

The wrapper implements only `initialize`, `notifications/initialized`, `tools/list` and `tools/call`. Everything else, including `ping`, gets JSON-RPC -32601 (`:228-237`).

Usage history (`mcp_server.log`, 2026-07-27 to 2026-10-12): browser_execute_script 7,921; navigate 973; get_tabs 242; click 188; create_tab 153; screenshot 139; get_page_info 43; find_tabs 42; type 37; close_tab 35; get_network_logs 24; get_elements 22; focus_tab 22; get_tab_info 15; start_logging 14; click_and_wait 13; get_console_logs 9; wait_for_element 5; hard_refresh 5; eval_chain 3; wait_for_network_idle 2; scroll 1; refresh 1; hover 1. Every logging, eval_chain and hover call failed.

The workspace adds 9 tools: `browser_go_back`, `browser_go_forward`, `browser_press_key`, `browser_get_text`, `browser_request_approval`, `browser_run_workflow`, `browser_solve_captcha`, `browser_audit_page`, `browser_safety_status` (48 total).

---

## 4. Network requests and response bodies

- **Installed (v1.0.0): none.** The manifest has no `webRequest` or `webRequestBlocking` permission (`xpi:manifest.json:8-16`). There is no `browser.webRequest`, no `filterResponseData`, no devtools panel and no `browser.cookies`. The only fetch/XHR hook is inside `waitForNetworkIdle` (`xpi:content.js:603-671`), which is unreachable (no background case) and temporary. The logging tools return `Unknown action`.
- **Repo HEAD (not installed), `repo:extension/content.js:21-290`.** It wraps `window.fetch` (`:78`) and `XMLHttpRequest.prototype.open/send` (`:144`) inside the content-script sandbox, with `MAX_LOG_ENTRIES = 500` (`:28`).
  - Fields captured: `type` (fetch/xhr), `method`, `url`, `requestHeaders` (fetch only, and only when `init.headers` was passed; a `Headers` object serialises to `{}`), `requestBody`, `startTime`, `pageUrl`, `status`, `statusText`, `duration`, `responseHeaders` (fetch only), `responseBody`, `error`.
  - Truncation: `requestBody` is `String(body)` cut to 1,000 chars (`:89`, `:158`). `responseBody` for JSON is re-serialised pretty and cut to 5,000 chars (`:110`). For `text/*` it is cut to 5,000 (`:112`). Anything else becomes `'[Binary data]'` (`:114`). XHR `responseText` is cut to 5,000 (`:164`).
  - Scope: the buffer is per frame and per document, lost on navigation, and collection starts only after `startLogging`.
  - **In Firefox these wrappers live in the Xray sandbox, so page-initiated fetch/XHR is never seen.** Only requests made by content-script code are logged. The workspace changelog adds that the HEAD assignment can even throw and abort the whole content script.
- **Workspace (not installed).** It is the same design, with `try` guards and `interceptionAvailable` flags (`ws:extension/content.js:148`, `:265`, `:305`) and the same limits (`:96`, `:117`, `:119`, `:121`, `:173`, `:179`). There is still no `webRequest` and no `filterResponseData`.
- **Bottom line: this tool can never return full response bodies or page traffic.** Use Burp proxy history and filter by `User-Agent` containing `Firefox/`.

---

## 5. JavaScript execution

- **Path:** `browser_execute_script` maps to `executeScript` (`xpi:background.js:497-509`), which calls `browser.tabs.executeScript(tab.id, {code: data.script})` and returns `{success:true, result: result[0]}`.
- **World: the Firefox content-script sandbox (isolated world with Xray vision).**
  - The DOM is shared.
  - Page JS globals, expandos and monkeypatches are invisible except through `window.wrappedJSObject` (Xray waiver).
  - Hooks assigned to `window.fetch` and similar inside the sandbox do not affect page code. This matches the researcher's memory note: "Firefox MCP = isolated content-script world (hooks capture nothing)".
- **Frame:** top-level frame only (`frameId` defaults to 0, `allFrames` to false). There is no argument for targeting a frame.
- **Timing:** `runAt` defaults to `document_idle`, so the call waits for the page to settle. There is no extension-side timeout. The end-to-end ceiling is 30 s (`repo:mcp-server/stdio_wrapper.py:111` urlopen, `repo:mcp-server/server.py:969` event wait).
- **Return value:**
  - It is the value of the last expression and must be structured-clonable; DOM nodes, functions and cross-compartment wrappers cause an error.
  - Per MDN (tabs.executeScript): "The last statement may be also a Promise", which is resolved (not supported by webextension-polyfill). Pattern: `(async () => { ...; return JSON.stringify(x); })()`. This was not verified live.
  - A thrown exception gives `{success:false, error}`.
- **Size limits:**
  - Script (command to extension): at most 1 MB per message, the native-messaging limit for messages from the app.
  - Result: no extension cap. It is pretty-printed (`indent=2`) into one MCP text block, so Claude Code's MCP output cap (about 25k tokens by default) is the practical ceiling. There is no chunking; slice large values across calls.
- **CSP:** the injected code itself is not subject to page CSP. A `<script>` element it inserts into the page IS subject to page CSP: inline needs `unsafe-inline` or a nonce, and a `blob:` src needs `blob:` in `script-src`. The `wrappedJSObject`/`exportFunction`/`cloneInto` route does not depend on CSP.
- **Requests made from injected code (MDN, Content scripts, "XHR and Fetch").**
  - In Firefox MV2 the sandbox's global `fetch`/`XMLHttpRequest` are privileged instances. They get the extension's cross-origin rights (`<all_urls>`, so CORS is not enforced) and do NOT set Origin and Referer as a page request would.
  - `content.fetch()` and `content.XMLHttpRequest` behave like the page.
  - Consequence: any "cross-origin read worked" or "request accepted without Origin" result produced via plain `fetch` in this tool is an artefact. Not verified live, but documented platform behaviour.
- **Where it does not run:** about:, moz-extension:, view-source:, reader view, the PDF viewer, Mozilla restricted domains (`extensions.webextensions.restrictedDomains`, e.g. addons.mozilla.org, accounts.firefox.com), and private windows (the extension is not allowed there).
- **eval_chain, wait_and_act and inject_observer** are not implemented in any extension version. In headless mode (`repo:mcp-server/headless_backend.py:214-291`) they use Playwright `page.evaluate`, i.e. the page main world, but headless is inactive here.

---

## 6. Tab identity and closing

- **Identifiers:** raw Firefox `tab.id` integers. They are unique within a browser session and reset when Firefox restarts (the native host and server restart with it). Tab results also carry `windowId`.
  - There is no session scoping, tab group or ownership record anywhere: not in the server, the native host, or the extension.
  - Container (`cookieStoreId`) is not returned.
- **Default target when `tab_id` is omitted:** `browser.tabs.query({active:true, currentWindow:true})[0]`. From a background script that is the active tab of the last-focused window, i.e. the tab the researcher is looking at. Example: `xpi:background.js:388`, repeated in every handler.
- **Can it close tabs it did not open?** YES. `closeTab` calls `browser.tabs.remove(tabId)` for any id (`xpi:background.js:686-693`). Other calls affect tabs the agent does not own:
  - `reloadAll` reloads every tab (`:749-781`).
  - `screenshotAllTabs` activates every tab (`:325-383`).
  - `navigate` without `tab_id` overwrites the researcher's active tab.
  - `screenshot(tab_id)` and `focusTab` switch the visible tab.
  - `createTab` is `active: true` by default.
  - A screenshot of a tab in ANOTHER window leaves that window switched, because restore only touches the current window's original tab (`:277-317`).
- **Content-script tools are broadcast.** click, type, scroll, getPageInfo, getElements, highlight and waitForElement use `tabs.sendMessage(tab.id, msg)` with NO `frameId` (e.g. `xpi:background.js:390-393`). Every frame's content script (`all_frames:true`) runs the action, and the first frame to respond wins, including third-party iframes and "Element not found" errors from them. Only `executeScript` is deterministic (top frame).
- **Multi-Account Containers is active.**
  - `createTab` opens in the default container.
  - To act as a container-held session, reuse that tab (`navigate` with its `tab_id`).
  - If MAC has an "always open in" rule for the site, MAC may close and reopen the tab, which invalidates the returned `tab.id`.
- **Private-window tabs** are invisible to this extension.

---

## 7. Cookies and storage

- No version declares the `cookies` permission, so there is no `browser.cookies` API and no cookie tool. The tool cannot read or set HttpOnly cookies.
- `document.cookie` through `browser_execute_script` returns the non-HttpOnly cookies of the top-frame origin (subject to Firefox Total Cookie Protection partitioning). Setting non-HttpOnly cookies through `document.cookie` works.
- `localStorage` and `sessionStorage` of the top-frame origin are readable and writable through `browser_execute_script`.
- The `storage` permission is declared but unused. `webNavigation` is also declared and unused: no `browser.storage` or `browser.webNavigation` call exists in the installed code.
- For HttpOnly session material, use Burp request `Cookie:` headers (Firefox UA) or a read-only copy of the profile's `cookies.sqlite` (+ `-wal`), which is the researcher's existing recipe.

---

## 8. Manifest and permissions (verbatim)

**Installed `xpi:manifest.json` (MV2, version 1.0.0):**

- `permissions` (`:8-16`): `"activeTab"`, `"tabs"`, `"nativeMessaging"`, `"storage"`, `"<all_urls>"`, `"webNavigation"`, `"contextMenus"`
- `background` (`:17-22`): `{"scripts":["background.js"],"persistent":true}`
- `content_scripts` (`:23-37`): `matches ["<all_urls>"]`, `js ["content.js"]`, `css ["content.css"]`, `run_at "document_end"`, `all_frames true`
- `browser_action` (`:38-46`): `default_popup "popup/popup.html"`, `default_title "ClaudeCodeBrowser"`, icons 16/32/48
- `browser_specific_settings.gecko` (`:53-63`): `id "claudecodebrowser@ligandal.com"`, `strict_min_version "78.0"`, `data_collection_permissions {"required":["none"]}`
- `web_accessible_resources` (`:64-66`): `["icons/*"]`. These sit behind Firefox's random per-install UUID, so pages cannot probe them without the UUID.
- `homepage_url`: `"https://ligandal.com"`; author "Ligandal"
- No `content_security_policy` key (MV2 default `script-src 'self'; object-src 'self'`). No `optional_permissions`, no `host_permissions` key (MV2 puts hosts in `permissions`), no `externally_connectable` (unsupported in Firefox), no `update_url`.
- Firefox-recorded grants (`extensions.json`):
  - permissions `[nativeMessaging, activeTab, contextMenus, storage, tabs, webNavigation]`
  - origins `[<all_urls>]`
  - data_collection `[none]`
  - optional/requested permissions all empty
  - private browsing: NOT allowed

**Other manifest versions:**

- **Repo HEAD `repo:extension/manifest.json`:** identical permissions and keys, without `data_collection_permissions`.
- **Workspace `ws:extension/manifest.json` (1.4.0):** adds `"notifications"` (`:13`) and `"update_url": "https://github.com/nanogenomic/ClaudeCodeBrowser/releases/latest/download/updates.json"` (`:56`); everything else is the same.

**Page-visible artefacts:** `content.css` is injected into every page and frame with global selectors `.claude-highlight-overlay`, `.claude-inspector-mode *`, `.claude-element-tooltip` (z-index 999999, background `#1e1e2e`), `.claude-typing-cursor` and `.claude-click-indicator`, plus keyframes `claude-pulse`, `claude-blink` and `claude-click-ripple` (`xpi:content.css:3-75`). Any page can create `<div class="claude-element-tooltip">` and read `getComputedStyle()` to detect the extension with zero interaction.

---

## 9. Egress (anything not localhost)

| Location | Destination | What | When | Severity |
|---|---|---|---|---|
| Firefox add-on manager (not extension code); `extensions.json` `sourceURI`, `installTelemetryInfo.source=amo`, `updateURL=null`, `applyBackgroundUpdates=1` | AMO update service (addons.mozilla.org / services.addons.mozilla.org) | add-on id and version, Firefox version, OS and locale (standard update ping) | periodic background update checks, default on | low, but a supply-chain risk: a new AMO version auto-installs over a `<all_urls>`+`nativeMessaging`+`tabs` extension in the logged-in browser. Only permission increases prompt. Whether AMO currently hosts a newer version was not checked (no network by design). |
| `ws:extension/manifest.json:56` (workspace only, NOT installed) | `https://github.com/nanogenomic/ClaudeCodeBrowser/releases/latest/download/updates.json` | Firefox update-manifest fetch | periodic, if this build were installed | low (supply chain: the GitHub repo owner controls future builds; they must still be Mozilla-signed) |
| `xpi:popup/popup.html:72` | `https://ligandal.com` | top-level navigation only | only if the user clicks the popup footer link | none |
| `xpi:manifest.json:7` | `https://ligandal.com` | link in about:addons | user click only | none |
| `xpi:popup/popup.js:75,99,122,152` | `http://localhost:8765/health` | GET, no token | when the popup opens or buttons are clicked | none (loopback) |
| `repo:mcp-server/stdio_wrapper.py:21-23,54,80,94,107-111` | `http://127.0.0.1:8765` (`CLAUDE_BROWSER_HOST`/`_HTTP_PORT` override, unset) | tool calls, args and results, `X-API-Key` | every tool call | none on default. If the host env were set to a non-loopback address, the token and all traffic would go over plain HTTP. |
| `repo:native-host/claudecodebrowser_host.py:54-56,129,166,432,480` | `http://127.0.0.1:8765` (`CLAUDE_MCP_HOST`/`PORT` override, unset) | /health every 10 s, /browser/poll every 0.5 s, /browser/response with full results incl. screenshots, `X-API-Key` | continuously while Firefox runs | none (loopback) |
| `repo:agent/browser_agent.py:27,86` | `CLAUDE_BROWSER_URL` (default `http://127.0.0.1:8765`) | tool calls | only if this CLI is run manually (not used by MCP) | none. There are no AI-provider calls anywhere: no anthropic/openai/requests/httpx imports. The file is identical in repo and ws. |
| `repo:mcp-server/headless_backend.py` | whatever URLs the agent navigates (headless Playwright browser) | normal page loads | only with `CLAUDE_BROWSER_HEADLESS=1` (inactive; playwright not installed) | none |
| `ws:scripts/publish-release.sh:66-96`, `ws:scripts/package-extension.sh` / `.ps1` | api.github.com, uploads.github.com, AMO signing API | release artefacts, `GITHUB_TOKEN`/AMO JWT | developer-only, manual | none for the researcher |

No telemetry, sendBeacon, analytics, remote script or WebSocket to non-loopback exists in any extension or Python file. The repo sweep regexes covered `https?://`, `urlopen`, `requests.`, `httpx`, `aiohttp`, `socket`, `fetch(`, `XMLHttpRequest`, `sendBeacon`, `new WebSocket`, `EventSource`, `curl`, `wget` and `Invoke-WebRequest`.

By design, all tool results (page text, element values, and the URLs and titles of ALL tabs via `browser_get_tabs`) flow into the model context. That is data flow to the model, not exfiltration, but `get_tabs` exposes unrelated tabs (other targets, mail, report drafts).

---

## 10. Local listeners

### 127.0.0.1:8765, HTTP

Implementation: `ThreadingHTTPServer` (BaseHTTP/0.6, HTTP/1.0), `repo:mcp-server/server.py:1025-1038`. Bind address comes from `HOST` at `:90`.

- **`GET /health` (unauthenticated, `:741-748`)** returns `status`, `timestamp` (µs), `version` "1.0.0" and `browsers_connected`. Verified live.
- **Authenticated endpoints** (`X-API-Key == API_TOKEN`, `:728-730`, plain `==`, not constant-time):
  - `GET /mcp/tools`
  - `GET /screenshots` (lists screenshot files with full paths)
  - `GET /browser/poll` (pops the next queued command, including scripts and typed text, `:777-785`)
  - `POST /mcp/call`
  - `POST /browser/command`, a no-op ack (`:814-827`), so extension-originated actions like the context-menu "screenshotTaken" go nowhere
  - `POST /browser/response`, which resolves waiters (`:829-832`)
  - Unknown paths return 403 without a token.
- **Token:** `secrets.token_hex(32)` in `~/.claudecodebrowser/api_token` (created 2026-07-27, 64 chars, `:73-87`). `chmod(0o600)` is a no-op on Windows. The ACL grants Aastik F, SYSTEM F, Administrators F and `DESKTOP-TO9KUGV\CodexSandboxUsers` RX (inherited from the profile), so any process in that sandbox group can read the token and fully drive the logged-in Firefox over loopback.
- **CORS:** no `Access-Control-*` header is ever sent (`:719-726`). `OPTIONS` returns 403 (`:732-735`). Verified live: OPTIONS gave 403, and `/health` with `Origin: https://evil.example` returned 200 with no ACAO. Cross-origin pages cannot read responses or attach `X-API-Key`. Simple no-cors POSTs are refused 403 before the body is parsed (`:792-794`).
- **Host header:** not validated. Verified live: `Host: rebind.example:8765` returned 200. DNS rebinding therefore reaches only `/health`, which leaks version, `browsers_connected` and the server clock at µs resolution.
- **Presence detection:** any page can detect the port, since a no-cors fetch resolves versus a network error. This is a fingerprint.
- **Past collision:** `mcp_server.log` shows 403s for `GET /evil.html` (2026-08-01) and `GET /jsurl.html` (2026-08-09). Those requests reached this server on 8765. This was most likely a PoC-port collision, possibly deliberate probing; the log cannot tell which.

### 127.0.0.1:8766, WebSocket

Implementation: `websockets.serve(websocket_handler, HOST, WS_PORT)` (`repo:mcp-server/server.py:1068-1076`). With websockets 13.1 this is the legacy server. No `origins=` is passed, so ANY Origin is accepted (`websockets.legacy.server.process_origin` only checks when `origins` is not None). The 2-arg handler is adapted by `remove_path_argument`.

- **No authentication in the installed HEAD.** `register_browser` runs on connect, before any frame is read (`:1041-1044`).
- **Commands are NOT delivered to WebSocket clients in the installed build.** `execute_tool` takes the WebSocket branch whenever a client is registered (`:896-926`), but it calls `asyncio.get_event_loop()` inside a `ThreadingHTTPServer` worker thread (`:908`). That raises `RuntimeError: There is no current event loop in thread ...` (verified on this Python 3.12.10 with a local thread test), which is caught, and the call falls back to HTTP polling.
- **Log evidence:** 0 "Browser registered", 0 "WebSocket command failed", 0 "Received from browser" in `mcp_server.log` since 2026-07-27. Live `browsers_connected` is 0.
- **Residual risks (installed):**
  - (a) Any frame containing `requestId` is passed to `handle_response` (`:1052-1054`), which also resolves HTTP-polling waiters (`:703-706`). A WebSocket client that guesses the `requestId` of an in-flight command (`str(time.time())`, `:951`) can therefore forge the tool result: prompt injection with tool-level trust, or corrupted evidence.
    - Python 3.12 `time.time()` uses `GetSystemTimeAsFileTime` (nominal 15.625 ms; observed steps on this host 0.75 to 1.0 ms), giving about 1,000 distinct ids per second. That is not blind-guessable.
    - `/health` leaks the same clock to µs, but only to a same-origin (DNS-rebinding) reader.
    - Theoretical, not demonstrated. Rated low to medium.
    - On Python 3.13 the clock is 100 ns (`GetSystemTimePreciseAsFileTime`), which makes guessing harder still.
  - (b) Every frame is DEBUG-logged verbatim (`:1050`) into the unrotated `mcp_server.log`, which allows disk fill and log injection by any web page.
  - (c) The WebSocket `onopen` event proves to any page that ClaudeCodeBrowser is running (fingerprint).
  - (d) The `browser_connections` dict and connection count are unbounded.
- **Browser reachability (NOT verified live):** Firefox treats loopback as potentially trustworthy, so mixed-content blocking should not stop `ws://127.0.0.1` from an https page. Whether Firefox 157 or Chrome gate public-to-loopback connections behind a local-network-access permission was not checked.

### Could an arbitrary website drive the browser through these listeners?

Not through HTTP (token, no CORS, preflight 403), and not through WebSocket command routing (dead path in this build). A website can register on the WebSocket, flood the logs, fingerprint the tool and, theoretically, forge results. It cannot reach the extension directly either: `content.js` has no `window.postMessage` or DOM-event bridge, and the background `runtime.onMessage` only accepts extension contexts (`xpi:background.js:823-829`).

A co-installed EXTENSION can drive it fully (section 11.1).

### Other processes

- The native host opens no listener; it is stdio plus HTTP client only.
- It auto-spawns the server detached whenever Firefox starts (`repo:native-host/claudecodebrowser_host.py:230-302`, `start_new_session`), so both ports are open whenever Firefox runs, even with Claude Code closed.
- `stdio_wrapper` opens no listener.

---

## 11. Other security observations (installed)

1. **`runtime.onMessageExternal` passthrough (`xpi:background.js:831-836`).** `handleCommand(message)` receives a caller-chosen `action`, `tabId` and `data`, and the result is returned to the caller. Any other installed extension can call `browser.runtime.sendMessage("claudecodebrowser@ligandal.com", {action:"executeScript", tabId:N, data:{script:"..."}})` and get script execution on any `<all_urls>` tab plus the return value. It can also use captureVisibleTab, getTabs (all URLs and titles), closeTab, navigate, reloadAll and so on.
   - Active co-installed extensions: Easy Screenshot, FoxScroller, Firefox Multi-Account Containers, TryWebKits Helper Kit (no host origins of its own), Free VPN - VPN Proxy VeePN (no host origins of its own), FoxyProxy, AdBlock, Wappalyzer. Pinterest Save Button is disabled. New Tab is built in.
   - Latent: there is no evidence of abuse and no logging of external messages. Severity high for a logged-in research browser.
   - Fixed in `ws:extension/background.js:966-975` (refuses all external messages).
2. **Password values readable.** `getPageInfo` masks `forms[].fields` (`xpi:content.js:425`) but not `interactiveElements[].value` (`:388`). `getElementInfo` returns `value` up to 200 chars (`:1108`), so `browser_get_elements {"selector":"input[type=password]"}` returns typed passwords. This is unchanged in the workspace (`ws:extension/content.js:916`, `:1695`).
3. **Logs at rest in clear.**
   - The native host logs at DEBUG to a file and stderr (`repo:native-host/claudecodebrowser_host.py:30-49`): every command it sends (`:118` "Sent message: {...}") and every extension response (`:457`, `:602`). It rotates at 5 MB, keeping one `.old` (`:36-40`).
   - Counts in `native_host.log.old` (from 2026-09-17) plus `native_host.log`: 7 `type` commands with typed text in clear, 422 `executeScript` commands with scripts in clear, 402 results, 64 base64 PNG data URLs.
   - The server logs at DEBUG with no rotation (`repo:mcp-server/server.py:52-63`). `mcp_server.log` is 404,938,800 bytes and 3,857,997 lines since 2026-07-27, of which 3,629,705 are `/browser/poll` access lines and 186,811 are `/health`. Polling adds 2 lines per second whenever Firefox is running; the average since July is about 0.55 per second.
   - The server masks only `text`, `script`, `value` and `password` (`:839-841`). `steps`, `action_script` and `condition` (eval_chain/wait_and_act) are logged in clear: 3 occurrences.
4. **Screenshots persisted world-readable.**
   - The server saves to `Path('/tmp/claudecodebrowser/screenshots')` (`repo:mcp-server/server.py:97-99`, `:984-1022`). On Windows that is drive-relative, i.e. `C:\tmp\...`.
   - The native host ALSO saves every response carrying `data` as `screenshot_<epoch>.png` (`repo:native-host/claudecodebrowser_host.py:397-405`, `:354-383`).
   - 215 files and 22 MB exist (109 of them native-host duplicates), the oldest from 2026-08-16. The ACL allows `BUILTIN\Users:(RX)` and `Authenticated Users:(M)`, so every local account can read them. Nothing ever cleans them.
5. **Linux/macOS only: the native host kills whatever holds port 8765** if `/health` does not answer "ok" (`repo:native-host/claudecodebrowser_host.py:176-227`, lsof/fuser, SIGTERM then SIGKILL). This violates "never close a program you did not start". On Windows lsof/fuser are absent, so it is a no-op.
6. **Robustness.**
   - `send_message` is called from the poll thread (`:491`) and the main thread (`:611`) without a lock, risking interleaved native-messaging frames.
   - Responses from the extension are echoed back to it (`:605-611`); harmless.
   - The popup's "status"/"Inspect" actions are not handled by the installed background, so they error.
   - Its "auto-start" is effectively done by the native host on connect.
7. **Detectability and identity hygiene.**
   - content.css global classes can be detected via `getComputedStyle`.
   - The highlight overlay and smooth `scrollIntoView` are page-observable.
   - All input events are `isTrusted=false`.
   - The loopback ports 8765/8766 are detectable from pages.
   - Together these give a stable cross-target marker of the researcher's Firefox.
8. **Prompt-injection surface.** Page text, element text, tab titles and tab URLs returned by tools are attacker-controlled (the target is the attacker from the tool's perspective).

---

## 12. Installed vs workspace: material differences

| Component | Installed / running | Workspace (`ws:`) |
|---|---|---|
| extension | AMO 1.0.0 = git `c246197`-era JS (no logging, 22 background actions) | 1.4.0: forwards all content actions, logging, approval/captcha banners, credential guard, history, pressKey, getText, onMessageExternal refused |
| mcp-server | repo HEAD `d5f6bbe` (39 tools, no safety, WebSocket unauthenticated, WebSocket dispatch dead, snake_case args) | 48 tools, `safety.py`, WebSocket token, `MAIN_EVENT_LOOP`, `camelize_args`, version 1.4.0 |
| stdio_wrapper.py | HEAD | identical |
| native host .py | HEAD | identical; only the manifest JSON differs (Linux path, older description) |
| agent, `.claude/agents` | HEAD | identical |
| scripts | install.sh, uninstall.sh | + install.ps1 (re-points the HKCU native-host key to `%USERPROFILE%\.claudecodebrowser\native-host\claudecodebrowser.json` with a `run_host.bat`), build-chrome.sh, package-extension.sh/.ps1, publish-release.sh |

**Security-relevant changes in the workspace:**

1. **WebSocket requires the API token as the first frame** (`ws:mcp-server/server.py:1479-1503`, `secrets.compare_digest` at `:1491`, close 1008 at `:1499`). `origins=` is still not passed (`:1538`), but the token gates registration.
   - `MAIN_EVENT_LOOP` (`:1528-1532`, `:1546-1549`) makes the WebSocket dispatch path LIVE.
   - Never deploy the loop fix without the token check. With the installed handler, a live dispatch path would hand every command (typed text, scripts) to any web page that connected to 8766.
2. **`onMessageExternal` refused** (`ws:extension/background.js:966-975`).
3. **`safety.py` (new, 407 lines).**
   - Features: scheme guard (http/https/about:blank only), block and allow regexes, protected-domain confirmation (token flow or in-page human approval), read-only mode, script kill switch, 120 actions/min rate limit, and `~/.claudecodebrowser/logs/audit.jsonl` with redaction of text/script/value/password/steps/action_script/condition. Config lives in `~/.claudecodebrowser/safety.json`, with env overrides `CLAUDE_BROWSER_READ_ONLY` and `CLAUDE_BROWSER_ALLOW_SCRIPTS`.
   - Weakness: only `arguments.url` is URL-checked (`safety.py:327-329`); script tools can navigate anywhere.
   - Weakness: the protected-domain check for actions without a URL uses a best-effort `_current_url` taken from the last result (`:218-223`, `:299`). It goes stale when `tab_id` targets another tab or the user switches tabs.
   - Weakness: `OBSERVE_TOOLS` (`:109-121`) includes `browser_get_value`, `browser_screenshot_all_tabs`, `browser_focus_tab`, `browser_hover`, `browser_scroll`, `browser_highlight`, `browser_request_approval` and `browser_solve_captcha`. These are allowed even in read-only mode.
   - Weakness: `browser_audit_page` dispatches `executeScript` directly and bypasses the script kill switch (`ws:mcp-server/server.py:1398-1404`, `_audit_page`).
   - Weakness: the in-page Approve/Deny banner (`ws:extension/content.js:423-486`) lives in page DOM as `#__ccb_approval_banner`, and its click handler (`:480`) has no `event.isTrusted` check. Page script can therefore click Approve itself. The captcha "Done" button has the same issue (`:600`).
   - Weakness: in token mode the agent can simply echo the `confirm_token`.
4. **Credential guard.** Typing or setting into password fields is refused (`ws:extension/content.js:406-420`, flag from `ws:mcp-server/server.py:1114-1119`). It is enforced browser-side, so it does nothing with the installed 1.0.0 extension. Reading password values is still allowed.
5. **`camelize_args`** (`ws:mcp-server/server.py:114-125`, `:1217`) fixes the snake_case bug for the 1.4.0 extension. But `ws:extension/background.js:665-667` reads snake_case (`current_window_only`, `include_favicon`, `url_pattern`) after the server camelizes them, so those `get_tabs` options are dead. `get_tabs` is always current window only and `limit` works.
6. **Auto-update channel moves to GitHub** (`update_url`), and the `notifications` permission is added (triggers a permission prompt on update).
7. **Unchanged in the workspace (still true after an upgrade):**
   - no `webRequest` or bodies; logging only in the isolated world
   - `executeScript` is isolated world and top frame only
   - `closeTab` works on any tab
   - password values readable
   - native host DEBUG logs everything; server log unrotated (the server log mask set is still only 4 keys, `ws:mcp-server/server.py:1011`)
   - world-readable screenshot directory
   - no Host/Origin validation on HTTP
   - eval_chain/wait_and_act/inject_observer still missing from the extension

---

## 13. Facts the bbh harness must know

1. **Tool prefix and probe.** The prefix is `mcp__claudecodebrowser__`; 39 tools are live.
   - Liveness without touching any page: `GET http://127.0.0.1:8765/health` (no token) returns `{"status":"ok","version":"1.0.0","browsers_connected":0}`. `browsers_connected > 0` means an unexpected WebSocket client is on 8766: alert.
   - End-to-end probe with no side effects: `browser_find_tabs {"title":"<impossible string>"}` returns `{success:true, tabs:[], count:0}`.
2. **Parse results as JSON.** Parse the single text block with `json.loads`; `isError` is never set. `"Unknown action: X"` means the installed extension does not support the tool. It is NOT a negative finding and must never be written down as "no network requests" or "no console errors".
3. **PreToolUse deny or rewrite list for the installed pairing.**
   - Block outright: the 19 UNKNOWN tools (section 3); `browser_reload_all`; `browser_screenshot_all_tabs`.
   - Block `browser_close_tab` and `browser_focus_tab` unless the `tab_id` is in the harness's owned-tab ledger.
   - Block any tab-scoped tool without an explicit `tab_id`. That covers `browser_navigate` with no `tab_id` and `new_tab:true` (ignored).
   - Block `browser_click` with `double_click`/`right_click` (they silently become a left click), `browser_type` with `press_enter` (ignored; use `form.requestSubmit()` in execute_script or click the submit button), `browser_find_tabs` with only `url_pattern` (returns every tab), `browser_screenshot` with `save_to_file:false` (huge output) or `full_page` (ignored), and `browser_create_tab` without `active:false` (steals focus from the researcher).
   - Verify against the current docs whether PreToolUse can return `updatedInput`; if it can, rewrite instead of denying.
4. **Tab ownership ledger.** Record `result.tab.id` from every `browser_create_tab`. Ids reset when Firefox restarts. MAC "always open in container" rules may close and reopen the tab, changing its id. `browser_get_tabs` returns every non-private tab; prefer `browser_find_tabs {url: <prefix>}`.
5. **Network evidence.**
   - Never from this tool. Read Burp proxy history and identify Firefox by `User-Agent` containing `Firefox/`.
   - Requests issued by plain `fetch`/`XMLHttpRequest` inside `browser_execute_script` are extension-privileged (no CORS, no page-like Origin/Referer). The ledger must tag them non-evidence for CORS, CSRF and SameSite.
   - For page-equivalent requests use `content.fetch(...)`, or a page-world call through `window.wrappedJSObject`.
6. **JS recipe.**
   - Isolated world, top frame, `document_idle`.
   - Return `JSON.stringify(...)`; the last expression may be a Promise.
   - Read page state via `window.wrappedJSObject`.
   - Page-world hooks need `exportFunction`/`wrappedJSObject`, or a CSP-permitting `<script>` injection.
   - 30 s ceiling; commands up to 1 MB; output bounded by Claude Code's MCP output cap, so chunk large values.
7. **Frame ambiguity.** Every DOM tool except execute_script is broadcast to all frames and returns the first responder. Check `url` in `getPageInfo` results, and prefer execute_script for reads.
8. **Input is synthetic** (`isTrusted=false`, no user activation). Popups, clipboard, file choosers, fullscreen and trusted-gesture widgets will not work, and anti-bot scripts can see it.
9. **Throughput.** The native host polls every 0.5 s and pops one command per poll (`has_more` is ignored), so about 2 commands per second at most, with up to 0.5 s extra latency each. Concurrent calls queue FIFO. 30 s timeout per call.
10. **Screenshots.**
    - The returned `filepath` is drive-relative (`\tmp\claudecodebrowser\screenshots\<name>.png`, i.e. `C:\tmp\...`).
    - `filename` is basenamed.
    - A duplicate `screenshot_<epoch>.png` is also written.
    - Copy into `captures/` and treat `C:\tmp\claudecodebrowser` as sensitive (world-readable).
11. **Data hygiene.**
    - Never type real credentials or OTPs via `browser_type` (they are logged in clear in `native_host.log`).
    - Scripts and results are logged too, so do not return raw tokens in execute_script results unless they are needed as evidence.
    - `mcp_server.log` grows about 2 lines per second while Firefox runs, without rotation (405 MB now).
12. **Reserved ports.** 8765 and 8766 are taken whenever Firefox runs. The bbh dashboard, lab and PoC servers must use other ports (a past PoC collision is visible in the logs).
13. **Identity hygiene.** The researcher's Firefox is detectable by targets (content.css classes, loopback ports, synthetic events). Note it in `workings.md`; the harness cannot remove it.
14. **Registration scope.** claudecodebrowser is registered only for the `C:/Tools/burp-mcp` project in `~/.claude.json`. The bbh plugin must not assume it exists in other engagement folders.
15. **Version drift.** The extension version is not exposed over MCP, and `/health` reports only the server version. Read `extensions.json` (read-only) at session start and record the extension version and hashes in the ledger. AMO auto-update can change tool support underneath the harness. Upgrading only the server to the workspace build has these effects:
    - `camelize_args` would make the multi-word options work.
    - Browser-side behaviour stays at 1.0.0: there is no credential guard, because it is enforced in the 1.4.0 content script.
    - The same 19 tools stay Unknown.
    - Six of the 9 new tools would also be Unknown (`goBack`, `goForward`, `pressKey`, `getText`, `requestApproval`, `solveCaptcha`).
    - `browser_run_workflow`, `browser_audit_page` and `browser_safety_status` would work, because they are server-side or use executeScript.
16. **Token-direct driving.** Any local process that can read `~/.claudecodebrowser/api_token` can drive Firefox via `POST http://127.0.0.1:8765/mcp/call` with `X-API-Key`, bypassing Claude Code hooks. The harness must not do this silently. Note the token ACL includes `CodexSandboxUsers`.
17. **No cookie API.** Get session cookies, including HttpOnly, from Burp request headers or a read-only copy of `cookies.sqlite`.

---

## 14. Evidence log (commands run, all read-only)

- Copied the XPI to the scratchpad and extracted it with Python `zipfile`; computed sha256; hash-compared every file against repo and ws (CRLF-normalised); located matching git blobs with `git hash-object` across `git rev-list --all`.
- `git log`, `git status`, and `git diff c246197 d5f6bbe` for the extension in `C:/Tools/ClaudeCodeBrowser`; `diff -u` repo vs ws for server.py, background.js, content.js and headless_backend.py; read `safety.py` in full.
- Registry: `Get-ChildItem HKCU:\Software\Mozilla\NativeMessagingHosts` (and HKLM); read the referenced JSON and `.bat`.
- Processes: `netstat -ano` (8765/8766 LISTENING, PID 30084), `Get-CimInstance Win32_Process` command lines, `Get-Process 6328` (firefox).
- Python: `websockets` 13.1 legacy `serve` (verified `remove_path_argument` and `process_origin` behaviour by reading the installed library source); `asyncio.get_event_loop()` raises in a worker thread on 3.12.10; clock resolution of 3.12 (`GetSystemTimeAsFileTime`, 15.625 ms nominal, about 0.75 to 1.0 ms observed) vs 3.13 (`GetSystemTimePreciseAsFileTime`, 100 ns).
- Logs, counts only (no secret content printed): "Browser registered" 0; tool usage counts; "Unknown action" counts; 403 request lines (paths only); counts of logged type/executeScript commands, results and screenshot data URLs.
- `extensions.json` entry for this add-on, and the co-installed extension list; `prefs.js` update prefs; `application.ini` version.
- ACLs via `icacls` on `api_token`, `C:\tmp\claudecodebrowser\screenshots` and `C:\tmp`.
- Live loopback probes: `GET /health` returned 200 with `browsers_connected:0`; `GET /mcp/tools` without a token returned 403; `OPTIONS /mcp/call` with a foreign Origin returned 403; `GET /health` with Origin `evil.example` and Host `rebind.example:8765` returned 200 with no ACAO header.
- `ToolSearch "+claudecodebrowser"` loaded 39 schemas. NONE invoked. No `mcp__browser-mcp__*`, `mcp__claudecodebrowser__*` or `mcp__claude-in-chrome__*` call was made.
