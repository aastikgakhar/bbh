# Egress red-team audit: Agent360 Browser MCP (Chrome) and ClaudeCodeBrowser (Firefox)

Date: 2026-10-12. Method: read-only static source audit of the INSTALLED copies, plus read-only environment checks (netstat, registry, Firefox `extensions.json`, Python/npm package metadata, log line counts). No browser tool was invoked, no live site was touched, and no MCP server was executed.

Starting assumption: both stacks leak. Each section below records what the code proves.

## 0. Verdict in one paragraph

Neither stack has autonomous phone-home code. There is no telemetry or analytics SDK, no crash reporter, no remote script loading, no LLM API client, and no obfuscated or string-built URL. Every programmatic network endpoint in both stacks is loopback by default. Off-machine data movement happens through five other kinds of channel:

- **(a) Agent-driven egress primitives.** These run with the researcher's logged-in sessions: navigate, execute_script, fetch, upload, and the Firefox executeScript.
- **(b) Unauthenticated local control channels.** These let something other than the agent drive the logged-in browser:
  - The Agent360 extension obeys any process that answers HTTP 426 on 127.0.0.1:9876-9895.
  - ClaudeCodeBrowser (CCB) obeys any other installed Firefox extension via `runtime.onMessageExternal`. There are 8 active third-party extensions, including a free VPN.
  - The CCB WebSocket on 127.0.0.1:8766 accepts any origin. It is currently latent because of an asyncio threading bug.
- **(c) Supply-chain auto-update.** `npx @agent360/browser-mcp@latest` runs on every session start, the Chrome Web Store auto-updates Agent360, and AMO auto-updates CCB. Each can replace the code that holds `<all_urls>` (plus `debugger`/`cookies` for Agent360, plus `nativeMessaging` for CCB) without a new permission prompt.
- **(d) By-design flow of page data to the MCP client.** This includes cookies, screenshots and credentials typed into `browser_ask_user`, which therefore reach the LLM provider.
- **(e) GitHub "feedback" pre-filled issue links.** The agent is told to generate them without asking. They carry the target's origin and path, and data leaves only when a human clicks or the agent opens the link.

## 1. Scope and exact files

| Stack | Component | Path (installed copy audited) |
|---|---|---|
| A | Chrome extension 1.30.1 (CWS id `jdehgalffmffhfhmmhaokfbfnafnmgcl`, Profile 4) | `C:/Users/Aastik/AppData/Local/Google/Chrome/User Data/Profile 4/Extensions/jdehgalffmffhfhmmhaokfbfnafnmgcl/1.30.1_0/` (below: `EXT/`) |
| A | MCP server 1.30.1 (npx cache) | `C:/Users/Aastik/AppData/Local/npm-cache/_npx/3a1945bdadeae2b9/node_modules/@agent360/browser-mcp/` (below: `SRV/`) |
| A | Registration | `~/.claude.json` user `mcpServers.browser-mcp` = `npx @agent360/browser-mcp@latest`, `env: {}` |
| B | Firefox XPI (AMO-signed, v1.0.0) extracted copy | `C:/Users/Aastik/AppData/Local/Temp/claude/C--Tools-burp-mcp/c28dd141-9d65-442b-990f-d465b45e9d7e/scratchpad/ff-xpi-egress/` (below: `XPI/`) |
| B | Native host | `C:/Tools/ClaudeCodeBrowser/native-host/` (HKCU `Software\Mozilla\NativeMessagingHosts\claudecodebrowser` -> `claudecodebrowser.json` -> `claudecodebrowser_host.bat` -> `python claudecodebrowser_host.py`) |
| B | MCP server | `C:/Tools/ClaudeCodeBrowser/mcp-server/` (Claude Code project config for `C:/Tools/burp-mcp`: `python C:/Tools/ClaudeCodeBrowser/mcp-server/stdio_wrapper.py`) |
| B | Agent CLI | `C:/Tools/ClaudeCodeBrowser/agent/browser_agent.py` |

Integrity and provenance:
- **A:** `EXT/background.js`, `offscreen.js`, `offscreen.html`, `popup.html` and `popup.js` are byte-identical (sha256) to `SRV/extension/*`. The installed manifest differs only by CWS-added `key` and `update_url` plus formatting.
- **B:** The installed XPI is NOT the repo HEAD. `XPI/background.js` equals the repo blob at commit `c3cfd10`, `content.js` at `0f00c33`, and `popup.js` at `a9dce86`. `manifest.json` differs from the repo only by formatting and the AMO-required `data_collection_permissions: none`.
  - The repo HEAD (`d5f6bbe`) adds a fetch/XHR/console logger to `content.js` and logging actions to `background.js`. That code is not installed.
  - No hidden code was found in the signed build.
- **B install source:** Firefox `extensions.json` records `sourceURI=https://addons.mozilla.org/firefox/downloads/file/4641779/claudecodebrowser-1.0.0.xpi`, `installTelemetryInfo.source=amo`, `signedState=2` and `applyBackgroundUpdates=1`.

## 2. Listeners and bridges (bind, auth, Origin/Host)

Observed live (`Get-NetTCPConnection`, 2026-10-12 21:0x):

| Socket | Owner |
|---|---|
| `127.0.0.1:8765` | python PID 30084 (CCB `server.py`) |
| `127.0.0.1:8766` | python PID 30084 (CCB `server.py`) |
| `127.0.0.1:9876` | BurpSuite PID 13068 (Burp MCP, configured as `burp` SSE `http://127.0.0.1:9876`) |

No Agent360 port is currently bound; its server binds lazily on the first browser call.

| # | Component | Bind | Auth | Origin / Host check | Who can reach it | Risk |
|---|---|---|---|---|---|---|
| L1 | Agent360 MCP server WebSocket (`SRV/index.js:202-222`) | `127.0.0.1`, ports `9876-9895` (`index.js:45-46`). 9876 is taken by Burp, so it would use 9877+ | None. Pairing was withdrawn in 1.30.1 and `BROWSER_MCP_TOKEN` is ignored (`index.js:133-147`, `113-115`) | Origin must match `^chrome-extension://[a-p]{32}$`. Checked in `verifyClient` (`index.js:214-221`) and again on connection (`index.js:261-287`). No Host check | Any Chrome/Chromium extension (any id, any profile, Edge included). Any local process can forge the Origin header. Web pages are blocked (Origin), including DNS rebinding | Medium (local) |
| L2 | Agent360 extension as client, reverse trust (`EXT/offscreen.js:109-119`, `142-181`, `183-311`, `352-354`) | Outbound to `http://127.0.0.1:{9876..9895}/` every 2 s (host hardcoded; range only from `?porte=`, validated `1024-65535`, span <200, `offscreen.js:58-69`) | None. The server is trusted if `GET /` returns 426 (`offscreen.js:115`) | n/a | Any local process (any Windows user/session, because loopback ports are machine-wide) that squats a port in the range | High (local). It obeys every command (`offscreen.js:266-294` -> `EXT/background.js:3199-3426`): `get_cookies`, `execute_script`, `navigate`, `fetch`, and `upload_file`/`drop_file` with arbitrary local paths. The cwd guard exists only in the server (`SRV/index.js:822-870`); the extension passes paths straight to `DOM.setFileInputFiles` (`background.js:5395-5404`, `3087`, `3169`). Always on: scanning runs whether or not an agent is running. This also routes around Chrome's App-Bound cookie encryption |
| L3 | CCB MCP HTTP (`mcp-server/server.py:1034-1038`, handler `713-835`) | `CLAUDE_BROWSER_HOST` (default and observed `127.0.0.1`):`8765` | `X-API-Key` = 64-hex token from `~/.claudecodebrowser/api_token` (`server.py:73-87`, `728-730`) on everything except `GET /health` (`741-748`) | No Origin or Host check. No CORS headers (`719-726`). `OPTIONS` -> 403 (`732-735`) | Local processes with the token. The token file ACL includes `DESKTOP-TO9KUGV\CodexSandboxUsers:(RX)`, and `chmod 0o600` (`server.py:82`) is a no-op on Windows. A DNS-rebinding page can read only `/health` (version, `browsers_connected`) | Low |
| L4 | CCB MCP WebSocket (`server.py:1041-1076`) | `CLAUDE_BROWSER_HOST`:`8766` (observed `127.0.0.1`) | None | None. websockets 13.1 `serve()` = legacy server, `origins=None` | Any local process, and any web page in any browser on the machine (subject only to the browser's own local-network restrictions) | Low today, High if "fixed". See F5 |
| L5 | CCB Firefox background `runtime.onMessageExternal` (`XPI/background.js:832-836`) | In-browser message channel | None. There is no `sender.id` check, and Firefox has no `externally_connectable` | n/a | Any other installed Firefox extension. Active now: Easy Screenshot, FoxScroller, Multi-Account Containers, TryWebKits Helper Kit, Free VPN - VPN Proxy VeePN, FoxyProxy, AdBlock, Wappalyzer | High. See F2 |
| L6 | CCB native messaging host (`native-host/claudecodebrowser_host.py`) | stdio only | Firefox `allowed_extensions: ["claudecodebrowser@ligandal.com"]` (`claudecodebrowser.json:6-8`) | n/a | Only the CCB extension | None |
| L7 | Agent360 extension `chrome.runtime.onMessage` (`EXT/background.js:2058-2117`) | Internal | Internal contexts only. No `onMessageExternal`, no `externally_connectable`, no `web_accessible_resources`, no content scripts | n/a | Extension's own pages | None |

Note on the port collision: Agent360's default `BASE_PORT` 9876 is Burp MCP's SSE port. The Agent360 offscreen document sends `GET http://127.0.0.1:9876/` to Burp every 2 s. It would attach and obey only if Burp answered 426, which it does not.

## 3. Stack A: Agent360 Browser MCP (Chrome). Every network-capable path

### 3.1 Extension (`EXT/`)

| Location | Destination | Data | Trigger | Class / severity |
|---|---|---|---|---|
| `manifest.json:13` CSP `connect-src 'self' ws://127.0.0.1:* http://127.0.0.1:*` | n/a | n/a | n/a | Control. Restricts fetch/XHR/WS from the popup, the offscreen document and (per Chrome docs) the service worker to loopback. It does not restrict injected page scripts, tab navigation or file uploads |
| `manifest.json:26` `update_url https://clients2.google.com/service/update2/crx` | Google CWS update service | Extension id, version, Chrome version (Chrome-generated) | Chrome periodic update check | Low data. Supply chain: silent updates keep `<all_urls>`+`debugger`+`cookies`+`scripting` (`manifest.json:16,25`) |
| `offscreen.js:36` `fetch(chrome.runtime.getURL(fil))` | Own package files | none | Hello handshake | None |
| `offscreen.js:111` `fetch('http://127.0.0.1:'+port+'/')` | Loopback 9876-9895 (hits Burp MCP on 9876) | GET probe (extension Origin header) | Every 2 s (`offscreen.js:353-354`) | None (loopback). Feeds L2 |
| `offscreen.js:194` `new WebSocket('ws://127.0.0.1:'+port)` | Loopback | hello `{extensionId, version, kode: 12-hex sha256 prefix of background.js+offscreen.js}` (`offscreen.js:240-259`), then every command result | On a 426 probe | None (loopback). Feeds L2 |
| `background.js:4757-4773` `case 'fetch'`: `fetch(params.url, {method, headers, body})` | Any URL the agent chooses | Any headers/body the agent supplies (for example cookies obtained via `get_cookies`) | Agent tool `browser_fetch` (`SRV/tools.js:280-292` "NOT subject to CORS") | Medium, agent-mediated. Likely blocked for non-loopback by the manifest CSP (documented to apply to MV3 service workers; not verified at runtime) |
| `background.js:3201-3336` navigate: `tabs.update` `:3308`, `tabs.create` `:3305`, `windows.create` `:3246` | Any URL in the logged-in Chrome | URL/query string, with cookies attached by the browser | Agent tool `browser_navigate`; `browser_extract_token` (`SRV/index.js:1298-1317` -> `SRV/tools.js:525-562`: Stripe, HubSpot, Slack, Shopify, Mailchimp, Pipedrive, Calendly, Google Cloud, LinkedIn dashboards) | Medium, agent-mediated (prompt-injection exfil channel) |
| `background.js:3583-3735` execute_script: ISOLATED `:3621`, MAIN `:3653`, CDP `Runtime.evaluate` `:3700`. `background.js:5196-5234` select_frame (MAIN) | Whatever the injected JS requests (page origin, page cookies) | Anything on the page | Agent tool | Medium-High, agent-mediated. Strongest primitive |
| `background.js:5348-5414` upload_file, `3040-3195` + `4105-4112` drop_file -> `DOM.setFileInputFiles` | The website the form posts to | Local files | Agent tool (server limits paths to cwd: `SRV/index.js:822-870`) | Medium. Unrestricted if driven via L1/L2 |
| `background.js:5038-5194` ask_user: overlay injected with `world: 'MAIN'` (`:5185`), password/text inputs (`:5126-5139`), values returned (`:5146-5151`). OS notification with message text (`:5050-5058`) | (1) The page's own scripts can read the overlay inputs and send them to the page's servers. (2) Values go to the MCP client and then the LLM provider | Credentials and 2FA codes the human types | Agent tool. The server INSTRUCTIONS tell the agent to use it for credentials (`SRV/index.js:642`, `654-660`) | Medium |
| `background.js:4790-4886` get_cookies (scoped to http(s) hosts of session tabs, `4810-4851`); `4888-4900` get_local_storage; `4688-4755` wait_for_network (response body up to 5000 chars, `:4733`); `3338-3383` get_page_content; `3451-3581` screenshot (session tab only) | MCP client, then LLM provider | Cookie values, storage, page text/HTML, network bodies, screenshots | Agent tool | By design. High sensitivity |
| `background.js:965-990`, `1028-1129` (`window.__bmcpClickTarget/__bmcpClicked/__bmcpClickListener` in MAIN world during clicks); `5011-5025` (`window.__mcpConsoleLogs` plus a wrapped `console.*`, persistent); `5095-5103` (`#a360-styles` left in the DOM); `3069` (`data-bmcp-drop-tag`) | The target site's own scripts (anti-bot or analytics) can detect them and report off-machine | Automation fingerprint | Tool use | Low. Identity-hygiene concern |
| `popup.html:78`, `:86` (`https://browsermcp.dev/...`) | browsermcp.dev | Standard navigation | Human click only | Info |
| `popup.js:105` `navigator.clipboard.writeText` (static install command) | Local clipboard | none sensitive | Human click | None |
| `background.js:2016-2044` logAction | `chrome.storage.local` (local) | method, time and session label only (params stripped) | Every command | None |

### 3.2 MCP server (`SRV/`)

| Location | Destination | Data | Trigger | Class / severity |
|---|---|---|---|---|
| `~/.claude.json` `npx @agent360/browser-mcp@latest` (`SRV/bin/cli.js:28-29` also registers this way) | `registry.npmjs.org` (via npm) | Package name, npm/node user-agent, IP, timing | Every Claude Code session start | Low data. Medium supply chain: the newest published release auto-executes with full control of the logged-in Chrome |
| `index.js:1060-1080` `execFile('npm', ['view','@agent360/browser-mcp','version'])` | `registry.npmjs.org` | Package name | Only when `BROWSER_MCP_CHECK_NPM=1` (not set: no User/Machine env var; `~/.claude.json` env `{}`) | Info, disabled |
| `index.js:1006-1043` `browser_about` and `1125-1296` `browser_provide_feedback` -> `submit_url = https://github.com/Agent360dk/browser-mcp/issues/new?template=...&title=...&body=...` (`1241-1258`) | github.com (only if opened) | `what_happened` (agent free text), tool, target URL reduced to origin+path (`afkortUrl` `1105-1108`), attempted, environment JSON (server/extension versions, extension ids, code hash, node, platform, ws port) (`1223-1239`) | INSTRUCTIONS make the agent call it "yourself, without asking" and offer the link (`728-736`; `tools.js:493`). Opened by a human click or by the agent navigating. The server never fetches it | Low. User-gated, but it would publish the target origin and path. The local log `~/.browser-mcp/feedback.jsonl` (`index.js:1090-1123`) already holds 1 entry (2026-09-01), which shows the auto-call happens |
| `index.js:633` `conn.ws.send({id, method, params, pid})` | Loopback (L1 peer) | All tool params: URLs, fill values (passwords), code, cookie values, file paths | Every tool call | None if the peer is the real extension. See L1 |
| `index.js:1376-1387` `execSync('ps -o ppid= -p <pid>')`; `vagt.js:26-57` `process.kill(pid,0)` | Local | none | Startup and every 5 s | None |
| `bin/cli.js:73-81`, `83-176` `execFileSync` `claude`/`codex`/`code` and write `~/.cursor/mcp.json` | Local | none | Only `npx @agent360/browser-mcp install` | None |
| `bin/cli.js:259-292` autoUpdateExtension | Local file copy to `~/.browser-mcp/extension` | n/a | Only if that dir exists (it does not here; CWS install) | None |

Dependencies:
- No package in the tree has a `preinstall`/`install`/`postinstall` script. Only `prepare`/`prepublish` exist, and npm does not run those for registry tarballs. There are no native `.node`/`binding.gyp` files. The lockfile has no `hasInstallScript`.
- The static import graph from `bin/cli.js` loads 253 files: MCP SDK `server/index.js`, `shared/protocol.js`, `types.js`, `server/stdio.js`, `experimental/tasks/*`, zod, zod-to-json-schema, ajv, ajv-formats, fast-uri and ws.
- express, hono, cors, eventsource, jose, pkce-challenge and cross-spawn are installed but never loaded.
- The only network-capable library code loaded is `ws/lib/websocket.js` client code (`http.request` `:748`, `net.connect` `:1073`, `tls.connect` `:1090`). It is unused: `index.js:16` imports only `WebSocketServer`.
- The ajv `$id` `https://raw.githubusercontent.com/...` (`ajv/dist/core.js:613`) is an identifier and is never fetched.

## 4. Stack B: ClaudeCodeBrowser (Firefox). Every network-capable path

### 4.1 Extension (`XPI/`)

| Location | Destination | Data | Trigger | Class / severity |
|---|---|---|---|---|
| Firefox `extensions.json`: AMO install, `applyBackgroundUpdates=1` | addons.mozilla.org update service | Add-on id/version (Firefox-generated) | Firefox add-on update timer | Low data. Medium supply chain: `<all_urls>`+`nativeMessaging`+content scripts in every frame (`manifest.json:8-16`, `23-37`) mean an update adds code silently |
| `background.js:40` `browser.runtime.connectNative('claudecodebrowser')` | Native host (stdio) | All command results | Background start (`:872`) and reconnects | None (local) |
| `background.js:832-836` `onMessageExternal` -> `handleCommand(message)` -> `sendResponse` | The calling extension, which can then send it anywhere with its own network access | Arbitrary-code results from any tab (`executeScript` `:497-509` via `tabs.executeScript(code)`); screenshots of every tab (`screenshotAllTabs` `:325-383` with `includeData`); all tab URLs/titles (`getTabs` `:544-585`, `findTabs` `:631-669`); page/form info (`getPageInfo` `:462-478`); tab navigation (`:434-459`) | Any other installed extension calls `runtime.sendMessage('claudecodebrowser@ligandal.com', {...})`. No agent is needed | High. Confused deputy: grants `<all_urls>` code execution and screenshots to extensions that were never granted them |
| `background.js:497-509` executeScript, `434-459` navigate, `671-684` createTab | Anywhere (page context) | Anything on the page | Agent tool via native host | Medium, agent-mediated |
| `background.js:182-268` default target = active tab of current window (`:388`, `:404`, etc.); `getTabs`/`screenshotAllTabs` cover ALL windows/tabs; `content.js:939-953` getValue returns any field's full value; `content.js:1099-1127` `getElementInfo.value` is unmasked (only `getPageInfo` masks password fields, `:425`) | Native host, then the MCP client, then the LLM provider. Also written to disk (section 6) | Unrelated logged-in tabs, typed secrets, screenshots | Agent tool | Medium. Data-minimization, by design |
| `background.js:851-861` context-menu "Take Screenshot for Claude" | Native host | Screenshot | Human right-click | None (local) |
| `content.js` (whole file) | none | none | none | Only `browser.runtime.onMessage` (`:21-26`). It never calls `runtime.sendMessage`/`postMessage`, so web pages have no route into the background. `waitForNetworkIdle` (`:603-671`) wraps `fetch`/XHR in the content-script sandbox only and restores them |
| `popup/popup.js:75`, `:99`, `:122`, `:152` `fetch('http://localhost:8765/health')` | Loopback | none | Popup open / Test button | None |
| `popup/popup.html:72` `https://ligandal.com`; `manifest.json` `homepage_url` | ligandal.com | Navigation | Human click only | Info |

### 4.2 Native host (`native-host/claudecodebrowser_host.py`)

| Location | Destination | Data | Trigger | Class |
|---|---|---|---|---|
| `:54-56` `MCP_SERVER_HOST = $CLAUDE_MCP_HOST or 127.0.0.1`, port `$CLAUDE_MCP_PORT or 8765` | Loopback (env not set: no User/Machine `CLAUDE_*` vars) | All traffic below | n/a | None. An env override would send the token and all browser data elsewhere |
| `:123-147` `POST /browser/command` with `X-API-Key` (`:62-70`) | Loopback | Messages from the extension | Extension message | None |
| `:150-173` socket connect plus `GET /health` | Loopback | none | Health checks every 10 s (`:504-549`) | None |
| `:426-446` `POST /browser/response` | Loopback | Every command result (screenshots, script results, field values) | Each result | None |
| `:471-501` `GET /browser/poll` every 500 ms | Loopback | Receives commands (scripts, typed text) | Continuous | None |
| `:176-227` `lsof`/`fuser` kill; `:230-302` `Popen(server.py)` | Local | n/a | Server down | None (no-op kill on Windows) |
| `:333-385`, `:397-405` save any `data` payload as PNG | `C:\tmp\claudecodebrowser\screenshots` | Screenshots | Every result carrying `data` | None (local; see section 6 for ACL) |

Urllib proxy check: WinINET `ProxyEnable=0` and WinHTTP is direct, so these loopback requests are not routed through a proxy.

### 4.3 MCP server (`mcp-server/`)

| Location | Destination | Data | Trigger | Class |
|---|---|---|---|---|
| `server.py:1036` HTTP and `server.py:1074` WS listeners | See L3/L4 | | | |
| `server.py:896-926` WS dispatch: `asyncio.get_event_loop()` (`:908`) runs in a ThreadingHTTPServer worker thread | Would send `{action, tab_id, data(args incl. typed text, scripts, URLs), request_id}` to the first WS client (`get_active_browser` `:666-670`) | as stated | Every tool call while any WS client is registered | Today: Python 3.12 raises `RuntimeError('There is no current event loop in thread ...')` (`Lib/asyncio/events.py:702`). It is caught at `:924-926`, and the call falls back to HTTP polling (`:951-982`). So no command reaches a rogue WS client |
| `server.py:1041-1065` `websocket_handler`: registers ANY client (`:1044`), logs every message at DEBUG (`:1050`), passes any `requestId` to `handle_response` (`:1052-1054`, `:695-706`) | Loopback in; no egress | A rogue client can inject a forged result only by guessing `str(time.time())` request ids (`:951`), which is infeasible, or flood the log | Any WS client | Low |
| `server.py:929-946` + `headless_backend.py` (Playwright) | Any URL (agent) | Page data | Only if `CLAUDE_BROWSER_HEADLESS=1`/`--headless`, and Playwright is not installed | Info, inert |
| `stdio_wrapper.py:21-23`, `48-115` (`GET /health`, `GET /mcp/tools`, `POST /mcp/call` with token) | Loopback (`CLAUDE_BROWSER_HOST`/`_HTTP_PORT`, not set) | Tool calls/results | Every Claude Code tool call | None |
| `agent/browser_agent.py:27`, `72-92` | `$CLAUDE_BROWSER_URL` or `http://127.0.0.1:8765` | Tool calls incl. token | Manual CLI only (not wired to MCP) | None. No LLM/AI API calls anywhere |
| `scripts/install.sh:127` `pip3 install --user websockets`; `install-guide.md:20` `pip install websockets` | PyPI | Package name | Install time only (Linux script; Windows guide) | Info |

Evidence that the L4 WS listener is live but unused: `~/.claudecodebrowser/logs/mcp_server.log` (405 MB) contains 88 `WebSocket server starting` lines and 0 `Browser registered` lines. websockets 13.1 resolves `serve` to `websockets.legacy.server`, which accepts the 2-arg handler (`legacy/server.py:135` `remove_path_argument`).

## 5. Hardcoded URL inventory (classification)

| URL | Location | Requested by code? |
|---|---|---|
| `https://clients2.google.com/service/update2/crx` | `EXT/manifest.json:26` | Yes, by Chrome (update check) |
| `http://127.0.0.1:{9876-9895}/`, `ws://127.0.0.1:{port}` | `EXT/offscreen.js:111`, `:194` | Yes (loopback) |
| `https://browsermcp.dev/docs/install-claude-code/`, `https://browsermcp.dev/#try` | `EXT/popup.html:78`, `:86` | No. Link, human click |
| `https://chromewebstore.google.com/detail/agent360-browser-mcp/...`, `https://browsermcp.dev/docs/troubleshooting/` | `SRV/index.js:609`, `:611` | No. Error text |
| `https://github.com/Agent360dk/browser-mcp` (+ `/issues/new...`, `WISHLIST.md`, `USE_CASES.md`) | `SRV/index.js:1006`, `1014-1018`, `1257-1258` | No. Returned to the agent as a link |
| `https://dashboard.stripe.com/apikeys`, `https://app.hubspot.com/settings/`, `https://api.slack.com/apps`, `https://admin.shopify.com/store/`, `https://us1.admin.mailchimp.com/account/api/`, `https://app.pipedrive.com/settings/api`, `https://calendly.com/integrations/api_webhooks`, `https://console.cloud.google.com/apis/credentials`, `https://www.linkedin.com/developers/apps` | `SRV/tools.js:527-559` | Yes. Navigated in the user's Chrome when the agent calls `browser_extract_token` |
| `https://github.com/...`, `https://browsermcp.dev`, `https://chromewebstore.google.com/...` | `SRV/bin/cli.js:54`, `104`, `227`, `240`, `241`, `244` | No. Console text |
| `'http://' + d + '/'` | `EXT/background.js:4843`, `4946` | No. `new URL()` parsing only |
| OAuth domains, captcha iframe URL fragments | `EXT/background.js:2121`; `5438-5491` | No. String matching |
| `http://localhost:8765/health` | `XPI/popup/popup.js:75`, `99`, `122`, `152` | Yes (loopback) |
| `https://ligandal.com` | `XPI/popup/popup.html:72`, `XPI/manifest.json` `homepage_url` | No. Link/metadata |
| `http://127.0.0.1:8765` (+ env overrides) | `native-host/...py:54-56`; `stdio_wrapper.py:21-23`; `agent/browser_agent.py:27`; `server.py:90-92` | Yes (loopback) |
| `http://localhost:5000`, `http://localhost:{port}` | `server.py:428`; `browser_agent.py:292` | No. Description text / tab matching |
| `https://addons.mozilla.org/developers/` | `scripts/install.sh:146` | No. echo |
| `https://addons.mozilla.org/firefox/downloads/file/4641779/claudecodebrowser-1.0.0.xpi` | Firefox `extensions.json` `sourceURI` | Yes, by Firefox (install/update) |

Obfuscation scan (base64 blobs of 60+ chars, `\x`/`\u` escape runs, `fromCharCode`, string-built schemes, dynamic imports, `atob`) found nothing in either stack:
- The only hit is `EXT/background.js:1451` `'h' + Math.random()`, an event id.
- The `b64decode` calls in `native-host:373,376` and `server.py:998,1000` decode screenshots for local file writes.

## 6. Non-egress findings that matter for the same threat model (local data at rest)

- `~/.claudecodebrowser/logs/native_host.log.old` (5.5 MB) holds plaintext DEBUG copies of messages (`claudecodebrowser_host.py:42-49`, `118`). Counts: 419 executeScript scripts, 69 `'text':` (typed text), 53 `password` mentions, 62 `data:image` screenshots. `mcp_server.log` is 405 MB with no rotation (`server.py:56-63`); tool args `text`/`script`/`value`/`password` are redacted there (`server.py:839-841`).
- `C:\tmp\claudecodebrowser\screenshots` holds 215 PNGs of browsed pages. ACL: `BUILTIN\Users:(RX)` and `Authenticated Users:(M)`, so any local user can read or replace them.
- `~/.claudecodebrowser/api_token` is readable by `DESKTOP-TO9KUGV\CodexSandboxUsers` (inherited profile ACL).
- Chrome `Profile 4/Local Extension Settings/jdehgalffmffhfhmmhaokfbfnafnmgcl/000005.ldb` (2026-09-04) still contains 308 legacy `"params"` action-log entries from pre-1.29 versions. Per `background.js:2018-2022`, these were the first 200 chars of every tool's params, including fill values. LevelDB has not compacted them away. Content was not printed, and my scratch copy was deleted.

## 7. What I did NOT verify (honest gaps)

- I did not verify at runtime that the Agent360 manifest CSP `connect-src` blocks `browser_fetch` to external hosts from the MV3 service worker (Chrome docs say `extension_pages` CSP covers service workers).
- Whether Chrome's or Firefox's local-network-access protections currently block a public web page from opening `ws://127.0.0.1:8766` was not tested.
- Dependency code (zod, ajv, MCP SDK, ws) was covered by import-graph enumeration plus a network-API grep of all 253 loaded files, not a line-by-line read.

## 8. Files read in full (justification for the negatives)

Stack A:
- `EXT/manifest.json`, `EXT/background.js` (1-5702), `EXT/offscreen.js` (1-354), `EXT/offscreen.html`, `EXT/popup.html`, `EXT/popup.js`
- `SRV/package.json`, `SRV/index.js` (1-1451), `SRV/tools.js` (1-563), `SRV/vagt.js`, `SRV/bin/cli.js` (1-293), `SRV/extension/manifest.json`
- npx `package.json`, `package-lock.json` (parsed)
- Install-hook fields of every dependency `package.json` (parsed)

Stack B:
- `XPI/manifest.json`, `XPI/background.js` (1-874), `XPI/content.js` (1-1192), `XPI/popup/popup.js`, `XPI/popup/popup.html`
- `native-host/claudecodebrowser_host.py` (1-626), `native-host/claudecodebrowser.json`, `native-host/claudecodebrowser_host.bat`
- `mcp-server/server.py` (1-1129), `mcp-server/stdio_wrapper.py` (1-259), `mcp-server/headless_backend.py` (1-310), `mcp-server/mcp_config.json`
- `agent/browser_agent.py` (1-623)
- `scripts/install.sh`, `scripts/uninstall.sh`, `install-guide.md`, `.mcp.json`, `.gitignore`
- Full diff of the repo `extension/background.js` and `extension/content.js` against the XPI
