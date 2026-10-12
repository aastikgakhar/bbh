# bbh design

Status: living document. Written before any code (per `build-harness.md`), updated as layers land. Section 13 lists every place the existing skills and this harness disagree, and who wins.

## 1. Purpose and the one-sentence model

The methodology in `.claude/CLAUDE.md` and the four skills is correct but advisory. bbh moves the parts that keep failing out of prose and into code:

- **State** lives in a SQLite ledger the agent cannot argue with (`server/bbh/ledger.py`).
- **Tools** refuse invalid transitions and tell the agent exactly what is missing (`server/bbh/server.py`).
- **Hooks** inject the next task after compaction, guard scope before network tools run, lint reports before they are written, and refuse to let the session stop while work is open (`hooks/`).

The agent's loop becomes: `next_task()` returns one unit of work, the agent executes it through `run_cases` / `send_case` / `record_case`, and closes it through `close_cell` or `open_finding`. The ledger decides what is done.

## 2. Failure modes and the mechanism that kills each

| Observed failure | Mechanism |
|---|---|
| Sibling classes collapsed (XSS fails, HTMLi never recorded) | One `cells` row per (endpoint, input, class). Every transition function takes exactly one cell id and its SQL touches only `WHERE id = ?`. There is no "close all classes on this input" call. A unit test asserts every other cell row is byte-identical before and after each transition. |
| One test case, then a verdict | `close_cell(..., 'negative')` counts the latest outcome of each distinct case: needs >= 10 `negative` cases over >= 5 technique ids, >= 1 `control_pass`, no outstanding `control_fail`, every cited capture on disk and non-empty, plus class-specific required techniques. `inconclusive` never counts. |
| Hedged dismissals | `observation`, `reason`, `note`, finding text: banned-hedge check, rejected with "State what the response showed, with the capture filename." No free-text states exist; `n_a` and `blocked` take enum reasons plus proof. |
| Early stopping | Stop hook computes open work from the ledger and blocks with the next three tasks. `next_task()` always returns something (depth queue, then a recon refresh). A no-progress guard (3 blocked stops with zero new events) lets a stuck session end and writes `.bbh/stuck.md`. |
| Weak reproducibility | Findings carry a JSON assertion that `verify_finding` replays from fresh session files; `verified` needs two passes >= 60 s apart. `render_report` pulls raw HTTP verbatim from captures and writes `repro/finding-N.sh` (self-checking curl) and `repro/finding-N.json`. |
| Drifting focus | `next_task()` picks and claims the work with a fixed priority order. Claims expire after 30 minutes. Hooks re-inject the next task after compaction and after new traffic. |

## 3. Packaging

```
bbh/                              # this repo; also a single-plugin local marketplace
  .claude-plugin/plugin.json
  .claude-plugin/marketplace.json # lets `/plugin marketplace add <path>` + `/plugin install bbh@bbh-local` work
  .mcp.json                       # registers the stdio server "bbh"
  requirements.txt                # mcp<2 (FastMCP), httpx, websocket-client, cryptography; flask + pytest for lab/tests
  server/bbh/...                  # Python package
  server/tests/...                # pytest
  hooks/hooks.json + *.py         # stdlib-only hook scripts
  agents/{class-tester,verifier,triager}.md
  skills/{recon,coverage-matrix,report-writer,triage-gate}/
  lab/                            # Flask lab with planted bugs + ground_truth.json
  docs/{inventory,design,usage,lab-results}.md
```

FastMCP: the `mcp` package 2.x renamed `FastMCP` to `MCPServer` and changed its API, so `requirements.txt` pins `mcp>=1.26,<2`, where `mcp.server.fastmcp.FastMCP` is the stable API. No `uv` on the researcher's machine, so the server runs as `python -m bbh.server` with `PYTHONPATH=${CLAUDE_PLUGIN_ROOT}/server`.

Hook scripts import only stdlib modules of the package (`paths`, `config`, `scope`, `hedge`, `ledger`, `tasks`, `lint`, `render`), never `httpx` or `mcp`, so they start in well under the 2 s budget.

## 4. Engagement folder at runtime

```
<engagement>/
  prompt.md                          # per-target brief (never written by bbh)
  .bbh/ledger.db                     # single source of truth (WAL mode)
  .bbh/STOP                          # kill switch: present = every send refused, stop allowed
  .bbh/traffic/<request-id>.http     # raw requests/responses ingested from Burp/browser/sender
  .bbh/stuck.md  .bbh/handoff.md     # written by the stop gate / PreCompact
  .bbh/hook.log                      # every hook warning (hooks fail open, loudly)
  .bbh/guidance.json                 # last ingest worker result, consumed by PostToolUse hook
  captures/<cell-id>/<case-no>-<technique>.http   # every case exchange, verbatim
  captures/session-<label>.txt       # principal session material (researcher-owned)
  captures/verify/finding-<id>/run-<n>/...        # verification replays
  repro/finding-<n>.sh  repro/finding-<n>.json
  report-<n>.md  poc-<n>.html
  state.csv  feature-matrix.md  progress.log  findings-summary.md   # GENERATED views
```

Engagement root discovery (server and hooks): `BBH_ENGAGEMENT_DIR` env, else `CLAUDE_PROJECT_DIR`, else the process cwd (hooks: the `cwd` field of the hook input); then walk up to the first directory holding `prompt.md` or `.bbh/`.

## 5. Layer 1: the ledger

SQLite, `journal_mode=WAL`, `busy_timeout=5000`, `foreign_keys=ON`. Every multi-statement write runs in `BEGIN IMMEDIATE`. All state transitions go through `ledger.py`; `server.py` never writes SQL.

### 5.1 Tables

| Table | Key columns |
|---|---|
| `meta` | `key`, `value` (schema version) |
| `engagement` | singleton: `target`, `scope_json`, `oos_json`, `oos_unparsed_json`, `programme`, `marker_header`, `rate_limit_rps`, `oob_json`, `burp_proxy`, `burp_mcp_url`, `max_testers`, `support_hosts_json`, `accounts_json`, `login_json`, `prompt_hash`, `configured` |
| `principals` | `id`, `label` UNIQUE (`A`, `B`, `unauth`, `viewer-token`, ...), `kind` (`account`/`unauth`/`role`/`token`/`share_link`/`other`), `account`, `browser`, `session_file`, `identifiers_json` (ids/emails that belong to this principal; feeds the third-party guard), `notes` |
| `requests` | `id`, `source` (`burp`/`sender`/`browser`/`import`), `burp_offset`, `principal_id`, `method`, `url`, `host`, `status`, `content_type`, `ua_family`, `raw_path`, `truncated`, `content_hash` UNIQUE, `ts` |
| `endpoints` | `id`, `host`, `method`, `path_template`, `family`, `feature`, `auth_required`, `content_type`, `first_seen_request_id`, `source` (`traffic`/`js`/`spec`/`guess`/`model`), `third_party_lock`; UNIQUE(`host`,`method`,`path_template`) |
| `inputs` | `id`, `endpoint_id`, `name`, `location` (`query`/`path`/`form`/`json`/`header`/`cookie`/`multipart`/`filename`), `json_path`, `sample_value`, `value_type`, `reflection_contexts` (JSON list from `html_text`,`html_attr`,`js_string`,`js_block`,`url`,`css`,`json`,`response_header`,`none`,`unknown`); UNIQUE(`endpoint_id`,`location`,`name`) |
| `cells` | `id`, `endpoint_id`, `input_id` (NULL = endpoint-level), `vuln_class`, `state`, `claimed_by`, `claimed_at`, `reason`, `reason_request_id`, `unblock`, `note`, `context_json`, `priority`, `source` (`rule`/`depth`/`model`/`researcher`), `salt` (per-cell random seed so regenerated cases are identical), `verifier_json`; UNIQUE index on (`endpoint_id`, `ifnull(input_id,0)`, `vuln_class`) |
| `planned_cases` | generated plan per cell: `cell_id`, `case_no`, `technique`, `is_control`, `payload`, `mutation_json`, `positive_json`, `negative`, `route`, `principal`, `repeat` |
| `test_cases` | executions: `id`, `cell_id`, `case_no`, `attempt`, `technique`, `payload`, `principal_id`, `request_capture`, `response_capture`, `observation`, `outcome` (`positive`/`negative`/`inconclusive`/`control_pass`/`control_fail`), `route`, `elapsed_ms`, `status`, `ts` |
| `findings` | `id`, `cell_id` UNIQUE, `rung`, `rung_index`, `title`, `severity`, `summary`, `root_cause`, `impact_json`, `escalation_blocked_by_json`, `status` (`draft`/`verified`/`gated`/`killed`), `report_path`, `report_no` |
| `finding_rungs` | `finding_id`, `rung`, `rung_index`, `assertion_json`, `status` (`draft`/`verified`/`failed`) |
| `verifications` | `finding_id`, `rung`, `passed`, `detail`, `started_at`, `finished_at` |
| `triage` | `finding_id`, `round`, `verdict` (`ACCEPT`/`REJECT`), `objection`, `required_evidence` |
| `depth_queue` | `id`, `kind` (1..8, the Layer 6 order), `title`, `detail_json`, `source` (`rule`/`model`/`researcher`), `test_plan`, `state` (`open`/`in_progress`/`done`/`blocked`), `claimed_at`, `result`, `dedupe_key` UNIQUE |
| `canaries` | `token` UNIQUE, `input_id`, `request_id`, `principal_id`, `kind` (`reflection`/`store`), `ts` |
| `sightings` | `token`, `request_id`, `endpoint_id`, `principal_id`, `context`; drives second-order cells |
| `oob` / `oob_hits` | per-cell OOB tokens and received interactions |
| `rate_state` | `host`, `next_allowed`, `penalty` (cross-process limiter) |
| `events` | append-only: `id`, `ts`, `kind`, `entity`, `entity_id`, `from_state`, `to_state`, `detail`. Triggers abort any UPDATE or DELETE. |
| `kv` | hook throttles, stop-gate counters, ingest cursor |

### 5.2 Cell state machine

States: `open`, `in_progress`, `negative`, `candidate`, `confirmed`, `n_a`, `blocked`. Nothing else is storable (CHECK constraint).

| From | To | Through | Requires |
|---|---|---|---|
| open | in_progress | `next_task` claim | atomic claim in one transaction |
| in_progress | open | `release_cell`, claim expiry (30 min, applied lazily on every read) | note for release |
| open, in_progress, negative, n_a | candidate | automatic when any case of the cell records `positive` | the positive case row |
| open, in_progress | negative | `close_cell` | evidence threshold (5.3) |
| candidate | negative | `close_cell` | evidence threshold **and** verifier sign-off recorded on the cell |
| candidate | confirmed | `verify_finding` | finding rung verified twice >= 60 s apart |
| open, in_progress | n_a | `close_cell` | reason from the class's n_a enum, `reason_request_id` that exists in `requests` |
| open, in_progress | blocked | `close_cell` | reason from the blocked enum, non-empty `unblock` |
| candidate | blocked | `close_cell` | as above **plus** verifier sign-off (a candidate never dies silently) |
| negative, n_a, blocked | open | `reopen_cell` | reason (depth re-test, unblocked, new evidence) |

`confirmed` is terminal for the cell; its finding keeps climbing.

### 5.3 Invariants enforced in code

1. **Ten-case minimum.** Counted per distinct `case_no`, using that case's latest attempt: >= 10 with outcome `negative` (control cases excluded), >= 5 distinct technique ids among them, >= 1 `control_pass`, zero controls whose latest attempt is `control_fail`, every `request_capture`/`response_capture` of the counted rows exists and is non-empty. Class minimums from `classes.py` can raise the case count and add required technique prefixes (SQLi on a sort parameter must include `sqli.orderby.*`; time-based SQLi requires the timing-baseline control).
2. **Positive control.** A `control_fail` writes an event, sets the cell note to the tooling problem, and moves an `in_progress` cell back to `open`. `close_cell(negative)` is refused while any control's latest attempt is `control_fail`.
3. **Sibling independence.** Each transition touches one row. Tested by snapshotting every other cell before and after every transition type.
4. **Ladders never downgrade.** `findings.rung_index` only increases (code check plus a trigger that aborts any decrease). A failed climb is appended to `escalation_blocked_by_json` and the confirmed rung is kept.
5. **Candidates cannot silently die.** `candidate -> negative|blocked` requires `verifier_json` with verdict `refuted` (or `blocked`) recorded by `verifier_signoff`. When hook input identifies the calling subagent type, the PreToolUse hook additionally refuses `verifier_signoff` from anything but the `verifier` agent.
6. **Scope.** `add_endpoint`, ingest, and the sender call `scope.check(url)`; out of scope raises `ScopeError` (ingest skips and counts instead of raising, so foreign traffic in Burp is ignored, never stored).
7. **No hedge text.** Every observation, reason, note, unblock text and finding text field passes `hedge.check()` against: maybe, might, probably, likely, unlikely, possibly, potential(ly), seems, appears to, could, may allow, theoretically, should be, perhaps, presumably. Rejection text: "State what the response showed, with the capture filename."

### 5.4 n_a and blocked reasons

`n_a`: `no_datastore_reach`, `no_url_input`, `not_state_changing`, `no_render_path`, `no_reflection`, `no_header_reflection`, `no_object_identifier`, `not_list_endpoint`, `no_file_input`, `no_xml_parsing`, `not_graphql`, `no_json_body`, `no_limit_or_counter`, `no_cache_layer`, `no_cors_headers`, `no_message_listener`, `static_asset`, `programme_excluded` (forced logout / forced login, which CLAUDE.md lists as out of scope). Each class accepts only the subset that can logically apply to it.

`blocked`: `no_second_account`, `no_oob_listener`, `paid_tier`, `geo_block`, `waf_block`, `feature_flag`, `session_unavailable`, `requires_browser`, `requires_researcher`, `kill_switch`, `other`. Always with `unblock` text saying what would unblock it.

## 6. Layer 2: ingest and planner

### 6.1 Sources

1. **Burp proxy history** via Burp's own MCP endpoint (`http://127.0.0.1:9876`, SSE), using the `mcp` client library directly from Python. Measured on this machine: init about 1.2 s, a `get_proxy_http_history` call about 0.08 s at low offsets.
   - Records come as one text blob of `{"request": ..., "response": ..., "notes": ...}` objects separated by blank lines. Offset 0 is the oldest record. Past the end the tool returns `Reached end of items`.
   - **Every record is cut at 5,000 characters** with the suffix `... (truncated)`, which breaks that record's JSON. bbh therefore parses with literal markers rather than `json.loads`, keeps the request when the response is cut, and marks the row `truncated=1`. Full bodies are never taken from Burp; when a body matters, the sender re-fetches it and captures it in full.
   - The cursor (next offset plus a hash of the last record) lives in `kv`; a hash mismatch means the history was cleared, and ingest restarts from 0 with content-hash dedupe.
2. **The sender's own exchanges**, recorded directly with full bodies (source `sender`).
3. **Browser MCP network logs** passed to `ingest(source='browser', payload=...)` when Burp is down. The source used is recorded on every request row.
4. **Recon additions**: `add_endpoint` (source `js`/`spec`/`guess`/`model`) and the bounded `crawl` tool (same-origin, in-scope, GET only, logout/delete-shaped links never followed).

Foreign traffic (out of scope) is counted and dropped, never stored.

### 6.2 Normalisation

Path segments that are numeric, UUIDs, hex >= 16, base64-looking >= 16, or long mixed slugs become `{id}`; dates become `{date}`. Family = host plus the template with trailing parameter segments removed, capped at three segments. Feature defaults to the family's first meaningful segment and can be renamed with `set_feature`.

Inputs extracted per request: query, path parameters (one per `{id}` segment), form fields, JSON leaves (dot path), multipart fields and filenames, cookies (names only for non-session cookies), and headers that the app itself sets beyond the browser defaults.

### 6.3 Reflection probe

`probe_reflection(request_id)` resends the request once per input with a fresh random canary (lowercase letter plus 9 random alphanumerics, **no fixed prefix**, because a stable marker would link the researcher's testing across targets). It classifies every occurrence with a small HTML tokenizer: header, `<script>` block (string or code), attribute (and URL-valued attribute), `<style>`, text node, JSON body. Results go to `inputs.reflection_contexts`; the canary is registered in `canaries`. One request per input at the engagement rate limit.

Second-order detection: every response the harness sees is scanned for registered canaries. A canary seen on a different endpoint than the one that stored it, or by a different principal, writes a `sightings` row and opens `htmli_stored`, `xss_stored`, `ssti` on the storing input with the render endpoint and viewing principal in the cell context.

### 6.4 Rules (`planner.plan(endpoint_id)`)

Idempotent: inserts missing cells, never edits existing ones.

| Signal | Cells |
|---|---|
| Reflection in `html_text` / `html_attr` / `url` | `htmli`, `xss_reflected`, `ssti`, `csti` |
| Canary sighting on another endpoint or principal | `htmli_stored`, `xss_stored`, `ssti` |
| Reflection in `js_string` / `js_block` | `xss_reflected` (context `js`) |
| Reflection in `response_header` | `crlf`, `header_injection` |
| URL- or host-shaped value, or name in (`url`, `next`, `redirect`, `redirect_uri`, `return_to`, `returnUrl`, `continue`, `callback`, `dest`, `goto`, `u`, `r`, ...) | `open_redirect`, `ssrf` |
| Datastore-reaching input (ids, search, filter, sort, order, column, limit, JSON body leaves) | `sqli`, `nosqli` |
| Sort / order / column name | `sqli` with `orderby` required |
| Object identifier (numeric, UUID, slug, base64) | `idor_read`, `idor_write` (when state-changing), and endpoint `unauth_replay` |
| List / search / export / sync / batch / feed endpoint | `mass_dump` |
| State-changing method, or GET whose path verb mutates | `csrf`, `idor_write`, `mass_assignment`, `method_swap` |
| JSON body | `mass_assignment`, `nosqli`, `content_type_swap` |
| Multipart file field | `upload` (input-level on the filename) |
| Limit / counter / one-time token / uniqueness name | `race` |
| Filename or path-shaped value | `path_traversal` |
| XML body or XML content type | `xxe` |
| GraphQL endpoint | `graphql_introspection`, `graphql_batching`, `mass_dump` |
| Any read endpoint | `info_leak` |
| Any endpoint | `unauth_replay`; once per family: `cache_deception`, `cache_poisoning`, `cors` |

Exclusions: login endpoints get `csrf` closed `n_a: programme_excluded` (forced login is chain material only, per CLAUDE.md); logout endpoints get `csrf` and `method_swap` closed the same way (forced logout). The cell still exists, so the matrix shows the decision and its proof request.

The model can propose hypotheses only through `add_depth_item(kind=8, test_plan=...)`; they never replace rule-opened cells.

## 7. Layer 3: case generators

`cases/` has one module per family; each class exposes `generate(cell, ctx) -> list[TestCase]`. Contract (tested for every class and every context it supports): case 0 is the control, then >= 10 non-control cases over >= 5 technique ids, every case has a machine-checkable `positive` condition or is explicitly `route='browser'`/`'oob'`/`'counter_read'`, and every payload passes the safety screen (no `DROP`, `DELETE`, `UPDATE`, `INSERT`, `TRUNCATE`, `ALTER`, `EXEC`, `xp_`, `LOAD_FILE`, `INTO OUTFILE`, shell metacharacter command strings, file-scheme URLs, system file paths, or entity expansions that recurse).

A `TestCase` holds `case_no`, `technique` (dotted id, e.g. `sqli.time.pg_sleep`), `payload` (human-readable), `mutation` (a list of ops applied to the base request), `positive` (condition), `negative` (text), `is_control`, `route`, `principal`, `repeat`.

Mutation ops: `set_input`, `append_input`, `move_input` (query/body/json/header), `remove_input`, `duplicate_input` (parameter pollution), `json_set` (any JSON value, used for type juggling), `add_field` (mass assignment), `set_header`, `remove_header`, `set_method`, `set_content_type` (re-encodes the body as `text/plain`, form, multipart or JSON), `replace_body`, `as_principal`.

Conditions (`evaluate.py`): `body_contains`, `body_not_contains`, `body_regex`, `header_contains`, `header_present`, `status_in`, `location_host`, `elapsed_over_baseline`, `len_diff` (against another case), `oob_hit`, `counter_read`, `browser_marker`, `all`/`any`/`not`. A condition the harness cannot evaluate (`manual`) makes the case return `needs_judgement`, and the agent must `record_case` it with a factual observation.

Ladders (rungs in order; the finding's rung index only rises):

| Class | Rungs (minimum reportable rung in bold) |
|---|---|
| htmli, htmli_stored | canary_reflects, raw_angle_brackets, **tag_renders**, dangling_markup |
| xss_reflected, xss_stored | canary_reflects, raw_angle_brackets, tag_renders, **script_executes** |
| xss_dom | source_reaches_sink, **script_executes** |
| ssti | syntax_probe, **arithmetic_evaluates**, engine_identified |
| csti | syntax_probe, **expression_evaluates**, framework_identified |
| sqli | error_differential, **boolean_pair**, time_based, dbms_identified |
| nosqli | **operator_injection**, type_juggling, boolean_differential |
| open_redirect | **redirect_to_attacker**, token_carried |
| ssrf | **oob_callback**, oob_http_request, response_reflected |
| crlf | encoded_crlf_reflects, **header_injected**, response_split |
| header_injection | reflects_in_header, **header_semantics_altered** |
| idor_read / idor_write / unauth_replay | **cross_principal_read** / **cross_principal_write_counter_read** / **unauth_read**, unauth_write_counter_read |
| csrf | **cross_origin_state_change** (poc.html + counter-read) |
| others | listed in `classes.py` |

Safety restrictions that go beyond the skills (Section 13): SSTI stops at engine identification plus a harmless evaluation; SQLi extracts nothing beyond the DBMS version string; SSRF confirms by OOB only and never requests metadata or internal addresses; XXE uses internal-entity reflection and OOB fetch only, no file entities, no recursive expansion; path traversal proves itself with normalisation differentials and the application's own public files, never system files; cache poisoning always carries a unique cache buster so no shared cache entry is ever poisoned; race bursts are capped at 30.

## 8. Layer 4: the sender

`sender.send(spec, principal, cell_id=None, case_no=None, technique=None)` is the only path to the network.

1. Kill switch: `.bbh/STOP` present -> `KillSwitchError`, checked before every send and before every connection of a burst.
2. Scope: `scope.check(url)`; out of scope -> `ScopeError`.
3. Third-party lock: endpoint locked by the Rule 0 guard -> refuse paging requests and any `mass_dump` case.
4. Rate limit: cross-process reservation in `rate_state` (one `BEGIN IMMEDIATE` per send): `start = max(now, next_allowed)`, `next_allowed = start + interval * penalty`. Default 2 req/s per host. A race burst of N (N <= 30) reserves N slots at once, so the long-run average never exceeds the limit. 429, block pages and resets double the penalty (cap 32x, `Retry-After` honoured) and successes decay it.
5. Session material: `captures/session-<label>.txt` holds `Header: value` lines (`Cookie`, `Authorization`, CSRF headers). Re-read on every send (verification needs fresh material). `unauth` strips Cookie, Authorization and any header listed in any session file.
6. Headers: start from the captured request being replayed, so the request carries only what the application sent. Add the marker header only when `prompt.md` sets one. No other additions; httpx's own `User-Agent` is never sent.
7. Proxy: Burp at the `prompt.md` address (default `127.0.0.1:8080`) so everything lands in one history; `none` sends direct. The route is recorded on every exchange.
8. Capture: `captures/<cell-id>/<case-no>-<technique>.http`, request and response verbatim (status line, headers, full body; content-encoding decoded and noted). Recon sends go to `captures/_recon/`.
9. Tooling-block detection marks the exchange `inconclusive` with a reason: connection error or reset, `status 0`, HTTP/2 protocol errors, a 403/429/503 whose body matches a known block-page signature, or a 403 where the browser-captured baseline for the same endpoint was 2xx. Inconclusive never counts toward a negative, and a depth item (kind 6) is queued to rerun the case through the browser route. There is deliberately no evasion logic: a block is recorded, not worked around.
10. Rule 0 guard: every response is scanned for e-mail addresses and owner/user identifiers outside the known test-principal identifiers. On a hit the stored capture body is replaced by a redaction summary (record count and one proving field, masked), the endpoint gets `third_party_lock`, and the tool result tells the agent to stop and report the count.

## 9. Layer 5: findings, assertions, reproducibility

Assertion JSON (`version: 1`): `steps` (each: `id`, `principal`, `request` as `{capture: path}` or `{method,url,headers,body}`, optional `repeat`, optional `browser: {open, wait_ms}`), and `checks` (the same condition vocabulary as cases, addressed to a step or a pair of steps, with `all_repeats`). Examples live in `docs/usage.md`.

`verify_finding(id)` replays the highest draft rung's assertion from fresh session files (no cached client, new captures under `captures/verify/`), records pass/fail, and promotes: two passes >= 60 s apart -> rung `verified`, finding `verified` (or rung raised), cell `confirmed`. A failed higher rung is recorded in `escalation_blocked_by` and never lowers the finding.

`render_report(id)` writes `report-N.md` from `report-writer/references/template.md`: unwrapped paragraphs, literal `Step N:` labels under `**As the attacker**` / `**As the victim**`, raw HTTP pulled verbatim from the captures for attacker steps only, session headers replaced by `<replace with your session cookie>`, no long dashes, test e-mails replaced by Account A / Account B. It also writes `repro/finding-N.sh` (bash + curl, reads session files, exits 0 only when the assertion holds) and `repro/finding-N.json`.

Report lint (`lint.py`, run by the PreToolUse hook on any Write/Edit of `report-*.md`, and by `render_report`): banned words outside code fences, long dashes, hard-wrapped prose, numbered-list steps, raw HTTP under the victim header, every cited capture exists, every fenced HTTP block appears in a capture file, every attacker-step capture belongs to principal A (or unauth), `User-Agent` family matches the browser named in the step, cross-site classes have a `poc*.html`, no test e-mail, no bold except the two role headers.

Triage: `record_triage(id, verdict, objection, required_evidence)`. ACCEPT -> `gated`. Three REJECT rounds -> `killed`, objection kept.

## 10. Layer 6: depth queue

When base cells run out, `tasks.refill_depth()` adds items in this order (each deduplicated by key):

1. Endpoints with source `js`/`spec`/`guess` and no traffic: call them as each principal.
2. Every endpoint again as every other principal (roles, tokens, share links, unauth).
3. Alternate content types and API versions (`/v1` <-> `/v2`, hosts found in JS).
4. Second-order sweeps: every store endpoint (state-changing with text inputs) paired with every render or query endpoint of the same object type, with canaries.
5. Chain attempts from candidates, low confirmed findings and `bug-name-chain.md` entries, preconditions listed.
6. Re-tests of negative cells whose evidence holds an inconclusive case or a tooling note, by the other route.
7. Fresh recon: new hosts, features and bundles since session start.
8. Model hypotheses (`add_depth_item`, test plan required).

`next_task()` then returns a recon-refresh task forever, but the stop gate counts only real queue items, so a session whose base and depth work is exhausted may stop.

## 11. Layer 7: MCP tools

`status`, `next_task`, `ingest`, `plan`, `probe_reflection`, `send_case`, `run_cases`, `record_case`, `close_cell`, `release_cell`, `reopen_cell`, `verifier_signoff`, `open_finding`, `escalation_blocked`, `verify_finding`, `render_report`, `record_triage`, `add_principal`, `add_endpoint`, `set_feature`, `add_depth_item`, `complete_depth_item`, `oob_url`, `oob_check`, `fetch` (scoped captured request for recon), `crawl` (bounded scoped recon crawl), `show` (one cell or finding with its cases and captures), `render_views`.

`next_task` priority: (1) candidates, (2) findings needing verification, a report, or triage, (3) open cells on high-value surfaces (cross-principal classes, shared/public pages, state-changing endpoints), (4) the remaining open cells, (5) depth items, (6) recon refresh. The payload is the cell, endpoint, input, context, generated cases, the recipe excerpt from `classes.md`, and the exact completion criteria.

## 12. Layers 8 and 9: hooks and agents

Every format below was verified empirically on Claude Code 2.1.287 (`inventory.md` Section 5). bbh tool names are `mcp__plugin_bbh_bbh__<tool>`; plugin agents are `bbh:class-tester`, `bbh:verifier`, `bbh:triager`.

Hook mechanics common to all scripts: `hooks/hooks.json` runs `python "${CLAUDE_PLUGIN_ROOT}/hooks/<script>.py"` (Git Bash on this machine). Each script reads the JSON from stdin, locates the engagement from `cwd`, opens the ledger with a 1 s busy timeout, and has a hard internal deadline of 1.8 s. Any exception or timeout is appended to `.bbh/hook.log` and the hook exits 0 with no output (fail open). The two exceptions are the scope guard and the kill switch: when they cannot load the engagement, they still deny out-of-scope-looking navigation if `.bbh/STOP` exists, because failing open there would defeat the kill switch. A folder without `prompt.md` and `.bbh/` is not an engagement, and every hook is a no-op there, so the plugin is harmless in unrelated projects.

| Hook | Event / matcher | Behaviour |
|---|---|---|
| `session_start.py` | SessionStart, all sources (`startup`, `resume`, `compact`, `clear`) | Syncs `prompt.md` into the ledger, then injects at most 40 lines via `additionalContext`: engagement, scope, unparsed out-of-scope notes, coverage numbers, open candidates, and the next task (peeked, not claimed). After `compact` it also points at `.bbh/handoff.md`. |
| `pre_tool_scope.py` | PreToolUse, `^(mcp__browser-mcp__\|mcp__claudecodebrowser__\|mcp__claude-in-chrome__\|mcp__burp__\|mcp__plugin_bbh_bbh__\|mcp__claude_ai_\|Bash\|PowerShell\|WebFetch\|Write\|Edit)` | (1) `.bbh/STOP` present: deny every network-capable tool and every bbh send tool. (2) Scope: navigation and fetch URLs, Burp `targetHostname`/`content` Host, URLs in curl/wget/httpie/Invoke-WebRequest commands, WebFetch URLs. In scope: allow. Explicit out-of-scope or a target-adjacent host (same registrable domain as an in-scope pattern): deny. Support hosts (mail, IdP, ngrok, loopback): allow navigation and WebFetch, deny Burp sends. Anything else: deny with the support-host hint. Non-http schemes (`file:`, `data:`, `javascript:`, `chrome:`) are always denied for navigation. (3) Real-browser safety: deny every real-browser tool to subagents (`agent_type` present); deny browser-mcp `provide_feedback`, `about`, `extract_token`; deny Firefox `reload_all` and `screenshot_all_tabs`; deny Firefox tab-scoped tools without an explicit `tab_id`; deny `close_tab`/`focus_tab` on tab ids the session did not create (owned-tab ledger filled by the PostToolUse hook); deny the 19 Firefox tools the installed extension does not implement, with that explanation. (4) `verifier_signoff` from any caller other than the `bbh:verifier` agent: deny. (5) claude.ai connectors from subagents: deny (captures never leave the machine). (6) Write/Edit of `report-*.md`: run the report lint on the post-edit content and deny with the exact failing lines. |
| `post_tool_ingest.py` | PostToolUse, `^(mcp__browser-mcp__\|mcp__claudecodebrowser__\|mcp__claude-in-chrome__\|mcp__burp__\|mcp__plugin_bbh_bbh__)` | (1) Records tab ids created by browser tools into the owned-tab ledger. (2) Burp send/history tool responses are ingested inline (they are already in `tool_response`). (3) At most once per 30 s, starts a detached ingest worker (`python -m bbh.worker ingest`) that syncs Burp, plans new endpoints and writes `.bbh/guidance.json`; the hook itself never waits on the network. (4) If the previous worker produced guidance the agent has not seen, injects at most 15 lines: new endpoints and inputs, cells opened grouped by class, top 3 next tasks. Silent when nothing is new. (5) After `close_cell` with `negative`, injects one red-team line for that class from `evidence-rules.md`. |
| `stop_gate.py` | Stop | Computes open work from the ledger. Allows the stop when `.bbh/STOP` exists or nothing is open. Otherwise blocks with the next three tasks, unless the no-progress guard trips: the gate has blocked three times in a row with no new progress event between attempts, in which case it allows the stop and writes `.bbh/stuck.md`. `stop_hook_active` is an input to that guard, not an automatic pass: when it is true and progress was made, the gate blocks again; when it is true and nothing moved, the no-progress counter rises. Gate events are recorded with `progress = 0`, so the gate never counts its own activity as progress. |
| `pre_compact.py` | PreCompact | `render_views()` and `.bbh/handoff.md` (state counts, claimed work, the next three tasks, open candidates, recent events). |
| `subagent_stop.py` | SubagentStop, `^bbh:class-tester$` | If the subagent still holds an `in_progress` claim with no verdict, blocks once with the completion criteria for that cell. On the second attempt it releases the claim with a note, so a dead subagent cannot strand a cell. |

Agents (`agents/*.md`, tools listed explicitly because wildcard support in `tools:` was not verified):

- `class-tester`: bbh tools (`next_task`, `show`, `run_cases`, `send_case`, `record_case`, `fetch`, `probe_reflection`, `oob_url`, `oob_check`, `close_cell`, `release_cell`, `open_finding`, `escalation_blocked`, `add_depth_item`, `complete_depth_item`, `status`), Burp read tools, `Read`, `Grep`, `Glob`. No Bash, no real-browser tools; the hook also denies those to any subagent. The browser rule from CLAUDE.md is in the file verbatim.
- `verifier`: `show`, `verify_finding`, `verifier_signoff`, `send_case`, `oob_check`, `fetch`, Burp read tools, `Read`, `Grep`, `Glob`. Prompted to refute. The only agent the hook lets call `verifier_signoff`.
- `triager`: `Read`, `Glob`, `Grep` only. Body is `triage-gate/references/agent-brief.md` verbatim, plus the browser rule.

Concurrency: `prompt.md` `Max concurrent testers` (default 3, hard cap 25). All testers share one sender and one cross-process rate limiter, so more testers never means more load on the target.

## 13. Contradictions between the skills and this harness

(The skills win on testing methodology and report format; `build-harness.md` wins on enforcement mechanics.)

1. coverage-matrix has four cell states (`tested`, `FINDING-N`, `n-a`, `blocked`); the ledger has seven. `render.py` maps `negative` -> `tested`, `confirmed` -> `FINDING-N`, `n_a` -> `n-a`, `blocked` -> `blocked: <reason>`, and shows `open`/`in_progress`/`candidate` as unfinished.
2. coverage-matrix fills an IDOR cell with one cross-principal read; the ledger needs ten cases and a control for any negative. Enforcement wins.
3. coverage-matrix puts the `n-a` reason in free text; the ledger needs an enum reason plus a proving request id. Enforcement wins; free text goes in `note`.
4. Banned words: the ledger checks the build-spec hedge list on ledger fields; the report lint uses the report-writer list (`if`, `potentially`, `could be chained`, `may allow`, `theoretically`, `phishing`, `should`, `seems`, `appears to`, plus `potential`, `could`, `may` from the writer's gate). Report format belongs to the skill.
5. report-writer asks for two clean reproductions; the harness adds the 60-second gap and does it by replaying the assertion.
6. recon seeds `state.csv` by hand with `pending` rows; `state.csv` is now generated, and `pending` means an endpoint with unfinished cells.
7. CLAUDE.md caps agents at 25 and says to prefer far fewer; the harness defaults to 3 class-testers, reads `Max concurrent testers` from `prompt.md`, and hard-caps at 25.
8. classes.md suggests cloud-metadata and internal-address SSRF probes and file-based traversal; the generators confirm SSRF only through OOB and traversal only through normalisation differentials and app-owned files (Rule 0 and the no-file-read rule of the build spec). The researcher can still do more by hand.
9. CLAUDE.md forbids "automated scanners against production"; bbh is not a scanner: every case is chosen by the planner for one input, sent one at a time at the engagement rate limit, scope-checked, and driven by the agent.
10. coverage-matrix verifies CSRF by opening `poc.html` in the second principal's real browser; the harness generates `poc-N.html` and either opens it in a private headless browser with Account B's session or records the researcher's manual confirmation through `record_case`.
11. `build-harness.md` asks PreToolUse to block every out-of-scope host on navigation, Burp, curl and WebFetch; the researcher's workflow needs mailboxes and identity providers (OTP, magic links, Google sign-in). bbh adds a `Support hosts` field to `prompt.md`: navigation and WebFetch to those hosts are allowed, sending test traffic to them is not.

## 14. Optional: browser extension or dashboard

Decision: **neither a new Chrome extension nor a live web dashboard; ship read-only generated views instead.**

The build spec offers a minimal `chrome.debugger` capture extension only "if neither browser MCP can return full response bodies and Burp is unreliable". The inventory (`docs/inventory.md`) shows Burp is present and reachable over its MCP endpoint, and its only real limitation is the 5,000-character truncation over MCP, which bbh already works around by re-fetching full bodies through its own sender (every sent exchange is captured verbatim). So the precondition for building a capture extension is not met, and adding another extension would sit next to the two the egress audit already flagged (the Agent360 loopback bridge accepts any local process; a new listener is more attack surface, not less). No extension.

The dashboard alternative is also declined in its live-server form, for the same reason: bbh deliberately does not open a long-lived HTTP listener. The inventory found three unauthenticated or weakly-authenticated local listeners already (Agent360 on 9876-9895, ClaudeCodeBrowser on 8765/8766), and Rule 0's spirit is to reduce the researcher's exposure, not add to it. Instead, bbh renders the same information as **static files the researcher opens in any editor**: `feature-matrix.md` (the coverage grid by feature and class, with per-cell state and finding refs), `state.csv` (one row per endpoint with its tested classes and status), `findings-summary.md` (findings by status, blocked cells with what would unblock them, chain candidates, killed reports), and `progress.log`. These regenerate on demand (`render_views`) and before every compaction, are diffable, need no port, and carry no new egress or trust risk. `status()` gives the same at-a-glance view inside the session. If a live dashboard is ever wanted, it would bind 127.0.0.1 on 7733 (reserved, outside every range the inventory flagged) and read the ledger read-only; it is intentionally not built in this version.
