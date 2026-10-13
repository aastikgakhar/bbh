# bbh

bbh is a Claude Code plugin that keeps a bug-bounty engagement honest. The methodology lives in prose (a `CLAUDE.md` and four skills), but prose is advisory and an agent forgets it: it goes deep on one bug class, calls a 200 a finding, closes a class after one test, or stops while most of the attack surface is untested. bbh moves the parts that keep failing into code. State lives in a SQLite ledger the agent cannot argue with, every request goes through one scoped and rate-limited sender, and hooks inject the next task, guard scope, lint reports, and refuse to let the session stop while work is open.

It is built for a specific, legal use: **authorized** black-box / grey-box testing of a target you hold a bug-bounty invitation for. It is not a scanner and it does not find bugs for you; it enforces the discipline around the testing you drive.

---

## What you get (60 seconds)

- **A ledger as the single source of truth** (`.bbh/ledger.db`, SQLite/WAL). One row per `(endpoint, input, vuln-class)` cell. Closing a class on one input never touches its siblings. Every state change is an append-only event.
- **31 MCP tools** over that ledger. The loop is `status` -> `next_task` -> `run_cases`/`send_case` -> `close_cell` or `open_finding` -> `verify_finding` -> `render_report`. Each tool refuses an invalid transition and tells you exactly what is missing.
- **A planner** that opens the right cells from each request/response shape, and **generators for 32 vulnerability classes** (SQLi, XSS, IDOR, CSRF, SSRF, mass-dump, and more). Every class gets at least 10 cases over 5 techniques plus a positive control before it can close negative.
- **One scoped sender.** Scope and Rule 0 (no third-party data) are checked in code on every request; a kill switch stops all traffic instantly; one cross-process rate limiter caps load no matter how many sub-agents run.
- **Hooks** that survive compaction (they re-inject the next task), block out-of-scope navigation, deny sub-agents the researcher's real browser, lint every `report-*.md` into the house format, and block the Stop while cells are open.
- **Generated views** you open in any editor: `feature-matrix.md` (the coverage grid = definition of done), `state.csv`, `findings-summary.md`, `progress.log`. No live dashboard, no extra listening socket.
- **Confirmed findings become `report-N.md`** in the required format, each with a self-checking `repro/finding-N.sh` and `repro/finding-N.json`.

Deeper references: **`docs/usage.md`** (day-to-day), **`docs/design.md`** (why each mechanism exists), **`docs/extending.md`** (make it stronger), **`docs/for-ai-agents.md`** (onboarding for a fresh AI instance).

---

## Install

**Prerequisites**

- **Python 3.12 on PATH as `python`.** Not the Windows Store `py` launcher (it points at a separate interpreter without `mcp`; hooks and the MCP server call `python` by name). Check with `python --version`.
- **Burp Suite** running, with its MCP server reachable (default SSE endpoint `http://127.0.0.1:9876`) and the proxy on `127.0.0.1:8080`.
- **The two browser extensions already set up**: Agent360 Browser MCP in Chrome and ClaudeCodeBrowser in Firefox, both proxied through Burp. (bbh never drives these itself; you and the skills do.)

**Install the Python dependencies** (from this folder):

```
python -m pip install -r requirements.txt
```

That pulls `mcp` (the FastMCP API, pinned `<2`), `httpx`, `h2`, `truststore`, `websocket-client`, plus `flask` and `pytest` for the lab and tests.

**Load the plugin.** Either install it from the local marketplace that ships in this repo:

```
/plugin marketplace add C:/Tools/burp-mcp/bbh
/plugin install bbh@bbh-local
```

or, to run it for a single session without installing, launch Claude Code in the engagement folder with:

```
claude --plugin-dir C:/Tools/burp-mcp/bbh
```

Either way loads the bbh MCP server (31 tools), the six hooks, the three sub-agents (`bbh:class-tester`, `bbh:verifier`, `bbh:triager`), and the four skills (namespaced `bbh:recon`, `bbh:coverage-matrix`, `bbh:report-writer`, `bbh:triage-gate`).

---

## Quickstart

1. **Make an engagement folder** for the target (one folder per target). Copy `prompt.md.template` from this repo into it as `prompt.md`, then fill the fields at the top: asset, **scope** (enforced in code, so get it exactly right), out-of-scope, programme (public/private), login method, and the accounts. Pick the "two accounts" or "one account" block and delete the other. The optional **Harness** block tunes the rate limit, OOB listener, Burp proxy, max concurrent testers, and support hosts; the defaults are shown in the template.
2. **Proxy both browsers through Burp** and log in to the test accounts, so there is one shared HTTP history. bbh ingests Burp's proxy history over MCP; it never trusts Burp's truncated bodies and re-fetches a full body through its own sender when one matters.
3. **Say `go`.** The SessionStart hook injects the brief and the next task. Run the `recon` skill first (it ingests traffic, recovers source maps, reads JS, registers endpoints, and the planner opens cells), then let `next_task()` hand you one cell at a time.

---

## Everyday use

- **The loop.** `status()` is the compact dashboard (coverage by state, findings, depth queue, the single next task). `next_task()` claims and returns one unit of work with its context, generated cases, recipe excerpt, and exact completion criteria. Work on **what it returns**, not on what you feel like testing. Run the cases with `run_cases()` (or one at a time with `send_case()`); the ledger flips a cell to `candidate` the moment a case comes back positive, and a cell only closes `negative` with 10 cases over 5 techniques plus a passing control.
- **Findings land as files in the engagement folder.** Confirmed findings become `report-N.md` via `render_report()`, alongside `repro/finding-N.sh` (bash + curl, exits 0 only when the assertion still holds) and `repro/finding-N.json`. Raw evidence is in `captures/<cell-id>/`; principal session material in `captures/session-<label>.txt`; the end-of-session summary in `findings-summary.md`.
- **Stopping — three controls, see `docs/usage.md`.** `.bbh/STOP` is the kill switch: an emergency brake that refuses every tool reaching the target (browsers, Burp, WebFetch, bbh sends, networked shell commands) but leaves local disk/documentation/read-only tools working, so a halted session can wrap up and `rm` the file itself. `.bbh/PAUSE` is the soft stop: it lets the session end cleanly without blocking any tool (the agent's own clean exit). The Stop gate refuses to end while actionable work is open, and releases after 3 blocks in a row where the open-work total does not drop.
- **If the Stop gate writes `.bbh/stuck.md`,** the loop stalled (blocked repeatedly with no drop in the open-work total), it did not finish. Read it, unblock what it names (usually a second account, an OOB listener, or a browser step), and start again.

---

## Verify it works

From `server/`, run the unit and integration suite (ledger invariants, the planner rules, the 10-case/5-technique/control contract for every class, scope, the rate limiter, the kill switch, the report lint, the stop gate, and an end-to-end finding lifecycle):

```
cd C:/Tools/burp-mcp/bbh/server
python -m pytest tests/ -q
```

Then the planted-bug lab. `test_lab.py` proves every planted bug fires and every decoy resists; `acceptance.py` drives the **whole harness** end-to-end against a live local-only Flask app and scores recall, precision, and the invariants:

```
cd C:/Tools/burp-mcp/bbh/lab
python -m pytest test_lab.py -q
python ../lab/acceptance.py
```

The acceptance result is recorded in **`docs/lab-results.md`**: **10/10 recall, 0 false confirmations, 0 negatives missing their evidence, sibling independence holding on both multi-class bugs, the full IDOR lifecycle (verify twice + report + repro), and the stop gate blocking while work is open. Overall PASS.** The lab binds `127.0.0.1` only and is the regression test for every future change. (`acceptance.py` starts the lab on port 5099 and rewrites `docs/lab-results.md`; `run_lab.py` serves it on 5057 for manual poking.)

---

## Upgrade and extend

To add a vulnerability class, a planner rule, an MCP tool, a hook, or a condition/mutation op, follow the step-by-step recipes in **`docs/extending.md`**. It lists the exact files to touch, the contract each new piece must meet, the invariants you must not break, and how to run everything. A fresh AI instance that has to *use* bbh in an engagement should read **`docs/for-ai-agents.md`** first.

---

## Save it and use it on another machine

bbh is a self-contained git repo and the plugin is portable (every path inside it is relative or uses `${CLAUDE_PLUGIN_ROOT}`/`${CLAUDE_PROJECT_DIR}`, so it works wherever you put it). To move it:

1. Copy or clone the whole `bbh/` folder to the other machine (anywhere). Runtime artefacts (`.bbh/`, `__pycache__/`, `*.db`, lab run state) are git-ignored, so a clone is clean.
2. On the new machine, install the one-time prerequisites there: Python 3.12 as `python`, `python -m pip install -r requirements.txt`, and Burp + the two browser extensions proxied through Burp (the same environment you already use).
3. Load the plugin: `/plugin marketplace add <path-to-bbh>` then `/plugin install bbh@bbh-local` (or `claude --plugin-dir <path-to-bbh>` per session).

That is all bbh needs. Your own `.claude/` folder (the `CLAUDE.md` methodology and your settings) is separate and travels with you as before; the plugin adds the ledger, tools, and hooks on top of it. Your per-target workflow is unchanged: one engagement folder per target, a filled `prompt.md` in it, and say `go`.

## Safety

- **Scope is enforced in code.** Every navigation, fetch, Burp send, and curl/wget/Invoke-WebRequest URL is scope-checked by the pre-tool hook; the sender re-checks on every request. Out-of-scope and target-adjacent hosts are denied with a reason. Get the `Scope` field in `prompt.md` exactly right.
- **Rule 0 is enforced in code.** The sender scans every response for e-mail addresses and identifiers outside the registered test principals; on a hit it redacts the stored body to a count plus one masked proving field, locks the endpoint, and tells you to stop and report the count. It never pages through a stranger's data.
- **No destructive payloads.** Every generated payload passes a safety screen (no `DROP`/`DELETE`/`UPDATE`, no command execution, no file-scheme URLs or system paths, no cloud-metadata addresses, no recursive entity expansion); race bursts are capped at 30; cache probes always carry a unique buster.
- **Never run bbh against a target you are not authorized to test.** The ledger, the scope check, and the kill switch reduce the blast radius; they do not grant permission. Authorization comes from the programme, not the tool.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| Burp ingest returns nothing, or a connection error | bbh reads Burp proxy history from the SSE endpoint in `prompt.md` (`Burp MCP`, default `http://127.0.0.1:9876`). Confirm Burp and its MCP server are up and on that port, or set the field to `none` to disable Burp ingest and rely on the sender's own captures / a HAR import. Note the Agent360 Chrome extension scans `9876-9895`, so nothing of bbh's ever listens in that range. |
| `python` runs the wrong interpreter, or `mcp` is not found | Use `python`, never `py`. The Store `py` launcher resolves to a separate interpreter that does not have `mcp` installed. Check `python --version` (expect 3.12) and re-run `python -m pip install -r requirements.txt` against that interpreter. |
| XSS / CSRF browser cases record `inconclusive` instead of confirming | Those cases run in a private headless browser, which needs a Chromium-family binary (Chrome or Edge) on the machine. Without one, script-execution and cross-site PoC cases cannot confirm and are recorded inconclusive, not negative. Install Chrome/Edge, or drive that step manually and record it with `record_case`. |
| A CSRF / cross-origin finding cannot be submitted | Those reports need a hosted, working `poc.html`. Serve it (`python -m http.server 80`) and expose it over HTTPS with `ngrok http 80`, then use the HTTPS URL in the report. The ngrok Store alias hangs when run non-interactively, so always wrap it in a timeout. |

For anything deeper, read `docs/usage.md` and `docs/design.md`.
