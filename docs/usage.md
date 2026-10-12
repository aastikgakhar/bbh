# Using bbh

bbh is a Claude Code plugin that turns the bug-bounty methodology in `.claude/CLAUDE.md` and the four skills into something the harness enforces: a SQLite ledger that is the source of truth, a scoped and rate-limited sender, case generators for 32 vulnerability classes, and hooks that inject the next task, guard scope, lint reports, and refuse to let the session stop while work is open.

## Install once

bbh ships with a local marketplace, so it installs like any plugin:

```
/plugin marketplace add C:/Tools/burp-mcp/bbh
/plugin install bbh@bbh-local
```

Then restart Claude Code (or `/plugin` to confirm it loaded). To develop or run it for a single session without installing, launch Claude Code in the engagement folder with:

```
claude --plugin-dir C:/Tools/burp-mcp/bbh
```

Either way loads the bbh MCP server (28 tools), the hooks, and the three agents (`bbh:class-tester`, `bbh:verifier`, `bbh:triager`). The plugin skills are namespaced `bbh:recon`, `bbh:coverage-matrix`, `bbh:report-writer`, `bbh:triage-gate`; the project copies under `.claude/skills/` keep their bare names, so both coexist.

### Requirements

Python 3.11+ on PATH as `python` (not the Store `py` launcher). From `bbh/`:

```
python -m pip install -r requirements.txt
```

That is `mcp<2` (the FastMCP API), `httpx`, `h2`, `truststore`, `websocket-client`, plus `flask` and `pytest` for the lab and tests. The MCP server runs as `python -m bbh.server` with `PYTHONPATH` set to `bbh/server` (the `.mcp.json` does this).

### Ports

bbh never listens on 8080, 8765, 8766, 9222, or 9876-9895 (Burp, ClaudeCodeBrowser, and the Agent360 extension's scan range live there; see `docs/inventory.md`). Its own defaults are the OOB listener on 7731, a PoC server on 7732, and the dashboard on 7733.

## Start an engagement

1. In a fresh folder for the target, copy `bbh/prompt.md.template` to `prompt.md` and fill the fields at the top: asset, scope, accounts, login method, and the optional **Harness** block (rate limit, OOB callback, Burp proxy, max concurrent testers, support hosts). Scope is enforced in code, so get it right; everything else is already in `CLAUDE.md` and the skills.
2. Proxy both browsers through Burp (so there is one history) and log in to the test accounts. bbh reads Burp's proxy history over its MCP endpoint; it never trusts Burp's truncated bodies and re-fetches through its own sender when a full body matters.
3. Say **go**. The SessionStart hook injects the engagement brief and the next task; `status()` and `next_task()` drive the loop. Run `recon` first (it ingests traffic, recovers source maps, reads JS, and the planner opens cells), then let `next_task()` hand you one cell at a time.

The agent works on what `next_task()` returns: candidates first, then unverified findings, then open cells on high-value surfaces, then the rest, then depth items, then a recon refresh. A cell closes `negative` only with 10 executed cases over 5 technique families plus a passing control; the ledger lists exactly what is missing if it refuses. Confirmed findings become `report-N.md` via `render_report()`, which also writes `repro/finding-N.sh` and `repro/finding-N.json` and runs the report lint.

## Watch progress

- `status()` is the compact dashboard: coverage by state, findings by status, the depth queue, and the single next task.
- The generated views refresh on demand (`render_views()`) and before every compaction: `state.csv`, `feature-matrix.md` (the coverage grid, the definition of done), `progress.log`, and `findings-summary.md`.
- The ledger is `./.bbh/ledger.db`; every state change is in its append-only `events` table. Raw exchanges are in `./.bbh/traffic/` and every test case's request/response pair is in `captures/<cell-id>/`.

bbh ships read-only views (the generated markdown) rather than a live web dashboard. The decision and reasoning are in `docs/design.md` (Optional section): the two browser MCPs and Burp already cover capture, and a static grid the researcher can open in any editor is lower-risk than another listening socket next to the ones the inventory already flagged.

## The kill switch

Create the file `./.bbh/STOP` (any content) to stop immediately: every send is refused, every network-capable tool is denied by the PreToolUse hook, and the Stop gate allows the session to end. Delete the file to resume. Use it whenever something looks wrong.

## Reading stuck.md

If the Stop gate blocks three times in a row with no new progress between attempts, it stops fighting you: it allows the stop and writes `./.bbh/stuck.md` with the open-work counts and the next tasks the agent did not do. That means the loop stalled, not that the work is finished. Read it, see where it stalled (usually a cell that needs a second account, an OOB listener, or a browser step), unblock that, and start again. A genuinely finished session has an empty matrix of open cells and needs no `stuck.md`.

## What the hooks enforce (and what they leave to you)

Enforced in code: scope on every navigation, fetch, Burp send and curl (out of scope is denied with a reason, target-adjacent hosts too; support hosts allow navigation but not test traffic); the kill switch; the per-host rate limit and burst cap; the 10-case + control evidence threshold; sibling independence; ladder rungs never downgrading; the report house format (lint on every `report-*.md` write); subagents never driving the real Chrome or Firefox; the verifier being the only caller of `verifier_signoff`.

Left to your judgment: which object identifiers to fetch for a cross-account test, whether a candidate is real, the wording of a finding, and the red-team pass on every negative (the hook prompts it; you do it). The methodology in the skills is the reasoning; the harness is the bookkeeping.

## Settings bbh does not change

bbh installs its hooks and MCP server through the plugin, so it does not write your `settings.local.json`. If you want to pre-allow its tools to avoid prompts, add `"mcp__plugin_bbh_bbh__*"` to the `permissions.allow` list in your own settings; nothing requires it. The plugin adds nothing else to your configuration.

## Run the tests and the lab

From `bbh/server`: `python -m pytest tests/ -q` runs the 257 unit and integration tests (ledger invariants, planner rules, the case-count contract for every class, the scope check, the rate limiter, the kill switch, the report lint, the stop gate, and an end-to-end finding lifecycle).

From `bbh/lab`: `python -m pytest test_lab.py -q` proves the planted bugs and decoys, and `python ../lab/acceptance.py` runs the whole harness against the live lab and writes `docs/lab-results.md` (target: 10/10 recall, 0 false confirmations). The lab binds 127.0.0.1 only and is the regression test for every future change.
