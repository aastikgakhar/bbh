# bbh for AI agents

You are an AI instance with no memory of how bbh was built, and you have to run a bug-bounty engagement with it. This page is the minimum you need to act correctly. It is not a tour; it is the operating manual. Read `.claude/CLAUDE.md` for the methodology and the hard safety rules; read this for how the harness expects you to behave.

## 1. The ledger is the only source of truth

State lives in a SQLite ledger at `./.bbh/ledger.db`, not in your context and not in your notes. Every endpoint, input, vulnerability-class cell, case, finding, and triage verdict is a row; every change is an append-only event. **Do not track progress in your head or in prose.** When you want to know where things stand, call `status()`; to see one thing in detail, call `show(cell_id=...)` or `show(finding_id=...)`. The ledger refuses invalid transitions and tells you exactly what is missing — believe it over your own memory of what you think you did.

## 2. The loop, and you work on what it hands you

Call `status()` and `next_task()` first, every session. Then repeat:

```
next_task()                 → claims ONE cell/finding/depth item and returns its context, the
                              generated cases, the recipe excerpt, and the exact completion criteria
run_cases(cell_id)          → execute every generated case (control first) through the sender
   or send_case(cell_id, n) → execute one case
                              (a case that comes back positive flips the cell to `candidate` automatically)
close_cell(cell_id, state)  → 'negative' (full evidence), 'n_a' (enum reason + proving request id),
                              or 'blocked' (enum reason + what would unblock it)
   or, if there is a real signal:
open_finding(cell_id, rung, assertion, title, severity)   → records the machine-checkable proof
verify_finding(finding_id)  → replays the assertion from a clean state; two passes ≥ 60 s apart
                              plus the bbh:verifier agent's sign-off make it verified / the cell confirmed
render_report(finding_id)   → writes report-N.md + repro/finding-N.{sh,json} in the house format, runs the lint
record_triage(finding_id, verdict, ...)  → after the triage-gate agent reviews it
```

**Work on what `next_task()` returns, not on what you find interesting.** Its priority order is deliberate: open candidates first (a candidate blocks everything until confirmed or refuted), then findings needing verification / a report / triage, then open cells on high-value surfaces (cross-principal, shared/public, state-changing), then the remaining open cells, then depth-queue items, then a recon refresh. Cherry-picking is the failure mode this order exists to prevent.

## 3. Every class on every input is its own verdict

The planner opens one cell per `(endpoint, input, vuln-class)`. Confirming or refuting one class on one input **never** closes its siblings — if XSS fails on a parameter, HTMLi, SSTI and CSTI on that same parameter are still open and must each be worked. There is no "close everything here" action, by design.

A cell closes `negative` only with **at least 10 executed cases over at least 5 technique families, plus a passing positive control**, every cited capture saved, the class's required families present, and a counter-read for write classes. If `close_cell` refuses, it returns the `missing` list — supply exactly that, do not argue with it. A control that fails means your tooling is broken (silent throttle, WAF on the scripted client, stale session), not that the target is safe: fix the tooling and the control reopens the cell.

## 4. The single most common mistake: a candidate is not a finding, and 200 is not success

Internalise this or you will file garbage:

- **A `candidate` is a signal, not a finding.** A positive case makes a cell a candidate; it is a thing to confirm or refute, nothing more. A finding exists only after `open_finding` + `verify_finding` (two clean replays + verifier sign-off) move the cell to `confirmed`. Never write a report from a candidate.
- **"The server returned 200" is not "something happened".** A 200 with an empty body is nothing. Read the body. For any write, counter-read as the other principal to prove the state actually changed — a cross-account write that returns `{"ok": true}` is frequently a no-op.
- **A reflected value is not a vulnerability.** Prove script execution (XSS), cross-account data access (IDOR), a confirmed state change, or an observed outbound request. The generators encode this: XSS script-execution rungs only confirm via a `browser_marker`, never via raw reflection.
- **Your own negatives are the least trustworthy artefact in the session.** Red-team each one before accepting it; a candidate going to `negative` requires the `bbh:verifier` agent's `verifier_signoff`, and the harness enforces that.

## 5. Set a cell's context before its cases can prove anything

Many classes need a fact you have to supply first, via `set_cell_context(cell_id, {...})`. The cases contain placeholders the sender fills from that context:

- **IDOR / BOLA:** `{"other_object_id": "7"}` (an object that belongs to the *other* principal), usually with `{"own_object_id": "1"}`. Payloads use `{{OTHER_ID}}` / `{{OWN_ID}}`; `{{OTHER_ID}}` is refused until you set `other_object_id`. Fetch that id from the other account's browser, then come back to your primary browser.
- **Stored / second-order (stored XSS, stored HTMLi, SSTI):** `{"render_endpoint": "GET /people", "viewer": "B"}` — where the stored value is rendered and which principal sees it. The case stores as you, then counter-reads as the viewer.
- **Race:** the counter-read request and a marker proving the limit was exceeded, e.g. `{"counter_read": {"method": "GET", "path": "/api/credits"}, "limit_exceeded_marker": "..."}`.
- **SSRF / XXE:** need an OOB listener set in `prompt.md`. Mint a URL with `oob_url(cell_id)`, let the payload carry `{{OOB}}`, then poll with `oob_check(cell_id)`. With no listener these cells can only close `blocked: no_oob_listener`.

Register every principal you will act as with `add_principal` (labels like `A`, `B`, `unauth`, a role, a scoped token, a share link) so cross-principal cases and the `unauth` strip have session material and identifiers.

## 6. Some cases you run outside the sender — then record them

Most cases run straight through the sender via `run_cases`/`send_case`. Cases with `route` of `browser`, `oob`, `counter_read`, or `manual` may need you to do something the sender cannot: drive a page, judge a rendered result, confirm an OOB hit. When you execute a case outside the sender, save the raw request/response files yourself and call `record_case(cell_id, case_no, technique, outcome, observation, request_capture=..., response_capture=...)` with a **factual** observation that states what the response showed and names the capture file. `outcome` is one of `positive` / `negative` / `inconclusive` / `control_pass` / `control_fail`; an `inconclusive` never counts toward a negative.

## 7. Generated files are read-only; never hand-edit them

`state.csv`, `feature-matrix.md`, `findings-summary.md`, and `progress.log` are **views rendered from the ledger** by `render_views()`. Editing them does nothing useful: they are overwritten on the next render and your edit desyncs you from the truth. Read them to orient; change the world through the tools. `report-N.md` is generated by `render_report()` and then yours to polish (prose only — the lint enforces the house format on every save). `prompt.md` is the one file you never overwrite: it is the researcher's brief.

## 8. The kill switch

If anything looks wrong — unexpected data, an out-of-scope response, a destructive effect — create the file `./.bbh/STOP` (any content). Every send is then refused, every network-capable tool is denied, and the Stop gate lets the session end. Delete the file to resume. This is a safety brake; use it rather than pressing on.

## 9. The real-browser rule (absolute, especially for sub-agents)

Never launch, attach to, automate, or kill the researcher's real Chrome or Firefox, and never close a tab or process you did not create. This has destroyed the researcher's working tabs before. A sub-agent that needs a browser gets a **private headless instance** with a fresh `--user-data-dir` in temp and an unused `--remote-debugging-port`, and kills only that PID. The PreToolUse hook already denies every real-browser tool to any sub-agent; do not try to route around it. If you are the main session and genuinely need the real browser for a step, do it yourself, minimally, and never from an agent brief.

## 10. Evidence discipline (the parts the harness cannot count for you)

The ledger counts cases, controls and captures. It cannot judge them. You must: save a real request/response pair for every claim (negatives included — `close_cell` refuses without them); reproduce from a clean state before believing a result; counter-read every write as the other principal; and check whether a behaviour is intended (docs, the API spec, the settings UI, prior public disclosure) before calling it a finding. When you are uncertain, spawn a sub-agent to resolve it — never resolve uncertainty by writing a confident report.

---

If you remember one sentence: **work the cell `next_task()` gives you, prove every claim with a saved exchange and a counter-read, and treat a candidate and a bare 200 as nothing until the harness says `confirmed`.**
