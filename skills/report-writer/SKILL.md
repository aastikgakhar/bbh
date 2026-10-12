---
name: report-writer
description: Write or revise a bug bounty finding as report-N.md in the researcher's required house format, which is unwrapped prose, literal "Step N:" labels, raw HTTP inline under each step, role headers, banned words removed and no long dashes. Use before writing any confirmed finding up, when revising a report after triage rejection, and whenever a report needs its evidence citations checked against the capture files.
---

# Report writer

The reader is a twenty-year-old triager who knows security, has never used this product, and has just closed a hundred reports as not-applicable. Nothing is assumed, nothing is skipped, and nothing in the report hands them a reason to close it.

## The harness drafts it; you confirm and polish

You do not hand-write `report-N.md` from scratch. The flow is: confirm the finding with the bbh tool `open_finding` (give it the cell, the ladder rung, and the machine-checkable assertion), verify it with the bbh tool `verify_finding` (two clean replays sixty seconds apart plus the `bbh:verifier` agent's sign-off), then draft it with the bbh tool `render_report`. That tool writes `report-N.md` in the house format below, pulls the raw HTTP verbatim from the capture files, writes `repro/finding-N.sh` and `repro/finding-N.json`, and runs the lint. Your job is to read the draft, tighten the prose (the summary, root cause and impact are yours to write well), and fix anything the lint flags. The PreToolUse lint re-runs on every `report-*.md` write and blocks the save with the exact failing lines, so the format rules below are enforced, not merely requested.

## Gate first. No report until every line passes.

- [ ] Raw request and raw response saved in `captures/`, and the report cites the filenames. (`render_report` cites the captures behind the finding's assertion for you.)
- [ ] Reproduced twice from a clean session, which the bbh tool `verify_finding` does: two passing replays sixty seconds apart from fresh session material. A finding that is not `verified` has no report.
- [ ] Impact is a demonstrated effect, not a theory.
- [ ] Tested cross-principal or cross-origin as applicable, not only against my own data.
- [ ] Not documented intended behaviour. The docs, the settings UI and the published API spec were checked.
- [ ] Not a known duplicate. Prior public disclosures on this asset were searched.
- [ ] A triager following the steps with no context sees the same result.
- [ ] The words "potential", "could", "may", "if" and "theoretically" appear nowhere in the description of what happens.
- [ ] It is not forced logout, forced login, self-XSS, a missing header, or anything else on the out-of-scope list in `CLAUDE.md`.

Fail any line, no report. Fix the line or kill the finding.

## Then cite-check

**Open every file the report cites and diff it against the prose.** Does the capture actually contain the request the step describes? Does the response actually show what the sentence claims? Do the account identifiers in the capture match the roles the report assigns them? Does the `User-Agent` match the browser the report says produced it?

One self-contradicting citation discredits everything else in the report. This check is not optional and it is not the same as remembering that the test worked.

## Format

The full skeleton is in `references/template.md`. Copy it and fill it in.

The rules that get corrected every single time, in order of how often:

**Write prose unwrapped.** Each paragraph is one long line. Do not hard-wrap at 78 or 80 columns. Wrapped text renders on the platform as a line break every five or six words and reads as fragmented. Compose unwrapped from the start rather than fixing it afterwards. `python unwrap.py report-N.md` re-flows an already-wrapped file while leaving fences, indented blocks and list items intact.

Only these keep their line breaks: fenced code blocks, raw HTTP dumps, and bullet lists, where each bullet is one line and each bullet is itself unwrapped.

**Label steps `Step 1:` as literal text**, on its own paragraph. Not a markdown numbered list. `1.` renumbers or collapses when the steps are split across role sections. Group the steps under bold role headers, `**As the attacker**` and then `**As the victim**`.

**Put the raw request inline, under its own step.** Never describe a request in prose, and never park the captures in an Evidence section at the bottom. Steps in one place and evidence in another is unreadable. Each step is a short sentence of intent, then a fenced `http` block with the verbatim request, then a fenced `http` block with the verbatim response, then one line saying what just changed.

Where a step can be done by clicking a button or visiting a URL, say that instead, with the exact button label and the exact URL, and cut the raw request for that step. Keep raw requests for the steps that cannot be done through the UI. Annotate the session-bearing header as `<replace with your session cookie>`.

**Note:** A victim step must never contain a Burp request or raw HTTP block. The victim should only perform the normal browser action required to trigger the issue. This applies even when the triager is reproducing the report by acting as the victim in a cross-tenant or cross-principal scenario. The triager must not need Burp Suite, Repeater, curl, DevTools, or any attacker-controlled request on the victim side. The attacker performs the setup and sends any required attacker-side requests, while the victim only logs in normally and performs the stated browser action. The reproduction must make it completely clear that the victim does not need cooperation from the attacker beyond the attacker having already prepared the PoC or malicious state.

**No long dashes anywhere.** Use commas.

**Banned words anywhere in the report:** if, potentially, could be chained, may allow, theoretically, phishing. Also avoid "should", "seems", "appears to", and any sentence that invites dismissal, such as "this may be by design" or "feel free to disregard".

**Never name the test emails.** Account A and Account B only, with both account identifiers in a small table at the top.

**No special bold text** of words or letters in the report

First person once or twice across the whole report, no more. Prefer "I believe" over "I think".

## Shape that works

Five steps, around ten HTTP blocks:

- Step 1: log in and grab the identifier.
- Step 2: the benign read that shows the target identifiers.
- Step 3: the override request that acts across the boundary.
- Step 4: the variant that shows the full effect.
- Step 5: re-run Step 2's request as the other principal, to show the effect landed on their side.

Four to six reproduction steps maximum. Everything else is Prerequisites, and Prerequisites is three lines at most.

## Severity

Match the severity to the demonstrated effect, not to the effort it took. Source map disclosure is a **Low**, written short and factual. A cross-principal read or write is where High starts. If the finding needs a precondition the attacker cannot create, it is not the severity you want it to be.

## Cross-site findings

Any CSRF or cross-origin finding needs `poc.html`, hosted on the HTTPS ngrok URL, attached to the report, and a line in the steps saying to host it and open it in the second account's browser. A cross-site report without a working attached PoC cannot be submitted.

Include a demo video where the effect is visual, and mention it in the report.

## After writing

All reports go to `triage-gate` together before anything is filed. Never file straight from here. Each triage round's verdict is recorded with the bbh tool `record_triage` (an ACCEPT gates the finding, three REJECTs kill it), and `findings-summary.md` is regenerated by the bbh tool `render_views`.
