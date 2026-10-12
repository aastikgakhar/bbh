---
name: coverage-matrix
description: Drives feature-matrix.md, the generated feature by bug-class grid that defines when a bug bounty session is finished. Use right after recon, every time a cell is worked, and whenever the session feels done, to refuse to stop with blank cells. The grid is a view of the bbh ledger (rendered by render_views); cells are worked through next_task/run_cases/close_cell. Holds the per-class test recipes, the single-account fallbacks, and the evidence rules that separate a real finding from a 200 status code.
---

# Coverage matrix

The most expensive failure mode in this work is tunnel vision: going deep on authorization and never testing XSS, SQLi, mass data exposure, unauthenticated data access/manipulation, open redirect, CRLF, SSRF or CSRF at all. A past session produced zero findings that way. This skill exists to make that impossible.

**The matrix is the definition of done.** Not "I found something". Not "I ran out of ideas". Every cell filled.

## It is a generated view

`feature-matrix.md` is the feature-by-class grid, one row per feature, one column per bug class. You do not build or edit it by hand: it is rendered from the bbh ledger by the bbh tool `render_views`, and the planner opens one cell per (endpoint, input, class) from the request and response shape during recon. Run `render_views` to see the grid, and the bbh tool `status` for the counts.

Every cell ends in one of the ledger's states; the matrix shows them as:

| Cell state | Shown as | Meaning |
|---|---|---|
| `negative` | `tested` | Attempted for real, evidence threshold met, nothing found. |
| `confirmed` | `FINDING-N` | Confirmed and verified, linked to `report-N.md`. |
| `n_a` | `n-a` | The class genuinely cannot apply. Needs an enum reason plus a request that proves it. |
| `blocked` | `blocked: <reason>` | Testable in principle, prevented by something concrete (a second account, a paid tier, a geo-block, a WAF, a feature flag). Needs the reason and what would unblock it. |
| `candidate` | `candidate` | A signal was seen; confirm or refute it before anything else. |
| `open` / `in_progress` | blank / `wip` | Unfinished. |

Blank means unfinished. "I did not get to it" is never `n_a`. You move a cell with the bbh tool `close_cell`; it refuses the transition and tells you exactly what is missing (the ten-case plus control plus five-technique rule, the enum reason, the counter-read) rather than trusting you to remember it. Blocked cells surface in `findings-summary.md` at the end with what would unblock them, because that list is often where the next session starts.

## Fill it

You do not pick the next cell; the bbh tool `next_task` claims it and hands you the endpoint, the input, the context, the generated cases and the completion criteria. Run every case with the bbh tool `run_cases` (or one at a time with `send_case`); each is sent through the scoped, rate-limited sender and recorded, and the harness flips the cell to `candidate` the moment a case comes back positive. The harness enforces sibling independence (confirming or refuting one class never touches another on the same input) and the evidence threshold in code, so the counting is automatic; your job is the judgement.

**Read `references/classes.md` before working a row.** It holds the actual test recipes: what to send, what to vary, and what specifically proves each cell. This page only says what counts as filled.

One line per class, for deciding whether a cell can honestly be closed `negative`:

| Class | The cell is filled when you have |
|---|---|
| **IDOR / authz** | The second principal's object ID used with the first principal's session, and the response body read. Or, with one account, the unauthenticated replay. |
| **Mass-dump** | The scoping parameter removed or widened on every list, search, export, sync and batch endpoint, and the result counted. |
| **SQLi / NoSQLi** | Time-based or boolean-based confirmation, or a clean negative on every parameter that reaches a datastore, including JSON body fields and headers. |
| **XSS** | The payload viewed from the surface that renders it, as the principal who would see it. Stored, reflected and DOM traced separately. |
| **HTMLi** | Markup injection attempted where script is blocked by CSP, including dangling markup. |
| **CSRF** | Token removed, emptied, swapped, and `Content-Type` swapped, on every state-changing endpoint. Cross-origin `fetch` and top-level form POST tested separately. |
| **Open redirect** | Every redirect-shaped parameter tried, and then checked for whether it carries a token. |
| **CRLF** | `%0d%0a` and its encodings in every parameter reflected into a response header, and in filenames. |
| **SSRF** | An out-of-band callback you control, actually received. No callback, no cell. |
| **Upload** | Extension, MIME and magic-byte bypass attempted, plus the serving origin identified. |
| **Race** | 20 or more parallel requests fired at every limit, counter, one-time token and uniqueness constraint. Not clicks. |
| **Info-leak** | The API response diffed against what the UI renders, plus debug parameters tried. |

## The account situation decides which columns are testable

Read the Accounts section of `prompt.md` first.

### Two accounts

Standard. Take the object ID from the second principal's browser, use it from Chrome with the first principal's session, and verify the effect back on the second principal's side. Do not alternate browsers; fetch the identifier once and return to Chrome.

### One account

Do not mark the cross-account columns `n-a`. Work through this in order.

**First, try to make a second principal.** This restores full coverage and takes minutes.

- Open signup and register a second account, if the programme allows it and signup is not gated by payment, invite, KYC or geography.
- Plus-addressing (`name+b@gmail.com`) or a dot variant often works where a second mailbox does not exist.
- Invite a second user from inside the app to an address the researcher controls, then accept it.

**Second, find the second principal that already exists inside the one account.** Almost every app has several, and privilege boundaries between them are real findings. A past confirmed High came from exactly this shape, with no second account involved.

- Roles: owner, admin, editor, viewer, guest. Create a second workspace or project and assign a lower role to a token or a share link.
- API tokens with reduced scopes. Mint one with scopes denied, then call the denied endpoint with it.
- Public or unlisted share links. A share link is an unauthenticated principal with defined permissions, and testing whether it exceeds them needs nobody else.
- Invited-but-unaccepted users, integrations, OAuth apps, service accounts, webhooks.
- The pre-authentication state of your own account: an object created before login, an onboarding session, an anonymous cart.

**Third, the unauthenticated replay is the strongest single-account substitute.** Take your own object ID, strip every cookie and auth header, and replay. If the data comes back, that is broken authorization proven with zero exposure to any third party, and it is a stronger report than a cross-account one because nobody's real data was touched.

**Fourth, these classes stay fully testable with one account and no second principal at all:** XSS on every surface, HTML injection, SQLi, CSRF, open redirect, CRLF, SSRF, file upload, race conditions, cache poisoning, information disclosure and over-fetching, client-side-only enforcement, mass-data endpoints with your own scoping filter removed, and every endpoint found in JS that the UI never calls.

Only after all four have been worked does a cell get `blocked: no second account`.

## Evidence discipline

**Read `references/evidence-rules.md` before marking any cell either way.** It holds the rules that have each personally cost a session: why a 200 can be a no-op, why a silent failure is your own client rate-limiting you, why a 422 is not an authz bypass, why an injected identity proves nothing without a counter-write, and why a failed enumeration is not a negative.

The short version, applied to every cell (the harness enforces the mechanical parts; these are why):

- A cell closed `negative` needs saved request/response pairs just as much as a `FINDING` does. `close_cell` refuses without them.
- Every negative needs a positive control: the same request, same tooling, same session, in a shape you know works. A failed control reopens the cell with a tooling note rather than letting it close.
- Every write needs a counter-read as the other principal before you believe it landed. The write classes require the counter-read capture.
- **Your own negatives are the least trustworthy artefact in the session.** The harness counts the cases, but it cannot judge them: before accepting a negative, red-team the "no finding" conclusion the same way you would red-team a report (a candidate going negative needs the `bbh:verifier` agent's sign-off via the bbh tool `verifier_signoff`). This has caught three wrong calls in a single past engagement.

## Chaining, and keeping the scraps

Maintain `bug-name-chain.md` alongside the matrix.

1. Research current public methodology and recent disclosed reports on similar assets for the classes above. **Skip this step entirely if `prompt.md` says the programme is private.**
2. For each technique, write the class, the preconditions it needs, and whether those preconditions exist here, checked with evidence rather than assumed.
3. **Keep every low-value behaviour.** Anything with real, observed behaviour that is not worth reporting alone goes in this file as a chain candidate with one line on what it would need to become reportable. Do not delete it. Actively look for the other half. A P5 alone does not ship; a P5 chained often does.
4. A chain is reportable only if **every link is independently confirmed**. Never chain a confirmed bug to a hypothetical one.
5. Report independently confirmed issues as **separate findings**, not one chain, unless the chain is the only way to show impact.

Chains that have worked: open redirect plus a token in the URL, CORS misconfiguration plus information disclosure, postMessage origin reflection plus an outbound read, cache poisoning plus stored XSS, IDOR plus email enumeration, a dangling subdomain plus wildcard CORS.

## Before the session can end

Answer these in `attack-surface.md` with evidence, including the negative answers and what makes them negative.

1. Can a page on the ngrok URL change **any** setting on the second principal's account? Enumerate every settings endpoint and test each one.
2. Can that page **read** anything belonging to the second principal? Any response, any ID, any existence oracle.
3. Is there any endpoint that returns data for users beyond the test accounts?
4. Can any account-linked identifier be read cross-origin and used as a persistent tracking supercookie?
5. Can any endpoint be made to navigate, open, or embed a page of your choosing?
6. Is any object accessible cross-account, or unauthenticated, without authorization?
7. Does any endpoint behave differently when the CSRF token is removed versus wrong versus absent?
8. Is there any path where a client-side-only check is the sole enforcement?

Then run the bbh tool `render_views`: it writes `findings-summary.md` with coverage as filled over total and the percentage, and the Stop gate refuses to end the session while any cell is `open`, `in_progress` or `candidate`, any finding is unverified or unreported, or the depth queue is non-empty. A session that ends below 100% ends with an explicit list of what is blank and why, which `findings-summary.md` already carries.
