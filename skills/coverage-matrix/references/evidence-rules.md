# Evidence rules

Each of these has personally cost a session, either by producing a report that died at triage or by closing a real finding as a negative. Check them before marking any cell in either direction.

## Rules that kill false positives

**A 200 can be a no-op.** A cross-account write that returns `OK` frequently changes nothing at all. Counter-read the object as its owner before believing any write. This applies to `DELETE` especially: an `OK` on a cross-account delete has come back with the object still present.

**An injected identity proves nothing on its own.** Sending `gpid`, `user_id`, `owner` or `tenant_id` in a request and getting a success does not mean the server honoured it. Run the counter-write: repeat the operation and show that the result follows the injected value rather than the session. Until that, the server was almost certainly ignoring the field.

**A broken postMessage origin check is worth nothing inbound-only.** Unless data goes out to the attacker's frame, or an injected identity is honoured, there is no impact. Run the counter-read before writing anything up.

**Input is often validated before authorization.** A `422` or `400` on a cross-account request is a validation failure, not an authz bypass. Resend with a fully valid payload before concluding either way.

**ACL changes propagate slowly.** A `200` right after a share or permission change proves nothing. Re-test after about a minute.

**A secret in a response is only a finding if the attacker can reach what it unlocks.** Keys that write into the target's own GA4, Ads, Sentry or similar are not findings; the attacker cannot read the destination.

**Source map exposure is a Low, and it is recon.** Do not inflate it by attaching the consequences of reading it. If reading it produced a separate confirmed bug, that is its own report.

**Check the published API spec before calling anything undocumented.** `openapi.json`, `swagger.json`, `llms.txt`, `/.well-known/`. An endpoint the vendor documents publicly is intended behaviour, and this has killed a report at the last moment before.

**A self-privileged action is not a cross-tenant one.** Escalating within your own account or claiming your own unverified resource affects nobody else. Check whether any other principal's state changed.

## Rules that kill false negatives

**Every negative needs a positive control.** The same request, the same tooling, the same session, in a shape known to work. Without one you cannot distinguish "the server refused" from "my client broke".

**A silent failure is usually your own client.** `status: 0`, an empty response, or `Error("silent")` from a borrowed in-page client is almost always a client-side rate limit or a local throttle, not a server answer. Slow down and re-run with the control.

**Akamai and similar WAFs ban the scripted client by fingerprint** while the browser still works fine. A standing `403` on a Python or curl harness against endpoints the browser reaches is a tooling block, not a security control. Capture evidence through the browser the moment a finding is confirmed, because the ban can arrive at any time.

**A failed enumeration is not a negative.** Check the HTTP status of the enumeration itself. A wildcard certificate means certificate transparency cannot enumerate subdomains, so the honest answer is "unknown", not "N hosts found".

**Cookie replay rots fast.** A `401` does not disprove a finding if the session expired, and a valid `exp` claim does not mean the session is still live. Re-establish and replay before concluding.

**Protocol mismatch looks like a block.** `RST_STREAM` or a connection reset when replaying a captured request is often HTTP/1.1 versus HTTP/2, not the server rejecting the request. Match the protocol before concluding.

**Synthetic clicks never fire `javascript:` hrefs.** An automated click on one does nothing, which is indistinguishable from a patched sink. Drive the sink another way.

**A canvas app is still automatable.** Flutter and similar do not expose DOM elements, but file pickers can be reached by patching `HTMLInputElement.prototype.click`, text by setting the `flt-text-editing` textarea, and everything else by coordinate clicks. "No DOM" is not a reason to mark a cell `n-a`.

**Do not reimplement a request signer.** If requests carry a signature, a nonce or a derived header, pull the application's own HTTP client out of the module registry and call it. Hand-rolling the signer produces failures that look like server-side rejections.

## Red-teaming your own negatives

Before a feature is closed out, spend one pass attacking the conclusion rather than the target. Ask:

- Which of the rules above could explain this negative as a tooling artefact?
- Did I test the endpoint, or did I test the UI path that reaches it?
- Did I vary method, auth state, content type and parameter shape, or only the value?
- Is there a second principal (role, token, share link, unauthenticated) I did not try?
- Did I read the response body, or only the status?

This pass caught three wrong "no finding" calls in a single past engagement. Budget for it.

## Evidence hygiene

**Save every pair.** One file per request/response pair in `captures/`, named after the step that will cite it. A report citing a capture that does not exist, or that says something different from the prose, discredits everything else in it.

**Never mix artefacts across role swaps.** If the attacker and victim roles were swapped mid-session, every capture from before the swap is poison. Anchor the identifiers first: which account ID maps to which email maps to which name, and check the `User-Agent` in each capture matches the browser the report claims produced it.
