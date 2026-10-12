# Per-class test recipes

One section per matrix column. Read the section before working that cell.

---

## IDOR and broken authorization

For every object type the app has (page, record, database, workspace, file, comment, block, template, integration, invite, export, webhook, whatever exists):

- `GET` it as the other principal. Read the body, not the status.
- `PUT`, `POST`, `PATCH` it. Then **counter-read as the owner** to confirm the edit actually landed. An `OK` on a cross-account write frequently changes nothing.
- `DELETE` it, only between the test accounts.
- Swap methods: `GET` to `POST`, `POST` to `PUT`/`PATCH`/`DELETE`. Try `HEAD` and `OPTIONS` for oracles.
- Strip all cookies and auth headers and replay. Is it simply public?
- Downgrade the role: can a viewer perform owner actions, a collaborator perform admin actions, a reduced-scope token perform a denied one?
- Parameter pollution: duplicate parameters, array versus scalar, `id[]=A&id[]=B`, the same key in query and body.
- Mass assignment: add fields the UI never sends. `owner`, `owner_id`, `role`, `isAdmin`, `visibility`, `permissions`, `status`, `verified`, `price`, `tenant_id`, and every internal flag seen in any response body. Use the exact permission strings recovered from the JS.
- Object type confusion: pass an ID of a different resource type into the same parameter.
- ID format attacks: sequential neighbours of your own ID, a UUID with one character changed, a base64 or hex ID decoded and re-encoded, an ID from a different environment.

**Two error messages are a finding by themselves.** If "not yours" and "not found" produce different responses, status codes, or timings, authorization is being evaluated after lookup, and that difference is an existence oracle that needs no target object at all.

**Validation order matters.** On many APIs input is validated before authorization, so a `422` on a malformed cross-account request proves nothing. Resend with a valid payload before concluding anything.

**ACL changes propagate.** A `200` immediately after a share or permission change proves nothing. Re-test cross-principal reads after a minute.

---

## Mass data exposure

The class that pays most and gets skipped most. For every list, search, export, sync, feed, report and batch endpoint:

- Remove the pagination limit. Then `limit=99999`, `per_page=0`, `-1`, `limit` absent entirely.
- **Remove the filter that scopes results to your account.** `workspace_id`, `user_id`, `space_id`, `tenant_id`, `owner`, `account`. Try it absent, empty, `null`, `0`, `*`, `%`, and the other principal's value.
- Change `offset`, `after`, `cursor` or the sort order to walk past your own data.
- Batch endpoints: submit an array mixing your IDs and the other principal's, and see what comes back.
- Search: query for a string you only ever created in the other account.
- Export and sync: do they honour the same scoping as the read endpoints? They frequently do not.
- GraphQL: introspect if enabled. If it is disabled, **validation still runs before authentication**, so batched aliases and field-suggestion errors rebuild the schema unauthenticated. Then query root collections with no scoping argument, and request fields the UI never asks for.
- Index and metadata routes: `sitemap.xml`, `robots.txt`, `/api`, `/v1`, `/v2`, `/internal`, admin routes found in JS.

**Rule 0 applies hardest here.** The moment data outside the test accounts appears, stop. Capture the count, or one field of one record that proves the leak, and nothing else.

---

## SQLi and NoSQLi

Every parameter that plausibly reaches a datastore: search terms, filters, sort fields, column names, IDs, pagination values, JSON body fields, and header values.

- Time-based and boolean-based confirmation only. Never report from an error message alone.
- Test the sort and order-by parameters specifically; they are concatenated far more often than `WHERE` clauses.
- JSON body fields and headers, not just query strings.
- NoSQL operators in JSON bodies: `$ne`, `$gt`, `$regex`, `$where`, `$in`, and the array-versus-string type juggle on login endpoints.
- Second-order: store the payload through one endpoint, trigger it through another that reads it back.

---

## XSS and HTML injection

Every input from `workings.md` where the input reaches a render path.

- **Stored:** name it, title it, comment it, describe it, then view it as the principal who would see it. If it renders in their view, that is the finding. If it renders only in yours, it is self-XSS and needs a chain.
- **Reflected:** every parameter that appears in a response, in every context: HTML body, attribute, `<script>` block, JSON later parsed into the DOM, and inside an existing tag.
- **DOM:** every sink catalogued in `js-inventory.md`. Trace source to sink; do not guess.
- **postMessage:** send crafted messages to every listener from a frame you control.
- **Highest-value surfaces first:** published pages, shared links, embeds, public profiles, anything a stranger can view. Then filenames, SVG uploads, markdown renderers, rich-text fields, link labels, and embed URLs.
- Where script is blocked by CSP, test **HTML injection and dangling markup** anyway. That is still reportable.
- Read the CSP: unsafe directives, JSONP endpoints on allowed domains, script gadgets in included libraries.

**A client-side encoder is not a control.** If encoding happens on send, the server stores raw, and any other client that renders it without decoding is still vulnerable. If the client decodes before writing to a sink, that cancels the server's encoding entirely. Check both directions.

**Synthetic clicks never fire `javascript:` URLs.** An automated click on such an href does nothing, which looks exactly like a fixed bug. Test the sink through a control you can drive, then hand the final click to the researcher.

---

## CSRF (test in Chrome)

For every state-changing endpoint:

- Remove the CSRF token entirely. Does it still work?
- Empty token, token from a different session, token from a different endpoint, token with one character changed.
- `Content-Type` swap to `text/plain`, `application/x-www-form-urlencoded`, `multipart/form-data`. Does the body still parse? A JSON-only body parser is the single most common thing standing between a target and a CSRF finding.
- Cross-origin `fetch` with `credentials: 'include'` from the hosted page. Read the CORS response headers; look for a reflected `Origin` with `Access-Control-Allow-Credentials: true`.
- Top-level navigation POST via form submit, tested **separately** from `fetch`. Different cookie rules apply, and a top-level form POST beats browser cookie partitioning that blocks a subresource request.
- An SPA route that mutates on mount from query parameters alone defeats `SameSite=Lax`, because a top-level navigation carries the cookie and the mutation needs no POST at all. Look for these specifically.

**Check `Secure` and `SameSite` before building any CORS theory.** No `Secure` flag means the cookie cannot be `SameSite=None`, which means it is `Lax`, which means the credentialed cross-origin read is dead no matter what the CORS headers say.

Every confirmed CSRF gets a working `poc.html` on the HTTPS ngrok URL, opened in the second principal's browser, with the state change verified visually.

Forced logout and forced login are out of scope; see `CLAUDE.md`.

---

## Open redirect, CRLF, header injection

Every `url`, `next`, `continue`, `redirect`, `redirect_uri`, `return_to`, `returnUrl`, `callback`, `dest`, `goto`, `u`, `r` parameter. Then ask the question that decides severity: **can the redirect carry a token** in the query or the fragment?

Bypass shapes worth trying against any allowlist: `//evil.test`, `https:/\evil.test`, `https://target.com@evil.test`, `https://target.com.evil.test`, `https://evil.test%23@target.com`, a path-relative `/\/evil.test`, and double encoding.

**Protocol-blind guards.** A check that validates only the hostname passes `javascript://target.com/%0a<payload>`. Confirm whether the caller uses the guard's return value or the raw input; passing the check and being used are different things.

**Denylist plus normaliser.** An exact-match denylist on a key combined with a consumer that strips a prefix is a bypass: re-insert the stripped prefix and the denylist misses it.

CRLF: `%0d%0a` and its encodings in any parameter reflected into a response header, any URL parameter, any filename. Look for header splitting and response splitting.

For OAuth specifically: test `redirect_uri` for prefix matching rather than exact matching, and test whether `state` is validated at all. Both have produced High findings.

---

## SSRF

Any parameter accepting a URL, hostname, IP or file reference: image proxies, thumbnail generators, link previews, webhooks, integrations, import-from-URL, avatar-from-URL, PDF renderers, HTML-to-image, RSS readers.

- Confirm with an out-of-band callback you control. **No callback, no finding.**
- Before concluding a callback is blind, check that your listener accepts the method the target actually sends. A "blind" SSRF is often just a listener rejecting `POST`.
- Redirect-based: point the target at a URL you control that `302`s to the internal address.
- DNS rebinding, decimal and hex IP encodings, `[::]`, `0.0.0.0`, `127.1`, and the cloud metadata endpoints.
- A server-side fetcher that follows redirects but only reaches public hosts is not SSRF. Say so and move on.

---

## File handling

- Extension, MIME and magic-byte bypass, independently and in combination.
- SVG containing script. Test whether it is served inline or with `Content-Disposition: attachment`.
- Polyglots: a valid image that is also valid HTML or JS.
- Path traversal in the filename, and in export and thumbnail paths.
- Where do uploads land, what origin serves them, and is that origin sandboxed? An upload rendered on the primary origin is worth far more than one on a separate CDN host.
- Overwrite another object's file by reusing its identifier or path.

---

## Race conditions

Every operation with a limit, a counter, a one-time token, or a uniqueness constraint: invites, redemptions, quota consumption, seat allocation, one-time links, coupon codes, balance transfers, email verification, rate-limited actions.

Fire 20 or more parallel requests, not clicks. Use single-packet or last-byte synchronisation where the tooling allows. Confirm by reading the resulting state, not by reading the responses.

---

## Cache poisoning and deception

Unkeyed headers (`X-Forwarded-Host`, `X-Forwarded-Scheme`, `X-Original-URL`, `X-Rewrite-URL`), extension-based caching (`/settings.css`, `/settings.js`), path confusion (`/settings/..%2fstatic`), and fat GET. Check the `Cache-Control`, `Age`, `X-Cache` and `Vary` headers on every response before theorising.

---

## Information disclosure

- **Diff the API response against what the UI renders**, for every read endpoint. Over-fetching is the most common real finding in this column.
- Error messages, stack traces, internal hostnames, framework debug pages.
- Debug parameters: `?debug=1`, `?alt=json`, `?pretty`, `?format=json`, `?raw=1`, `?fields=*`, `?expand=all`, `?include=`.
- Cross-origin leaks: does response size, timing, status code or frame count differ based on the other principal's state? Existence oracles and XS-Leaks.
- Referrer leakage of tokens to third-party origins. Check `Referrer-Policy` and then check what is actually in the URL.
- An identifier leaked in a `Referer` header, or a `userId` that maps to an email through any other endpoint, is a chain link worth keeping.

**A secret that only reaches the target's own analytics, error tracker or ad platform is not a finding.** The attacker cannot read that destination. Say so and move on.
