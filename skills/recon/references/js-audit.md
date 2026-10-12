# Reading the JS line by line

Use this when no source map was available, and as the checklist for agent briefs when one was.

## What to look for

**Sinks.** `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval`, `new Function`, `setTimeout`/`setInterval` with a string, `dangerouslySetInnerHTML`, `v-html`, `$.html()`, template compilation, `srcdoc`, `iframe.src`, `location`/`location.href`/`location.replace` assignment, `window.open`, `history.pushState`, dynamic `import()`, `script.src` assignment, `postMessage` targets.

For each sink, **trace back to the source**. A sink fed by a constant is nothing. A sink fed by `location.hash`, `location.search`, `document.referrer`, `postMessage` data, a URL path segment, localStorage, or an API response field that another user controls is a test case. Write the chain into `js-inventory.md`, do not guess it.

**postMessage.** Every `addEventListener("message", ...)` and every `.postMessage(...)`. For each listener record the origin check verbatim. A missing check, a check using `indexOf` or `includes` or `startsWith`, or a check against a regex with an unescaped dot, are all bypassable. Then ask the question that decides whether it is worth anything: **does data go out, or does an injected identity get honoured?** A listener that only accepts inbound data and changes local UI state is worth nothing. Run the counter-read before writing anything up.

**Endpoints.** Every URL, every path template, every base URL constant. Include the ones no UI element calls: admin routes, internal routes, `/v1` when the app uses `/v2`, debug routes, feature-flagged routes. Each goes into `state.csv` as `pending`.

**Client-side authorization.** Anything shaped like `if (user.role === ...)`, `hasPermission(...)`, `canEdit`, `isAdmin`, `disabled={!...}`, or a route guard. Every one of these is a server-side test case: call the endpoint it guards, with the guard's condition false. Where the client is the only enforcement, that is the finding.

**Validation regexes.** Copy each out verbatim and run it locally in Python or Node against bypass candidates. Do not reason about a regex in your head. Offline execution proves a bypass with no session, no rate limit, and no WAF.

**Feature flags and config.** Flag names, default values, and where they are read. A flag read from a query parameter or localStorage is a direct switch. Flags also tell you which features exist but are not yet visible.

**Secrets and infrastructure.** API keys, bucket names, internal hostnames, analytics IDs, third-party project IDs. Judge each by whether **the attacker can read the destination**. A key that only writes into the target's own analytics, error tracker, or ad platform is not a finding, because the attacker cannot get the data back out. A key that grants read access to a third-party API is.

**Third-party SDK versions.** Note each version and check for known CVEs affecting that exact version. Also check for script gadgets in included libraries that turn an HTML injection into script execution under a strict CSP.

**Old bundles.** Burp history holds bundle hashes from earlier in the session and from the researcher's own browsing. Diff an old bundle against the current one: removed checks, renamed endpoints, and deprecated-but-still-live routes are all visible in the delta.

## Obfuscated bundles

If the bundle was run through `javascript-obfuscator`, it is fully reversible: the string array, the rotation function and the decoder are all present in the file. Recover it before reading.

Substitution must be **alias-aware**. The decoder gets aliased to local names throughout the file, and substituting only the original name catches a fraction of the references. On one past bundle, name-only substitution resolved 4,277 references while alias-aware substitution resolved 16,953. Resolve every alias chain first, then substitute.

## What to do with the output

Every item lands in `js-inventory.md` in this shape, one line each:

```
path:line | what it is | hypothesis to test | state.csv id
```

A line with no hypothesis is not finished. A hypothesis with no `state.csv` row will never get tested.
