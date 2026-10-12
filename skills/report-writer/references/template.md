# Report skeleton

Copy everything below the line into `report-N.md` and fill it in. Angle brackets are placeholders. The parenthesised notes are constraints, delete them as you go.

Remember: every paragraph on one long line, `Step N:` as literal text, raw HTTP inline, no long dashes, no banned words.

---

# \<Title, 10 to 15 words, plain language mixed with technical. What breaks, and what the attacker gains.\>

| | |
|---|---|
| Account A (attacker) | `<account id>` |
| Account B (victim) | `<account id>` |
| Affected host | `<host>` |
| Severity | `<Low / Medium / High / Critical>` |
| CWE | `CWE-xx, CWE-XX` |
## Summary

\<Around 100 words, one unwrapped paragraph. The first two sentences must be readable by a non-technical programme manager: what an attacker does, and to whom. The rest gives the mechanism: which endpoint, which control is missing, why it works. No hedging, no banned words.\>

## Prerequisites

- \<10 to 15 words. As few as possible.\>
- \<10 to 15 words.\>
- \<10 to 15 words. Three lines maximum.\>

## Attack Scenario

- \<20 to 25 words. A concrete situation in which this is used, with no victim cooperation.\>
- \<20 to 25 words.\>
- \<Optional third.\>

## Steps to Reproduce

**As the attacker**

Step 1: \<20 to 25 words. Concrete action, exact URL or exact button label.\>

```http
<verbatim request: request line, Host, Content-Type, Authorization or Cookie shown as
Cookie: <replace with your session cookie>, then the body>
```

```http
<verbatim response: status line, two or three relevant headers, body>
```

\<One line saying what just changed.>

Step 2: \<20 to 25 words.\>

```http
<request>
```

```http
<response>
```

\<One line on the effect.>

Step 3: \<20 to 25 words.\>

**As the victim**

Step 4: \<20 to 25 words. This is where the effect is shown landing on the other account. Visit the example.com/x\>

Note: A victim step must not contain a Burp request or raw HTTP block. The victim should only need to perform the exact browser action required to trigger the issue.

Step 5: \<Optional. Four to six steps total, no more.\>

\<For a cross-site finding, add this line: Host the attached `poc.html` on an HTTPS domain and open it in Account B's browser. The file must be attached.\>

## Root Cause

\<The actual mechanism, in as few words as it takes. Which check is missing, where it should have been, and why the server accepts what it accepts. One unwrapped paragraph.\>

## Impact

As an attacker, I could:

- \<15 to 20 words.\>
- \<15 to 20 words.\>
- \<15 to 20 words.\>

## Attachments

- `poc.html` \<for cross-site findings, required\>
- `<demo video filename>` \<where the effect is visual researcher will create it himself\>