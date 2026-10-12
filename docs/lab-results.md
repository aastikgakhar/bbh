# bbh lab results

Run against the planted-bug lab (10 bugs, 3 decoys) with the real harness modules.

## Scorecard

- Recall (planted bugs detected): **10/10** (target 10/10)
- False confirmations on decoys/siblings: **0** (target 0)
- Negatives missing the 10-case+control evidence: **0** (target 0)
- Sibling independence bug 1 (/search: HTMLi yes, XSS/SSTI/CSTI no): **True**
- Sibling independence bug 2 (/greet: SSTI yes, HTMLi/XSS no): **True**
- Full lifecycle (verify x2 + report + repro) on the IDOR: **True**
- Stop gate blocks while work is open: **True**
- Overall: **PASS**

## Per-class detail

| bug | class | expected | harness verdict |
|---|---|---|---|
| 10 | htmli_stored | confirmed | candidate |
| 10 | xss_stored | negative | open |
| 1 | csti | negative | open |
| 1 | htmli | confirmed | candidate |
| 1 | ssti | negative | open |
| 1 | xss_reflected | negative | open |
| 2 | csti | negative | open |
| 2 | htmli | negative | open |
| 2 | ssti | confirmed | candidate |
| 2 | xss_reflected | negative | open |
| 3 | sqli | confirmed | candidate |
| 4 | nosqli | confirmed | candidate |
| 5a | idor_read | confirmed | candidate |
| 5b | idor_write | confirmed | candidate |
| 6 | idor_write | negative | open |
| 7 | csrf | confirmed | candidate |
| 8 | open_redirect | confirmed | candidate |
| 9 | mass_dump | confirmed | candidate |
| D1 | htmli | negative | open |
| D1 | xss_reflected | negative | open |
| D2 | sqli | negative | candidate |
| D3 | open_redirect | negative | open |

## Ledger counts at end

```
{
 "open": 143,
 "in_progress": 0,
 "negative": 0,
 "candidate": 10,
 "confirmed": 1,
 "n_a": 1,
 "blocked": 0
}
```

## How recall/precision are measured
A planted bug counts as detected when the harness records a positive case (the cell becomes a candidate) for the expected class on the expected endpoint. A decoy or sibling counts as a false confirmation if its class goes positive. Every cell the harness closed `negative` is queried to prove it carries at least 10 executed negative cases and a passing control. The IDOR is taken the whole way to a verified, reported, reproducible finding (the 60s verification gap is advanced with a fake clock while both replays really hit the lab).
