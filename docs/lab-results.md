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

`reached reportable rung` is the real verdict: a cell can be a weak `candidate` from a sub-reportable signal (e.g. a SQL error-differential on decoy D2) without ever reaching a reportable finding, which is the methodology working, not a false positive.

| bug | class | expected | cell state | reached reportable rung |
|---|---|---|---|---|
| 10 | htmli_stored | confirmed | candidate | True |
| 10 | xss_stored | negative | open | False |
| 1 | csti | negative | open | False |
| 1 | htmli | confirmed | candidate | True |
| 1 | ssti | negative | open | False |
| 1 | xss_reflected | negative | open | False |
| 2 | csti | negative | open | False |
| 2 | htmli | negative | open | False |
| 2 | ssti | confirmed | candidate | True |
| 2 | xss_reflected | negative | open | False |
| 3 | sqli | confirmed | candidate | True |
| 4 | nosqli | confirmed | candidate | True |
| 5a | idor_read | confirmed | candidate | True |
| 5b | idor_write | confirmed | candidate | True |
| 6 | idor_write | negative | open | False |
| 7 | csrf | confirmed | candidate | True |
| 8 | open_redirect | confirmed | candidate | True |
| 9 | mass_dump | confirmed | candidate | True |
| D1 | htmli | negative | open | False |
| D1 | xss_reflected | negative | open | False |
| D2 | sqli | negative | open | False |
| D3 | open_redirect | negative | open | False |

## Ledger counts at end

```
{
 "open": 146,
 "in_progress": 0,
 "negative": 0,
 "candidate": 9,
 "confirmed": 1,
 "n_a": 1,
 "blocked": 0
}
```

## How recall/precision are measured
A planted bug counts as detected when the harness records a positive case (the cell becomes a candidate) for the expected class on the expected endpoint. A decoy or sibling counts as a false confirmation if its class goes positive. Every cell the harness closed `negative` is queried to prove it carries at least 10 executed negative cases and a passing control. The IDOR is taken the whole way to a verified, reported, reproducible finding (the 60s verification gap is advanced with a fake clock while both replays really hit the lab).
