"""SessionStart: sync prompt.md into the ledger and inject the engagement brief,
coverage numbers, open candidates and the next task. This is what keeps focus
after context compaction (source=compact)."""

from __future__ import annotations

import _hooklib as h


def body(data, root):
    source = data.get("source", "startup")
    led = h.open_ledger(root)
    eng = led.engagement()
    lines = ["=== bbh engagement ledger ==="]
    if not eng.get("configured"):
        lines.append("prompt.md is not filled in yet. Fill the fields at the top, then say go.")
        for p in (eng.get("problems") or [])[:6]:
            lines.append(f"  - {p}")
        h.session_context("\n".join(lines))
        return
    scope = ", ".join(eng.get("scope") or [])
    lines.append(f"Target: {eng.get('target')}  |  scope: {scope}  |  programme: {eng.get('programme')}  |  rate: {eng.get('rate_limit_rps')}/s")
    oos = eng.get("oos_notes") or []
    if oos:
        lines.append("Out of scope (notes): " + "; ".join(oos[:4]))
    if eng.get("marker_header"):
        lines.append(f"Marker header: {eng['marker_header'][0]} (send exactly this, nothing else identifying)")
    if led.paths.stop_requested():
        lines.append("KILL SWITCH IS ON (.bbh/STOP present): every send is refused and the session may stop.")

    from bbh import tasks

    counts = led.counts()
    c = counts["cells"]
    lines.append(f"Coverage: {counts['cells_total']} cells "
                 f"(open {c['open']}, in_progress {c['in_progress']}, candidate {c['candidate']}, "
                 f"negative {c['negative']}, confirmed {c['confirmed']}, blocked {c['blocked']}, n/a {c['n_a']}); "
                 f"findings {counts['findings']}; endpoints {counts['endpoints']}; depth open {counts['depth']['open']}")
    cands = led.q("SELECT id, vuln_class, endpoint_id FROM cells WHERE state='candidate' ORDER BY id LIMIT 8")
    if cands:
        lines.append("Open candidates (resolve first): " + ", ".join(f"cell {r['id']} {r['vuln_class']}(ep{r['endpoint_id']})" for r in cands))
    work = tasks.open_work(led)
    nxt = tasks.next_task(led, peek=True)
    if nxt:
        lines.append(f"NEXT TASK [{nxt.kind}]: {nxt.title}")
        comp = (nxt.detail or {}).get("completion")
        if comp and comp.get("to_close_negative"):
            lines.append("  to close negative: " + "; ".join(comp["to_close_negative"][:2]))
    lines.append("Call next_task() for the claimed unit of work and its cases. Work on what it returns. "
                 "Every class on every input is its own verdict; a negative needs 10 cases + a control.")
    if source == "compact" and led.paths.handoff.exists():
        lines.append(f"(resumed after compaction; see {led.paths.rel(led.paths.handoff)})")
    text = "\n".join(lines)
    if len(text) > 4000:
        text = text[:4000]
    h.session_context(text)


h.run("session_start", body)
