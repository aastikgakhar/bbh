"""PreCompact: render the generated views and write a short handoff so nothing is
lost across compaction. Cannot block compaction; it just persists state."""

from __future__ import annotations

import json
import time

import _hooklib as h


def body(data, root):
    led = h.open_ledger(root)
    if not led.engagement().get("configured"):
        return
    try:
        from bbh import render

        render.render_views(led)
    except Exception as exc:  # noqa: BLE001
        h.log(root, "pre_compact", f"render_views: {exc}")

    from bbh import tasks

    counts = led.counts()
    work = tasks.open_work(led)
    lines = ["# bbh handoff (written before compaction)", "",
             f"written {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
             "## State", json.dumps({"cells": counts["cells"], "findings": counts["findings"],
                                     "depth": counts["depth"], "open_work": work}, indent=1), ""]
    cands = led.q("SELECT id, vuln_class, endpoint_id FROM cells WHERE state='candidate' ORDER BY id")
    if cands:
        lines.append("## Open candidates")
        for r in cands:
            lines.append(f"- cell {r['id']} {r['vuln_class']} (endpoint {r['endpoint_id']})")
        lines.append("")
    claimed = led.q("SELECT id, vuln_class, claimed_by FROM cells WHERE state='in_progress'")
    if claimed:
        lines.append("## In progress")
        for r in claimed:
            lines.append(f"- cell {r['id']} {r['vuln_class']} (claimed by {r['claimed_by']})")
        lines.append("")
    lines.append("## Next tasks")
    seen = set()
    for _ in range(6):
        t = tasks.next_task(led, peek=True)
        if not t or t.title in seen:
            break
        seen.add(t.title)
        lines.append(f"- [{t.kind}] {t.title}")
    try:
        led.paths.handoff.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception as exc:  # noqa: BLE001
        h.log(root, "pre_compact", f"handoff write: {exc}")


h.run("pre_compact", body)
