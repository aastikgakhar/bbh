"""SubagentStop: if a class-tester subagent leaves a cell claimed with no verdict,
block once with the completion criteria; on the second attempt release the claim
so a dead subagent never strands a cell."""

from __future__ import annotations

import _hooklib as h


def body(data, root):
    agent_type = data.get("agent_type", "")
    if agent_type not in ("bbh:class-tester", "class-tester"):
        return
    agent_id = data.get("agent_id", "")
    led = h.open_ledger(root)
    if not led.engagement().get("configured"):
        return
    rows = led.q("SELECT id, vuln_class FROM cells WHERE state='in_progress' AND claimed_by = ?", (agent_id,))
    if not rows:
        return
    if data.get("stop_hook_active"):
        # second pass: do not strand the cell, release it with a note
        for r in rows:
            try:
                led.release_cell(r["id"], note=f"class-tester {agent_id} stopped without closing it")
            except Exception:  # noqa: BLE001
                pass
        return
    first = rows[0]
    ev = led.evidence_status(first["id"])
    miss = "; ".join(ev["missing"][:3]) if ev["missing"] else "close it negative, or open_finding if a case went positive"
    h.stop_block(f"bbh: you still hold cell {first['id']} ({first['vuln_class']}) and {len(rows)-1} other(s) open. "
                 f"Finish cell {first['id']} (to close negative: {miss}) or release_cell it, then stop.")


h.run("subagent_stop", body)
