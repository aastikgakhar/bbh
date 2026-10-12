"""Stop: the gate. Block the stop while work is open; allow it when the kill switch
is set, when nothing is open, or when the no-progress guard trips (blocked three
times in a row with zero new progress events between attempts). Respects
stop_hook_active so it never recurses forever."""

from __future__ import annotations

import json
import time

import _hooklib as h

GUARD_LIMIT = 3


def body(data, root):
    if (root / ".bbh" / "STOP").exists():
        return  # kill switch: allow the stop (exit 0, no block)

    led = h.open_ledger(root)
    if not led.engagement().get("configured"):
        return  # nothing configured, nothing to guard

    from bbh import tasks

    work = tasks.open_work(led)
    if work["total"] == 0:
        _reset_guard(led)
        led.event("gate.allowed", detail={"reason": "no open work"})
        return  # allow

    # no-progress guard: track consecutive blocks and the last progress event id
    last_progress = led.last_progress_event_id()
    state = led.kv_get("stop_guard", {"blocks": 0, "last_progress_event": -1}) or {"blocks": 0, "last_progress_event": -1}
    if last_progress != state.get("last_progress_event"):
        # progress was made since the last block attempt: reset the counter
        state = {"blocks": 0, "last_progress_event": last_progress}

    state["blocks"] = state.get("blocks", 0) + 1
    state["last_progress_event"] = last_progress
    led.kv_set("stop_guard", state)

    if state["blocks"] >= GUARD_LIMIT:
        _write_stuck(led, root, work)
        _reset_guard(led)
        led.event("gate.allowed", detail={"reason": "no-progress guard", "blocks": state["blocks"]})
        return  # allow the stop; the researcher sees .bbh/stuck.md

    # block with the next three tasks
    titles = []
    seen = set()
    for _ in range(6):
        t = tasks.next_task(led, peek=True)
        if not t or t.title in seen:
            break
        seen.add(t.title)
        titles.append(f"[{t.kind}] {t.title}")
        if len(titles) >= 3:
            break
    summary = (f"open cells {work['open_cells']}, candidates {work['candidates']}, "
               f"draft findings {work['draft_findings']}, verified-without-report {work['verified_without_report']}, "
               f"reports untriaged {work['reports_untriaged']}, depth {work['open_depth']}")
    led.event("gate.blocked", detail={"attempt": state["blocks"], "work": work["total"]})
    reason = ("bbh: work is still open ({}). Do the next tasks, then stop:\n{}\n"
              "The matrix is the definition of done. If you are genuinely stuck, touch .bbh/STOP to stop, "
              "or this gate will allow the stop after {} blocked attempts with no progress.").format(
        summary, "\n".join("  - " + t for t in titles) or "  - call next_task()", GUARD_LIMIT)
    h.stop_block(reason)


def _reset_guard(led):
    led.kv_set("stop_guard", {"blocks": 0, "last_progress_event": led.last_progress_event_id()})


def _write_stuck(led, root, work):
    from bbh import tasks

    lines = ["# bbh: session stalled", "",
             f"The stop gate allowed a stop after {GUARD_LIMIT} blocked attempts with no new progress.",
             "", "## Open work at stop", json.dumps(work, indent=1), "", "## Next tasks the agent did not do"]
    seen = set()
    for _ in range(8):
        t = tasks.next_task(led, peek=True)
        if not t or t.title in seen:
            break
        seen.add(t.title)
        lines.append(f"- [{t.kind}] {t.title}")
    lines += ["", "Resume by addressing these, or review the ledger in .bbh/ledger.db and feature-matrix.md."]
    try:
        led.paths.stuck.write_text("\n".join(lines) + "\n", encoding="utf-8")
    except Exception:  # noqa: BLE001
        pass


h.run("stop_gate", body)
