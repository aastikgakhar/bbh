"""Stop: the gate. Block the stop while actionable work is open; allow it when the
kill switch (.bbh/STOP) or the soft stop (.bbh/PAUSE) is set, when the ledger is
unreachable (we cannot guard what we cannot read), when nothing is open, or when
the no-progress guard trips (blocked GUARD_LIMIT times in a row with no drop in the
open-work total between attempts). Respects stop_hook_active so it never recurses.

Two deliberate escapes, because the field report showed this gate was the single
biggest token sink when it fired every turn and could not be satisfied:
 - progress is measured as the open-work TOTAL dropping, not as any event firing, so
   a background fleet closing one cell while the re-ingest loop opens two does not
   reset the guard forever;
 - .bbh/PAUSE lets the agent end a session cleanly (board is done, or only blocked/
   n_a work with reasons remains) without the .bbh/STOP kill switch's tool lockout."""

from __future__ import annotations

import json
import time

import _hooklib as h

GUARD_LIMIT = 3


def body(data, root):
    if (root / ".bbh" / "STOP").exists():
        return  # kill switch: allow the stop (exit 0, no block)
    if (root / ".bbh" / "PAUSE").exists():
        # soft stop: the agent or researcher asked to end cleanly. Unlike STOP it blocks no tools;
        # it only releases this gate. Remove the file to re-engage the gate.
        try:
            h.open_ledger(root).event("gate.allowed", detail={"reason": ".bbh/PAUSE soft stop"})
        except Exception:  # noqa: BLE001
            pass
        return

    try:
        led = h.open_ledger(root)
        configured = bool(led.engagement().get("configured"))
    except Exception:  # noqa: BLE001
        return  # the ledger / MCP server is unreachable: we cannot guard what we cannot read, so allow
    if not configured:
        return  # nothing configured, nothing to guard

    from bbh import tasks

    work = tasks.open_work(led)
    if work["total"] == 0:
        _reset_guard(led)
        led.event("gate.allowed", detail={"reason": "no open work"})
        return  # allow

    # no-progress guard: the escape hatch. Progress means the open-work TOTAL actually dropped
    # since the last blocked attempt, not merely that some event fired. A background fleet closing
    # one cell while the re-ingest loop opens two is NOT progress and must not reset the counter,
    # or the gate blocks every turn forever (the biggest token sink in the field report).
    state = led.kv_get("stop_guard", {"blocks": 0, "last_total": -1}) or {"blocks": 0, "last_total": -1}
    prev_total = state.get("last_total", -1)
    if prev_total < 0 or work["total"] < prev_total:
        state = {"blocks": 0, "last_total": work["total"]}  # first block, or the total really dropped: reset

    state["blocks"] = state.get("blocks", 0) + 1
    state["last_total"] = work["total"]
    led.kv_set("stop_guard", state)

    if state["blocks"] > GUARD_LIMIT:
        # blocked GUARD_LIMIT times in a row with no drop in the total; stop fighting it
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
              "The matrix is the definition of done. To end cleanly right now — the board is done, or only "
              "blocked/n_a work with reasons remains — create .bbh/PAUSE (a soft stop that blocks no tools). "
              "For an emergency brake on all network traffic, touch .bbh/STOP. Otherwise this gate allows the "
              "stop after {} attempts in a row where the open-work total does not drop.").format(
        summary, "\n".join("  - " + t for t in titles) or "  - call next_task()", GUARD_LIMIT)
    h.stop_block(reason)


def _reset_guard(led):
    # last_total = -1 re-baselines on the next block, so a fresh run of attempts starts clean.
    led.kv_set("stop_guard", {"blocks": 0, "last_total": -1})


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
