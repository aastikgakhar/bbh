"""Detached background worker for the PostToolUse hook: sync Burp, plan new
endpoints, and write .bbh/guidance.json for the next PostToolUse injection.
Runs out of process so the hook never waits on the network.

    python -m bbh.worker ingest
"""

from __future__ import annotations

import json
import sys
import time

from . import config
from .ingest import sync_burp
from .ledger import Ledger
from .paths import Paths
from .planner import plan as plan_endpoint
from .tasks import next_task


def run_ingest() -> dict:
    paths = Paths.discover().ensure()
    led = Ledger(paths)
    led.sync_engagement(config.load(paths.prompt))
    if not led.engagement().get("configured"):
        return {"skipped": "prompt.md not configured"}
    if paths.stop_requested():
        return {"skipped": "kill switch set"}
    try:
        rep = sync_burp(led, max_records=300, budget_s=45)
    except Exception as exc:  # noqa: BLE001
        return {"error": f"{type(exc).__name__}: {exc}"}
    opened = {}
    for eid in rep.new_endpoints:
        try:
            pr = plan_endpoint(led, eid)
            for k, v in pr.opened.items():
                opened[k] = opened.get(k, 0) + v
        except Exception:  # noqa: BLE001
            pass
    top = []
    for _ in range(3):
        t = next_task(led, peek=True)
        if t:
            top.append(t.title)
    guidance = {
        "ts": time.time(),
        "new_endpoints": rep.new_endpoints[:20],
        "new_inputs": len(rep.new_inputs),
        "cells_opened": opened,
        "foreign_skipped": rep.foreign_skipped,
        "top_tasks": top[:3],
    }
    paths.guidance.write_text(json.dumps(guidance), encoding="utf-8")
    return guidance


def main(argv=None):
    argv = argv or sys.argv[1:]
    cmd = argv[0] if argv else "ingest"
    if cmd == "ingest":
        out = run_ingest()
    else:
        out = {"error": f"unknown worker command {cmd!r}"}
    print(json.dumps(out))


if __name__ == "__main__":
    main()
