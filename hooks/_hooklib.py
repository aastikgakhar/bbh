"""Shared helpers for the bbh hooks. Stdlib only, fail-open, fast.

Every hook: read JSON from stdin, locate the engagement from `cwd`, open the
ledger with a short busy timeout, do its work within ~1.8 s, and on any error
append to .bbh/hook.log and exit 0 producing no output. The two exceptions are
the scope guard and the kill switch, which still deny when they cannot load the
ledger (failing open there would defeat the control).
"""

from __future__ import annotations

import json
import os
import sys
import time
import traceback
from pathlib import Path

DEADLINE_S = 1.8


def _server_on_path():
    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if root:
        server = str(Path(root) / "server")
        if server not in sys.path:
            sys.path.insert(0, server)
    # dev fallback: this file is hooks/_hooklib.py; server/ is a sibling
    here = Path(__file__).resolve().parents[1] / "server"
    if here.is_dir() and str(here) not in sys.path:
        sys.path.insert(0, str(here))


def read_input() -> dict:
    try:
        return json.loads(sys.stdin.read() or "{}")
    except Exception:  # noqa: BLE001
        return {}


def engagement_dir(data: dict) -> Path:
    cwd = data.get("cwd") or os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    _server_on_path()
    try:
        from bbh.paths import find_engagement_dir

        return find_engagement_dir(cwd)
    except Exception:  # noqa: BLE001
        p = Path(cwd)
        for d in (p, *p.parents):
            if (d / ".bbh").is_dir() or (d / "prompt.md").is_file():
                return d
        return p


def is_engagement(root: Path) -> bool:
    return (root / ".bbh").is_dir() or (root / "prompt.md").is_file()


def log(root: Path, hook: str, message: str) -> None:
    try:
        (root / ".bbh").mkdir(parents=True, exist_ok=True)
        with (root / ".bbh" / "hook.log").open("a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{hook}] {message}\n")
    except Exception:  # noqa: BLE001
        pass


def open_ledger(root: Path):
    _server_on_path()
    from bbh import config
    from bbh.ledger import Ledger

    led = Ledger(root, busy_timeout_ms=1200)
    try:
        cfg = config.load(root / "prompt.md")
        led.sync_engagement(cfg)
    except Exception:  # noqa: BLE001
        pass
    return led


# --- output helpers ------------------------------------------------------------------------

def emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def session_context(text: str) -> None:
    emit({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}})


def post_context(text: str) -> None:
    emit({"hookSpecificOutput": {"hookEventName": "PostToolUse", "additionalContext": text}})


def deny(reason: str) -> None:
    emit({"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason}})


def stop_block(reason: str) -> None:
    emit({"decision": "block", "reason": reason})


def run(hook_name: str, fn) -> None:
    """Run a hook body with a hard fail-open wrapper. fn(data, root, led) -> None.
    fn opens the ledger itself when it needs one (the scope/kill hooks do not)."""
    data = read_input()
    root = None
    try:
        root = engagement_dir(data)
        if not is_engagement(root):
            sys.exit(0)
        fn(data, root)
    except SystemExit:
        raise
    except Exception as exc:  # noqa: BLE001
        if root is not None:
            log(root, hook_name, f"{type(exc).__name__}: {exc}\n{traceback.format_exc()[:800]}")
    sys.exit(0)
