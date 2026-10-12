"""Drive the real hook scripts via subprocess with crafted stdin. Proves the
scope guard, kill switch, SessionStart injection, report lint, and the stop
gate's three exit conditions (STOP file, no open work, no-progress guard)."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

HOOKS = Path(__file__).resolve().parents[2] / "hooks"
SERVER = Path(__file__).resolve().parents[1]

PROMPT = """## Target
- **Asset:** `Lab`
- **Scope:** `127.0.0.1:5057`
## Accounts
| Role | Account | Browser | MCP |
|---|---|---|---|
| A, attacker | `a@lab.test` | Chrome | `m` |
- **Burp proxy:** `none`
- **Burp MCP:** `none`
"""


def run_hook(script, payload, root, plugin_root=None):
    env = dict(os.environ)
    env["CLAUDE_PLUGIN_ROOT"] = str(plugin_root or HOOKS.parent)
    env["PYTHONPATH"] = str(SERVER) + os.pathsep + env.get("PYTHONPATH", "")
    env.pop("BBH_ENGAGEMENT_DIR", None)
    env.pop("CLAUDE_PROJECT_DIR", None)  # isolation: the hook must key off the payload cwd, not a leaked project dir
    p = subprocess.run([sys.executable, str(HOOKS / script)], input=json.dumps(payload).encode(),
                       capture_output=True, env=env, timeout=30)
    out = p.stdout.decode("utf-8", "replace").strip()
    try:
        return json.loads(out) if out else {}, p.returncode, p.stderr.decode("utf-8", "replace")
    except json.JSONDecodeError:
        return {"_raw": out}, p.returncode, p.stderr.decode("utf-8", "replace")


@pytest.fixture
def eng(tmp_path):
    root = tmp_path / "eng"
    root.mkdir()
    (root / "prompt.md").write_text(PROMPT, encoding="utf-8")
    (root / ".bbh").mkdir()
    return root


def _mk_ledger(root):
    sys.path.insert(0, str(SERVER))
    from bbh import config
    from bbh.ledger import Ledger
    from bbh.paths import Paths
    led = Ledger(Paths(root).ensure())
    led.sync_engagement(config.load(root / "prompt.md"))
    return led


# --- scope guard -------------------------------------------------------------------------

def test_pre_tool_denies_out_of_scope_webfetch(eng):
    out, rc, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "tool_name": "WebFetch",
                                                "tool_input": {"url": "https://example.com/"}}, eng)
    hso = out.get("hookSpecificOutput", {})
    assert hso.get("permissionDecision") == "deny" and "out of scope" in hso.get("permissionDecisionReason", "")


def test_pre_tool_allows_in_scope(eng):
    out, rc, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "tool_name": "WebFetch",
                                                "tool_input": {"url": "http://127.0.0.1:5057/x"}}, eng)
    assert out == {} and rc == 0  # no deny


def test_pre_tool_denies_file_scheme_navigation(eng):
    out, _, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "tool_name": "mcp__browser-mcp__browser_navigate",
                                               "tool_input": {"url": "file:///etc/passwd"}}, eng)
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def test_pre_tool_denies_browser_tool_in_subagent(eng):
    out, _, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "agent_id": "a1", "agent_type": "bbh:class-tester",
                                               "tool_name": "mcp__browser-mcp__browser_navigate",
                                               "tool_input": {"url": "http://127.0.0.1:5057/x"}}, eng)
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def test_kill_switch_denies_sends(eng):
    (eng / ".bbh" / "STOP").write_text("x")
    out, _, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "tool_name": "mcp__burp__send_http1_request",
                                               "tool_input": {"targetHostname": "127.0.0.1", "targetPort": 5057, "usesHttps": False, "content": "GET / HTTP/1.1"}}, eng)
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def test_report_lint_blocks_bad_report(eng):
    out, _, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "tool_name": "Write",
                                               "tool_input": {"file_path": str(eng / "report-1.md"),
                                                              "content": "# T\n\nThis could potentially allow an attacker to maybe do things."}}, eng)
    hso = out.get("hookSpecificOutput", {})
    assert hso.get("permissionDecision") == "deny" and "lint" in hso.get("permissionDecisionReason", "").lower()


def test_verifier_signoff_denied_to_non_verifier_subagent(eng):
    out, _, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "agent_id": "a1", "agent_type": "bbh:class-tester",
                                               "tool_name": "mcp__plugin_bbh_bbh__verifier_signoff", "tool_input": {}}, eng)
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def test_scope_fails_closed_when_ledger_unreadable(eng):
    # corrupt the ledger so open_ledger raises; the scope guard must still DENY http(s) sends (C3)
    (eng / ".bbh" / "ledger.db").write_bytes(b"not a database" * 100)
    out, _, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "tool_name": "mcp__browser-mcp__browser_navigate",
                                               "tool_input": {"url": "http://evil.test/x"}}, eng)
    hso = out.get("hookSpecificOutput", {})
    assert hso.get("permissionDecision") == "deny" and "could not be read" in hso.get("permissionDecisionReason", "")


def test_kill_switch_still_denies_with_unreadable_ledger(eng):
    (eng / ".bbh" / "ledger.db").write_bytes(b"corrupt" * 100)
    (eng / ".bbh" / "STOP").write_text("x")
    out, _, _ = run_hook("pre_tool_scope.py", {"cwd": str(eng), "tool_name": "WebFetch",
                                               "tool_input": {"url": "http://127.0.0.1:5057/x"}}, eng)
    assert out.get("hookSpecificOutput", {}).get("permissionDecision") == "deny"


def test_non_engagement_dir_is_noop(tmp_path):
    out, rc, _ = run_hook("pre_tool_scope.py", {"cwd": str(tmp_path), "tool_name": "WebFetch",
                                                "tool_input": {"url": "https://example.com/"}}, tmp_path)
    assert out == {} and rc == 0  # no prompt.md / .bbh -> not an engagement -> no-op


# --- session start -----------------------------------------------------------------------

def test_session_start_injects_context(eng):
    _mk_ledger(eng)
    out, _, _ = run_hook("session_start.py", {"cwd": str(eng), "source": "startup"}, eng)
    ctx = out.get("hookSpecificOutput", {}).get("additionalContext", "")
    assert "bbh engagement ledger" in ctx and "127.0.0.1:5057" in ctx and "NEXT TASK" in ctx


# --- stop gate: three exit conditions ----------------------------------------------------

def _open_cell(root):
    led = _mk_ledger(root)
    eid, _ = led.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/x")
    iid, _ = led.upsert_input(endpoint_id=eid, name="q", location="query", sample_value="1")
    led.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")
    led.close()


def test_stop_gate_allows_when_no_open_work(eng):
    _mk_ledger(eng)  # configured, zero cells
    out, _, _ = run_hook("stop_gate.py", {"cwd": str(eng), "stop_hook_active": False}, eng)
    assert out == {}  # allowed


def test_stop_gate_blocks_with_open_work(eng):
    _open_cell(eng)
    out, _, _ = run_hook("stop_gate.py", {"cwd": str(eng), "stop_hook_active": False}, eng)
    assert out.get("decision") == "block" and "open" in out.get("reason", "")


def test_stop_gate_allows_when_kill_switch(eng):
    _open_cell(eng)
    (eng / ".bbh" / "STOP").write_text("x")
    out, _, _ = run_hook("stop_gate.py", {"cwd": str(eng), "stop_hook_active": True}, eng)
    assert out == {}  # kill switch overrides open work


def test_stop_gate_no_progress_guard_allows_after_three(eng):
    _open_cell(eng)
    verdicts = []
    for _ in range(5):
        out, _, _ = run_hook("stop_gate.py", {"cwd": str(eng), "stop_hook_active": True}, eng)
        verdicts.append("block" if out.get("decision") == "block" else "allow")
    # blocked three times in a row (no progress between them), then the 4th attempt is allowed
    assert verdicts[:3] == ["block", "block", "block"] and verdicts[3] == "allow"
    assert (eng / ".bbh" / "stuck.md").is_file()


def test_stop_gate_resets_on_progress(eng):
    _open_cell(eng)
    run_hook("stop_gate.py", {"cwd": str(eng), "stop_hook_active": True}, eng)   # block 1
    run_hook("stop_gate.py", {"cwd": str(eng), "stop_hook_active": True}, eng)   # block 2
    # make progress: close a cell negative is heavy; just append a progress event via a new cell
    led = _mk_ledger(eng)
    eid = led.q1("SELECT id FROM endpoints LIMIT 1")["id"]
    iid2, _ = led.upsert_input(endpoint_id=eid, name="r", location="query", sample_value="1")
    led.open_cell(endpoint_id=eid, input_id=iid2, vuln_class="xss_reflected")  # a new progress event
    led.close()
    out, _, _ = run_hook("stop_gate.py", {"cwd": str(eng), "stop_hook_active": True}, eng)
    # progress since the last block resets the guard, so it blocks again rather than allowing
    assert out.get("decision") == "block"
