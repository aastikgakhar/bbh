"""Report lint and the stop-gate / next_task priority."""

import pytest

from bbh import tasks
from bbh.lint import lint_text
from conftest import make_capture

GOOD = """# IDOR: any note readable across accounts via the numeric id

| | |
|---|---|
| Account A (attacker) | `a` |

## Summary

Account A reads Account B's private note by changing the numeric id in the path, because the server runs no owner check on the endpoint, so any authenticated user reads any note.

## Steps to Reproduce

**As the attacker**

Step 1: send the request below as Account A.

```http
GET /api/notes/3 HTTP/1.1
Host: x
Cookie: <replace with your session cookie>
```

```http
HTTP/1.1 200 OK

{"owner":"bob","content":"secret"}
```

The response holds Account B's note.

## Root Cause

The endpoint resolves the note by id with no check that it belongs to the caller.
"""


def test_clean_report_passes():
    assert lint_text(GOOD).ok


def test_banned_words_caught():
    for w in ("could", "may", "potentially", "should", "might", "seems"):
        txt = GOOD.replace("so any authenticated user reads any note.", f"this {w} let an attacker read notes.")
        res = lint_text(txt)
        assert not res.ok and any(w in p for p in res.problems), w


def test_long_dash_caught():
    assert not lint_text(GOOD.replace("no owner check", "no owner check — none")).ok


def test_numbered_list_steps_caught():
    bad = GOOD.replace("Step 1: send the request below as Account A.", "1. send the request below as Account A.")
    assert not lint_text(bad).ok


def test_victim_section_cannot_hold_raw_http():
    bad = GOOD + "\n**As the victim**\n\nStep 2: the victim logs in.\n\n```http\nGET /x HTTP/1.1\n```\n"
    res = lint_text(bad)
    assert not res.ok and any("victim section" in p for p in res.problems)


def test_victim_console_mention_caught():
    bad = GOOD + "\n**As the victim**\n\nStep 2: the victim opens the browser console and runs the snippet.\n"
    assert not lint_text(bad).ok


def test_concrete_email_caught():
    assert not lint_text(GOOD.replace("Account B's private note", "victim@gmail.com's private note")).ok


def test_extra_bold_caught():
    assert not lint_text(GOOD.replace("no owner check", "**no** owner check")).ok


def test_cite_check_missing_capture(tmp_path):
    txt = GOOD + "\nEvidence: `captures/does-not-exist.http`\n"
    res = lint_text(txt, root=tmp_path)
    assert not res.ok and any("does not exist" in p for p in res.problems)


def test_cross_site_needs_poc(tmp_path):
    txt = GOOD.replace("IDOR", "CSRF")
    res = lint_text(txt, root=tmp_path, cross_site=True)
    assert not res.ok and any("poc.html" in p for p in res.problems)


# --- stop gate / next_task -------------------------------------------------------------------

def test_open_work_counts_everything(ledger, eng):
    (eng.captures / "session-A.txt").write_text("Cookie: lab_session=AAA\n")
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/x")
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="q", location="query", sample_value="1")
    ledger.open_cell(endpoint_id=eid, input_id=iid, vuln_class="htmli")
    w = tasks.open_work(ledger)
    assert w["open_cells"] >= 1 and w["total"] >= 1


def test_stop_gate_allows_when_empty(ledger):
    w = tasks.open_work(ledger)
    assert w["total"] == 0  # nothing opened


def test_next_task_returns_recon_when_idle(ledger):
    t = tasks.next_task(ledger, peek=True)
    assert t.kind == "recon"
