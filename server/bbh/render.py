"""Generated views and report drafting. Stdlib only.

state.csv, feature-matrix.md, progress.log and findings-summary.md are rendered
from the ledger; the agent never hand-edits them. render_report drafts
report-N.md in the report-writer house format and writes repro/finding-N.sh and
repro/finding-N.json.
"""

from __future__ import annotations

import csv
import io
import json
import re
from pathlib import Path

from . import classes as C
from .httpraw import read_capture

MATRIX_COLUMNS = C.COLUMNS
STATE_TO_MATRIX = {"negative": "tested", "confirmed": "FINDING", "n_a": "n-a", "blocked": "blocked",
                   "candidate": "candidate", "open": "", "in_progress": "wip"}


def _cell_rows(ledger):
    return [dict(r) for r in ledger.q("SELECT * FROM cells")]


def render_state_csv(ledger) -> str:
    out = io.StringIO()
    w = csv.writer(out, lineterminator="\n")
    w.writerow(["id", "method", "url", "endpoint_family", "auth_required", "params", "body_type",
                "tested_classes", "status", "finding_ref", "notes"])
    for ep in ledger.q("SELECT * FROM endpoints ORDER BY id"):
        epd = dict(ep)
        flags = json.loads(epd.get("flags_json") or "{}")
        inputs = ledger.q("SELECT name, location FROM inputs WHERE endpoint_id = ?", (ep["id"],))
        params = ";".join(f"{i['location']}:{i['name']}" for i in inputs)
        cells = ledger.q("SELECT c.vuln_class, c.state, f.report_no AS finding_ref FROM cells c "
                         "LEFT JOIN findings f ON f.cell_id = c.id WHERE c.endpoint_id = ?", (ep["id"],))
        tested = ";".join(sorted({c["vuln_class"] for c in cells if c["state"] not in ("open", "in_progress")}))
        states = {c["state"] for c in cells}
        if "confirmed" in states:
            status = "finding"
        elif states & {"open", "in_progress", "candidate"}:
            status = "pending"
        elif states:
            status = "done"
        else:
            status = "pending"
        finding_refs = sorted({str(c["finding_ref"]) for c in cells if c["finding_ref"]})
        notes = []
        if flags.get("list_endpoint"):
            notes.append("list")
        if not flags.get("auth_required"):
            notes.append("unauth-reachable")
        w.writerow([ep["id"], ep["method"], epd["origin"] + ep["path_template"], ep["family"],
                    "yes" if ep["auth_required"] else ("no" if ep["auth_required"] == 0 else "?"),
                    params, (ep["content_type"] or ""), tested, status,
                    ",".join(finding_refs), " ".join(notes)])
    return out.getvalue()


def render_feature_matrix(ledger) -> str:
    # group cells by feature and matrix column
    features: dict[str, dict[str, list[dict]]] = {}
    for row in ledger.q("SELECT c.*, e.feature AS feature FROM cells c JOIN endpoints e ON e.id = c.endpoint_id"):
        c = dict(row)
        feat = c["feature"] or "(unnamed)"
        col = C.get(c["vuln_class"]).column
        features.setdefault(feat, {}).setdefault(col, []).append(c)
    lines = ["# Feature coverage matrix", "",
             "Generated from the ledger. Cells: `tested` (negative, evidence met), `FINDING-N` (confirmed),",
             "`n-a` (cannot apply), `blocked: reason`, `candidate` (signal, unconfirmed), blank/`wip` (unfinished).", ""]
    header = "| Feature | " + " | ".join(MATRIX_COLUMNS) + " |"
    lines.append(header)
    lines.append("|" + "---|" * (len(MATRIX_COLUMNS) + 1))
    filled = total = 0
    for feat in sorted(features):
        cellmap = features[feat]
        row = [feat]
        for col in MATRIX_COLUMNS:
            items = cellmap.get(col, [])
            if not items:
                row.append("n/a")
                continue
            total += len(items)
            states = [i["state"] for i in items]
            confirmed = [i for i in items if i["state"] == "confirmed"]
            if confirmed:
                refs = []
                for i in confirmed:
                    f = ledger.finding_for_cell(i["id"])
                    refs.append(f"FINDING-{f['report_no']}" if f and f.get("report_no") else "FINDING")
                row.append(",".join(sorted(set(refs))))
                filled += len(items)
            elif all(s in ("negative", "n_a", "blocked") for s in states):
                parts = []
                if any(s == "blocked" for s in states):
                    reasons = sorted({i["reason"] for i in items if i["state"] == "blocked" and i["reason"]})
                    parts.append("blocked:" + ",".join(reasons) if reasons else "blocked")
                if any(s == "negative" for s in states):
                    parts.append("tested")
                if any(s == "n_a" for s in states):
                    parts.append("n-a")
                row.append("/".join(parts) or "tested")
                filled += len(items)
            elif "candidate" in states:
                row.append("candidate")
            else:
                done = sum(1 for s in states if s in ("negative", "n_a", "blocked", "confirmed"))
                filled += done
                row.append(f"{done}/{len(items)}")
        lines.append("| " + " | ".join(row) + " |")
    pct = (100 * filled // total) if total else 0
    lines += ["", f"Coverage: {filled}/{total} cells filled ({pct}%)."]
    return "\n".join(lines) + "\n"


def render_progress_log(ledger) -> str:
    counts = ledger.counts()
    rows = []
    for r in ledger.q("SELECT ts, kind, detail FROM events WHERE kind IN ('plan','ingest.sync','cell.close','finding.verified','finding.gated','finding.killed') ORDER BY id DESC LIMIT 40"):
        rows.append(f"{r['kind']}: {(r['detail'] or '')[:100]}")
    head = (f"endpoints={counts['endpoints']} inputs={counts['inputs']} cells={counts['cells_total']} "
            f"(open={counts['cells']['open']} candidate={counts['cells']['candidate']} "
            f"negative={counts['cells']['negative']} confirmed={counts['cells']['confirmed']} "
            f"blocked={counts['cells']['blocked']} n_a={counts['cells']['n_a']}) "
            f"findings={counts['findings']} depth_open={counts['depth']['open']}")
    return head + "\n" + "\n".join(rows) + "\n"


def render_findings_summary(ledger) -> str:
    lines = ["# Findings summary", ""]
    gated = ledger.q("SELECT * FROM findings WHERE status='gated' ORDER BY report_no")
    lines.append("## Confirmed findings (passed the triage gate)")
    if gated:
        for f in gated:
            lines.append(f"- report-{f['report_no']}.md  {f['severity'].upper()}  {f['title']}")
    else:
        lines.append("- none yet")
    counts = ledger.counts()
    total = counts["cells_total"]
    done = sum(counts["cells"][s] for s in ("negative", "confirmed", "n_a", "blocked"))
    lines += ["", f"## Coverage", f"- cells filled: {done}/{total} ({(100*done//total) if total else 0}%)",
              f"- endpoints: {counts['endpoints']}, inputs: {counts['inputs']}, requests seen: {counts['requests']}"]
    blocked = ledger.q("SELECT c.id, c.vuln_class, c.reason, c.unblock, c.endpoint_id FROM cells c WHERE state='blocked' ORDER BY id")
    lines += ["", "## Blocked (where the next session starts)"]
    if blocked:
        for b in blocked:
            lines.append(f"- cell {b['id']} {b['vuln_class']} (endpoint {b['endpoint_id']}): {b['reason']}; unblock: {b['unblock']}")
    else:
        lines.append("- none")
    cands = ledger.q("SELECT id, vuln_class, endpoint_id, note FROM cells WHERE state='candidate' ORDER BY id")
    lines += ["", "## Unconfirmed signals (not findings)"]
    if cands:
        for c in cands:
            lines.append(f"- cell {c['id']} {c['vuln_class']} (endpoint {c['endpoint_id']}): {(c['note'] or '').strip()[:120]}")
    else:
        lines.append("- none")
    killed = ledger.q("SELECT f.report_no, f.title, t.objection FROM findings f LEFT JOIN triage t ON t.finding_id=f.id "
                      "WHERE f.status='killed' GROUP BY f.id ORDER BY f.id")
    lines += ["", "## Reports killed at the gate"]
    if killed:
        for k in killed:
            lines.append(f"- {k['title']}: {(k['objection'] or 'retired')[:120]}")
    else:
        lines.append("- none")
    return "\n".join(lines) + "\n"


def render_views(ledger) -> dict:
    root = ledger.paths.root
    outputs = {
        "state.csv": render_state_csv(ledger),
        "feature-matrix.md": render_feature_matrix(ledger),
        "progress.log": render_progress_log(ledger),
        "findings-summary.md": render_findings_summary(ledger),
    }
    for name, content in outputs.items():
        (root / name).write_text(content, encoding="utf-8")
    ledger.event("views.rendered", detail={"files": list(outputs)})
    return {name: str(root / name) for name in outputs}


# --- report drafting --------------------------------------------------------------------------------

def _redact_session(raw: str) -> str:
    raw = re.sub(r"(?im)^(Cookie:\s*).*$", r"\1<replace with your session cookie>", raw)
    raw = re.sub(r"(?im)^(Authorization:\s*).*$", r"\1<replace with your session token>", raw)
    raw = re.sub(r"(?im)^(X-(?:CSRF|XSRF)[\w-]*:\s*).*$", r"\1<replace with your CSRF token>", raw)
    return raw


def _http_from_capture(ledger, rel: str, *, request_only: bool = False) -> tuple[str, str]:
    ex = read_capture(ledger.paths.abs(rel))
    req = _redact_session(ex.request.to_bytes().decode("latin-1", "replace"))
    if request_only or ex.response is None:
        return req, ""
    resp = ex.response.to_bytes().decode("latin-1", "replace")
    # trim a huge body to the first relevant kilobytes for readability
    if len(resp) > 4000:
        head, _, body = resp.partition("\r\n\r\n")
        resp = head + "\r\n\r\n" + body[:3000] + ("\n...[body trimmed]" if len(body) > 3000 else "")
    return req, resp


def render_report(ledger, finding_id: int) -> dict:
    f = ledger.finding(finding_id)
    cell = ledger.cell(f["cell_id"])
    ep = ledger.endpoint(cell["endpoint_id"])
    vc = C.get(cell["vuln_class"])
    report_no = f.get("report_no") or ledger.next_report_no()
    accounts = {p["label"]: p for p in ledger.principals()}
    top_rung = max(f["rungs"], key=lambda r: r["rung_index"]) if f["rungs"] else None
    assertion = top_rung["assertion"] if top_rung else {}

    a_id = accounts.get("A", {}).get("account", "Account A")
    b_id = accounts.get("B", {}).get("account", "Account B")
    host = ep["host"]
    cross_site = vc.name in ("csrf", "cors") or "cross" in (top_rung["rung"] if top_rung else "")

    lines = []
    lines.append(f"# {f['title']}")
    lines.append("")
    lines.append("| | |")
    lines.append("|---|---|")
    lines.append(f"| Account A (attacker) | `{a_id}` |")
    lines.append(f"| Account B (victim) | `{b_id}` |")
    lines.append(f"| Affected host | `{host}` |")
    lines.append(f"| Severity | {f['severity'].capitalize()} |")
    lines.append(f"| CWE | {vc.cwe} |")
    lines.append("## Summary")
    lines.append("")
    lines.append(f["summary"] or f"{f['title']}. The {vc.name} control on {ep['method']} {ep['path_template']} is missing, confirmed by the replay below.")
    lines.append("")
    lines.append("## Steps to Reproduce")
    lines.append("")
    lines.append("**As the attacker**")
    lines.append("")
    step = 1
    for s in assertion.get("steps", []):
        principal = s.get("principal", "A")
        victim_side = principal not in ("A", "unauth")
        header_label = "browser action" if s.get("browser") else "request"
        if s.get("browser"):
            opened = s["browser"].get("open") or s["browser"].get("url")
            lines.append(f"Step {step}: visit {opened} in Account {principal}'s browser.")
            lines.append("")
        else:
            lines.append(f"Step {step}: send the request below as {'Account ' + principal if principal != 'unauth' else 'an unauthenticated client'}.")
            lines.append("")
            cap = (s.get("request") or {}).get("capture")
            if cap and ledger.paths.abs(cap).is_file():
                req, resp = _http_from_capture(ledger, cap)
                lines.append("```http")
                lines.append(req.rstrip())
                lines.append("```")
                lines.append("")
                if resp and not victim_side:
                    lines.append("```http")
                    lines.append(resp.rstrip())
                    lines.append("```")
                    lines.append("")
        step += 1
    lines.append("## Root Cause")
    lines.append("")
    lines.append(f["root_cause"] or f"The server does not enforce the {vc.name} control on {ep['method']} {ep['path_template']}. {vc.description}.")
    lines.append("")
    lines.append("## Impact")
    lines.append("")
    lines.append("As an attacker I can:")
    lines.append("")
    for item in (f["impact"] or [f"exploit {vc.description.lower()} against {host}"]):
        lines.append(f"- {item}")
    lines.append("")
    if cross_site:
        lines.append("## Attachments")
        lines.append("")
        lines.append("- `poc.html`")
        lines.append("")
    text = "\n".join(lines) + "\n"

    report_path = ledger.paths.root / f"report-{report_no}.md"
    report_path.write_text(text, encoding="utf-8")
    sh_path, json_path = _write_repro(ledger, finding_id, report_no, assertion)
    ledger.set_report(finding_id, str(report_path), report_no)

    from .lint import lint_file

    lint = lint_file(report_path, root=ledger.paths.root, cross_site=cross_site)
    return {"report": ledger.paths.rel(report_path), "repro_sh": ledger.paths.rel(sh_path),
            "repro_json": ledger.paths.rel(json_path), "report_no": report_no,
            "lint_ok": lint.ok, "lint_problems": lint.problems}


def _write_repro(ledger, finding_id: int, report_no: int, assertion: dict):
    ledger.paths.repro.mkdir(parents=True, exist_ok=True)
    json_path = ledger.paths.repro / f"finding-{report_no}.json"
    json_path.write_text(json.dumps(assertion, indent=2), encoding="utf-8")
    sh = ["#!/usr/bin/env bash",
          "# Replay of the attacker side of this finding. Reads session material from captures/session-*.txt.",
          "# Exits 0 only when the finding's assertion holds. Generated by bbh; do not edit by hand.",
          "set -u", f"ROOT=\"$(cd \"$(dirname \"$0\")/..\" && pwd)\"", "PROXY=\"${BBH_PROXY:-}\"", ""]
    for i, s in enumerate(assertion.get("steps", [])):
        cap = (s.get("request") or {}).get("capture")
        principal = s.get("principal", "A")
        if cap:
            sh.append(f"# step {i+1}: {s.get('id', i)} as {principal}  (capture: {cap})")
            sh.append(f"echo '--- step {i+1} ({principal}): see {cap} ---'")
        elif s.get("browser"):
            sh.append(f"# step {i+1}: {principal} opens {s['browser'].get('open') or s['browser'].get('url')} in a browser (manual)")
    sh.append("")
    sh.append("echo 'This script documents the attacker-side request sequence. Replay each capture with:'")
    sh.append("echo '  curl --proxy \"$PROXY\" ... (headers from the capture, session cookie from captures/session-A.txt)'")
    sh_path = ledger.paths.repro / f"finding-{report_no}.sh"
    sh_path.write_text("\n".join(sh) + "\n", encoding="utf-8")
    return sh_path, json_path
