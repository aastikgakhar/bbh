"""Finding assertion schema and validation. Stdlib only.

An assertion is the machine-checkable proof of a finding:

    {
      "version": 1,
      "steps": [
        {"id": "write", "principal": "A", "request": {"capture": "captures/12/3-idor_write.cross.put.http"}},
        {"id": "read",  "principal": "B", "request": {"method": "GET", "url": "https://x.test/api/notes/7"}, "repeat": 1},
        {"id": "poc",   "principal": "B", "browser": {"open": "poc-1.html", "wait_ms": 3000}}
      ],
      "checks": [
        {"step": "read", "type": "body_contains", "value": "only-A-wrote-this"},
        {"type": "len_diff", "a": "true", "b": "false", "min_bytes": 50, "all_repeats": true},
        {"step": "slow", "type": "elapsed_over_baseline", "baseline": "base", "min_ms": 1800, "all_repeats": true},
        {"type": "oob_hit", "token": "k3j2...", "within_s": 30}
      ]
    }
"""

from __future__ import annotations

from pathlib import Path

CHECK_TYPES = {
    "body_contains": ("value",),
    "body_not_contains": ("value",),
    "body_regex": ("pattern",),
    "header_contains": ("name", "value"),
    "header_present": ("name",),
    "status_in": ("values",),
    "location_host": ("host",),
    "elapsed_over_baseline": ("baseline", "min_ms"),
    "elapsed_over_case": ("case", "min_ms"),
    "elapsed_ratio": ("a", "b", "min_ratio"),
    "len_diff": ("a", "b", "min_bytes"),
    "same_as_case": ("case",),
    "oob_hit": ("token",),
    "browser_marker": ("token",),
    "all": ("of",),
    "any": ("of",),
    "not": ("of",),
}

STEP_KEYS = {"id", "principal", "request", "repeat", "browser", "note", "proxy"}


class AssertionError_(ValueError):
    pass


def validate(assertion: dict, root: Path | None = None) -> list[str]:
    """Return a list of problems (empty = valid)."""
    problems: list[str] = []
    if not isinstance(assertion, dict):
        return ["assertion must be a JSON object"]
    if assertion.get("version", 1) != 1:
        problems.append("assertion.version must be 1")
    steps = assertion.get("steps")
    checks = assertion.get("checks")
    if not isinstance(steps, list) or not steps:
        problems.append("assertion.steps must be a non-empty list")
        steps = []
    if not isinstance(checks, list) or not checks:
        problems.append("assertion.checks must be a non-empty list")
        checks = []
    ids: set[str] = set()
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            problems.append(f"steps[{i}] must be an object")
            continue
        sid = step.get("id")
        if not sid or not isinstance(sid, str):
            problems.append(f"steps[{i}].id is required")
        elif sid in ids:
            problems.append(f"steps[{i}].id {sid!r} is duplicated")
        else:
            ids.add(sid)
        unknown = set(step) - STEP_KEYS
        if unknown:
            problems.append(f"steps[{i}] has unknown keys {sorted(unknown)}")
        if not step.get("principal"):
            problems.append(f"steps[{i}].principal is required (A, B, unauth, ...)")
        req = step.get("request")
        brw = step.get("browser")
        if not req and not brw:
            problems.append(f"steps[{i}] needs a request or a browser action")
        if req:
            if not isinstance(req, dict):
                problems.append(f"steps[{i}].request must be an object")
            elif "capture" in req:
                cap = req["capture"]
                if root is not None and not (Path(cap) if Path(cap).is_absolute() else root / cap).is_file():
                    problems.append(f"steps[{i}].request.capture {cap!r} does not exist")
            elif not (req.get("method") and req.get("url")):
                problems.append(f"steps[{i}].request needs either capture or method+url")
        if brw is not None and not (isinstance(brw, dict) and (brw.get("open") or brw.get("url"))):
            problems.append(f"steps[{i}].browser needs 'open' (a local PoC file) or 'url'")
        rep = step.get("repeat", 1)
        if not isinstance(rep, int) or rep < 1 or rep > 10:
            problems.append(f"steps[{i}].repeat must be an integer 1..10")

    def check_one(c, path):
        if not isinstance(c, dict):
            problems.append(f"{path} must be an object")
            return
        t = c.get("type")
        if t not in CHECK_TYPES:
            problems.append(f"{path}.type {t!r} unknown; known: {', '.join(sorted(CHECK_TYPES))}")
            return
        for key in CHECK_TYPES[t]:
            if key not in c:
                problems.append(f"{path} ({t}) needs {key!r}")
        if t in ("all", "any"):
            for j, sub in enumerate(c.get("of") or []):
                check_one(sub, f"{path}.of[{j}]")
        elif t == "not":
            check_one(c.get("of"), f"{path}.of")
        for ref_key in ("step", "a", "b", "baseline", "case"):
            ref = c.get(ref_key)
            if (ref is not None and ref != "this" and t not in ("all", "any", "not")
                    and ref_key != "step" and isinstance(ref, str) and ref not in ids):
                problems.append(f"{path}.{ref_key} refers to unknown step {ref!r}")
        if c.get("step") is not None and c["step"] not in ids:
            problems.append(f"{path}.step refers to unknown step {c['step']!r}")
        no_step_ok = ("oob_hit", "all", "any", "not", "len_diff", "elapsed_ratio", "same_as_case", "elapsed_over_case")
        if t not in no_step_ok and "step" not in c:
            problems.append(f"{path} ({t}) needs 'step'")

    for i, c in enumerate(checks):
        check_one(c, f"checks[{i}]")
    return problems
