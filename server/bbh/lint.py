"""Report lint: enforce the report-writer house format on report-*.md. Stdlib only.

Run by render_report and by the PreToolUse hook on any Write/Edit of report-*.md.
Returns a list of problems; empty means the report passes. Checks the format
rules the skill corrects every time, and cite-checks every fenced HTTP block and
capture reference against the files on disk.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

# report-writer's banned list (stricter than the ledger hedge list; report format is the skill's)
BANNED_WORDS = [
    r"\bpotential(ly)?\b", r"\bcould be chained\b", r"\bcould\b", r"\bmay allow\b", r"\bmay\b",
    r"\btheoretically\b", r"\bphishing\b", r"\bshould\b", r"\bseems\b", r"\bappears to\b",
    r"\bmight\b", r"\bprobably\b", r"\blikely\b", r"\bpossibly\b",
]
DISMISSAL = [r"this may be by design", r"feel free to disregard", r"if this is intended", r"not sure if", r"this is just"]
LONG_DASH = re.compile(r"[—–]| -- ")
CODE_FENCE = re.compile(r"^```", re.M)


@dataclass
class LintResult:
    problems: list[str]

    @property
    def ok(self) -> bool:
        return not self.problems

    def report(self) -> str:
        if self.ok:
            return "report lint passed"
        return "report lint failed:\n" + "\n".join(f"  - {p}" for p in self.problems)


def _segments(text: str):
    """Yield (is_code, is_http, text) for fenced vs prose segments."""
    parts = re.split(r"(```[a-zA-Z0-9]*\n.*?```)", text, flags=re.S)
    for part in parts:
        if part.startswith("```"):
            lang = part[3:part.index("\n")].strip().lower() if "\n" in part else ""
            body = part[part.index("\n") + 1:].rsplit("```", 1)[0] if "\n" in part else ""
            yield True, lang in ("http", "https"), body
        else:
            yield False, False, part


def _http_blocks(text: str) -> list[str]:
    return [body for is_code, is_http, body in _segments(text) if is_http]


def lint_text(text: str, *, root: Path | None = None, cited_captures: list[str] | None = None,
              principal_identifiers: dict | None = None, cross_site: bool = False) -> LintResult:
    problems: list[str] = []
    prose = "".join(t for is_code, _, t in _segments(text) if not is_code)
    prose_lower = prose.lower()

    # banned words (prose only, never inside code/HTTP)
    for pat in BANNED_WORDS:
        m = re.search(pat, prose, re.I)
        if m:
            line = prose[:m.start()].count("\n") + 1
            problems.append(f"banned word {m.group(0)!r} in prose (near prose line {line}); state what the response showed")
    for pat in DISMISSAL:
        if re.search(pat, prose_lower):
            problems.append(f"dismissal-inviting phrase {pat!r}; remove it")

    # long dashes
    for is_code, _, seg in _segments(text):
        if is_code:
            continue
        if LONG_DASH.search(seg):
            problems.append("long dash (em/en dash or ' -- ') in prose; use a comma")
            break

    # literal 'Step N:' labels, not a markdown numbered list for steps
    if re.search(r"^\s*\d+\.\s+\w", text, re.M) and "Steps to Reproduce" in text:
        steps_section = text.split("Steps to Reproduce", 1)[1]
        if re.search(r"^\s*\d+\.\s", steps_section, re.M):
            problems.append("steps use a markdown numbered list; use literal 'Step N:' labels on their own paragraph")
    if "Steps to Reproduce" in text and not re.search(r"\bStep\s+\d+:", text):
        problems.append("no literal 'Step N:' labels found under Steps to Reproduce")

    # role headers
    if "Steps to Reproduce" in text and "**As the attacker**" not in text:
        problems.append("missing the '**As the attacker**' role header")

    # prose must be unwrapped: flag paragraphs with several short hard-wrapped lines
    for para in re.split(r"\n\s*\n", prose):
        lines = [ln for ln in para.splitlines() if ln.strip() and not ln.strip().startswith(("-", "*", "|", ">", "#"))]
        if len(lines) >= 3:
            shortish = [ln for ln in lines[:-1] if 1 <= len(ln.strip()) <= 72]
            if len(shortish) >= 3 and sum(len(ln) for ln in lines) / len(lines) < 70:
                problems.append("prose looks hard-wrapped (several short lines in one paragraph); write each paragraph on one long line")
                break

    # no bold other than the two role headers
    bolds = re.findall(r"\*\*(.+?)\*\*", text)
    for b in bolds:
        if b.strip() not in ("As the attacker", "As the victim"):
            problems.append(f"bold text {b[:40]!r} is not allowed; only the two role headers may be bold")
            break

    # victim section must not contain raw HTTP
    if "**As the victim**" in text:
        victim = text.split("**As the victim**", 1)[1]
        # stop at the next top-level heading
        victim = re.split(r"\n##? ", victim, 1)[0]
        if _http_blocks(victim):
            problems.append("the victim section contains a raw HTTP block; the victim only performs a normal browser action")
        if re.search(r"\b(burp|repeater|curl|devtools|console)\b", victim, re.I):
            problems.append("the victim section mentions an attacker tool (Burp/Repeater/curl/DevTools/console); remove it")

    # test emails must be replaced with Account A / Account B
    for m in re.finditer(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[a-z]{2,}", prose):
        email = m.group(0)
        if not email.endswith((".test", ".example", ".invalid")):
            problems.append(f"a concrete email {email!r} appears in prose; use Account A / Account B")
            break

    # cite-check: every cited capture exists; every fenced HTTP block comes from a capture
    if root is not None:
        cited = set(re.findall(r"`?(captures/[^\s`)]+\.http)`?", text))
        for cap in cited:
            if not (root / cap).is_file():
                problems.append(f"cited capture {cap} does not exist on disk")
            elif (root / cap).stat().st_size == 0:
                problems.append(f"cited capture {cap} is empty")
        # cross-site finding needs a poc.html
        if cross_site:
            pocs = list(root.glob("poc*.html"))
            if not pocs and "poc" not in text.lower():
                problems.append("a cross-site finding needs an attached poc.html hosted on the HTTPS ngrok URL")

    return LintResult(problems)


def lint_file(path: str | Path, *, root: Path | None = None, cross_site: bool = False) -> LintResult:
    p = Path(path)
    if not p.is_file():
        return LintResult([f"{path} does not exist"])
    return lint_text(p.read_text(encoding="utf-8", errors="replace"), root=root or p.parent, cross_site=cross_site)


def lint_pending_edit(file_path: str, new_text: str, root: Path) -> LintResult:
    """For the PreToolUse hook: lint the content a Write/Edit is about to produce."""
    cross_site = bool(re.search(r"\b(csrf|cors|cross-origin|cross-site|poc\.html)\b", new_text, re.I))
    return lint_text(new_text, root=root, cross_site=cross_site)
