"""Banned-hedge check for every verdict text field in the ledger. Stdlib only.

The list is the build spec's list plus three obvious synonyms. Report prose has
its own, stricter list in lint.py (report format belongs to report-writer).
"""

from __future__ import annotations

import re

BANNED_HEDGES = (
    "maybe",
    "might",
    "probably",
    "likely",
    "unlikely",
    "possibly",
    "potential",
    "potentially",
    "seems",
    "appears to",
    "could",
    "may allow",
    "theoretically",
    "should be",
    "perhaps",
    "presumably",
)

HEDGE_MESSAGE = "State what the response showed, with the capture filename."

_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(w).replace(r"\ ", r"\s+") for w in sorted(BANNED_HEDGES, key=len, reverse=True)) + r")\b",
    re.IGNORECASE,
)


class HedgeError(ValueError):
    def __init__(self, problems: dict[str, list[str]]):
        self.problems = problems
        parts = [
            f"{field} contains banned hedge word(s) {', '.join(repr(w) for w in words)}"
            for field, words in problems.items()
        ]
        super().__init__("; ".join(parts) + ". " + HEDGE_MESSAGE)


def find_hedges(text: str | None) -> list[str]:
    if not text:
        return []
    seen: list[str] = []
    for m in _PATTERN.finditer(text):
        word = re.sub(r"\s+", " ", m.group(1).lower())
        if word not in seen:
            seen.append(word)
    return seen


def check(text: str | None, field: str) -> None:
    check_many({field: text})


def check_many(fields: dict[str, str | None]) -> None:
    problems = {name: find_hedges(value) for name, value in fields.items()}
    problems = {name: words for name, words in problems.items() if words}
    if problems:
        raise HedgeError(problems)
