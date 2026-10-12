"""Engagement directory discovery and the well-known paths inside it. Stdlib only."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


def find_engagement_dir(start: str | os.PathLike | None = None) -> Path:
    """Return the engagement root.

    Order: BBH_ENGAGEMENT_DIR, then the first ancestor (inclusive) of `start`,
    CLAUDE_PROJECT_DIR or the cwd that holds `.bbh/` or `prompt.md`. Falls back
    to the first candidate when nothing matches.
    """
    env = os.environ.get("BBH_ENGAGEMENT_DIR")
    if env:
        return Path(env).resolve()
    candidates: list[Path] = []
    if start:
        candidates.append(Path(start))
    project = os.environ.get("CLAUDE_PROJECT_DIR")
    if project:
        candidates.append(Path(project))
    candidates.append(Path.cwd())
    for cand in candidates:
        cand = cand.resolve()
        for d in (cand, *cand.parents):
            if (d / ".bbh").is_dir() or (d / "prompt.md").is_file():
                return d
    return candidates[0].resolve()


def plugin_root() -> Path:
    """Root of the bbh plugin (the directory holding .claude-plugin/)."""
    env = os.environ.get("CLAUDE_PLUGIN_ROOT")
    if env:
        return Path(env).resolve()
    # server/bbh/paths.py -> plugin root is three levels up
    return Path(__file__).resolve().parents[2]


@dataclass(frozen=True)
class Paths:
    root: Path

    @classmethod
    def discover(cls, start: str | os.PathLike | None = None) -> "Paths":
        return cls(find_engagement_dir(start))

    @property
    def prompt(self) -> Path:
        return self.root / "prompt.md"

    @property
    def bbh(self) -> Path:
        return self.root / ".bbh"

    @property
    def ledger(self) -> Path:
        return self.bbh / "ledger.db"

    @property
    def stop_file(self) -> Path:
        return self.bbh / "STOP"

    @property
    def stuck(self) -> Path:
        return self.bbh / "stuck.md"

    @property
    def handoff(self) -> Path:
        return self.bbh / "handoff.md"

    @property
    def hook_log(self) -> Path:
        return self.bbh / "hook.log"

    @property
    def guidance(self) -> Path:
        return self.bbh / "guidance.json"

    @property
    def traffic(self) -> Path:
        return self.bbh / "traffic"

    @property
    def captures(self) -> Path:
        return self.root / "captures"

    @property
    def repro(self) -> Path:
        return self.root / "repro"

    def ensure(self) -> "Paths":
        for d in (self.bbh, self.traffic, self.captures, self.repro):
            d.mkdir(parents=True, exist_ok=True)
        return self

    def stop_requested(self) -> bool:
        return self.stop_file.exists()

    def rel(self, p: str | os.PathLike) -> str:
        """Engagement-relative POSIX path when possible (what the ledger stores)."""
        path = Path(p)
        if not path.is_absolute():
            return path.as_posix()
        try:
            return path.resolve().relative_to(self.root.resolve()).as_posix()
        except ValueError:
            return path.as_posix()

    def abs(self, p: str | os.PathLike) -> Path:
        path = Path(p)
        return path if path.is_absolute() else (self.root / path)

    def session_file(self, label: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in "-_." else "_" for ch in label)
        return self.captures / f"session-{safe}.txt"
