"""Fingerprint of the bbh source on disk, to detect a stale long-running server.

The MCP server (`python -m bbh.server`) imports its modules once and then runs for
the whole session. A detached worker (`bbh.worker`) or a hand edit can change the
code on disk while the server keeps executing the old version. That was the field
report's #1 pain: after the generators/evaluator were fixed on disk, the running
server still raised `unknown condition 'min_len'` on every new plan, and nothing
warned that the live code no longer matched disk.

`fingerprint()` hashes every `.py` in the package on disk. `status()` compares the
value captured when the server imported with a fresh read, so a mismatch surfaces
as `code.stale`; `reload()` refreshes the modules and the captured value. Stdlib only.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

_PKG = Path(__file__).resolve().parent


def fingerprint() -> str:
    """A short, stable hash of all package sources on disk (order-independent, name-sensitive)."""
    h = hashlib.sha256()
    for p in sorted(_PKG.rglob("*.py"), key=lambda q: str(q).lower()):
        if "__pycache__" in p.parts:
            continue
        try:
            data = p.read_bytes()
        except OSError:
            continue
        h.update(p.relative_to(_PKG).as_posix().encode("utf-8"))
        h.update(b"\0")
        h.update(data)
        h.update(b"\0")
    return h.hexdigest()[:16]
