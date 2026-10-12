import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from bbh.config import parse_prompt_text  # noqa: E402
from bbh.ledger import Ledger  # noqa: E402
from bbh.paths import Paths  # noqa: E402

PROMPT = """# Target brief
## Target
- **Asset:** `Lab`
- **Scope:** `127.0.0.1:5057, *.lab.test`
- **Out of scope:** `admin.lab.test`
- **Programme:** `private`
- **Marker header:** `none`
## Login
- **Method:** `email and password`
## Accounts
| Role | Account | Browser | MCP |
|---|---|---|---|
| A, attacker | `alice@lab.test` | Chrome | `browser-mcp` |
| B, victim | `bob@lab.test` | Firefox | `claudecodebrowser` |
## Harness
- **Rate limit:** `20`
- **OOB callback:** `none`
- **Burp proxy:** `none`
"""


class Clock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


@pytest.fixture
def clock():
    return Clock()


@pytest.fixture
def eng(tmp_path, monkeypatch):
    root = tmp_path / "eng"
    root.mkdir()
    (root / "prompt.md").write_text(PROMPT, encoding="utf-8")
    monkeypatch.setenv("BBH_ENGAGEMENT_DIR", str(root))
    return Paths(root).ensure()


@pytest.fixture
def ledger(eng, clock):
    L = Ledger(eng, now=clock)
    L.sync_engagement(parse_prompt_text(PROMPT))
    yield L
    L.close()


def make_capture(paths: Paths, name: str = "c.http", body: str = "x") -> str:
    p = paths.captures / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(f"GET / HTTP/1.1\r\nHost: 127.0.0.1:5057\r\n\r\n### response\r\nHTTP/1.1 200 OK\r\n\r\n{body}", encoding="utf-8")
    return paths.rel(p)


@pytest.fixture
def cap(eng):
    return make_capture(eng)


@pytest.fixture
def endpoint(ledger):
    eid, _ = ledger.upsert_endpoint(origin="http://127.0.0.1:5057", method="GET", path_template="/search")
    iid, _ = ledger.upsert_input(endpoint_id=eid, name="q", location="query", sample_value="hi")
    return eid, iid


def fill_negative(ledger, cell_id, cap, *, klass, families=("a", "b", "c", "d", "e"), n=10, control=True,
                  control_family="control", counter=False):
    """Record n negative cases spread over the given families, plus a passing control."""
    if control:
        ledger.record_case(cell_id=cell_id, case_no=0, technique=f"{klass}.{control_family}.baseline",
                           outcome="control_pass", observation="baseline 200 as captured (captures/c.http)",
                           request_capture=cap, response_capture=cap)
    for i in range(1, n + 1):
        fam = families[(i - 1) % len(families)]
        ledger.record_case(cell_id=cell_id, case_no=i, technique=f"{klass}.{fam}.v{i}", outcome="negative",
                           observation=f"status 200, payload absent (captures/c.http) case {i}",
                           request_capture=cap, response_capture=cap, counter_capture=cap if counter else None)
