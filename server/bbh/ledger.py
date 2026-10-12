"""The ledger: schema, state machine and invariants. Stdlib only.

Every state change in bbh goes through this module. Each transition touches
exactly one cell row (sibling independence), refuses anything that breaks an
invariant, and appends to the events table, which triggers make append-only.
"""

from __future__ import annotations

import json
import secrets
import sqlite3
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from . import classes as C
from . import hedge
from .paths import Paths
from .scope import Scope, ScopeError

SCHEMA_VERSION = 1
CELL_STATES = ("open", "in_progress", "negative", "candidate", "confirmed", "n_a", "blocked")
OUTCOMES = ("positive", "negative", "inconclusive", "control_pass", "control_fail")
SEVERITIES = ("info", "low", "medium", "high", "critical")
CLAIM_TTL_S = 30 * 60
VERIFY_GAP_S = 60
MAX_TRIAGE_REJECTS = 3
PRINCIPAL_KINDS = ("account", "unauth", "role", "token", "share_link", "other")
INPUT_LOCATIONS = ("query", "path", "form", "json", "header", "cookie", "multipart", "filename")
ENDPOINT_SOURCES = ("traffic", "js", "spec", "guess", "model")
# Event kinds that do not count as progress for the stop gate.
NON_PROGRESS_EVENTS = {"cell.claim", "cell.release", "cell.claim_expired", "depth.claim", "gate.blocked", "gate.allowed", "views.rendered"}

DDL = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS engagement (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  target TEXT, scope_json TEXT NOT NULL DEFAULT '[]', oos_json TEXT NOT NULL DEFAULT '[]',
  oos_notes_json TEXT NOT NULL DEFAULT '[]', programme TEXT, marker_header_json TEXT,
  rate_limit_rps REAL NOT NULL DEFAULT 2.0, oob_json TEXT NOT NULL DEFAULT '{"mode": "none"}',
  burp_proxy TEXT, burp_mcp_url TEXT, max_testers INTEGER NOT NULL DEFAULT 3,
  support_hosts_json TEXT NOT NULL DEFAULT '[]', accounts_json TEXT NOT NULL DEFAULT '[]',
  login_json TEXT, target_notes TEXT, prompt_hash TEXT, configured INTEGER NOT NULL DEFAULT 0,
  problems_json TEXT NOT NULL DEFAULT '[]', updated_at REAL
);
CREATE TABLE IF NOT EXISTS principals (
  id INTEGER PRIMARY KEY, label TEXT NOT NULL UNIQUE,
  kind TEXT NOT NULL CHECK (kind IN ('account','unauth','role','token','share_link','other')),
  account TEXT, browser TEXT, session_file TEXT, identifiers_json TEXT NOT NULL DEFAULT '[]',
  notes TEXT, created_at REAL
);
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY,
  source TEXT NOT NULL CHECK (source IN ('burp','sender','browser','import')),
  burp_offset INTEGER, principal_id INTEGER REFERENCES principals(id),
  method TEXT NOT NULL, url TEXT NOT NULL, host TEXT NOT NULL, status INTEGER, content_type TEXT,
  resp_len INTEGER, ua_family TEXT, raw_path TEXT, truncated INTEGER NOT NULL DEFAULT 0,
  content_hash TEXT UNIQUE, endpoint_id INTEGER, ts REAL
);
CREATE TABLE IF NOT EXISTS endpoints (
  id INTEGER PRIMARY KEY, origin TEXT NOT NULL, host TEXT NOT NULL, method TEXT NOT NULL,
  path_template TEXT NOT NULL, family TEXT, feature TEXT, auth_required INTEGER, content_type TEXT,
  first_seen_request_id INTEGER,
  source TEXT NOT NULL CHECK (source IN ('traffic','js','spec','guess','model')),
  flags_json TEXT NOT NULL DEFAULT '{}', third_party_lock INTEGER NOT NULL DEFAULT 0, created_at REAL,
  UNIQUE (origin, method, path_template)
);
CREATE TABLE IF NOT EXISTS inputs (
  id INTEGER PRIMARY KEY, endpoint_id INTEGER NOT NULL REFERENCES endpoints(id), name TEXT NOT NULL,
  location TEXT NOT NULL CHECK (location IN ('query','path','form','json','header','cookie','multipart','filename')),
  json_path TEXT, sample_value TEXT, value_type TEXT, reflection_contexts TEXT NOT NULL DEFAULT '[]',
  created_at REAL, UNIQUE (endpoint_id, location, name)
);
CREATE TABLE IF NOT EXISTS cells (
  id INTEGER PRIMARY KEY, endpoint_id INTEGER NOT NULL REFERENCES endpoints(id),
  input_id INTEGER REFERENCES inputs(id), vuln_class TEXT NOT NULL,
  state TEXT NOT NULL DEFAULT 'open'
    CHECK (state IN ('open','in_progress','negative','candidate','confirmed','n_a','blocked')),
  claimed_by TEXT, claimed_at REAL, reason TEXT, reason_request_id INTEGER, unblock TEXT, note TEXT,
  context_json TEXT NOT NULL DEFAULT '{}', priority INTEGER NOT NULL DEFAULT 50,
  source TEXT NOT NULL DEFAULT 'rule' CHECK (source IN ('rule','depth','model','researcher')),
  salt TEXT NOT NULL, verifier_json TEXT, created_at REAL, updated_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS cells_uniq ON cells (endpoint_id, ifnull(input_id, 0), vuln_class);
CREATE INDEX IF NOT EXISTS cells_state ON cells (state);
CREATE TABLE IF NOT EXISTS planned_cases (
  cell_id INTEGER NOT NULL REFERENCES cells(id), case_no INTEGER NOT NULL, technique TEXT NOT NULL,
  is_control INTEGER NOT NULL, payload TEXT, mutation_json TEXT NOT NULL, positive_json TEXT NOT NULL,
  negative TEXT, route TEXT NOT NULL, principal TEXT, repeat INTEGER NOT NULL DEFAULT 1,
  needs_counter_read INTEGER NOT NULL DEFAULT 0, description TEXT, extra_json TEXT NOT NULL DEFAULT '{}',
  PRIMARY KEY (cell_id, case_no)
);
CREATE TABLE IF NOT EXISTS test_cases (
  id INTEGER PRIMARY KEY, cell_id INTEGER NOT NULL REFERENCES cells(id), case_no INTEGER NOT NULL,
  attempt INTEGER NOT NULL, technique TEXT NOT NULL, payload TEXT,
  principal_id INTEGER REFERENCES principals(id), request_capture TEXT, response_capture TEXT,
  counter_capture TEXT, observation TEXT NOT NULL,
  outcome TEXT NOT NULL CHECK (outcome IN ('positive','negative','inconclusive','control_pass','control_fail')),
  route TEXT NOT NULL DEFAULT 'sender', elapsed_ms INTEGER, status INTEGER, ts REAL,
  UNIQUE (cell_id, case_no, attempt)
);
CREATE INDEX IF NOT EXISTS test_cases_cell ON test_cases (cell_id);
CREATE TABLE IF NOT EXISTS findings (
  id INTEGER PRIMARY KEY, cell_id INTEGER NOT NULL UNIQUE REFERENCES cells(id),
  rung TEXT NOT NULL, rung_index INTEGER NOT NULL, title TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('info','low','medium','high','critical')),
  summary TEXT, root_cause TEXT, impact_json TEXT NOT NULL DEFAULT '[]',
  escalation_blocked_by_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','verified','gated','killed')),
  verifier_json TEXT, report_path TEXT, report_no INTEGER UNIQUE, created_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS finding_rungs (
  id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id), rung TEXT NOT NULL,
  rung_index INTEGER NOT NULL, assertion_json TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','verified','failed')),
  verifier_json TEXT, created_at REAL, updated_at REAL, UNIQUE (finding_id, rung)
);
CREATE TABLE IF NOT EXISTS verifications (
  id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id), rung TEXT NOT NULL,
  passed INTEGER NOT NULL, detail TEXT, run_dir TEXT, started_at REAL, finished_at REAL
);
CREATE TABLE IF NOT EXISTS triage (
  id INTEGER PRIMARY KEY, finding_id INTEGER NOT NULL REFERENCES findings(id), round INTEGER NOT NULL,
  verdict TEXT NOT NULL CHECK (verdict IN ('ACCEPT','REJECT')), objection TEXT, required_evidence TEXT, ts REAL
);
CREATE TABLE IF NOT EXISTS depth_queue (
  id INTEGER PRIMARY KEY, kind INTEGER NOT NULL CHECK (kind BETWEEN 1 AND 8), title TEXT NOT NULL,
  detail_json TEXT NOT NULL DEFAULT '{}',
  source TEXT NOT NULL CHECK (source IN ('rule','model','researcher')), test_plan TEXT,
  state TEXT NOT NULL DEFAULT 'open' CHECK (state IN ('open','in_progress','done','blocked')),
  claimed_by TEXT, claimed_at REAL, result TEXT, dedupe_key TEXT UNIQUE, created_at REAL, updated_at REAL
);
CREATE TABLE IF NOT EXISTS canaries (
  token TEXT PRIMARY KEY, input_id INTEGER, endpoint_id INTEGER, request_id INTEGER,
  principal_id INTEGER, kind TEXT NOT NULL, ts REAL
);
CREATE TABLE IF NOT EXISTS sightings (
  id INTEGER PRIMARY KEY, token TEXT NOT NULL, request_id INTEGER, endpoint_id INTEGER,
  principal_id INTEGER, context TEXT, ts REAL, UNIQUE (token, endpoint_id, principal_id)
);
CREATE TABLE IF NOT EXISTS oob (token TEXT PRIMARY KEY, cell_id INTEGER, url TEXT NOT NULL, created_at REAL);
CREATE TABLE IF NOT EXISTS oob_hits (
  id INTEGER PRIMARY KEY, token TEXT NOT NULL, ts REAL, protocol TEXT, method TEXT, remote TEXT, raw TEXT
);
CREATE TABLE IF NOT EXISTS rate_state (
  host TEXT PRIMARY KEY, next_allowed REAL NOT NULL DEFAULT 0, penalty REAL NOT NULL DEFAULT 1,
  ok_streak INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL, kind TEXT NOT NULL, entity TEXT,
  entity_id INTEGER, from_state TEXT, to_state TEXT, detail TEXT, progress INTEGER NOT NULL DEFAULT 1
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
  BEGIN SELECT RAISE(ABORT, 'events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
  BEGIN SELECT RAISE(ABORT, 'events is append-only'); END;
CREATE TRIGGER IF NOT EXISTS test_cases_no_update BEFORE UPDATE ON test_cases
  BEGIN SELECT RAISE(ABORT, 'test_cases is append-only; record a new attempt'); END;
CREATE TRIGGER IF NOT EXISTS test_cases_no_delete BEFORE DELETE ON test_cases
  BEGIN SELECT RAISE(ABORT, 'test_cases is append-only'); END;
CREATE TRIGGER IF NOT EXISTS cells_no_delete BEFORE DELETE ON cells
  BEGIN SELECT RAISE(ABORT, 'cells are never deleted'); END;
CREATE TRIGGER IF NOT EXISTS findings_no_downgrade BEFORE UPDATE OF rung_index ON findings
  WHEN NEW.rung_index < OLD.rung_index
  BEGIN SELECT RAISE(ABORT, 'a finding rung can never be lowered'); END;
CREATE TRIGGER IF NOT EXISTS cells_state_check BEFORE UPDATE OF state ON cells
  WHEN NEW.state NOT IN ('open','in_progress','negative','candidate','confirmed','n_a','blocked')
  BEGIN SELECT RAISE(ABORT, 'invalid cell state'); END;
"""


class LedgerError(Exception):
    """A refused operation. `missing` lists exactly what would make it valid."""

    def __init__(self, message: str, missing: list[str] | None = None):
        self.missing = list(missing or [])
        text = message
        if self.missing:
            text += "\nMissing:\n" + "\n".join(f"  - {m}" for m in self.missing)
        super().__init__(text)


def _j(value: Any) -> str:
    return json.dumps(value, sort_keys=True, default=str)


def _u(text: str | None, default: Any = None) -> Any:
    if text is None or text == "":
        return default
    try:
        return json.loads(text)
    except (TypeError, ValueError):
        return default


class Ledger:
    def __init__(self, paths: Paths | str | Path, *, now=time.time, busy_timeout_ms: int = 5000):
        self.paths = paths if isinstance(paths, Paths) else Paths(Path(paths))
        self.paths.bbh.mkdir(parents=True, exist_ok=True)
        self.db_path = self.paths.ledger
        self.now = now
        self.busy_timeout_ms = busy_timeout_ms
        self._local = threading.local()
        self._init_lock = threading.Lock()
        with self._init_lock:
            conn = self.conn
            conn.executescript(DDL)
            conn.execute("INSERT OR IGNORE INTO meta(key, value) VALUES ('schema_version', ?)", (str(SCHEMA_VERSION),))
            conn.execute("INSERT OR IGNORE INTO engagement(id) VALUES (1)")
            conn.execute(
                "INSERT OR IGNORE INTO principals(label, kind, notes, created_at) VALUES ('unauth', 'unauth', 'no cookies, no auth headers', ?)",
                (self.now(),),
            )

    # -- connection / transactions -------------------------------------------------

    @property
    def conn(self) -> sqlite3.Connection:
        c = getattr(self._local, "conn", None)
        if c is None:
            c = sqlite3.connect(str(self.db_path), timeout=self.busy_timeout_ms / 1000, isolation_level=None, check_same_thread=False)
            c.row_factory = sqlite3.Row
            c.execute(f"PRAGMA busy_timeout={int(self.busy_timeout_ms)}")
            c.execute("PRAGMA journal_mode=WAL")
            c.execute("PRAGMA foreign_keys=ON")
            c.execute("PRAGMA synchronous=NORMAL")
            self._local.conn = c
            self._local.depth = 0
        return c

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        conn = self.conn
        if self._local.depth:
            self._local.depth += 1
            try:
                yield conn
            finally:
                self._local.depth -= 1
            return
        conn.execute("BEGIN IMMEDIATE")
        self._local.depth = 1
        try:
            yield conn
        except BaseException:
            conn.execute("ROLLBACK")
            raise
        else:
            conn.execute("COMMIT")
        finally:
            self._local.depth = 0

    def close(self) -> None:
        c = getattr(self._local, "conn", None)
        if c is not None:
            c.close()
            self._local.conn = None

    def q(self, sql: str, params: tuple | list = ()) -> list[sqlite3.Row]:
        return self.conn.execute(sql, params).fetchall()

    def q1(self, sql: str, params: tuple | list = ()) -> sqlite3.Row | None:
        return self.conn.execute(sql, params).fetchone()

    # -- events / kv -----------------------------------------------------------------------

    def event(self, kind: str, entity: str | None = None, entity_id: int | None = None,
              from_state: str | None = None, to_state: str | None = None, detail: Any = None) -> int:
        progress = 0 if kind in NON_PROGRESS_EVENTS else 1
        cur = self.conn.execute(
            "INSERT INTO events(ts, kind, entity, entity_id, from_state, to_state, detail, progress) VALUES (?,?,?,?,?,?,?,?)",
            (self.now(), kind, entity, entity_id, from_state, to_state,
             detail if isinstance(detail, str) or detail is None else _j(detail), progress),
        )
        return int(cur.lastrowid)

    def last_progress_event_id(self) -> int:
        row = self.q1("SELECT MAX(id) AS m FROM events WHERE progress = 1")
        return int(row["m"] or 0)

    def kv_get(self, key: str, default: Any = None) -> Any:
        row = self.q1("SELECT value FROM kv WHERE key = ?", (key,))
        return _u(row["value"], default) if row else default

    def kv_set(self, key: str, value: Any) -> None:
        self.conn.execute("INSERT INTO kv(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", (key, _j(value)))

    # -- engagement ------------------------------------------------------------------------

    def sync_engagement(self, cfg) -> dict:
        """Write the parsed prompt.md (config.EngagementConfig) into the ledger and
        seed one principal per account row. Idempotent."""
        with self.tx() as c:
            c.execute(
                """UPDATE engagement SET target=?, scope_json=?, oos_json=?, oos_notes_json=?, programme=?,
                   marker_header_json=?, rate_limit_rps=?, oob_json=?, burp_proxy=?, burp_mcp_url=?, max_testers=?,
                   support_hosts_json=?, accounts_json=?, login_json=?, target_notes=?, prompt_hash=?, configured=?,
                   problems_json=?, updated_at=? WHERE id = 1""",
                (
                    cfg.target, _j(cfg.scope), _j(cfg.out_of_scope), _j(cfg.out_of_scope_notes), cfg.programme,
                    _j(list(cfg.marker_header) if cfg.marker_header else None), cfg.rate_limit_rps, _j(cfg.oob),
                    cfg.burp_proxy, cfg.burp_mcp_url, cfg.max_testers, _j(cfg.support_hosts),
                    _j([a.__dict__ for a in cfg.accounts]),
                    _j({"method": cfg.login_method, "notes": cfg.login_notes}), cfg.target_notes, cfg.prompt_hash,
                    1 if cfg.configured else 0, _j(cfg.problems), self.now(),
                ),
            )
            for acct in cfg.accounts:
                existing = self.q1("SELECT id FROM principals WHERE label = ?", (acct.label,))
                if existing is None:
                    c.execute(
                        "INSERT INTO principals(label, kind, account, browser, session_file, identifiers_json, notes, created_at) VALUES (?,?,?,?,?,?,?,?)",
                        (acct.label, "account", acct.account, acct.browser, self.paths.rel(self.paths.session_file(acct.label)),
                         _j([acct.account]), acct.role_text, self.now()),
                    )
                    self.event("principal.add", "principal", None, None, None, {"label": acct.label})
                else:
                    c.execute("UPDATE principals SET account=?, browser=? WHERE id=?", (acct.account, acct.browser, existing["id"]))
        return self.engagement()

    def engagement(self) -> dict:
        row = self.q1("SELECT * FROM engagement WHERE id = 1")
        d = dict(row)
        for k in ("scope_json", "oos_json", "oos_notes_json", "marker_header_json", "oob_json", "support_hosts_json",
                  "accounts_json", "login_json", "problems_json"):
            d[k[:-5]] = _u(d.pop(k), None)
        return d

    def scope(self) -> Scope:
        e = self.engagement()
        return Scope.from_lists(e.get("scope") or [], e.get("oos") or [], e.get("oos_notes") or [])

    def require_configured(self) -> dict:
        e = self.engagement()
        if not e.get("configured"):
            raise LedgerError("prompt.md is not filled in; nothing can be tested yet", e.get("problems") or ["fill prompt.md"])
        return e

    # -- principals ----------------------------------------------------------------------

    def add_principal(self, label: str, kind: str, *, account: str | None = None, browser: str | None = None,
                      session_file: str | None = None, identifiers: list[str] | None = None, notes: str | None = None) -> int:
        if kind not in PRINCIPAL_KINDS:
            raise LedgerError(f"principal kind must be one of {', '.join(PRINCIPAL_KINDS)}")
        if not label or not all(ch.isalnum() or ch in "-_." for ch in label):
            raise LedgerError("principal label must be non-empty and use letters, digits, '-', '_' or '.'")
        hedge.check(notes, "notes")
        sf = session_file or self.paths.rel(self.paths.session_file(label))
        with self.tx() as c:
            row = self.q1("SELECT id, identifiers_json FROM principals WHERE label = ?", (label,))
            if row:
                ids = _u(row["identifiers_json"], []) or []
                for ident in identifiers or []:
                    if ident not in ids:
                        ids.append(ident)
                c.execute(
                    "UPDATE principals SET kind=?, account=coalesce(?, account), browser=coalesce(?, browser), session_file=?, identifiers_json=?, notes=coalesce(?, notes) WHERE id=?",
                    (kind, account, browser, sf, _j(ids), notes, row["id"]),
                )
                self.event("principal.update", "principal", row["id"], detail={"label": label})
                return int(row["id"])
            cur = c.execute(
                "INSERT INTO principals(label, kind, account, browser, session_file, identifiers_json, notes, created_at) VALUES (?,?,?,?,?,?,?,?)",
                (label, kind, account, browser, sf, _j(list(identifiers or [])), notes, self.now()),
            )
            pid = int(cur.lastrowid)
            self.event("principal.add", "principal", pid, detail={"label": label, "kind": kind})
            return pid

    def principal(self, label_or_id: str | int) -> dict:
        if isinstance(label_or_id, int) or (isinstance(label_or_id, str) and label_or_id.isdigit()):
            row = self.q1("SELECT * FROM principals WHERE id = ?", (int(label_or_id),))
        else:
            row = self.q1("SELECT * FROM principals WHERE label = ?", (label_or_id,))
        if row is None:
            labels = [r["label"] for r in self.q("SELECT label FROM principals ORDER BY id")]
            raise LedgerError(f"unknown principal {label_or_id!r}; known: {', '.join(labels)}")
        d = dict(row)
        d["identifiers"] = _u(d.pop("identifiers_json"), []) or []
        return d

    def principals(self) -> list[dict]:
        out = []
        for row in self.q("SELECT * FROM principals ORDER BY id"):
            d = dict(row)
            d["identifiers"] = _u(d.pop("identifiers_json"), []) or []
            out.append(d)
        return out

    def known_identifiers(self) -> set[str]:
        out: set[str] = set()
        for p in self.principals():
            for ident in p["identifiers"]:
                out.add(str(ident).lower())
            if p.get("account"):
                out.add(str(p["account"]).lower())
        return out

    # -- traffic ---------------------------------------------------------------------------

    def add_request(self, *, source: str, method: str, url: str, host: str, raw_path: str | None,
                    content_hash: str, principal_id: int | None = None, status: int | None = None,
                    content_type: str | None = None, resp_len: int | None = None, ua_family: str | None = None,
                    truncated: bool = False, burp_offset: int | None = None) -> tuple[int, bool]:
        """Insert one observed exchange (deduplicated by content hash). Returns (id, created)."""
        with self.tx() as c:
            row = self.q1("SELECT id FROM requests WHERE content_hash = ?", (content_hash,))
            if row:
                return int(row["id"]), False
            cur = c.execute(
                """INSERT INTO requests(source, burp_offset, principal_id, method, url, host, status, content_type,
                   resp_len, ua_family, raw_path, truncated, content_hash, ts) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (source, burp_offset, principal_id, method.upper(), url, host, status, content_type, resp_len,
                 ua_family, raw_path, 1 if truncated else 0, content_hash, self.now()),
            )
            return int(cur.lastrowid), True

    def request(self, request_id: int) -> dict:
        row = self.q1("SELECT * FROM requests WHERE id = ?", (int(request_id),))
        if row is None:
            raise LedgerError(f"request {request_id} does not exist")
        return dict(row)

    def link_request(self, request_id: int, endpoint_id: int) -> None:
        self.conn.execute("UPDATE requests SET endpoint_id = ? WHERE id = ?", (endpoint_id, request_id))

    # -- endpoints / inputs --------------------------------------------------------------------

    def upsert_endpoint(self, *, origin: str, method: str, path_template: str, source: str = "traffic",
                        first_seen_request_id: int | None = None, family: str | None = None, feature: str | None = None,
                        auth_required: bool | None = None, content_type: str | None = None,
                        flags: dict | None = None) -> tuple[int, bool]:
        if source not in ENDPOINT_SOURCES:
            raise LedgerError(f"endpoint source must be one of {', '.join(ENDPOINT_SOURCES)}")
        self.require_configured()
        url = origin.rstrip("/") + (path_template if path_template.startswith("/") else "/" + path_template)
        try:
            self.scope().check_url(url.replace("{", "").replace("}", ""))
        except ScopeError as exc:
            raise LedgerError(f"endpoint refused: {exc}") from exc
        host = origin.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0].strip("[]").lower()
        method = method.upper()
        with self.tx() as c:
            row = self.q1("SELECT id, flags_json FROM endpoints WHERE origin=? AND method=? AND path_template=?", (origin, method, path_template))
            if row:
                if flags:
                    merged = (_u(row["flags_json"], {}) or {}) | flags
                    c.execute("UPDATE endpoints SET flags_json=? WHERE id=?", (_j(merged), row["id"]))
                if content_type:
                    c.execute("UPDATE endpoints SET content_type=coalesce(content_type, ?) WHERE id=?", (content_type, row["id"]))
                if auth_required is not None:
                    c.execute("UPDATE endpoints SET auth_required=coalesce(auth_required, ?) WHERE id=?", (1 if auth_required else 0, row["id"]))
                if first_seen_request_id:
                    c.execute("UPDATE endpoints SET first_seen_request_id=coalesce(first_seen_request_id, ?) WHERE id=?", (first_seen_request_id, row["id"]))
                return int(row["id"]), False
            cur = c.execute(
                """INSERT INTO endpoints(origin, host, method, path_template, family, feature, auth_required, content_type,
                   first_seen_request_id, source, flags_json, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (origin, host, method, path_template, family, feature,
                 None if auth_required is None else (1 if auth_required else 0), content_type,
                 first_seen_request_id, source, _j(flags or {}), self.now()),
            )
            eid = int(cur.lastrowid)
            self.event("endpoint.add", "endpoint", eid, detail={"method": method, "path": path_template, "source": source})
            return eid, True

    def endpoint(self, endpoint_id: int) -> dict:
        row = self.q1("SELECT * FROM endpoints WHERE id = ?", (int(endpoint_id),))
        if row is None:
            raise LedgerError(f"endpoint {endpoint_id} does not exist")
        d = dict(row)
        d["flags"] = _u(d.pop("flags_json"), {}) or {}
        return d

    def set_feature(self, endpoint_ids: list[int], feature: str) -> int:
        hedge.check(feature, "feature")
        with self.tx() as c:
            n = 0
            for eid in endpoint_ids:
                n += c.execute("UPDATE endpoints SET feature = ? WHERE id = ?", (feature, int(eid))).rowcount
            self.event("endpoint.feature", "endpoint", None, detail={"ids": endpoint_ids, "feature": feature})
            return n

    def lock_third_party(self, endpoint_id: int, detail: dict) -> None:
        with self.tx() as c:
            c.execute("UPDATE endpoints SET third_party_lock = 1 WHERE id = ?", (endpoint_id,))
            self.event("endpoint.third_party_lock", "endpoint", endpoint_id, detail=detail)

    def upsert_input(self, *, endpoint_id: int, name: str, location: str, json_path: str | None = None,
                     sample_value: str | None = None, value_type: str | None = None) -> tuple[int, bool]:
        if location not in INPUT_LOCATIONS:
            raise LedgerError(f"input location must be one of {', '.join(INPUT_LOCATIONS)}")
        with self.tx() as c:
            row = self.q1("SELECT id FROM inputs WHERE endpoint_id=? AND location=? AND name=?", (endpoint_id, location, name))
            if row:
                return int(row["id"]), False
            sample = None if sample_value is None else str(sample_value)[:500]
            cur = c.execute(
                "INSERT INTO inputs(endpoint_id, name, location, json_path, sample_value, value_type, created_at) VALUES (?,?,?,?,?,?,?)",
                (endpoint_id, name, location, json_path, sample, value_type, self.now()),
            )
            iid = int(cur.lastrowid)
            self.event("input.add", "input", iid, detail={"endpoint": endpoint_id, "name": name, "location": location})
            return iid, True

    def input(self, input_id: int) -> dict:
        row = self.q1("SELECT * FROM inputs WHERE id = ?", (int(input_id),))
        if row is None:
            raise LedgerError(f"input {input_id} does not exist")
        d = dict(row)
        d["reflection_contexts"] = _u(d["reflection_contexts"], []) or []
        return d

    def add_reflection_contexts(self, input_id: int, contexts: list[str]) -> list[str]:
        with self.tx() as c:
            cur = set(self.input(input_id)["reflection_contexts"])
            new = sorted(cur | set(contexts))
            if new != sorted(cur):
                c.execute("UPDATE inputs SET reflection_contexts = ? WHERE id = ?", (_j(new), input_id))
                self.event("input.reflection", "input", input_id, detail={"contexts": new})
            return new

    # -- cells ----------------------------------------------------------------------------------

    def open_cell(self, *, endpoint_id: int, input_id: int | None, vuln_class: str, context: dict | None = None,
                  source: str = "rule", priority: int | None = None, note: str | None = None) -> tuple[int, bool]:
        vc = C.get(vuln_class)
        if vc.level == "input" and input_id is None:
            raise LedgerError(f"{vuln_class} is an input-level class; pass input_id")
        hedge.check(note, "note")
        with self.tx() as c:
            row = self.q1(
                "SELECT id FROM cells WHERE endpoint_id = ? AND ifnull(input_id, 0) = ? AND vuln_class = ?",
                (endpoint_id, input_id or 0, vuln_class),
            )
            if row:
                return int(row["id"]), False
            cur = c.execute(
                """INSERT INTO cells(endpoint_id, input_id, vuln_class, state, context_json, priority, source, salt, note, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
                (endpoint_id, input_id, vuln_class, "open", _j(context or {}),
                 priority if priority is not None else vc.base_priority, source, secrets.token_hex(8), note,
                 self.now(), self.now()),
            )
            cid = int(cur.lastrowid)
            self.event("cell.open", "cell", cid, None, "open", {"class": vuln_class, "endpoint": endpoint_id, "input": input_id, "source": source})
            return cid, True

    def cell(self, cell_id: int) -> dict:
        row = self.q1("SELECT * FROM cells WHERE id = ?", (int(cell_id),))
        if row is None:
            raise LedgerError(f"cell {cell_id} does not exist")
        d = dict(row)
        d["context"] = _u(d.pop("context_json"), {}) or {}
        d["verifier"] = _u(d.pop("verifier_json"), None)
        return d

    def update_cell_context(self, cell_id: int, updates: dict) -> dict:
        with self.tx() as c:
            ctx = self.cell(cell_id)["context"] | updates
            c.execute("UPDATE cells SET context_json = ?, updated_at = ? WHERE id = ?", (_j(ctx), self.now(), cell_id))
            return ctx

    def _set_state(self, cell_id: int, expected: tuple[str, ...], new_state: str, kind: str, detail: dict | None = None,
                   **cols: Any) -> None:
        """The single place a cell's state changes. Touches only this row."""
        if new_state not in CELL_STATES:
            raise LedgerError(f"invalid state {new_state!r}")
        cur = self.cell(cell_id)
        if cur["state"] not in expected:
            raise LedgerError(f"cell {cell_id} is {cur['state']}; this transition needs one of: {', '.join(expected)}")
        sets = ["state = ?", "updated_at = ?"]
        vals: list[Any] = [new_state, self.now()]
        for k, v in cols.items():
            sets.append(f"{k} = ?")
            vals.append(v)
        vals += [cell_id, cur["state"]]
        n = self.conn.execute(f"UPDATE cells SET {', '.join(sets)} WHERE id = ? AND state = ?", vals).rowcount
        if n != 1:
            raise LedgerError(f"cell {cell_id} changed concurrently; re-read it and retry")
        self.event(kind, "cell", cell_id, cur["state"], new_state, detail)

    def expire_claims(self) -> int:
        cutoff = self.now() - CLAIM_TTL_S
        with self.tx():
            rows = self.q("SELECT id, state FROM cells WHERE claimed_at IS NOT NULL AND claimed_at < ?", (cutoff,))
            for r in rows:
                if r["state"] == "in_progress":
                    self._set_state(r["id"], ("in_progress",), "open", "cell.claim_expired", claimed_by=None, claimed_at=None)
                else:
                    self.conn.execute("UPDATE cells SET claimed_by = NULL, claimed_at = NULL WHERE id = ?", (r["id"],))
            drows = self.q("SELECT id FROM depth_queue WHERE state = 'in_progress' AND claimed_at < ?", (cutoff,))
            for r in drows:
                self.conn.execute("UPDATE depth_queue SET state = 'open', claimed_by = NULL, claimed_at = NULL WHERE id = ?", (r["id"],))
                self.event("depth.claim_expired", "depth", r["id"], "in_progress", "open")
            return len(rows) + len(drows)

    def claim_cell(self, cell_id: int, agent: str) -> dict:
        with self.tx():
            cur = self.cell(cell_id)
            if cur["claimed_by"] and cur["claimed_by"] != agent and cur["claimed_at"] and cur["claimed_at"] >= self.now() - CLAIM_TTL_S:
                raise LedgerError(f"cell {cell_id} is claimed by {cur['claimed_by']}")
            if cur["state"] == "open":
                self._set_state(cell_id, ("open",), "in_progress", "cell.claim", {"agent": agent},
                                claimed_by=agent, claimed_at=self.now())
            elif cur["state"] in ("in_progress", "candidate"):
                self.conn.execute("UPDATE cells SET claimed_by = ?, claimed_at = ? WHERE id = ?", (agent, self.now(), cell_id))
                self.event("cell.claim", "cell", cell_id, cur["state"], cur["state"], {"agent": agent})
            else:
                raise LedgerError(f"cell {cell_id} is {cur['state']}; only open, in_progress or candidate cells can be claimed")
            return self.cell(cell_id)

    def release_cell(self, cell_id: int, note: str | None = None) -> dict:
        hedge.check(note, "note")
        with self.tx():
            cur = self.cell(cell_id)
            if cur["state"] == "in_progress":
                self._set_state(cell_id, ("in_progress",), "open", "cell.release", {"note": note},
                                claimed_by=None, claimed_at=None, note=note or cur["note"])
            else:
                self.conn.execute("UPDATE cells SET claimed_by = NULL, claimed_at = NULL WHERE id = ?", (cell_id,))
                self.event("cell.release", "cell", cell_id, cur["state"], cur["state"], {"note": note})
            return self.cell(cell_id)

    def reopen_cell(self, cell_id: int, reason: str) -> dict:
        if not reason:
            raise LedgerError("reopen_cell needs a reason (depth re-test, unblocked, new evidence)")
        hedge.check(reason, "reason")
        with self.tx():
            self._set_state(cell_id, ("negative", "n_a", "blocked"), "open", "cell.reopen", {"reason": reason},
                            claimed_by=None, claimed_at=None, reason=None, reason_request_id=None, unblock=None,
                            note=reason)
            return self.cell(cell_id)

    # -- planned cases ------------------------------------------------------------------------

    def store_plan(self, cell_id: int, cases: list[dict]) -> int:
        """Persist generated cases. Existing case numbers are never rewritten."""
        with self.tx() as c:
            n = 0
            for case in cases:
                cur = c.execute(
                    """INSERT OR IGNORE INTO planned_cases(cell_id, case_no, technique, is_control, payload, mutation_json,
                       positive_json, negative, route, principal, repeat, needs_counter_read, description, extra_json)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (cell_id, int(case["case_no"]), case["technique"], 1 if case.get("is_control") else 0,
                     case.get("payload"), _j(case.get("mutation") or []), _j(case.get("positive") or {}),
                     case.get("negative"), case.get("route") or "sender", case.get("principal"),
                     int(case.get("repeat") or 1), 1 if case.get("needs_counter_read") else 0,
                     case.get("description"), _j(case.get("extra") or {})),
                )
                n += cur.rowcount
            return n

    def plan_for(self, cell_id: int) -> list[dict]:
        out = []
        for r in self.q("SELECT * FROM planned_cases WHERE cell_id = ? ORDER BY case_no", (cell_id,)):
            d = dict(r)
            d["mutation"] = _u(d.pop("mutation_json"), [])
            d["positive"] = _u(d.pop("positive_json"), {})
            d["extra"] = _u(d.pop("extra_json"), {})
            d["is_control"] = bool(d["is_control"])
            d["needs_counter_read"] = bool(d["needs_counter_read"])
            out.append(d)
        return out

    def planned_case(self, cell_id: int, case_no: int) -> dict | None:
        for d in self.plan_for(cell_id):
            if d["case_no"] == int(case_no):
                return d
        return None

    # -- test cases -----------------------------------------------------------------------------

    def _capture_ok(self, rel: str | None) -> bool:
        if not rel:
            return False
        p = self.paths.abs(rel)
        try:
            return p.is_file() and p.stat().st_size > 0
        except OSError:
            return False

    def record_case(self, *, cell_id: int, case_no: int, technique: str, outcome: str, observation: str,
                    request_capture: str | None, response_capture: str | None, payload: str | None = None,
                    principal: str | int | None = None, route: str = "sender", counter_capture: str | None = None,
                    elapsed_ms: int | None = None, status: int | None = None) -> dict:
        if outcome not in OUTCOMES:
            raise LedgerError(f"outcome must be one of {', '.join(OUTCOMES)}")
        if not observation or not observation.strip():
            raise LedgerError("observation is required: state what the response showed, with the capture filename")
        hedge.check(observation, "observation")
        if not technique or "." not in technique:
            raise LedgerError("technique must be a dotted id like '<class>.<family>.<variant>'")
        cell = self.cell(cell_id)
        missing = []
        need_caps = outcome != "inconclusive"
        for label, cap in (("request_capture", request_capture), ("response_capture", response_capture)):
            if cap and not self._capture_ok(cap):
                missing.append(f"{label} {cap!r} does not exist or is empty")
            elif need_caps and not cap:
                missing.append(f"{label} is required for outcome {outcome}")
        if counter_capture and not self._capture_ok(counter_capture):
            missing.append(f"counter_capture {counter_capture!r} does not exist or is empty")
        if missing:
            raise LedgerError(f"case {case_no} on cell {cell_id} refused", missing)
        pid = self.principal(principal)["id"] if principal not in (None, "") else None
        with self.tx() as c:
            row = self.q1("SELECT MAX(attempt) AS a FROM test_cases WHERE cell_id = ? AND case_no = ?", (cell_id, case_no))
            attempt = int(row["a"] or 0) + 1
            cur = c.execute(
                """INSERT INTO test_cases(cell_id, case_no, attempt, technique, payload, principal_id, request_capture,
                   response_capture, counter_capture, observation, outcome, route, elapsed_ms, status, ts)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (cell_id, int(case_no), attempt, technique, payload, pid,
                 self.paths.rel(request_capture) if request_capture else None,
                 self.paths.rel(response_capture) if response_capture else None,
                 self.paths.rel(counter_capture) if counter_capture else None,
                 observation.strip(), outcome, route, elapsed_ms, status, self.now()),
            )
            tcid = int(cur.lastrowid)
            self.event("case.record", "test_case", tcid, None, outcome, {"cell": cell_id, "case_no": case_no, "technique": technique})
            state = cell["state"]
            if outcome == "positive" and state in ("open", "in_progress", "negative", "n_a", "blocked"):
                self._set_state(cell_id, (state,), "candidate", "cell.candidate",
                                {"case_no": case_no, "test_case": tcid, "observation": observation})
            elif outcome == "control_fail":
                note = f"tooling: control case {case_no} failed ({observation.strip()[:200]})"
                if state == "in_progress":
                    self._set_state(cell_id, ("in_progress",), "open", "cell.control_fail", {"case_no": case_no},
                                    note=note, claimed_by=None, claimed_at=None)
                else:
                    c.execute("UPDATE cells SET note = ?, updated_at = ? WHERE id = ?", (note, self.now(), cell_id))
                    self.event("cell.control_fail", "cell", cell_id, state, state, {"case_no": case_no})
            return {"test_case_id": tcid, "attempt": attempt, "cell_state": self.cell(cell_id)["state"]}

    def latest_cases(self, cell_id: int) -> list[dict]:
        rows = self.q(
            """SELECT tc.* FROM test_cases tc
               JOIN (SELECT case_no, MAX(attempt) AS a FROM test_cases WHERE cell_id = ? GROUP BY case_no) l
                 ON tc.case_no = l.case_no AND tc.attempt = l.a
               WHERE tc.cell_id = ? ORDER BY tc.case_no""",
            (cell_id, cell_id),
        )
        return [dict(r) for r in rows]

    def all_cases(self, cell_id: int) -> list[dict]:
        return [dict(r) for r in self.q("SELECT * FROM test_cases WHERE cell_id = ? ORDER BY case_no, attempt", (cell_id,))]

    def evidence_status(self, cell_id: int) -> dict:
        """What a negative close would need, computed from the latest attempt per case."""
        cell = self.cell(cell_id)
        req = C.requirements(cell["vuln_class"], cell["context"])
        latest = self.latest_cases(cell_id)
        plan = {p["case_no"]: p for p in self.plan_for(cell_id)}
        counter_families = _counter_read_families(cell["vuln_class"])
        negatives, problems, positives = [], [], []
        for r in latest:
            if r["outcome"] == "positive":
                positives.append(r["case_no"])
            if r["outcome"] != "negative":
                continue
            planned = plan.get(r["case_no"])
            needs_counter = (planned and planned["needs_counter_read"]) or (
                counter_families is not None and (counter_families == "*" or C.technique_family(r["technique"]) in counter_families)
                and C.technique_family(r["technique"]) != "control")
            if needs_counter and not self._capture_ok(r["counter_capture"]):
                problems.append(f"case {r['case_no']} ({r['technique']}) is a write without a counter-read capture; it does not count")
                continue
            if not (self._capture_ok(r["request_capture"]) and self._capture_ok(r["response_capture"])):
                problems.append(f"case {r['case_no']} cites a capture that is missing or empty; it does not count")
                continue
            negatives.append(r)
        controls = [r for r in latest if r["outcome"] in ("control_pass", "control_fail")]
        passing_controls = [r for r in controls if r["outcome"] == "control_pass"
                            and self._capture_ok(r["request_capture"]) and self._capture_ok(r["response_capture"])]
        failing_controls = [r for r in controls if r["outcome"] == "control_fail"]
        # A technique id is "<class>.<family>": ten variants of one idea are one technique.
        techniques = sorted({C.technique_id(r["technique"]) for r in negatives})
        families = {C.technique_family(t) for t in techniques}
        inconclusive = [r["case_no"] for r in latest if r["outcome"] == "inconclusive"]
        missing: list[str] = []
        if len(negatives) < req["min_cases"]:
            missing.append(f"{req['min_cases'] - len(negatives)} more executed negative case(s) (have {len(negatives)} of {req['min_cases']}; inconclusive cases never count)")
        if len(techniques) < req["min_techniques"]:
            missing.append(f"{req['min_techniques'] - len(techniques)} more distinct technique id(s) '<class>.<family>' among negatives (have {len(techniques)} of {req['min_techniques']}: {', '.join(techniques) or 'none'})")
        for fam in req["required_families"]:
            if fam not in families:
                missing.append(f"at least one negative case from the required '{cell['vuln_class']}.{fam}.*' family")
        if not passing_controls:
            missing.append("a control case with outcome control_pass (same request, same tooling, a shape known to work)")
        if failing_controls:
            missing.append("control case(s) " + ", ".join(str(r["case_no"]) for r in failing_controls)
                           + " failed: fix the tooling and re-run the control until it passes")
        for fam in req["required_control_families"]:
            if not any(C.technique_family(r["technique"]) == fam for r in passing_controls):
                missing.append(f"a passing control from the '{cell['vuln_class']}.{fam}.*' family (for example the timing baseline)")
        if positives:
            missing.append("case(s) " + ", ".join(map(str, positives)) + " are positive: confirm via open_finding, or re-run them and record what the response showed")
        if req["needs_oob"]:
            oob = self.engagement().get("oob") or {}
            if oob.get("mode") in (None, "none"):
                missing.append("an OOB listener: without one this class can only close as blocked: no_oob_listener")
        return {
            "ok": not missing,
            "missing": missing,
            "negative_cases": len(negatives),
            "techniques": techniques,
            "families": sorted(families),
            "controls_passed": len(passing_controls),
            "controls_failed": len(failing_controls),
            "inconclusive_cases": inconclusive,
            "positive_cases": positives,
            "problems": problems,
            "requirements": req,
        }

    def close_cell(self, cell_id: int, state: str, *, reason: str | None = None, reason_request_id: int | None = None,
                   unblock: str | None = None, note: str | None = None) -> dict:
        hedge.check_many({"reason": reason, "unblock": unblock, "note": note})
        cell = self.cell(cell_id)
        vc = C.get(cell["vuln_class"])
        with self.tx():
            cell = self.cell(cell_id)
            current = cell["state"]
            if state == "negative":
                ev = self.evidence_status(cell_id)
                missing = list(ev["missing"])
                if current == "candidate":
                    v = cell["verifier"] or {}
                    if v.get("verdict") != "refuted":
                        missing.append("verifier sign-off: a candidate goes negative only after the verifier agent records verdict 'refuted' (verifier_signoff)")
                if missing:
                    raise LedgerError(f"cell {cell_id} ({vc.name}) cannot close negative", missing)
                self._set_state(cell_id, ("open", "in_progress", "candidate"), "negative", "cell.close",
                                {"evidence": {k: ev[k] for k in ("negative_cases", "techniques", "controls_passed")}},
                                claimed_by=None, claimed_at=None, note=note or cell["note"], reason=None, unblock=None)
                self._retire_draft_finding(cell_id, "cell closed negative after verifier refuted it")
            elif state == "n_a":
                missing = []
                if reason not in vc.na_reasons:
                    missing.append(f"reason from this class's n_a list: {', '.join(vc.na_reasons)}")
                if reason_request_id is None:
                    missing.append("reason_request_id: the id of a request that proves the reason")
                elif self.q1("SELECT id FROM requests WHERE id = ?", (int(reason_request_id),)) is None:
                    missing.append(f"reason_request_id {reason_request_id} is not a recorded request")
                if current == "candidate":
                    missing.append("a candidate cannot become n_a; it was observed to respond, so confirm it or refute it with the verifier")
                if missing:
                    raise LedgerError(f"cell {cell_id} ({vc.name}) cannot close n_a", missing)
                self._set_state(cell_id, ("open", "in_progress"), "n_a", "cell.close", {"reason": reason},
                                claimed_by=None, claimed_at=None, reason=reason, reason_request_id=int(reason_request_id),
                                note=note or cell["note"])
            elif state == "blocked":
                missing = []
                if reason not in C.BLOCKED_REASONS:
                    missing.append(f"reason from: {', '.join(C.BLOCKED_REASONS)}")
                if not unblock or not unblock.strip():
                    missing.append("unblock: what concretely would unblock this cell")
                if current == "candidate":
                    v = cell["verifier"] or {}
                    if v.get("verdict") not in ("refuted", "blocked"):
                        missing.append("verifier sign-off with verdict 'blocked' (a candidate never dies silently)")
                if missing:
                    raise LedgerError(f"cell {cell_id} ({vc.name}) cannot close blocked", missing)
                self._set_state(cell_id, ("open", "in_progress", "candidate"), "blocked", "cell.close",
                                {"reason": reason, "unblock": unblock}, claimed_by=None, claimed_at=None,
                                reason=reason, unblock=unblock.strip(), note=note or cell["note"])
                self._retire_draft_finding(cell_id, f"cell blocked: {reason}")
            elif state == "confirmed":
                raise LedgerError("a cell becomes confirmed only through verify_finding (two passing replays >= 60 s apart)")
            elif state == "candidate":
                raise LedgerError("a cell becomes candidate automatically when a case records outcome 'positive'")
            elif state in ("open", "in_progress"):
                raise LedgerError("use release_cell (in_progress -> open) or reopen_cell (negative/n_a/blocked -> open)")
            else:
                raise LedgerError(f"unknown state {state!r}")
            return self.cell(cell_id)

    def verifier_signoff(self, *, target: str, target_id: int, verdict: str, rationale: str, agent: str = "verifier",
                         rung: str | None = None) -> dict:
        if not rationale or not rationale.strip():
            raise LedgerError("rationale is required: what in the evidence decided the verdict, with capture filenames")
        hedge.check(rationale, "rationale")
        record = {"verdict": verdict, "rationale": rationale.strip(), "agent": agent, "ts": self.now()}
        with self.tx() as c:
            if target == "cell":
                if verdict not in ("refuted", "upheld", "blocked"):
                    raise LedgerError("cell verdict must be refuted, upheld or blocked")
                cell = self.cell(target_id)
                if cell["state"] != "candidate":
                    raise LedgerError(f"cell {target_id} is {cell['state']}; sign-off applies to candidates")
                c.execute("UPDATE cells SET verifier_json = ?, updated_at = ? WHERE id = ?", (_j(record), self.now(), target_id))
                self.event("cell.verifier", "cell", target_id, cell["state"], cell["state"], record)
                return self.cell(target_id)
            if target == "finding":
                if verdict not in ("upheld", "refuted"):
                    raise LedgerError("finding verdict must be upheld or refuted")
                f = self.finding(target_id)
                drafts = [r for r in f["rungs"] if r["status"] == "draft"]
                if rung is None:
                    if not drafts:
                        raise LedgerError(f"finding {target_id} has no draft rung awaiting sign-off")
                    rung = max(drafts, key=lambda r: r["rung_index"])["rung"]
                row = next((r for r in f["rungs"] if r["rung"] == rung), None)
                if row is None:
                    raise LedgerError(f"finding {target_id} has no rung {rung!r}")
                if row["status"] != "draft":
                    raise LedgerError(f"rung {rung!r} is already {row['status']}")
                record["rung"] = rung
                c.execute("UPDATE finding_rungs SET verifier_json = ?, updated_at = ? WHERE id = ?", (_j(record), self.now(), row["id"]))
                if verdict == "refuted":
                    c.execute("UPDATE finding_rungs SET status = 'failed', updated_at = ? WHERE id = ?", (self.now(), row["id"]))
                c.execute("UPDATE findings SET verifier_json = ?, updated_at = ? WHERE id = ?", (_j(record), self.now(), target_id))
                self.event("finding.verifier", "finding", target_id, f["status"], f["status"], record)
                self._maybe_promote(target_id)
                return self.finding(target_id)
        raise LedgerError("target must be 'cell' or 'finding'")

    def _retire_draft_finding(self, cell_id: int, why: str) -> None:
        f = self.finding_for_cell(cell_id)
        if f and f["status"] == "draft":
            self.conn.execute("UPDATE findings SET status = 'killed', updated_at = ? WHERE id = ?", (self.now(), f["id"]))
            self.event("finding.retired", "finding", f["id"], "draft", "killed", {"why": why})

    # -- findings ----------------------------------------------------------------------------------

    def finding(self, finding_id: int) -> dict:
        row = self.q1("SELECT * FROM findings WHERE id = ?", (int(finding_id),))
        if row is None:
            raise LedgerError(f"finding {finding_id} does not exist")
        d = dict(row)
        d["impact"] = _u(d.pop("impact_json"), []) or []
        d["escalation_blocked_by"] = _u(d.pop("escalation_blocked_by_json"), []) or []
        d["verifier"] = _u(d.pop("verifier_json"), None)
        d["rungs"] = []
        for r in self.q("SELECT * FROM finding_rungs WHERE finding_id = ? ORDER BY rung_index", (finding_id,)):
            rd = dict(r)
            rd["assertion"] = _u(rd.pop("assertion_json"), {})
            rd["verifier"] = _u(rd.pop("verifier_json"), None)
            d["rungs"].append(rd)
        return d

    def finding_for_cell(self, cell_id: int) -> dict | None:
        row = self.q1("SELECT id FROM findings WHERE cell_id = ?", (cell_id,))
        return self.finding(row["id"]) if row else None

    def open_finding(self, *, cell_id: int, rung: str, assertion: dict, title: str, severity: str,
                     summary: str | None = None, root_cause: str | None = None, impact: list[str] | None = None) -> dict:
        from .assertions import validate

        cell = self.cell(cell_id)
        vc = C.get(cell["vuln_class"])
        missing: list[str] = []
        try:
            idx = vc.rung_index(rung)
        except KeyError as exc:
            raise LedgerError(str(exc)) from exc
        if idx < vc.min_rung_index:
            missing.append(f"rung {rung!r} is a signal, not a finding; the lowest reportable rung of {vc.name} is {vc.min_rung!r}")
        if severity not in SEVERITIES:
            missing.append(f"severity from: {', '.join(SEVERITIES)}")
        if not title or not title.strip():
            missing.append("title")
        if cell["state"] not in ("candidate", "confirmed"):
            missing.append(f"cell {cell_id} is {cell['state']}: record the positive case first (run_cases / send_case / record_case)")
        missing += [f"assertion: {p}" for p in validate(assertion, self.paths.root)]
        hedge.check_many({"title": title, "summary": summary, "root_cause": root_cause,
                          "impact": "\n".join(impact or [])})
        if missing:
            raise LedgerError(f"finding on cell {cell_id} refused", missing)
        with self.tx() as c:
            existing = self.finding_for_cell(cell_id)
            if existing is None:
                cur = c.execute(
                    """INSERT INTO findings(cell_id, rung, rung_index, title, severity, summary, root_cause, impact_json, status, created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?, 'draft', ?, ?)""",
                    (cell_id, rung, idx, title.strip(), severity, summary, root_cause, _j(impact or []), self.now(), self.now()),
                )
                fid = int(cur.lastrowid)
                self.event("finding.open", "finding", fid, None, "draft", {"cell": cell_id, "rung": rung})
            else:
                fid = existing["id"]
                c.execute(
                    "UPDATE findings SET title = ?, severity = ?, summary = coalesce(?, summary), root_cause = coalesce(?, root_cause), impact_json = ?, updated_at = ? WHERE id = ?",
                    (title.strip(), severity, summary, root_cause, _j(impact or existing["impact"]), self.now(), fid),
                )
                self.event("finding.update", "finding", fid, existing["status"], existing["status"], {"rung": rung})
            prior = self.q1("SELECT status FROM finding_rungs WHERE finding_id = ? AND rung = ?", (fid, rung))
            if prior and prior["status"] == "verified":
                raise LedgerError(f"rung {rung!r} of finding {fid} is already verified; open a higher rung to climb")
            c.execute(
                """INSERT INTO finding_rungs(finding_id, rung, rung_index, assertion_json, status, created_at, updated_at)
                   VALUES (?,?,?,?, 'draft', ?, ?)
                   ON CONFLICT(finding_id, rung) DO UPDATE SET assertion_json = excluded.assertion_json, status = 'draft', updated_at = excluded.updated_at""",
                (fid, rung, idx, _j(assertion), self.now(), self.now()),
            )
            self.event("finding.rung", "finding", fid, None, "draft", {"rung": rung})
            return self.finding(fid)

    def escalation_blocked(self, finding_id: int, attempted_rung: str, blocked_by: str) -> dict:
        if not blocked_by or not blocked_by.strip():
            raise LedgerError("blocked_by: what stopped the climb, as observed (e.g. the CSP header value and the capture)")
        hedge.check(blocked_by, "blocked_by")
        f = self.finding(finding_id)
        vc = C.get(self.cell(f["cell_id"])["vuln_class"])
        ladders = set(vc.ladder) | {"script_executes", "dangling_markup"}
        if attempted_rung not in ladders:
            raise LedgerError(f"{attempted_rung!r} is not a rung on this ladder ({', '.join(vc.ladder)})")
        with self.tx() as c:
            items = f["escalation_blocked_by"] + [{"rung": attempted_rung, "blocked_by": blocked_by.strip(), "ts": self.now()}]
            c.execute("UPDATE findings SET escalation_blocked_by_json = ?, updated_at = ? WHERE id = ?", (_j(items), self.now(), finding_id))
            c.execute("UPDATE finding_rungs SET status = 'failed', updated_at = ? WHERE finding_id = ? AND rung = ? AND status = 'draft'",
                      (self.now(), finding_id, attempted_rung))
            self.event("finding.escalation_blocked", "finding", finding_id, f["status"], f["status"],
                       {"rung": attempted_rung, "blocked_by": blocked_by})
            return self.finding(finding_id)

    def record_verification(self, finding_id: int, rung: str, passed: bool, detail: str, run_dir: str | None,
                            started_at: float, finished_at: float) -> dict:
        with self.tx() as c:
            f = self.finding(finding_id)
            if not any(r["rung"] == rung for r in f["rungs"]):
                raise LedgerError(f"finding {finding_id} has no rung {rung!r}")
            c.execute(
                "INSERT INTO verifications(finding_id, rung, passed, detail, run_dir, started_at, finished_at) VALUES (?,?,?,?,?,?,?)",
                (finding_id, rung, 1 if passed else 0, detail, run_dir, started_at, finished_at),
            )
            self.event("finding.verification", "finding", finding_id, f["status"], f["status"],
                       {"rung": rung, "passed": bool(passed)})
            self._maybe_promote(finding_id)
            return self.finding(finding_id)

    def verification_state(self, finding_id: int, rung: str) -> dict:
        runs = [dict(r) for r in self.q(
            "SELECT * FROM verifications WHERE finding_id = ? AND rung = ? ORDER BY id DESC", (finding_id, rung))]
        last_two = runs[:2]
        two_pass = len(last_two) == 2 and all(r["passed"] for r in last_two)
        gap = (last_two[0]["finished_at"] - last_two[1]["finished_at"]) if len(last_two) == 2 else 0.0
        next_at = None
        if runs and runs[0]["passed"] and not (two_pass and gap >= VERIFY_GAP_S):
            next_at = runs[0]["finished_at"] + VERIFY_GAP_S
        return {"runs": len(runs), "last_two_passed": two_pass, "gap_s": gap,
                "satisfied": two_pass and gap >= VERIFY_GAP_S, "next_run_not_before": next_at}

    def _maybe_promote(self, finding_id: int) -> None:
        """A rung is verified when its last two replays passed >= 60 s apart AND the
        verifier upheld that rung. The finding's rung only ever rises."""
        f = self.finding(finding_id)
        cell = self.cell(f["cell_id"])
        for r in f["rungs"]:
            if r["status"] != "draft":
                continue
            upheld = (r.get("verifier") or {}).get("verdict") == "upheld"
            if not upheld or not self.verification_state(finding_id, r["rung"])["satisfied"]:
                continue
            self.conn.execute("UPDATE finding_rungs SET status = 'verified', updated_at = ? WHERE id = ?", (self.now(), r["id"]))
            self.event("finding.rung_verified", "finding", finding_id, "draft", "verified", {"rung": r["rung"]})
        f = self.finding(finding_id)
        verified = [r for r in f["rungs"] if r["status"] == "verified"]
        if not verified:
            return
        top = max(verified, key=lambda r: r["rung_index"])
        if top["rung_index"] > f["rung_index"] or (top["rung_index"] == f["rung_index"] and f["rung"] != top["rung"]):
            self.conn.execute("UPDATE findings SET rung = ?, rung_index = ?, updated_at = ? WHERE id = ?",
                              (top["rung"], top["rung_index"], self.now(), finding_id))
            self.event("finding.climb", "finding", finding_id, f["rung"], top["rung"])
        if f["status"] == "draft":
            self.conn.execute("UPDATE findings SET status = 'verified', updated_at = ? WHERE id = ?", (self.now(), finding_id))
            self.event("finding.verified", "finding", finding_id, "draft", "verified")
        if cell["state"] == "candidate":
            self._set_state(cell["id"], ("candidate",), "confirmed", "cell.confirmed", {"finding": finding_id},
                            claimed_by=None, claimed_at=None)

    def set_report(self, finding_id: int, report_path: str, report_no: int) -> dict:
        with self.tx() as c:
            f = self.finding(finding_id)
            if f["status"] not in ("verified", "gated"):
                raise LedgerError(f"finding {finding_id} is {f['status']}; reports are rendered only for verified findings")
            c.execute("UPDATE findings SET report_path = ?, report_no = ?, updated_at = ? WHERE id = ?",
                      (self.paths.rel(report_path), report_no, self.now(), finding_id))
            self.event("finding.report", "finding", finding_id, f["status"], f["status"], {"report": report_path})
            return self.finding(finding_id)

    def next_report_no(self) -> int:
        row = self.q1("SELECT MAX(report_no) AS m FROM findings")
        used = int(row["m"] or 0)
        n = used + 1
        while self.paths.abs(f"report-{n}.md").exists():
            n += 1
        return n

    def record_triage(self, finding_id: int, verdict: str, objection: str | None, required_evidence: str | None) -> dict:
        verdict = (verdict or "").upper()
        if verdict not in ("ACCEPT", "REJECT"):
            raise LedgerError("verdict must be ACCEPT or REJECT")
        with self.tx() as c:
            f = self.finding(finding_id)
            if f["status"] not in ("verified", "gated"):
                raise LedgerError(f"finding {finding_id} is {f['status']}; triage runs on verified findings with a rendered report")
            if not f["report_path"] or not self.paths.abs(f["report_path"]).is_file():
                raise LedgerError(f"finding {finding_id} has no rendered report; call render_report first")
            if verdict == "REJECT" and not (required_evidence and required_evidence.strip()):
                raise LedgerError("a REJECT must name the exact evidence that would make the report acceptable (required_evidence)")
            rnd = int(self.q1("SELECT COUNT(*) AS n FROM triage WHERE finding_id = ?", (finding_id,))["n"]) + 1
            c.execute("INSERT INTO triage(finding_id, round, verdict, objection, required_evidence, ts) VALUES (?,?,?,?,?,?)",
                      (finding_id, rnd, verdict, objection, required_evidence, self.now()))
            self.event("finding.triage", "finding", finding_id, f["status"], f["status"], {"round": rnd, "verdict": verdict})
            rejects = int(self.q1("SELECT COUNT(*) AS n FROM triage WHERE finding_id = ? AND verdict = 'REJECT'", (finding_id,))["n"])
            if verdict == "ACCEPT":
                c.execute("UPDATE findings SET status = 'gated', updated_at = ? WHERE id = ?", (self.now(), finding_id))
                self.event("finding.gated", "finding", finding_id, f["status"], "gated")
            elif rejects >= MAX_TRIAGE_REJECTS:
                c.execute("UPDATE findings SET status = 'killed', updated_at = ? WHERE id = ?", (self.now(), finding_id))
                self.event("finding.killed", "finding", finding_id, f["status"], "killed", {"objection": objection})
            return self.finding(finding_id)

    # -- depth queue ---------------------------------------------------------------------------------

    def add_depth_item(self, *, kind: int, title: str, detail: dict | None = None, source: str = "rule",
                       test_plan: str | None = None, dedupe_key: str | None = None) -> tuple[int, bool]:
        if not 1 <= int(kind) <= 8:
            raise LedgerError("depth kind must be 1..8 (see design.md Section 10)")
        if source == "model" and not (test_plan and test_plan.strip()):
            raise LedgerError("a model hypothesis needs a concrete test_plan before it is accepted into the queue")
        hedge.check_many({"title": title, "test_plan": test_plan})
        key = dedupe_key or f"{kind}:{title}"
        with self.tx() as c:
            row = self.q1("SELECT id FROM depth_queue WHERE dedupe_key = ?", (key,))
            if row:
                return int(row["id"]), False
            cur = c.execute(
                "INSERT INTO depth_queue(kind, title, detail_json, source, test_plan, state, dedupe_key, created_at, updated_at) VALUES (?,?,?,?,?, 'open', ?, ?, ?)",
                (int(kind), title, _j(detail or {}), source, test_plan, key, self.now(), self.now()),
            )
            did = int(cur.lastrowid)
            self.event("depth.add", "depth", did, None, "open", {"kind": kind, "title": title})
            return did, True

    def depth_item(self, item_id: int) -> dict:
        row = self.q1("SELECT * FROM depth_queue WHERE id = ?", (int(item_id),))
        if row is None:
            raise LedgerError(f"depth item {item_id} does not exist")
        d = dict(row)
        d["detail"] = _u(d.pop("detail_json"), {}) or {}
        return d

    def claim_depth(self, item_id: int, agent: str) -> dict:
        with self.tx() as c:
            d = self.depth_item(item_id)
            if d["state"] != "open":
                raise LedgerError(f"depth item {item_id} is {d['state']}")
            c.execute("UPDATE depth_queue SET state = 'in_progress', claimed_by = ?, claimed_at = ?, updated_at = ? WHERE id = ?",
                      (agent, self.now(), self.now(), item_id))
            self.event("depth.claim", "depth", item_id, "open", "in_progress", {"agent": agent})
            return self.depth_item(item_id)

    def complete_depth_item(self, item_id: int, state: str, result: str) -> dict:
        if state not in ("done", "blocked"):
            raise LedgerError("state must be done or blocked")
        if not result or not result.strip():
            raise LedgerError("result is required: what was done and what it showed (cells opened, captures)")
        hedge.check(result, "result")
        with self.tx() as c:
            d = self.depth_item(item_id)
            if d["state"] in ("done", "blocked"):
                raise LedgerError(f"depth item {item_id} is already {d['state']}")
            c.execute("UPDATE depth_queue SET state = ?, result = ?, claimed_by = NULL, claimed_at = NULL, updated_at = ? WHERE id = ?",
                      (state, result.strip(), self.now(), item_id))
            self.event("depth.complete", "depth", item_id, d["state"], state, {"result": result[:300]})
            return self.depth_item(item_id)

    # -- canaries / sightings / oob -----------------------------------------------------------------------

    def add_canary(self, token: str, *, kind: str, input_id: int | None, endpoint_id: int | None,
                   request_id: int | None = None, principal_id: int | None = None) -> None:
        self.conn.execute(
            "INSERT OR IGNORE INTO canaries(token, input_id, endpoint_id, request_id, principal_id, kind, ts) VALUES (?,?,?,?,?,?,?)",
            (token, input_id, endpoint_id, request_id, principal_id, kind, self.now()),
        )

    def canaries(self) -> list[dict]:
        return [dict(r) for r in self.q("SELECT * FROM canaries")]

    def add_sighting(self, token: str, *, request_id: int | None, endpoint_id: int | None, principal_id: int | None,
                     context: str | None) -> bool:
        with self.tx() as c:
            cur = c.execute(
                "INSERT OR IGNORE INTO sightings(token, request_id, endpoint_id, principal_id, context, ts) VALUES (?,?,?,?,?,?)",
                (token, request_id, endpoint_id, principal_id, context, self.now()),
            )
            if cur.rowcount:
                self.event("canary.sighting", "canary", None, detail={"token": token, "endpoint": endpoint_id, "principal": principal_id})
            return bool(cur.rowcount)

    def add_oob(self, token: str, cell_id: int | None, url: str) -> None:
        with self.tx():
            self.conn.execute("INSERT OR IGNORE INTO oob(token, cell_id, url, created_at) VALUES (?,?,?,?)", (token, cell_id, url, self.now()))
            self.event("oob.issue", "cell", cell_id, detail={"token": token})

    def add_oob_hit(self, token: str, *, protocol: str, method: str | None, remote: str | None, raw: str | None, ts: float | None = None) -> None:
        with self.tx():
            self.conn.execute("INSERT INTO oob_hits(token, ts, protocol, method, remote, raw) VALUES (?,?,?,?,?,?)",
                              (token, ts or self.now(), protocol, method, remote, (raw or "")[:4000]))
            self.event("oob.hit", "oob", None, detail={"token": token, "protocol": protocol})

    # -- summaries -------------------------------------------------------------------------------------

    def counts(self) -> dict:
        by_state = {s: 0 for s in CELL_STATES}
        for r in self.q("SELECT state, COUNT(*) AS n FROM cells GROUP BY state"):
            by_state[r["state"]] = r["n"]
        findings = {s: 0 for s in ("draft", "verified", "gated", "killed")}
        for r in self.q("SELECT status, COUNT(*) AS n FROM findings GROUP BY status"):
            findings[r["status"]] = r["n"]
        depth = {s: 0 for s in ("open", "in_progress", "done", "blocked")}
        for r in self.q("SELECT state, COUNT(*) AS n FROM depth_queue GROUP BY state"):
            depth[r["state"]] = r["n"]
        return {
            "cells": by_state,
            "cells_total": sum(by_state.values()),
            "findings": findings,
            "depth": depth,
            "endpoints": int(self.q1("SELECT COUNT(*) AS n FROM endpoints")["n"]),
            "inputs": int(self.q1("SELECT COUNT(*) AS n FROM inputs")["n"]),
            "requests": int(self.q1("SELECT COUNT(*) AS n FROM requests")["n"]),
            "cases": int(self.q1("SELECT COUNT(*) AS n FROM test_cases")["n"]),
        }


def _counter_read_families(name: str):
    spec = {"idor_write": "*", "mass_assignment": "*", "race": "*", "csrf": "*", "unauth_replay": ("write",)}
    return spec.get(name)
