"""Rule 0 guard: detect and redact data that belongs to anyone outside the test
accounts. Stdlib only.

On a hit the capture written to disk keeps the status line and headers but the
body is replaced by a redaction summary holding only the record count and one
masked proving field, and the agent is told to stop and report the count.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,24}")
ROLE_LOCALS = {"support", "info", "noreply", "no-reply", "donotreply", "security", "privacy", "help", "contact", "admin",
               "sales", "abuse", "webmaster", "postmaster", "hello", "team", "legal", "press", "billing", "hostmaster",
               "careers", "jobs", "marketing", "notifications", "notification", "mailer-daemon", "dpo", "compliance"}
OWNER_KEYS = re.compile(r"^(owner_?id|user_?id|account_?id|author_?id|created_?by|uid|owner|user|customer_?id|member_?id)$", re.I)
EMAIL_KEYS = re.compile(r"(e-?mail|owner_email|user_email)$", re.I)
PAGING = {"page", "offset", "cursor", "after", "before", "start", "skip", "limit", "per_page", "perpage", "page_size",
          "pagesize", "since_id", "max_id", "from", "size", "first", "last", "next", "continuation", "token"}


@dataclass
class GuardResult:
    third_party: bool = False
    count: int = 0
    proving_field: str | None = None
    foreign_emails: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.third_party:
            return "no records outside the test accounts"
        return (f"{self.count} record(s) outside the test accounts were returned; proving field {self.proving_field}. "
                "Rule 0: the body was not saved; stop, do not page further, report the count.")


def _mask_email(e: str) -> str:
    local, _, domain = e.partition("@")
    return f"{local[:1]}***@{domain}"


def _is_foreign_email(e: str, known: set[str]) -> bool:
    e = e.lower()
    if e in known:
        return False
    local = e.split("@", 1)[0]
    if local in ROLE_LOCALS:
        return False
    return True


def scan(body_text: str, known_identifiers: set[str], *, known_ids: set[str] | None = None,
         header_text: str = "") -> GuardResult:
    """known_identifiers: lowercase emails/handles of the test principals.
    known_ids: object/user ids that belong to test principals (strings). When it is
    None, id-based detection is skipped (unknown ids are not evidence).
    header_text: response header lines; foreign e-mails there are detected too (C2)."""
    res = GuardResult()
    data = None
    stripped = body_text.lstrip()[:1]
    if stripped in ("{", "["):
        try:
            data = json.loads(body_text)
        except ValueError:
            data = None
    if data is not None:
        records = _records(data)
        foreign_records = 0
        for rec in records:
            hit = _foreign_in_record(rec, known_identifiers, known_ids)
            if hit:
                foreign_records += 1
                if res.proving_field is None:
                    res.proving_field = hit
        if foreign_records:
            res.third_party = True
            res.count = foreign_records
            return res
    emails = sorted({e for e in EMAIL_RE.findall(body_text + "\n" + (header_text or ""))
                     if _is_foreign_email(e, known_identifiers)})
    if emails:
        res.third_party = True
        res.count = len(emails)
        res.foreign_emails = [_mask_email(e) for e in emails[:3]]
        where = "header" if (header_text and emails[0] in header_text and emails[0] not in body_text) else "body"
        res.proving_field = f"email={_mask_email(emails[0])} ({where})"
    return res


def _records(data, depth: int = 0) -> list[dict]:
    """The row-list to inspect: the top-level list, or the first list-of-dicts found
    at any reasonable nesting depth (S2: a dump nested under a key is still a dump)."""
    if isinstance(data, list):
        return [r for r in data if isinstance(r, dict)]
    if isinstance(data, dict):
        for v in data.values():
            if isinstance(v, list) and v and all(isinstance(x, dict) for x in v):
                return v
        if depth < 4:
            for v in data.values():
                if isinstance(v, dict):
                    nested = _records(v, depth + 1)
                    if nested:
                        return nested
        return [data]
    return []


def _foreign_in_record(rec: dict, known: set[str], known_ids: set[str] | None) -> str | None:
    for k, v in rec.items():
        # an e-mail value owned by a test account is NOT third-party, whatever the key
        if isinstance(v, str) and EMAIL_RE.fullmatch(v.strip() or ""):
            if _is_foreign_email(v.strip(), known):
                return f"{k}={_mask_email(v.strip())}"
            continue  # own / role e-mail: not foreign
        # owner-style id fields: a value equal to a known test identifier (id OR handle) is own data.
        if OWNER_KEYS.match(k) and isinstance(v, (int, str)):
            sv = str(v)
            if sv.lower() in known:
                continue  # the test account's own handle/id
            if known_ids is not None and sv not in known_ids and not _is_email(sv):
                return f"{k}={sv[:2]}***"
    return None


def _is_email(s: str) -> bool:
    return bool(EMAIL_RE.fullmatch((s or "").strip()))


def scrub_headers_value(value: str, known: set[str]) -> str:
    """Mask any foreign e-mail in a response header value before it is written to disk (C2)."""
    def repl(m):
        e = m.group(0)
        return _mask_email(e) if _is_foreign_email(e, known) else e
    return EMAIL_RE.sub(repl, value or "")


def redaction_body(res: GuardResult) -> bytes:
    return json.dumps({
        "redacted_by_harness": True,
        "reason": "Rule 0: response held data outside the test accounts",
        "records_outside_test_accounts": res.count,
        "proving_field": res.proving_field,
    }, indent=1).encode()


def has_paging(params: dict) -> bool:
    return any(k.lower() in PAGING for k in params)
