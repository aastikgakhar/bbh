"""Evaluate case conditions against exchanges. Stdlib only.

Returns (result, detail): result True/False, or None when a condition cannot be
machine-checked (manual) or its inputs are missing. `detail` is a short factual
string used in observations; it never contains hedge words.
"""

from __future__ import annotations

import re
import statistics
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlsplit

from .httpraw import Exchange


@dataclass
class EvalContext:
    this_case: int | str
    exchanges: dict = field(default_factory=dict)  # case_no (runner) OR step id (verify) -> repeats
    counter: Exchange | None = None
    browser: dict | None = None  # {"console": [...], "dialogs": [...], "title": str, "text": str}
    oob_hits: list[dict] = field(default_factory=list)
    third_party: bool = False
    base: Exchange | None = None

    def this(self) -> list[Exchange]:
        return self.exchanges.get(self.this_case, [])

    def case(self, ref) -> list[Exchange]:
        # Runner keys exchanges by integer case_no; verify keys them by string step id (and by
        # integer position). Resolve an exact key first (so a string step id like "false" or a
        # numeric step id never collides with a position), then fall back to an int case_no.
        if ref in (None, "this"):
            return self.this()
        if ref in self.exchanges:
            return self.exchanges[ref]
        try:
            return self.exchanges.get(int(ref), [])
        except (TypeError, ValueError):
            return self.exchanges.get(ref, [])


def _hdr(ex: Exchange, name: str) -> list[str]:
    return ex.response.headers_all(name) if ex.response else []


def location_host(location: str, request_url: str) -> str | None:
    """Host a browser would navigate to for this Location value (WHATWG-ish:
    tabs/newlines removed, backslashes treated as slashes for http(s))."""
    if location is None:
        return None
    loc = re.sub(r"[\t\n\r]", "", location.strip(" \x00\x01\x02\x03\x04\x05\x06\x07\x08\x0b\x0c\x0e\x0f\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f"))
    loc = loc.replace("\\", "/")
    # WHATWG: for http(s) any run of slashes before the host is ignored
    loc = re.sub(r"^(https?):/*", lambda m: m.group(1) + "://", loc, flags=re.I)
    loc = re.sub(r"^/{2,}", "//", loc)
    absolute = urljoin(request_url, loc)
    try:
        return (urlsplit(absolute).hostname or "").lower() or None
    except ValueError:
        return None


def _median_elapsed(exs: list[Exchange]) -> float | None:
    vals = [e.elapsed_ms for e in exs if e.response is not None]
    return statistics.median(vals) if vals else None


def _per_repeat(exs: list[Exchange], fn) -> tuple[bool | None, str]:
    if not exs:
        return None, "no exchange recorded for this case"
    results = []
    details = []
    for e in exs:
        r, d = fn(e)
        results.append(r)
        details.append(d)
    if any(r is None for r in results):
        return None, details[results.index(None)]
    ok = all(results)
    if len(exs) == 1:
        return ok, details[0]
    return ok, f"{sum(bool(r) for r in results)}/{len(exs)} repeats: " + "; ".join(details[:3])


def evaluate(cond: dict, ctx: EvalContext) -> tuple[bool | None, str]:
    t = cond.get("type")
    if t == "all":
        parts = [evaluate(c, ctx) for c in cond.get("of") or []]
        if any(r is False for r, _ in parts):
            return False, " AND ".join(d for _, d in parts)
        if any(r is None for r, _ in parts):
            return None, " AND ".join(d for _, d in parts)
        return True, " AND ".join(d for _, d in parts)
    if t == "any":
        parts = [evaluate(c, ctx) for c in cond.get("of") or []]
        if any(r is True for r, _ in parts):
            return True, " OR ".join(d for _, d in parts)
        if any(r is None for r, _ in parts):
            return None, " OR ".join(d for _, d in parts)
        return False, " OR ".join(d for _, d in parts)
    if t == "not":
        r, d = evaluate(cond.get("of") or {}, ctx)
        return (None if r is None else not r), f"NOT({d})"
    if t == "manual":
        return None, f"manual judgement required: {cond.get('describe', '')}"

    if t == "body_contains":
        v = cond["value"]
        return _per_repeat(ctx.this(), lambda e: (v in e.body_text, f"body {'contains' if v in e.body_text else 'lacks'} {v[:60]!r}"))
    if t == "body_not_contains":
        v = cond["value"]
        return _per_repeat(ctx.this(), lambda e: (v not in e.body_text, f"body {'lacks' if v not in e.body_text else 'contains'} {v[:60]!r}"))
    if t == "body_regex":
        rx = re.compile(cond["pattern"], re.S)
        return _per_repeat(ctx.this(), lambda e: (bool(rx.search(e.body_text)), f"body {'matches' if rx.search(e.body_text) else 'does not match'} /{cond['pattern'][:50]}/"))
    if t == "header_contains":
        name, v = cond["name"], cond["value"]
        return _per_repeat(ctx.this(), lambda e: (any(v.lower() in h.lower() for h in _hdr(e, name)),
                                                  f"{name}: {(_hdr(e, name) or ['<absent>'])[0][:80]!r}"))
    if t == "header_present":
        name = cond["name"]
        return _per_repeat(ctx.this(), lambda e: (bool(_hdr(e, name)), f"header {name} {'present' if _hdr(e, name) else 'absent'}"))
    if t == "header_regex":
        name, rx = cond["name"], re.compile(cond["pattern"], re.I)
        return _per_repeat(ctx.this(), lambda e: (any(rx.search(h) for h in _hdr(e, name)),
                                                  f"{name}: {(_hdr(e, name) or ['<absent>'])[0][:80]!r}"))
    if t == "status_in":
        vals = [int(x) for x in cond["values"]]
        return _per_repeat(ctx.this(), lambda e: (e.status in vals, f"status {e.status}"))
    if t == "location_host":
        want = cond["host"].lower()

        def f(e):
            loc = (_hdr(e, "Location") or [None])[0]
            host = location_host(loc, e.request.url) if loc else None
            return host == want, f"status {e.status}, Location {loc!r} -> host {host!r}"
        return _per_repeat(ctx.this(), f)
    if t == "matches_base":
        ratio = float(cond.get("max_len_ratio", 0.25))
        base = ctx.base
        # Burp truncates history responses to ~5 KB, so a base ingested from Burp is a PREFIX of
        # the real page. The control's own send is the full page, so a strict length match would
        # always fail for pages over ~5 KB. When the base is truncated, require only that the
        # status matches and the full response is at least as long as the truncated prefix.
        base_truncated = bool(base and (base.meta or {}).get("truncated"))

        def f(e):
            if e.response is None:
                return False, f"no response ({e.error})"
            if base is None or base.response is None:
                return e.status < 400 and e.length > 0, f"status {e.status} (no captured base; 2xx/3xx with a body required)"
            same_status = e.status == base.status
            bl, el = base.length, e.length
            if base_truncated:
                ok = same_status and el >= bl - 32
                return ok, f"status {e.status} vs base {base.status}, {el} bytes vs truncated base prefix {bl}"
            close = abs(el - bl) <= max(64, ratio * max(bl, 1))
            return same_status and close, f"status {e.status} vs base {base.status}, {el} vs {bl} bytes"
        return _per_repeat(ctx.this(), f)
    if t == "len_diff":
        a, b, n = cond.get("a", "this"), cond["b"], int(cond["min_bytes"])
        bex = ctx.case(b)
        if not bex:
            return None, f"case {b} has no exchange"
        bl = bex[0].length

        def f(e):
            d = abs(e.length - bl)
            return d >= n, f"{e.length} vs {bl} bytes (case {b}), diff {d}"
        return _per_repeat(ctx.case(a), f)
    if t == "min_len":
        # Body of the referenced case (default "this") is at least `min` bytes. Used to gate an
        # unauth-read positive on the authenticated control actually carrying data: "same as the
        # control" proves nothing when the control body is empty (an anonymous beacon or a 204-like
        # 200). Returns None (not a verdict) when the case has no exchange.
        ref, lo = cond.get("case", "this"), int(cond["min"])
        return _per_repeat(ctx.case(ref), lambda e: (e.length >= lo, f"body {e.length} bytes (need >= {lo})"))
    if t == "same_as_case":
        a, k, m = cond.get("a", "this"), cond["case"], int(cond.get("max_len_diff", 0))
        kex = ctx.case(k)
        if not kex:
            return None, f"case {k} has no exchange"
        ref = kex[0]

        def f(e):
            d = abs(e.length - ref.length)
            return (e.status == ref.status and d <= m), f"status {e.status} vs {ref.status}, len diff {d} vs case {k}"
        return _per_repeat(ctx.case(a), f)
    if t == "elapsed_over_baseline":
        # runner cases use "baseline_case" (an int case_no); finding assertions use "baseline"
        # (a step id). Honour either, so the verifier does not silently fall back to case 0.
        base_case = cond.get("baseline_case", cond.get("baseline", 0))
        med = _median_elapsed(ctx.case(base_case))
        if med is None:
            return None, f"baseline case {base_case} has no timing"
        n = int(cond["min_ms"])
        return _per_repeat(ctx.this(), lambda e: (e.response is not None and e.elapsed_ms - med >= n,
                                                  f"{e.elapsed_ms} ms vs baseline median {med:.0f} ms (need +{n})"))
    if t == "elapsed_ratio":
        a, b = cond.get("a", "this"), cond["b"]
        med_b = _median_elapsed(ctx.case(b))
        if med_b is None or med_b <= 0:
            return None, f"case {b} has no usable baseline timing"
        ratio = float(cond["min_ratio"])

        def f(e):
            if e.response is None:
                return None, f"no response ({e.error})"
            r = e.elapsed_ms / med_b
            return r >= ratio, f"{e.elapsed_ms} ms / {med_b:.0f} ms = {r:.2f}x (need >= {ratio}x)"
        return _per_repeat(ctx.case(a), f)
    if t == "elapsed_over_case":
        med = _median_elapsed(ctx.case(cond["case"]))
        if med is None:
            return None, f"case {cond['case']} has no timing"
        n = int(cond["min_ms"])
        return _per_repeat(ctx.this(), lambda e: (e.response is not None and e.elapsed_ms - med >= n,
                                                  f"{e.elapsed_ms} ms vs case {cond['case']} median {med:.0f} ms (need +{n})"))
    if t in ("counter_read_contains", "counter_read_not_contains"):
        if ctx.counter is None:
            return None, "no counter-read exchange"
        v = cond["value"]
        has = v in ctx.counter.body_text
        ok = has if t == "counter_read_contains" else not has
        return ok, f"counter-read status {ctx.counter.status} {'contains' if has else 'lacks'} {v[:60]!r}"
    if t == "browser_marker":
        if ctx.browser is None:
            return None, "no browser result"
        tok = cond["token"]
        where = [k for k in ("console", "dialogs") if any(tok in str(x) for x in ctx.browser.get(k) or [])]
        if tok in (ctx.browser.get("title") or ""):
            where.append("title")
        return bool(where), (f"marker seen in {', '.join(where)}" if where else "marker not seen in console, dialogs or title")
    if t == "browser_text_contains":
        if ctx.browser is None:
            return None, "no browser result"
        v = cond["value"]
        has = v in (ctx.browser.get("text") or "")
        return has, f"rendered text {'contains' if has else 'lacks'} {v[:60]!r}"
    if t == "oob_hit":
        n = len(ctx.oob_hits)
        return n > 0, f"{n} OOB interaction(s)"
    if t == "third_party_seen":
        return ctx.third_party, ("records outside the test accounts were returned" if ctx.third_party else "no records outside the test accounts")
    # An unknown condition type almost always means the running server is executing STALE code: a
    # plan was stored by fresh code (a detached worker or a hand edit) that uses a condition this
    # evaluator does not know. Make it unmistakable (the runner turns this sentinel into a loud
    # staleness warning) rather than letting it hide as a quiet inconclusive. Never a negative.
    return None, f"UNKNOWN_CONDITION {t!r}: the evaluator does not know this condition type; the server is likely running stale code (call reload() or restart it)"


def summarise(ex: Exchange) -> str:
    if ex.response is None:
        return f"no response ({ex.error or 'transport error'})"
    ct = ex.response.content_type or "-"
    return f"status {ex.status}, {ex.length} bytes, {ct}, {ex.elapsed_ms} ms"


# --- variable-response guard --------------------------------------------------------------------
# Some endpoints return a different body per request by design (an SDK flag resolver, a feed, a
# nonce-bearing page). For those, a positive that only means "this response differs from the
# control" is not attributable to the payload, so it must not raise a candidate. These helpers let
# the runner downgrade exactly those positives to inconclusive, while leaving a definitive signal
# (a specific content marker, timing, OOB, a counter-read, third-party data) untouched.

_BASELINE_CMP_TYPES = {"same_as_case", "len_diff", "matches_base"}
_STRONG_SIGNAL_TYPES = {"oob_hit", "counter_read_contains", "counter_read_not_contains",
                        "elapsed_over_baseline", "elapsed_over_case", "elapsed_ratio",
                        "browser_marker", "browser_text_contains", "third_party_seen",
                        "body_contains", "body_regex"}


def _condition_types(cond) -> set:
    if not isinstance(cond, dict):
        return set()
    t = cond.get("type")
    out = {t} if t else set()
    if t in ("all", "any"):
        for sub in cond.get("of") or []:
            out |= _condition_types(sub)
    elif t == "not":
        out |= _condition_types(cond.get("of"))
    return out


def positive_is_pure_baseline_cmp(cond: dict) -> bool:
    """True if the positive is only a 'differs from / matches the control' comparison (length or
    status), with no content marker, timing, OOB, counter-read or third-party signal. Those are the
    positives a variable-response endpoint can trip on its own."""
    types = _condition_types(cond)
    return bool(types & _BASELINE_CMP_TYPES) and not (types & _STRONG_SIGNAL_TYPES)


def baseline_unstable(ctx: EvalContext, case: int | str = 0, *, min_rel: float = 0.25, min_abs: int = 64) -> bool:
    """True if the reference case's own repeats differ materially (a different status, or a length
    spread beyond the comparison tolerance): the endpoint varies by design, so a baseline
    differential is unreliable. Needs >= 2 repeats to judge; otherwise returns False (cannot tell)."""
    exs = [e for e in ctx.case(case) if e.response is not None]
    if len(exs) < 2:
        return False
    if len({e.status for e in exs}) > 1:
        return True
    lens = [e.length for e in exs]
    return (max(lens) - min(lens)) > max(min_abs, int(min_rel * max(max(lens), 1)))
