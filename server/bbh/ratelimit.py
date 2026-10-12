"""Per-host rate limiting shared by every process that uses the ledger. Stdlib only.

Reservation model: each send reserves the next free slot for its host inside one
BEGIN IMMEDIATE transaction (`start = max(now, next_allowed)`,
`next_allowed = start + interval * penalty * slots`) and then sleeps until `start`.
Any number of threads or processes therefore never exceed `rate` requests per
second on average, and a race burst of N reserves N slots at once, so the quiet
period after a burst repays it (the one place a parallel burst is allowed; capped
at MAX_BURST). Throttle signals double the penalty (cap 32x); sustained success
halves it again.
"""

from __future__ import annotations

import time

MAX_BURST = 30
MAX_PENALTY = 32.0
DECAY_AFTER = 10


class RateLimiter:
    def __init__(self, ledger, rate_per_s: float, *, clock=time.time, sleep=time.sleep):
        if rate_per_s <= 0:
            raise ValueError("rate must be > 0")
        self.ledger = ledger
        self.rate = float(rate_per_s)
        self.clock = clock
        self.sleep = sleep

    @property
    def interval(self) -> float:
        return 1.0 / self.rate

    def reserve(self, host: str, slots: int = 1) -> float:
        """Reserve `slots` consecutive sends for `host`; return the start time."""
        if slots < 1:
            raise ValueError("slots must be >= 1")
        if slots > MAX_BURST:
            raise ValueError(f"a burst is capped at {MAX_BURST} requests")
        host = host.lower()
        with self.ledger.tx() as c:
            row = c.execute("SELECT next_allowed, penalty FROM rate_state WHERE host = ?", (host,)).fetchone()
            next_allowed, penalty = (row["next_allowed"], row["penalty"]) if row else (0.0, 1.0)
            now = self.clock()
            start = max(now, next_allowed)
            new_next = start + self.interval * penalty * slots
            c.execute(
                "INSERT INTO rate_state(host, next_allowed, penalty, ok_streak) VALUES (?, ?, ?, 0) "
                "ON CONFLICT(host) DO UPDATE SET next_allowed = excluded.next_allowed",
                (host, new_next, penalty),
            )
        return start

    def wait(self, host: str, slots: int = 1) -> float:
        start = self.reserve(host, slots)
        delay = start - self.clock()
        if delay > 0:
            self.sleep(delay)
        return start

    def throttled(self, host: str, retry_after_s: float | None = None) -> float:
        """Record a throttle signal (429, block page, reset). Returns the new penalty."""
        host = host.lower()
        with self.ledger.tx() as c:
            row = c.execute("SELECT next_allowed, penalty FROM rate_state WHERE host = ?", (host,)).fetchone()
            penalty = min(MAX_PENALTY, (row["penalty"] if row else 1.0) * 2)
            now = self.clock()
            hold = max(retry_after_s or 0.0, self.interval * penalty)
            nxt = max((row["next_allowed"] if row else 0.0), now + hold)
            c.execute(
                "INSERT INTO rate_state(host, next_allowed, penalty, ok_streak) VALUES (?, ?, ?, 0) "
                "ON CONFLICT(host) DO UPDATE SET next_allowed = excluded.next_allowed, penalty = excluded.penalty, ok_streak = 0",
                (host, nxt, penalty),
            )
            return penalty

    def ok(self, host: str) -> None:
        host = host.lower()
        with self.ledger.tx() as c:
            row = c.execute("SELECT penalty, ok_streak FROM rate_state WHERE host = ?", (host,)).fetchone()
            if not row:
                return
            streak = row["ok_streak"] + 1
            penalty = row["penalty"]
            if penalty > 1 and streak >= DECAY_AFTER:
                penalty, streak = max(1.0, penalty / 2), 0
            c.execute("UPDATE rate_state SET penalty = ?, ok_streak = ? WHERE host = ?", (penalty, streak, host))

    def penalty(self, host: str) -> float:
        row = self.ledger.q1("SELECT penalty FROM rate_state WHERE host = ?", (host.lower(),))
        return float(row["penalty"]) if row else 1.0
