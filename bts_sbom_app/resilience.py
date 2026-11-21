"""Host-level circuit breaker + the four honest outcomes of an outbound fetch (stdlib only).

Lecture 3: "the answer to an access failure is not 'not found' but 'could not check'" - so a fetch
returns one of exactly four states: success / empty_result (the server answered: no such record) /
partial_result (we hold a truncated but usable answer) / access_failure (could not check: retries
exhausted, or this host's circuit is open). A circuit breaker per host stops hammering a dead host:
Closed -> 3 consecutive failed calls -> Open for 60s -> exactly one Half-Open probe -> Closed or Open again.
"""
from __future__ import annotations

import os
import threading
import time
import urllib.parse
from dataclasses import dataclass
from typing import Callable, Dict, Optional

STATES = ("success", "empty_result", "partial_result", "access_failure")
DEFAULT_THRESHOLD = 3


@dataclass
class Outcome:
    """One fetch result, honest about HOW we know. ``data`` is the payload or None; ``reason`` is a short ASCII line."""
    state: str
    data: object
    status: Optional[int]
    reason: str
    attempts: int


class CircuitBreaker:
    """Closed -> (threshold consecutive failed calls) -> Open for ``open_seconds`` -> one half-open probe -> Closed / Open.

    Thread-safe; the clock is injectable so tests advance time without sleeping.
    """

    def __init__(self, failure_threshold: int = DEFAULT_THRESHOLD, open_seconds: float = 60.0,
                 clock: Callable[[], float] = time.monotonic):
        self._threshold = failure_threshold
        self._open_seconds = open_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._state = "closed"
        self._consecutive = 0
        self._opened_at = 0.0
        self._probe_in_flight = False

    def allow(self) -> bool:
        """May one more call go out? During open: no calls; after the cooldown exactly one probe (first concurrent caller wins)."""
        with self._lock:
            if self._state == "closed":
                return True
            if self._state == "open":
                if self._clock() - self._opened_at >= self._open_seconds:
                    self._state = "half_open"
                    self._probe_in_flight = True
                    return True
                return False
            if self._probe_in_flight:                       # half_open: exactly one probe at a time
                return False
            self._probe_in_flight = True
            return True

    def record_success(self) -> None:
        """Probe or normal call succeeded: back to closed with a clean consecutive counter."""
        with self._lock:
            self._state = "closed"
            self._consecutive = 0
            self._probe_in_flight = False

    def record_neutral(self) -> None:
        """The server answered but the record does not exist (404): neither a failure nor a success for the counter."""
        with self._lock:
            self._probe_in_flight = False
            if self._state == "half_open":
                self._state = "closed"          # the host is alive; the consecutive count stays untouched

    def record_failure(self) -> None:
        with self._lock:
            self._probe_in_flight = False
            if self._state == "half_open":
                self._state = "open"            # the probe failed: a fresh cooldown starts now
                self._opened_at = self._clock()
                return
            self._consecutive += 1
            if self._threshold and self._consecutive >= self._threshold:
                self._state = "open"
                self._opened_at = self._clock()

    def snapshot(self) -> Dict[str, object]:
        with self._lock:
            return {"state": self._state, "consecutive_failures": self._consecutive}


def threshold_from_env(env: Optional[Dict[str, str]] = None) -> int:
    """BTS_SBOM_BREAKER_THRESHOLD: 0 disables the breaker, a non-integer falls back to the default 3."""
    raw = (env or os.environ).get("BTS_SBOM_BREAKER_THRESHOLD", "")
    try:
        return int(raw)
    except (TypeError, ValueError):
        return DEFAULT_THRESHOLD


_BREAKERS: Dict[str, CircuitBreaker] = {}
_BREAKERS_LOCK = threading.Lock()


def breaker_for(url: str, *, clock: Callable[[], float] = time.monotonic) -> Optional[CircuitBreaker]:
    """The breaker of this URL's host (netloc), created on first use; None when disabled by env."""
    if threshold_from_env() <= 0:
        return None
    host = urllib.parse.urlsplit(url).netloc
    if not host:
        return None
    with _BREAKERS_LOCK:
        brk = _BREAKERS.get(host)
        if brk is None:
            brk = _BREAKERS[host] = CircuitBreaker(threshold_from_env(), clock=clock)
        return brk


def reset_breakers() -> None:
    """Drop every host breaker (tests call this between tests so one test's open circuit never blocks the next)."""
    with _BREAKERS_LOCK:
        _BREAKERS.clear()
