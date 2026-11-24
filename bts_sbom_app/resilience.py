"""Circuit breaker + honest "no answer" outcomes for outbound calls (course package A).

Why: ``net.http_json``/``http_text`` retried every call the same way whether the remote host was merely
slow or completely dead, and folded "the server said no such resource" (404) and "we could not reach the
server at all" into the same ``None`` - a caller (license resolution over hundreds of components, OSV
batch queries) could not tell "nothing to report" from "we do not know". This module adds the two missing
pieces on top of ``net.py`` without changing any existing return value:

  * :class:`CircuitBreaker` - a per-host (``urlsplit().netloc``) three-state breaker (closed/open/half_open)
    so a dead host stops being hammered after a handful of failures instead of being retried for every one
    of the thousands of components in a large SBOM.
  * :class:`Outcome` - the fourth state the lecture material calls "the shape of no answer": success,
    empty_result (host answered, nothing there - e.g. HTTP 404), partial_result (host answered, the body
    was truncated at a byte limit), access_failure (never got a trustworthy answer).

Thread safety: every state transition happens under the breaker's own ``threading.Lock``, so concurrent
callers (the license/OSV resolvers use a thread pool) always see a consistent state and at most one of them
becomes the half-open probe.
"""
from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple
from urllib.parse import urlsplit

CLOSED = "closed"
OPEN = "open"
HALF_OPEN = "half_open"

DEFAULT_FAILURE_THRESHOLD = 3
DEFAULT_OPEN_SECONDS = 60.0

#: Outcome.state values ("the shape of no answer", lecture 3-2)
SUCCESS = "success"
EMPTY_RESULT = "empty_result"
PARTIAL_RESULT = "partial_result"
ACCESS_FAILURE = "access_failure"


@dataclass
class Outcome:
    """What a fetch actually learned, as opposed to a bare ``None``.

    ``state`` is one of success/empty_result/partial_result/access_failure. ``data`` carries the payload for
    success and partial_result (empty_result and access_failure always carry ``data=None``). ``status`` is the
    HTTP status code when one was obtained (``None`` for a transport-level failure such as a timeout).
    ``reason`` is a short machine-readable tag (e.g. ``"circuit_open"``, ``"not_found"``, ``"http_500"``,
    ``"truncated_at_limit"``, ``"retries_exhausted"``). ``attempts`` is how many requests were actually sent
    (0 when the circuit breaker short-circuited the call before any network attempt).
    """

    state: str
    data: Any = None
    status: Optional[int] = None
    reason: str = ""
    attempts: int = 0


def _env_threshold() -> int:
    raw = os.environ.get("BTS_SBOM_BREAKER_THRESHOLD")
    if raw is None:
        return DEFAULT_FAILURE_THRESHOLD
    try:
        return int(raw)
    except ValueError:
        return DEFAULT_FAILURE_THRESHOLD


class CircuitBreaker:
    """closed -> (``failure_threshold`` consecutive failures) -> open (no calls allowed for ``open_seconds``)
    -> half_open (exactly one probe let through) -> success closes it, failure reopens with a fresh cooldown.

    ``failure_threshold <= 0`` disables the breaker entirely: :meth:`allow` always returns True and
    :meth:`on_success`/:meth:`on_failure` are no-ops, so callers do not need a separate code path.
    """

    def __init__(self, *, failure_threshold: int = DEFAULT_FAILURE_THRESHOLD, open_seconds: float = DEFAULT_OPEN_SECONDS,
                 clock: Callable[[], float] = time.monotonic) -> None:
        self.failure_threshold = failure_threshold
        self.open_seconds = open_seconds
        self._clock = clock
        self._lock = threading.Lock()
        self._state = CLOSED
        self._consecutive_failures = 0
        self._opened_at: Optional[float] = None
        self._probe_in_flight = False
        self._gen = 0                              # bumped whenever the breaker opens or goes half-open
        self._stats = {"allowed": 0, "short_circuited": 0, "successes": 0, "failures": 0, "opens": 0}

    @property
    def enabled(self) -> bool:
        return self.failure_threshold > 0

    def allow(self) -> bool:
        """True if a call may proceed now (see :meth:`begin`, which also returns the generation to report back with)."""
        return self.begin()[0]

    def begin(self) -> Tuple[bool, int]:
        """(allowed, generation). In OPEN state this performs the OPEN -> HALF_OPEN transition and atomically claims the
        (single) probe slot for the caller that observes the cooldown has elapsed. Pass the generation to
        :meth:`on_success` / :meth:`on_failure`: a report from a call that began in an OLDER generation (it was already in
        flight when the breaker opened) is counted but never changes the state, so a straggler cannot reopen the breaker
        under the real probe or hide the probe's success."""
        if not self.enabled:
            return True, 0
        with self._lock:
            if self._state == CLOSED:
                self._stats["allowed"] += 1
                return True, self._gen
            if self._state == OPEN:
                assert self._opened_at is not None
                if (self._clock() - self._opened_at) >= self.open_seconds:
                    self._state = HALF_OPEN
                    self._gen += 1
                    self._probe_in_flight = True
                    self._stats["allowed"] += 1
                    return True, self._gen
                self._stats["short_circuited"] += 1
                return False, self._gen
            # HALF_OPEN: exactly one probe at a time; every other concurrent caller is turned away.
            if self._probe_in_flight:
                self._stats["short_circuited"] += 1
                return False, self._gen
            self._probe_in_flight = True
            self._stats["allowed"] += 1
            return True, self._gen

    def on_success(self, gen: Optional[int] = None) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._stats["successes"] += 1
            if gen is not None and gen != self._gen:
                return                              # straggler from an older generation: counted, state untouched
            if self._state == OPEN:
                # a CLOSED-state call that was already in flight when a sibling call's failure opened the
                # breaker; its late success must not override the (majority) decision to open - the breaker
                # stays open until its own cooldown elapses and a real probe is sent.
                return
            self._state = CLOSED
            self._consecutive_failures = 0
            self._opened_at = None
            self._probe_in_flight = False

    def on_failure(self, gen: Optional[int] = None) -> None:
        if not self.enabled:
            return
        with self._lock:
            self._stats["failures"] += 1
            if gen is not None and gen != self._gen:
                return                              # straggler from an older generation: counted, state untouched
            if self._state == OPEN:
                return                              # already open; a straggling call's failure changes nothing
            if self._state == HALF_OPEN:
                self._open_locked()
                return
            self._consecutive_failures += 1
            if self._consecutive_failures >= self.failure_threshold:
                self._open_locked()

    def _open_locked(self) -> None:
        self._gen += 1
        self._state = OPEN
        self._opened_at = self._clock()
        self._probe_in_flight = False
        self._stats["opens"] += 1

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return {"state": self._state, "consecutive_failures": self._consecutive_failures,
                    "opened_at": self._opened_at, "enabled": self.enabled, **self._stats}


_REGISTRY: Dict[str, CircuitBreaker] = {}
_REGISTRY_LOCK = threading.Lock()
#: Overridable by tests: a fake clock shared by every breaker created after it is set (reset via reset_breakers()).
CLOCK: Callable[[], float] = time.monotonic


def host_of(url: str) -> str:
    return urlsplit(url).netloc or url


def get_breaker(host: str) -> CircuitBreaker:
    """The breaker for this host, creating it on first use. The failure threshold is read from
    ``BTS_SBOM_BREAKER_THRESHOLD`` at creation time, so tests that change the env var must also call
    :func:`reset_breakers` for the change to take effect on the next lookup."""
    with _REGISTRY_LOCK:
        b = _REGISTRY.get(host)
        if b is None:
            b = _REGISTRY[host] = CircuitBreaker(failure_threshold=_env_threshold(), clock=CLOCK)
        return b


def reset_breakers() -> None:
    """Drop every registered breaker (fresh closed state, re-reads the env threshold on next use)."""
    with _REGISTRY_LOCK:
        _REGISTRY.clear()


def snapshot() -> Dict[str, Dict[str, Any]]:
    """Per-host breaker state, for the evidence file: {host: CircuitBreaker.snapshot()}."""
    with _REGISTRY_LOCK:
        hosts = list(_REGISTRY.items())
    return {host: b.snapshot() for host, b in hosts}


__all__ = ["Outcome", "CircuitBreaker", "get_breaker", "reset_breakers", "snapshot", "host_of",
           "SUCCESS", "EMPTY_RESULT", "PARTIAL_RESULT", "ACCESS_FAILURE", "CLOSED", "OPEN", "HALF_OPEN"]
