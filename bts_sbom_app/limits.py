"""Resource limits for a public server (task 14): concurrent jobs, job deadline, work-copy size, drain - stdlib only.

A scan can eat CPU and disk for a long time (an unbounded clone once grew to 1.1 GB inside a repo - AC-68), so a
public deployment needs hard bounds: a bounded job gate (429 with Retry-After when full), a per-job deadline
checked at stage boundaries, a work-copy size cap checked right after clone, and a bounded SIGTERM drain that
records unfinished jobs as interrupted(sigterm) instead of leaving them "running" forever. Non-integer or
negative env values fall back to their defaults - never an exception.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable, Dict, Optional


class JobGate:
    """A counting semaphore with try_acquire/release; leaked permits would silently shrink capacity."""

    def __init__(self, max_concurrent: int):
        self.max = max(0, int(max_concurrent))
        self._slots = self.max
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)

    @property
    def enabled(self) -> bool:
        return self.max > 0

    def try_acquire(self) -> bool:
        if not self.enabled:
            return True
        with self._cond:
            if self._slots <= 0:
                return False
            self._slots -= 1
            return True

    def release(self) -> None:
        if not self.enabled:
            return
        with self._cond:
            self._slots = min(self.max, self._slots + 1)
            self._cond.notify_all()

    @property
    def held(self) -> int:
        with self._lock:
            return self.max - self._slots


def _int_env(env: Dict[str, str], key: str, default: int) -> int:
    """Non-integer or negative values fall back to the default (no exception, honest default)."""
    raw = str(env.get(key, "") or "").strip()
    try:
        n = int(raw)
    except ValueError:
        return default
    return n if n >= 0 else default


class Limits:
    """The effective resource limits for this process (cloud mode supplies the job-count default of 2)."""

    def __init__(self, env: Optional[Dict[str, str]] = None, *, cloud_default_jobs: int = 2):
        e = env if env is not None else os.environ
        self.max_jobs = _int_env(e, "BTS_SBOM_MAX_JOBS", cloud_default_jobs)
        self.job_timeout_s = _int_env(e, "BTS_SBOM_JOB_TIMEOUT_S", 900)
        self.max_workcopy_mb = _int_env(e, "BTS_SBOM_MAX_WORKCOPY_MB", 500)
        self.drain_s = _int_env(e, "BTS_SBOM_DRAIN_S", 20)

    def gate(self) -> JobGate:
        return JobGate(self.max_jobs)


def dir_size_bytes(path: str) -> int:
    total = 0
    for dp, _dns, fns in os.walk(path):
        for fn in fns:
            try:
                total += os.path.getsize(os.path.join(dp, fn))
            except OSError:
                pass
    return total


class Deadline:
    """A per-job deadline the pipeline checks at stage boundaries (clock injectable for tests)."""

    def __init__(self, started_at: float, timeout_s: int, clock: Callable[[], float] = time.time):
        self.deadline = started_at + timeout_s
        self.clock = clock
        self.exceeded = False

    def check(self) -> None:
        if self.clock() >= self.deadline:
            self.exceeded = True
            raise TimeoutError("job exceeded its deadline (BTS_SBOM_JOB_TIMEOUT_S)")
