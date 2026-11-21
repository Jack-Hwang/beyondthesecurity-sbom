"""Single-writer lock for the evidence store (task 13) - stdlib only.

The evidence folder is shared state: two instances writing it at once (e.g. a staging slot swapping with
production) would race on .prev.json swaps and job records. ``acquire`` creates <evidence>/.instance.lock via
O_CREAT|O_EXCL (atomic on a local filesystem); a lock whose heartbeat is stale can be taken over, a fresh one
is held by somebody. The second instance either refuses to start (LockHeld) or - with BTS_SBOM_STANDBY_OK=1 -
serves read-only (standby) until the lock goes stale and it takes over. KNOWN LIMITATION (honest): the
atomicity of O_CREAT|O_EXCL and os.replace on a SHARED filesystem (SMB / Azure Files) was not verified in this
environment - the lock is a safety net on top of "run one instance" (ADR-0019); its shared-filesystem behaviour
is NOT RUN.
"""
from __future__ import annotations

import json
import os
import socket
import threading
import time
from typing import Any, Callable, Dict, Optional

from .util import read_json

LOCK_NAME = ".instance.lock"
DEFAULT_STALE_AFTER = 60.0


class LockHeld(Exception):
    """Another instance holds a fresh lock on the evidence folder."""


def _now(clock: Callable[[], float]) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(clock()))


def _lock_fresh(record: Dict[str, Any], stale_after: float, clock: Callable[[], float]) -> bool:
    """True while the holder's heartbeat is within ``stale_after`` seconds (an unreadable heartbeat counts as held)."""
    try:
        return clock() - float(record.get("heartbeat")) < stale_after
    except (TypeError, ValueError):
        return True


class HeldLock:
    """The evidence store is ours: heartbeat thread keeps the record fresh; release removes the file."""

    standby = False

    def __init__(self, path: str, *, host: str, pid: int, clock: Callable[[], float] = time.time,
                 stale_after: float = DEFAULT_STALE_AFTER, heartbeat_s: float = 15.0):
        self.path = path
        self.clock = clock
        self.stale_after = stale_after
        self.heartbeat_s = heartbeat_s
        self.lost = threading.Event()
        self._stop = threading.Event()
        self.pid = pid
        self.host = host
        self._record: Dict[str, Any] = {"host": host, "pid": pid, "started": _now(clock)}
        self._thread: Optional[threading.Thread] = None
        self._write()

    def _write(self) -> None:
        d = dict(self._record)
        d["heartbeat"] = self.clock()
        with open(self.path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(d, fh)

    def _beat(self) -> None:
        while not self._stop.wait(self.heartbeat_s):
            cur = read_json(self.path, None)
            if not isinstance(cur, dict) or cur.get("pid") != self.pid:
                self.lost.set()                       # the file vanished or was taken over
                return
            try:
                self._write()
            except OSError:
                self.lost.set()
                return

    def start_heartbeat(self) -> None:
        self._thread = threading.Thread(target=self._beat, daemon=True)
        self._thread.start()

    @property
    def active(self) -> bool:
        return not self.lost.is_set()

    def release(self) -> None:
        self._stop.set()
        cur = read_json(self.path, None)
        if isinstance(cur, dict) and cur.get("pid") == self.pid:
            try:
                os.remove(self.path)
            except OSError:
                pass


class Standby:
    """Another instance holds a fresh lock and we were allowed to wait (BTS_SBOM_STANDBY_OK=1):
    serve read-only; ``promote`` takes the lock once it goes stale."""

    standby = True

    def __init__(self, path: str, *, clock: Callable[[], float] = time.time, stale_after: float = DEFAULT_STALE_AFTER,
                 host: Optional[str] = None, pid: Optional[int] = None):
        self.path = path
        self.clock = clock
        self.stale_after = stale_after
        self.host = host or socket.gethostname()
        self.pid = pid if pid is not None else os.getpid()
        self.held: Optional[HeldLock] = None

    @property
    def active(self) -> bool:
        return self.held is not None and self.held.active

    def promote(self) -> bool:
        """Take over the store when the holder's heartbeat went stale. True when this instance is now the writer."""
        if self.held is not None:
            return self.held.active
        existing = read_json(self.path, None)
        if isinstance(existing, dict) and _lock_fresh(existing, self.stale_after, self.clock):
            return False
        if os.path.exists(self.path):
            # takeover: the stale holder never released; remove and re-create exclusively (only one waiter wins)
            try:
                os.remove(self.path)
            except OSError:
                return False
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
        except FileExistsError:
            return False
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(json.dumps({"host": self.host, "pid": self.pid, "started": _now(self.clock),
                                 "heartbeat": self.clock()}))
        self.held = HeldLock(self.path, host=self.host, pid=self.pid, clock=self.clock, stale_after=self.stale_after)
        return True

    def release(self) -> None:
        if self.held is not None:
            self.held.release()


def acquire(evidence_dir: str, *, clock: Callable[[], float] = time.time, host: Optional[str] = None,
            pid: Optional[int] = None, standby_ok: Optional[bool] = None,
            stale_after: float = DEFAULT_STALE_AFTER) -> Any:
    """Take the single-writer lock. Returns a HeldLock; raises LockHeld when a fresh lock exists and standby
    is not allowed (the default: refuse to start rather than risk two writers)."""
    os.makedirs(evidence_dir, exist_ok=True)
    path = os.path.join(evidence_dir, LOCK_NAME)
    if standby_ok is None:
        standby_ok = os.environ.get("BTS_SBOM_STANDBY_OK") in ("1", "true", "yes", "on")
    host = host or socket.gethostname()
    pid = pid if pid is not None else os.getpid()
    for _ in range(600):                                       # bounded re-check loop (~30 s) against a concurrent acquirer
        existing = read_json(path, None)
        if isinstance(existing, dict) and _lock_fresh(existing, stale_after, clock):
            if not standby_ok:
                raise LockHeld("evidence store is held by %s pid %s (started %s)" %
                               (existing.get("host"), existing.get("pid"), existing.get("started")))
            return Standby(path, clock=clock, stale_after=stale_after, host=host, pid=pid)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(json.dumps({"host": host, "pid": pid, "started": _now(clock), "heartbeat": clock()}))
            return HeldLock(path, host=host, pid=pid, clock=clock, stale_after=stale_after)
        except FileExistsError:
            time.sleep(0.05)
    raise LockHeld("could not acquire the evidence store lock within 30 s")
