"""Scan-progress events over SSE (schema bts-sbom.events.v1) - stdlib only.

Lecture 4-3: progress is a stream of typed events, not a polling loop. Six types only (this product's scan is
not token streaming, so token/handoff/tool_call/tool_result from the lecture are dropped): job_start, step_start,
step_end, patch_gate, final, error. Every event carries a monotonically increasing ``seq``, a ``type`` and the
``schema`` name. The bus validates before publishing (a malformed event is refused, never broadcast), keeps a
bounded history for reconnects (Last-Event-ID), and never carries secrets - the patch approval travels as a
digest, the token itself never enters an event.
"""
from __future__ import annotations

import json
import threading
from typing import Any, Dict, List, Optional

SCHEMA = "bts-sbom.events.v1"
TYPES: Dict[str, List[str]] = {
    "job_start": ["job", "source"],
    "step_start": ["step"],
    "step_end": ["step", "ok", "seconds"],
    "patch_gate": ["state"],
    "final": ["state"],
    "error": ["error_type", "severity", "retryable", "recovery_hint"],
}
TERMINAL = ("final", "error")
MAX_SUBSCRIBERS = 4


def validate(event: Dict[str, Any]) -> List[str]:
    """Problems with one event (empty list = publishable). Unknown types and missing required fields are problems."""
    if not isinstance(event, dict):
        return ["event is not an object"]
    problems: List[str] = []
    t = event.get("type")
    if t not in TYPES:
        problems.append("unknown type: %r" % (t,))
        return problems
    if event.get("schema") != SCHEMA:
        problems.append("schema must be %s" % SCHEMA)
    for f in TYPES[t]:
        if f not in event:
            problems.append("missing field: %s" % f)
    if not isinstance(event.get("seq"), int) or event["seq"] < 0:
        problems.append("seq must be a non-negative integer")
    return problems


def format_sse(event: Dict[str, Any]) -> bytes:
    """One SSE frame: id/event/data lines then a blank line. The JSON payload is one line - no raw newlines can hide in it."""
    data = json.dumps(event, ensure_ascii=False, sort_keys=True)
    return ("id: %d\nevent: %s\ndata: %s\n\n" % (event["seq"], event["type"], data)).encode("utf-8")


class EventBus:
    """One job's event bus: publish (validated), replay after reconnect, at most MAX_SUBSCRIBERS live streams."""

    def __init__(self, *, history_limit: int = 2000):
        self._lock = threading.Lock()
        self._seq = 0
        self._history: List[Dict[str, Any]] = []
        self._history_limit = history_limit
        self._cond = threading.Condition(self._lock)
        self._closed = False
        self._subscribers = 0

    def publish(self, event_type: str, **fields: Any) -> Optional[Dict[str, Any]]:
        """Validate and broadcast one event of ``event_type``. Returns the stored event, or None when refused."""
        with self._cond:
            if self._closed:
                return None
            ev = {"schema": SCHEMA, "seq": self._seq, "type": event_type, **fields}
            problems = validate(ev)
            if problems:
                ev["problems"] = problems
                return None
            self._seq += 1
            ev["seq"] = self._seq
            self._history.append(ev)
            del self._history[:-self._history_limit]
            self._cond.notify_all()
            return ev

    def iter_events(self, after_seq: int = 0, timeout: float = 15.0):
        """Yield events with seq > after_seq, waiting up to ``timeout`` between events. Stops on close or a terminal event."""
        while True:
            ev = self.next_event(after_seq, timeout=timeout)
            if ev is None:
                if self.closed:
                    return
                continue
            after_seq = ev["seq"]
            yield ev
            if ev["type"] in TERMINAL:
                return

    def next_event(self, after_seq: int = 0, timeout: float = 15.0) -> Optional[Dict[str, Any]]:
        """The next event with seq > after_seq, or None after ``timeout`` seconds of silence (the caller sends a keepalive)."""
        with self._cond:
            batch = [e for e in self._history if e["seq"] > after_seq]
            if not batch and not self._closed:
                self._cond.wait(timeout)
                batch = [e for e in self._history if e["seq"] > after_seq]
            if batch:
                return batch[0]
            return None

    def close(self) -> None:
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def admit_subscriber(self) -> bool:
        """True while a live stream slot is free; the 5th concurrent subscriber is refused (429 upstream)."""
        with self._lock:
            if self._subscribers >= MAX_SUBSCRIBERS:
                return False
            self._subscribers += 1
            return True

    def release_subscriber(self) -> None:
        with self._lock:
            self._subscribers = max(0, self._subscribers - 1)
