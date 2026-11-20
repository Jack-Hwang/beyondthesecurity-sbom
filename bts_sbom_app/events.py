"""Scan-progress event schema (``bts-sbom.events.v1``) and the in-memory bus that serves ``GET /api/jobs/<id>/events``.

Six event types, each built with :func:`EventBus.publish` so every event the bus ever hands out already carries a
monotonically increasing ``seq`` and has passed :func:`validate`:

* ``job_start``  -- a scan job began (``source``).
* ``step_start``  / ``step_end`` -- one pipeline stage (``name``); ``step_end`` carries ``ok``, ``seconds`` and an
  optional ``error``.
* ``patch_gate`` -- the approval-gated patch loop's state for this job: ``awaiting_approval`` (a plan was produced but
  no approval token was supplied -- ``digest`` is the plan digest to approve), ``approved`` (the request already
  carried an approval token) or ``not_requested`` (no patch was asked for at all).
* ``final`` -- the job finished without an unhandled exception (``state``, normally ``"done"``).
* ``error`` -- the job could not finish (``error_type``, ``severity``, ``retryable``, ``recovery_hint``).

Exactly one of ``final``/``error`` ends a job's stream; once one of them is published the bus is closed (no more
events, :meth:`EventBus.iter_events` returns for good after handing it out).

Every event is a plain ``dict`` (JSON-safe): ``{"schema": SCHEMA, "type": ..., "seq": int, "ts": iso8601, "job": id,
...type-specific fields}``. Nothing here touches the network, a clock other than ``time.monotonic``/``util.now_iso``,
or any global state -- one ``EventBus`` instance per job, held by ``server.State``.
"""
from __future__ import annotations

import json
import threading
import time
from typing import Any, Dict, Iterator, List, Optional, Tuple

from .util import now_iso

SCHEMA = "bts-sbom.events.v1"

JOB_START = "job_start"
STEP_START = "step_start"
STEP_END = "step_end"
PATCH_GATE = "patch_gate"
FINAL = "final"
ERROR = "error"
EVENT_TYPES: Tuple[str, ...] = (JOB_START, STEP_START, STEP_END, PATCH_GATE, FINAL, ERROR)
_TERMINAL = (FINAL, ERROR)

PATCH_GATE_STATES: Tuple[str, ...] = ("awaiting_approval", "approved", "not_requested")
ERROR_SEVERITIES: Tuple[str, ...] = ("low", "medium", "high", "critical")

# field -> required for this event type (beyond the common envelope: schema, type, seq, ts, job)
_REQUIRED: Dict[str, Tuple[str, ...]] = {
    JOB_START: (),
    STEP_START: ("name",),
    STEP_END: ("name", "ok", "seconds"),
    PATCH_GATE: ("state",),
    FINAL: ("state",),
    ERROR: ("error_type", "severity", "retryable", "recovery_hint"),
}
_COMMON: Tuple[str, ...] = ("schema", "type", "seq", "ts", "job")


def validate(event: Any) -> List[str]:
    """Problems with ``event`` as a ``bts-sbom.events.v1`` event; ``[]`` means it is well formed. Never raises."""
    problems: List[str] = []
    if not isinstance(event, dict):
        return ["event is not a JSON object"]
    for field in _COMMON:
        if field not in event or event[field] in (None, ""):
            problems.append("missing required field %r" % (field,))
    schema = event.get("schema")
    if schema != SCHEMA:
        problems.append("schema must be %r, got %r" % (SCHEMA, schema))
    etype = event.get("type")
    if etype not in _REQUIRED:
        problems.append("unknown event type %r (expected one of %s)" % (etype, ", ".join(EVENT_TYPES)))
        return problems                                             # the type-specific checks below need a known type
    seq = event.get("seq")
    if isinstance(seq, bool) or not isinstance(seq, int) or seq < 1:
        problems.append("seq must be a positive integer, got %r" % (seq,))
    for field in _REQUIRED[etype]:
        if field not in event or event[field] in (None, ""):
            problems.append("%s: missing required field %r" % (etype, field))
    if etype == STEP_END:
        if not isinstance(event.get("ok"), bool):
            problems.append("step_end: 'ok' must be a bool")
        seconds = event.get("seconds")
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)):
            problems.append("step_end: 'seconds' must be a number")
    if etype == PATCH_GATE and event.get("state") not in PATCH_GATE_STATES:
        problems.append("patch_gate: 'state' must be one of %s" % ", ".join(PATCH_GATE_STATES))
    if etype == ERROR:
        if event.get("severity") not in ERROR_SEVERITIES:
            problems.append("error: 'severity' must be one of %s" % ", ".join(ERROR_SEVERITIES))
        if not isinstance(event.get("retryable"), bool):
            problems.append("error: 'retryable' must be a bool")
    return problems


def format_sse(event: Dict[str, Any]) -> str:
    """``event`` as one ``text/event-stream`` record: ``id``/``event`` lines plus a newline-safe ``data:`` body
    (every line of the JSON payload gets its own ``data:`` prefix, so an embedded ``\\n`` cannot truncate the event
    or start a stray field), terminated by the blank line SSE requires between records."""
    data = json.dumps(event, ensure_ascii=False, sort_keys=True, default=str)
    body = "\n".join("data: %s" % line for line in data.split("\n"))
    return "id: %s\nevent: %s\n%s\n\n" % (event.get("seq"), event.get("type"), body)


class TooManySubscribers(Exception):
    """Raised by :meth:`EventBus.subscribe` when a job already has ``EventBus.MAX_SUBSCRIBERS`` live readers."""


class EventBus:
    """One per scan job. Thread-safe: ``publish`` is called from the job's worker thread, ``iter_events`` from one or
    more HTTP handler threads reading the same job. A ``threading.Condition`` lets readers block until a new event
    exists instead of polling, while never holding the lock while a reader is blocked on handing an event to its
    caller (so a slow / stalled HTTP write can never stall ``publish``)."""

    MAX_SUBSCRIBERS = 4

    def __init__(self, job_id: str):
        self.job_id = job_id
        self._cond = threading.Condition()
        self._events: List[Dict[str, Any]] = []
        self._next_seq = 1
        self._closed = False
        self._subscribers = 0

    def publish(self, event_type: str, **fields: Any) -> Dict[str, Any]:
        """Build, validate and append one event; returns it. Raises ValueError if the result would not validate
        (a programming error in the caller, not a runtime condition) and RuntimeError once the bus is closed
        (a final/error event was already published - nothing may follow it)."""
        with self._cond:
            if self._closed:
                raise RuntimeError("event bus for job %s is already closed" % self.job_id)
            event: Dict[str, Any] = {"schema": SCHEMA, "type": event_type, "seq": self._next_seq,
                                     "ts": now_iso(), "job": self.job_id}
            for k, v in fields.items():
                if v is not None:
                    event[k] = v
            problems = validate(event)
            if problems:
                raise ValueError("invalid %s event: %s" % (event_type, "; ".join(problems)))
            self._next_seq += 1
            self._events.append(event)
            if event_type in _TERMINAL:
                self._closed = True
            self._cond.notify_all()
            return event

    @property
    def closed(self) -> bool:
        with self._cond:
            return self._closed

    def close(self) -> None:
        """Idempotent safety net: stop any blocked reader even if no final/error event was ever published
        (e.g. the worker thread died before it could report one)."""
        with self._cond:
            self._closed = True
            self._cond.notify_all()

    def subscribe(self) -> None:
        """Reserve one of the ``MAX_SUBSCRIBERS`` slots. Raises TooManySubscribers when the job is already at cap.
        Always pair with :meth:`unsubscribe` (use try/finally)."""
        with self._cond:
            if self._subscribers >= self.MAX_SUBSCRIBERS:
                raise TooManySubscribers("job %s already has %d subscribers (max %d)" %
                                         (self.job_id, self._subscribers, self.MAX_SUBSCRIBERS))
            self._subscribers += 1

    def unsubscribe(self) -> None:
        with self._cond:
            self._subscribers = max(0, self._subscribers - 1)

    def all_events(self) -> List[Dict[str, Any]]:
        """A shallow copy of every event published so far, oldest first (for tests and diagnostics)."""
        with self._cond:
            return list(self._events)

    def iter_events(self, after_seq: int = 0, timeout: float = 15.0) -> Iterator[Optional[Dict[str, Any]]]:
        """Yield events with ``seq > after_seq`` as they are published, oldest first (replaying any backlog first,
        then live). Yields ``None`` whenever ``timeout`` seconds pass with nothing new -- a heartbeat point for the
        caller, so a connection with no progress for a while still proves it is alive. Stops for good right after
        yielding a final/error event, or immediately if the bus is already closed with nothing left to replay."""
        seq = after_seq
        while True:
            pending: List[Dict[str, Any]] = []
            with self._cond:
                deadline = time.monotonic() + max(0.0, timeout)
                while True:
                    pending = [e for e in self._events if e["seq"] > seq]
                    if pending or self._closed:
                        break
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    self._cond.wait(remaining)
            if not pending:
                if self._closed:
                    return
                yield None
                continue
            for e in pending:
                seq = e["seq"]
                yield e
                if e["type"] in _TERMINAL:
                    return
