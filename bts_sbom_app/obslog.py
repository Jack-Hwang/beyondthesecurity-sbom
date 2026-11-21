"""One-line JSON access logging with request ids (task 17) - stdlib only.

Every request writes ONE stdout line: ``{"ts", "level", "event", "request_id", "job_id", "route_class", "status",
"ms"}`` (plus ``who`` when an identity is known). Request bodies, query strings, Authorization headers, API keys,
approval tokens and URL credentials are NEVER logged - values pass through ``mask`` first and the log carries only
structural fields the server itself builds. A client-supplied X-Request-Id is reused only when it matches
``^[A-Za-z0-9._-]{1,64}$`` (log-injection guard); anything else gets a fresh id.
"""
from __future__ import annotations

import json
import re
import sys
import threading
import time
import uuid
from typing import Any

REQUEST_ID_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
_LOCK = threading.Lock()

# planted values a test uses to prove the log never echoes them - kept here only so tests can share one list
SECRET_KEYS = ("authorization", "api_key", "approval_token", "token", "password", "secret")


def new_request_id() -> str:
    return uuid.uuid4().hex[:16]


def clean_request_id(raw: str) -> str:
    """Reuse a client id only when it is plain and short; otherwise mint a fresh one (no log injection)."""
    s = str(raw or "").strip()
    return s if REQUEST_ID_RE.match(s) else new_request_id()


def route_class(path: str) -> str:
    """A fixed low-cardinality class per route family - raw paths never become metric labels."""
    p = str(path or "")
    if p in ("/healthz", "/readyz"):
        return "probe"
    if p.startswith("/metrics"):
        return "metrics"
    if p.startswith("/api/scan"):
        return "scan"
    if p.startswith("/api/jobs"):
        return "jobs"
    if p.startswith("/api/chat"):
        return "chat"
    if p.startswith("/api/llm"):
        return "llm"
    if p.startswith("/api/fleet") or p.startswith("/api/affected"):
        return "fleet"
    if p.startswith("/api/sbom/") or p.startswith("/api/view/") or p.startswith("/api/doc/") or p.startswith("/api/history") \
            or p.startswith("/api/selfcheck") or p.startswith("/api/conformance") or p.startswith("/api/changes") \
            or p.startswith("/api/vex") or p.startswith("/api/coverage"):
        return "sbom"
    if p.startswith("/api/"):
        return "other"
    return "view"


def mask(text: str) -> str:
    """Defence in depth: if a secret-shaped value ever reached the log line, drop it here."""
    s = str(text or "")
    low = s.lower()
    for key in SECRET_KEYS:
        if key in low:
            return "[masked]"
    return s


def write(event: str, *, request_id: str = "", route: str = "", status: int = 0, ms: float = 0.0,
          job_id: str = "", who: str = "", stream: Any = None) -> str:
    """One JSON line to stdout. Returns the line (tests capture it instead of parsing stdout)."""
    line = json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": "info", "event": mask(event),
                       "request_id": clean_request_id(request_id), "job_id": mask(job_id), "route_class": route_class(route),
                       "status": int(status), "ms": round(float(ms), 1),
                       **({"who": mask(who)} if who else {})}, ensure_ascii=False, sort_keys=False)
    stream = stream or sys.stdout
    with _LOCK:
        try:
            stream.write(line + "\n")
            stream.flush()
        except (OSError, ValueError):
            pass
    return line
