"""Minimal HTTP JSON/text helper (stdlib urllib) with retry/backoff, a per-host circuit breaker and honest failure accounting.

Every outbound call in BTS-SBOM goes through here so one place can: set a User-Agent, back off on 429/5xx,
honour Retry-After, stop hammering a dead host (circuit breaker), count requests/failures for the evidence
file, and be monkey-patched by tests (no test touches the network). ``fetch_json``/``fetch_text`` return a
four-state ``Outcome`` (success / empty_result / partial_result / access_failure - "could not check" is not
"not found"); the older ``http_json``/``http_text`` wrappers keep returning exactly what they always did.
"""
from __future__ import annotations
from . import __version__
from .resilience import Outcome, breaker_for
from .resilience import reset_breakers as _reset_breakers_impl

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

UA = "bts-sbom-app/" + __version__ + " (BTS-SBOM license and vulnerability analysis; contact via repository issues)"
STATS: Dict[str, Any] = {"requests": 0, "failures": 0, "last_error": "", "short_circuited": 0, "empty": 0, "partial": 0}
_LOCK = threading.Lock()
# tests set this to a callable(url, headers, body) -> (status, parsed_json_or_None) or (status, parsed, headers); None = real network
TRANSPORT = None
# tests replace this to observe/avoid real backoff waits
SLEEP = time.sleep
RETRY_AFTER_CAP = 30.0
# statuses worth another try: rate limiting and server-side trouble; other 4xx (403 et al) answer the question
_RETRYABLE = (429, 500, 502, 503, 504)


def reset_stats() -> None:
    with _LOCK:
        STATS.update(requests=0, failures=0, last_error="", short_circuited=0, empty=0, partial=0)


def reset_breakers() -> None:
    _reset_breakers_impl()


def _tally(ok: bool, err: str = "", short_circuit: bool = False) -> None:
    with _LOCK:
        STATS["requests"] += 1
        if short_circuit:
            STATS["short_circuited"] += 1
        if not ok:
            STATS["failures"] += 1
            STATS["last_error"] = err[:200]


def _tally_empty() -> None:
    with _LOCK:
        STATS["empty"] += 1


def _tally_partial() -> None:
    with _LOCK:
        STATS["partial"] += 1


def _call_transport(url: str, hdrs: Dict[str, str], body: Any) -> Tuple[int, Any, Dict[str, str]]:
    """Run the test hook, accepting both the old 2-tuple and the newer (status, parsed, headers) 3-tuple."""
    out = TRANSPORT(url, hdrs, body)
    if isinstance(out, tuple) and len(out) == 3:
        status, parsed, extra = out
        return status, parsed, (extra or {})
    status, parsed = out
    return status, parsed, {}


def _retry_after_seconds(hdrs: Dict[str, str]) -> Optional[float]:
    """Retry-After in seconds (integer form only; the HTTP-date form is ignored), capped at 30."""
    raw = hdrs.get("Retry-After") or hdrs.get("retry-after")
    if raw is None:
        return None
    try:
        return min(max(float(str(raw).strip()), 0.0), RETRY_AFTER_CAP)
    except (TypeError, ValueError):
        return None


def _short_circuit(url: str) -> Outcome:
    """The host's circuit is open: 0 requests sent, the honest answer is 'could not check'."""
    _tally(False, "circuit_open " + url[:80], short_circuit=True)
    return Outcome("access_failure", None, None, "circuit_open", 0)


def fetch_text(url: str, *, timeout: float = 20.0, retries: int = 1, limit: int = 400_000) -> Outcome:
    """GET -> text (e.g. a Maven POM). Reads at most ``limit`` bytes; a truncated body is a partial_result, still returned."""
    hdrs = {"User-Agent": UA, "Accept": "text/xml,text/plain,*/*"}
    brk = breaker_for(url)
    if brk is not None and not brk.allow():
        return _short_circuit(url)
    wait = 1.0
    last = ""
    attempts = 0
    while attempts <= retries:
        attempts += 1
        ra = None
        retryable = True
        if TRANSPORT is not None:
            status, parsed, _extra = _call_transport(url, hdrs, None)
            if status < 400 and isinstance(parsed, str):
                _tally(True)
                if brk:
                    brk.record_success()
                return Outcome("success", parsed, status, "", attempts)
            if status == 404:
                _tally(True)
                _tally_empty()
                if brk:
                    brk.record_neutral()
                return Outcome("empty_result", None, 404, "http 404", attempts)
            last = "http %s" % status
            retryable = status in _RETRYABLE
            failed = True
        else:
            failed = False
            try:
                with urllib.request.urlopen(urllib.request.Request(url, headers=hdrs), timeout=timeout) as resp:
                    raw = resp.read(limit + 1)
                _tally(True)
                if brk:
                    brk.record_success()
                text = raw.decode("utf-8", errors="replace")
                if len(raw) > limit:                    # one extra byte read means the body was cut at the limit
                    _tally_partial()
                    return Outcome("partial_result", text[:limit], resp.status, "truncated at %d bytes" % limit, attempts)
                return Outcome("success", text, resp.status, "", attempts)
            except urllib.error.HTTPError as exc:
                status = exc.code
                if status == 404:
                    _tally(True)
                    _tally_empty()
                    if brk:
                        brk.record_neutral()
                    return Outcome("empty_result", None, 404, "http 404", attempts)
                last = "http %s" % status
                retryable = status in _RETRYABLE
                if status == 429:
                    ra = _retry_after_seconds(getattr(exc, "headers", None) or {})
                failed = True
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last = "%s: %s" % (type(exc).__name__, str(exc)[:120])
                failed = True
        if failed and attempts <= retries and retryable:
            SLEEP(ra if ra is not None else wait)
            wait *= 2.5
            continue
        break
    _tally(False, last + " " + url[:80])
    if brk:
        brk.record_failure()
    return Outcome("access_failure", None, None, last, attempts)


def fetch_json(url: str, *, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
               timeout: float = 20.0, retries: int = 2) -> Outcome:
    """GET (or POST when ``body``) -> parsed JSON. 404 is an empty_result (not a failure); timeouts/429/5xx/URLError retry."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    brk = breaker_for(url)
    if brk is not None and not brk.allow():
        return _short_circuit(url)
    wait = 1.0
    last = ""
    attempts = 0
    while attempts <= retries:
        attempts += 1
        ra = None
        retryable = True
        if TRANSPORT is not None:
            status, parsed, extra = _call_transport(url, hdrs, body)
            if status < 400:
                _tally(True)
                if brk:
                    brk.record_success()
                return Outcome("success", parsed, status, "", attempts)
            if status == 404:
                _tally(True)
                _tally_empty()
                if brk:
                    brk.record_neutral()
                return Outcome("empty_result", None, 404, "http 404", attempts)
            last = "http %s" % status
            retryable = status in _RETRYABLE
            if status == 429:
                ra = _retry_after_seconds(extra)
            failed = True
        else:
            failed = False
            try:
                req = urllib.request.Request(url, data=data, headers=hdrs)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                _tally(True)
                if brk:
                    brk.record_success()
                return Outcome("success", json.loads(raw.decode("utf-8", errors="replace")), resp.status, "", attempts)
            except urllib.error.HTTPError as exc:
                status = exc.code
                if status == 404:
                    _tally(True)
                    _tally_empty()
                    if brk:
                        brk.record_neutral()
                    return Outcome("empty_result", None, 404, "http 404", attempts)
                last = "http %s" % status
                retryable = status in _RETRYABLE
                if status == 429:
                    ra = _retry_after_seconds(getattr(exc, "headers", None) or {})
                failed = True
            except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
                last = "%s: %s" % (type(exc).__name__, str(exc)[:120])
                failed = True
        if failed and attempts <= retries and retryable:
            SLEEP(ra if ra is not None else wait)
            wait *= 2.5
            continue
        break
    _tally(False, last + " " + url[:80])
    if brk:
        brk.record_failure()
    return Outcome("access_failure", None, None, last, attempts)


def http_text(url: str, *, timeout: float = 20.0, retries: int = 1, limit: int = 400_000) -> Optional[str]:
    """Backward-compatible wrapper: text or None (404/failure), exactly as before."""
    out = fetch_text(url, timeout=timeout, retries=retries, limit=limit)
    return out.data if out.state in ("success", "partial_result") and isinstance(out.data, str) else None


def http_json(url: str, *, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
              timeout: float = 20.0, retries: int = 2) -> Optional[Any]:
    """Backward-compatible wrapper: parsed JSON or None (404/failure), exactly as before."""
    out = fetch_json(url, body=body, headers=headers, timeout=timeout, retries=retries)
    return out.data if out.state == "success" else None
