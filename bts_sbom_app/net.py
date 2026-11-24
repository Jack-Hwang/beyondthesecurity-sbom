"""Minimal HTTP JSON helper (stdlib urllib) with retry/backoff and honest failure accounting.

Every outbound call in BTS-SBOM goes through here so one place can: set a User-Agent, back off on 429/5xx,
count requests/failures for the evidence file, be monkey-patched by tests (no test touches the network), and
(course package A) short-circuit a dead host through a per-host circuit breaker instead of retrying every one
of the thousands of components in a large SBOM against it.

``fetch_json``/``fetch_text`` return a :class:`resilience.Outcome` that tells the caller the SHAPE of what
happened (success / empty_result / partial_result / access_failure) instead of folding "no such resource"
(404) and "could not reach the host" into the same ``None``. ``http_json``/``http_text`` are kept as thin
wrappers with their ORIGINAL return value (data, or ``None`` on 404/failure) so every existing caller is
unaffected.
"""
from __future__ import annotations
from . import __version__
from . import resilience

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional, Tuple

UA = "bts-sbom-app/" + __version__ + " (BTS-SBOM license and vulnerability analysis; contact via repository issues)"
STATS: Dict[str, Any] = {"requests": 0, "failures": 0, "last_error": "", "short_circuited": 0, "empty": 0, "partial": 0}
_LOCK = threading.Lock()
# tests set this to a callable(url, headers, body) -> (status, parsed_json_or_None)
#                                                    or (status, parsed_json_or_None, response_headers)
# the 3-tuple form lets a fake transport simulate a Retry-After header; None = real network
TRANSPORT = None
#: Injectable backoff sleep (tests replace this with a recording no-op so retry tests run instantly).
SLEEP = time.sleep
_RETRYABLE_STATUS = (429, 500, 502, 503, 504)
_RETRY_AFTER_CAP = 30.0


def reset_stats() -> None:
    with _LOCK:
        STATS.update(requests=0, failures=0, last_error="", short_circuited=0, empty=0, partial=0)


def reset_breakers() -> None:
    """Drop every per-host circuit breaker (fresh closed state). See resilience.reset_breakers()."""
    resilience.reset_breakers()


def _count(ok: bool, err: str = "") -> None:
    with _LOCK:
        STATS["requests"] += 1
        if not ok:
            STATS["failures"] += 1
            STATS["last_error"] = err[:200]


def _count_tag(tag: str) -> None:
    with _LOCK:
        STATS[tag] = STATS.get(tag, 0) + 1


def _call_transport(url: str, headers: Dict[str, str], body: Any) -> Tuple[int, Any, Dict[str, str]]:
    result = TRANSPORT(url, headers, body)
    if len(result) == 3:
        status, parsed, resp_headers = result
        return status, parsed, dict(resp_headers or {})
    status, parsed = result
    return status, parsed, {}


def _retry_after_seconds(resp_headers: Dict[str, str]) -> Optional[float]:
    raw = None
    for k, v in (resp_headers or {}).items():
        if k.lower() == "retry-after":
            raw = v
            break
    if raw is None:
        return None
    try:
        secs = float(raw)
    except (TypeError, ValueError):
        return None
    if secs < 0:
        return None
    return min(secs, _RETRY_AFTER_CAP)


def _classify(status: Optional[int], parsed: Any, breaker: "resilience.CircuitBreaker", attempts: int,
              truncated: bool, gen: Optional[int] = None) -> resilience.Outcome:
    """Turn one attempt's (status, parsed) into an Outcome AND tell the breaker about it (except for 404,
    which is neutral - the host answered, so it is neither a success nor a failure for breaker purposes)."""
    if status == 404:
        _count(True)
        _count_tag("empty")
        return resilience.Outcome(resilience.EMPTY_RESULT, None, 404, "not_found", attempts)
    if status is not None and status < 400:
        _count(True)
        breaker.on_success(gen)
        if truncated:
            _count_tag("partial")
            return resilience.Outcome(resilience.PARTIAL_RESULT, parsed, status, "truncated_at_limit", attempts)
        return resilience.Outcome(resilience.SUCCESS, parsed, status, "", attempts)
    _count(False, "http %s" % status if status else "transport_error")
    breaker.on_failure(gen)
    reason = "http_%s" % status if status else "transport_error"
    return resilience.Outcome(resilience.ACCESS_FAILURE, None, status, reason, attempts)


_TL = threading.local()


def thread_access_failures() -> int:
    """How many fetches in THIS thread ended as access_failure (including a short-circuited one) since the thread started.
    A caller that must tell "the server said there is nothing" from "could not check" (so it never caches the second as the
    first) reads it before and after its lookups."""
    return getattr(_TL, "failures", 0)


def _fetch(url: str, *, method_headers: Dict[str, str], body: Optional[Any], timeout: float, retries: int,
           limit: Optional[int], as_text: bool) -> resilience.Outcome:
    oc = _fetch_once(url, method_headers=method_headers, body=body, timeout=timeout, retries=retries, limit=limit,
                     as_text=as_text)
    if oc.state == resilience.ACCESS_FAILURE:
        _TL.failures = getattr(_TL, "failures", 0) + 1
    return oc


def _fetch_once(url: str, *, method_headers: Dict[str, str], body: Optional[Any], timeout: float, retries: int,
                limit: Optional[int], as_text: bool) -> resilience.Outcome:
    host = resilience.host_of(url)
    breaker = resilience.get_breaker(host)
    permitted, gen = breaker.begin()
    if not permitted:
        _count_tag("short_circuited")
        return resilience.Outcome(resilience.ACCESS_FAILURE, None, None, "circuit_open", 0)

    if TRANSPORT is not None:
        # Test-hook path: exactly one call (same as before this module grew retries), so existing tests that
        # never monkeypatch SLEEP stay instant. The breaker still sees this call's outcome, which is all the
        # breaker's own tests need (it opens/closes on CALLS, not on retries within one call).
        status, parsed, _hdrs = _call_transport(url, method_headers, body)
        truncated = bool(limit) and as_text and isinstance(parsed, str) and len(parsed) >= limit
        return _classify(status, parsed, breaker, 1, truncated, gen)

    data_bytes = json.dumps(body).encode("utf-8") if body is not None else None
    wait = 1.0
    last_status: Optional[int] = None
    last_reason = ""
    for attempt in range(retries + 1):
        attempts = attempt + 1
        resp_headers: Dict[str, str] = {}
        truncated = False
        try:
            req = urllib.request.Request(url, data=data_bytes, headers=method_headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read(limit) if limit else resp.read()
                status = getattr(resp, "status", None) or 200
            truncated = bool(limit) and len(raw) >= limit
            parsed = raw.decode("utf-8", errors="replace") if as_text else json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            status = exc.code
            parsed = None
            resp_headers = dict(exc.headers.items()) if exc.headers is not None else {}
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            status = None
            parsed = None
            last_reason = "%s: %s" % (type(exc).__name__, str(exc)[:120])

        if status == 404 or (status is not None and status < 400):
            return _classify(status, parsed, breaker, attempts, truncated, gen)

        retryable = status is None or status in _RETRYABLE_STATUS
        if not retryable:
            return _classify(status, parsed, breaker, attempts, truncated, gen)

        last_status = status
        if not last_reason:
            last_reason = "http %s" % status
        if attempt < retries:
            retry_after = _retry_after_seconds(resp_headers)
            SLEEP(retry_after if retry_after is not None else wait)
            wait *= 2.5
            continue

    # retries exhausted: the breaker counts exactly one failure per call, not per attempt.
    _count(False, last_reason + " " + url[:80])
    breaker.on_failure(gen)
    reason = "retries_exhausted" if last_status is None else "http_%s" % last_status
    return resilience.Outcome(resilience.ACCESS_FAILURE, None, last_status, reason, retries + 1)


def fetch_text(url: str, *, timeout: float = 20.0, retries: int = 1, limit: int = 400_000) -> resilience.Outcome:
    """GET -> Outcome carrying text (e.g. a Maven POM). Reads at most ``limit`` bytes; hitting the limit is
    reported as partial_result (the truncated text is still returned)."""
    hdrs = {"User-Agent": UA, "Accept": "text/xml,text/plain,*/*"}
    return _fetch(url, method_headers=hdrs, body=None, timeout=timeout, retries=retries, limit=limit, as_text=True)


def fetch_json(url: str, *, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
               timeout: float = 20.0, retries: int = 2) -> resilience.Outcome:
    """GET (or POST when ``body``) -> Outcome carrying parsed JSON."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    hdrs.update(headers or {})
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    return _fetch(url, method_headers=hdrs, body=body, timeout=timeout, retries=retries, limit=None, as_text=False)


def http_text(url: str, *, timeout: float = 20.0, retries: int = 1, limit: int = 400_000) -> Optional[str]:
    """GET -> text or None on 404/failure. Unchanged contract: kept as a thin wrapper over fetch_text()."""
    oc = fetch_text(url, timeout=timeout, retries=retries, limit=limit)
    return oc.data if oc.state in (resilience.SUCCESS, resilience.PARTIAL_RESULT) else None


def http_json(url: str, *, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
              timeout: float = 20.0, retries: int = 2) -> Optional[Any]:
    """GET (or POST when ``body``) -> parsed JSON, or None on 404/failure. Unchanged contract: kept as a thin
    wrapper over fetch_json()."""
    oc = fetch_json(url, body=body, headers=headers, timeout=timeout, retries=retries)
    return oc.data if oc.state in (resilience.SUCCESS, resilience.PARTIAL_RESULT) else None
