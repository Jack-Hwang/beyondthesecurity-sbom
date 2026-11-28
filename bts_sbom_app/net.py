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
from . import netaddr, resilience
from bts_sbom import ossscan

import json
import logging
import os
import threading
import time
import urllib.error
import urllib.parse
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
_LOG = logging.getLogger(__name__)

#: Egress allowlist/SSRF guard (course package C01). Every real network attempt below (never the TRANSPORT test-hook
#: path, which never opens a socket) is checked before any connection is attempted: only http(s) URLs whose host
#: resolves to a PUBLIC address are let through. The address classification itself is bts_sbom.ossscan's own
#: _non_public_address (loopback / link-local incl. 169.254.169.254 cloud metadata / private / CGNAT / multicast /
#: reserved / unspecified, IPv4 and IPv6) - reused rather than re-implemented so the two guards never drift apart.
#: BTS_OSS_ALLOW_PRIVATE_HOSTS=1 (the same opt-out bts_sbom/ossscan.py and oss_api.py already read) lets an operator
#: who really wants an internal host reach it; it never bypasses the scheme check (file://, ftp:// etc. stay refused
#: either way - that is a different, larger permission than "this one intranet host").
#:
#: DNS is a real, potentially-blocking network call, so three cases below never reach ``socket.getaddrinfo`` at all
#: (this module's own docstring claim that "no test touches the network" is true for ALL of these, not just the
#: TRANSPORT-hook path): a literal IP-address host is classified with :mod:`ipaddress` directly (same rules as
#: ossscan's own - loopback/link-local/private/CGNAT/multicast/reserved/unspecified); a host in
#: :data:`KNOWN_PUBLIC_HOSTS` (this app's own well-known API hosts - pypi.org and friends, the same list the test
#: suite reuses) is treated as public outright, which also halves the DNS cost of every real production fetch to one
#: of them (previously resolved once here and again inside ``urlopen``); and a host under an RFC 2606 reserved
#: documentation/testing suffix (``.invalid``/``.test``/``.example`` - guaranteed never to be registered in the real
#: DNS, so it can never be a live SSRF target either) is let through unresolved - this is what keeps the
#: pre-existing ``test_resilience.py`` convention (``TRANSPORT=None`` + a direct ``urllib.request.urlopen`` mock,
#: with hosts like ``real1.example.invalid``) from ever making a real DNS round trip. ``localhost``/``*.localhost``
#: (RFC 6761 - always the loopback alias) is blocked the same way, also without a lookup. Everything else still goes
#: through the real (mockable-by-tests) ``_non_public_address`` resolution below.
#:
#: Known limitation (stated, not silently dropped): this only re-checks the URL the caller gave; a redirect the
#: remote host sends back is followed by plain ``urlopen`` without a second host check, same as every caller of this
#: module already got before this guard existed. Re-checking the redirect target too (as bts_sbom/ossscan.py's own
#: ``_GuardedRedirect`` does for the OSS-scanner download path) needs a custom opener, and this module's existing
#: tests replace ``urllib.request.urlopen`` directly to simulate the network - installing a custom opener would
#: either bypass those tests' stub or (via ``install_opener``) leak a process-global opener into unrelated
#: ``urlopen`` callers such as ossscan's own. Left for a follow-up that revisits the test-mocking convention too.

#: This app's own well-known public API hosts (pypi/npm/maven/osv/endoflife - every literal host this codebase's own
#: licenses.py/compat.py/arch.py/osv.py already fetch from). Classified as public without a DNS lookup; the test
#: suite imports this same constant so the allowlist can never silently drift between production code and tests.
KNOWN_PUBLIC_HOSTS = frozenset({
    "pypi.org", "files.pythonhosted.org", "registry.npmjs.org",
    "repo1.maven.org", "api.osv.dev", "endoflife.date",
})

#: RFC 2606 suffixes reserved for documentation/testing - never registered in the real DNS, so a host under one of
#: these can never resolve to a real (public or internal) address and needs no lookup either way.
_RESERVED_TEST_TLDS = frozenset({"invalid", "test", "example"})


def _allow_private_hosts() -> bool:
    return os.environ.get("BTS_OSS_ALLOW_PRIVATE_HOSTS", "").strip() == "1"


def _is_reserved_test_host(host: str) -> bool:
    label = host.rsplit(".", 1)[-1]
    return label in _RESERVED_TEST_TLDS


_NOT_A_LITERAL_IP = object()  # sentinel: distinguishes "host isn't a literal IP" from "it is, and it's public"


def _literal_ip_refusal(host: str):
    """``"egress_blocked_host"``/``None`` if ``host`` is itself a literal IP address (classified with
    :mod:`netaddr` alone - no DNS round trip needed, it already IS the address; legacy spellings such as
    ``2130706433``, ``0x7f000001``, ``0177.0.0.1`` and ``127.1`` are literals too: they are what the clients connect to),
    else :data:`_NOT_A_LITERAL_IP` so the caller falls back to real resolution for an actual hostname."""
    ip = netaddr.parse_literal(host)
    if ip is None:
        return _NOT_A_LITERAL_IP
    return None if netaddr.is_public(ip) else "egress_blocked_host"


def _egress_refusal(url: str) -> Optional[str]:
    """None if ``url`` may be fetched; else a short machine-readable reason (never raises)."""
    try:
        parts = urllib.parse.urlsplit(url)
    except ValueError:
        return "egress_blocked_scheme"
    host = parts.hostname
    if parts.scheme not in ("http", "https") or not host:
        return "egress_blocked_scheme"
    if _allow_private_hosts():
        return None
    host = netaddr.normalize_host(host)
    if host == "localhost" or host.endswith(".localhost"):
        return "egress_blocked_host"
    if host in KNOWN_PUBLIC_HOSTS:
        return None
    literal = _literal_ip_refusal(host)
    if literal is not _NOT_A_LITERAL_IP:
        return literal
    if _is_reserved_test_host(host):
        return None
    bad = ossscan._non_public_address(host)
    if bad:
        return "egress_blocked_host"
    return None


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
           limit: Optional[int], as_text: bool, as_bytes: bool = False) -> resilience.Outcome:
    oc = _fetch_once(url, method_headers=method_headers, body=body, timeout=timeout, retries=retries, limit=limit,
                     as_text=as_text, as_bytes=as_bytes)
    if oc.state == resilience.ACCESS_FAILURE:
        _TL.failures = getattr(_TL, "failures", 0) + 1
    return oc


def _fetch_once(url: str, *, method_headers: Dict[str, str], body: Optional[Any], timeout: float, retries: int,
                limit: Optional[int], as_text: bool, as_bytes: bool = False) -> resilience.Outcome:
    if TRANSPORT is None:
        # Only the real network path below ever opens a socket; a test that injects TRANSPORT never does, so it is
        # never asked to resolve its (often fake/unresolvable) host - the guard runs exactly where a connection
        # could otherwise happen, which is what "before any socket opens" means.
        refusal = _egress_refusal(url)
        if refusal is not None:
            # host only (never resilience.host_of(url)'s netloc, which keeps http(s)://user:pass@host userinfo) -
            # a refused request is still logged, but never with the credentials that made the caller refuse it.
            try:
                safe_host = urllib.parse.urlsplit(url).hostname
            except ValueError:
                safe_host = None
            _LOG.warning("net: refusing egress to host=%r (%s)", safe_host, refusal)
            _count(False, refusal)
            return resilience.Outcome(resilience.ACCESS_FAILURE, None, None, refusal, 0)

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
        truncated = bool(limit) and ((as_text and isinstance(parsed, str)) or (as_bytes and isinstance(parsed, (bytes, bytearray))))             and len(parsed) >= limit
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
            if as_bytes:
                parsed = raw
            else:
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


def fetch_bytes(url: str, *, timeout: float = 60.0, retries: int = 1, limit: int = 40_000_000) -> resilience.Outcome:
    """GET -> Outcome carrying the raw bytes (a package archive). Reads at most ``limit`` bytes; hitting the limit is
    reported as partial_result and a truncated archive is NOT usable - callers must treat that as a failure."""
    hdrs = {"User-Agent": UA, "Accept": "application/octet-stream,*/*"}
    return _fetch(url, method_headers=hdrs, body=None, timeout=timeout, retries=retries, limit=limit, as_text=False, as_bytes=True)


def fetch_json(url: str, *, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
               timeout: float = 20.0, retries: int = 2) -> resilience.Outcome:
    """GET (or POST when ``body``) -> Outcome carrying parsed JSON."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    hdrs.update(headers or {})
    if body is not None:
        hdrs["Content-Type"] = "application/json"
    return _fetch(url, method_headers=hdrs, body=body, timeout=timeout, retries=retries, limit=None, as_text=False)


def http_json_oc(url: str, *, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
                 timeout: float = 20.0, retries: int = 2) -> resilience.Outcome:
    """fetch_json passthrough for callers that must tell 'no such data' from 'we never asked' (C07): the full
    Outcome carries ``state`` and ``reason`` (e.g. ``circuit_open``), which plain ``http_json`` collapses to
    None. No new transport path - exactly what fetch_json learned, nothing invented."""
    return fetch_json(url, body=body, headers=headers, timeout=timeout, retries=retries)


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
