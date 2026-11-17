"""Pooled, retrying, gzip-aware HTTP client used by the OSV live/mirror layer (stdlib only).

Why not ``urllib.request.urlopen`` per call (what ``osv_client`` does)?  Every urlopen opens a new TCP
connection and, for https, a new TLS handshake (~100-300 ms each).  A scan that issues hundreds of tiny
requests to api.osv.dev spends most of its wall-clock time in handshakes, not in OSV.  This client keeps one
keep-alive connection per (thread, host) so N requests cost one handshake per worker thread.

Contract (honest failure accounting - the substitution rule of this project applies here too):
  * ``HttpResult.ok`` is True only for a 2xx answer.  Network errors / 5xx / 429 that survive the retries
    come back as ``status=None`` or the last bad status with ``error`` set - never as an empty "success".
  * 404 and 304 are *answers*, not failures: they are returned (``not_found`` / ``not_modified``), not retried.
  * 429/500/502/503/504 and connection-level errors are retried with exponential backoff + full jitter and
    ``Retry-After`` is honoured (capped).
  * Requests go through ``TRANSPORT`` when a test installs one, so no test needs the real network.

When an HTTP(S) proxy is configured for the target host the client transparently falls back to urllib
(``http.client`` does not understand proxies), trading keep-alive for compatibility.
"""
from __future__ import annotations

import http.client
import os
import random
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple

try:  # single source of truth for the version (also used by the writers)
    from bts_sbom._version import __version__ as _VERSION
except Exception:  # pragma: no cover - defensive
    _VERSION = "0"

USER_AGENT = "bts-sbom/%s (+osv-live; stdlib)" % _VERSION

# tests install a callable(method, url, headers, body_bytes) -> (status, headers_dict, body_bytes).
# It may raise to simulate a network error.  None = real network.
TRANSPORT: Optional[Callable[[str, str, Dict[str, str], Optional[bytes]],
                             Tuple[int, Dict[str, str], bytes]]] = None

RETRY_STATUSES = frozenset({429, 500, 502, 503, 504})
MAX_BODY = 128 << 20                 # hard cap on ONE response body, raw and after decompression (OSV documents 32 MiB)
MAX_DOWNLOAD = 4 << 30               # hard cap on a streamed download (all.zip)
TOTAL_TIMEOUT = 180.0                # wall-clock cap for one request, however slowly the server trickles bytes
DOWNLOAD_TOTAL_TIMEOUT = 3 * 3600.0


class ResponseTooLarge(Exception):
    """A response exceeded the size cap (raw or once decompressed): never buffered further, never retried."""
_STALE_CONN_ERRORS = (http.client.RemoteDisconnected, http.client.BadStatusLine,
                      http.client.CannotSendRequest, http.client.ResponseNotReady,
                      ConnectionResetError, ConnectionAbortedError, BrokenPipeError)
_NET_ERRORS = (OSError, http.client.HTTPException, ssl.SSLError, socket.timeout, TimeoutError)


@dataclass
class HttpResult:
    status: Optional[int]                 # None = no HTTP answer (network failure)
    body: bytes = b""
    headers: Dict[str, str] = field(default_factory=dict)   # lower-cased names
    error: Optional[str] = None
    attempts: int = 1
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def not_found(self) -> bool:
        return self.status == 404

    @property
    def not_modified(self) -> bool:
        return self.status == 304

    @property
    def answered(self) -> bool:
        """True when the server gave a definitive answer (2xx, 304 or 404) - i.e. NOT a transport/server failure."""
        return self.status is not None and (self.ok or self.status in (304, 404))

    def json(self) -> Any:
        """Parsed JSON body, or None when empty / not JSON (never raises)."""
        import json
        if not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8", "replace"))
        except (ValueError, RecursionError):          # RecursionError: a hostile, absurdly nested body must not crash a sync
            return None

    def text(self) -> str:
        return self.body.decode("utf-8", "replace")


def _lower_headers(items) -> Dict[str, str]:
    return {str(k).lower(): str(v) for k, v in items}


def _bounded_inflate(body: bytes, wbits: int, limit: int) -> bytes:
    d = zlib.decompressobj(wbits)
    out = d.decompress(body, limit + 1)
    if len(out) > limit or d.unconsumed_tail:
        raise ResponseTooLarge("response expands beyond %d bytes" % limit)
    out += d.flush()
    if len(out) > limit:
        raise ResponseTooLarge("response expands beyond %d bytes" % limit)
    return out


def _decode_body(body: bytes, encoding: str, limit: Optional[int] = None) -> bytes:
    """Decode Content-Encoding with a hard output cap (a ~1000:1 gzip bomb must not be inflated in memory)."""
    limit = MAX_BODY if limit is None else limit
    enc = (encoding or "").lower().strip()
    if not body or not enc or enc == "identity":
        if len(body) > limit:
            raise ResponseTooLarge("response larger than %d bytes" % limit)
        return body
    try:
        if enc in ("gzip", "x-gzip"):
            return _bounded_inflate(body, zlib.MAX_WBITS | 16, limit)
        if enc == "deflate":
            try:
                return _bounded_inflate(body, zlib.MAX_WBITS, limit)
            except zlib.error:
                return _bounded_inflate(body, -zlib.MAX_WBITS, limit)
    except (OSError, EOFError, zlib.error):
        # a corrupt body must surface as a failure upstream, not as silent garbage
        raise ValueError("undecodable %s body" % enc)
    return body


def _read_limited(resp: Any, deadline: float, limit: Optional[int] = None) -> bytes:
    """Read a response body in chunks, enforcing BOTH a size cap and a wall-clock deadline (the per-socket timeout alone lets
    a server that sends one byte every few seconds hold a worker thread forever).  ``read1`` returns as soon as ANY data has
    arrived, so the deadline is checked after every packet instead of after every 64 KiB."""
    limit = MAX_BODY if limit is None else limit
    reader = getattr(resp, "read1", None) or resp.read
    chunks: List[bytes] = []
    n = 0
    while True:
        if time.monotonic() > deadline:
            raise TimeoutError("request exceeded its total time limit")
        part = reader(65536)
        if not part:
            return b"".join(chunks)
        n += len(part)
        if n > limit:
            raise ResponseTooLarge("response larger than %d bytes" % limit)
        chunks.append(part)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """The proxy-fallback transport must behave like the pooled one: a 3xx is a failure to report, never silently followed
    to another host."""

    def redirect_request(self, *a: Any, **k: Any) -> None:       # type: ignore[override]
        return None


_OPENER: Any = None


def _opener() -> Any:
    global _OPENER
    if _OPENER is None:
        _OPENER = urllib.request.build_opener(_NoRedirect())     # still honours the proxy environment variables
    return _OPENER


class HttpClient:
    """Thread-safe client; one keep-alive connection per (thread, scheme+host)."""

    def __init__(self, *, timeout: float = 30.0, retries: int = 4, backoff: float = 0.5,
                 max_backoff: float = 20.0, user_agent: str = USER_AGENT, total_timeout: float = TOTAL_TIMEOUT,
                 sleep: Callable[[float], None] = time.sleep,
                 rng: Callable[[], float] = random.random) -> None:
        self.timeout = float(timeout)
        self.total_timeout = float(total_timeout)
        self.retries = max(0, int(retries))
        self.backoff = float(backoff)
        self.max_backoff = float(max_backoff)
        self.user_agent = user_agent
        self._sleep = sleep
        self._rng = rng
        self._local = threading.local()
        self._lock = threading.Lock()
        self._ssl = ssl.create_default_context()
        self.stats: Dict[str, Any] = {"requests": 0, "retries": 0, "failures": 0, "bytes_in": 0,
                                      "connections_opened": 0, "connections_reused": 0, "last_error": ""}

    # ------------------------------------------------------------------ stats
    def _bump(self, **kw: int) -> None:
        with self._lock:
            for k, v in kw.items():
                self.stats[k] = self.stats.get(k, 0) + v

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self.stats)

    # ------------------------------------------------------------- connections
    def _pool(self) -> Dict[Tuple[str, str], http.client.HTTPConnection]:
        pool = getattr(self._local, "pool", None)
        if pool is None:
            pool = self._local.pool = {}
        return pool

    def close(self) -> None:
        """Close this thread's connections (other threads close theirs when they exit)."""
        pool = getattr(self._local, "pool", None) or {}
        for conn in list(pool.values()):
            try:
                conn.close()
            except Exception:
                pass
        pool.clear()

    @staticmethod
    def _proxied(url: str) -> bool:
        parts = urllib.parse.urlsplit(url)
        try:
            proxies = urllib.request.getproxies()
            if parts.scheme in proxies and not urllib.request.proxy_bypass(parts.hostname or ""):
                return True
        except Exception:
            return False
        return False

    def _connection(self, parts) -> Tuple[http.client.HTTPConnection, bool]:
        """(connection, reused)"""
        key = (parts.scheme, parts.netloc)
        pool = self._pool()
        conn = pool.get(key)
        if conn is not None:
            return conn, True
        host = parts.hostname or ""
        port = parts.port
        if parts.scheme == "https":
            conn = http.client.HTTPSConnection(host, port, timeout=self.timeout, context=self._ssl)
        else:
            conn = http.client.HTTPConnection(host, port, timeout=self.timeout)
        pool[key] = conn
        self._bump(connections_opened=1)
        return conn, False

    def _drop(self, parts) -> None:
        pool = self._pool()
        conn = pool.pop((parts.scheme, parts.netloc), None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass

    # ---------------------------------------------------------------- one try
    def _once(self, method: str, url: str, headers: Dict[str, str], body: Optional[bytes],
              timeout: float, deadline: Optional[float] = None) -> Tuple[int, Dict[str, str], bytes]:
        deadline = deadline if deadline is not None else time.monotonic() + self.total_timeout
        if TRANSPORT is not None:
            status, hdrs, data = TRANSPORT(method, url, dict(headers), body)
            hdrs = _lower_headers((hdrs or {}).items())
            if len(data or b"") > MAX_BODY:
                raise ResponseTooLarge("response larger than %d bytes" % MAX_BODY)
            return status, hdrs, _decode_body(data or b"", hdrs.get("content-encoding", ""))
        if self._proxied(url):
            return self._once_urllib(method, url, headers, body, timeout, deadline)
        parts = urllib.parse.urlsplit(url)
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        for _stale_retry in (0, 1):
            conn, reused = self._connection(parts)
            if reused:
                self._bump(connections_reused=1)
            try:
                conn.timeout = timeout
                if conn.sock is not None:
                    conn.sock.settimeout(timeout)
                conn.request(method, path, body=body, headers=headers)
                resp = conn.getresponse()
                data = _read_limited(resp, deadline)
                hdrs = _lower_headers(resp.getheaders())
                if (hdrs.get("connection", "").lower() == "close") or resp.will_close:
                    self._drop(parts)
                return resp.status, hdrs, _decode_body(data, hdrs.get("content-encoding", ""))
            except _STALE_CONN_ERRORS:
                self._drop(parts)
                if reused and _stale_retry == 0:
                    continue      # a keep-alive socket the server closed: reconnect once, free of charge
                raise
            except BaseException:
                self._drop(parts)
                raise
        raise http.client.HTTPException("unreachable")   # pragma: no cover

    def _once_urllib(self, method, url, headers, body, timeout, deadline=None):
        deadline = deadline if deadline is not None else time.monotonic() + self.total_timeout
        req = urllib.request.Request(url, data=body, headers=headers, method=method)
        try:
            with _opener().open(req, timeout=timeout) as resp:
                data = _read_limited(resp, deadline)
                hdrs = _lower_headers(resp.headers.items())
                return resp.status, hdrs, _decode_body(data, hdrs.get("content-encoding", ""))
        except urllib.error.HTTPError as exc:
            try:
                data = _read_limited(exc, deadline) if hasattr(exc, "read") else b""
            except ResponseTooLarge:
                data = b""
            hdrs = _lower_headers(exc.headers.items()) if exc.headers else {}
            try:
                data = _decode_body(data, hdrs.get("content-encoding", ""))
            except ValueError:
                data = b""
            return exc.code, hdrs, data

    # -------------------------------------------------------------- public API
    def request(self, method: str, url: str, *, body: Optional[bytes] = None,
                headers: Optional[Dict[str, str]] = None, retries: Optional[int] = None,
                timeout: Optional[float] = None) -> HttpResult:
        hdrs = {"User-Agent": self.user_agent, "Accept-Encoding": "gzip", "Accept": "application/json, */*"}
        hdrs.update(headers or {})
        max_retries = self.retries if retries is None else max(0, int(retries))
        tmo = self.timeout if timeout is None else float(timeout)
        t0 = time.monotonic()
        last_status: Optional[int] = None
        last_headers: Dict[str, str] = {}
        last_body = b""
        last_error = ""
        attempts = 0
        for attempt in range(max_retries + 1):
            attempts = attempt + 1
            self._bump(requests=1)
            delay = None
            try:
                status, rheaders, data = self._once(method, url, hdrs, body, tmo, time.monotonic() + self.total_timeout)
                self._bump(bytes_in=len(data))
                last_status, last_headers, last_body = status, rheaders, data
                if status not in RETRY_STATUSES:
                    definitive = (200 <= status < 300) or status in (304, 404)
                    return HttpResult(status, data, rheaders, None if definitive else "http %d" % status,
                                      attempts, time.monotonic() - t0)
                last_error = "http %d" % status
                ra = rheaders.get("retry-after", "")
                if ra.isdigit():
                    delay = min(float(ra), self.max_backoff)
            except ResponseTooLarge as exc:    # hostile / broken server: report it, do not retry, do not buffer it
                self._bump(failures=1)
                with self._lock:
                    self.stats["last_error"] = ("%s %s" % (exc, url[:100]))[:240]
                return HttpResult(None, b"", {}, "response too large: %s" % exc, attempts, time.monotonic() - t0)
            except ValueError as exc:          # undecodable body: transport-level corruption -> retry
                last_error = "bad response: %s" % exc
            except _NET_ERRORS as exc:
                last_status = None
                last_error = "%s: %s" % (type(exc).__name__, str(exc)[:160])
            if attempt < max_retries:
                self._bump(retries=1)
                if delay is None:
                    delay = self._rng() * min(self.max_backoff, self.backoff * (2 ** attempt))
                self._sleep(delay)
        self._bump(failures=1)
        with self._lock:
            self.stats["last_error"] = ("%s %s" % (last_error, url[:100]))[:240]
        return HttpResult(last_status, last_body, last_headers, last_error, attempts, time.monotonic() - t0)

    def get(self, url: str, **kw: Any) -> HttpResult:
        return self.request("GET", url, **kw)

    def post_json(self, url: str, payload: Any, **kw: Any) -> HttpResult:
        import json
        hdrs = dict(kw.pop("headers", None) or {})
        hdrs["Content-Type"] = "application/json"
        return self.request("POST", url, body=json.dumps(payload, separators=(",", ":")).encode("utf-8"),
                            headers=hdrs, **kw)

    # ------------------------------------------------------- big file download
    def download_to_file(self, url: str, dest: str, *, chunk: int = 1 << 20, retries: Optional[int] = None,
                         timeout: Optional[float] = None, max_bytes: int = MAX_DOWNLOAD,
                         total_timeout: float = DOWNLOAD_TOTAL_TIMEOUT) -> HttpResult:
        """Stream ``url`` into ``dest`` (never into memory), resuming with Range after a broken connection.

        Used for ``all.zip`` dumps that can be hundreds of MB.  Returns an HttpResult with an empty body;
        ``ok`` means the complete file is on disk (size matched Content-Length when the server gave one)."""
        if TRANSPORT is not None:
            res = self.get(url, retries=retries, timeout=timeout, headers={"Accept-Encoding": "identity"})
            if res.ok and len(res.body) > max_bytes:
                return HttpResult(None, b"", {}, "download larger than %d bytes" % max_bytes, res.attempts, res.elapsed)
            if res.ok:
                with open(dest, "wb") as fh:
                    fh.write(res.body)
            return HttpResult(res.status, b"", res.headers, res.error, res.attempts, res.elapsed)
        max_retries = self.retries if retries is None else max(0, int(retries))
        tmo = self.timeout if timeout is None else float(timeout)
        t0 = time.monotonic()
        deadline = t0 + float(total_timeout)
        total: Optional[int] = None
        have = 0
        open(dest, "wb").close()
        last_error = ""
        status: Optional[int] = None
        attempts = 0
        for attempt in range(max_retries + 1):
            attempts = attempt + 1
            self._bump(requests=1)
            headers = {"User-Agent": self.user_agent, "Accept-Encoding": "identity"}
            if have:
                headers["Range"] = "bytes=%d-" % have
            try:
                req = urllib.request.Request(url, headers=headers)
                with _opener().open(req, timeout=tmo) as resp:
                    status = resp.status
                    cl = resp.headers.get("Content-Length")
                    if status == 200 and have:
                        have = 0                     # server ignored Range: restart
                        open(dest, "wb").close()
                    if cl and cl.isdigit() and total is None:
                        total = have + int(cl)
                    if total is not None and total > max_bytes:
                        self._bump(failures=1)
                        return HttpResult(None, b"", {}, "download larger than %d bytes" % max_bytes, attempts, time.monotonic() - t0)
                    with open(dest, "ab") as fh:
                        while True:
                            if time.monotonic() > deadline:
                                raise TimeoutError("download exceeded its total time limit")
                            block = resp.read(chunk)
                            if not block:
                                break
                            fh.write(block)
                            have += len(block)
                            self._bump(bytes_in=len(block))
                            if have > max_bytes:
                                self._bump(failures=1)
                                return HttpResult(None, b"", {}, "download larger than %d bytes" % max_bytes, attempts, time.monotonic() - t0)
                if total is None or have >= total:
                    return HttpResult(200, b"", {"content-length": str(have)}, None, attempts, time.monotonic() - t0)
                last_error = "short read %d/%d" % (have, total)
            except urllib.error.HTTPError as exc:
                status = exc.code
                if exc.code == 416 and total is not None and have >= total:
                    return HttpResult(200, b"", {"content-length": str(have)}, None, attempts, time.monotonic() - t0)
                last_error = "http %d" % exc.code
                if exc.code not in RETRY_STATUSES:
                    break
            except _NET_ERRORS as exc:
                status = None
                last_error = "%s: %s" % (type(exc).__name__, str(exc)[:160])
            if attempt < max_retries:
                self._bump(retries=1)
                self._sleep(self._rng() * min(self.max_backoff, self.backoff * (2 ** attempt)))
        self._bump(failures=1)
        with self._lock:
            self.stats["last_error"] = ("%s %s" % (last_error, url[:100]))[:240]
        return HttpResult(status, b"", {}, last_error, attempts, time.monotonic() - t0)


_DEFAULT: Optional[HttpClient] = None
_DEFAULT_LOCK = threading.Lock()


def default_client() -> HttpClient:
    """Process-wide shared client (connections are per-thread, so sharing is safe)."""
    global _DEFAULT
    with _DEFAULT_LOCK:
        if _DEFAULT is None:
            _DEFAULT = HttpClient(timeout=float(os.environ.get("BTS_SBOM_OSV_TIMEOUT", "30") or 30))
        return _DEFAULT
