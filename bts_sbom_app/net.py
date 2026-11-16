"""Minimal HTTP JSON helper (stdlib urllib) with retry/backoff and honest failure accounting.

Every outbound call in BTS-SBOM goes through here so one place can: set a User-Agent, back off on 429/5xx,
count requests/failures for the evidence file, and be monkey-patched by tests (no test touches the network).
"""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Dict, Optional

UA = "bts-sbom-app/0.1 (BTS-SBOM license and vulnerability analysis; contact via repository issues)"
STATS: Dict[str, Any] = {"requests": 0, "failures": 0, "last_error": ""}
_LOCK = threading.Lock()
# tests set this to a callable(url, headers, body) -> (status, parsed_json_or_None); None = real network
TRANSPORT = None


def reset_stats() -> None:
    with _LOCK:
        STATS.update(requests=0, failures=0, last_error="")


def _count(ok: bool, err: str = "") -> None:
    with _LOCK:
        STATS["requests"] += 1
        if not ok:
            STATS["failures"] += 1
            STATS["last_error"] = err[:200]


def http_text(url: str, *, timeout: float = 20.0, retries: int = 1, limit: int = 400_000) -> Optional[str]:
    """GET -> text (e.g. a Maven POM) or None on 404/failure. Reads at most ``limit`` bytes."""
    hdrs = {"User-Agent": UA, "Accept": "text/xml,text/plain,*/*"}
    if TRANSPORT is not None:
        status, parsed = TRANSPORT(url, hdrs, None)
        _count(status < 400 or status == 404, "http %s" % status)
        return parsed if (status < 400 and isinstance(parsed, str)) else None
    wait = 1.0
    last = ""
    for attempt in range(retries + 1):
        try:
            with urllib.request.urlopen(urllib.request.Request(url, headers=hdrs), timeout=timeout) as resp:
                raw = resp.read(limit)
            _count(True)
            return raw.decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                _count(True)
                return None
            last = "http %s" % exc.code
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = "%s: %s" % (type(exc).__name__, str(exc)[:120])
        if attempt < retries:
            time.sleep(wait)
            wait *= 2.5
    _count(False, last + " " + url[:80])
    return None


def http_json(url: str, *, body: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None,
              timeout: float = 20.0, retries: int = 2) -> Optional[Any]:
    """GET (or POST when ``body``) -> parsed JSON, or None on 404/failure. 404 is not counted as a failure."""
    hdrs = {"User-Agent": UA, "Accept": "application/json"}
    hdrs.update(headers or {})
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        hdrs["Content-Type"] = "application/json"
    if TRANSPORT is not None:
        status, parsed = TRANSPORT(url, hdrs, body)
        _count(status < 400 or status == 404, "http %s" % status)
        return parsed if status < 400 else None
    wait = 1.0
    last = ""
    for attempt in range(retries + 1):
        try:
            req = urllib.request.Request(url, data=data, headers=hdrs)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                raw = resp.read()
            _count(True)
            return json.loads(raw.decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            if exc.code == 404:
                _count(True)
                return None
            last = "http %s" % exc.code
            if exc.code in (429, 500, 502, 503, 504) and attempt < retries:
                time.sleep(wait)
                wait *= 2.5
                continue
            break
        except (urllib.error.URLError, TimeoutError, ValueError, OSError) as exc:
            last = "%s: %s" % (type(exc).__name__, str(exc)[:120])
            if attempt < retries:
                time.sleep(wait)
                wait *= 2.5
                continue
            break
    _count(False, last + " " + url[:80])
    return None
