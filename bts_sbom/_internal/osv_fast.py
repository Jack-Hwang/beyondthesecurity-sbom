"""Fast online OSV lookups: ``querybatch`` for the matching, a revision-aware record cache for the details.

The previous online path did one ``POST /v1/query`` per component (full records back, one TLS handshake each).
For a 300-component lockfile that is 300 round trips.  This module answers the same question with:

  1. ``POST /v1/querybatch`` - up to 1000 components per request.  The API returns only ``{id, modified}`` per
     advisory, and pages (``next_page_token``) when one query has >1000 hits or the batch >3000 hits - both are
     followed here (the older code in this repo never did, silently truncating).
  2. A record cache keyed by advisory id and validated by ``modified``: a record is re-fetched only when OSV says
     it changed.  Records live in memory and in the sqlite mirror (``osv_mirror``), so the SECOND scan of a project
     is one batch request and zero detail requests.
  3. Cache misses are resolved in whichever way costs fewer round trips (measured against the real API: with a
     ~180 ms round trip, request COUNT is the cost):
       * a component with at most ``bulk_threshold`` missing advisories -> ``GET /v1/vulns/{id}`` per advisory,
         each unique advisory once even if it hits many components;
       * a component with more -> ONE ``POST /v1/query`` that returns all its full records inline.
     Both run in parallel over keep-alive connections.  (An earlier version fetched every advisory with its own
     GET and was 2.8x SLOWER than per-component queries on a cold cache for an old, vulnerability-dense lockfile:
     1,671 requests instead of 94.)

Honesty: a component is answered (``Outcome.ok``) only if the batch answered AND every advisory id it returned
was resolved to a full record.  Anything else is ``ok=False`` with a reason, so the caller can fall back to the
single-query path - an unresolved advisory is never dropped and read as "no vulnerability".
"""
from __future__ import annotations

import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from bts_sbom._internal import osv_http
from bts_sbom._internal.osv_mirror import OsvMirror, norm_ts

Key = Tuple[str, str, str]          # (OSV ecosystem, package name, exact version)
DEFAULT_WORKERS = 24                # network-latency bound, not CPU bound; the API documents no rate limit


def api_base() -> str:
    """https://api.osv.dev/v1 (override with BTS_SBOM_OSV_API_BASE, or the legacy BTS_SBOM_OSV_API_URL)."""
    env = os.environ.get("BTS_SBOM_OSV_API_BASE")
    if env:
        return env.rstrip("/")
    legacy = os.environ.get("BTS_SBOM_OSV_API_URL")
    if legacy:
        for tail in ("/querybatch", "/query"):
            if legacy.rstrip("/").endswith(tail):
                return legacy.rstrip("/")[: -len(tail)]
        return legacy.rstrip("/")
    return "https://api.osv.dev/v1"


@dataclass
class Outcome:
    ok: bool
    vulns: List[Dict[str, Any]] = field(default_factory=list)
    error: Optional[str] = None


def _query_obj(key: Key, token: Optional[str] = None) -> Dict[str, Any]:
    eco, name, version = key
    q: Dict[str, Any] = {"package": {"name": name, "ecosystem": eco}, "version": version}
    if token:
        q["page_token"] = token
    return q


class FastOsv:
    def __init__(self, *, http: Optional[osv_http.HttpClient] = None, mirror: Optional[OsvMirror] = None,
                 use_mirror: bool = True, base: Optional[str] = None, chunk: int = 1000,
                 workers: Optional[int] = None, max_pages: int = 100, bulk_threshold: int = 3) -> None:
        self.http = http or osv_http.default_client()
        self.mirror = mirror if mirror is not None else (OsvMirror(http=self.http) if use_mirror else None)
        self.base = (base or api_base()).rstrip("/")
        self.chunk = max(1, min(int(chunk), 1000))
        if workers is None:
            try:
                workers = int(os.environ.get("BTS_SBOM_OSV_WORKERS", DEFAULT_WORKERS))
            except ValueError:
                workers = DEFAULT_WORKERS
        self.workers = max(1, min(int(workers), 64))
        self.max_pages = max(1, int(max_pages))
        self.bulk_threshold = max(0, int(bulk_threshold))
        self._mem: Dict[str, Tuple[str, Dict[str, Any]]] = {}
        self._lock = threading.Lock()
        self._pool: Optional[ThreadPoolExecutor] = None
        self.last_stats: Dict[str, Any] = {}

    # ------------------------------------------------------------------ plumbing
    def _executor(self) -> ThreadPoolExecutor:
        with self._lock:
            if self._pool is None:
                self._pool = ThreadPoolExecutor(max_workers=self.workers, thread_name_prefix="osvfast")
            return self._pool

    def close(self) -> None:
        with self._lock:
            pool, self._pool = self._pool, None
        if pool is not None:
            pool.shutdown(wait=True)

    def __enter__(self) -> "FastOsv":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()

    # ------------------------------------------------------------------- batch
    def _post_batch(self, keys: Sequence[Key], tokens: Dict[Key, str]) -> Tuple[Optional[List[Dict[str, Any]]], Optional[str]]:
        payload = {"queries": [_query_obj(k, tokens.get(k)) for k in keys]}
        res = self.http.post_json(self.base + "/querybatch", payload, timeout=60)
        if not res.ok:
            if res.status is None or res.status >= 500 or res.status == 429:
                # no usable answer from OSV at all (down / overloaded after every retry): the caller treats this as
                # "unreachable" and does not repeat the same doomed request once per component
                return None, "unreachable: %s" % (res.error or "no response")
            return None, res.error or ("http %s" % res.status)
        doc = res.json()
        results = doc.get("results") if isinstance(doc, dict) else None
        if not isinstance(results, list) or len(results) != len(keys):
            return None, "malformed querybatch response (%s results for %d queries)" % (
                len(results) if isinstance(results, list) else "no", len(keys))
        return results, None

    def _batch_ids(self, keys: Sequence[Key], depth: int = 0) -> Dict[Key, Tuple[Optional[Dict[str, str]], Optional[str]]]:
        """{key: ({advisory id: modified}, None) | (None, error)} - follows next_page_token; bisects a rejected
        batch so one malformed query cannot take down its 999 neighbours."""
        out: Dict[Key, Tuple[Optional[Dict[str, str]], Optional[str]]] = {}
        acc: Dict[Key, Dict[str, str]] = {k: {} for k in keys}
        pending: List[Key] = list(keys)
        tokens: Dict[Key, str] = {}
        pages = 0
        while pending:
            pages += 1
            if pages > self.max_pages:
                for k in pending:
                    out[k] = (None, "querybatch pagination exceeded %d pages" % self.max_pages)
                break
            results, err = self._post_batch(pending, tokens)
            if results is None:
                if len(pending) > 1 and err and ("http 400" in err or "malformed" in err) and depth < 12:
                    mid = len(pending) // 2
                    for half in (pending[:mid], pending[mid:]):
                        sub = self._batch_ids(half, depth + 1)
                        for k, v in sub.items():
                            # keep ids already gathered from earlier pages
                            if v[0] is not None:
                                v[0].update(acc.get(k, {}))
                            out[k] = v
                else:
                    for k in pending:
                        out[k] = (None, err)
                break
            nxt: List[Key] = []
            new_tokens: Dict[Key, str] = {}
            for k, r in zip(pending, results):
                r = r or {}
                for v in r.get("vulns") or []:
                    vid = (v or {}).get("id")
                    if vid:
                        acc[k][vid] = norm_ts((v or {}).get("modified")) or ""
                tok = r.get("next_page_token")
                if tok:
                    nxt.append(k)
                    new_tokens[k] = tok
            pending, tokens = nxt, new_tokens
        for k in keys:
            if k not in out:
                out[k] = (acc[k], None)
        return out

    # ----------------------------------------------------------------- records
    def _cached(self, wanted: Dict[str, str]) -> Dict[str, Dict[str, Any]]:
        """Records we hold that are at least as new as the batch said: {id: record}."""
        have: Dict[str, Dict[str, Any]] = {}
        probe: List[str] = []
        with self._lock:
            for vid, mod in wanted.items():
                hit = self._mem.get(vid)
                if hit and mod and hit[0] >= mod:       # no usable `modified` from OSV = a cache we cannot validate = a miss
                    have[vid] = hit[1]
                else:
                    probe.append(vid)
        if probe and self.mirror is not None:
            try:
                for vid, (mod, rec) in self.mirror.get_records(probe).items():
                    if wanted.get(vid) and mod >= wanted[vid]:
                        have[vid] = rec
                        with self._lock:
                            self._mem[vid] = (mod, rec)
            except Exception:
                pass                                   # a broken cache is a miss, never an error
        return have

    def _fetch_one(self, vid: str) -> Tuple[str, Optional[Dict[str, Any]], Optional[str]]:
        import urllib.parse
        res = self.http.get("%s/vulns/%s" % (self.base, urllib.parse.quote(vid, safe="")), timeout=30)
        if not res.ok:
            return vid, None, ("not found" if res.not_found else (res.error or "http %s" % res.status))
        rec = res.json()
        if not isinstance(rec, dict) or rec.get("id") != vid:
            return vid, None, "bad record body"
        return vid, rec, None

    def _query_full(self, key: Key) -> Tuple[Key, Optional[List[Dict[str, Any]]], Optional[str]]:
        """ONE ``POST /v1/query`` (following next_page_token): every full record that affects ``key``."""
        recs: List[Dict[str, Any]] = []
        token: Optional[str] = None
        for _page in range(self.max_pages):
            res = self.http.post_json(self.base + "/query", _query_obj(key, token), timeout=60)
            if not res.ok:
                return key, None, res.error or ("http %s" % res.status)
            doc = res.json()
            if not isinstance(doc, dict):
                return key, None, "bad query body"
            recs.extend(v for v in (doc.get("vulns") or []) if isinstance(v, dict) and v.get("id"))
            token = doc.get("next_page_token")
            if not token:
                return key, recs, None
        return key, None, "query pagination exceeded %d pages" % self.max_pages

    # ------------------------------------------------------------------- public
    def query_many(self, keys: Iterable[Key]) -> Dict[Key, Outcome]:
        t0 = time.monotonic()
        keys = list(dict.fromkeys(keys))
        stats: Dict[str, Any] = {"components": len(keys), "batches": 0, "advisories": 0, "cache_hits": 0,
                                 "fetched": 0, "fetch_failed": 0, "batch_failed": 0}
        outcomes: Dict[Key, Outcome] = {}
        if not keys:
            self.last_stats = stats
            return outcomes
        chunks = [keys[i:i + self.chunk] for i in range(0, len(keys), self.chunk)]
        stats["batches"] = len(chunks)
        if len(chunks) > 1:
            parts = list(self._executor().map(self._batch_ids, chunks))
        else:
            parts = [self._batch_ids(chunks[0])]
        ids_by_key: Dict[Key, Dict[str, str]] = {}
        for part in parts:
            for k, (ids, err) in part.items():
                if ids is None:
                    outcomes[k] = Outcome(False, [], err or "querybatch failed")
                    stats["batch_failed"] += 1
                else:
                    ids_by_key[k] = ids
        wanted: Dict[str, str] = {}
        for ids in ids_by_key.values():
            for vid, mod in ids.items():
                if mod > wanted.get(vid, ""):
                    wanted[vid] = mod
                else:
                    wanted.setdefault(vid, mod)
        stats["advisories"] = len(wanted)
        records = self._cached(wanted)
        stats["cache_hits"] = len(records)
        errors: Dict[str, str] = {}
        fetched: List[Dict[str, Any]] = []
        # wave 1: components with many missing advisories -> one /v1/query each (fewest round trips)
        bulk_keys = [k for k, ids in ids_by_key.items()
                     if sum(1 for v in ids if v not in records) > self.bulk_threshold]
        stats["bulk_queries"] = len(bulk_keys)
        stats["bulk_failed"] = 0
        if bulk_keys:
            for key, recs, err in self._executor().map(self._query_full, bulk_keys):
                if recs is None:
                    stats["bulk_failed"] += 1               # falls through to per-advisory GETs below
                    continue
                for rec in recs:
                    if rec["id"] not in records:
                        records[rec["id"]] = rec
                        fetched.append(rec)
        # wave 2: whatever is still missing, one GET per unique advisory
        missing = [vid for vid in wanted if vid not in records]
        stats["detail_gets"] = len(missing)
        if missing:
            for vid, rec, err in self._executor().map(self._fetch_one, missing):
                if rec is not None:
                    records[vid] = rec
                    fetched.append(rec)
                else:
                    errors[vid] = err or "fetch failed"
        stats["fetched"], stats["fetch_failed"] = len(fetched), len(errors)
        if fetched:
            with self._lock:
                for rec in fetched:
                    self._mem[rec["id"]] = (norm_ts(rec.get("modified")) or "", rec)
            if self.mirror is not None:
                try:
                    self.mirror.put_records(fetched)
                except Exception:
                    pass                                   # the cache is best-effort; the answer is not affected
        for k, ids in ids_by_key.items():
            lost = [vid for vid in ids if vid not in records]
            if lost:
                outcomes[k] = Outcome(False, [], "advisory record(s) unavailable: %s" % ", ".join(
                    "%s (%s)" % (v, errors.get(v, "missing")) for v in lost[:5]))
            else:
                outcomes[k] = Outcome(True, [records[v] for v in ids])
        stats["elapsed_s"] = round(time.monotonic() - t0, 3)
        stats["http"] = self.http.snapshot()
        self.last_stats = stats
        return outcomes
