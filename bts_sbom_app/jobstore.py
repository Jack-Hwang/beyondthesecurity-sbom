"""Persistent scan-job records under <evidence>/.jobs/<id>.json (schema bts-sbom.job.v1) - stdlib only.

A restart must not erase what happened: the in-memory ``st.jobs`` dict stays the fast cache, but every job also
gets one JSON record here so a new server state can answer "what happened to job X" and distinguish "a job that
ended in error" from "a job that never existed because the process restarted mid-scan" (an honest-contract gap).
Same conventions as the OSS Scanner screen's job repository (oss_api.py, read-only here): 10-hex ids, running
records are never pruned, finished records are pruned oldest-first. Never persisted: approval tokens, API keys,
request bodies - only the sanitized source, the patch/approved/offline/use_llm flags.
"""
from __future__ import annotations

import os
import re
import threading
import time
import urllib.parse
from typing import Any, Dict, List, Optional, Tuple

from .util import read_json, write_json

SCHEMA = "bts-sbom.job.v1"
ID_RE = re.compile(r"^[0-9a-f]{10}$")
CREDS_RE = re.compile(r"^(?:[A-Za-z][A-Za-z0-9+.-]*://)(?:[^/@:]+:[^/@]+@)?")


def sanitize_source(source: str) -> str:
    """Credentials (user:token@), query string and fragment never reach a stored record (max 300 chars)."""
    s = str(source or "")
    s = CREDS_RE.sub(lambda m: m.group(0).split("://")[0] + "://", s)
    parts = urllib.parse.urlsplit(s)
    if parts.scheme and parts.netloc:
        s = urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, "", ""))
    return s[:300]


class JobStore:
    """One JSON file per job. Atomic writes (util.write_json); a corrupt file is skipped and counted, never fatal."""

    def __init__(self, dir_path: str, *, max_jobs: int = 200, max_bytes: int = 65536, clock: Any = time.time):
        self.dir = dir_path
        self.max_jobs = max_jobs
        self.max_bytes = max_bytes
        self._clock = clock
        self._lock = threading.Lock()

    def _path(self, jid: str) -> str:
        return os.path.join(self.dir, jid + ".json")

    def _now(self) -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock()))

    def _records(self) -> List[Tuple[str, Dict[str, Any]]]:
        """(id, record) for every readable job file; corrupt files are counted in the return of recover()."""
        out: List[Tuple[str, Dict[str, Any]]] = []
        try:
            names = os.listdir(self.dir)
        except OSError:
            return out
        for fn in sorted(names):
            if fn.endswith(".json"):
                d = read_json(self._path(fn[:-5]), None)
                if isinstance(d, dict) and d.get("id"):
                    out.append((str(d["id"]), d))
        return out

    def create(self, source: str, idempotency_key: str = "", id_gen: Any = None) -> Tuple[Dict[str, Any], bool]:
        """A fresh record (running) for a new job. Returns (record, reused) - reused is False: reuse is the server's decision."""
        jid = (id_gen() if id_gen else "%010x" % int.from_bytes(os.urandom(5), "big"))
        rec: Dict[str, Any] = {"schema": SCHEMA, "id": jid, "state": "running", "source": sanitize_source(source),
                               "idempotency_key": idempotency_key or "", "created_at": self._now(), "updated_at": self._now(),
                               "steps": [], "name": "", "error": "", "metrics": {}, "artifacts": {}, "stage_errors": {},
                               "work_copy": "", "interrupted_reason": ""}
        self._write(rec)
        return rec, False

    def _write(self, rec: Dict[str, Any]) -> None:
        """Trim oversized metrics/stage_errors rather than exceed max_bytes; the record then says it was truncated."""
        os.makedirs(self.dir, exist_ok=True)
        if self.max_bytes and len(json_dumps(rec)) > self.max_bytes:
            rec = dict(rec)
            rec["metrics"] = {"truncated": True}
            rec["stage_errors"] = {"truncated": True}
        write_json(self._path(rec["id"]), rec)

    def update(self, jid: str, **fields: Any) -> Optional[Dict[str, Any]]:
        rec = self.get(jid)
        if rec is None:
            return None
        rec.update(fields)
        rec["updated_at"] = self._now()
        if rec.get("state") in ("done", "error", "interrupted") and not rec.get("finished_at"):
            rec["finished_at"] = rec["updated_at"]
        self._write(rec)
        return rec

    def get(self, jid: str) -> Optional[Dict[str, Any]]:
        """A record or None. An id that is not 10 lowercase hex characters never opens a file (path-escape guard)."""
        if not ID_RE.match(str(jid or "")):
            return None
        d = read_json(self._path(jid), None)
        return d if isinstance(d, dict) and d.get("id") == jid else None

    def list(self, limit: int = 50) -> List[Dict[str, Any]]:
        rows = sorted(self._records(), key=lambda kv: str(kv[1].get("created_at") or ""), reverse=True)
        return [r for _i, r in rows[:max(0, limit)]]

    def find_by_key(self, idempotency_key: str, max_age_s: float = 86400.0) -> Optional[Dict[str, Any]]:
        """The most recent record carrying this idempotency key within the last 24 hours."""
        if not idempotency_key:
            return None
        cutoff = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(self._clock() - max_age_s))
        rows = [r for _i, r in self._records() if r.get("idempotency_key") == idempotency_key and str(r.get("created_at") or "") >= cutoff]
        return max(rows, key=lambda r: str(r.get("created_at") or ""), default=None)

    def recover(self) -> Dict[str, int]:
        """Called once at startup: queued/running records become interrupted(server_restart); corrupt files are counted."""
        interrupted = 0
        corrupt = 0
        try:
            names = os.listdir(self.dir)
        except OSError:
            names = []
        for fn in names:
            if not fn.endswith(".json"):
                continue
            jid = fn[:-5]
            d = read_json(self._path(jid), None)
            if not isinstance(d, dict) or d.get("id") != jid:
                corrupt += 1
                continue
            if d.get("state") in ("queued", "running"):
                d["state"] = "interrupted"
                d["interrupted_reason"] = "server_restart"
                d["finished_at"] = self._now()
                self._write(d)
                interrupted += 1
        return {"interrupted": interrupted, "corrupt": corrupt}

    def prune(self) -> int:
        """Keep max_jobs records: finished ones are deleted oldest-first; running records are never deleted."""
        rows = sorted(self._records(), key=lambda kv: str(kv[1].get("created_at") or ""))
        finished = [(i, r) for i, r in rows if r.get("state") not in ("running", "queued")]
        excess = len(rows) - self.max_jobs
        deleted = 0
        for jid, _r in finished:
            if excess <= 0:
                break
            try:
                os.remove(self._path(jid))
                deleted += 1
            except OSError:
                pass
            excess -= 1
        return deleted


def json_dumps(obj: Any) -> str:
    import json as _json
    return _json.dumps(obj, ensure_ascii=False, default=str)
