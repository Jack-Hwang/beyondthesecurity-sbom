"""JSON API behind the "Arch Intel" screen: license verdict + AI architecture deep-dive of one open-source source
tree (a local folder or a git URL), exposed to ``web/arch_intel.js``. The analysis itself lives in
``arch_intel.py``; this module owns jobs, progress events and result retrieval.

POST /api/arch/scan            {source, ref?, use_llm?, lang?, distribution?}  -> {job}   (background thread)
GET  /api/arch/jobs/<id>       -> state, stage, overview (license + totals + AI source)
POST /api/arch/jobs/<id>/cancel
GET  /api/arch/jobs/<id>/events -> text/event-stream (bts-sbom.events.v1; served via :func:`serve_events`)
GET  /api/arch/result/<id>     -> the full result document (diagrams, snippets, notice checklist)
GET  /api/arch/report/<id>?format=md|json  -> download
GET  /api/arch/history         -> one row per finished run

Safety: results are written only below <evidence>/archintel/<job id>/ (the caller never chooses a write path); job
ids are validated hex; the analysed tree is prepared by workspace.prepare (hooks off, no submodules, ``ext::``
refused) and never executed; every request must carry a Host header that is the service's own address and a
mutating request from another web origin is refused - the same checks as the OSS screen (imported from ``oss_api``);
at most MAX_RUNNING analyses run at once and MAX_JOBS finished jobs are kept.
"""
from __future__ import annotations

import os
import re
import shutil
import tempfile
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import events
from .oss_api import _host_allowed, _same_origin

MAX_RUNNING = 1
MAX_JOBS = 60
_ID = re.compile(r"^[0-9a-f]{10}$")
_LANGS = ("ko", "en")
_DISTRIBUTIONS = ("binary", "saas", "internal")
# Seconds a GET /api/arch/jobs/<id>/events connection waits for a new event before writing a heartbeat comment
# line. Module-level (read fresh on every wait, never captured as a default argument) so tests can shrink it.
EVENTS_HEARTBEAT_SECONDS = 15.0
_lock = threading.Lock()

Response = Tuple[int, Any, str, Dict[str, str]]


def _err(code: int, msg: str) -> Response:
    return code, {"error": msg}, "application/json", {}


def _ok(obj: Any, code: int = 200) -> Response:
    return code, obj, "application/json", {}


class _Jobs:
    def __init__(self, evidence: str) -> None:
        self.base = os.path.join(evidence, "archintel")
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.cancel: Dict[str, threading.Event] = {}
        self.buses: Dict[str, events.EventBus] = {}

    def dir(self, jid: str) -> str:
        return os.path.join(self.base, jid)


def _jobs(st: Any) -> _Jobs:
    j = getattr(st, "arch_jobs", None)
    if j is None:
        with _lock:
            j = getattr(st, "arch_jobs", None)
            if j is None:
                j = st.arch_jobs = _Jobs(st.evidence)
    return j


def _load(j: _Jobs, jid: str) -> Optional[Dict[str, Any]]:
    from .arch_intel import load_result
    return load_result(j.dir(jid)) if _ID.match(jid or "") else None


def _overview(doc: Dict[str, Any]) -> Dict[str, Any]:
    lic = doc.get("license") or {}
    st = doc.get("structure") or {}
    return {"project_license": lic.get("project_license"), "category": lic.get("category"),
            "files": st.get("files_count"), "loc": st.get("total_loc"),
            "entry_points": len(st.get("entry_points") or []), "ai_source": doc.get("ai_source")}


def _evict(j: _Jobs) -> None:
    """Keep the in-memory tables bounded: finished jobs beyond MAX_JOBS go, oldest first; running jobs and their
    open buses are never dropped."""
    with _lock:
        finished = [k for k, v in j.jobs.items() if v.get("state") != "running"]
        for k in list(j.cancel):
            if k not in j.jobs or k in finished:
                j.cancel.pop(k, None)
        for k in [k for k, b in j.buses.items() if b.closed and k in finished][:]:
            if len(j.buses) > MAX_JOBS:
                j.buses.pop(k, None)
        if len(finished) > MAX_JOBS:
            finished.sort(key=lambda k: str(j.jobs[k].get("finished") or j.jobs[k].get("started") or ""))
            for k in finished[:len(finished) - MAX_JOBS]:
                j.jobs.pop(k, None)


# ------------------------------------------------------------------------------------------------------- scan
def _run_job(st: Any, jid: str, source: str, ref: str, use_llm: bool, lang: str, distribution: str) -> None:
    from .arch_intel import run as ai_run
    j = _jobs(st)
    job = j.jobs[jid]
    bus = j.buses[jid]
    wdir = tempfile.mkdtemp(prefix="bts_arch_job_")

    def progress(etype: str, **fields: Any) -> None:
        try:
            bus.publish(etype, **fields)
        except Exception:                                             # noqa: BLE001 - telemetry must never kill the run
            pass
        if etype == "step_start" and fields.get("name"):
            job["stage"] = str(fields["name"])

    try:
        bus.publish("job_start", source=source)
        client = st.client if getattr(st.client, "available", False) else None
        res = ai_run(source, work_root=wdir, out_dir=j.dir(jid), jid=jid, client=client, use_llm=use_llm,
                     lang=lang, distribution=distribution, ref=ref or None, cache_dir=os.path.join(st.evidence, "cache"),
                     progress=progress, cancel=j.cancel.get(jid))
        if res.get("error") == "cancelled":
            job.update(state="cancelled", stage="cancelled", error="cancelled")
            bus.publish("error", error_type="cancelled", severity="low", retryable=True, recovery_hint="re-run the analysis")
        elif res.get("error"):
            job.update(state="error", stage="error", error=str(res["error"])[:300])
            bus.publish("error", error_type="analysis_error", severity="high", retryable=False,
                        recovery_hint=str(res["error"])[:200])
        else:
            ov = _overview(res)
            job.update(state="done", stage="done", overview=ov)
            bus.publish("final", state="done")
    except Exception as exc:                                          # noqa: BLE001
        job.update(state="error", stage="error", error="%s: %s" % (type(exc).__name__, str(exc)[:200]))
        try:
            bus.publish("error", error_type=type(exc).__name__, severity="high", retryable=False,
                        recovery_hint=str(exc)[:200])
        except Exception:                                             # noqa: BLE001
            pass
    finally:
        job["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        shutil.rmtree(wdir, ignore_errors=True)                       # the work copy inside it was removed by ai_run
        try:
            bus.close()                                               # safety net: idempotent if final/error closed it
        except Exception:                                             # noqa: BLE001
            pass
        _evict(j)


def _start(st: Any, b: Dict[str, Any]) -> Response:
    source = str(b.get("source") or "").strip()
    if not source or len(source) > 2000:
        return _err(400, "source required (a local folder or a git URL / owner-repo shorthand)")
    lang = str(b.get("lang") or "ko")
    if lang not in _LANGS:
        return _err(400, "lang must be one of %s" % ", ".join(_LANGS))
    distribution = str(b.get("distribution") or "binary")
    if distribution not in _DISTRIBUTIONS:
        return _err(400, "distribution must be one of %s" % ", ".join(_DISTRIBUTIONS))
    ref = str(b.get("ref") or "")[:200]
    j = _jobs(st)
    with _lock:
        if sum(1 for x in j.jobs.values() if x.get("state") == "running") >= MAX_RUNNING:
            return _err(429, "too many analyses are running (limit %d); wait for one to finish" % MAX_RUNNING)
        jid = uuid.uuid4().hex[:10]
        j.jobs[jid] = {"id": jid, "state": "running", "stage": "queued", "source": source,
                       "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
        j.cancel[jid] = threading.Event()
        bus = events.EventBus(jid)
        j.buses[jid] = bus                                            # registered before the thread starts: an
                                                                      # immediate GET .../events never 404s
    threading.Thread(target=_run_job, daemon=True,
                     args=(st, jid, source, ref, b.get("use_llm") is not False, lang, distribution)).start()
    return _ok({"job": jid}, 202)


# -------------------------------------------------------------------------------------------------------- route
def route(method: str, path: str, query: Dict[str, List[str]], body: Dict[str, Any], headers: Any, st: Any,
          bind: Optional[Tuple[Any, ...]] = None) -> Optional[Response]:
    """Return a response for /api/arch/... or None when the path is not ours. ``bind`` = (host, port)."""
    if not path.startswith("/api/arch/"):
        return None
    j = _jobs(st)
    rest = path[len("/api/arch/"):].strip("/")
    parts = rest.split("/")
    if headers is not None and not _host_allowed(headers.get("Host", "") or "", bind):
        return _err(403, "unexpected Host header (the service answers only at its own address)")
    if method == "POST" and not _same_origin(headers, bind):
        return _err(403, "cross-origin request refused")
    if method == "POST":
        if rest == "scan":
            return _start(st, body)
        if len(parts) == 3 and parts[0] == "jobs" and parts[2] == "cancel" and _ID.match(parts[1]):
            ev = j.cancel.get(parts[1])
            if ev is None:
                known = j.jobs.get(parts[1])
                if known is None and not _load(j, parts[1]):
                    return _err(404, "unknown job")
                return _ok({"ok": True, "state": (known or {}).get("state", "done"), "note": "already finished"})
            ev.set()
            return _ok({"ok": True})
        return _err(404, "not found")
    if rest == "history":
        return _history(j)
    if len(parts) == 2 and parts[0] in ("jobs", "result", "report") and _ID.match(parts[1] or ""):
        jid = parts[1]
        if parts[0] == "jobs":
            job = j.jobs.get(jid)
            if job is None:                                           # a finished run from an earlier server run
                doc = _load(j, jid)
                if not doc:
                    return _err(404, "unknown job")
                job = {"id": jid, "state": "done", "stage": "done", "source": (doc.get("meta") or {}).get("source"),
                       "overview": _overview(doc)}
            return _ok(job)
        doc = _load(j, jid)
        if doc is None:
            return _err(404, "unknown or unfinished run")
        if parts[0] == "result":
            return _ok(doc)
        fmt = (query.get("format") or ["md"])[0]
        if fmt not in ("md", "json"):
            return _err(400, "format must be md or json")
        if fmt == "json":
            import json as _json
            return 200, _json.dumps(doc, ensure_ascii=False, sort_keys=True, default=str).encode("utf-8"), "application/json", \
                {"Content-Disposition": 'attachment; filename="arch_intel_%s.json"' % jid}
        from .arch_intel import load_report
        rep = load_report(j.dir(jid))
        if rep is None:
            from .arch_intel import report_md
            rep = report_md(doc)
        return 200, rep.encode("utf-8"), "text/markdown", {"Content-Disposition": 'attachment; filename="arch_intel_%s.md"' % jid}
    return _err(404, "not found")


def _history(j: _Jobs) -> Response:
    rows = []
    try:
        names = [n for n in os.listdir(j.base) if _ID.match(n)]
    except OSError:
        names = []
    for n in names:
        doc = _load(j, n)
        if doc:
            m = doc.get("meta") or {}
            rows.append({"id": n, "source": m.get("source"), "finished": m.get("finished"),
                         "lang": m.get("lang"), "distribution": m.get("distribution"), "overview": _overview(doc)})
    rows.sort(key=lambda r: r.get("finished") or "", reverse=True)
    return _ok({"history": rows[:MAX_JOBS]})


# ------------------------------------------------------------------------------------------------- events (SSE)
def serve_events(st: Any, handler: Any, jid: str, q: Dict[str, List[str]]) -> None:
    """GET /api/arch/jobs/<jid>/events as text/event-stream. Unknown job -> plain 404 JSON (never a stream).
    Resumes after ``Last-Event-ID`` (header takes precedence over ``?after=``); heartbeats keep an idle connection
    open; the stream ends for good right after a final/error event. Same contract as server._serve_events."""
    j = _jobs(st)
    bus = j.buses.get(jid)
    if bus is None:
        return handler._send(404, {"error": "unknown job"})
    try:
        after = int(handler.headers.get("Last-Event-ID") or (q.get("after") or ["0"])[0])
    except (TypeError, ValueError):
        after = 0
    try:
        bus.subscribe()
    except events.TooManySubscribers:
        return handler._send(503, {"error": "too many event subscribers for this job (max %d)" % events.EventBus.MAX_SUBSCRIBERS})
    try:
        handler.send_response(200)
        handler.send_header("Content-Type", "text/event-stream; charset=utf-8")
        handler.send_header("Cache-Control", "no-store")
        handler.send_header("X-Content-Type-Options", "nosniff")
        handler.end_headers()
        for item in bus.iter_events(after_seq=after, timeout=EVENTS_HEARTBEAT_SECONDS):
            chunk = b": heartbeat\n\n" if item is None else events.format_sse(item).encode("utf-8")
            handler.wfile.write(chunk)
            handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass                                               # the reader went away mid-stream: nothing left to do
    finally:
        bus.unsubscribe()
