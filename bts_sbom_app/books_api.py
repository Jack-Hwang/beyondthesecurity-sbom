"""JSON API behind the Book KB screen: the local architecture-book knowledge base (``books.py``), exposed to
``web/bts_books.js``.

GET  /api/books            -> registry summary (totals + one row per book, each with its explicit status)
GET  /api/books/<slug>     -> chapter/section outline of one indexed book (headings + sizes, never the full text)
GET  /api/books/search?q=  -> top-k passages over the serve-time book index (book, source id, snippet, scores)
POST /api/books/ingest     -> {src: local folder} builds/refreshes the knowledge base as a background job
                              (state on /api/jobs/<id>, events on /api/jobs/<id>/events - the same wire the
                              /api/scan jobs use)

Safety: results are read-only except the ingest job, which writes only below <evidence>/books/ (the caller never
chooses a write path); the ingested folder is only ever read; every request must carry a Host header that is the
service's own address and a mutating request from another web origin is refused - the same checks as the Arch
Intel screen (imported from ``oss_api``); at most one ingest runs at a time and finished ingest jobs live in the
same bounded ``st.jobs`` table as scan jobs.
"""
from __future__ import annotations

import os
import re
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

from . import books, events
from .oss_api import _host_allowed, _same_origin
from .util import clip

MAX_RUNNING_INGEST = 1
_BUSES_KEEP = 64                     # mirrors server.MAX_BUSES without importing server (import cycle)
_MAX_Q = 300
_MAX_K = 20

Response = Tuple[int, Any, str, Dict[str, str]]


def _bdir(st: Any) -> str:
    """The books folder. A State has books_dir() (root-based, see server.State.books_dir); a test double may
    just point ``evidence`` at a temp folder."""
    fn = getattr(st, "books_dir", None)
    return fn() if callable(fn) else books.books_dir(st.evidence)


def _err(code: int, msg: str) -> Response:
    return code, {"error": msg}, "application/json", {}


def _ok(obj: Any, code: int = 200) -> Response:
    return code, obj, "application/json", {}


# ------------------------------------------------------------------------------------------------------ reads
def _row(b: Dict[str, Any]) -> Dict[str, Any]:
    keys = ("slug", "title", "format", "status", "sections", "chars", "pages", "junk_ratio", "reason", "duplicate_of")
    return {k: b.get(k) for k in keys if b.get(k) is not None}


def _registry(st: Any) -> Response:
    reg = books.load_registry(_bdir(st))
    if reg is None:
        return _ok({"built": False, "hint": "POST /api/books/ingest {src: local folder} or "
                                            "bts-sbom-app books --src <folder> (artifacts under evidence/books/)"})
    return _ok({"built": True, "built_at": reg.get("built_at"), "src": reg.get("src"),
                "pdftotext": reg.get("pdftotext"), "totals": reg.get("totals"),
                "books": [_row(b) for b in reg.get("books", [])]})


def _search(st: Any, q: Dict[str, List[str]]) -> Response:
    query = str((q.get("q") or [""])[0]).strip()
    if not query or len(query) > _MAX_Q:
        return _err(400, "q required (1..%d chars)" % _MAX_Q)
    try:
        k = int((q.get("k") or ["5"])[0])
    except ValueError:
        return _err(400, "k must be an integer")
    k = max(1, min(k, _MAX_K))
    idx = st.books_index()
    if not getattr(idx, "chunks", None):
        return _ok({"found": False, "reason": "the book knowledge base is empty - ingest a folder first (POST /api/books/ingest)"})
    t0 = time.perf_counter()
    res = idx.search(query, k=k)
    out: List[Dict[str, Any]] = []
    for r in res.get("results", [])[:k]:
        ch = r["chunk"]
        m = ch.get("meta") or {}
        out.append({"source": ch["source"], "heading": ch.get("heading") or "", "book": m.get("book") or "",
                    "format": m.get("format") or "", "snippet": clip(re.sub(r"\s+", " ", ch["text"]), 240),
                    "rrf": r["rrf"], "bm25": r["bm25"]})
    return _ok({"found": bool(res.get("found")), "reason": res.get("reason", ""),
                "results": out, "took_ms": round((time.perf_counter() - t0) * 1000, 2)})


# ------------------------------------------------------------------------------------------------ ingest job
def _running_ingests(st: Any) -> int:
    return sum(1 for v in getattr(st, "jobs", {}).values() if v.get("kind") == "books" and v.get("state") == "running")


def _run_job(st: Any, jid: str, src: str) -> None:
    job, bus = st.jobs[jid], st.buses[jid]

    def progress(ev: Dict[str, Any]) -> None:
        if ev.get("step") == "file":
            job["stage"] = str(ev.get("book") or "extract")
            bus.publish("step_start", name="extract", book=str(ev.get("book") or ""))

    try:
        bus.publish("job_start", source=src)
        reg = books.build(src, _bdir(st), progress=progress)
        job.update(state="done", stage="done", totals=reg.get("totals"), books=len(reg.get("books", [])))
        bus.publish("final", state="done", totals=reg.get("totals"))
    except Exception as exc:                                          # noqa: BLE001
        job.update(state="error", stage="error", error="%s: %s" % (type(exc).__name__, str(exc)[:200]))
        try:
            bus.publish("error", error_type=type(exc).__name__, severity="high", retryable=False,
                        recovery_hint=str(exc)[:200])
        except Exception:                                             # noqa: BLE001
            pass
    finally:
        job["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        try:
            bus.close()
        except Exception:                                             # noqa: BLE001
            pass
        reset = getattr(st, "reset_books_cache", None)
        if reset:
            reset()                                                   # the next search rebuilds from the new registry


def _ingest(st: Any, b: Dict[str, Any]) -> Response:
    src = str(b.get("src") or "").strip()
    if not src or len(src) > 1000:
        return _err(400, "src required (a local folder that exists on this machine)")
    if not os.path.isdir(src):
        return _err(400, "src must be an existing local folder (books are read, never fetched over the network)")
    if _running_ingests(st) >= MAX_RUNNING_INGEST:
        return _err(429, "an ingest is already running; wait for it to finish")
    jid = uuid.uuid4().hex[:10]
    st.jobs[jid] = {"id": jid, "state": "running", "stage": "queued", "kind": "books", "source": src,
                    "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
    bus = events.EventBus(jid)
    st.buses[jid] = bus
    closed = [k for k, v in st.buses.items() if v.closed and k != jid]
    for k in closed[:max(0, len(st.buses) - _BUSES_KEEP)]:            # the oldest CLOSED buses go first (server.MAX_BUSES)
        st.buses.pop(k, None)
    import threading
    threading.Thread(target=_run_job, daemon=True, args=(st, jid, src)).start()
    return _ok({"job": jid}, 202)


# ------------------------------------------------------------------------------------------------------ route
def route(method: str, path: str, q: Dict[str, List[str]], body: Dict[str, Any], headers: Any, st: Any,
          bind: Optional[Tuple[Any, ...]] = None) -> Optional[Response]:
    """Return a response for /api/books/... or None when the path is not ours. ``bind`` = (host, port)."""
    if not path.startswith("/api/books"):
        return None
    if path.startswith("/api/books/") and path[len("/api/books/"):] not in ("search", "ingest") \
            and "/" in path[len("/api/books/"):]:
        return _err(404, "not found")
    if headers is not None and not _host_allowed(headers.get("Host", "") or "", bind):
        return _err(403, "unexpected Host header (the service answers only at its own address)")
    if method == "POST" and not _same_origin(headers, bind):
        return _err(403, "cross-origin request refused")
    if method == "GET":
        if path == "/api/books":
            return _registry(st)
        if path == "/api/books/search":
            return _search(st, q)
        slug = path[len("/api/books/"):]
        if slug:
            doc = books.outline(_bdir(st), slug)
            return _ok(doc) if doc else _err(404, "unknown book slug")
        return _err(404, "not found")
    if method == "POST":
        if path == "/api/books/ingest":
            return _ingest(st, body)
        return _err(404, "not found")
    return _err(405, "method not allowed")
