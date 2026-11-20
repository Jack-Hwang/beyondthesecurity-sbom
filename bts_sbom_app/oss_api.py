"""JSON API behind the "OSS Scanner" screen: scan a folder / archive / URL, watch the stages, browse the results, download
reports, generate the OSS notice, compare two scans and lint a tree for REUSE-style declarations.

This is the web counterpart of ``bts-sbom oss ...`` (the BTS-SBOM answer to the FOSSLight Scanner GUI): the same scanners,
the same report model, the same notice generator - exposed to the page in ``web/oss_scanner.js``.

POST /api/oss/scan            {target, modes?, excludes?, branch?, correction?}   -> {job}   (background thread)
GET  /api/oss/jobs/<id>       -> state, stage (prepare | analyze | normalize), warnings, overview
POST /api/oss/jobs/<id>/cancel
GET  /api/oss/history         -> one row per finished scan (re-open a previous result)
GET  /api/oss/items/<id>?kind=src|dep|bin&q=&sort=&dir=&limit=&offset=   -> table rows (search / sort / paginate)
GET  /api/oss/report/<id>?format=xlsx|csv|json|yaml|spdx-json|spdx-tag|cyclonedx-json|cyclonedx-xml   -> download
POST /api/oss/notice          {job, format?, lang?, product?, contact?, fetch_license_texts?, strict?}   -> notice + audit
GET  /api/oss/compare?a=<id>&b=<id>
GET  /api/oss/precheck?path=  -> REUSE-style lint of a local folder (read-only)

Safety: report files are written only below <evidence>/oss/<job id>/ (the caller never chooses a write path); job ids are
validated hex; targets are checked by ossscan.prepare_target (archive limits, safe git flags, no dangerous transports);
the analysed material is never executed; every request must carry a Host header that is the address the service is bound
to (loopback name / IP literal and the bound port - a DNS-rebinding page is refused, see BTS_OSS_ALLOWED_HOSTS for a reverse
proxy) and a mutating request from another web origin is refused (CSRF); URLs that resolve to non-public addresses are
refused unless BTS_OSS_ALLOW_PRIVATE_HOSTS=1; at most MAX_RUNNING scans run at once and MAX_JOBS finished jobs are kept.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import tempfile
import threading
import time
import urllib.parse
import uuid
from typing import Any, Dict, List, Optional, Tuple

from bts_sbom import notice as notice_mod
from bts_sbom import ossreport, ossscan
from bts_sbom._internal import oss_common
from bts_sbom.ossreport import OssReport

MAX_RUNNING = 2
MAX_JOBS = 200
MAX_ROWS = 500
MODES = ("source", "dependency", "binary")
_ID = re.compile(r"^[0-9a-f]{10}$")
_REPORT_TYPES = {"xlsx": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet", "csv": "text/csv",
                 "json": "application/json", "yaml": "text/yaml", "spdx-json": "application/json", "spdx-tag": "text/plain",
                 "cyclonedx-json": "application/json", "cyclonedx-xml": "application/xml"}
_lock = threading.Lock()

Response = Tuple[int, Any, str, Dict[str, str]]


def _err(code: int, msg: str) -> Response:
    return code, {"error": msg}, "application/json", {}


def _ok(obj: Any, code: int = 200) -> Response:
    return code, obj, "application/json", {}


class _Jobs:
    def __init__(self, evidence: str) -> None:
        self.base = os.path.join(evidence, "oss")
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.cancel: Dict[str, threading.Event] = {}

    def dir(self, jid: str) -> str:
        return os.path.join(self.base, jid)


def _jobs(st: Any) -> _Jobs:
    j = getattr(st, "oss_jobs", None)
    if j is None:
        with _lock:
            j = getattr(st, "oss_jobs", None)
            if j is None:
                j = st.oss_jobs = _Jobs(st.evidence)
    return j


def _split_host(value: str) -> Tuple[str, Optional[int]]:
    parts = urllib.parse.urlsplit("//" + value.strip())
    return (parts.hostname or "").lower(), parts.port


def _host_allowed(host_header: str, bind: Optional[Tuple[Any, ...]]) -> bool:
    """Is ``Host`` an address this service is really reachable at?  An attacker page that makes its own DNS name point at
    127.0.0.1 (DNS rebinding) sends ``Host: evil.example`` and, from the browser's point of view, is same-origin with the
    service - so a name that is not loopback / an IP literal / explicitly allowed is refused, for reads as well as writes."""
    if not host_header:
        return False
    try:
        name, port = _split_host(host_header)
    except ValueError:
        return False
    if not name:
        return False
    extra = {h.strip().lower() for h in os.environ.get("BTS_OSS_ALLOWED_HOSTS", "").split(",") if h.strip()}
    if host_header.strip().lower() in extra or name in extra:
        return True
    if bind and len(bind) >= 2 and isinstance(bind[1], int):
        if (port or 80) != bind[1]:
            return False
    if name == "localhost":
        return True
    try:
        ipaddress.ip_address(name)                    # an IP literal cannot be re-pointed by an attacker's DNS
        return True
    except ValueError:
        pass
    return bool(bind) and isinstance(bind[0], str) and name == bind[0].lower()


def _same_origin(headers: Any, bind: Optional[Tuple[Any, ...]] = None) -> bool:
    """A mutating request is refused when its Origin is another site (CSRF against a localhost service), when the browser
    says so (``Sec-Fetch-Site: cross-site``) or when the Host header is not the service's own address."""
    if headers is None:
        return False
    host = headers.get("Host", "") or ""
    if not _host_allowed(host, bind):
        return False
    if (headers.get("Sec-Fetch-Site") or "").lower() == "cross-site":
        return False
    origin = headers.get("Origin")
    if not origin:
        return True                                   # a non-browser client (curl, the CLI): no ambient browser credentials
    try:
        return urllib.parse.urlsplit(origin).netloc.lower() == host.lower()
    except ValueError:
        return False


# ------------------------------------------------------------------------------------------------ persistence
def _write_result(d: str, report: OssReport, overview: Dict[str, Any], meta: Dict[str, Any]) -> None:
    os.makedirs(d, exist_ok=True)
    tmp = os.path.join(d, "result.json.tmp")
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump({"meta": meta, "overview": overview, "report": ossreport.report_to_dict(report)}, fh, ensure_ascii=False)
    os.replace(tmp, os.path.join(d, "result.json"))


def _load(j: _Jobs, jid: str) -> Optional[Dict[str, Any]]:
    if not _ID.match(jid or ""):
        return None
    try:
        with open(os.path.join(j.dir(jid), "result.json"), "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def _report_of(j: _Jobs, jid: str) -> Optional[Tuple[OssReport, Dict[str, Any]]]:
    doc = _load(j, jid)
    if not doc:
        return None
    try:
        return ossreport.report_from_dict(doc["report"]), doc
    except (KeyError, ValueError):
        return None


def _evict(j: _Jobs) -> None:
    """Keep the in-memory table bounded: errors and cancellations never reach the disk, so ``_prune`` alone never forgets
    them.  Finished jobs beyond MAX_JOBS go, oldest first (by their own timestamps); running jobs are never dropped."""
    with _lock:
        finished = [k for k, v in j.jobs.items() if v.get("state") != "running"]
        for k in list(j.cancel):
            if k not in j.jobs or k in finished:
                j.cancel.pop(k, None)
        if len(finished) > MAX_JOBS:
            finished.sort(key=lambda k: str(j.jobs[k].get("finished") or j.jobs[k].get("started") or ""))
            for k in finished[:len(finished) - MAX_JOBS]:
                j.jobs.pop(k, None)


def _prune(j: _Jobs) -> None:
    try:
        names = sorted((n for n in os.listdir(j.base) if _ID.match(n)),
                       key=lambda n: os.path.getmtime(os.path.join(j.base, n)))
    except OSError:
        return
    for n in names[:-MAX_JOBS]:
        shutil.rmtree(os.path.join(j.base, n), ignore_errors=True)
        j.jobs.pop(n, None)


# ------------------------------------------------------------------------------------------------------- scan
def _clean_list(v: Any, limit: int = 50, width: int = 200) -> List[str]:
    if not isinstance(v, list):
        return []
    return [str(x).strip()[:width] for x in v if str(x).strip()][:limit]


def _allow_private_hosts() -> bool:
    return os.environ.get("BTS_OSS_ALLOW_PRIVATE_HOSTS", "").strip() == "1"


def _run_job(st: Any, jid: str, target: str, modes: List[str], excludes: List[str], branch: str, correction: bool) -> None:
    j = _jobs(st)
    job = j.jobs[jid]
    cancel = j.cancel[jid]

    def stage(name: str) -> None:
        oss_common.check_cancel()
        job["stage"] = name

    try:
        with oss_common.cancel_scope(cancel):
            stage("prepare")
            with ossscan.prepare_target(target, branch=branch, allow_private_hosts=_allow_private_hosts()) as pt:
                stage("analyze")
                report = ossscan.run_scan(pt.root, modes, excludes=excludes, correction=None if correction else False,
                                          meta={"spec": target, "kind": pt.kind, **pt.meta})
                report.warnings = list(pt.warnings) + report.warnings
                stage("normalize")
                ov = ossscan.overview(report)
                meta = {"id": jid, "target": target, "kind": pt.kind, "modes": modes, "excludes": excludes,
                        "branch": branch, "finished": time.strftime("%Y-%m-%dT%H:%M:%S"), "started": job["started"]}
                _write_result(j.dir(jid), report, ov, meta)
        job.update(state="done", stage="done", overview=ov, warnings=report.warnings[:50], counts=ov["counts"])
    except oss_common.Cancelled:
        job.update(state="cancelled", error="cancelled")
    except ossscan.TargetError as exc:
        job.update(state="error", error=str(exc)[:300])
    except Exception as exc:                                                      # noqa: BLE001
        job.update(state="error", error="%s: %s" % (type(exc).__name__, str(exc)[:200]))
    finally:
        job["finished"] = time.strftime("%Y-%m-%dT%H:%M:%S")
        _evict(j)


def _start_scan(st: Any, b: Dict[str, Any]) -> Response:
    target = str(b.get("target") or "").strip()
    if not target or len(target) > 2000:
        return _err(400, "target required (a folder, an archive file, a git URL or an archive URL)")
    modes = [m for m in _clean_list(b.get("modes"), 10, 20) if m in MODES] or list(MODES)
    j = _jobs(st)
    with _lock:
        if sum(1 for x in j.jobs.values() if x.get("state") == "running") >= MAX_RUNNING:
            return _err(429, "too many scans are running (limit %d); wait for one to finish" % MAX_RUNNING)
        jid = uuid.uuid4().hex[:10]
        j.jobs[jid] = {"id": jid, "state": "running", "stage": "queued", "target": target, "modes": modes,
                       "started": time.strftime("%Y-%m-%dT%H:%M:%S")}
        j.cancel[jid] = threading.Event()
    _prune(j)
    threading.Thread(target=_run_job, daemon=True, args=(
        st, jid, target, modes, _clean_list(b.get("excludes")), str(b.get("branch") or "")[:200], b.get("correction", True) is not False)).start()
    return _ok({"job": jid}, 202)


# ------------------------------------------------------------------------------------------------- read views
def _row(i: Any) -> Dict[str, Any]:
    return {"path": i.purl if i.kind == "dep" and i.purl else i.source_path, "source_path": i.source_path, "purl": i.purl,
            "oss_name": i.oss_name, "version": i.version, "license": i.license_field, "download_location": i.download_location,
            "homepage": i.homepage, "copyright": i.copyright, "comment": i.comment, "exclude": i.exclude,
            "direct": i.direct, "checksum": i.checksum, "needs_check": i.needs_check, "notice_status": i.notice_status,
            "evidence": i.evidence[:4]}


def _items(j: _Jobs, jid: str, q: Dict[str, List[str]]) -> Response:
    hit = _report_of(j, jid)
    if hit is None:
        return _err(404, "unknown or unfinished scan")
    report, _doc = hit
    kind = (q.get("kind") or ["src"])[0]
    if kind not in ossreport.KINDS:
        return _err(400, "kind must be one of %s" % ", ".join(ossreport.KINDS))
    rows = [_row(i) for i in report.of_kind(kind)]
    needle = (q.get("q") or [""])[0].strip().lower()
    if needle:
        rows = [r for r in rows if needle in " ".join(str(r[k]) for k in ("path", "oss_name", "license", "version")).lower()]
    sort = (q.get("sort") or ["path"])[0]
    if sort not in ("path", "oss_name", "version", "license"):
        sort = "path"
    rows.sort(key=lambda r: str(r[sort]).lower(), reverse=(q.get("dir") or ["asc"])[0] == "desc")
    try:
        limit = max(1, min(int((q.get("limit") or ["100"])[0]), MAX_ROWS))
        offset = max(0, int((q.get("offset") or ["0"])[0]))
    except ValueError:
        return _err(400, "limit and offset must be integers")
    return _ok({"kind": kind, "total": len(rows), "offset": offset, "limit": limit, "rows": rows[offset:offset + limit]})


def _history(j: _Jobs) -> Response:
    rows = []
    try:
        names = [n for n in os.listdir(j.base) if _ID.match(n)]
    except OSError:
        names = []
    for n in names:
        doc = _load(j, n)
        if doc:
            m, ov = doc.get("meta") or {}, doc.get("overview") or {}
            rows.append({"id": n, "target": m.get("target"), "kind": m.get("kind"), "modes": m.get("modes"),
                         "finished": m.get("finished"), "counts": ov.get("counts"), "excluded": ov.get("excluded")})
    rows.sort(key=lambda r: r.get("finished") or "", reverse=True)
    return _ok({"history": rows[:MAX_JOBS]})


def _download(j: _Jobs, jid: str, fmt: str) -> Response:
    if fmt not in ossreport.FORMATS:
        return _err(400, "format must be one of %s" % ", ".join(ossreport.FORMATS))
    hit = _report_of(j, jid)
    if hit is None:
        return _err(404, "unknown or unfinished scan")
    report, _doc = hit
    tmp = tempfile.mkdtemp(prefix="bts_oss_dl_")
    try:
        path = ossreport.write_report(report, fmt, os.path.join(tmp, "report"))
        with open(path, "rb") as fh:
            data = fh.read()
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    ext = ossreport._EXT[fmt]
    return 200, data, _REPORT_TYPES[fmt], {"Content-Disposition": 'attachment; filename="bts_report_%s%s"' % (jid, ext)}


def _notice(j: _Jobs, b: Dict[str, Any]) -> Response:
    jid = str(b.get("job") or "")
    hit = _report_of(j, jid)
    if hit is None:
        return _err(404, "unknown or unfinished scan")
    fmt, lang = str(b.get("format") or "html"), str(b.get("lang") or "en")
    if fmt not in notice_mod.FORMATS or lang not in ("en", "ko"):
        return _err(400, "format must be one of %s and lang en|ko" % ", ".join(notice_mod.FORMATS))
    opts = notice_mod.NoticeOptions(fmt=fmt, lang=lang, product=str(b.get("product") or "")[:200], contact=str(b.get("contact") or "")[:200],
                                    fetch_license_texts=bool(b.get("fetch_license_texts")), strict=bool(b.get("strict")),
                                    cache_dir=os.path.join(j.base, ".license_cache"))
    res = notice_mod.build_notice(hit[0], opts)
    return _ok({"notice": res.text, "format": fmt, "audit": res.audit, "ok": res.ok})


def _compare(j: _Jobs, q: Dict[str, List[str]]) -> Response:
    a, b = (q.get("a") or [""])[0], (q.get("b") or [""])[0]
    ra, rb = _report_of(j, a), _report_of(j, b)
    if ra is None or rb is None:
        return _err(404, "both scans must exist and be finished")
    return _ok(ossreport.compare_reports(ra[0], rb[0]))


def _precheck(q: Dict[str, List[str]]) -> Response:
    path = (q.get("path") or [""])[0]
    if not path or not os.path.isdir(path):
        return _err(400, "path must be an existing folder on the machine running this service")
    try:
        from bts_sbom._internal import oss_precheck
        return _ok(oss_precheck.lint(path))
    except ImportError:
        return _err(501, "the precheck module is not available in this build")


# -------------------------------------------------------------------------------------------------------- route
def route(method: str, path: str, query: Dict[str, List[str]], body: Dict[str, Any], headers: Any, st: Any,
          bind: Optional[Tuple[Any, ...]] = None) -> Optional[Response]:
    """Return a response for /api/oss/... or None when the path is not ours.  ``bind`` = (host, port) the HTTP server
    listens on; the Host header of every request is checked against it."""
    if not path.startswith("/api/oss/"):
        return None
    j = _jobs(st)
    rest = path[len("/api/oss/"):].strip("/")
    parts = rest.split("/")
    if headers is not None and not _host_allowed(headers.get("Host", "") or "", bind):
        return _err(403, "unexpected Host header (the service answers only at its own address)")
    if method == "POST" and not _same_origin(headers, bind):
        return _err(403, "cross-origin request refused")
    if method == "POST":
        if rest == "scan":
            return _start_scan(st, body)
        if rest == "notice":
            return _notice(j, body)
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
    if rest == "compare":
        return _compare(j, query)
    if rest == "precheck":
        return _precheck(query)
    if len(parts) == 2 and _ID.match(parts[1] or ""):
        jid = parts[1]
        if parts[0] == "jobs":
            job = j.jobs.get(jid)
            if job is None:                                   # a finished scan from an earlier server run
                doc = _load(j, jid)
                if not doc:
                    return _err(404, "unknown job")
                m = doc.get("meta") or {}
                job = {"id": jid, "state": "done", "stage": "done", "target": m.get("target"), "modes": m.get("modes"),
                       "overview": doc.get("overview"), "counts": (doc.get("overview") or {}).get("counts"),
                       "warnings": (doc.get("overview") or {}).get("warnings", [])[:50]}
            return _ok(job)
        if parts[0] == "items":
            return _items(j, jid, query)
        if parts[0] == "report":
            return _download(j, jid, (query.get("format") or ["xlsx"])[0])
        if parts[0] == "overview":
            doc = _load(j, jid)
            return _ok(doc.get("overview")) if doc else _err(404, "unknown scan")
    return _err(404, "not found")
