"""Small stdlib HTTP service: the open-source security screen (``web/``) and the JSON API behind it.

GET  /                                     -> the page (web/index.html); its assets are served under /static/<file> from a fixed allow-list
POST /api/scan   {source, patch?, approved?, approval_token?, offline?, use_llm?}  -> {job}
                                           (background thread; the origin is never modified; ``approved`` needs the digest of the reviewed plan)
GET  /api/jobs/<id>                        -> status + metrics + artifact paths
POST /api/chat   {question, project?, use_llm?}  -> grounded answer with verified claims
GET  /api/projects                         -> names of the analysed projects (from the evidence folder)
GET  /api/history                          -> one row per analysed project (counts, analysis time)
GET  /api/engine                           -> core version, LLM state, evidence folder
GET  /api/view/<project>                   -> console report + data of every pane
GET  /api/sbom/<project>?format=cdx|spdx|vex , GET /api/doc/<project>   -> downloads
GET|POST /api/triage                       -> "ignore with reason" decisions (stored next to the evidence; optional justification, expires, scope, by)
GET  /api/vex/<project>                    -> OpenVEX with the triage decisions applied (fail-closed, see triage.py)
GET  /api/conformance/<project>            -> SBOM conformance matrix (NTIA 2021, CISA 2025 draft, EU CRA, BSI TR-03183-2, vulnerability readiness)
GET  /api/changes/<project>                -> what changed since the previous analysis (alerts, new / resolved findings)
GET  /api/fleet , /api/affected?cve=&component=&version=   -> portfolio roll-up, projects hit by an advisory / using a component
GET  /api/health
Binds to 127.0.0.1 by default. There is no authentication: do not expose it beyond localhost without a reverse proxy.
Scan sources are restricted to https/ssh/file git URLs, owner/repo shorthands and EXISTING local folders.
"""
from __future__ import annotations

import datetime
import json
import os
import shutil
import tempfile
import threading
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from . import __version__, actions as actionsmod, chat as chatmod, conformance, console, engine, evals, fleet, pipeline, report, sbom, triage as triagemod, workspace
from .cli import evidence_chunks, load_projects, project_records
from .llm import ChatClient

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
_CTYPES = {".html": "text/html", ".js": "application/javascript", ".css": "text/css"}
_SBOM_FILES = {"cdx": ".cdx.json", "spdx": ".spdx.json", "vex": ".vex.json"}
# The page loads only its own files; everything it renders from analysed data is escaped, and this policy is the second line of defence.
_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'none'; frame-ancestors 'none'")


def static_files() -> Dict[str, str]:
    """relative name -> path of every .js/.css under web/. index.html is served at '/', never under /static."""
    out: Dict[str, str] = {}
    for dp, _, fns in os.walk(WEB_DIR):
        for fn in fns:
            if os.path.splitext(fn)[1] in (".js", ".css"):
                full = os.path.join(dp, fn)
                out[os.path.relpath(full, WEB_DIR).replace(os.sep, "/")] = full
    return out


class State:
    def __init__(self, root: str, evidence: str, cfg: Optional[str], chat_actions: bool = False):
        self.root, self.evidence = root, evidence
        self.chat_actions = chat_actions                     # /api/chat may analyse, patch (approved) and record decisions only when the service was started so
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        if cfg:
            os.environ["BTS_SBOM_LLM_CONFIG"] = cfg
        self.client = ChatClient.from_env(ledger=os.path.join(root, "evidence", ".llm_ledger.json"))
        self.triage_path = os.path.join(evidence, ".triage.json")

    def bot(self) -> chatmod.Chatbot:
        projs = load_projects(self.evidence)
        client = self.client if self.client.available else None
        acts = actionsmod.ChatActions(self.root, self.evidence, client=client) if self.chat_actions else None
        return chatmod.Chatbot(evals.build_index(self.root, evidence_chunks(projs)), projs, client, acts, self.triage())

    def triage(self) -> Dict[str, Any]:
        with self.lock:
            try:
                with open(self.triage_path, "r", encoding="utf-8") as fh:
                    d = json.load(fh)
                return d if isinstance(d, dict) else {}
            except (OSError, ValueError):
                return {}

    def set_triage(self, key: str, status: str, note: str, extra: Optional[Dict[str, str]] = None) -> Optional[Dict[str, Any]]:
        """Store one decision; None when the store is full (TRIAGE_MAX_ENTRIES) and the key is new. ``extra``: justification / expires / scope / by."""
        cur = self.triage()
        if key not in cur and len(cur) >= console.TRIAGE_MAX_ENTRIES:
            return None
        cur[key] = {"status": status, "note": note, "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds")}
        cur[key].update({k: v for k, v in (extra or {}).items() if v})
        with self.lock:
            os.makedirs(self.evidence, exist_ok=True)
            tmp = self.triage_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(cur, fh, ensure_ascii=False, indent=1)
            os.replace(tmp, self.triage_path)
        return cur

    def project(self, name: str) -> Optional[Tuple[str, Dict[str, Any]]]:
        return project_records(self.evidence).get(name)


def _safe_source(src: str) -> Optional[str]:
    from .workspace import normalize_source
    try:
        spec = normalize_source(src)
    except ValueError as exc:
        return str(exc)
    if spec["kind"] == "local" and not os.path.exists(spec["path"]):
        return "local path does not exist"
    return None


def _mtime_iso(path: str) -> Optional[str]:
    try:
        return datetime.datetime.fromtimestamp(os.path.getmtime(path)).astimezone().isoformat(timespec="seconds")
    except OSError:
        return None


def _record_file(folder: str) -> str:
    return os.path.join(folder, os.path.basename(folder) + ".json")


def _history_row(name: str, folder: str, rec: Dict[str, Any]) -> Dict[str, Any]:
    m = rec.get("metrics") or {}
    return {"name": name, "source": rec.get("source"), "analysed_at": _mtime_iso(_record_file(folder)), "components": m.get("components"),
            "vulns": m.get("vulns"), "severity": m.get("severity") or {}, "license_resolved_rate": m.get("license_resolved_rate"),
            "patch_status": m.get("patch_status"), "proposal_source": m.get("proposal_source"), "stage_errors": m.get("stage_errors")}


def make_handler(st: State):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def _emit(self, code: int, body: bytes, ctype: str, headers: Optional[Dict[str, str]] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            if ctype == "text/html":
                self.send_header("Content-Security-Policy", _CSP)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _send(self, code: int, obj: Any, ctype: str = "application/json", headers: Optional[Dict[str, str]] = None) -> None:
            body = (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, default=str)).encode("utf-8")
            self._emit(code, body, ctype, headers)

        def _file(self, path: str) -> None:
            ctype = _CTYPES.get(os.path.splitext(path)[1], "application/octet-stream")
            try:
                with open(path, "rb") as fh:
                    self._emit(200, fh.read(), ctype)
            except OSError:
                self._send(404, {"error": "not found"})

        def _body(self) -> Dict[str, Any]:
            n = min(int(self.headers.get("Content-Length") or 0), 1_000_000)
            try:
                d = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                return d if isinstance(d, dict) else {}
            except ValueError:
                return {}

        def do_GET(self) -> None:                                    # noqa: N802
            u = urllib.parse.urlsplit(self.path)
            path, q = u.path, urllib.parse.parse_qs(u.query)
            if path in ("/", "/index.html"):
                return self._file(os.path.join(WEB_DIR, "index.html"))
            if path.startswith("/static/"):
                files = static_files()
                rel = urllib.parse.unquote(path[len("/static/"):])
                return self._file(files[rel]) if rel in files else self._send(404, {"error": "not found"})
            if path == "/api/health":
                return self._send(200, {"ok": True, "llm": st.client.describe()})
            if path == "/api/engine":
                try:
                    core: Any = engine.core_info()
                except ImportError as exc:
                    core = {"error": str(exc)}
                return self._send(200, {"name": "BTS-SBOM", "workflow_version": __version__, "core": core, "llm": st.client.describe(),
                                        "evidence": st.evidence, "projects": len(project_records(st.evidence))})
            if path == "/api/projects":
                return self._send(200, {"projects": sorted(load_projects(st.evidence))})
            if path == "/api/history":
                rows = [_history_row(n, d, r) for n, (d, r) in project_records(st.evidence).items()]
                return self._send(200, {"history": sorted(rows, key=lambda x: x.get("analysed_at") or "", reverse=True)})
            if path == "/api/triage":
                return self._send(200, {"triage": st.triage()})
            if path == "/api/fleet":
                return self._send(200, fleet.rollup(load_projects(st.evidence)))
            if path == "/api/affected":
                try:
                    return self._send(200, fleet.affected(load_projects(st.evidence), vuln_id=(q.get("cve") or [None])[0], component=(q.get("component") or [None])[0],
                                                          version=(q.get("version") or [None])[0]))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            for prefix in ("/api/conformance/", "/api/changes/", "/api/vex/"):
                if path.startswith(prefix):
                    hit = st.project(urllib.parse.unquote(path[len(prefix):]))
                    if hit is None:
                        return self._send(404, {"error": "unknown project"})
                    folder, rec = hit
                    if prefix == "/api/vex/":
                        return self._send(200, sbom.openvex(rec["name"], rec.get("vulns") or [], triage=st.triage()), "application/json")
                    if prefix == "/api/changes/":
                        return self._send(200, rec.get("changes") or {"note": "no earlier analysis of this project was recorded"})
                    doc, note = conformance.load_document(_record_file(folder))
                    return self._send(200 if doc else 404, conformance.evaluate(doc) if doc else {"error": note})
            if path.startswith("/api/jobs/"):
                j = st.jobs.get(path.rsplit("/", 1)[-1])
                return self._send(200 if j else 404, j or {"error": "unknown job"})
            for prefix in ("/api/view/", "/api/sbom/", "/api/doc/"):
                if path.startswith(prefix):
                    name = urllib.parse.unquote(path[len(prefix):])
                    hit = st.project(name)
                    if hit is None:
                        return self._send(404, {"error": "unknown project"})
                    folder, rec = hit
                    if prefix == "/api/view/":
                        return self._send(200, console.build_view(rec, st.triage(), _mtime_iso(_record_file(folder))))
                    base = os.path.basename(folder)
                    if prefix == "/api/doc/":
                        return self._send(200, report.project_md(rec), "text/markdown", {"Content-Disposition": 'attachment; filename="%s.md"' % base})
                    fmt = (q.get("format") or ["cdx"])[0]
                    if fmt not in _SBOM_FILES:
                        return self._send(400, {"error": "format must be one of %s" % ", ".join(sorted(_SBOM_FILES))})
                    try:
                        with open(os.path.join(folder, base + _SBOM_FILES[fmt]), "r", encoding="utf-8") as fh:
                            doc = fh.read()
                    except OSError:
                        return self._send(404, {"error": "this project has no %s document" % fmt})
                    return self._send(200, doc, "application/json", {"Content-Disposition": 'attachment; filename="%s.%s.json"' % (base, fmt)})
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:                                   # noqa: N802
            b = self._body()
            path = urllib.parse.urlsplit(self.path).path
            if path == "/api/triage":
                key, status, note = b.get("check_id"), b.get("status"), b.get("note")
                bad = console.valid_triage(key, status, note) or triagemod.check_extras(b.get("justification"), b.get("expires"), b.get("scope"), b.get("by"))
                if bad:
                    return self._send(400, {"error": bad})
                done = st.set_triage(str(key).strip(), str(status), str(note or ""),
                                     {k: str(b.get(k)).strip() for k in ("justification", "expires", "scope", "by") if b.get(k)})
                if done is None:
                    return self._send(409, {"error": "triage store is full (%d entries)" % console.TRIAGE_MAX_ENTRIES})
                return self._send(200, {"ok": True, "triage": done})
            if path == "/api/scan":
                src = str(b.get("source") or "")
                bad = _safe_source(src)
                if bad:
                    return self._send(400, {"error": bad})
                patch, approved, token = bool(b.get("patch")), bool(b.get("approved")), b.get("approval_token")
                if approved and not patch:
                    return self._send(400, {"error": "approved needs patch"})
                if approved and not (isinstance(token, str) and token.strip()):
                    return self._send(400, {"error": "approved needs approval_token: the digest of the plan you reviewed (from a patch run without approval)"})
                jid = uuid.uuid4().hex[:10]
                st.jobs[jid] = {"state": "running", "source": src}

                def work() -> None:
                    wdir = tempfile.mkdtemp(prefix="bts_sbom_job_")
                    keep = False
                    final: Dict[str, Any]
                    try:
                        rec = pipeline.run_project(src, work_root=wdir, out_dir=st.evidence, patch=patch, approved=approved,
                                                   approval_token=token.strip() if approved else None, offline=bool(b.get("offline")),
                                                   use_llm=bool(b.get("use_llm")), client=st.client if st.client.available else None,
                                                   cache_dir=os.path.join(st.root, "evidence", "cache"))
                        keep = bool(patch and approved and (rec.get("patch") or {}).get("status") == "applied")
                        final = {"state": "error" if rec.get("error") else "done", "source": src, "name": rec.get("name"),
                                 "error": rec.get("error"), "metrics": rec.get("metrics"), "artifacts": rec.get("artifacts"),
                                 "stage_errors": rec.get("stage_errors"), "work_copy": wdir if keep else None}
                    except Exception as exc:                          # noqa: BLE001
                        final = {"state": "error", "source": src, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
                    finally:
                        if not keep:                                  # an applied patch lives in the work copy, so only that one is kept
                            shutil.rmtree(wdir, onerror=workspace._force_remove)
                    st.jobs[jid] = final                              # published only after the clean-up: "done" implies the copy is gone

                threading.Thread(target=work, daemon=True).start()
                return self._send(202, {"job": jid})
            if path == "/api/chat":
                q = str(b.get("question") or "").strip()
                if not q:
                    return self._send(400, {"error": "question required"})
                return self._send(200, st.bot().ask(q, project=b.get("project"), use_llm=bool(b.get("use_llm"))))
            self._send(404, {"error": "not found"})

    return H


def serve(root: str, host: str, port: int, evidence: str, cfg: Optional[str] = None, chat_actions: bool = False) -> int:
    st = State(root, evidence, cfg, chat_actions)
    httpd = ThreadingHTTPServer((host, port), make_handler(st))
    print("BTS-SBOM serving on http://%s:%d (evidence: %s)" % (host, port, evidence), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
