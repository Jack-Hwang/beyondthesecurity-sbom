"""Small stdlib HTTP service: the open-source security screen (``web/``) and the JSON API behind it.

GET  /                                     -> the page (web/index.html); its assets are served under /static/<file> from a fixed allow-list
POST /api/scan   {source, patch?, approved?, approval_token?, offline?, use_llm?}  -> {job}
                                           (background thread; the origin is never modified; ``approved`` needs the digest of the reviewed plan)
GET  /api/jobs/<id>                        -> status + metrics + artifact paths
POST /api/chat   {question, project?, use_llm?}  -> grounded answer with verified claims
POST /api/llm    {api_key, base_url?, model?, remember?} -> connect the AI for this process (never returns the key; ``remember`` keeps
                                           it in evidence/.llm_config.json so a restart reconnects - only a localhost base_url may omit the key)
POST /api/llm/clear                       -> disconnect: saved key file removed, back to the startup configuration
GET  /api/llm                             -> connection status (model, provider, masked key tail, whether a key is saved)
GET  /api/projects                         -> names of the analysed projects (from the evidence folder)
GET  /api/history                          -> one row per analysed project (counts, analysis time)
GET  /api/engine                           -> core version, LLM state, evidence folder
GET  /api/view/<project>                   -> console report + data of every pane
GET  /api/sbom/<project>?format=cdx|spdx|vex , GET /api/doc/<project>   -> downloads
GET|POST /api/triage                       -> "ignore with reason" decisions (stored next to the evidence; optional justification, expires, scope, by)
GET  /api/vex/<project>                    -> OpenVEX with the triage decisions applied (fail-closed, see triage.py)
GET  /api/coverage/<project>               -> decision coverage graph: verdict per advisory, the worklist, the decision lineage and chains
GET  /api/selfcheck/<project>              -> FOSSLight-style self-check sheet (CSV download): OSS name/version/license per component
GET  /api/conformance/<project>            -> SBOM conformance matrix (NTIA 2021, CISA 2025 draft, EU CRA, BSI TR-03183-2, vulnerability readiness)
GET  /api/changes/<project>                -> what changed since the previous analysis (alerts, new / resolved findings)
GET  /api/fleet , /api/affected?cve=&component=&version=   -> portfolio roll-up, projects hit by an advisory / using a component
GET  /api/health
*    /api/oss/...                          -> the OSS Scanner screen (oss_api.py: scan folder / archive / URL, results, reports, notice, compare)
Binds to 127.0.0.1 by default. There is no authentication: do not expose it beyond localhost without a reverse proxy.
Scan sources are restricted to https/ssh/file git URLs, owner/repo shorthands and EXISTING local folders.
"""
from __future__ import annotations

import datetime
import json
import re
import os
import shutil
import tempfile
import threading
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional, Tuple

from . import __version__, actions as actionsmod, ai as aimod, chat as chatmod, guardrail as guardrailmod, alternatives as alternativesmod, codeprop as codepropmod, evidence as evidencemod, handover as handovermod, reconcile as reconcilemod, vnv as vnvmod, migration as migrationmod, legacy as legacymod, obligations as obligationsmod, conformance, console, coverage, audit as auditmod, auth as authmod, cloud, engine, events as eventsmod, evals, fleet, instance as instancemod, jobstore as jobstoremod, limits as limitsmod, metrics as metricsmod, obslog as obslogmod, oss_api, pipeline, report, sbom, selfcheck, triage as triagemod, workspace
from .cli import evidence_chunks, load_projects, project_records
from . import net
from .llm import ChatClient
from .util import read_json, write_json

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
        self.cloud_policy = cloud.policy()                   # cloud mode flips the localhost-only defaults to safe ones
        self.chat_actions = chat_actions                     # /api/chat may analyse, patch (approved) and record decisions only when the service was started so
        if self.chat_actions and not self.cloud_policy["chat_actions_allowed"]:
            self.chat_actions = False                            # cloud mode refuses the write-capable chat session
            self.cloud_policy["chat_actions_refused"] = True
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.buses: Dict[str, "eventsmod.EventBus"] = {}    # one SSE event bus per scan job
        self.store = jobstoremod.JobStore(os.path.join(evidence, ".jobs"))
        self.audit = auditmod.AuditLog(os.path.join(evidence, "audit.jsonl"))
        self.instance_lock: Optional[Any] = None             # set by serve(); tests may set a Standby/HeldLock
        self.limits = limitsmod.Limits(cloud_default_jobs=2 if cloud.is_cloud() else 0)
        self.gate = self.limits.gate()                       # bounded concurrent jobs (429 with Retry-After when full)
        self.shutting_down = False                            # set by the SIGTERM handler; drains before exit
        self._jobs_running = 0                                 # in-flight scan jobs (for the drain)
        self._job_dirs: Dict[str, str] = {}                    # job id -> temp work copy, so a drain can remove leftovers
        self._drain_s = self.limits.drain_s
        self.lock = threading.Lock()
        if cfg:
            os.environ["BTS_SBOM_LLM_CONFIG"] = cfg
        self.client = ChatClient.from_env(ledger=os.path.join(root, "evidence", ".llm_ledger.json"))
        self.startup_client = self.client                    # a disconnect falls back to what the process was started with
        if not self.client.available:                        # the key entered in the web console survives a restart (evidence/.llm_config.json);
            saved = self.saved_llm_config()                  # an explicit startup configuration (env / --llm-config) still wins over the saved file
            if saved.get("api_key"):
                self.client = ChatClient.from_config(str(saved.get("api_key")), str(saved.get("base_url") or ""),
                                                     str(saved.get("model") or ""), ledger=os.path.join(root, "evidence", ".llm_ledger.json"))
        self.triage_path = os.path.join(evidence, ".triage.json")
        self.store.recover()                                 # jobs that were queued/running when the last process died are interrupted, never "running" forever

    def _llm_config_path(self) -> str:
        return os.path.join(self.evidence, ".llm_config.json")

    def saved_llm_config(self) -> Dict[str, Any]:
        """The key the user entered in the web console and chose to keep (evidence/.llm_config.json, plain text - the evidence folder is local)."""
        d = read_json(self._llm_config_path(), {})
        return d if isinstance(d, dict) else {}

    def set_llm(self, cfg: Dict[str, Any], remember: bool) -> Dict[str, Any]:
        """Swap the LLM client for this process (scan jobs and the chatbot read it on every use); ``remember`` also keeps the key in the evidence folder."""
        key = str(cfg.get("api_key") or "").strip()
        base, model = str(cfg.get("base_url") or "").strip(), str(cfg.get("model") or "").strip()
        c = ChatClient.from_config(key, base, model, ledger=os.path.join(self.root, "evidence", ".llm_ledger.json"))
        if not c.available:
            return {}
        with self.lock:
            self.client = c
            if remember:
                os.makedirs(self.evidence, exist_ok=True)
                path = self._llm_config_path()
                write_json(path, {"api_key": key, **({"base_url": base} if base else {}), **({"model": model} if model else {})})
                if os.name == "posix":                       # defensive: mkstemp is already 0600 on POSIX, keep it that way (no-op on Windows)
                    try:
                        os.chmod(path, 0o600)
                    except OSError:
                        pass
        return self.llm_status()

    def clear_llm(self) -> Dict[str, Any]:
        """Disconnect: the saved key file is removed and the client falls back to the startup configuration (which may still hold an env key)."""
        saved = os.path.exists(self._llm_config_path())
        try:
            os.remove(self._llm_config_path())
        except OSError:
            saved = os.path.exists(self._llm_config_path())
        with self.lock:
            self.client = self.startup_client
        st = self.llm_status()
        st["saved_removed"] = saved
        return st

    def llm_status(self) -> Dict[str, Any]:
        """Connection status for the web console: the key is never returned, at most its last 4 characters."""
        d = dict(self.client.describe())
        key = self.client.api_key
        d["key_tail"] = key[-4:] if (self.client.available and len(key) >= 8) else ""
        d["saved"] = os.path.exists(self._llm_config_path())
        d["storage"] = "plaintext-file" if d["saved"] else "none"
        return d

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
    from .workspace import check_source_policy, normalize_source
    try:
        spec = normalize_source(src)
    except ValueError as exc:
        return str(exc)
    # cloud policy first: a refused local path must not even be stat'ed, and refused URLs start no clone
    bad = check_source_policy(spec, cloud=cloud.is_cloud())
    if bad:
        return bad
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


HEARTBEAT_SECONDS = 15.0                                   # SSE keepalive comment interval (tests shrink it)


def _check_evidence_writable(evidence: str) -> Optional[str]:
    """None = ok, otherwise the check name only - never the path or the exception text."""
    try:
        os.makedirs(evidence, exist_ok=True)
        probe = os.path.join(evidence, ".readyz_probe")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("probe")
        os.remove(probe)
    except OSError:
        return "evidence_writable"
    return None


def _check_core_importable() -> Optional[str]:
    try:
        __import__("bts_sbom")
    except Exception:                                          # noqa: BLE001 - the check only names itself, never the traceback
        return "core_importable"
    return None


def _check_knowledge_corpus(root: str) -> Optional[str]:
    if os.path.isdir(os.path.join(root, "knowledge")):
        return None
    return "knowledge_corpus"


def _readiness_checks(st: State) -> Dict[str, Optional[str]]:
    lock = st.instance_lock
    return {"evidence_writable": _check_evidence_writable(st.evidence),
            "core_importable": _check_core_importable(),
            "knowledge_corpus": _check_knowledge_corpus(st.root),
            # standby (not yet the writer) is an expected, healthy state: readiness names it via /readyz "mode"
            "evidence_lock": None if (lock is None or lock.active or (lock.standby and not lock.held)) else "evidence_lock"}


class _BadBody(Exception):
    def __init__(self, code: int, msg: str) -> None:
        super().__init__(msg)
        self.code = code


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
            self.send_header("X-Request-Id", getattr(self, "_req_id", ""))     # the only header added to existing responses
            if ctype == "text/html":
                self.send_header("Content-Security-Policy", _CSP)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)
            self._observe(code)                                   # one JSON access line + one metric observation per request

        def _observe(self, code: int) -> None:
            """Access log + metrics for the finished request. No request body, no query string, no credentials."""
            ms = round((time.time() - getattr(self, "_req_start", time.time())) * 1000, 1)
            metricsmod.observe_request(urllib.parse.urlsplit(self.path).path, code)
            obslogmod.write("http_request", request_id=getattr(self, "_req_id", ""), route=urllib.parse.urlsplit(self.path).path,
                            status=code, ms=ms, job_id=getattr(self, "_req_job", ""), who=getattr(self, "_identity", "") or "")

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
            """The JSON object of the request body.  A Content-Length that is not a plain non-negative integer, or is over
            1,000,000, raises _BadBody (a negative value would otherwise make ``rfile.read`` wait for EOF - a hang - and
            a non-numeric one used to crash the handler); no Content-Length means no body."""
            raw = (self.headers.get("Content-Length") or "").strip()
            if raw and not raw.isdigit():
                raise _BadBody(400, "invalid Content-Length")
            n = int(raw or 0)
            if n > 1_000_000:
                raise _BadBody(413, "request body larger than 1000000 bytes")
            try:
                d = json.loads(self.rfile.read(n).decode("utf-8") or "{}")
                return d if isinstance(d, dict) else {}
            except ValueError:
                return {}

        def _oss(self, method: str, path: str, q: Dict[str, Any], body: Dict[str, Any]) -> bool:
            """The OSS Scanner screen's API (oss_api.py); False when the path is not one of its routes."""
            hit = oss_api.route(method, path, q, body, self.headers, st, bind=tuple(self.server.server_address[:2]))
            if hit is None:
                return False
            code, obj, ctype, headers = hit
            if isinstance(obj, (bytes, bytearray)):
                self._emit(code, bytes(obj), ctype, headers)
            else:
                self._send(code, obj, ctype, headers)
            return True

        def _gate(self, path: str) -> bool:
            """Cloud-mode authentication for /api routes. False when the request was refused (a response was sent).
            The probes /healthz and /readyz always stay unauthenticated. Local mode: unchanged, no auth."""
            if not path.startswith("/api/") and not path.startswith("/metrics"):
                return True
            if not cloud.is_cloud():
                return True
            if path in ("/healthz", "/readyz"):
                return True
            if not authmod.configured():
                self._send(503, {"error": "auth_not_configured"})     # fail-closed: no method, no anonymous API
                return False
            ident = authmod.check(self.headers)
            if ident is None:                                 # one body for missing AND wrong credentials (no oracle)
                self._send(401, {"error": "unauthorized"})
                return False
            self._identity = ident
            return True

        def _standby_blocked(self) -> bool:
            """True (and a 503 already sent) when this instance serves read-only in standby mode."""
            lock = st.instance_lock
            if lock is not None and lock.standby and not lock.active:
                self._send(503, {"error": "standby"})
                return True
            return False

        def do_GET(self) -> None:                                    # noqa: N802
            u = urllib.parse.urlsplit(self.path)
            path, q = u.path, urllib.parse.parse_qs(u.query)
            self._identity = None
            self._req_id = obslogmod.clean_request_id(self.headers.get("X-Request-Id"))
            self._req_start = time.time()
            self._req_job = ""
            if not self._gate(path):
                return
            if path in ("/", "/index.html"):
                return self._file(os.path.join(WEB_DIR, "index.html"))
            if path.startswith("/static/"):
                files = static_files()
                rel = urllib.parse.unquote(path[len("/static/"):])
                return self._file(files[rel]) if rel in files else self._send(404, {"error": "not found"})
            if path == "/metrics":
                body = metricsmod.render(net.STATS)
                return self._emit(200, body.encode("utf-8"), "text/plain", {"Cache-Control": "no-store"})
            if path == "/healthz":
                return self._send(200, {"ok": True})
            if path == "/readyz":
                if st.shutting_down:
                    return self._send(503, {"ok": False, "failed": ["draining"]})
                failed = sorted(name for name, problem in _readiness_checks(st).items() if problem)
                if failed:
                    return self._send(503, {"ok": False, "failed": failed})
                mode = "standby" if (st.instance_lock is not None and st.instance_lock.standby and not st.instance_lock.active) else "active"
                return self._send(200, {"ok": True, "mode": mode})
            if path == "/api/health":
                return self._send(200, {"ok": True, "llm": st.client.describe()})
            if path == "/api/llm":
                return self._send(200, st.llm_status())
            if path.startswith("/api/handover/freeze/"):
                name = urllib.parse.unquote(path[len("/api/handover/freeze/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                return self._send(200, handovermod.freeze(rec, os.path.join(_folder, "handover")))
            if path.startswith("/api/handover/post/"):
                name = urllib.parse.unquote(path[len("/api/handover/post/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                frozen = handovermod.load(os.path.join(_folder, "handover"))
                if frozen is None:
                    return self._send(400, {"error": "no frozen baseline: call /api/handover/freeze first"})
                return self._send(200, handovermod.post_handover(rec, frozen))
            if path.startswith("/api/reconcile/"):
                name = urllib.parse.unquote(path[len("/api/reconcile/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                sbom_path = (q.get("sbom") or [""])[0]
                if not sbom_path or not os.path.isfile(sbom_path):
                    return self._send(400, {"error": "give ?sbom=<path to the provider SBOM file>"})
                doc = json.load(open(sbom_path, encoding="utf-8"))
                return self._send(200, reconcilemod.reconcile(doc, rec))
            if path.startswith("/api/evidence/"):
                name = urllib.parse.unquote(path[len("/api/evidence/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                out_dir = os.path.join(_folder, "bundle")
                manifest = evidencemod.bundle(rec, out_dir)
                return self._send(200, manifest)
            if path.startswith("/api/vnv/"):
                name = urllib.parse.unquote(path[len("/api/vnv/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                if rec.get("vnv"):
                    return self._send(200, rec["vnv"])
                return self._send(200, vnvmod.report(rec, plan_ref=(q.get("plan_ref") or [""])[0], req_ref=(q.get("req_ref") or [""])[0]))
            if path.startswith("/api/codeprop/"):
                name = urllib.parse.unquote(path[len("/api/codeprop/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                return self._send(200, {"proposals": codepropmod.list_proposals(os.path.join(_folder, "codeprop")),
                                        "note": "read-only; applying a proposal is a CLI-only action with the diff digest token"})
            if path.startswith("/api/migration/"):
                name = urllib.parse.unquote(path[len("/api/migration/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                if rec.get("migration"):
                    return self._send(200, rec["migration"])
                return self._send(200, migrationmod.plan(rec, root=None))
            if path.startswith("/api/alternatives/"):
                name = urllib.parse.unquote(path[len("/api/alternatives/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                if rec.get("alternatives"):
                    return self._send(200, rec["alternatives"])
                flagged = []
                ob = rec.get("obligations") or {}
                for row in ((ob.get("scenarios") or {}).get("binary") or {}).get("components", []):
                    if row.get("verdict") == "offer":
                        flagged.append({"component": row.get("name"), "reason": "copyleft"})
                return self._send(200, alternativesmod.suggest(flagged, client=None))
            if path.startswith("/api/legacy/"):
                name = urllib.parse.unquote(path[len("/api/legacy/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                if rec.get("legacy"):
                    return self._send(200, rec["legacy"])
                return self._send(200, legacymod.assess(rec.get("components") or [], rec.get("plans") or [], online=False, computed_on_read=True))
            if path.startswith("/api/obligations/"):
                name = urllib.parse.unquote(path[len("/api/obligations/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                if rec.get("obligations"):
                    return self._send(200, rec["obligations"])
                return self._send(200, obligationsmod.assess(rec.get("components") or [], project_license=(rec.get("license") or {}).get("project_license", ""),
                                                             computed_on_read=True))
            if path.startswith("/api/llm/outbound/"):
                name = urllib.parse.unquote(path[len("/api/llm/outbound/"):])
                hit = st.project(name)
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                _folder, rec = hit
                return self._send(200, {"project": name, "payload": aimod.evidence(rec),
                                        "note": "exactly what the proposal step would send to the LLM; 0 requests were sent"})
            if path == "/api/engine":
                try:
                    core: Any = engine.core_info()
                except ImportError as exc:
                    core = {"error": str(exc)}
                return self._send(200, {"name": "BTS-SBOM", "workflow_version": __version__, "core": core, "llm": st.client.describe(),
                                        "evidence": st.evidence, "projects": len(project_records(st.evidence)),
                                        "cloud": {"enabled": cloud.is_cloud(), "policy": dict(st.cloud_policy)}})
            if path == "/api/projects":
                return self._send(200, {"projects": sorted(load_projects(st.evidence))})
            if path == "/api/history":
                rows = [_history_row(n, d, r) for n, (d, r) in project_records(st.evidence).items()]
                return self._send(200, {"history": sorted(rows, key=lambda x: x.get("analysed_at") or "", reverse=True)})
            if path == "/api/triage":
                return self._send(200, {"triage": st.triage()})
            if path == "/api/fleet":
                return self._send(200, fleet.rollup(load_projects(st.evidence)))
            if path.startswith("/api/selfcheck/"):
                hit = st.project(urllib.parse.unquote(path[len("/api/selfcheck/"):]))
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                folder, rec = hit
                return self._send(200, selfcheck.to_csv(rec), "text/csv", {"Content-Disposition": 'attachment; filename="%s-selfcheck.csv"' % rec.get("name", "project")})
            if path == "/api/affected":
                try:
                    return self._send(200, fleet.affected(load_projects(st.evidence), vuln_id=(q.get("cve") or [None])[0], component=(q.get("component") or [None])[0],
                                                          version=(q.get("version") or [None])[0]))
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            for prefix in ("/api/conformance/", "/api/changes/", "/api/vex/", "/api/coverage/"):
                if path.startswith(prefix):
                    hit = st.project(urllib.parse.unquote(path[len(prefix):]))
                    if hit is None:
                        return self._send(404, {"error": "unknown project"})
                    folder, rec = hit
                    if prefix == "/api/coverage/":
                        return self._send(200, coverage.build(rec, st.triage()))
                    if prefix == "/api/vex/":
                        return self._send(200, sbom.openvex(rec["name"], rec.get("vulns") or [], triage=st.triage()), "application/json")
                    if prefix == "/api/changes/":
                        return self._send(200, rec.get("changes") or {"note": "no earlier analysis of this project was recorded"})
                    doc, note = conformance.load_document(_record_file(folder))
                    return self._send(200 if doc else 404, conformance.evaluate(doc) if doc else {"error": note})
            if path.startswith("/api/jobs/") and path.endswith("/events"):
                jid = path[len("/api/jobs/"):-len("/events")]
                bus = st.buses.get(jid)
                if bus is None and st.jobs.get(jid) is None:
                    rec = st.store.get(jid)
                    if rec is None:
                        return self._send(404, {"error": "unknown job"})
                    if rec.get("state") == "interrupted":
                        # a job the last process died in the middle of: one honest error event, then the stream ends
                        bus = eventsmod.EventBus()
                        bus.publish("error", error_type="interrupted", severity="error", retryable=True,
                                    recovery_hint="the server restarted while this job ran; submit the scan again (idempotency_key avoids a duplicate)")
                        bus.close()
                        st.buses[jid] = bus
                if bus is None:
                    return self._send(404, {"error": "unknown job"})
                if not bus.admit_subscriber():
                    return self._send(429, {"error": "too many stream subscribers"})
                after = 0
                lei = (self.headers.get("Last-Event-ID") or "").strip()
                if lei.isdigit():
                    after = int(lei)
                qs_after = (q.get("after") or [""])[0]
                if qs_after.isdigit():
                    after = int(qs_after)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                try:
                    cursor = after
                    while True:
                        ev = bus.next_event(cursor, timeout=HEARTBEAT_SECONDS)
                        if ev is None:
                            self.wfile.write(b": keepalive\n\n")           # a comment line: not an event, keeps the stream alive
                            self.wfile.flush()
                            if bus.closed:
                                break
                            continue
                        cursor = ev["seq"]
                        self.wfile.write(eventsmod.format_sse(ev))
                        self.wfile.flush()
                        if ev["type"] in eventsmod.TERMINAL:
                            break
                except (OSError, ValueError):
                    pass                                        # the client went away mid-stream
                finally:
                    bus.release_subscriber()
                return
            if path.startswith("/api/jobs/"):
                jid = path.rsplit("/", 1)[-1]
                j = st.jobs.get(jid)
                if j is None:
                    j = st.store.get(jid)                     # a finished job from before a restart lives only in the store
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
            if self._oss("GET", path, q, {}):
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:                                   # noqa: N802
            try:
                b = self._body()
            except _BadBody as exc:
                return self._send(exc.code, {"error": str(exc)})
            path = urllib.parse.urlsplit(self.path).path
            self._identity = None
            self._req_id = obslogmod.clean_request_id(self.headers.get("X-Request-Id"))
            self._req_start = time.time()
            self._req_job = ""
            if not self._gate(path):
                return
            if path == "/api/triage":
                if self._standby_blocked():
                    return
                key, status, note = b.get("check_id"), b.get("status"), b.get("note")
                bad = console.valid_triage(key, status, note) or triagemod.check_extras(b.get("justification"), b.get("expires"), b.get("scope"), b.get("by"))
                if bad:
                    return self._send(400, {"error": bad})
                extra = {k: str(b.get(k)).strip() for k in ("justification", "expires", "scope", "by") if b.get(k)}
                if getattr(self, "_identity", None) and not extra.get("by"):
                    extra["by"] = self._identity
                if not extra.get("by") and cloud.is_cloud():
                    return self._send(403, {"error": "a VEX decision needs a known identity in cloud mode"})
                done = st.set_triage(str(key).strip(), str(status), str(note or ""), extra)
                if done is None:
                    return self._send(409, {"error": "triage store is full (%d entries)" % console.TRIAGE_MAX_ENTRIES})
                st.audit.append(getattr(self, "_identity", None) or "", "vex_decision", str(key), "accepted")
                return self._send(200, {"ok": True, "triage": done})
            if path == "/api/scan":
                if self._standby_blocked():
                    return
                if st.shutting_down:
                    return self._send(503, {"error": "shutting down"})
                if not st.gate.try_acquire():
                    return self._send(429, {"error": "busy"}, headers={"Retry-After": "30"})
                src = str(b.get("source") or "")
                bad = _safe_source(src)
                if bad:
                    return self._send(400, {"error": bad})
                patch, approved, token = bool(b.get("patch")), bool(b.get("approved")), b.get("approval_token")
                if approved and not patch:
                    return self._send(400, {"error": "approved needs patch"})
                if approved and not (isinstance(token, str) and token.strip()):
                    return self._send(400, {"error": "approved needs approval_token: the digest of the plan you reviewed (from a patch run without approval)"})
                idem = str(b.get("idempotency_key") or "").strip()
                if idem and (len(idem) > 64 or not re.fullmatch(r"[A-Za-z0-9_.-]+", idem)):
                    return self._send(400, {"error": "idempotency_key must be at most 64 characters of A-Za-z0-9_.-"})
                if cloud.is_cloud() and approved and not getattr(self, "_identity", None):
                    return self._send(403, {"error": "an approval needs a known identity in cloud mode"})
                if cloud.is_cloud():
                    st.audit.append(getattr(self, "_identity", None) or "", "scan", jobstoremod.sanitize_source(src), "accepted")
                    if approved:
                        st.audit.append(getattr(self, "_identity", None) or "", "patch_approve", jobstoremod.sanitize_source(src), "accepted")
                if idem:
                    prior = st.store.find_by_key(idem)
                    if prior and prior.get("state") in ("queued", "running", "done"):
                        return self._send(200, {"job": prior["id"], "reused": True})
                rec0, _reused = st.store.create(src, idempotency_key=idem)
                jid = rec0["id"]
                st.jobs[jid] = {"state": "running", "source": src}
                self._req_job = jid
                metricsmod.observe_job("running")
                bus = eventsmod.EventBus()
                st.buses[jid] = bus
                bus.publish("job_start", job=jid, source=src)
                if patch:
                    # the approval token never enters an event - only the fact that the plan is/was awaiting approval
                    bus.publish("patch_gate", state="approved" if approved else "awaiting_approval")

                def progress(ev: Dict[str, Any]) -> None:
                    if ev.get("type") == "step_start":
                        bus.publish("step_start", step=ev.get("step"))
                    elif ev.get("type") == "step_end":
                        fields = {"step": ev.get("step"), "ok": bool(ev.get("ok")), "seconds": ev.get("seconds")}
                        if ev.get("error"):
                            fields["error"] = ev["error"]
                        bus.publish("step_end", **fields)

                effective_use_llm = bool(b.get("use_llm")) and (st.cloud_policy["llm_default"] if cloud.is_cloud() else True)

                deadline = limitsmod.Deadline(time.time(), st.limits.job_timeout_s) if st.limits.job_timeout_s > 0 else None

                def work() -> None:
                    job_started = time.time()
                    wdir = tempfile.mkdtemp(prefix="bts_sbom_job_")
                    st._job_dirs[jid] = wdir
                    st._jobs_running += 1
                    keep = False
                    final: Dict[str, Any]
                    try:
                        rec = pipeline.run_project(src, work_root=wdir, out_dir=st.evidence, patch=patch, approved=approved,
                                                   approval_token=token.strip() if approved else None, offline=bool(b.get("offline")),
                                                   use_llm=effective_use_llm, client=st.client if st.client.available else None,
                                                   cache_dir=os.path.join(st.root, "evidence", "cache"), progress=progress,
                                                   deadline=deadline, max_copy_mb=st.limits.max_workcopy_mb)
                        keep = bool(patch and approved and (rec.get("patch") or {}).get("status") == "applied")
                        if patch and approved and getattr(threading.current_thread(), "_approval_identity", None):
                            rec.setdefault("patch", {})["approved_by"] = threading.current_thread()._approval_identity
                        final = {"state": "error" if rec.get("error") else "done", "source": src, "name": rec.get("name"),
                                 "error": rec.get("error"), "metrics": rec.get("metrics"), "artifacts": rec.get("artifacts"),
                                 "stage_errors": rec.get("stage_errors"), "work_copy": wdir if keep else None}
                        bus.publish("final", state=final["state"], job=jid)
                    except Exception as exc:                          # noqa: BLE001
                        final = {"state": "error", "source": src, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
                        bus.publish("error", error_type=type(exc).__name__, severity="error", retryable=False,
                                    recovery_hint="inspect the job record and the server logs, then retry the scan")
                    finally:
                        if not keep:                                  # an applied patch lives in the work copy, so only that one is kept
                            shutil.rmtree(wdir, onerror=workspace._force_remove)
                        st._jobs_running -= 1                         # the gate permit must come back even after 3 failures in a row
                        st.gate.release()
                        st._job_dirs.pop(jid, None)
                    st.jobs[jid] = final                              # published only after the clean-up: "done" implies the copy is gone
                    metricsmod.observe_job(final["state"], time.time() - job_started)
                    st.store.update(jid, state=final["state"], source=jobstoremod.sanitize_source(src), name=final.get("name") or "",
                                    error=final.get("error") or "", metrics=final.get("metrics") or {}, artifacts=final.get("artifacts") or {},
                                    stage_errors=final.get("stage_errors") or {}, work_copy=final.get("work_copy") or "",
                                    patch=patch, approved=approved, offline=bool(b.get("offline")), use_llm=effective_use_llm,
                                    **({"approved_by": wt._approval_identity} if (approved and wt._approval_identity) else {}))
                    st.store.prune()
                    bus.close()

                wt = threading.Thread(target=work, daemon=True)
                wt._approval_identity = getattr(self, "_identity", None) or ""
                wt.start()
                return self._send(202, {"job": jid})
            if path == "/api/chat":
                if self._standby_blocked():
                    return
                q = str(b.get("question") or "").strip()
                if not q:
                    return self._send(400, {"error": "question required"})
                if cloud.is_cloud():
                    hit = guardrailmod.check_input(q)
                    if hit["blocked"]:                        # generic refusal, the request text is never echoed back
                        return self._send(200, {"found": False, "answer": guardrailmod.generic_reply(), "claims": [],
                                                "answer_source": "none", "tools": [], "blocked_by": hit["rule"],
                                                "citation_accuracy": 1.0, "contains_untrusted": False})
                return self._send(200, st.bot().ask(q, project=b.get("project"), use_llm=bool(b.get("use_llm"))))
            if path == "/api/llm" and self._standby_blocked():
                return
            if path == "/api/llm" and not st.cloud_policy["llm_write_allowed"]:
                return self._send(403, {"error": "disabled_in_cloud_mode"})      # no key file is written in cloud mode
            if path == "/api/llm/clear" and self._standby_blocked():
                return
            if path == "/api/llm/clear" and not st.cloud_policy["llm_write_allowed"]:
                return self._send(403, {"error": "disabled_in_cloud_mode"})
            if path == "/api/llm":
                key = str(b.get("api_key") or "").strip()
                base = str(b.get("base_url") or "").strip()
                if len(key) > 400 or len(base) > 300 or len(str(b.get("model") or "")) > 200:
                    return self._send(400, {"error": "field too long"})
                if not key and not base.startswith(("http://localhost", "http://127.0.0.1")):
                    return self._send(400, {"error": "api_key required (only a localhost base_url may connect without one)"})
                out = st.set_llm(b, remember=bool(b.get("remember")))
                st.audit.append(getattr(self, "_identity", None) or "", "llm_connect", str(out.get("model") or "")[:60], "accepted")
                return self._send(200, {"ok": True, "llm": out})
            if path == "/api/llm/clear":
                return self._send(200, {"ok": True, "llm": st.clear_llm()})
            if self._oss("POST", path, {}, b):
                return
            self._send(404, {"error": "not found"})

    return H


def serve(root: str, host: str, port: int, evidence: str, cfg: Optional[str] = None, chat_actions: bool = False) -> int:
    st = State(root, evidence, cfg, chat_actions)
    lock = instancemod.acquire(evidence)                     # single writer for the evidence store (refuses or standby)
    st.instance_lock = lock
    if lock.standby:
        print("standby mode: serving read-only until the evidence lock frees", flush=True)

        def _promote() -> None:
            while True:
                if lock.promote():
                    print("took over the evidence lock: switching to active", flush=True)
                    st.instance_lock = lock.held
                    return
                time.sleep(5.0)

        threading.Thread(target=_promote, daemon=True).start()
    else:
        lock.start_heartbeat()
    httpd = ThreadingHTTPServer((host, port), make_handler(st))
    print("BTS-SBOM serving on http://%s:%d (evidence: %s)" % (host, port, evidence), flush=True)
    pol = st.cloud_policy
    print("cloud mode: %s (policy: %s)" % ("on" if cloud.is_cloud() else "off",
                                           ", ".join("%s=%s" % (k, pol[k]) for k in sorted(pol) if isinstance(pol[k], bool))), flush=True)
    st._drain_s = st.limits.drain_s

    def _drain() -> None:
        """Bounded drain: give running jobs up to BTS_SBOM_DRAIN_S seconds, then record the leftovers as
        interrupted(sigterm), remove their temp copies, and stop the server."""
        end = time.time() + st._drain_s
        while time.time() < end and st._jobs_running > 0:
            time.sleep(0.2)
        for jid in list(st.jobs):
            if st.jobs[jid].get("state") == "running":
                st.store.update(jid, state="interrupted", interrupted_reason="sigterm")
        for jid, wdir in list(st._job_dirs.items()):
            shutil.rmtree(wdir, onerror=workspace._force_remove)
            st._job_dirs.pop(jid, None)
        httpd.shutdown()

    def _on_sigterm(signum: Any, frame: Any) -> None:
        st.shutting_down = True                               # the handler only sets flags; the thread does the heavy work
        threading.Thread(target=_drain, daemon=True).start()

    try:
        import signal
        signal.signal(signal.SIGTERM, _on_sigterm)            # Windows: SIGTERM exists but its delivery is limited - best effort
    except (OSError, ValueError) as _sig_exc:                 # pragma: no cover - platform dependent
        print("SIGTERM handler unavailable: %s" % type(_sig_exc).__name__, flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if not st.shutting_down:
            st.shutting_down = True
            for jid in list(st.jobs):                         # a clean exit records the same honesty as a SIGTERM drain
                if st.jobs[jid].get("state") == "running":
                    st.store.update(jid, state="interrupted", interrupted_reason="sigterm")
        lock.release()                                        # a clean shutdown leaves the store free for the next instance
    return 0
