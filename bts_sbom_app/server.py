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
GET  /api/jobs/<id>/events                 -> the same job as Server-Sent Events (bts-sbom.events.v1, see events.py): job_start,
                                           step_start/step_end per pipeline stage, patch_gate (when a patch was requested),
                                           then exactly one of final/error. ``Last-Event-ID`` (or ``?after=``) resumes after
                                           a drop; periodic heartbeat comment lines keep a quiet connection alive.
GET  /healthz                              -> the process is alive (always 200, no checks)
GET  /readyz                               -> the process can actually serve: evidence folder writable, core importable,
                                           knowledge corpus present. 503 with just the failed check names if not (4-1 probes).
*    /api/oss/...                          -> the OSS Scanner screen (oss_api.py: scan folder / archive / URL, results, reports, notice, compare)
*    /api/arch/...                         -> the Arch Intel screen (arch_api.py: license verdict + AI architecture deep-dive of one source tree)
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
from typing import Any, Dict, List, Optional, Tuple

from . import __version__, actions as actionsmod, arch_api, books, books_api, chat as chatmod, chat_stream, conformance, console, conversation, coverage, engine, events, evals, fleet, oss_api, pipeline, rag, report, sbom, selfcheck, triage as triagemod, workspace
from .cli import evidence_chunks, load_projects, project_records
from .llm import ChatClient
from .util import clip, read_json, write_json

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
_CTYPES = {".html": "text/html", ".js": "application/javascript", ".css": "text/css"}
_SBOM_FILES = {"cdx": ".cdx.json", "spdx": ".spdx.json", "vex": ".vex.json"}
# Seconds a GET /api/jobs/<id>/events connection waits for a new event before writing a heartbeat comment line.
# A module-level name (read fresh on every wait, never captured as a default argument) so tests can shrink it.
EVENTS_HEARTBEAT_SECONDS = 15.0
_READYZ_PROBE_NAME = ".readyz_probe"
MAX_BUSES = 64                                                # event buses kept in memory; the oldest CLOSED ones are dropped first


def _prune_buses(buses: Dict[str, "events.EventBus"], keep: int) -> int:
    """Drop the oldest closed buses until at most ``keep`` remain. A bus that is still open (its job is running) is never dropped,
    so the cap can be exceeded by running jobs only. Returns how many were dropped."""
    dropped = 0
    for jid in list(buses):
        if len(buses) <= keep:
            break
        bus = buses.get(jid)
        if bus is not None and bus.closed and buses.pop(jid, None) is not None:
            dropped += 1
    return dropped
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
        self.buses: Dict[str, events.EventBus] = {}           # one EventBus per job id, same lifetime as the job's entry in self.jobs
        self.lock = threading.Lock()
        if cfg:
            os.environ["BTS_SBOM_LLM_CONFIG"] = cfg
        self.client = ChatClient.from_env(ledger=os.path.join(root, "evidence", ".llm_ledger.json"))
        self.startup_client = self.client                    # a disconnect falls back to what the process was started with
        if not self.client.available:                        # the key entered in the web console survives a restart (evidence/.llm_config.json);
            saved = self.saved_llm_config()                  # an explicit startup configuration (env / --llm-config) still wins over the saved file
            key = str(saved.get("api_key") or saved.get("azure_api_key") or "")   # the file may hold the Azure shape the
            if key:                                                               # console/earlier versions wrote (user-test 2026-11-22)
                base = str(saved.get("base_url") or saved.get("azure_base_url") or "")
                model = str(saved.get("model") or saved.get("azure_deployment") or saved.get("azure_model") or "")
                self.client = ChatClient.from_config(key, base, model, ledger=os.path.join(root, "evidence", ".llm_ledger.json"),
                                                     api_version=str(saved.get("azure_api_version") or "") or None)
        self.triage_path = os.path.join(evidence, ".triage.json")
        self._books_cache: Optional[Tuple[Optional[Tuple[int, int]], Any]] = None   # ((mtime_ns, size) of registry.json, rag.Index)
        self.chat_memory = conversation.ConversationMemory()   # multi-turn continuity: shared across requests, per server process

    def books_dir(self) -> str:
        """The book KB is stable state, not a run artifact: it lives at <root>/evidence/books (same root-based
        location as the LLM ledger), independent of which --evidence runs folder the service was started with."""
        return books.books_dir(os.path.join(self.root, "evidence"))

    def books_index(self):
        """The serve-time index over the ingested books (kind="books"), built once and reused across chat requests
        (``State.bot`` rebuilds the main index per request; the book corpus is far too large for that - ADR-0021).
        Invalidated by the registry.json signature, so an ingest job is picked up without a server restart.
        An empty (no registry) index is still a valid ``rag.Index``: every reader answers honestly on it."""
        path = os.path.join(self.books_dir(), "registry.json")
        try:
            sig = (os.stat(path).st_mtime_ns, os.stat(path).st_size)
        except OSError:
            sig = None
        with self.lock:
            if sig is not None and self._books_cache and self._books_cache[0] == sig:
                return self._books_cache[1]
        idx = rag.Index(books.load_chunks(self.books_dir())) if sig is not None else rag.Index(())
        with self.lock:
            self._books_cache = (sig, idx)
        return idx

    def reset_books_cache(self) -> None:
        with self.lock:
            self._books_cache = None

    def _llm_config_path(self) -> str:
        """The saved console key is stable state, not a run artifact: it lives at <root>/evidence/.llm_config.json
        (the same root-based location as the LLM ledger), so a server started with the default --evidence runs
        folder still finds the key the user chose to keep. Bug found in the user test 2026-11-22: the lookup used
        the --evidence runs folder and silently disconnected every restart that did not pass --evidence evidence."""
        return os.path.join(self.root, "evidence", ".llm_config.json")

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
                os.makedirs(os.path.dirname(self._llm_config_path()), exist_ok=True)
                write_json(self._llm_config_path(), {"api_key": key, **({"base_url": base} if base else {}), **({"model": model} if model else {})})
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
        return d

    def bot(self) -> chatmod.Chatbot:
        projs = load_projects(self.evidence)
        client = self.client if self.client.available else None
        acts = actionsmod.ChatActions(self.root, self.evidence, client=client) if self.chat_actions else None
        return chatmod.Chatbot(evals.build_index(self.root, evidence_chunks(projs) + books.load_notes(self.root)),
                               projs, client, acts, self.triage(),
                               arch_dir=os.path.join(self.evidence, "archintel"), books=self.books_index(),
                               memory=self.chat_memory)

    def stream_bot(self, sink: Any) -> chat_stream.StreamingChatbot:
        """The same wiring as :meth:`bot`, as the observing subclass: the 7 chat-level events go to ``sink``."""
        projs = load_projects(self.evidence)
        client = self.client if self.client.available else None
        acts = actionsmod.ChatActions(self.root, self.evidence, client=client) if self.chat_actions else None
        return chat_stream.StreamingChatbot(evals.build_index(self.root, evidence_chunks(projs) + books.load_notes(self.root)),
                                            projs, client, acts, self.triage(), arch_dir=os.path.join(self.evidence, "archintel"),
                                            books=self.books_index(), memory=self.chat_memory, sink=sink)

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


def agent_card(st: "State") -> Dict[str, Any]:
    """A2A-style agent card (Building Agentic AI Systems, brief-5 books): machine-readable discovery of THIS
    agent's skills, gates and endpoints. A card declares capability, not state - readiness is /readyz, and the
    honesty rules apply here too (securitySchemes says plainly that there is none on localhost)."""
    return {
        "name": "bts-sbom", "version": __version__,
        "description": "Open-source vulnerability / license / SBOM analyzer with an approval-gated patch loop, "
                       "a deterministic license council, a grounded chatbot and a book knowledge base.",
        "url": "http://127.0.0.1", "protocolVersion": "bts-sbom.card.v1",
        "capabilities": {"streaming": True, "pushNotifications": False, "stateTransitionHistory": False},
        "securitySchemes": {"none": {"type": "none", "description": "localhost only, no authentication - do not expose beyond loopback (docs/RUNBOOK.md)"}},
        "handoffSchema": "bts-sbom.handoff.v1",
        "skills": [
            {"id": "scan", "name": "Analyze a source", "gate": "none",
             "description": "git URL / owner-repo / local folder -> components, CVEs, licenses, SBOM, VEX, architecture; the record feeds every other skill.",
             "inputModes": ["git-url", "owner-repo", "local-path", "archive"], "outputModes": ["project-record", "sse-job-events"]},
            {"id": "patch", "name": "Propose and apply upgrades", "gate": "approval-token",
             "description": "plan -> 16-hex approval token -> apply in an isolated work copy with regression check; the token must be text the USER typed.",
             "inputModes": ["plan-preview", "approval-token"], "outputModes": ["patch-result", "sse-job-events"]},
            {"id": "license_council", "name": "Multi-member license verdict", "gate": "deterministic-aggregation",
             "description": "3 independent LLM members + deterministic verdict code; member failures surface as a recoverable/fatal error envelope (handoff.v1).",
             "inputModes": ["license-text"], "outputModes": ["verdict", "error-envelope"]},
            {"id": "chat", "name": "Grounded chatbot", "gate": "citation-verification",
             "description": "tool-routed answers with verified claims; untrusted quotes are marked verbatim; streams 7 chat-level event kinds.",
             "inputModes": ["text"], "outputModes": ["answer-claims", "sse-chat-events"]},
            {"id": "book_search", "name": "Book knowledge base", "gate": "serve-time-index",
             "description": "search the ingested local book library (deterministic extraction, distilled notes; ADR-0021).",
             "inputModes": ["text-query"], "outputModes": ["passages"]},
            {"id": "nl2sql", "name": "Read-only text-to-SQL", "gate": "3-layer-safety",
             "description": "natural-language questions over the local OSV mirror; tokenizer validator + read-only connection + 4-state executor.",
             "inputModes": ["text-query"], "outputModes": ["rows-or-4-state"]},
            {"id": "supply_chain_gate", "name": "Self supply-chain gate", "gate": "trivy-critical-0",
             "description": "build -> Trivy CRITICAL gate -> CycloneDX SBOM -> own-repo SBOM -> serving bench (scripts/supply_chain_gate.py).",
             "inputModes": ["none"], "outputModes": ["gate-report"]},
        ],
        "endpoints": {"/api/chat": "POST answer", "/api/chat/stream": "POST sse-7-events", "/api/scan": "POST job",
                      "/api/jobs/<id>/events": "GET sse-job-events", "/api/books/search": "GET passages",
                      "/api/books/ingest": "POST job", "/api/oss/scan": "POST oss-scan-job",
                      "mcp": "stdio via: python -m bts_sbom_app mcp"},
    }


def _record_file(folder: str) -> str:
    return os.path.join(folder, os.path.basename(folder) + ".json")


def readyz_checks(st: "State") -> List[str]:
    """Names of the readiness probes that fail right now (empty list = ready). Each probe reports only its own name:
    paths, exception text and other internals never reach the caller (this answers an unauthenticated GET)."""
    failed: List[str] = []
    try:
        os.makedirs(st.evidence, exist_ok=True)
        # A name unique to this call/thread: concurrent /readyz requests (the Docker HEALTHCHECK and a human curious
        # at the same moment, say) must never race on the same probe file and have one's os.remove fail because the
        # other already deleted it.
        probe = os.path.join(st.evidence, "%s.%d.%d" % (_READYZ_PROBE_NAME, os.getpid(), threading.get_ident()))
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
    except OSError:
        failed.append("evidence_writable")
    try:
        engine.core_version()
    except Exception:                                             # noqa: BLE001 - readiness probe: name only, never the exception
        failed.append("core_import")
    try:
        kdir = os.path.join(evals.repo_root(), "knowledge")
        if not (os.path.isdir(kdir) and os.listdir(kdir)):
            failed.append("knowledge_corpus")
    except OSError:
        failed.append("knowledge_corpus")
    return failed


def _history_row(name: str, folder: str, rec: Dict[str, Any]) -> Dict[str, Any]:
    m = rec.get("metrics") or {}
    return {"name": name, "source": rec.get("source"), "analysed_at": _mtime_iso(_record_file(folder)), "components": m.get("components"),
            "vulns": m.get("vulns"), "severity": m.get("severity") or {}, "license_resolved_rate": m.get("license_resolved_rate"),
            "patch_status": m.get("patch_status"), "proposal_source": m.get("proposal_source"), "stage_errors": m.get("stage_errors")}


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

        def _arch(self, method: str, path: str, q: Dict[str, Any], body: Dict[str, Any]) -> bool:
            """The Arch Intel screen's API (arch_api.py); False when the path is not one of its routes."""
            hit = arch_api.route(method, path, q, body, self.headers, st, bind=tuple(self.server.server_address[:2]))
            if hit is None:
                return False
            code, obj, ctype, headers = hit
            if isinstance(obj, (bytes, bytearray)):
                self._emit(code, bytes(obj), ctype, headers)
            else:
                self._send(code, obj, ctype, headers)
            return True

        def _books(self, method: str, path: str, q: Dict[str, Any], body: Dict[str, Any]) -> bool:
            """The Book KB screen's API (books_api.py); False when the path is not one of its routes."""
            hit = books_api.route(method, path, q, body, self.headers, st, bind=tuple(self.server.server_address[:2]))
            if hit is None:
                return False
            code, obj, ctype, headers = hit
            if isinstance(obj, (bytes, bytearray)):
                self._emit(code, bytes(obj), ctype, headers)
            else:
                self._send(code, obj, ctype, headers)
            return True

        def _serve_events(self, jid: str, q: Dict[str, Any]) -> None:
            """GET /api/jobs/<jid>/events as text/event-stream. Unknown job -> plain 404 JSON (never a stream).
            Resumes after ``Last-Event-ID`` (header takes precedence over ``?after=``); heartbeats keep an idle
            connection open; the stream ends for good right after a final/error event."""
            bus = st.buses.get(jid)
            if bus is None:
                return self._send(404, {"error": "unknown job"})
            try:
                after = int(self.headers.get("Last-Event-ID") or (q.get("after") or ["0"])[0])
            except (TypeError, ValueError):
                after = 0
            try:
                bus.subscribe()
            except events.TooManySubscribers:
                return self._send(503, {"error": "too many event subscribers for this job (max %d)" % events.EventBus.MAX_SUBSCRIBERS})
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()
                for item in bus.iter_events(after_seq=after, timeout=EVENTS_HEARTBEAT_SECONDS):
                    chunk = b": heartbeat\n\n" if item is None else events.format_sse(item).encode("utf-8")
                    self.wfile.write(chunk)
                    self.wfile.flush()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass                                               # the reader went away mid-stream: nothing left to do
            finally:
                bus.unsubscribe()

        def do_GET(self) -> None:                                    # noqa: N802
            u = urllib.parse.urlsplit(self.path)
            path, q = u.path, urllib.parse.parse_qs(u.query)
            if path in ("/", "/index.html"):
                return self._file(os.path.join(WEB_DIR, "index.html"))
            if path.startswith("/static/"):
                files = static_files()
                rel = urllib.parse.unquote(path[len("/static/"):])
                return self._file(files[rel]) if rel in files else self._send(404, {"error": "not found"})
            if path == "/healthz":
                return self._send(200, {"ok": True})
            if path == "/readyz":
                failed = readyz_checks(st)
                return self._send(503 if failed else 200, {"ready": not failed, "failed": failed})
            if path == "/api/health":
                return self._send(200, {"ok": True, "llm": st.client.describe()})
            if path == "/api/llm":
                return self._send(200, st.llm_status())
            if path == "/api/engine":
                try:
                    core: Any = engine.core_info()
                except ImportError as exc:
                    core = {"error": str(exc)}
                return self._send(200, {"name": "BTS-SBOM", "workflow_version": __version__, "core": core, "llm": st.client.describe(),
                                        "evidence": st.evidence, "projects": len(project_records(st.evidence))})
            if path == "/api/agent-card":
                return self._send(200, agent_card(st))
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
            if path.startswith("/api/arch/jobs/") and path.endswith("/events"):
                jid = path[len("/api/arch/jobs/"):-len("/events")].strip("/")
                return arch_api.serve_events(st, self, jid, q)
            if path.startswith("/api/jobs/") and path.endswith("/events"):
                jid = path[len("/api/jobs/"):-len("/events")].strip("/")
                return self._serve_events(jid, q)
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
            if self._oss("GET", path, q, {}):
                return
            if self._arch("GET", path, q, {}):
                return
            if self._books("GET", path, q, {}):
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:                                   # noqa: N802
            try:
                b = self._body()
            except _BadBody as exc:
                return self._send(exc.code, {"error": str(exc)})
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
                bus = events.EventBus(jid)
                _prune_buses(st.buses, MAX_BUSES - 1)
                st.buses[jid] = bus                                   # registered before the thread starts: an immediate GET .../events never 404s

                def on_progress(event_type: str, name: str, **fields: Any) -> None:
                    bus.publish(event_type, name=name, **fields)

                def work() -> None:
                    wdir = tempfile.mkdtemp(prefix="bts_sbom_job_")
                    keep = False
                    final: Dict[str, Any]
                    try:
                        bus.publish("job_start", source=src)
                    except Exception:                                 # noqa: BLE001 - the job must run even if its own telemetry cannot
                        pass
                    try:
                        rec = pipeline.run_project(src, work_root=wdir, out_dir=st.evidence, patch=patch, approved=approved,
                                                   approval_token=token.strip() if approved else None, offline=bool(b.get("offline")),
                                                   use_llm=bool(b.get("use_llm")), client=st.client if st.client.available else None,
                                                   cache_dir=os.path.join(st.root, "evidence", "cache"), progress=on_progress)
                        keep = bool(patch and approved and (rec.get("patch") or {}).get("status") == "applied")
                        final = {"state": "error" if rec.get("error") else "done", "source": src, "name": rec.get("name"),
                                 "error": rec.get("error"), "metrics": rec.get("metrics"), "artifacts": rec.get("artifacts"),
                                 "stage_errors": rec.get("stage_errors"), "work_copy": wdir if keep else None}
                        try:
                            pstatus = (rec.get("patch") or {}).get("status")
                            if patch and pstatus:                     # one patch_gate event, only when a patch was actually requested
                                if pstatus == "not_approved":
                                    bus.publish("patch_gate", state="awaiting_approval", digest=rec["patch"].get("digest"))
                                elif pstatus != "not_requested":
                                    bus.publish("patch_gate", state="approved")
                            if rec.get("error"):
                                bus.publish("error", error_type="analysis_error", severity="high", retryable=False,
                                            recovery_hint=clip(rec["error"], 200))
                            else:
                                bus.publish("final", state="done")
                        except Exception:                             # noqa: BLE001 - telemetry must never mask the real result below
                            pass
                    except Exception as exc:                          # noqa: BLE001
                        final = {"state": "error", "source": src, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}
                        try:
                            bus.publish("error", error_type=type(exc).__name__, severity="high", retryable=False,
                                        recovery_hint=clip(str(exc), 200))
                        except Exception:                             # noqa: BLE001
                            pass
                    finally:
                        if not keep:                                  # an applied patch lives in the work copy, so only that one is kept
                            shutil.rmtree(wdir, onerror=workspace._force_remove)
                        bus.close()                                    # safety net: idempotent if final/error already closed it
                    st.jobs[jid] = final                              # published only after the clean-up: "done" implies the copy is gone

                threading.Thread(target=work, daemon=True).start()
                return self._send(202, {"job": jid})
            if path == "/api/chat":
                q = str(b.get("question") or "").strip()
                if not q:
                    return self._send(400, {"error": "question required"})
                return self._send(200, st.bot().ask(q, project=b.get("project"), use_llm=bool(b.get("use_llm"))))
            if path == "/api/chat/stream":
                q = str(b.get("question") or "").strip()
                if not q:
                    return self._send(400, {"error": "question required"})
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.end_headers()

                def sink(ev: Dict[str, Any]) -> None:      # live flush per event; a gone reader must not fail the turn
                    try:
                        self.wfile.write(chat_stream.format_stream_sse(ev).encode("utf-8"))
                        self.wfile.flush()
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        pass

                try:
                    st.stream_bot(sink).ask(q, project=b.get("project"), use_llm=bool(b.get("use_llm")))
                except Exception:                          # noqa: BLE001 - the bot already emitted its fatal error envelope
                    pass
                return
            if path == "/api/llm":
                key = str(b.get("api_key") or "").strip()
                base = str(b.get("base_url") or "").strip()
                if len(key) > 400 or len(base) > 300 or len(str(b.get("model") or "")) > 200:
                    return self._send(400, {"error": "field too long"})
                if not key and not base.startswith(("http://localhost", "http://127.0.0.1")):
                    return self._send(400, {"error": "api_key required (only a localhost base_url may connect without one)"})
                return self._send(200, {"ok": True, "llm": st.set_llm(b, remember=bool(b.get("remember")))})
            if path == "/api/llm/clear":
                return self._send(200, {"ok": True, "llm": st.clear_llm()})
            if self._oss("POST", path, {}, b):
                return
            if self._arch("POST", path, {}, b):
                return
            if self._books("POST", path, {}, b):
                return
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
