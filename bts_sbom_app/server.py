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
GET  /api/policy/<project>?distribution=   -> license-policy findings recomputed for binary|saas|internal (includes the project's own copyleft duty)
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
import ipaddress
import json
import math
import os
import shutil
import socket
import tempfile
import threading
import time
import urllib.parse
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__, access, cra_api, escalation as escmod, actions as actionsmod, arch_api, books, books_api, chat as chatmod, chat_stream, conformance, console, conversation, coverage, engine, events, evals, fleet, licenses, oss_api, pipeline, rag, report, sbom, selfcheck, triage as triagemod, workspace
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
MAX_QUESTION_CHARS = 4000                                     # C72: a boundary-condition guard on /api/chat(/stream); exactly this many chars is still accepted
HANDLER_TIMEOUT = float(os.environ.get("BTS_SBOM_HANDLER_TIMEOUT", "15"))   # seconds a connection may stall while the REQUEST is being read (slowloris)
MAX_CONNECTIONS = max(1, int(os.environ.get("BTS_SBOM_MAX_CONNECTIONS", "128")))   # accepted sockets served at once; the rest get an immediate 503
TRUST_FORWARDED_ENV = "BTS_SBOM_TRUST_FORWARDED"                       # =1 only when a trusted proxy (the Container Apps ingress) is the TCP peer
AUTH_FAIL_LIMIT = max(1, int(os.environ.get("BTS_SBOM_AUTH_FAIL_LIMIT", "20")))     # failed credentials per caller per window before 429 (no verification)
HEARTBEAT_SECONDS = max(5.0, float(os.environ.get("BTS_SBOM_SSE_HEARTBEAT_SECONDS", "15")))   # C69: silent-gap SSE keep-alive interval
AUTH_FAIL_WINDOW = max(1.0, float(os.environ.get("BTS_SBOM_AUTH_FAIL_WINDOW_SECONDS", "60")))
MAX_CHAT_RATE_CALLERS = 4096                                  # cap on distinct caller identities tracked by State._chat_hits at once (C10 follow-up);
                                                               # stale/oldest entries are pruned first once exceeded, mirroring MAX_BUSES/_prune_buses above


def _question_error(q: str) -> Optional[str]:
    """C72: None when ``q`` (already stripped) is acceptable, else the 400 body's error message. Mirrors the
    existing empty-question check the two chat routes already had."""
    if not q:
        return "question required"
    if len(q) > MAX_QUESTION_CHARS:
        return "question too long (max %d characters)" % MAX_QUESTION_CHARS
    return None


def _is_private_or_loopback(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    mapped = getattr(addr, "ipv4_mapped", None)
    if mapped is not None:
        addr = mapped
    # not globally routable: RFC1918, loopback, link-local AND the shared address space 100.64.0.0/10 - the Container Apps ingress
    # connects from 100.100.0.x (measured live 2026-11-27: ipaddress.is_private is False for it, so the real client was never seen)
    return addr.is_private or addr.is_loopback or addr.is_link_local or not addr.is_global


def _caller_id(handler: "BaseHTTPRequestHandler") -> str:
    """Best-effort caller identity for the C10 per-caller chat rate limiter, behind Azure Container Apps ingress.

    ACA's own ingress proxy terminates the public connection and opens a NEW one to this container from an
    address inside its private network; it appends the address it saw (the real public caller, when ACA is the
    first hop) as the LAST entry of X-Forwarded-For itself - any EARLIER entry in that header could have been
    forged by the client and is never trusted. So: trust the header's last entry only when the TCP peer this
    socket sees is itself private/loopback (that is the signature of "a proxy, not the public caller, is what
    the socket sees"); otherwise - no proxy in front, e.g. local dev or a direct connection - the TCP peer IS
    the caller, and the header (fully attacker-controlled in that case) is ignored.

    The header is honoured ONLY when the operator says a trusted proxy is in front (``BTS_SBOM_TRUST_FORWARDED=1``, set in the
    Container Apps template): a private/loopback peer alone is not proof of a proxy (red-team finding 2026-11-27: any
    private-network or loopback peer could forge X-Forwarded-For and defeat the limit). Without the switch the TCP peer is the caller.

    Known limitation, stated rather than hidden: a direct, unproxied caller that happens to connect from a
    private/loopback address (local dev, a test harness, a private-network peer) is indistinguishable from
    "behind ACA's ingress" by this rule alone, and could forge X-Forwarded-For to dodge the rate limit. That
    matches the one deployment topology this rule targets (ACA's ingress is the only private-address peer of
    the production container) and the course material's own design; it is not a defence against a trusted
    network peer spoofing its own identity.
    """
    peer = (handler.client_address[0] if handler.client_address else "") or ""
    if os.environ.get(TRUST_FORWARDED_ENV, "").strip() == "1" and _is_private_or_loopback(peer):
        xff = (handler.headers.get("X-Forwarded-For") or "") if handler.headers is not None else ""
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        if parts:
            return parts[-1]
    return peer


def _annotate_budget_note(res: Any, client: "ChatClient") -> None:
    """C33: thread the LLM budget tier into a chat response's existing llm_note field (llm.py computes the
    tier via ChatClient.budget_tier - chat.py itself is never touched). ``res`` is either the /api/chat response
    dict or the /api/chat/stream 'final' SSE event dict - both already carry an ``llm_note`` key. A no-op once
    the tier is back to 'ok'."""
    if not isinstance(res, dict):
        return
    tier = client.budget_tier()
    if tier == "ok":
        return
    note = "LLM daily budget %s (%d/%d calls today)" % (tier, client.calls_today(), client.daily_budget)
    existing = res.get("llm_note") or ""
    res["llm_note"] = (existing + " | " + note) if existing else note


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


def _prune_chat_hits(hits: Dict[str, List[float]], now: float, window: float, keep: int) -> int:
    """Bound State._chat_hits (C10 follow-up): without this, a long-running internet-facing process (this
    app is deployed on Azure Container Apps per the repo's own deploy docs) accumulates one permanent dict
    entry per distinct caller id (e.g. public client IP) ever seen, even once every hit in that caller's
    history has aged out of the sliding window - an unbounded memory leak. Mirrors _prune_buses/MAX_BUSES
    above: first drop any caller whose whole history has already expired out of the window (free - that
    caller has no state worth keeping), then, if still over ``keep``, drop the oldest-inserted remaining
    callers (a rare caller that returns later simply starts a fresh window, same as a brand-new caller).
    Returns how many were dropped."""
    dropped = 0
    for key in list(hits):
        if len(hits) <= keep:
            break
        if not [t for t in hits[key] if t > now - window]:
            del hits[key]
            dropped += 1
    for key in list(hits):
        if len(hits) <= keep:
            break
        del hits[key]
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
        # Bulkhead + Throttling + Queue-Based Load Leveling (Azure architecture-center patterns, AC-617): one
        # background job at a time on this single replica (0.5 vCPU) - an excess POST is refused with 429 +
        # Retry-After instead of fan-out starving the HTTP/SSE side.
        self.max_jobs = max(1, int(os.environ.get("BTS_SBOM_MAX_JOBS", "1")))
        self.jobs_sem = threading.BoundedSemaphore(self.max_jobs)
        self.draining = False                                # SIGTERM: stop accepting new jobs, finish the running ones
        self.access_token = access.configured_token()        # BTS_SBOM_ACCESS_TOKEN: when set, every request but the probes must present it (access.py)
        self._auth_fails: Dict[str, List[float]] = {}        # caller -> monotonic times of failed credentials (bounded like the chat limiter)
        # C10: a global concurrency cap on /api/chat + /api/chat/stream (Bulkhead, same pattern as jobs_sem
        # above, but a separate/tighter semaphore so a scan job and a chat turn never starve each other) PLUS a
        # per-caller sliding-window rate limit, independent of and tighter than the daily LLM ledger. A refusal
        # from either gate never calls st.bot()/st.client, so it never spends that budget.
        self.chat_max_concurrency = max(1, int(os.environ.get("BTS_SBOM_CHAT_MAX_CONCURRENCY", "4")))
        self.chat_sem = threading.BoundedSemaphore(self.chat_max_concurrency)
        self.chat_rate_limit = max(1, int(os.environ.get("BTS_SBOM_CHAT_RATE_LIMIT", "30")))
        self.chat_rate_window = max(1.0, float(os.environ.get("BTS_SBOM_CHAT_RATE_WINDOW_SECONDS", "60")))
        self._chat_hits: Dict[str, List[float]] = {}
        self._chat_hits_lock = threading.Lock()
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

    def acquire_job(self) -> Optional[str]:
        """Bulkhead/Throttling gate for background jobs (Azure architecture-center patterns, AC-617). Returns the
        release callable when a slot is free and the service is not draining, else None - the route answers
        503+Retry-After (draining) or 429+Retry-After (cap reached) instead of fanning out job threads."""
        if self.draining:
            return None
        return self.jobs_sem.release if self.jobs_sem.acquire(blocking=False) else None

    def begin_drain(self, timeout: float = 25.0) -> None:
        """SIGTERM graceful drain (background-jobs best practice: stop accepting new work, finish the running
        items). Marks the state draining, waits up to ``timeout`` for the running job slots to free, then
        returns - the caller exits; ACA's own grace period bounds the wait in production."""
        self.draining = True
        if self.jobs_sem.acquire(blocking=True, timeout=timeout):
            self.jobs_sem.release()                          # everything finished: just confirming the slot is free

    def acquire_chat_slot(self) -> Optional[Callable[[], None]]:
        """Global concurrency cap for /api/chat + /api/chat/stream (C10, Bulkhead - same shape as acquire_job
        above but its own semaphore). Returns the release callable when a slot is free, else None (the route
        answers 429+Retry-After instead of proceeding)."""
        return self.chat_sem.release if self.chat_sem.acquire(blocking=False) else None

    def auth_blocked(self, caller: str) -> Tuple[bool, float]:
        """True (+ seconds to wait) when ``caller`` has failed AUTH_FAIL_LIMIT credentials inside the window: the next attempt is answered
        429 WITHOUT verifying the token, so guessing is rate-limited per caller. A caller that presents the right token never fails."""
        now = time.monotonic()
        with self._chat_hits_lock:
            hist = [t for t in self._auth_fails.get(caller, []) if t > now - AUTH_FAIL_WINDOW]
            self._auth_fails[caller] = hist
            if hist and len(hist) >= AUTH_FAIL_LIMIT:
                return True, max(1.0, hist[0] + AUTH_FAIL_WINDOW - now)
            return False, 0.0

    def auth_failed(self, caller: str) -> None:
        now = time.monotonic()
        with self._chat_hits_lock:
            self._auth_fails.setdefault(caller, []).append(now)
            if len(self._auth_fails) > MAX_CHAT_RATE_CALLERS:
                _prune_chat_hits(self._auth_fails, now, AUTH_FAIL_WINDOW, MAX_CHAT_RATE_CALLERS - 1)

    def chat_rate_check(self, caller: str) -> Tuple[bool, float]:
        """Per-caller sliding-window rate limit (C10), independent of the concurrency cap above - one noisy
        caller is throttled without touching any other caller's quota. Returns (allowed, retry_after_seconds).
        Also bounds State._chat_hits to at most MAX_CHAT_RATE_CALLERS distinct caller identities (pruning
        stale/oldest entries first) so a long-running, internet-facing deployment cannot accumulate one
        permanent dict entry per distinct caller address ever seen."""
        now = time.monotonic()
        with self._chat_hits_lock:
            hist = [t for t in self._chat_hits.get(caller, []) if t > now - self.chat_rate_window]
            if len(hist) >= self.chat_rate_limit:
                self._chat_hits[caller] = hist
                result = False, max(1.0, hist[0] + self.chat_rate_window - now)
            else:
                hist.append(now)
                self._chat_hits[caller] = hist
                result = True, 0.0
            if len(self._chat_hits) > MAX_CHAT_RATE_CALLERS:
                _prune_chat_hits(self._chat_hits, now, self.chat_rate_window, MAX_CHAT_RATE_CALLERS - 1)
            return result

    def db_path(self) -> str:
        """The local OSV database for the nl2sql lane. Resolution: the BTS_SBOM_OSV_DB_PATH env first, then the
        repo-root default the scanner writes to (bts_sbom/_internal/osv_local_db.py:42 uses cwd - the service
        resolves against self.root so the DB is found no matter where the server was launched from)."""
        return os.environ.get("BTS_SBOM_OSV_DB_PATH") or os.path.join(self.root, "bts_sbom_osv_local.db")

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

    def bot(self, trace_id: Optional[str] = None) -> chatmod.Chatbot:
        projs = load_projects(self.evidence)
        client = self.client if self.client.available else None
        acts = actionsmod.ChatActions(self.root, self.evidence, client=client) if self.chat_actions else None
        return chatmod.Chatbot(evals.build_index(self.root, evidence_chunks(projs) + books.load_notes(self.root)),
                               projs, client, acts, self.triage(),
                               arch_dir=os.path.join(self.evidence, "archintel"), books=self.books_index(),
                               memory=self.chat_memory, db_path=self.db_path(), escalations=self.evidence,
                               trace_id=trace_id)

    def stream_bot(self, sink: Any, cancelled: Optional[Any] = None, trace_id: Optional[str] = None) -> chat_stream.StreamingChatbot:
        """The same wiring as :meth:`bot`, as the observing subclass: the 7 chat-level events go to ``sink``.
        ``cancelled`` (C32) is the reader-gone predicate; ``trace_id`` (C25) rides into escalations and the final event."""
        projs = load_projects(self.evidence)
        client = self.client if self.client.available else None
        acts = actionsmod.ChatActions(self.root, self.evidence, client=client) if self.chat_actions else None
        return chat_stream.StreamingChatbot(evals.build_index(self.root, evidence_chunks(projs) + books.load_notes(self.root)),
                                            projs, client, acts, self.triage(), arch_dir=os.path.join(self.evidence, "archintel"), db_path=self.db_path(),
                                            books=self.books_index(), memory=self.chat_memory, sink=sink, escalations=self.evidence,
                                            cancelled=cancelled, trace_id=trace_id)

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
        "securitySchemes": ({"accessToken": {"type": "http", "scheme": "basic", "description": "shared access token (BTS_SBOM_ACCESS_TOKEN) as the Basic password, a Bearer token or X-BTS-Token; /healthz and /readyz are open"}}
                            if st is not None and getattr(st, "access_token", None) else
                            {"none": {"type": "none", "description": "localhost only, no authentication - do not expose beyond loopback (docs/RUNBOOK.md)"}}),
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
        timeout = HANDLER_TIMEOUT                                  # StreamRequestHandler.setup() applies it to the socket: a stalled client is dropped
        server_version = "bts-sbom"
        sys_version = ""

        def version_string(self) -> str:                           # no interpreter / stdlib version to anonymous callers
            return self.server_version

        def log_message(self, *a: Any) -> None:
            pass

        def _emit(self, code: int, body: bytes, ctype: str, headers: Optional[Dict[str, str]] = None,
                  cache: Optional[str] = None) -> None:
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            # api-implementation best practice (AC-618): mutable API responses are never cached; served files
            # (downloads, static assets) are immutable for the revision's lifetime, so a short max-age is safe
            self.send_header("Cache-Control", cache or "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Correlation-ID", getattr(self, "_cid", "") or "-")
            if ctype == "text/html":
                self.send_header("Content-Security-Policy", _CSP)
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            if os.environ.get("BTS_SBOM_DEBUG_CALLER") == "1" and getattr(self, "_authed", False):   # diagnosis aid for token holders only, off by default
                self.send_header("X-BTS-Caller-Debug", "peer=%s xff=%s eea=%s id=%s" % (
                    (self.client_address or ("",))[0], (self.headers.get("X-Forwarded-For") or "")[:200], (self.headers.get("X-Envoy-External-Address") or "")[:80], _caller_id(self)))
            self.end_headers()
            self.wfile.write(body)

        def _send(self, code: int, obj: Any, ctype: str = "application/json", headers: Optional[Dict[str, str]] = None) -> None:
            body = (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, default=str)).encode("utf-8")
            self._emit(code, body, ctype, headers)

        def _linger(self) -> None:
            """Lingering close after an early refusal: finish our side, then swallow what the client still sends (bounded) so the OS does not
            answer the unread bytes with a connection reset that can destroy the response we just wrote (seen as a flaky WinError 10053)."""
            try:
                self.connection.shutdown(socket.SHUT_WR)
                self.connection.settimeout(0.5)
                for _ in range(16):
                    if not self.connection.recv(65536):
                        break
            except OSError:
                pass

        def _gate(self, path: str) -> bool:
            """Access-token gate (access.py): True when the request may proceed; otherwise a 401 with the Basic challenge has been sent."""
            if access.exempt(path) or not st.access_token:
                return True
            caller = _caller_id(self)
            blocked, retry = st.auth_blocked(caller)
            if blocked:                                            # too many failures from this caller: refuse WITHOUT checking the token
                self._send(429, {"error": "too many failed attempts", "correlation_id": getattr(self, "_cid", "")}, headers={"Retry-After": str(int(retry) + 1)})
                return False
            if access.authorized(self.headers, st.access_token):
                self._authed = True
                return True
            st.auth_failed(caller)
            self._send(401, {"error": "authentication required", "correlation_id": getattr(self, "_cid", "")}, headers=access.challenge())
            return False

        def _chat_admit(self) -> Optional[Callable[[], None]]:
            """C10 gate for /api/chat and /api/chat/stream: the per-caller rate limit first (so a throttled
            caller never takes a concurrency slot from someone else), then the global concurrency cap. Returns
            the release callable to call once the turn is done, or None once a 429 has already been sent - in
            neither refusal case does this touch st.bot()/st.client, so the daily LLM budget is never spent."""
            caller = _caller_id(self)
            allowed, retry_after = st.chat_rate_check(caller)
            if not allowed:
                self._send(429, {"error": "rate limit exceeded for this caller - retry shortly"},
                          headers={"Retry-After": str(int(math.ceil(retry_after)))})
                return None
            release = st.acquire_chat_slot()
            if release is None:
                self._send(429, {"error": "too many concurrent chat requests - retry shortly"},
                          headers={"Retry-After": "2"})
                return None
            return release

        def _file(self, path: str) -> None:
            ctype = _CTYPES.get(os.path.splitext(path)[1], "application/octet-stream")
            try:
                with open(path, "rb") as fh:
                    self._emit(200, fh.read(), ctype, cache="public, max-age=60")
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
            except (ValueError, RecursionError):                       # deep nesting raises RecursionError, not ValueError
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

        def _cra(self, method: str, path: str, q: Dict[str, Any], body: Dict[str, Any]) -> bool:
            """The EU CRA compliance screen's API (cra_api.py); False when the path is not one of its routes."""
            hit = cra_api.route(method, path, q, body, self.headers, st, bind=tuple(self.server.server_address[:2]))
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
            self._cid = uuid.uuid4().hex[:12]
            try:
                self._do_get()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass                                                 # the client went away mid-response: nothing to answer
            except Exception:
                import traceback
                traceback.print_exc()                                # server log only - never the response body
                try:
                    self._send(500, {"error": "internal error", "correlation_id": self._cid})
                except OSError:
                    pass

        def _do_get(self) -> None:
            u = urllib.parse.urlsplit(self.path)
            path, q = u.path, urllib.parse.parse_qs(u.query)
            if not self._gate(path):
                return
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
            if path == "/api/escalations":                           # the handoff log: open / resolved escalations (data for tuning triggers and wording)
                want = (q.get("status") or ["all"])[0]
                if want not in ("all", "open", "resolved"):
                    return self._send(400, {"error": "status must be all, open or resolved"})
                rows = [dict(s, id=i) for i, s in sorted(escmod.load(st.evidence).items()) if want == "all" or s["status"] == want]
                return self._send(200, {"escalations": rows, "count": len(rows)})
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
            for prefix in ("/api/conformance/", "/api/changes/", "/api/vex/", "/api/coverage/", "/api/policy/"):
                if path.startswith(prefix):
                    hit = st.project(urllib.parse.unquote(path[len(prefix):]))
                    if hit is None:
                        return self._send(404, {"error": "unknown project"})
                    folder, rec = hit
                    if prefix == "/api/coverage/":
                        return self._send(200, coverage.build(rec, st.triage()))
                    if prefix == "/api/policy/":
                        # license-policy findings recomputed for a distribution model (the pane's selector);
                        # includes the project's OWN copyleft duty (u-boot measured 2026-11-23)
                        dist = (q.get("distribution") or ["binary"])[0]
                        if dist not in ("binary", "saas", "internal"):
                            return self._send(400, {"error": "distribution must be binary|saas|internal"})
                        lic = rec.get("license") or {}
                        return self._send(200, {"project": rec["name"], "distribution": dist,
                                                "project_license": lic.get("project_license"),
                                                "findings": licenses.policy_findings(rec.get("components") or [],
                                                                                     {"distribution": dist},
                                                                                     lic.get("project_license") or "")})
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
            if path.startswith("/api/db/schema"):
                dbp = st.db_path()
                if not os.path.exists(dbp):
                    return self._send(404, {"error": "the local OSV database is not present - build it with the scanner or set BTS_SBOM_OSV_DB_PATH"})
                from . import nl2sql as nl2sql_mod
                import sqlite3 as _sq
                conn = _sq.connect("file:%s?mode=ro" % dbp.replace("\\", "/"), uri=True)
                try:
                    tables = [r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")]
                    out = {}
                    for tb in tables:
                        out[tb] = conn.execute("SELECT COUNT(*) FROM %s" % tb).fetchone()[0]
                finally:
                    conn.close()
                return self._send(200, {"db": dbp, "tables": out})
            if path.startswith("/api/code-metrics/"):
                hit = st.project(urllib.parse.unquote(path[len("/api/code-metrics/"):]))
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                folder, rec = hit
                fns = ((rec.get("arch") or {}).get("code") or {}).get("functions") or []
                if not fns:
                    return self._send(404, {"error": "this project has no function-level analysis (Python-only lane)"})
                head = "name,file,line,complexity,nesting,loc,sloc,fan_in,fan_out"
                rows = "\n".join(",".join(str(f.get(k)) for k in
                                          ("name", "file", "line", "complexity", "nesting", "loc", "sloc", "fan_in", "fan_out"))
                                 for f in fns)
                return self._send(200, head + "\n" + rows, "text/csv",
                                  {"Content-Disposition": 'attachment; filename="%s-code-metrics.csv"' % rec.get("name", "project")})
            if path.startswith("/api/code-butterfly/"):
                hit = st.project(urllib.parse.unquote(path[len("/api/code-butterfly/"):]))
                if hit is None:
                    return self._send(404, {"error": "unknown project"})
                folder, rec = hit
                code = (rec.get("arch") or {}).get("code") or {}
                fname = (q.get("function") or [""])[0].strip()
                if not fname:
                    return self._send(400, {"error": "function required (?function=<name>)"})
                try:
                    from . import code_intel as _ci
                    bf = _ci.butterfly(code, fname)
                except ImportError:
                    bf = None
                if bf is None:
                    return self._send(404, {"error": "unknown function %r in this project's code intel" % fname})
                return self._send(200, bf)
            if path == "/api/ui/catalog":                            # A2UI-style card-catalog negotiation (docs/A2UI_INTEGRATION.md)
                from . import ui_cards as _uic
                return self._send(200, {"catalog": _uic.catalog_doc()})
            if path == "/api/diagrams":                              # the EA-17.2 catalog (ADR-0024): no project needed
                from . import diagrams as _dg
                return self._send(200, {"catalog": _dg.catalog_doc()})
            if path.startswith("/api/diagrams/"):
                from . import diagrams as _dg
                kind = urllib.parse.unquote(path[len("/api/diagrams/"):]).strip().lower()
                if kind not in _dg.CATALOG:
                    return self._send(404, {"error": "unknown diagram kind %r (GET /api/diagrams lists the catalog)" % kind})
                rec = None
                pname = (q.get("project") or [""])[0]
                if pname:
                    hit = st.project(urllib.parse.unquote(pname))
                    if hit is None:
                        return self._send(404, {"error": "unknown project"})
                    rec = hit[1]
                arch_dir = os.path.join(st.evidence, "archintel")
                doc = _dg.latest_arch_doc(arch_dir) if _dg.CATALOG[kind].get("arch_doc") else None
                d = _dg.build(kind, rec, doc, target=(q.get("target") or [""])[0], spec=(q.get("spec") or [""])[0][:400])
                return self._send(200, d)
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
            if self._cra("GET", path, q, {}):
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:                                   # noqa: N802
            self._cid = uuid.uuid4().hex[:12]
            try:
                self._do_post()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass                                                 # the client went away mid-response: nothing to answer
            except Exception:
                import traceback
                traceback.print_exc()                                # server log only - never the response body
                try:
                    self._send(500, {"error": "internal error", "correlation_id": self._cid})
                except OSError:
                    pass

        def _do_post(self) -> None:
            if not self._gate(urllib.parse.urlsplit(self.path).path):      # before the body is read: an unauthenticated POST costs nothing
                return self._linger()
            try:
                b = self._body()
            except _BadBody as exc:
                self._send(exc.code, {"error": str(exc)})
                return self._linger()
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/api/db/query"):
                dbp = st.db_path()
                if not os.path.exists(dbp):
                    return self._send(404, {"error": "the local OSV database is not present - build it with the scanner or set BTS_SBOM_OSV_DB_PATH"})
                question = (b.get("q") or "").strip()
                if not question:
                    return self._send(400, {"error": "q required"})
                from . import nl2sql as nl2sql_mod
                client = st.client if st.client.available else None
                res = nl2sql_mod.answer(question, db_path=dbp, client=client)
                return self._send(200, res)
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
                release = st.acquire_job()
                if release is None:                                   # bulkhead/throttle: one job at a time, or draining
                    if st.draining:
                        return self._send(503, {"error": "the service is draining - new jobs are not accepted", "job": None},
                                          headers={"Retry-After": "60"})
                    return self._send(429, {"error": "another background job is running on this single-replica service - retry shortly",
                                            "job": None}, headers={"Retry-After": "30"})
                st.jobs[jid] = {"state": "running", "source": src, "trace": self._cid}
                bus = events.EventBus(jid)
                _prune_buses(st.buses, MAX_BUSES - 1)
                st.buses[jid] = bus                                   # registered before the thread starts: an immediate GET .../events never 404s

                def on_progress(event_type: str, name: str, **fields: Any) -> None:
                    bus.publish(event_type, name=name, **fields)

                def work() -> None:
                    try:
                        _scan_work()
                    finally:
                        release()

                def _scan_work() -> None:
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
            if path.startswith("/api/escalations/") and path.endswith("/resolve"):
                esc_id = path[len("/api/escalations/"):-len("/resolve")]
                try:
                    return self._send(200, {"ok": True, "escalation": escmod.resolve(st.evidence, esc_id, b.get("note"), b.get("by"))})
                except KeyError:
                    return self._send(404, {"error": "unknown escalation"})
                except ValueError as exc:
                    return self._send(400, {"error": str(exc)})
            if path == "/api/chat":
                q = str(b.get("question") or "").strip()
                bad = _question_error(q)                    # C72: empty or over MAX_QUESTION_CHARS -> 400
                if bad:
                    return self._send(400, {"error": bad})
                release = self._chat_admit()                # C10: concurrency cap + per-caller rate limit
                if release is None:
                    return
                try:
                    res = st.bot(trace_id=self._cid).ask(q, project=b.get("project"), use_llm=bool(b.get("use_llm")))
                finally:
                    release()
                _annotate_budget_note(res, st.client)        # C33: budget tier -> the existing llm_note field
                return self._send(200, res)
            if path == "/api/chat/stream":
                q = str(b.get("question") or "").strip()
                bad = _question_error(q)                    # C72: empty or over MAX_QUESTION_CHARS -> 400
                if bad:
                    return self._send(400, {"error": bad})
                release = self._chat_admit()                # C10: concurrency cap + per-caller rate limit
                if release is None:
                    return
                wlock = threading.Lock()                    # C69: the frame writer and the heartbeat share one socket
                gone = threading.Event()                    # C32: set when a write learns the reader left

                def _w(raw: bytes) -> bool:
                    try:
                        with wlock:
                            self.wfile.write(raw)
                            self.wfile.flush()
                        return True
                    except (BrokenPipeError, ConnectionResetError, OSError):
                        gone.set()                          # the turn's remaining tools are cancelled from here
                        return False
                try:
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream; charset=utf-8")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("X-Content-Type-Options", "nosniff")
                    self.send_header("X-Correlation-ID", self._cid)    # C25: the same id the final event carries
                    self.end_headers()

                    stop_beat = threading.Event()

                    def beat() -> None:                     # C69: SSE comment lines during long silent gaps (a slow LLM
                        while not stop_beat.wait(HEARTBEAT_SECONDS):   # call, say) keep proxies from cutting the stream
                            if not _w(b": heartbeat\n\n"):
                                return

                    beat_t = threading.Thread(target=beat, daemon=True)
                    beat_t.start()

                    def sink(ev: Dict[str, Any]) -> None:      # live flush per event; a gone reader must not fail the turn
                        if ev.get("kind") == "final":
                            _annotate_budget_note(ev, st.client)    # C33
                        _w(chat_stream.format_stream_sse(ev).encode("utf-8"))

                    try:
                        st.stream_bot(sink, cancelled=gone.is_set, trace_id=self._cid) \
                          .ask(q, project=b.get("project"), use_llm=bool(b.get("use_llm")))
                    except Exception:                          # noqa: BLE001 - the bot already emitted its fatal error envelope
                        pass
                    finally:
                        stop_beat.set()
                        beat_t.join(timeout=2)
                finally:
                    release()
                return
            if path == "/api/reimpl":
                # the clean-room lane (brief 6): source -> interface spec + diagram -> NEW code -> copy gate ->
                # generated tests. Artifacts land under evidence/reimpl/<job>; publish is CLI-only (an HTTP
                # caller must not choose filesystem destinations). Live via the job's SSE stream.
                src = str(b.get("source") or "")
                bad = _safe_source(src)
                if bad:
                    return self._send(400, {"error": bad})
                comp = str(b.get("component") or "").strip()
                if not comp or comp.startswith("/") or ".." in comp:
                    return self._send(400, {"error": "component required (a module path inside the source, no traversal)"})
                jid = uuid.uuid4().hex[:10]
                release = st.acquire_job()
                if release is None:
                    if st.draining:
                        return self._send(503, {"error": "the service is draining - new jobs are not accepted"},
                                          headers={"Retry-After": "60"})
                    return self._send(429, {"error": "another background job is running on this single-replica service - retry shortly"},
                                      headers={"Retry-After": "30"})
                st.jobs[jid] = {"state": "running", "kind": "reimpl", "source": src, "component": comp, "trace": self._cid}
                bus = events.EventBus(jid)
                _prune_buses(st.buses, MAX_BUSES - 1)
                st.buses[jid] = bus

                def work() -> None:
                    try:
                        _reimpl_work()
                    finally:
                        release()

                def _reimpl_work() -> None:
                    from . import reimpl as reimpl_mod
                    out = os.path.join(st.evidence, "reimpl", jid)
                    final: Dict[str, Any]

                    def on_progress(ev: Dict[str, Any]) -> None:
                        try:
                            ok = not ev["event"].endswith("_failed") and ev["event"] not in ("refused", "copy_gate_failed", "publish_refused")
                            bus.publish("step_end", name=ev["event"], ok=ok, seconds=0.0)
                        except Exception:                      # noqa: BLE001 - telemetry never kills the lane
                            pass

                    try:
                        client = st.client if (st.client.available and bool(b.get("use_llm"))) else None

                        def patterns_provider(iface: Dict[str, Any]) -> Dict[str, Any]:
                            """Two-tier inference (AC-619): the merged book+notes index first, the deployment
                            model's own knowledge as the fallback tier when the books don't cover the domain."""
                            if not bool(b.get("patterns", True)):
                                return {"tier": "none", "queries": [], "patterns": [], "book_hits": 0}
                            try:
                                chunks = books.load_chunks(st.books_dir()) + books.load_notes(st.root)
                                idx = rag.Index(chunks) if chunks else None
                            except Exception:                  # noqa: BLE001 - no KB: tier "model" still stands
                                idx = None
                            return reimpl_mod.infer_patterns(iface, book_index=idx,
                                                             client=client if client is not None else None)

                        final = reimpl_mod.reimpl(src, comp, out, client=client,
                                                  license_ok=bool(b.get("license_ok", True)),
                                                  why=str(b.get("why") or "compliance-risky license (clean-room reimplementation)"),
                                                  patterns_provider=patterns_provider if client is not None else None,
                                                  progress=on_progress)
                    except Exception as exc:                   # noqa: BLE001 - the job reports, it never vanishes
                        final = {"verdict": "error", "reason": str(exc)[:200]}
                    try:
                        bus.publish("final", state=final.get("verdict", "error"))
                    except Exception:                          # noqa: BLE001
                        pass
                    st.jobs[jid] = dict(final, state=("done" if final.get("verdict") == "ok" else "error"),
                                        kind="reimpl", source=src, component=comp)
                    bus.close()

                threading.Thread(target=work, daemon=True).start()
                return self._send(202, {"job": jid})
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
            if self._cra("POST", path, {}, b):
                return
            self._send(404, {"error": "not found"})

    return H


class CappedServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that never serves more than MAX_CONNECTIONS sockets at once: an excess connection is answered 503 and closed
    at once instead of spawning one more thread (slowloris / connection flooding on a 0.5 vCPU replica). The per-connection read
    timeout (HANDLER_TIMEOUT) reclaims the slots of stalled clients."""
    daemon_threads = True

    def __init__(self, *args: Any, max_connections: Optional[int] = None, **kw: Any):
        self._slots = threading.BoundedSemaphore(max_connections or MAX_CONNECTIONS)
        super().__init__(*args, **kw)

    def process_request(self, request: Any, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.0 503 Service Unavailable" + b"\r\n" + b"Retry-After: 5" + b"\r\n" + b"Content-Length: 0" + b"\r\n" + b"\r\n")
            except OSError:
                pass
            self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: Any, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


SEED_ENV = "BTS_SBOM_OSV_SEED_DB"


def seed_local_osv_db(env: Optional[Dict[str, str]] = None) -> str:
    """Copy the OSV snapshot from a seed location (the evidence volume) to the LOCAL path the scanner and nl2sql use.

    SQLite on a network file share (Azure Files / SMB) cannot take the scanner's concurrent cache writes: every
    ``store_exact`` waited out the 5 s lock timeout and a full NodeGoat scan took 780 s instead of ~355 s (measured on
    the 2026-11-27 deployment). ``BTS_SBOM_OSV_SEED_DB`` names the read-mostly snapshot, ``BTS_SBOM_OSV_DB_PATH`` the
    local disk copy; the copy is made once, only when the local file is absent. Returns what happened ('' = nothing to do)."""
    e = env if env is not None else os.environ
    seed, dest = e.get(SEED_ENV, ""), e.get("BTS_SBOM_OSV_DB_PATH", "")
    if not seed or not dest or os.path.abspath(seed) == os.path.abspath(dest):
        return ""
    if os.path.exists(dest):
        return "present"
    if not os.path.isfile(seed):
        return "no-seed"
    try:
        os.makedirs(os.path.dirname(os.path.abspath(dest)), exist_ok=True)
        shutil.copyfile(seed, dest + ".part")
        os.replace(dest + ".part", dest)
    except OSError as exc:
        print("warning: could not copy the OSV snapshot %s -> %s (%s); the scanner will build its own cache" % (seed, dest, type(exc).__name__), flush=True)
        return "failed"
    return "copied"


def serve(root: str, host: str, port: int, evidence: str, cfg: Optional[str] = None, chat_actions: bool = False) -> int:
    seeded = seed_local_osv_db()
    if seeded:
        print("OSV snapshot: %s" % seeded, flush=True)
    st = State(root, evidence, cfg, chat_actions)

    def _warm_prompt_digest() -> None:                              # the chat version stamp needs it: pay the one-time parse before the first turn
        try:
            from . import promptreg
            promptreg.digest(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
        except Exception:                                           # a stamp that cannot be computed must never stop the service
            pass

    threading.Thread(target=_warm_prompt_digest, daemon=True).start()
    httpd = CappedServer((host, port), make_handler(st))
    print("BTS-SBOM serving on http://%s:%d (evidence: %s; access-token gate %s)" % (host, port, evidence, "ON" if st.access_token else "off"), flush=True)

    def _sigterm(signum: int, frame: Any) -> None:
        # background-jobs best practice (AC-618): stop accepting NEW jobs, let the running one finish inside the
        # platform's grace period, then exit. A full checkpoint/resume would be the production-grade version.
        st.begin_drain(timeout=20.0)
        threading.Thread(target=httpd.shutdown, daemon=True).start()

    try:
        import signal
        signal.signal(signal.SIGTERM, _sigterm)                   # ACA's stop signal; local Ctrl-C keeps its hard interrupt
    except (ValueError, OSError):                                 # not the main thread / restricted platform
        pass
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()
    return 0
