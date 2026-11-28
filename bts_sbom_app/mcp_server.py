"""MCP server for bts-sbom (MetaNet books: MCP Engineering Handbook + AI Agents with MCP; brief-5 G2).

Model Context Protocol over stdio, JSON-RPC 2.0, stdlib only. The server exposes the SAME capabilities the
HTTP API exposes - tools delegate to existing modules (no second implementation to drift):

  engine_status    -> engine + evidence + book-library + LLM summary (read-only)
  book_search      -> the serve-time book index (books.books_index-style, kind="books" chunks)
  project_overview -> the chat "overview" tool over one analysed project
  chat_ask         -> chat.Chatbot.ask in its read-only form (no analysis / no patch)
  nl2sql           -> the local OSV database in natural language (read-only SELECT, 4-state result)
  run_scan         -> pipeline.run_project on one source (read/record only, no patch); reports stage
                      progress as notifications/progress when the call carries _meta.progressToken

Wire discipline: one JSON-RPC message per line on stdin, one response line per request on stdout, and
NOTHING else is ever written to stdout (a stray print corrupts the protocol). Tool errors travel to the
model as ``result.isError`` + a message - never as a swallowed exception (the 4-state philosophy).
Protocol errors use the standard JSON-RPC codes (-32601 method not found, -32602 invalid params, -32700 parse).

Operator gate (C40): an MCP caller's chat_ask/run_scan ``use_llm=true`` only reaches the server's own LLM
key when the operator sets BTS_SBOM_MCP_ALLOW_LLM=1 - otherwise the call answers deterministically (RAG-only
/ template-only) and says so in ``llm_note``, making 0 outbound LLM calls. No connected MCP client implements
sampling yet, so the server holding its own key (gated) is the pragmatic default rather than MCP sampling.

Usage:  python -m bts_sbom_app --root <repo> mcp            (a client spawns this; it is not interactive)
"""
from __future__ import annotations

import concurrent.futures
import datetime
import hashlib
import json
import os
import shutil
import sys
import tempfile
import time
from typing import Any, Callable, Dict, List, Optional, Tuple

from . import __version__, books as booksmod, chat as chatmod, evals
from .cli import evidence_chunks, load_projects
from .util import clip

_MCP_TIMEOUT = float(os.environ.get("BTS_SBOM_MCP_TIMEOUT", "0") or 0)   # C58: per-call wall budget (0 = off)
_TOOL_STATS: Dict[str, Dict[str, int]] = {}                              # C58: per-tool calls and errors, in-memory


def _audit(s: Session, name: str, args: Any, t0: float, outcome: str, err_head: str) -> None:
    """One audit line per MCP tool call (C58): what ran, how long it took, how it ended - and the per-tool error
    counter a spiking error rate needs. The audit never carries argument VALUES (they are caller data): the keys
    only, plus the outcome. A failed audit write is reported in the stats, never raised into the session."""
    d = round((time.monotonic() - t0) * 1000)
    st = _TOOL_STATS.setdefault(name, {"calls": 0, "errors": 0})
    st["calls"] += 1
    if outcome != "ok":
        st["errors"] += 1
    try:
        path = os.path.join(s.evidence, "mcp_audit.jsonl")
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "a", encoding="utf-8", newline="\n") as fh:
            fh.write(json.dumps({"at": datetime.datetime.now().isoformat(timespec="seconds"), "tool": name,
                                 "arg_keys": sorted(args.keys()) if isinstance(args, dict) else [],
                                 "duration_ms": d, "outcome": outcome,
                                 "error_head": err_head or None}, ensure_ascii=False) + "\n")
    except OSError:
        st.setdefault("audit_write_errors", 0)
        st["audit_write_errors"] += 1


def tool_stats() -> Dict[str, Dict[str, int]]:
    """The per-tool counters (C58): calls, errors, error rate - the input to 'this tool has started failing'."""
    return {k: dict(v, error_rate=round(v["errors"] / v["calls"], 3) if v["calls"] else None) for k, v in sorted(_TOOL_STATS.items())}

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "bts-sbom"

#: C40 operator gate - set to "1" to let chat_ask/run_scan use_llm=true reach the server's own LLM key over MCP.
ALLOW_LLM_ENV = "BTS_SBOM_MCP_ALLOW_LLM"

TOOL_DEFS: List[Dict[str, Any]] = [
    {"name": "engine_status", "description": "Engine version, evidence folder, book-library totals and LLM connection summary (read-only).",
     "inputSchema": {"type": "object", "properties": {}, "required": []}},
    {"name": "book_search", "description": "Search the local architecture/AI book knowledge base; returns book, heading, snippet, scores.",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string", "description": "topic, book title or question"},
                                                      "k": {"type": "integer", "minimum": 1, "maximum": 10}},
                     "required": ["q"]}},
    {"name": "project_overview", "description": "Vulnerability / component / license overview of one analysed project.",
     "inputSchema": {"type": "object", "properties": {"project": {"type": "string", "description": "project id as shown by engine_status"}},
                     "required": ["project"]}},
    {"name": "chat_ask", "description": "Ask a grounded question about an analysed project or the book library; answers cite their source.",
     "inputSchema": {"type": "object", "properties": {"question": {"type": "string"},
                                                      "project": {"type": "string"},
                                                      "use_llm": {"type": "boolean"}},
                     "required": ["question"]}},
    {"name": "nl2sql", "description": "Ask the local OSV vulnerability database in natural language; read-only SELECT, capped rows, 4-state result (success/empty_result/partial_result/access_failure).",
     "inputSchema": {"type": "object", "properties": {"q": {"type": "string",
                                                            "description": "natural-language question over the vulns/pkg_map tables (see bts://nl2sql/catalog)"}},
                     "required": ["q"]}},
    {"name": "run_scan", "description": "Analyse one project (SBOM, licenses, vulnerabilities, remediation plan) and record it to the evidence folder; read/record only, no patch is applied. When the call carries _meta.progressToken, emits one notifications/progress message per completed pipeline stage before the final result.",
     "inputSchema": {"type": "object", "properties": {"source": {"type": "string", "description": "git URL, owner/repo or local folder to analyse"},
                                                      "offline": {"type": "boolean", "description": "skip network license/vulnerability lookups (default false)"},
                                                      "use_llm": {"type": "boolean",
                                                                 "description": "use the server-side LLM for the AI-proposal stage; gated like chat_ask by BTS_SBOM_MCP_ALLOW_LLM"}},
                     "required": ["source"]}},
]


RESOURCES: List[Dict[str, Any]] = [
    {"uri": "bts://tools/catalog", "name": "Tool catalog", "mimeType": "application/json",
     "description": "Every chat tool with its argument contract (chat.TOOL_CATALOG) - the dictionary an orchestrator reads before calling."},
    {"uri": "bts://agent/card", "name": "Agent card", "mimeType": "application/json",
     "description": "The A2A-style skill/gate declaration (same JSON as GET /api/agent-card)."},
    {"uri": "bts://books/notes-index", "name": "Distilled book notes index", "mimeType": "application/json",
     "description": "The knowledge_books/ distilled notes (our own synthesis) - titles only; read notes via the book_search tool or the files themselves."},
    {"uri": "bts://nl2sql/catalog", "name": "NL2SQL catalog", "mimeType": "application/json",
     "description": "The local OSV database catalog (nl2sql.CATALOG): tables, columns and example metrics - what a generated SELECT may read."},
]


def _resource_text(s: Session, uri: str) -> str:
    if uri == "bts://tools/catalog":
        return json.dumps(chatmod.TOOL_CATALOG, ensure_ascii=False, indent=1, default=str)
    if uri == "bts://agent/card":
        from .server import agent_card                     # lazy: keep mcp_server importable without the HTTP stack
        return json.dumps(agent_card(None), ensure_ascii=False, indent=1, default=str)
    if uri == "bts://books/notes-index":
        d = os.path.join(s.root, booksmod.NOTES_DIR)
        rows = []
        for fn in sorted(os.listdir(d)) if os.path.isdir(d) else []:
            if fn.endswith(".md"):
                head = ""
                try:
                    with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                        head = fh.readline().lstrip("# ").strip()[:120]
                except OSError:
                    head = ""
                rows.append({"file": "knowledge_books/" + fn, "title": head})
        return json.dumps({"count": len(rows), "notes": rows}, ensure_ascii=False, indent=1)
    if uri == "bts://nl2sql/catalog":
        from . import nl2sql as nl2sqlmod
        return json.dumps(nl2sqlmod.CATALOG, ensure_ascii=False, indent=1, default=str)
    raise KeyError(uri)


class Session:
    """Lazy per-process state: nothing is loaded until a tool actually needs it (an MCP client may only ever call one)."""

    def __init__(self, root: str, evidence: Optional[str] = None) -> None:
        self.root = root
        self.evidence = evidence or os.path.join(root, "evidence", "runs")
        self._books_dir = booksmod.books_dir(os.path.join(root, "evidence"))
        self._index: Any = None
        self._projects: Optional[Dict[str, Dict[str, Any]]] = None
        self._bot: Optional[chatmod.Chatbot] = None
        self._llm_client: Any = None

    def _projects_map(self) -> Dict[str, Dict[str, Any]]:
        if self._projects is None:
            self._projects = load_projects(self.evidence)
        return self._projects

    def _client(self) -> Any:
        """Lazy ChatClient from the operator's env/config - built once per session. Whether an MCP caller's
        use_llm=true actually reaches it is a separate, per-call gate (C40: see ``_gated_client``)."""
        if self._llm_client is None:
            from .llm import ChatClient
            ledger = os.path.join(self.root, "evidence", ".llm_ledger.json")
            client = ChatClient.from_env(ledger=ledger)     # env vars first, exactly like the HTTP server's State
            if not client.available:
                cfgp = os.path.join(self.root, "evidence", ".llm_config.json")
                if os.path.exists(cfgp):                    # the saved console config (azure_* or exaone keys) next
                    os.environ["BTS_SBOM_LLM_CONFIG"] = cfgp
                    client = ChatClient.from_env(ledger=ledger)
            self._llm_client = client
        return self._llm_client

    def osv_db_path(self) -> str:
        """The local OSV database for the nl2sql/run_scan tools (same resolution as server.State.db_path)."""
        return os.environ.get("BTS_SBOM_OSV_DB_PATH") or os.path.join(self.root, "bts_sbom_osv_local.db")

    def bot(self) -> chatmod.Chatbot:
        if self._bot is None:
            client = self._client()
            pm = self._projects_map()
            self._bot = chatmod.Chatbot(evals.build_index(self.root, evidence_chunks(pm) + booksmod.load_notes(self.root)),
                                        pm, client if client.available else None, None, {}, books=self._books_index())
        return self._bot

    def _books_index(self) -> Any:
        if self._index is None:
            self._index = evals.build_index(self.root, booksmod.load_chunks(self._books_dir) + booksmod.load_notes(self.root))
        return self._index


def _reg_summary(s: Session) -> Dict[str, Any]:
    reg = booksmod.load_registry(s._books_dir)
    if not reg:
        return {"built": False, "hint": "run: bts-sbom-app books <folder>"}
    t = reg.get("totals", {})
    return {"built": True, "built_at": reg.get("built_at"), "files": t.get("files"), "ok": t.get("ok"),
            "duplicates": t.get("duplicates"), "sections": t.get("sections"), "chars": t.get("chars")}


def _gated_client(s: Session, requested_llm: bool) -> Tuple[Any, bool, str]:
    """C40: an MCP caller's use_llm=true only reaches the server's own LLM key when the operator set
    BTS_SBOM_MCP_ALLOW_LLM=1; otherwise the call is forced deterministic and the reason travels in the
    returned note. Returns ``(client_or_None, effective_use_llm, gate_note)``."""
    allowed = os.environ.get(ALLOW_LLM_ENV) == "1"
    if requested_llm and not allowed:
        return None, False, ("MCP operator gate: %s is not set to 1, so this call answered deterministically "
                             "(no server-side LLM key used) - 0 outbound LLM calls" % ALLOW_LLM_ENV)
    if not requested_llm:
        return None, False, ""
    client = s._client()
    ok = bool(client is not None and client.available)
    return (client if ok else None), ok, ""


#: C46 - the product's own 7 canned evaluation questions (quality.REQUIRED_ELEMENTS), read-only, turned into
#: MCP prompt templates. Built at call time (not hardcoded here) so the two never drift apart.
_PROMPT_ARG = {"name": "project", "description": "project id as shown by engine_status", "required": True}


def _prompt_catalog() -> List[Tuple[str, Dict[str, Any]]]:
    from . import quality as qualitymod
    total = len(qualitymod.REQUIRED_ELEMENTS)
    out: List[Tuple[str, Dict[str, Any]]] = []
    for i, (question, elements) in enumerate(qualitymod.REQUIRED_ELEMENTS.items(), start=1):
        name = "canned_question_%d" % i
        fp = hashlib.sha256(question.encode("utf-8")).hexdigest()[:12]
        out.append((name, {
            "description": "Canned product evaluation question %d of %d (quality.REQUIRED_ELEMENTS); a correct "
                           "answer names %d required element(s)." % (i, total, len(elements)),
            "arguments": [dict(_PROMPT_ARG)],
            "question": question,
            "fingerprint": fp,
        }))
    return out


def _render_prompt(entry: Dict[str, Any], args: Dict[str, Any]) -> str:
    return "project={project}: {question}".format(project=args["project"], question=entry["question"])


def _tool_result(s: Session, name: str, args: Dict[str, Any], notify: Optional[Callable[[Dict[str, Any]], None]] = None,
                 progress_token: Any = None) -> Dict[str, Any]:
    if name == "engine_status":
        from . import __version__ as v
        cfg = os.path.join(s.root, "evidence", ".llm_config.json")
        return {"engine": "bts_sbom " + v, "evidence": s.evidence,
                "projects": sorted(s._projects_map()), "books": _reg_summary(s),
                "llm_configured": os.path.exists(cfg), "mcp": {"name": SERVER_NAME, "version": v}}
    if name == "book_search":
        q = str(args.get("q") or "").strip()
        if not q:
            raise ValueError("q is required")
        k = max(1, min(int(args.get("k") or 5), 10))
        idx = s._books_index()
        res = idx.search(q, k=k) if idx is not None else {}
        out = []
        for r in (res.get("results") or [])[:k]:
            ch = r["chunk"]
            m = ch.get("meta") or {}
            out.append({"book": m.get("book") or "", "heading": ch.get("heading") or "", "format": m.get("format") or "",
                        "snippet": clip(" ".join(str(ch["text"]).split()), 240), "rrf": r["rrf"]})
        found = bool(res.get("found"))
        return {"found": found, "results": out,
                "note": "" if found else "no confident passage (below the found threshold)"
                                         " - listed results, if any, are the closest matches, not a confirmed answer"}
    if name == "project_overview":
        name_arg = str(args.get("project") or "")
        rec = s._projects_map().get(name_arg)
        if rec is None:
            raise ValueError("unknown project %r; known: %s" % (name_arg, ", ".join(sorted(s._projects_map())) or "none"))
        lines = []
        for p in chatmod.run_tool(rec, "overview", {}, s._projects_map()):
            lines.extend(p.get("lines") or [])
        return {"project": name_arg, "lines": lines[:40]}
    if name == "chat_ask":
        question = str(args.get("question") or "").strip()
        if not question:
            raise ValueError("question is required")
        requested_llm = bool(args.get("use_llm"))
        _, effective_llm, gate_note = _gated_client(s, requested_llm)
        res = s.bot().ask(question, project=args.get("project") or None, use_llm=effective_llm)
        llm_note = res.get("llm_note") or ""
        if gate_note:
            llm_note = gate_note + ((" | " + llm_note) if llm_note else "")
        return {"found": res.get("found"), "answer": res.get("answer"), "answer_source": res.get("answer_source"),
                "citation_accuracy": res.get("citation_accuracy"), "tools": res.get("tools"),
                "llm_note": llm_note}
    if name == "nl2sql":
        q = str(args.get("q") or "").strip()
        if not q:
            raise ValueError("q is required")
        from . import nl2sql as nl2sqlmod
        dbp = s.osv_db_path()
        if not os.path.exists(dbp):
            return {"question": q, "status": nl2sqlmod.STATE_ACCESS, "rows": [], "sql": None,
                    "note": "the local OSV database is not present on this machine - build it first "
                           "(bts_sbom osvscanner) and check BTS_SBOM_OSV_DB_PATH (looked at %s)" % dbp}
        res = nl2sqlmod.answer(q, db_path=dbp)
        return {"question": q, "status": res.get("status"), "sql": res.get("sql"), "rows": res.get("rows"),
                "source": res.get("source"), "attempts": res.get("attempts"),
                "truncated": bool(res.get("truncated")), "error": res.get("error"),
                "clarification_needed": res.get("clarification_needed")}
    if name == "run_scan":
        source = str(args.get("source") or "").strip()
        if not source:
            raise ValueError("source is required")
        from . import pipeline as pipelinemod
        requested_llm = bool(args.get("use_llm"))
        client, effective_llm, gate_note = _gated_client(s, requested_llm)
        emit_token = progress_token if (notify is not None and progress_token is not None) else None
        count = [0]

        def _emit(event_type: str, stage_name: str, **fields: Any) -> None:
            if emit_token is None or event_type != "step_end":
                return
            count[0] += 1
            ok = bool(fields.get("ok"))
            seconds = float(fields.get("seconds") or 0.0)
            msg = "stage %s %s (%.2fs)" % (stage_name, "ok" if ok else "failed", seconds)
            notify({"jsonrpc": "2.0", "method": "notifications/progress",
                   "params": {"progressToken": emit_token, "progress": count[0], "message": msg}})

        work_root = tempfile.mkdtemp(prefix="bts_sbom_mcp_work_")
        try:
            rec = pipelinemod.run_project(source, work_root=work_root, out_dir=s.evidence,
                                          offline=bool(args.get("offline")), use_llm=effective_llm, client=client,
                                          cache_dir=os.path.join(s.root, "evidence", "cache"),
                                          progress=_emit if emit_token is not None else None)
        finally:
            shutil.rmtree(work_root, ignore_errors=True)
        if rec.get("error"):
            raise ValueError("scan failed: %s" % rec["error"])
        s._projects = None                       # invalidate: the next project_overview/chat_ask call re-reads the new record from disk
        s._bot = None
        out: Dict[str, Any] = {"project": rec.get("name"), "elapsed_s": rec.get("elapsed_s"),
                               "components": len(rec.get("components") or []), "vulns": len(rec.get("vulns") or []),
                               "severity_counts": pipelinemod.severity_counts(rec.get("vulns") or []),
                               "stage_errors": rec.get("stage_errors") or {}, "progress_events": count[0]}
        if gate_note:
            out["llm_note"] = gate_note
        return out
    raise ValueError("unknown tool %r" % name)


def handle(s: Session, msg: Any, notify: Optional[Callable[[Dict[str, Any]], None]] = None) -> Optional[Dict[str, Any]]:
    """One JSON-RPC message in, one response out (None for notifications). Never raises.

    ``notify``, when given, is called with a JSON-RPC notification object for every ``notifications/progress``
    message a long-running tool (``run_scan``) emits while the call is in flight - ``serve_stdio`` wires it to
    write+flush immediately so a client sees progress before the final response. ``None`` (the default, used by
    every direct ``handle()`` call in the test suite) means no mid-call notification is possible; a tool that
    would have emitted one simply skips it - the final result is unaffected."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "not a JSON-RPC 2.0 message"}}
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "params must be an object"}}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": PROTOCOL_VERSION,
                                                        "capabilities": {"tools": {}, "resources": {}, "prompts": {}},
                                                        "serverInfo": {"name": SERVER_NAME, "version": __version__}}}
    if method == "notifications/initialized":
        return None
    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"tools": TOOL_DEFS}}
    if method == "resources/list":
        return {"jsonrpc": "2.0", "id": mid, "result": {"resources": RESOURCES}}
    if method == "resources/read":
        uri = str(params.get("uri") or "")
        try:
            text = _resource_text(s, uri)
        except KeyError:
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"contents": [], "isError": True,
                               "content": [{"type": "text", "text": "unknown resource %r (known: %s)" % (uri, ", ".join(r["uri"] for r in RESOURCES))}]}}
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"contents": [{"uri": uri, "mimeType": next((r["mimeType"] for r in RESOURCES if r["uri"] == uri), "text/plain"),
                                         "text": text}]}}
    if method == "prompts/list":
        cat = _prompt_catalog()
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"prompts": [{"name": nm, "description": e["description"], "arguments": e["arguments"],
                                        "fingerprint": e["fingerprint"]} for nm, e in cat]}}
    if method == "prompts/get":
        pname = str(params.get("name") or "")
        cat = dict(_prompt_catalog())
        entry = cat.get(pname)
        if entry is None:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown prompt %r (known: %s)" % (
                pname, ", ".join(sorted(cat)))}}
        pargs = params.get("arguments") or {}
        if not isinstance(pargs, dict):
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "arguments must be an object"}}
        for spec in entry["arguments"]:
            if spec.get("required") and not str(pargs.get(spec["name"]) or "").strip():
                return {"jsonrpc": "2.0", "id": mid,
                        "error": {"code": -32602, "message": "missing required argument %r for prompt %r" % (spec["name"], pname)}}
        text = _render_prompt(entry, pargs)
        return {"jsonrpc": "2.0", "id": mid,
                "result": {"description": entry["description"],
                          "messages": [{"role": "user", "content": {"type": "text", "text": text}}]}}
    if method == "tools/call":
        name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        if name not in {t["name"] for t in TOOL_DEFS}:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool %r" % name}}
        meta = params.get("_meta")
        token = meta.get("progressToken") if isinstance(meta, dict) else None
        _t0 = time.monotonic()
        outcome, value, err_head = "ok", None, ""
        try:
            if _MCP_TIMEOUT > 0:                           # C58: a bounded call - the work itself is not cancellable
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as _ex:
                    value = _ex.submit(_tool_result, s, name, args, notify, token).result(timeout=_MCP_TIMEOUT)
            else:
                value = _tool_result(s, name, args, notify, token)
        except concurrent.futures.TimeoutError:
            outcome, err_head = "timeout", "timed out after %ss" % _MCP_TIMEOUT
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "tool timed out after %ss - the underlying work is NOT cancelled "
                                                           "(stdlib threads cannot be killed) and may still finish; its result is not reflected here" % _MCP_TIMEOUT}],
                               "isError": True}}
        except (ValueError, KeyError) as exc:
            outcome, err_head = "failed", str(exc)[:200]
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "tool failed: %s" % err_head}], "isError": True}}
        except Exception as exc:                           # noqa: BLE001 - the tool reports, it never crashes the session
            outcome, err_head = "crashed", "%s: %s" % (type(exc).__name__, str(exc)[:180])
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "tool crashed: %s" % err_head},
                                           ], "isError": True}}
        finally:
            _audit(s, name, args, _t0, outcome, err_head)  # C58: every call audited, errors counted per tool
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}],
                                                        "isError": False}}
    if method == "sampling/createMessage":                 # MCP sampling (course 6-1, D2 §20): the SERVER asks the CLIENT's
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601,   # model - but this server HOLDS its own gated client instead
                    "message": "this server does not consume client sampling: it runs its own gated LLM client "
                               "(promptreg + budget + retry ledger); its initialize declares no sampling capability."}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found: %s" % method}}


def serve_stdio(s: Session, reader: Any, writer: Any) -> int:
    """Line-delimited loop. ``reader``/``writer`` are injectable so tests drive the protocol without pipes."""
    def _notify(obj: Dict[str, Any]) -> None:
        writer.write(json.dumps(obj, ensure_ascii=False) + "\n")
        try:
            writer.flush()
        except AttributeError:
            pass

    for line in reader:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error: %s" % str(exc)[:120]}}
        else:
            resp = handle(s, msg, notify=_notify)
        if resp is not None:
            writer.write(json.dumps(resp, ensure_ascii=False) + "\n")
            try:
                writer.flush()
            except AttributeError:
                pass
    return 0
