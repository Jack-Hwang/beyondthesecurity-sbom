"""MCP server for bts-sbom (MetaNet books: MCP Engineering Handbook + AI Agents with MCP; brief-5 G2).

Model Context Protocol over stdio, JSON-RPC 2.0, stdlib only. The server exposes the SAME capabilities the
HTTP API exposes - tools delegate to existing modules (no second implementation to drift):

  engine_status    -> engine + evidence + book-library + LLM summary (read-only)
  book_search      -> the serve-time book index (books.books_index-style, kind="books" chunks)
  project_overview -> the chat "overview" tool over one analysed project
  chat_ask         -> chat.Chatbot.ask in its read-only form (no analysis / no patch)

Wire discipline: one JSON-RPC message per line on stdin, one response line per request on stdout, and
NOTHING else is ever written to stdout (a stray print corrupts the protocol). Tool errors travel to the
model as ``result.isError`` + a message - never as a swallowed exception (the 4-state philosophy).
Protocol errors use the standard JSON-RPC codes (-32601 method not found, -32602 invalid params, -32700 parse).

Usage:  python -m bts_sbom_app --root <repo> mcp            (a client spawns this; it is not interactive)
"""
from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Optional

from . import __version__, books as booksmod, chat as chatmod, evals
from .cli import evidence_chunks, load_projects
from .util import clip

PROTOCOL_VERSION = "2024-11-05"
SERVER_NAME = "bts-sbom"

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
]


RESOURCES: List[Dict[str, Any]] = [
    {"uri": "bts://tools/catalog", "name": "Tool catalog", "mimeType": "application/json",
     "description": "Every chat tool with its argument contract (chat.TOOL_CATALOG) - the dictionary an orchestrator reads before calling."},
    {"uri": "bts://agent/card", "name": "Agent card", "mimeType": "application/json",
     "description": "The A2A-style skill/gate declaration (same JSON as GET /api/agent-card)."},
    {"uri": "bts://books/notes-index", "name": "Distilled book notes index", "mimeType": "application/json",
     "description": "The knowledge_books/ distilled notes (our own synthesis) - titles only; read notes via the book_search tool or the files themselves."},
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

    def _projects_map(self) -> Dict[str, Dict[str, Any]]:
        if self._projects is None:
            self._projects = load_projects(self.evidence)
        return self._projects

    def bot(self) -> chatmod.Chatbot:
        if self._bot is None:
            from .llm import ChatClient
            ledger = os.path.join(self.root, "evidence", ".llm_ledger.json")
            client = ChatClient.from_env(ledger=ledger)     # env vars first, exactly like the HTTP server's State
            if not client.available:
                cfgp = os.path.join(self.root, "evidence", ".llm_config.json")
                if os.path.exists(cfgp):                    # the saved console config (azure_* or exaone keys) next
                    os.environ["BTS_SBOM_LLM_CONFIG"] = cfgp
                    client = ChatClient.from_env(ledger=ledger)
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


def _tool_result(s: Session, name: str, args: Dict[str, Any]) -> Dict[str, Any]:
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
        res = s.bot().ask(question, project=args.get("project") or None, use_llm=bool(args.get("use_llm")))
        return {"found": res.get("found"), "answer": res.get("answer"), "answer_source": res.get("answer_source"),
                "citation_accuracy": res.get("citation_accuracy"), "tools": res.get("tools"),
                "llm_note": res.get("llm_note") or ""}
    raise ValueError("unknown tool %r" % name)


def handle(s: Session, msg: Any) -> Optional[Dict[str, Any]]:
    """One JSON-RPC message in, one response out (None for notifications). Never raises."""
    if not isinstance(msg, dict) or msg.get("jsonrpc") != "2.0":
        return {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "not a JSON-RPC 2.0 message"}}
    mid, method, params = msg.get("id"), msg.get("method"), msg.get("params") or {}
    if not isinstance(params, dict):
        return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "params must be an object"}}
    if method == "initialize":
        return {"jsonrpc": "2.0", "id": mid, "result": {"protocolVersion": PROTOCOL_VERSION,
                                                        "capabilities": {"tools": {}},
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
    if method == "tools/call":
        name = str(params.get("name") or "")
        args = params.get("arguments") or {}
        if name not in {t["name"] for t in TOOL_DEFS}:
            return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32602, "message": "unknown tool %r" % name}}
        try:
            value = _tool_result(s, name, args)
        except (ValueError, KeyError) as exc:
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "tool failed: %s" % str(exc)[:200]}], "isError": True}}
        except Exception as exc:                           # noqa: BLE001 - the tool reports, it never crashes the session
            return {"jsonrpc": "2.0", "id": mid,
                    "result": {"content": [{"type": "text", "text": "tool crashed: %s: %s" % (type(exc).__name__, str(exc)[:180])},
                                           ], "isError": True}}
        return {"jsonrpc": "2.0", "id": mid, "result": {"content": [{"type": "text", "text": json.dumps(value, ensure_ascii=False)}],
                                                        "isError": False}}
    if method == "ping":
        return {"jsonrpc": "2.0", "id": mid, "result": {}}
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": -32601, "message": "method not found: %s" % method}}


def serve_stdio(s: Session, reader: Any, writer: Any) -> int:
    """Line-delimited loop. ``reader``/``writer`` are injectable so tests drive the protocol without pipes."""
    for line in reader:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError as exc:
            resp = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error: %s" % str(exc)[:120]}}
        else:
            resp = handle(s, msg)
        if resp is not None:
            writer.write(json.dumps(resp, ensure_ascii=False) + "\n")
            try:
                writer.flush()
            except AttributeError:
                pass
    return 0
