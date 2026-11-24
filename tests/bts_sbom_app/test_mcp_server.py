"""MCP server (Model Context Protocol over stdio, JSON-RPC 2.0): protocol shapes, tool delegation, honesty."""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys

import pytest

from bts_sbom_app import books as booksmod, evals, mcp_server
from conftest import FakeScanner


def _rpc(s, **kw):
    return mcp_server.handle(s, {"jsonrpc": "2.0", "id": 1, **kw})


@pytest.fixture
def s(tmp_path, make_repo):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = evals.pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                                     scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache")) \
        if hasattr(evals, "pipeline") else None
    if rec is None:
        from bts_sbom_app import pipeline
        rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                                   scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    return mcp_server.Session(evals.repo_root(), str(ev))


def test_initialize_and_tools_list_shapes(s):
    """AC: BSA-AC-534"""
    r = _rpc(s, method="initialize")
    assert r["result"]["protocolVersion"] == mcp_server.PROTOCOL_VERSION
    assert r["result"]["serverInfo"]["name"] == "bts-sbom"
    assert _rpc(s, method="notifications/initialized") is None          # notification: no response at all
    tl = _rpc(s, method="tools/list")["result"]["tools"]
    names = [t["name"] for t in tl]
    assert names == ["engine_status", "book_search", "project_overview", "chat_ask"]
    for t in tl:
        assert t["inputSchema"]["type"] == "object"                     # every tool self-describes its arguments
    assert _rpc(s, method="no/such")["error"]["code"] == -32601         # standard method-not-found
    assert _rpc(s, method="tools/call", params={"name": "nope", "arguments": {}})["error"]["code"] == -32602


def test_engine_status_and_project_overview_delegate_to_real_state(s):
    """AC: BSA-AC-534"""
    eng = json.loads(_rpc(s, method="tools/call",
                          params={"name": "engine_status", "arguments": {}})["result"]["content"][0]["text"])
    assert eng["engine"].startswith("bts_sbom ") and eng["llm_configured"] in (True, False)
    assert isinstance(eng["projects"], list)
    pname = eng["projects"][0]
    ov = json.loads(_rpc(s, method="tools/call",
                         params={"name": "project_overview", "arguments": {"project": pname}})["result"]["content"][0]["text"])
    assert ov["project"] == pname and ov["lines"]                       # the chat overview tool's own lines
    bad = _rpc(s, method="tools/call", params={"name": "project_overview", "arguments": {"project": "nope"}})
    assert bad["result"]["isError"] is True and "unknown project" in bad["result"]["content"][0]["text"]


def test_book_search_finds_real_book_passages_with_provenance(s):
    """AC: BSA-AC-534"""
    res = json.loads(_rpc(s, method="tools/call", params={"name": "book_search", "arguments": {"q": "JSON-RPC tools/list"}})["result"]["content"][0]["text"])
    assert res["found"] is True and res["results"]
    top = res["results"][0]
    assert top["book"] and top["snippet"] and len(top["snippet"]) <= 240   # book provenance travels with every hit
    empty = json.loads(_rpc(s, method="tools/call", params={"name": "book_search", "arguments": {"q": "zzz-nonexistent-topic-qqq"}})["result"]["content"][0]["text"])
    assert empty["found"] is False and empty["note"]                        # a miss says so honestly


def test_stdio_loop_serves_line_delimited_protocol_without_stray_stdout(s, capsys):
    """AC: BSA-AC-534"""
    lines = [json.dumps({"jsonrpc": "2.0", "id": i, "method": m}) for i, m in
             enumerate(["initialize", "tools/list", "tools/call", "bogus"], start=1)]
    lines[2] = json.dumps({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
                           "params": {"name": "engine_status", "arguments": {}}})
    out = io.StringIO()
    rc = mcp_server.serve_stdio(s, iter(lines), out)
    assert rc == 0
    got = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert [g.get("id") for g in got] == [1, 2, 3, 4]
    assert got[3]["error"]["code"] == -32601 and got[0]["result"]["serverInfo"]["name"] == "bts-sbom"


def test_real_subprocess_stdio_session(tmp_path, make_repo):
    """AC: BSA-AC-534"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    from bts_sbom_app import pipeline
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    msgs = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
            json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                        "params": {"name": "chat_ask", "arguments": {"question": "CVE-2020-1111 취약점이 뭐야", "project": rec["name"]}}})]
    p = subprocess.run([sys.executable, "-X", "utf8", "-m", "bts_sbom_app", "--root", evals.repo_root(),
                        "mcp", "--evidence", str(ev)],
                       input="\n".join(msgs) + "\n", capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert p.returncode == 0
    rows = [json.loads(ln) for ln in p.stdout.splitlines() if ln.strip()]
    assert [r.get("id") for r in rows] == [1, 2]
    ask = json.loads(rows[1]["result"]["content"][0]["text"])
    assert ask["found"] is True and "vuln_lookup" in ask["tools"]       # grounded answer through the real CLI entry
    assert "bts-sbom MCP server" in p.stderr                            # banner went to stderr, stdout stayed pure
