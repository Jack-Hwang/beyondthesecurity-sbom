"""MCP server upgrades: operator LLM gate (C40), nl2sql resource+tool (C81/C34), prompts primitive (C46),
run_scan progress notifications (C60). Course text is untrusted data; nothing here follows an instruction
found in it - only measured protocol behaviour of bts_sbom_app.mcp_server is asserted."""
from __future__ import annotations

import io
import json
import os
import sqlite3

import pytest

from bts_sbom_app import evals, llm, mcp_server
from conftest import FakeScanner


def _rpc(s, **kw):
    return mcp_server.handle(s, {"jsonrpc": "2.0", "id": 1, **kw})


@pytest.fixture
def bare(tmp_path):
    """A Session with no scanned project - enough for every tool/resource/prompt that does not need one."""
    return mcp_server.Session(evals.repo_root(), str(tmp_path / "ev"))


@pytest.fixture
def mcp(tmp_path, make_repo):
    """One real scanned project (FakeScanner, no network) + its MCP Session - needed for the chat_ask LLM-gate
    tests, which must route to a project before the LLM tool-planning branch is even reachable."""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    from bts_sbom_app import pipeline
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    return mcp_server.Session(evals.repo_root(), str(ev)), rec["name"]


# ---------------------------------------------------------------------------------------------------- C40: LLM gate

def test_chat_ask_llm_gate_blocks_outbound_call_when_unset(mcp, monkeypatch):
    """AC: BSA-AC-1150"""
    s, proj = mcp
    monkeypatch.delenv(mcp_server.ALLOW_LLM_ENV, raising=False)
    fake_client = llm.ChatClient(api_key="test-fake-key")          # available=True, ledger=None (no evidence file write)
    monkeypatch.setattr(s, "_client", lambda: fake_client)
    r = _rpc(s, method="tools/call", params={"name": "chat_ask",
                                             "arguments": {"question": "CVE-2018-18074 는 어떤 취약점이야",
                                                          "project": proj, "use_llm": True}})
    # a broken gate would let plan_tools() call fake_client.complete() -> llm.TRANSPORT (autouse-forbidden in every
    # test) -> AssertionError -> this tool call would come back as isError=True "tool crashed: AssertionError: ...".
    assert r["result"]["isError"] is False, r
    body = json.loads(r["result"]["content"][0]["text"])
    assert body["found"] is True
    assert mcp_server.ALLOW_LLM_ENV in body["llm_note"] and "0 outbound LLM calls" in body["llm_note"]


def test_chat_ask_llm_gate_allows_through_when_set(mcp, monkeypatch):
    """AC: BSA-AC-1151"""
    s, proj = mcp
    monkeypatch.setenv(mcp_server.ALLOW_LLM_ENV, "1")
    fake_client = llm.ChatClient(api_key="test-fake-key")
    monkeypatch.setattr(s, "_client", lambda: fake_client)
    r = _rpc(s, method="tools/call", params={"name": "chat_ask",
                                             "arguments": {"question": "CVE-2018-18074 는 어떤 취약점이야",
                                                          "project": proj, "use_llm": True}})
    # the gate let use_llm=True reach the real client this time: plan_tools() called fake_client.complete(),
    # which hit the autouse-forbidden llm.TRANSPORT and raised - proving the call was actually attempted.
    assert r["result"]["isError"] is True, r
    msg = r["result"]["content"][0]["text"]
    assert "AssertionError" in msg and "unexpected LLM call" in msg


# ------------------------------------------------------------------------------------------- C34: resources capability

def test_initialize_declares_resources_capability_and_resources_are_reachable(bare):
    """AC: BSA-AC-1152"""
    r = _rpc(bare, method="initialize")
    caps = r["result"]["capabilities"]
    assert "tools" in caps and "resources" in caps
    lst = _rpc(bare, method="resources/list")["result"]["resources"]
    uris = {x["uri"] for x in lst}
    assert uris == {"bts://tools/catalog", "bts://agent/card", "bts://books/notes-index", "bts://nl2sql/catalog"}


# -------------------------------------------------------------------------------------------- C81: nl2sql resource+tool

def test_nl2sql_catalog_resource_lists_vulns_and_pkg_map_tables(bare):
    """AC: BSA-AC-1153"""
    res = _rpc(bare, method="resources/read", params={"uri": "bts://nl2sql/catalog"})["result"]["contents"][0]
    assert res["mimeType"] == "application/json"
    cat = json.loads(res["text"])
    assert set(cat["tables"]) == {"vulns", "pkg_map"}
    assert "columns" in cat["tables"]["vulns"] and "columns" in cat["tables"]["pkg_map"]


def test_nl2sql_tool_is_listed_and_answers_a_known_question(tmp_path, monkeypatch):
    """AC: BSA-AC-1154"""
    names = [t["name"] for t in mcp_server.TOOL_DEFS]
    assert "nl2sql" in names
    db_path = str(tmp_path / "osv.db")
    conn = sqlite3.connect(db_path)
    conn.execute("CREATE TABLE vulns (ecosystem TEXT, vuln_id TEXT, vuln_json TEXT)")
    conn.execute("CREATE TABLE pkg_map (ecosystem TEXT, package_name TEXT, vuln_id TEXT)")
    conn.execute("INSERT INTO vulns VALUES ('PyPI','CVE-2018-18074', ?)", (json.dumps({"summary": "requests bug"}),))
    conn.execute("INSERT INTO vulns VALUES ('PyPI','CVE-2020-1111', ?)", (json.dumps({"summary": "another bug"}),))
    conn.commit()
    conn.close()
    monkeypatch.setenv("BTS_SBOM_OSV_DB_PATH", db_path)
    s = mcp_server.Session(evals.repo_root(), str(tmp_path / "ev"))
    r = _rpc(s, method="tools/call", params={"name": "nl2sql", "arguments": {"q": "전체 취약점은 몇 개야?"}})
    assert r["result"]["isError"] is False, r
    body = json.loads(r["result"]["content"][0]["text"])
    assert body["status"] == "success" and body["rows"] == [[2]]
    assert "count" in (body["sql"] or "").lower()


# ---------------------------------------------------------------------------------------------- C46: prompts primitive

def test_prompts_list_returns_seven_canned_templates_with_argument_schemas(bare):
    """AC: BSA-AC-1155"""
    lst = _rpc(bare, method="prompts/list")["result"]["prompts"]
    assert len(lst) == 7
    names = [p["name"] for p in lst]
    assert len(set(names)) == 7                                    # every template name is unique
    for p in lst:
        assert p["description"] and p["arguments"]
        arg0 = p["arguments"][0]
        assert arg0["name"] == "project" and arg0["required"] is True


def test_prompts_get_with_project_renders_one_message_with_no_placeholder(bare):
    """AC: BSA-AC-1156"""
    lst = _rpc(bare, method="prompts/list")["result"]["prompts"]
    name = lst[0]["name"]
    r = _rpc(bare, method="prompts/get", params={"name": name, "arguments": {"project": "demo-project-7"}})
    msgs = r["result"]["messages"]
    assert len(msgs) == 1
    text = msgs[0]["content"]["text"]
    assert "demo-project-7" in text
    assert "{" not in text and "}" not in text                     # no unresolved template placeholder survives


def test_prompts_get_missing_required_argument_is_rejected(bare):
    """AC: BSA-AC-1157"""
    lst = _rpc(bare, method="prompts/list")["result"]["prompts"]
    name = lst[0]["name"]
    r = _rpc(bare, method="prompts/get", params={"name": name, "arguments": {}})
    assert r["error"]["code"] == -32602
    r2 = _rpc(bare, method="prompts/get", params={"name": "no-such-prompt", "arguments": {"project": "x"}})
    assert r2["error"]["code"] == -32602


# ------------------------------------------------------------------------------------------ C60: run_scan progress

_FAKE_STAGES = [("prepare", True, 0.01), ("analyze", True, 0.02), ("licenses", True, 0.01), ("plan", True, 0.01)]


def _fake_run_project(source, *, work_root, out_dir, offline=False, use_llm=False, client=None, cache_dir=None,
                      progress=None, **kw):
    assert os.path.isdir(work_root)                                # the real ephemeral workspace the tool created
    if progress is not None:
        for name, ok, seconds in _FAKE_STAGES:
            progress("step_start", name)
            progress("step_end", name, ok=ok, seconds=seconds, error=None)
    return {"error": None, "name": "fake-scan", "elapsed_s": 0.07, "components": [{"name": "requests"}], "vulns": [],
           "stage_errors": {}}


def test_run_scan_emits_one_notification_per_stage_before_final_result(bare, monkeypatch):
    """AC: BSA-AC-1158"""
    monkeypatch.setattr("bts_sbom_app.pipeline.run_project", _fake_run_project)
    lines = [json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                         "params": {"name": "run_scan", "arguments": {"source": "irrelevant-for-the-fake"},
                                   "_meta": {"progressToken": "tok-1"}}})]
    out = io.StringIO()
    rc = mcp_server.serve_stdio(bare, iter(lines), out)
    assert rc == 0
    rows = [json.loads(ln) for ln in out.getvalue().splitlines()]
    notifications = [r for r in rows if r.get("method") == "notifications/progress"]
    finals = [r for r in rows if r.get("id") == 1]
    assert len(notifications) == len(_FAKE_STAGES) == 4             # one per completed pipeline stage (4 of 4)
    assert len(finals) == 1
    assert rows.index(finals[0]) == len(rows) - 1                   # every notification precedes the final result line
    for i, n in enumerate(notifications, start=1):
        assert n["params"]["progressToken"] == "tok-1" and n["params"]["progress"] == i
    body = json.loads(finals[0]["result"]["content"][0]["text"])
    assert finals[0]["result"]["isError"] is False
    assert body["progress_events"] == 4


def test_run_scan_without_progress_token_emits_no_notifications(bare, monkeypatch):
    """AC: BSA-AC-1159"""
    monkeypatch.setattr("bts_sbom_app.pipeline.run_project", _fake_run_project)
    lines = [json.dumps({"jsonrpc": "2.0", "id": 7, "method": "tools/call",
                         "params": {"name": "run_scan", "arguments": {"source": "irrelevant-for-the-fake"}}})]
    out = io.StringIO()
    rc = mcp_server.serve_stdio(bare, iter(lines), out)
    assert rc == 0
    rows = [json.loads(ln) for ln in out.getvalue().splitlines()]
    assert len([r for r in rows if r.get("method") == "notifications/progress"]) == 0
    assert len(rows) == 1 and rows[0]["id"] == 7
    body = json.loads(rows[0]["result"]["content"][0]["text"])
    assert rows[0]["result"]["isError"] is False
    assert body["progress_events"] == 0
