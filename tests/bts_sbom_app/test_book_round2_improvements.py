"""Book round-2 improvements: LLM answer self-correction (AC-543), passage-trim reporting (AC-544), MCP resources (AC-545)."""
from __future__ import annotations

import json

import pytest

from bts_sbom_app import chat, evals, llm, mcp_server
from conftest import FakeScanner

GOOD = {"answer": "CVE-2018-18074 affects requests 2.19.1, fixed in 2.20.0.",
        "claims": [{"text": "a", "quote": "CVE-2018-18074 affects requests 2.19.1, severity HIGH (CVSS 7.5), fixed in 2.20.0.",
                    "source": "project:demo:vuln_lookup"}]}
BAD = {"answer": "요약", "claims": [{"text": "c", "quote": "CVE-2018-18074 는 번역된 인용이라 검증 실패", "source": "project:demo:vuln_lookup"}]}


def _bot(world):
    return chat.Chatbot(evals.build_index(), {"demo": evals.synthetic_project()}, llm.ChatClient("k"))


def _llm(world, bodies):
    calls = []
    it = iter(bodies)

    def handler(body):
        calls.append(body["messages"][0]["content"])
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(next(it))}}],
                                "usage": {"prompt_tokens": 5, "completion_tokens": 7}})

    world.llm_handler = handler
    return calls


# use_llm=True means the LLM PLANNER consumes one body before the answer lane - every list below is
# [planner, answer-attempt-1, answer-attempt-2].
def test_low_citation_answer_retries_once_with_failure_attached_then_succeeds(world):
    """AC: BSA-AC-543"""
    calls = _llm(world, [BAD, BAD, GOOD])
    r = _bot(world).ask("CVE-2018-18074 는 어떤 취약점이야", project="demo", use_llm=True)
    assert r["answer_source"] == "exaone" and r["citation_accuracy"] == 1.0
    assert len(calls) == 3
    assert "rejected" in calls[2] and "accuracy" in calls[2]      # the concrete failure rode along to attempt 2
    assert "Fix exactly that" in calls[2]


def test_bad_twice_falls_back_to_extractive_with_honest_note(world):
    """AC: BSA-AC-543"""
    calls = _llm(world, [BAD, BAD, BAD])
    r = _bot(world).ask("CVE-2018-18074 는 어떤 취약점이야", project="demo", use_llm=True)
    assert r["answer_source"] == "tools"                          # extractive fallback, exactly as before this change
    assert len(calls) == 3                                        # the budget is ONE retry, never an endless loop
    assert "rejected" in r["llm_note"] and "extractive" in r["llm_note"]


def test_unparseable_json_retries_then_succeeds(world):
    """AC: BSA-AC-543"""
    calls = []
    it = iter([json.dumps(BAD), '{"answer": broken json', json.dumps(GOOD)])

    def handler(body):
        calls.append(body["messages"][0]["content"])
        return 200, json.dumps({"choices": [{"message": {"content": next(it)}}],
                                "usage": {"prompt_tokens": 5, "completion_tokens": 7}})

    world.llm_handler = handler
    r = _bot(world).ask("CVE-2018-18074 는 어떤 취약점이야", project="demo", use_llm=True)
    assert r["answer_source"] == "exaone" and len(calls) == 3
    assert "rejected" in calls[2]                                 # the parse failure rode along too


def test_trim_note_is_honest_and_cap_is_enforced():
    """AC: BSA-AC-544"""
    assert chat.passage_trim_note(8) == "6 of 8 trusted passages handed to the model (2 trimmed by relevance, cap 6)"
    assert chat.passage_trim_note(6) == "" and chat.passage_trim_note(4) == ""    # nothing trimmed -> nothing claimed
    docs = [("s%d" % i, "CVE-2018-18074 requests filler %d" % i) for i in range(8)]
    assert len(chat.order_passages_for_prompt("CVE-2018-18074", docs)) == 6       # the prompt budget is enforced here


def test_mcp_resources_list_and_read(tmp_path, make_repo):
    """AC: BSA-AC-545"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    from bts_sbom_app import pipeline
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    s = mcp_server.Session(evals.repo_root(), str(ev))

    def rpc(**kw):
        return mcp_server.handle(s, {"jsonrpc": "2.0", "id": 1, **kw})

    lst = rpc(method="resources/list")["result"]["resources"]
    assert [r["uri"] for r in lst] == ["bts://tools/catalog", "bts://agent/card", "bts://books/notes-index",
                                       "bts://nl2sql/catalog"]
    catalog = rpc(method="resources/read", params={"uri": "bts://tools/catalog"})["result"]["contents"][0]
    assert catalog["uri"] == "bts://tools/catalog" and "vuln_lookup" in catalog["text"]
    card = json.loads(rpc(method="resources/read", params={"uri": "bts://agent/card"})["result"]["contents"][0]["text"])
    assert card["name"] == "bts-sbom" and len(card["skills"]) == 7
    notes = json.loads(rpc(method="resources/read", params={"uri": "bts://books/notes-index"})["result"]["contents"][0]["text"])
    assert notes["count"] >= 30 and all(n["file"].startswith("knowledge_books/") for n in notes["notes"])
    bad = rpc(method="resources/read", params={"uri": "bts://nope"})
    assert bad["result"]["isError"] is True and "known:" in bad["result"]["content"][0]["text"]
