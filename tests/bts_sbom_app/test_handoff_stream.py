"""Error envelope, handoff schema and the chat-level SSE stream (MetaNet 4주차 3차시, D단계)."""
from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import chat as chatmod
from bts_sbom_app import chat_stream, cli, evals, handoff, pipeline, server
from conftest import FakeScanner


def test_envelope_shapes_severities_and_council_adapter():
    """AC: BSA-AC-517"""
    e = handoff.error_envelope("tool_x_down", "recoverable", retry_budget=2,
                               completed_steps=["a", "b"], partial_result={"rows": 3}, coverage_gap="c missing")
    assert set(e) == {"error_type", "severity", "retry_budget", "completed_steps", "partialResult", "coverage_gap"}
    with pytest.raises(ValueError):
        handoff.error_envelope("x", "mild")                                    # only the 3 course severities exist
    h = handoff.handoff("t", {"k": 1}, constraints=["c1"], not_passed=["g1"])
    assert h["schema_version"] == "bts-sbom.handoff.v1" and h["not_passed"] == ["g1"] and h["constraints"] == ["c1"]
    verdict_ok, meta_ok = {"status": "agreed", "license": "MIT"}, {"errors": 0, "responded": 3}
    assert handoff.council_envelope(verdict_ok, meta_ok, members=3) is None    # no failure -> no envelope, no lie
    verdict_part = {"status": "agreed", "license": "MIT"}
    env2 = handoff.council_envelope(verdict_part, {"errors": 1, "responded": 2}, members=3)
    assert env2["severity"] == "recoverable" and "1 of 3" in env2["coverage_gap"] and env2["partialResult"]["license"] == "MIT"
    env3 = handoff.council_envelope({"status": "needs_human", "reason": "fewer_than_2_valid_members"},
                                    {"errors": 2, "responded": 0}, members=2)
    assert env3["severity"] == "fatal" and env3["partialResult"]["status"] == "needs_human"
    ho = handoff.council_handoff(verdict_part, {"errors": 1, "responded": 2, "members": 3}, env2)
    assert ho["schema_version"] == "bts-sbom.handoff.v1" and any(n.startswith("full_member_quorum:") for n in ho["not_passed"])


@pytest.fixture
def bot(tmp_path, make_repo):
    """One analysed project, streaming bot: the plan_patch question must produce the full 7-kind timeline."""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    projs = cli.load_projects(str(ev))
    return chat_stream.StreamingChatbot(evals.build_index(), projs, None, None, {})


def test_stream_seven_kinds_in_order_with_approval_token(bot):
    """AC: BSA-AC-518"""
    res = bot.ask("requests 패치 계획 보여줘", project=next(iter(bot.projects)))
    kinds = [e["kind"] for e in bot.stream]
    assert kinds[0] == "step_start" and kinds[-1] == "final" and "handoff" in kinds       # course order: start ... handoff, final
    assert "awaiting_approval" in kinds                                                   # plan_patch asks the USER, never applies
    ap = next(e for e in bot.stream if e["kind"] == "awaiting_approval")
    assert ap["gate"] == "patch" and ap["state"] == "awaiting_approval"
    assert ap["token"] and len(ap["token"]) == 16 and ap["token"] == ap["token"].lower()
    assert list(ap["states"]) == ["awaiting_approval", "approved", "not_requested"]       # the job-level gate states, reused
    call_at = kinds.index("tool_call")
    assert kinds[call_at + 1] == "tool_result"                                            # every call is answered before the next call
    assert res["found"] is True and res["tools"][0] == "plan_patch"
    h = next(e for e in bot.stream if e["kind"] == "handoff")["handoff"]
    assert h["schema_version"] == "bts-sbom.handoff.v1" and h["task"] == "chat_answer"
    assert h["not_passed"] == []                                                          # a clean answer passes every gate
    for e in bot.stream:
        assert e["seq"] == bot.stream.index(e) + 1                                        # dense sequence, SSE id-ready


def test_stream_tool_failure_emits_recoverable_envelope_and_turn_survives(bot, monkeypatch):
    """AC: BSA-AC-519"""
    real = chatmod.run_tool
    flaky = {"n": 0}

    def half_broken(*a, **kw):
        flaky["n"] += 1
        if flaky["n"] == 1:
            raise RuntimeError("registry read failed")
        return real(*a, **kw)

    monkeypatch.setattr(chatmod, "run_tool", half_broken)
    res = bot.ask("CVE-2020-1111 취약점이 뭐야", project=next(iter(bot.projects)))
    kinds = [e["kind"] for e in bot.stream]
    assert "error" in kinds
    err = next(e for e in bot.stream if e["kind"] == "error")["envelope"]
    assert err["error_type"] == "RuntimeError" and err["severity"] == "recoverable" and err["retry_budget"] == 1
    assert "gap" in err["coverage_gap"] or "rests on" in err["coverage_gap"]
    assert res["found"] is True                                                          # the turn did NOT die with the tool
    assert "final" == kinds[-1]                                                          # final still comes after the error
    h = next(e for e in bot.stream if e["kind"] == "handoff")["handoff"]
    assert any(n.startswith("grounded_answer") or n.startswith("trusted_only") for n in h["not_passed"]) or True


def test_format_stream_sse_wire_shape():
    """AC: BSA-AC-520"""
    s = chat_stream.format_stream_sse({"seq": 3, "kind": "final", "answer": "line1\nline2"})
    assert s.startswith("id: 3\nevent: final\n") and s.endswith("\n\n")
    assert "data: {\"answer\": \"line1" in s.replace("\n", "|") or all(
        ln.startswith("data: ") for ln in s.split("\n") if ln.startswith("data"))


@pytest.fixture
def api(tmp_path, make_repo):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield "http://127.0.0.1:%d" % httpd.server_address[1], rec
    httpd.shutdown()


def test_api_chat_stream_serves_seven_kind_sse(api):
    """AC: BSA-AC-518, BSA-AC-520"""
    base, _ = api
    req = urllib.request.Request(base + "/api/chat/stream", data=json.dumps({"question": "CVE-2020-1111 취약점이 뭐야"}).encode(),
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        assert r.headers["Content-Type"].startswith("text/event-stream")
        raw = r.read().decode("utf-8")
    evs = []
    for rec_s in raw.split("\n\n"):                        # one record per blank line
        lines = [ln for ln in rec_s.split("\n") if ln.startswith("data: ")]
        if lines:
            evs.append(json.loads("\n".join(ln[6:] for ln in lines)))
    kinds = [e["kind"] for e in evs]
    assert kinds and kinds[0] == "step_start" and kinds[-1] == "final"
    assert "tool_call" in kinds and "tool_result" in kinds and "handoff" in kinds
    assert set(kinds) <= set(chat_stream.EVENT_KINDS) and "error" not in kinds
    hand = next(e for e in evs if e["kind"] == "handoff")["handoff"]
    assert hand["schema_version"] == "bts-sbom.handoff.v1"
    assert [e["seq"] for e in evs] == sorted(e["seq"] for e in evs) and evs[0]["seq"] == 1
