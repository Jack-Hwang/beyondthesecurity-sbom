"""End-user feedback on chat answers (C76) + the metadata-only turn ledger + the stratified review queue (C66,
course D5.5 사람 검토·층화 표집): votes are an append-only event stream keyed by the turn's trace_id, the turn
ledger stores METADATA ONLY (never the question or the answer text), the review queue samples across verdict
strata so the unrated majority is a visible population instead of hiding inside the total, and the HTTP surface
keeps the same host-pin / same-origin contract as every other lane."""
from __future__ import annotations

import json
import os
import types

from bts_sbom_app import feedback

HOST = {"Host": "127.0.0.1:8800"}
BIND = ("127.0.0.1", 8800)


def _st(tmp_path):
    return types.SimpleNamespace(evidence=str(tmp_path), jobs={}, buses={})


def _req(st, method, path, body=None, headers=None):
    h = dict(HOST)
    h.update(headers or {})
    hit = feedback.route(method, path, {}, body or {}, h, st, BIND)
    assert hit is not None, "the path must be feedback's"
    return hit[0], hit[1]


# ------------------------------------------------------------------ the vote stream: validation, dedupe, flips
def test_a_vote_validates_its_inputs_before_touching_the_ledger(tmp_path):
    """AC: BSA-AC-1267"""
    e, err = feedback.record_feedback(str(tmp_path), "not a trace id!", "up")
    assert e is None and "trace_id" in err
    e2, err2 = feedback.record_feedback(str(tmp_path), "0123abcd", "maybe")
    assert e2 is None and "up|down" in err2
    e3, err3 = feedback.record_feedback(str(tmp_path), "0123abcd", "up", note="x" * 301)
    assert e3 is None and "cap" in err3
    assert not os.path.exists(tmp_path / "chat_feedback.jsonl")     # nothing was written by the refusals


def test_same_verdict_twice_is_one_vote_a_flip_is_a_second_event(tmp_path):
    """AC: BSA-AC-1267"""
    st = _st(tmp_path)
    feedback.record_turn(st.evidence, "aaaaaaaa0001", answer_source="llm")
    e1, _ = feedback.record_feedback(st.evidence, "aaaaaaaa0001", "up")
    assert e1.get("duplicate") is None
    e2, _ = feedback.record_feedback(st.evidence, "aaaaaaaa0001", "up")       # the same verdict again
    assert e2.get("duplicate") is True
    e3, _ = feedback.record_feedback(st.evidence, "aaaaaaaa0001", "down")     # the flip is data
    assert e3.get("duplicate") is None
    s = feedback.summary(st.evidence)
    assert s["up"] == 1 and s["down"] == 1 and s["down_with_note"] == 0


# ------------------------------------------------------------------ the turn ledger: metadata only + honest roll-up
def test_the_turn_ledger_stores_metadata_and_never_text(tmp_path):
    """AC: BSA-AC-1267"""
    st = _st(tmp_path)
    feedback.record_turn(st.evidence, "abcd1234", answer_source="llm", degraded=True, found=True, status="partial")
    row = json.loads((tmp_path / "chat_turns.jsonl").read_text(encoding="utf-8").splitlines()[0])
    assert row["trace_id"] == "abcd1234" and row["degraded"] is True and row["answer_source"] == "llm"
    assert "question" not in row and "answer" not in row and "q" not in row      # privacy by construction
    s = feedback.summary(st.evidence)
    assert s["turns"] == 1 and s["up"] == 0 and s["down"] == 0 and s["unrated"] == 1 and s["response_rate"] == 0.0
    feedback.record_feedback(st.evidence, "abcd1234", "down", note="근거가 없음")
    s2 = feedback.summary(st.evidence)
    assert s2["down"] == 1 and s2["unrated"] == 0 and s2["down_with_note"] == 1 and s2["response_rate"] == 1.0
    assert s2["notes"] == ["근거가 없음"]


def test_the_review_queue_stratifies_and_is_deterministic(tmp_path):
    """AC: BSA-AC-1267"""
    st = _st(tmp_path)
    for i in range(8):
        feedback.record_turn(st.evidence, "aaaaaaaa%04x" % i, answer_source="llm")
    feedback.record_feedback(st.evidence, "aaaaaaaa0000", "up")
    feedback.record_feedback(st.evidence, "aaaaaaaa0001", "down")
    q1 = feedback.review_queue(st.evidence, frac=0.5, minimum=1)
    assert q1["population"] == 8
    assert q1["strata"]["unrated"] == 6 and q1["sampled"]["unrated"] == 3          # the unrated majority is its own stratum
    assert q1["sampled"]["up"] == 1 and q1["sampled"]["down"] == 1
    ids = [r["trace_id"] for r in q1["queue"]]
    assert len(ids) == len(set(ids)) and all(ids.count(r["trace_id"]) == 1 for r in q1["queue"])
    q2 = feedback.review_queue(st.evidence, frac=0.5, minimum=1)
    assert [r["trace_id"] for r in q2["queue"]] == ids                              # same seed -> same members


# ------------------------------------------------------------------ the HTTP contract
def test_the_feedback_http_surface_keeps_the_lane_contract(tmp_path):
    """AC: BSA-AC-1267"""
    st = _st(tmp_path)
    code, obj = _req(st, "GET", "/api/chat/feedback")
    assert code == 200 and obj["turns"] == 0 and obj["queue"]["population"] == 0 and obj["queue"]["queue"] == []
    code2, obj2 = _req(st, "POST", "/api/chat/feedback", {"trace_id": "abcd1234", "verdict": "up"})
    assert code2 == 200 and obj2["verdict"] == "up"
    code3, obj3 = _req(st, "POST", "/api/chat/feedback", {"trace_id": "abcd1234", "verdict": "nope"})
    assert code3 == 400 and "up|down" in obj3["error"]
    code4, _ = _req(st, "GET", "/api/chat/feedback", headers={"Host": "evil.example:8800"})
    assert code4 == 403
    code5, _ = _req(st, "POST", "/api/chat/feedback", {"trace_id": "abcd1234", "verdict": "up"},
                    headers={"Origin": "https://evil.example", "Referer": "https://evil.example/x"})
    assert code5 == 403
    assert feedback.route("PUT", "/api/chat/feedback", {}, {}, HOST, st, BIND)[0] == 405
    assert feedback.route("GET", "/api/incidents", {}, {}, HOST, st, BIND) is None   # not our lane, server keeps routing


# ------------------------------------------------------------------ the wiring exists
def test_the_server_and_the_dock_are_wired():
    """AC: BSA-AC-1267"""
    srv = open("bts_sbom_app/server.py", encoding="utf-8").read()
    assert "feedback_mod.record_turn" in srv and "_feedback(\"GET\"" in srv and "_feedback(\"POST\"" in srv
    assert 'res["latency_ms"]' in srv and 'ev["ttft_ms"]' in srv and 'ev["duration_ms"]' in srv   # C86 measured on both surfaces
    panel = open("bts_sbom_app/web/bts_chat_panel.js", encoding="utf-8").read()
    assert "feedbackRow" in panel and "/api/chat/feedback" in panel
    assert 'aria-label' in panel and "도움이 되었다고 기록" in panel                # the vote buttons are labelled (C51)
