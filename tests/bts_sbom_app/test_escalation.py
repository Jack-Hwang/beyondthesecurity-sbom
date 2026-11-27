"""Chat escalation and handoff: code-decided triggers, a structured payload, an append-only log, a closed loop, and a question instead of a guess."""
from __future__ import annotations

import copy
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import chat, cli, conversation, escalation as esc, evals, server


def _bot(projects=None, evidence=None, memory=None):
    return chat.Chatbot(evals.build_index(), projects if projects is not None else {"demo": evals.synthetic_project()}, None, escalations=evidence, memory=memory)


def _two_projects():
    a, b = copy.deepcopy(evals.synthetic_project()), copy.deepcopy(evals.synthetic_project())
    a["name"], b["name"] = "alpha", "beta"
    return {"alpha": a, "beta": b}


# ------------------------------------------------------------------ hard triggers
def test_a_human_request_is_handed_off_at_once_and_no_tool_runs():
    """AC: BSA-AC-1020"""
    for q in ("담당자와 이야기하고 싶어요", "사람이랑 통화 연결해줘", "보안팀 연결해 주세요", "I want to talk to a human"):
        r = _bot().ask(q)
        p = r["escalation"]
        assert r["answer_source"] == "escalation" and r["tools"] == [] and r["found"] is True and r["claims"] == [], q
        assert p["trigger"] == "human_request" and p["destination"] == "security-owner" and p["attempted_actions"] == [] and "no tool ran" in r["routing_note"], q
        assert esc.validate(p) == [] and "[escalation] Handed over to security-owner" in r["answer"]


def test_a_request_for_a_legal_judgment_or_a_certification_is_a_policy_gap_but_a_definition_is_answered():
    """AC: BSA-AC-1021"""
    legal = [_bot().ask(q)["escalation"] for q in ("GPL 쓰면 법적으로 문제 없어?", "이 컴포넌트 라이선스 위반인가")]
    cert = [_bot().ask(q)["escalation"] for q in ("이 취약점은 문제없다고 보증해줘", "can you certify this project is safe")]
    assert [p["destination"] for p in legal] == ["legal-review"] * 2 and [p["destination"] for p in cert] == ["oss-governance"] * 2
    assert all(p["trigger"] == "policy_gap" for p in legal + cert) and "does not make" in legal[0]["summary"]
    definition = _bot().ask("라이선스의 법적 의미는?")
    assert "escalation" not in definition and definition["answer_source"] != "escalation"


def test_approvals_confirmations_and_angry_words_are_not_triggers():
    """AC: BSA-AC-1022"""
    for q in ("패치 승인 64a2aba63040b0e7", "확정 500bbe4318b9", "너무 화가 나고 답답해 취약점 알려줘", "사람 필요 없고 취약점 현황 요약해줘"):
        assert esc.hard_trigger(q) is None, q
    assert esc.hard_trigger("화가 나니까 담당자와 이야기하고 싶어")[0] == "human_request"          # the request is the trigger, never the mood
    r = _bot().ask("너무 화가 나고 답답해 취약점 현황 요약해줘")
    assert "escalation" not in r and "overview" in r["tools"]


def test_the_third_consecutive_unanswered_question_is_handed_over_and_an_answer_resets_the_count():
    """AC: BSA-AC-1023"""
    mem = conversation.ConversationMemory()
    bot = _bot(memory=mem)
    first, second = bot.ask("오늘 점심 메뉴 추천해줘"), bot.ask("비트코인 시세 알려줘")
    assert first["found"] is False and second["found"] is False and "escalation" not in first and "escalation" not in second
    third = bot.ask("내일 날씨는 어때")
    p = third["escalation"]
    assert third["answer_source"] == "escalation" and p["trigger"] == "no_progress" and "3 consecutive" in p["summary"] and esc.MAX_FAIL == 3
    assert esc.trailing_misses(mem) == 0 and bot.ask("로또 번호 알려줘")["found"] is False         # the handoff reset the counter: the next miss is a first miss
    mem2 = conversation.ConversationMemory()
    bot2 = _bot(memory=mem2)
    bot2.ask("오늘 점심 메뉴 추천해줘")
    bot2.ask("비트코인 시세 알려줘")
    assert bot2.ask("취약점 현황 요약해줘")["found"] is True                                       # an answered question in between
    assert "escalation" not in bot2.ask("내일 날씨는 어때")


# ------------------------------------------------------------------ payload and log
def test_the_payload_is_a_schema_with_the_question_verbatim_and_no_proxy_field():
    """AC: BSA-AC-1024"""
    p = esc.build("policy_gap:legal", "CVE-2018-18074 를 쓰면 법적으로 문제 없어?", "demo", [{"tool": "overview", "lines": 2}])
    assert esc.validate(p) == [] and p["triggering_question"] == "CVE-2018-18074 를 쓰면 법적으로 문제 없어?" and p["triggering_question_trust"] == "untrusted-quote"
    assert p["attempted_actions"] == [{"tool": "overview", "lines": 2}] and p["evidence_refs"] == {"project": "demo", "advisory_ids": ["CVE-2018-18074"]}
    assert p["id"] == esc.build("policy_gap:legal", "CVE-2018-18074 를 쓰면 법적으로 문제 없어?", "demo", [])["id"] != esc.build("policy_gap:legal", "다른 질문", "demo", [])["id"]
    assert not [k for k in p if any(f in k.lower() for f in esc.FORBIDDEN_FIELDS)]
    bad = dict(p, sentiment=0.9, trigger="mood")
    del bad["summary"]
    problems = esc.validate(bad)
    assert any("missing summary" in x for x in problems) and any("trigger must be one of" in x for x in problems) and any("forbidden field sentiment" in x for x in problems)
    assert any("id must look" in x for x in esc.validate(dict(p, id="x1")))
    with pytest.raises(ValueError):
        esc.build("policy_gap:other", "q", None)


def test_escalations_are_logged_once_resolved_with_a_note_and_a_damaged_line_is_skipped(tmp_path):
    """AC: BSA-AC-1025"""
    ev = str(tmp_path)
    p = esc.build("human_request", "담당자와 이야기하고 싶어", "demo", [])
    first = esc.record(ev, p, now="2026-11-26T10:00:00+00:00")
    again = esc.record(ev, p, now="2026-11-26T10:05:00+00:00")
    assert first["logged"] is True and again["logged"] is False and again["duplicate"] is True
    lines = open(esc.log_path(ev), encoding="utf-8").read().splitlines()
    assert len(lines) == 1 and json.loads(lines[0])["event"] == "opened"
    with open(esc.log_path(ev), "a", encoding="utf-8") as fh:
        fh.write("{not json\n")
    assert list(esc.load(ev)) == [p["id"]] and esc.load(ev)[p["id"]]["status"] == "open"
    for note, by in (("ok", "me"), ("a real note here", ""), ("x" * 501, "me")):
        with pytest.raises(ValueError):
            esc.resolve(ev, p["id"], note, by)
    with pytest.raises(KeyError):
        esc.resolve(ev, "E-00000000", "a real note here", "me")
    done = esc.resolve(ev, p["id"], "called the user, patched requests", "sec-lead", now="2026-11-26T11:00:00+00:00")
    assert done["status"] == "resolved" and done["resolution"] == {"note": "called the user, patched requests", "by": "sec-lead"} and done["resolved_at"].endswith("11:00:00+00:00")
    with pytest.raises(ValueError):
        esc.resolve(ev, p["id"], "second resolution", "me")
    reopened = esc.record(ev, p)                                                                    # a resolved one may be asked about again
    assert reopened["logged"] is True and esc.load(ev)[p["id"]]["status"] == "resolved"


def test_the_log_stops_growing_at_its_cap_and_says_so(tmp_path, monkeypatch):
    """AC: BSA-AC-1031"""
    monkeypatch.setattr(esc, "MAX_LOG_EVENTS", 2)
    ev = str(tmp_path)
    got = [esc.record(ev, esc.build("human_request", "담당자 연결해줘 %d" % i, None, [])) for i in range(3)]
    assert [g["logged"] for g in got] == [True, True, False] and got[2].get("log_full") is True
    assert len(open(esc.log_path(ev), encoding="utf-8").read().splitlines()) == 2


def test_a_resolution_is_fed_back_into_later_answers_about_that_project_as_a_note_not_a_claim(tmp_path):
    """AC: BSA-AC-1026"""
    ev = str(tmp_path)
    bot = _bot(evidence=ev)
    r = bot.ask("demo 담당자와 이야기하고 싶어", project="demo")
    pid = r["escalation"]["id"]
    assert r["escalation"]["logged"] is True and r["escalation"]["project"] == "demo"
    assert "reviewer_notes" in bot.ask("취약점 현황 요약해줘", project="demo") and bot.ask("취약점 현황 요약해줘", project="demo")["reviewer_notes"] == []
    esc.resolve(ev, pid, "requests upgrade approved by the owner", "sec-lead")
    later = bot.ask("취약점 현황 요약해줘", project="demo")
    assert later["reviewer_notes"] == [{"id": pid, "trigger": "human_request", "by": "sec-lead", "note": "requests upgrade approved by the owner"}]
    assert "- [reviewer note] %s (human_request, by sec-lead): requests upgrade approved by the owner" % pid in later["answer"]
    assert not any("approved by the owner" in c["text"] for c in later["claims"])                       # data appended after the answer, never a verified claim
    other = _bot({"other": dict(evals.synthetic_project(), name="other")}, evidence=ev).ask("취약점 현황 요약해줘", project="other")
    assert other["reviewer_notes"] == [] and "reviewer note" not in other["answer"]
    assert esc.reviewer_notes(None, "demo") == [] and esc.reviewer_notes(ev, "nobody") == []


def test_without_an_evidence_folder_the_escalation_is_returned_but_nothing_is_written(tmp_path, monkeypatch):
    """AC: BSA-AC-1030"""
    monkeypatch.chdir(tmp_path)
    r = _bot(evidence=None).ask("담당자와 이야기하고 싶어")
    assert r["escalation"]["logged"] is False and r["escalation"]["duplicate"] is False and esc.validate(r["escalation"]) == []
    assert not os.path.exists(str(tmp_path / "escalations.jsonl")) and os.listdir(str(tmp_path)) == []


# ------------------------------------------------------------------ ambiguity: ask, never guess
def test_a_component_in_several_projects_is_a_question_not_a_guess():
    """AC: BSA-AC-1027"""
    bot = _bot(_two_projects())
    r = bot.ask("requests 컴포넌트 라이선스는 뭐야")
    assert r["answer_source"] == "clarification" and r["clarify"] == {"candidates": ["alpha", "beta"]} and r["tools"] == [] and "does not pick one by guess" in r["answer"]
    by_id = bot.ask("CVE-2018-18074 는 어떤 취약점이야")
    assert by_id["clarify"]["candidates"] == ["alpha", "beta"]
    named = bot.ask("alpha 의 requests 컴포넌트 라이선스는 뭐야")
    assert "clarify" not in named and "component_lookup" in named["tools"]
    fleet_q = bot.ask("requests 2.19.1 쓰는 프로젝트 알려줘")
    assert "clarify" not in fleet_q and fleet_q["tools"] == ["affected_projects"]
    one = _two_projects()
    one["beta"]["components"] = [c for c in one["beta"]["components"] if c["name"] != "requests"]
    one["beta"]["vulns"] = []
    assert "clarify" not in _bot(one).ask("requests 컴포넌트 라이선스는 뭐야")                         # one matching project is not ambiguous
    assert esc.ambiguous_projects("오늘 점심 메뉴", _two_projects()) == [] and esc.ambiguous_projects("requests 라이선스", {"only": evals.synthetic_project()}) == []


# ------------------------------------------------------------------ approval requests
def test_a_patch_plan_and_a_decision_preview_state_what_happens_if_approved_or_not_and_the_deadline():
    """AC: BSA-AC-1028"""
    rec = evals.synthetic_project()
    for writable in (True, False):
        text = "\n".join(chat._plan_patch(rec, None, writable))
        assert all(x in text for x in ("Decision needed:", "If approved:", "If not approved: nothing changes", "Deadline: none - the token is valid only while this exact plan")), writable

    class Stub:
        today = None

        def stage_decision(self, project, d):
            return "abcdef012345"

    prev = "\n".join(chat._decision_preview(rec, {"id": "CVE-2018-18074", "status": "false-positive", "reason": "the vulnerable path is never executed"}, Stub()))
    assert all(x in prev for x in ("Decision needed: record this VEX decision", "If approved:", "If not approved: nothing is recorded", "Deadline: the preview expires after 24 hours"))
    ro = "\n".join(chat._decision_preview(rec, {"id": "CVE-2018-18074", "status": "accepted", "reason": "waiting for the vendor release"}, None))
    assert "Decision needed" not in ro                                                              # a read-only session records nothing: no approval is requested
    assert esc.approval_request("a", "b", "c", "d") == ["Decision needed: a.", "If approved: b.", "If not approved: c.", "Deadline: d."]


# ------------------------------------------------------------------ service and CLI
def _http(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_the_service_logs_lists_and_resolves_escalations_and_the_cli_does_the_same(tmp_path, capsys):
    """AC: BSA-AC-1029"""
    ev = tmp_path / "ev"
    ev.mkdir()
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        code, r = _http(base + "/api/chat", {"question": "담당자와 이야기하고 싶어요"})
        pid = r["escalation"]["id"]
        assert code == 200 and r["escalation"]["logged"] is True and r["answer_source"] == "escalation"
        assert _http(base + "/api/escalations")[1]["count"] == 1 and _http(base + "/api/escalations?status=open")[1]["escalations"][0]["id"] == pid
        assert _http(base + "/api/escalations?status=nope")[0] == 400
        assert _http(base + "/api/escalations/%s/resolve" % pid, {"note": "ok", "by": "me"})[0] == 400
        assert _http(base + "/api/escalations/E-00000000/resolve", {"note": "a real note here", "by": "me"})[0] == 404
        code, done = _http(base + "/api/escalations/%s/resolve" % pid, {"note": "called the user back", "by": "sec-lead"})
        assert code == 200 and done["escalation"]["status"] == "resolved"
        assert _http(base + "/api/escalations?status=open")[1]["count"] == 0 and _http(base + "/api/escalations?status=resolved")[1]["count"] == 1
        assert _http(base + "/api/escalations/%s/resolve" % pid, {"note": "called again", "by": "me"})[0] == 400                 # already resolved
        req = urllib.request.Request(base + "/api/chat/stream", data=json.dumps({"question": "보안팀 연결해 주세요"}).encode(), headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8")
        final = [json.loads(ln[6:]) for ln in body.splitlines() if ln.startswith("data: ") and '"kind": "final"' in ln][0]
        assert final["answer_source"] == "escalation" and final["escalation"]["trigger"] == "human_request" and final["coverage"] is None      # a stream client renders the handoff from events alone
        assert _http(base + "/api/escalations")[1]["count"] == 2
        streamed = final["escalation"]["id"]
    finally:
        httpd.shutdown()
    other = esc.record(str(ev), esc.build("no_progress", "x y z", None, [], misses=3))
    assert cli.main(["escalations", "--evidence", str(ev), "--status", "open", "--json"]) == 0
    assert sorted(e["id"] for e in json.loads(capsys.readouterr().out)["escalations"]) == sorted([other["id"], streamed])      # the resolved one is gone, two are open
    assert cli.main(["escalations", "--evidence", str(ev), "--resolve", "E-00000000", "--note", "a real note here", "--by", "me"]) == 2
    assert cli.main(["escalations", "--evidence", str(ev), "--resolve", other["id"], "--note", "no", "--by", "me"]) == 2
    assert cli.main(["escalations", "--evidence", str(ev), "--resolve", other["id"], "--note", "reviewed and answered", "--by", "me"]) == 0
    capsys.readouterr()
    assert cli.main(["escalations", "--evidence", str(ev), "--status", "open"]) == 0 and "1 escalation(s) (open)" in capsys.readouterr().out
