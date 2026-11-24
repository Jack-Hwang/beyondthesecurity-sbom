"""Chat-driven analysis, approved patching and VEX decisions: every effect keeps its gate, and only the user's own text can open it."""
from __future__ import annotations

import datetime
import io
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import actions as actionsmod, chat, cli, evals, server
from bts_sbom_app.util import read_json, tree_hash
from conftest import FakeScanner

TODAY = datetime.date(2026, 11, 17)
JUST = "vulnerable_code_not_in_execute_path"


@pytest.fixture
def env(tmp_path, make_repo, world):
    origin = make_repo({"requirements.txt": "requests==2.19.1\npyyaml==5.3\n"})
    ev = tmp_path / "ev"

    def acts():
        return actionsmod.ChatActions(evals.repo_root(), str(ev), scanner=FakeScanner(), use_llm=False, work_root=str(tmp_path / "work"),
                                      cache_dir=str(tmp_path / "cache"), today=TODAY)

    def bot(actions=True, projects=None, client=None):
        projs = projects if projects is not None else cli.load_projects(str(ev))
        store = read_json(str(ev / ".triage.json"), {})
        return chat.Chatbot(evals.build_index(), projs, client, acts() if actions else None, store)

    return {"origin": origin, "ev": ev, "acts": acts, "bot": bot, "tmp": tmp_path}


def _analysed(env):
    b = env["bot"](projects={})
    r = b.ask("%s 분석해줘" % env["origin"])
    assert r["found"] and "analyze_project" in r["tools"], r["answer"]
    return b, b.projects["proj"]


def _token(rec, comps=None):
    return actionsmod.plan_token(rec, comps)


def _llm(world, calls):
    world.llm_handler = lambda body: (200, json.dumps({"choices": [{"message": {"content": json.dumps({"calls": calls})}}], "usage": {"prompt_tokens": 5, "completion_tokens": 7}}))


# ------------------------------------------------------------------ analysis from the chat
def test_the_chat_analyses_a_source_in_a_work_copy_and_a_read_only_session_refuses(env):
    """AC: BSA-AC-200"""
    before = tree_hash(env["origin"])
    b = env["bot"](projects={})
    r = b.ask("%s 분석해줘" % env["origin"])
    assert r["found"] is True and r["tools"] == ["analyze_project"] and r["citation_accuracy"] == 1.0
    assert "Project proj: 2 components, 3 vulnerabilities" in r["answer"] and "approval token for all of them: " + _token(b.projects["proj"]) in r["answer"]
    assert list(cli.project_records(str(env["ev"]))) == ["proj"] and "proj" in b.projects
    assert tree_hash(env["origin"]) == before                                                 # the origin was never written
    ro = env["bot"](actions=False, projects={}).ask("%s 분석해줘" % env["origin"])
    assert "read-only" in ro["answer"] and ro["tools"] == ["analyze_project"]
    assert not os.path.exists(str(env["ev"] / "proj" / "proj.json.tmp")) and len(cli.project_records(str(env["ev"]))) == 1      # nothing new was analysed
    bad = env["bot"](projects={}).ask("http://insecure.example/x.git 분석해줘")
    assert "Refused source" not in bad["answer"] or bad["found"]                              # a plain-http source never reaches the engine


# ------------------------------------------------------------------ patch: token gate, exact scope, one round
def test_a_patch_needs_the_token_of_the_plan_it_was_shown_and_nothing_else_applies(env):
    """AC: BSA-AC-201"""
    b, rec = _analysed(env)
    tok = _token(rec)
    before = tree_hash(env["origin"])
    prev = b.ask("패치 해줘")
    assert "Approval token %s covers exactly these 2 upgrade(s); nothing has been changed" % tok in prev["answer"] and "apply_patch" not in prev["tools"]
    assert "apply_patch" not in b.ask("패치 적용 승인해줘")["tools"]                            # approval words without a token only show the plan again
    wrong = b.ask("패치 승인 0000000000000000")
    assert "Not applied: the token does not match" in wrong["answer"] and tok in wrong["answer"]
    assert read_json(str(env["ev"] / "proj" / "proj.json"))["patch"]["status"] == "not_requested" and not os.path.exists(str(env["tmp"] / "work" / "proj_fix"))
    ro = env["bot"](actions=False).ask("패치 승인 %s" % tok)
    assert "read-only" in ro["answer"] and not os.path.exists(str(env["tmp"] / "work" / "proj_fix"))
    done = b.ask("패치 승인 %s" % tok)
    assert "Patch applied in an isolated work copy: 2 component(s) upgraded; the re-scan reports 3 advisories fixed and 0 introduced" in done["answer"]
    assert "Patch status: not_requested" not in done["answer"] and rec["patch"]["status"] == "applied"           # the open session sees the result too
    fixed = open(str(env["tmp"] / "work" / "proj_fix" / "requirements.txt"), encoding="utf-8").read()
    assert "requests==2.31.0" in fixed and "pyyaml==5.4" in fixed
    assert tree_hash(env["origin"]) == before                                                 # the origin is untouched and nothing was pushed
    saved = read_json(str(env["ev"] / "proj" / "proj.json"))
    assert saved["patch"]["status"] == "applied" and saved["patch"]["branch"] == "bts-sbom/auto-fix" and len(saved["patch"]["rounds"]) == 1


def test_a_plan_request_routes_to_plan_patch_and_the_recorded_status_is_labelled_historical(env):
    """AC: BSA-AC-593 — the --chat-actions live-chain findings (2026-11-22): "수정 계획을 세워줘" asked for a PLAN
    but the regex router gave the read-only status display, and a stored patch status read as if it had just happened."""
    b, rec = _analysed(env)
    r = b.ask("수정 계획을 세워줘")
    assert "plan_patch" in r["tools"] and "Approval token" in r["answer"]          # a plan ask plans; it never patches
    tok = _token(rec)
    done = b.ask("패치 승인 %s" % tok)
    assert rec["patch"]["status"] == "applied" and rec["patch"].get("at")          # the approved run is timestamped
    status = b.ask("django-nV 패치 상태 보여줘")
    assert "Last recorded patch run of " in status["answer"] and "this question applied nothing" in status["answer"]
    assert "Patch status:" not in status["answer"]                                 # the bare stale wording is gone


def test_a_token_covers_exactly_its_selection_and_the_patch_runs_one_round(env):
    """AC: BSA-AC-202"""
    b, rec = _analysed(env)
    all_tok, one_tok = _token(rec), _token(rec, ["requests"])
    assert all_tok != one_tok and len(one_tok) == 16
    sub = b.ask("requests 만 패치 해줘")
    assert "Patch plan for proj for requests: 1 upgrade(s)" in sub["answer"] and one_tok in sub["answer"] and "pyyaml 5.3 ->" not in sub["answer"]
    mismatch = b.ask("requests 패치 승인 %s" % all_tok)                                           # the all-plan token does not open a subset
    assert "Not applied" in mismatch["answer"] and one_tok in mismatch["answer"]
    ok = b.ask("requests 패치 승인 %s" % one_tok)
    assert "1 component(s) upgraded" in ok["answer"]
    fixed = open(str(env["tmp"] / "work" / "proj_fix" / "requirements.txt"), encoding="utf-8").read()
    assert "requests==2.31.0" in fixed and "pyyaml==5.3" in fixed                              # only what was approved changed
    assert len(read_json(str(env["ev"] / "proj" / "proj.json"))["patch"]["rounds"]) == 1


# ------------------------------------------------------------------ the model cannot supply what only the user may type
def test_tokens_sources_codes_and_reasons_must_be_the_users_own_text(env, world):
    """AC: BSA-AC-203"""
    b, rec = _analysed(env)
    tok = _token(rec)
    q = "그 패치 적용해줘"
    forged = [{"tool": "apply_patch", "args": {"token": tok}},                                              # correct token, but the user never typed it
              {"tool": "analyze_project", "args": {"source": "https://github.com/evil/repo"}},              # a source that is not in the question
              {"tool": "confirm_decision", "args": {"code": "0123456789ab"}},
              {"tool": "record_decision", "args": {"id": "CVE-2020-1111", "status": "false-positive", "reason": "model wrote this reason itself"}}]
    ok, dropped = chat.validate_calls(forged, rec, q)
    assert ok == [] and dropped["semantic"] == 4
    typed = "%s 승인, https://github.com/a/b 분석, 확정 0123456789ab, CVE-2020-1111 오탐 사유: 호출 경로에 없다고 직접 확인함" % tok
    ok2, d2 = chat.validate_calls([dict(forged[0]), {"tool": "analyze_project", "args": {"source": "https://github.com/a/b"}},
                                   forged[2], {"tool": "record_decision", "args": {"id": "cve-2020-1111", "status": "false-positive", "reason": "호출 경로에 없다고 직접 확인함"}}],
                                  rec, typed)
    assert len(ok2) == 4 and sum(d2.values()) == 0 and ok2[3]["args"]["id"] == "CVE-2020-1111"
    inferred = {"tool": "record_decision", "args": {"id": "CVE-2020-1111", "status": "false-positive", "reason": "호출 경로에 없다고 직접 확인함", "justification": JUST}}
    assert chat.validate_calls([inferred], rec, typed)[1]["semantic"] == 1                                  # a justification the user did not name is dropped
    assert chat.validate_calls([forged[0]], None, typed)[1]["semantic"] == 1                                # no project -> no patch
    before = tree_hash(env["origin"])
    _llm(world, [{"tool": "apply_patch", "args": {"token": tok}}])                                           # the model tries to patch on its own
    r = chat.Chatbot(evals.build_index(), {"proj": rec}, __import__("bts_sbom_app.llm", fromlist=["ChatClient"]).ChatClient("k"), env["acts"]()).ask(q, project="proj", use_llm=True)
    assert "apply_patch" not in r["tools"] and r["routing"] == "regex" and not os.path.exists(str(env["tmp"] / "work" / "proj_fix"))
    assert tree_hash(env["origin"]) == before
    assert "analyze_project" not in chat.catalog(False) and {"analyze_project", "apply_patch", "confirm_decision"} <= set(chat.catalog(True))


# ------------------------------------------------------------------ VEX decisions
def test_a_decision_is_previewed_then_recorded_only_with_the_confirm_code(env):
    """AC: BSA-AC-204"""
    b, rec = _analysed(env)
    q = "CVE-2020-5555 오탐 처리 justification %s by sec-team expires 2027-06-30 사유: 신뢰된 입력만 YAML 로 파싱한다" % JUST
    r = b.ask(q)
    code = actionsmod.decision_digest({"id": "CVE-2020-5555", "status": "false-positive", "reason": "신뢰된 입력만 YAML 로 파싱한다", "justification": JUST,
                                       "scope": "", "expires": "2027-06-30", "by": "sec-team"})
    assert "owner sec-team, expires 2027-06-30" in r["answer"] and "reply: confirm %s" % code in r["answer"] and "VEX outcome: not_affected" in r["answer"]
    assert not os.path.exists(str(env["ev"] / ".triage.json"))                                              # a preview writes no decision
    ro = env["bot"](actions=False).ask(q)
    assert "this chat is read-only" in ro["answer"] and "confirm " not in ro["answer"].split("reply:")[-1][:12]
    assert "Not recorded: no previewed decision" in b.ask("확정 111111111111")["answer"]
    done = b.ask("확정 %s" % code)
    assert "Recorded the VEX decision for CVE-2020-5555" in done["answer"]
    entry = read_json(str(env["ev"] / ".triage.json"))["CVE-2020-5555"]
    assert entry["via"] == "chat" and entry["justification"] == JUST and entry["by"] == "sec-team" and entry["expires"] == "2027-06-30"
    assert "Not recorded" in b.ask("확정 %s" % code)["answer"]                                                # a code works once
    pend = str(env["ev"] / ".pending_decisions.json")
    b.ask("CVE-2020-3333 오탐 사유: 이 항목은 우리 제품 범위 밖이다 justification %s" % JUST)
    data = read_json(pend)
    (k, v), = data.items()
    v["decision"]["reason"] = "changed after the preview"                                                     # tampering with the staged content
    open(pend, "w", encoding="utf-8").write(json.dumps(data))
    assert "Not recorded" in b.ask("확정 %s" % k)["answer"] and "CVE-2020-3333" not in read_json(str(env["ev"] / ".triage.json"))
    v["decision"]["reason"] = "이 항목은 우리 제품 범위 밖이다"
    v["ts"] = "2020-01-01T00:00:00+09:00"                                                                       # an old preview expires
    open(pend, "w", encoding="utf-8").write(json.dumps(data))
    assert "Not recorded" in b.ask("확정 %s" % k)["answer"]


def test_decisions_keep_the_fail_closed_rules_and_the_vex_export_shows_them(env):
    """AC: BSA-AC-205"""
    b, rec = _analysed(env)
    weak = b.ask("CVE-2020-1111 오탐 사유: 우리 코드에서 안 쓴다")
    assert "VEX outcome: rejected" in weak["answer"] and "false-positive needs a VEX justification" in weak["answer"] and "justification vulnerable" not in weak["answer"]
    short = b.ask("CVE-2020-1111 오탐 justification %s 사유: 짧음" % JUST)
    assert "VEX outcome: rejected" in short["answer"]                                                           # a 3-character reason is refused by the triage rules
    stale = b.ask("CVE-2099-0001 오탐 justification %s 사유: 존재하지 않는 취약점이라 무시한다" % JUST)
    assert "would be stale" in stale["answer"]
    code = actionsmod.decision_digest({"id": "CVE-2020-1111", "status": "accepted", "reason": "벤더 릴리스를 기다리는 중이다", "justification": "", "scope": "", "expires": "", "by": ""})
    acc = b.ask("CVE-2020-1111 위험 수용 사유: 벤더 릴리스를 기다리는 중이다")
    assert "VEX outcome: accepted" in acc["answer"] and code in acc["answer"]
    b.ask("확정 %s" % code)
    exp = b.ask("VEX 내보내줘")
    assert "OpenVEX of proj: 3 statement(s) (affected 3); decisions: accepted 1" in exp["answer"]
    path = str(env["ev"] / "proj" / "proj.triaged.vex.json")
    doc = read_json(path)
    st = next(s for s in doc["statements"] if s["vulnerability"]["name"] == "CVE-2020-1111")
    assert st["status"] == "affected" and "벤더 릴리스를 기다리는 중이다" in st["action_statement"]
    stamp = os.stat(path).st_mtime_ns
    ro = env["bot"](actions=False).ask("VEX 내보내줘")
    assert "decisions: accepted 1" in ro["answer"] and "Not written (read-only chat)" in ro["answer"]
    assert os.stat(path).st_mtime_ns == stamp and read_json(path) == doc                                       # a read-only session leaves the file alone


# ------------------------------------------------------------------ license risks and proposals
def test_license_risk_view_depends_on_the_distribution_and_proposals_are_tagged_by_origin():
    """AC: BSA-AC-206"""
    rec = evals.synthetic_project()
    rec["components"] += [{"name": "gplthing", "version": "1.0", "ecosystem": "PyPI", "license": "GPL-3.0-only", "license_category": "strong-copyleft", "vulns": 0, "files": []},
                          {"name": "mystery", "version": "2", "ecosystem": "PyPI", "license": "", "license_category": "unknown", "vulns": 0, "files": []}]
    binary = chat.run_tool(rec, "license_risks", {})[0]["lines"]
    saas = chat.run_tool(rec, "license_risks", {"distribution": "saas"})[0]["lines"]
    internal = chat.run_tool(rec, "license_risks", {"distribution": "internal"})[0]["lines"]
    assert any("strong-copyleft" in x and "offer corresponding source" in x for x in binary)
    assert any("gplthing@1.0" in x for x in binary) and any("mystery@2" in x for x in binary[-3:])                # unresolved ones are named
    assert not any("strong-copyleft" in x for x in internal) and any("for a saas distribution" in x for x in saas)
    assert chat.validate_calls([{"tool": "license_risks", "args": {"distribution": "SaaS"}}, {"tool": "license_risks", "args": {"distribution": "lan"}}], rec)[0] == [
        {"tool": "license_risks", "args": {"distribution": "saas"}}]
    rec["proposals"] = {"source": "deterministic", "items": [{"action": "upgrade", "risk": "low", "title": "Upgrade requests", "rationale": "clears 1 advisory"}]}
    det = chat.run_tool(rec, "proposals", {})[0]
    assert det["trust"] == "tool" and "deterministic rules" in det["lines"][0]
    rec["proposals"]["source"] = "exaone"
    llm = chat.run_tool(rec, "proposals", {})[0]
    assert llm["trust"] == "untrusted-quote" and "validated against the analysed evidence" in llm["lines"][0]
    assert "No fix proposal" in chat.run_tool({"name": "x", "proposals": {}}, "proposals", {})[0]["lines"][0]


# ------------------------------------------------------------------ service and CLI opt-in
def test_the_service_offers_actions_only_when_started_with_them(env, world):
    """AC: BSA-AC-207"""
    b, rec = _analysed(env)

    def serve(flag):
        st = server.State(evals.repo_root(), str(env["ev"]), None, flag)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]

    def ask(base, q):
        req = urllib.request.Request(base + "/api/chat", data=json.dumps({"question": q, "project": "proj"}).encode(), headers={"Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                return json.loads(r.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read())

    off, base_off = serve(False)
    on, base_on = serve(True)
    try:
        assert "read-only" in ask(base_off, "패치 승인 %s" % _token(rec))["answer"]
        assert "Not applied: the token does not match" in ask(base_on, "패치 승인 0000000000000000")["answer"]
        assert "Approval token %s" % _token(rec) in ask(base_on, "패치 해줘")["answer"] and "apply patch" in ask(base_on, "패치 해줘")["answer"]
        assert "bts-sbom-app patch" in ask(base_off, "패치 해줘")["answer"]                                      # read-only: the CLI route with the same token
    finally:
        off.shutdown()
        on.shutdown()


def test_the_full_approval_chain_runs_over_http_and_the_readonly_server_refuses(env, monkeypatch):
    """AC: BSA-AC-609. The positive half of the approval chain over real HTTP - plan (token) -> approval sentence ->
    applied -> record updated - plus the read-only refusal of the same sentence. This is the 2026-11-22 live run
    (AC-593) made replayable; until now only its negative side ran over HTTP."""
    b, rec = _analysed(env)
    tok = _token(rec)
    real = actionsmod.ChatActions

    def offline_actions(root, evidence, client=None):        # the State builds real ChatActions; the test needs no network
        return real(root, evidence, client=None, scanner=FakeScanner(), offline=True, use_llm=False,
                    work_root=str(env["tmp"] / "work"), cache_dir=str(env["tmp"] / "cache"), today=TODAY)
    monkeypatch.setattr(server.actionsmod, "ChatActions", offline_actions)

    def serve(flag):
        st = server.State(evals.repo_root(), str(env["ev"]), None, flag)
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
        threading.Thread(target=httpd.serve_forever, daemon=True).start()
        return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]

    def ask(base, q):
        req = urllib.request.Request(base + "/api/chat", data=json.dumps({"question": q, "project": "proj"}).encode(),
                                     headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=120) as r:
            return json.loads(r.read())

    off, base_off = serve(False)
    on, base_on = serve(True)
    try:
        plan = ask(base_on, "패치 해줘")                      # turn 1: the plan shows exactly its own token
        assert plan["found"] and "Approval token %s" % tok in plan["answer"], plan["answer"][:200]
        assert "read-only" not in plan["answer"]
        r = ask(base_on, "패치 승인 %s" % tok)                # turn 2: the approval sentence applies the plan
        assert "Patch applied in an isolated work copy" in r["answer"], r["answer"][:300]
        assert "apply_patch" in r["tools"]
        folder, saved = next(iter(cli.project_records(str(env["ev"])).values()))
        assert saved["patch"]["status"] == "applied" and saved["patch"]["work_copy"]         # the record the console reads
        assert "read-only" in ask(base_off, "패치 승인 %s" % tok)["answer"]                  # the flag-off server refuses the same sentence
    finally:
        off.shutdown()
        on.shutdown()


def test_cli_chat_needs_a_question_or_interactive_mode_and_keeps_reading_in_a_session(env, monkeypatch, capsys):
    """AC: BSA-AC-208"""
    b, rec = _analysed(env)
    assert cli.main(["chat", "--evidence", str(env["ev"])]) == 2
    monkeypatch.setattr("sys.stdin", io.StringIO("라이선스 의무가 뭐야\n패치 해줘\n\n이 줄은 읽지 않는다\n"))
    assert cli.main(["chat", "--interactive", "--evidence", str(env["ev"]), "--project", "proj"]) == 0
    out = capsys.readouterr().out
    assert "actions off (read-only)" in out and out.count("found=True") == 2 and "License risk view of proj" in out and "read-only - apply them with" in out
    assert "이 줄은 읽지 않는다" not in out


# ------------------------------------------------------------------ routing measurement
def test_the_llm_planner_reaches_the_governance_tools_the_regex_router_misses(world):
    """AC: BSA-AC-209"""
    from bts_sbom_app import evals_chat
    from bts_sbom_app.llm import ChatClient
    base = evals_chat.governance_routing_eval()
    assert base["cases"] == 8 and base["tool_routing_rate"] == 0.25 and base["routing"] == {"regex": 8}            # measured: 2 of 8 by keyword
    plans = {"미국 정부": [{"tool": "sbom_conformance", "args": {}}], "저번 검사": [{"tool": "what_changed", "args": {}}],
             "SaaS": [{"tool": "license_risks", "args": {"distribution": "saas"}}], "해결책": [{"tool": "proposals", "args": {}}],
             "건드리지": [{"tool": "plan_patch", "args": {}}], "copyleft": [{"tool": "license_risks", "args": {}}],
             "NTIA": [{"tool": "sbom_conformance", "args": {"regime": "ntia-2021"}}],
             "쓰임새": [{"tool": "record_decision", "args": {"id": "CVE-2018-18074", "status": "false-positive", "reason": "우리 쓰임새에선 문제 안 되니까"}}]}

    def handler(body):
        user = body["messages"][-1]["content"]
        if "QUESTION:" in user:
            return 200, json.dumps({"choices": [{"message": {"content": "not json"}}], "usage": {}})
        question = json.loads(user)["question"]                                                               # the payload also holds the tool catalog: match the question only
        for k, calls in plans.items():
            if k in question:
                return 200, json.dumps({"choices": [{"message": {"content": json.dumps({"calls": calls})}}], "usage": {}})
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps({"calls": []})}}], "usage": {}})

    world.llm_handler = handler
    r = evals_chat.governance_routing_eval(client=ChatClient("k"))
    assert r["tool_routing_rate"] == 1.0 and r["routing"] == {"llm": 8} and r["misses"] == []
    plans["쓰임새"] = [{"tool": "record_decision", "args": {"id": "CVE-2018-18074", "status": "false-positive", "reason": "모델이 새로 쓴 사유"}}]      # a paraphrased reason
    forged = evals_chat.governance_routing_eval(client=ChatClient("k"))
    assert forged["tool_routing_rate"] == 0.875 and [m["expected"] for m in forged["misses"]] == ["record_decision"]


def test_evalchat_command_runs_the_regex_baseline_and_lists_the_misses(capsys):
    """The routing measurement is runnable from the CLI (exit 0 - the numbers are a measurement, not a gate)."""
    assert cli.main(["evalchat", "--json"]) == 0
    out = capsys.readouterr().out
    r = json.loads(out)
    assert r["cases"] == 8 and r["router"] == "regex" and r["tool_routing_rate"] == 0.25 and len(r["misses"]) == 6
    assert cli.main(["evalchat"]) == 0
    line = capsys.readouterr().out
    assert "regex router: 2 of 8" in line and "license_risks" in line
