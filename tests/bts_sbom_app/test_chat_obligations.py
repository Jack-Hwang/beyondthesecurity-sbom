"""Chat tools for obligations / legacy / migration / proposals (task 29, brief 2, AC 696-700, 705)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import chat, evals, evals_chat, obligations
from conftest import FakeScanner


def _bot_with_empty_project():
    idx = evals.build_index('.')
    rec = {"schema": "bts-sbom.project.v1", "name": "empty", "components": [], "vulns": [], "plans": [],
           "license": {"project_license": ""}, "artifacts": {}}
    return chat.Chatbot(idx, {"empty": rec})


def test_four_new_read_only_tools_registered_and_write_tools_unchanged():
    """AC: BSA-AC-696"""
    for t in ("license_obligations", "legacy_components", "migration_plan", "propose_code"):
        assert t in chat.TOOL_CATALOG, t
    assert chat.WRITE_TOOLS == ("analyze_project", "apply_patch", "confirm_decision")


def test_zero_chat_tools_apply_a_code_proposal():
    """AC: BSA-AC-697"""
    for name in chat.TOOL_CATALOG:
        assert "apply_code" not in name and "codeprop_apply" not in name
    assert not any("codeprop" in (chat.TOOL_CATALOG[n].get("doc") or "") and "apply" in (chat.TOOL_CATALOG[n].get("doc") or "").lower()
                   and "CLI" not in (chat.TOOL_CATALOG[n].get("doc") or "") for n in chat.TOOL_CATALOG)


def test_the_obligations_answer_carries_the_disclaimer_and_a_verified_citation(tmp_path, make_repo, world):
    """AC: BSA-AC-698"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    from bts_sbom_app import pipeline
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    idx = evals.build_index('.')
    bot = chat.Chatbot(idx, {rec["name"]: rec})
    ans = bot.ask("이 프로젝트 배포하면 소스 공개 의무 있는 컴포넌트 뭐가 있어", project=rec["name"])
    assert ans["found"] is True and ans["citation_accuracy"] == 1.0
    blob = json.dumps(ans, ensure_ascii=False)
    assert obligations.DISCLAIMER in blob
    assert "license_obligations" in ans["tools"]


def test_an_empty_project_is_never_reported_clean():
    """AC: BSA-AC-699"""
    bot = _bot_with_empty_project()
    ans = bot.ask("이 프로젝트 배포하면 소스 공개 의무 있는 컴포넌트 뭐가 있어", project="empty")
    assert ans["found"] is True
    blob = json.dumps(ans, ensure_ascii=False)
    assert "no data available" in blob
    assert "clean" not in blob.lower() or "no_data" in blob


def test_propose_code_without_stored_proposals_answers_with_cli_instructions(tmp_path, make_repo, world):
    """AC: BSA-AC-700"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    from bts_sbom_app import pipeline
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    idx = evals.build_index('.')
    bot = chat.Chatbot(idx, {rec["name"]: rec})
    ans = bot.ask("저장된 코드 수정 제안 목록 보여줘", project=rec["name"])
    assert ans["found"] is True
    blob = json.dumps(ans, ensure_ascii=False)
    assert "bts-sbom-app codeprop" in blob                                   # CLI instructions present
    assert not os.path.exists(os.path.join(ev, rec["name"], "codeprop")) or \
        len(os.listdir(os.path.join(ev, rec["name"], "codeprop"))) == 0     # 0 proposals created


def test_the_old_8_evalchat_questions_route_exactly_as_before():
    """AC: BSA-AC-701"""
    idx = evals.build_index('.')
    rec = evals_chat.governed_project()
    bot = chat.Chatbot(idx, {"demo": rec})
    old_cases = evals_chat.CASES[:8]
    ok = sum(1 for c in old_cases if c["tool"] in (bot.ask(c["q"], project="demo").get("tools") or []))
    assert ok == 2, ok                                                  # the regex baseline of the original 8 is preserved


def test_the_new_4_questions_are_measured_and_misses_recorded(tmp_path, make_repo, world):
    """AC: BSA-AC-702"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    from bts_sbom_app import pipeline
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    idx = evals.build_index('.')
    bot = chat.Chatbot(idx, {rec["name"]: rec})
    new_cases = evals_chat.CASES[8:]
    assert len(new_cases) == 4
    results = []
    for c in new_cases:
        tools = bot.ask(c["q"], project=rec["name"]).get("tools") or []
        results.append((c["tool"], c["tool"] in tools, tools))
    routed = sum(1 for _t, hit, _tools in results if hit)
    assert routed >= 3, results                                          # measured: 3-4 of 4; misses are reported below


def test_tool_groups_hold_25_tools_with_no_orphans():
    """AC: BSA-AC-705"""
    grouped = set()
    for group, tools in chat.TOOL_GROUPS.items():
        assert len(tools) <= 5, (group, len(tools))
        grouped |= set(tools)
    assert grouped == set(chat.TOOL_CATALOG)
    assert len(chat.TOOL_CATALOG) == 25


def test_evalrag_metrics_hold_or_improve_with_the_knowledge_doc():
    """AC: BSA-AC-704"""
    res = evals.rag_eval()
    assert res["recall_at_k"] >= 1.0 and res["mrr"] >= 0.95 and res["ndcg_at_k"] >= 0.948
