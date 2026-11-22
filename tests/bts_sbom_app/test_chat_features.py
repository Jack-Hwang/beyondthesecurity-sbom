"""The chat-driven feature suite: one conversational question per chat-runnable feature, run against the live
service by scripts/chat_features_run.py (evidence/chat_features/report.json). These tests pin the suite itself:
coverage (every read tool + the knowledge lane has a question), runner hygiene, and the Korean advisory-id
extraction that the fleet/proposal questions depend on."""
from __future__ import annotations

import json
import os

from bts_sbom_app.chat import _ID

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SUITE = os.path.join(ROOT, "evals", "chat_features.json")


def _suite() -> list:
    with open(SUITE, encoding="utf-8") as fh:
        return json.load(fh)


def test_every_read_tool_has_a_question():
    """AC: BSA-AC-558."""
    from bts_sbom_app.chat import TOOL_CATALOG, WRITE_TOOLS
    suite = _suite()
    tools = {r["tool"] for r in suite if r.get("tool")}
    read_tools = {t for t in TOOL_CATALOG if t not in WRITE_TOOLS} - {"record_decision"}
    missing = read_tools - tools
    assert not missing, "chat questions missing for read tools: %s" % sorted(missing)


def test_rows_carry_project_or_explicitly_target_the_knowledge_lane():
    """AC: BSA-AC-558."""
    for r in _suite():
        assert r.get("project") or r.get("tool") in (None, "latest_arch", "book_search", "affected_projects"), r["feature"]


def test_korean_particle_glued_to_an_id_still_extracts():
    """AC: BSA-AC-558. A Hangul particle directly after the id ("CVE-2018-18074에") used to break the \\b word
    boundary and silently killed fleet/vuln routing for every Korean sentence - measured 2026-11-22."""
    from bts_sbom_app.chat import _ID as advisory_id
    assert advisory_id.findall("CVE-2018-18074에 영향받는 프로젝트") == ["CVE-2018-18074"]
    assert advisory_id.findall("GHSA-x84v-xcm2-53pg은 requests 이슈") == ["GHSA-x84v-xcm2-53pg"]
    assert advisory_id.findall("CVE-2018-18074 is affected") == ["CVE-2018-18074"]


def test_runner_writes_a_report(tmp_path, capsys):
    """AC: BSA-AC-558."""
    import scripts.chat_features_run as runner
    base = "http://127.0.0.1:65530"                    # nothing listens: the runner records the failure, never aborts
    rows = [{"feature": "x", "tool": None, "q": "질문"}]
    results = runner.run(base, rows)
    assert results[0]["issues"] and "request failed" in results[0]["issues"][0]
