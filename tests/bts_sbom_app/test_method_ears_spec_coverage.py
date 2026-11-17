"""Method test: whole-document EARS 5-pattern coverage gate (closes advlab-harness:M27,
advlab-project:M19, w1s3:w1s3-06, w1s3:w1s3-07).

speclint already checked, per AC line, that the line carries one of the 5 EARS pattern keywords plus
"shall" plus a measured number. Nothing checked that all 5 keywords (Ubiquitous/Event/State/Optional/
Unwanted) are actually used somewhere across the whole spec document: [State] had 0 of 139 lines.
"""
from __future__ import annotations

import os

import pytest

from bts_sbom_app import speclint
from bts_sbom_app.llm import ChatClient, LLMUnavailable

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC = os.path.join(ROOT, "specs", "bts_sbom_app_features.md")


def test_all_five_ears_patterns_are_used_somewhere_in_the_real_spec():
    assert speclint.all_patterns_covered(SPEC) == []


def test_missing_pattern_is_named_once_its_only_ac_line_is_removed(tmp_path):
    lines = open(SPEC, "r", encoding="utf-8").readlines()
    kept = [ln for ln in lines if "[State]" not in ln]
    assert len(kept) < len(lines)  # the fixture really drops at least one real [State] AC line
    fixture = tmp_path / "fixture_no_state.md"
    fixture.write_text("".join(kept), encoding="utf-8")
    assert speclint.all_patterns_covered(str(fixture)) == ["State"]


def test_budget_exhausted_chatbot_stays_extractive_and_never_retries():
    """AC: BSA-AC-205

    Grounds the new [State] AC in behavior that is already real, not merely asserted: the daily-budget
    check raises before any network attempt, so there is nothing to retry and no call is made.
    """
    client = ChatClient("k", daily_budget=0)
    with pytest.raises(LLMUnavailable):
        client.complete("system", "question")
    assert client.calls == 0
