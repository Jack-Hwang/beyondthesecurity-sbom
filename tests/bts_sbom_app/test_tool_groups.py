"""Tool groups: <=5 per group, full coverage, flag-gated routing (task 21, AC 561-565)."""
from __future__ import annotations

import json

from bts_sbom_app import chat


def test_groups_hold_at_most_five_and_cover_all_tools():
    """AC: BSA-AC-561"""
    grouped = set()
    for group, tools in chat.TOOL_GROUPS.items():
        assert len(tools) <= 5, (group, len(tools))
        grouped |= set(tools)
    assert grouped == set(chat.TOOL_CATALOG)                     # 0 orphans, 0 unknown names


def test_the_flag_shows_only_the_matched_group(monkeypatch):
    """AC: BSA-AC-562"""
    monkeypatch.setenv("BTS_SBOM_TOOL_GROUPS", "1")
    rec = {"components": [{"name": "requests"}]}
    seen = {}

    def fake_complete(system, user, max_tokens=0, json_mode=False):
        payload = json.loads(user)
        seen["tools"] = set(payload["tools"])
        return '{"calls": [{"tool": "vuln_lookup", "args": {"id": "CVE-2020-1111"}}]}'

    client = _FakeClient(fake_complete)
    chat.plan_tools("CVE-2020-1111 취약점이 뭐야", rec, client)
    assert len(seen["tools"]) <= 5 and "vuln_lookup" in seen["tools"]


def test_no_group_match_shows_everything_and_counts_one_fallback(monkeypatch):
    """AC: BSA-AC-563"""
    monkeypatch.setenv("BTS_SBOM_TOOL_GROUPS", "1")
    chat.reset_group_fallbacks()
    rec = {"components": [{"name": "requests"}]}

    def fake_complete(system, user, max_tokens=0, json_mode=False):
        return '{"calls": []}'

    chat.plan_tools("xqzt undefined-topic question", rec, _FakeClient(fake_complete))
    assert chat.GROUP_FALLBACKS == 1


def test_flag_off_shows_all_21_tools_exactly_as_before(monkeypatch):
    """AC: BSA-AC-565"""
    monkeypatch.delenv("BTS_SBOM_TOOL_GROUPS", raising=False)
    chat.reset_group_fallbacks()                                 # the module counter may carry another test's fallback
    rec = {"components": [{"name": "requests"}]}
    seen = {}

    def fake_complete(system, user, max_tokens=0, json_mode=False):
        payload = json.loads(user)
        seen["tools"] = set(payload["tools"])
        return '{"calls": []}'

    chat.plan_tools("CVE-2020-1111 취약점이 뭐야", rec, _FakeClient(fake_complete))
    assert seen["tools"] == set(chat.catalog(False)) and chat.GROUP_FALLBACKS == 0   # the planner sees what it always saw


class _FakeClient:
    def __init__(self, fn):
        self._fn = fn
        self.model = "fake"
        self.available = True
        self.calls_today = lambda: 0
        self.daily_budget = 80

    def complete(self, system, user, max_tokens=2048, json_mode=False):
        return self._fn(system, user, max_tokens=max_tokens, json_mode=json_mode)


def test_flag_on_keeps_the_chat_eval_accuracy(monkeypatch):
    """AC: BSA-AC-564"""
    from bts_sbom_app import evals
    monkeypatch.delenv("BTS_SBOM_TOOL_GROUPS", raising=False)
    baseline = evals.chat_eval()["tool_routing_rate"]
    monkeypatch.setenv("BTS_SBOM_TOOL_GROUPS", "1")
    with_flag = evals.chat_eval()["tool_routing_rate"]
    assert with_flag >= baseline                                  # 0 regressions with the flag on
