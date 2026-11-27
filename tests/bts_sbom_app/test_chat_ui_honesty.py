"""The chat renderers show what an answer alone does not: handoff, clarification, partial coverage, partial turn, reviewer note, version stamp."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "js", "render_harness.js")
WEB = os.path.join(os.path.dirname(HERE), "..", "bts_sbom_app", "web")

BASE = {"found": True, "answer": "overview text", "answer_source": "tools", "citation_accuracy": 1.0, "routing": "regex", "retrieval": {"top": []}}


def js(*calls):
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    payload = json.dumps([{"mod": m, "fn": f, "args": list(a)} for m, f, *a in calls])
    p = subprocess.run([node, HARNESS], input=payload, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def test_a_handoff_a_clarification_and_a_reviewer_note_are_each_shown_once_as_text_markers():
    """AC: BSA-AC-1220"""
    d = dict(BASE, escalation={"trigger": "no_progress", "destination": "security-owner", "id": "E-1a2b3c4d", "summary": "3 consecutive unanswered questions"},
             clarify={"candidates": ["alpha", "beta"]}, reviewer_notes=[{"id": "E-1a2b3c4d", "by": "sec-lead", "note": "upgrade approved"}])
    m = js(("ui", "renderChatAnswer", d))[0]
    assert m.count("[handoff]") == 1 and "trigger no_progress, id E-1a2b3c4d" in m and "3 consecutive unanswered questions" in m
    assert m.count("[which project?]") == 1 and "alpha, beta" in m
    assert m.count("[reviewer note]") == 1 and "sec-lead on E-1a2b3c4d: upgrade approved" in m
    assert js(("ui", "chatExtras", d))[0].count("bts-note") == 3                                         # the exported helper the stream panel reuses


def test_a_partial_scan_and_a_turn_with_a_failed_tool_each_say_so_and_a_complete_turn_says_nothing():
    """AC: BSA-AC-1221"""
    d = dict(BASE, coverage={"status": "partial", "gaps": [{"code": "mode:offline"}, {"code": "unqueried"}]}, status="partial", tool_errors=[{"tool": "overview"}, {"tool": "license"}])
    m = js(("ui", "renderChatAnswer", d))[0]
    assert "[partial coverage]</b> mode:offline, unqueried" in m and "NOT verified clean" in m
    assert "[partial turn]</b> failed tool(s): overview, license" in m
    plain = js(("ui", "renderChatAnswer", dict(BASE, coverage={"status": "complete", "gaps": []}, status="complete", tool_errors=[], escalation=None, clarify=None, reviewer_notes=[])))[0]
    assert plain.count("bts-note") == 0 and "[partial" not in plain and "[handoff]" not in plain
    assert js(("ui", "chatExtras", None))[0] == "" and js(("ui", "chatExtras", {}))[0] == ""


def test_the_version_stamp_is_one_line_and_every_dynamic_value_is_escaped():
    """AC: BSA-AC-1222"""
    d = dict(BASE, versions={"app": "0.5.0", "model": "gpt-5-mini", "prompt_digest": "d4b64f1a53b9", "spec": "9f2c<img onerror=1>"},
             escalation={"trigger": "human_request", "destination": "<script>alert(1)</script>", "id": "E-1"}, reviewer_notes=[{"id": "E-1", "by": "<b>x</b>", "note": 'a "quote" & <i>'}])
    m = js(("ui", "renderChatAnswer", d))[0]
    assert m.count("versions: app 0.5.0 · model gpt-5-mini · prompts d4b64f1a53b9 · spec 9f2c&lt;img onerror=1&gt;") == 1
    assert "<script>" not in m and "<img" not in m and "&lt;script&gt;alert(1)&lt;/script&gt;" in m and "&lt;b&gt;x&lt;/b&gt;" in m and "&quot;quote&quot; &amp; &lt;i&gt;" in m
    assert "versions:" not in js(("ui", "renderChatAnswer", dict(BASE, versions={})))[0]


def test_the_answer_region_is_a_polite_live_region_in_both_renderers_and_the_stream_panel_uses_the_shared_helper():
    """AC: BSA-AC-1223"""
    assert js(("ui", "renderChatAnswer", BASE))[0].count('class="bts-chat-out" aria-live="polite"') == 1
    panel = open(os.path.join(WEB, "bts_chat_panel.js"), encoding="utf-8").read()
    assert panel.count('class="bts-chat-out" aria-live="polite"') == 1                                  # 1 of 1 stream renderer
    assert "U.chatExtras(fin)" in panel and "chatExtras: chatExtras" in open(os.path.join(WEB, "bts_ui.js"), encoding="utf-8").read()
