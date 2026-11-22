"""The Claude-client shell (CCD 명세 기반, 사용자 지시 2026-11-22 "메뉴를 주요 기능으로 통합, claude client
기능으로 따라서 만들어"): the rail is a SESSION list first (CCD Code 탭 해부 zone 1), the twelve feature panels
live inside five collapsed sections (nothing removed), ＋ 새 분석 starts a new analysis, and the conversation
surface (the chat dock) ships OPEN as the main window with the assistant one click away (IF-B04 정신: 기능은
대화가 앱을 부른다). Static structure checks over web/bts_console.js, index.html, bts_chat_panel.js, css."""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WEB = os.path.join(ROOT, "bts_sbom_app", "web")


def _read(name: str) -> str:
    with open(os.path.join(WEB, name), encoding="utf-8") as fh:
        return fh.read()


def test_the_rail_is_a_session_list_with_five_collapsed_feature_sections():
    """AC: BSA-AC-583"""
    con = _read("bts_console.js")
    sections = re.search(r"var SECTIONS = \[(.*?)\];", con, re.S)
    assert sections and sections.group(1).count("groups:") == 5, "five collapsed sections must be declared"
    for token in ("bts-rail-new", "railSessions", "bts-rail-grp", "bts-rail-assist"):
        assert token in con
    body = re.search(r"function buildSideNav\(\) \{(.*?)\n  \}", con, re.S).group(1)
    assert 'class="rtab" data-sv' in body                       # the .rtab contract the shell tests rely on
    assert 'data-act="goto"' in body and "renderRailSessions();" in body
    sess = con.split("function renderRailSessions")[1][:1400]
    assert 'data-act="session"' in sess and 'class="bts-rail-session' in sess     # the session rows open their report
    groups_block = con[con.index("var GROUPS"):con.index("var SECTIONS")]
    for m in ("git", "oss", "lock", "container", "risk", "ssvc", "epss", "exploit-mat", "report", "archintel",
              "diagrams", "dep-graph", "arch", "code", "supply-chain", "books", "ntia", "conformance", "vex",
              "license-risk", "sectors", "fix-plan", "fix-pr", "more", "fleet", "changes"):
        assert "'" + m + "'" in groups_block, "panel member %s lost" % m   # nothing removed: all 26 panes stay reachable
    handler = re.search(r"else if \(act === 'session'\).*activate\('report', true\);", con, re.S)
    assert handler, "a rail session must open its report panel"
    assert "act === 'new'" in con and "activate('git', true);" in con
    assert "act === 'assist'" in con and "function focusAssistant" in con
    assert "renderRailSessions();" in con.split("function loadHistory")[1][:400]      # the list refreshes with the history


def test_the_conversation_surface_ships_open_and_enlarged():
    """AC: BSA-AC-583"""
    html = _read("index.html")
    assert 'class="bts-chatdock open"' in html                                   # ships open, not collapsed
    panel = _read("bts_chat_panel.js")
    assert re.search(r"var open = .*root\.className", panel)                     # the markup decides the initial state
    css = _read("bts_console.css")
    mh = re.search(r"\.bts-cd-msgs\{max-height:(\d+)vh", css)
    assert mh and int(mh.group(1)) >= 50, "the main conversation surface must be enlarged (>= 50vh)"


def test_rail_styles_and_session_rows_are_csp_clean():
    """AC: BSA-AC-583"""
    con = _read("bts_console.js")
    seg = con[con.index("function buildSideNav"):con.index("function groupOf")]
    assert seg.count("esc(") >= 5                                                # dynamic values in the rail markup are escaped
    assert "onclick" not in seg and "innerHTML = h;" in seg                      # CSP: no inline handlers
    css = _read("bts_console.css")
    for cls in (".bts-rail-new", ".bts-rail-session", ".bts-rail-grp", ".bts-rail-chip", ".bts-rail-assist"):
        assert cls in css
