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
    assert sections and sections.group(1).count("groups:") == 6, "six collapsed sections must be declared"
    for token in ("bts-rail-new", "railSessions", "bts-rail-grp", "bts-rail-assist"):
        assert token in con
    body = re.search(r"function buildSideNav\(\) \{(.*?)\n  \}", con, re.S).group(1)
    assert 'class="rtab" data-sv' in body                       # the .rtab contract the shell tests rely on
    assert 'data-act="goto"' in body and "renderRailSessions();" in body
    sess = con.split("function renderRailSessions")[1][:1400]
    assert 'data-act="session"' in sess and 'class="bts-rail-session' in sess     # the session rows open their report
    groups_block = con[con.index("var GROUPS"):con.index("var SECTIONS")]
    for m in ("git", "oss", "lock", "container", "risk", "ssvc", "epss", "exploit-mat", "report", "archintel",
              "diagrams", "dep-graph", "arch", "code", "supply-chain", "books", "ntia", "conformance", "vex", "ir",
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


def test_the_conversation_drives_the_app_slash_next_steps_and_memory():
    """AC: BSA-AC-592"""
    panel = _read("bts_chat_panel.js")
    # IF-A04: slash commands drive the client and never reach the model
    assert "var SLASH = [" in panel and "function runSlash" in panel
    slash_body = panel.split("function runSlash")[1].split("var NEXT")[0]        # the runSlash body only
    assert "/api/chat/stream" not in slash_body and "fetch(" not in slash_body   # app commands never reach the model
    send_body = panel[panel.index("function send(text)"):]
    assert "if (runSlash(q)) { saveShown(); return; }" in send_body       # the slash branch returns BEFORE the fetch
    assert "document.getElementById('scaGitUrl')" in panel and "run.click()" in panel   # /scan <target> runs the unified Analyze
    assert "모르는 명령" in panel                                                # an unknown command is reported, not guessed
    # IF-B04: the finished turn offers the panels its tools actually touched
    nxt = re.search(r"var NEXT = \{(.*?)\};", panel, re.S)
    assert nxt and nxt.group(1).count("[") >= 12
    assert "var turnTools = [];" in panel and "bts-cd-next-b" in panel
    assert "openPanel(n[0]);" in panel                                           # suggestions dispatch the same panel jump
    # CL-12: the conversation persists per project in this browser; dead controls never persist
    for token in ("keyFor", "saveShown", "loadShown", "followProject", "'bts-chat-'"):
        assert token in panel
    assert "bts-cd-approve, .bts-cd-next" in panel                               # approve/next rows are stripped on save
    assert "addEventListener('bts:project'" in panel and "function followProject" in panel   # selectProject drives the swap (programmatic moves fire no change event)
    assert "chatDockClear" in panel                                              # a per-project clear exists
    css = _read("bts_console.css")
    for cls in (".bts-cd-next", ".bts-cd-next-b", ".bts-cd-clear"):
        assert cls in css


def test_pane_activation_survives_the_ccd_layout_transform():
    """AC: BSA-AC-1278. Regression (live user journey, 2026-11-28): the CCD transform (bts_ccd.js) moves
    .bts-content — the .rpane set included — into #ccDrawer, but activate() still toggled
    '#view-scan .rpane' (0 matches after the move), so EVERY rail pane switch was a silent no-op in the
    CCD layout. activate() must query BOTH containers."""
    con = _read("bts_console.js")
    m = re.search(r"function activate\(sv, exact\) \{(.*?)\n  \}", con, re.S)
    assert m, "activate() not found"
    body = m.group(1)
    assert "#ccDrawer .rpane" in body and "#view-scan .rpane" in body          # both layouts served
    assert "var panes = '#ccDrawer .rpane, #view-scan .rpane';" in body        # the toggle reaches the moved panes
    assert "$$(panes).forEach" in body                                         # the toggle uses the combined selector
    rtab = re.search(r"\$\((tabSel|'#ccDrawer \.rtab)", body)
    assert rtab, "the group-tab lookup must cover the drawer too"
    ccd = _read("bts_ccd.js")
    assert "drawer.appendChild(content)" in ccd                                # the transform is the premise of the fix
