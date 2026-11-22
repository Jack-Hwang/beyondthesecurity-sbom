"""The desktop-app shell (sidebar navigation) and the dedicated Report tab (header, ScaApp body, governance cards).

The page structure is checked statically (index.html / bts_console.js content), the pure builders of
bts_report.js run through the Node render harness (tests/js/render_harness.js, skipped when node is absent) -
the same pattern as test_governance_ui.py and test_kind_manifests.py.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import shutil

import pytest

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "..", "..", "bts_sbom_app", "web")
HARNESS = os.path.join(HERE, "js", "render_harness.js")


def _read(name: str) -> str:
    with open(os.path.join(WEB, name), "r", encoding="utf-8") as fh:
        return fh.read()


def js(*calls):
    if not shutil.which("node"):
        pytest.skip("node is not installed")
    import subprocess
    # encoding="utf-8": the builders emit UTF-8 Korean text; the default cp949 on a Korean Windows cannot decode it
    proc = subprocess.run(["node", HARNESS], input=json.dumps(list(calls)), capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert proc.returncode == 0, proc.stderr
    return json.loads(proc.stdout)


def test_shell_sidebar_replaces_the_top_tab_bar():
    """AC: BSA-AC-538."""
    html = _read("index.html")
    con = _read("bts_console.js")
    assert 'id="sideNav"' in html and 'class="bts-sidenav"' in html
    assert 'id="scanTabs"' not in html                      # the static top tab bar is gone
    assert 'class="bts-content"' in html
    m = re.search(r"var GROUPS = \{(.*?)\};", con, re.S)
    assert m, "GROUPS table missing"
    groups = m.group(1)
    # chat is owned by the bottom-dock refactor (bts_chat_panel.js, parallel session) and is asserted there
    for g in ("git", "risk", "prioritize", "graph-health", "compliance", "fix", "report", "archintel", "books", "more"):
        assert "'" + g + "':" in groups, "sidebar group %s missing" % g
    assert "'git': ['git', 'oss', 'lock', 'container']" in groups       # ADR-0026: the OSS Scanner group is a Scan-section member
    assert "function buildSideNav()" in con and "buildSideNav();" in con
    # the sidebar buttons keep the .rtab[data-sv] contract that the delegated click handler and activate() rely on
    assert 'class="rtab" data-sv' in con


def test_report_tab_structure_and_single_mount():
    """AC: BSA-AC-539."""
    html = _read("index.html")
    con = _read("bts_console.js")
    assert html.count('data-sv="report"') == 1 and 'id="reportOut"' in html
    assert 'id="reportHead"' in html and 'id="govCards"' in html and 'id="reportBanner"' in html
    assert "scaReportOut" not in html                        # the old in-pane mount is gone
    assert html.count('id="reportOut"') == 1                 # exactly ONE ScaApp mount exists
    assert "$('#reportOut')" in con and "scaReportOut" not in con
    assert "window.ScaApp.render(mount, rep" in con          # the copied renderer draws the body, untouched
    # re-render on every entry of the tab (the single-active-instance discipline)
    assert re.search(r"member === 'report'\) \{ renderConsole\(\); \}", con)
    # the header comes from the pure builder
    assert "BtsReport.renderHead(S.view)" in con


def test_report_head_builder():
    """AC: BSA-AC-539."""
    view = {"project": "pygoat", "source": "https://github.com/adeyosemanputra/pygoat.git", "analysed_at": "2026-11-20T01:46:00+09:00",
            "report": {"severity": {"total": 18, "CRITICAL": 0, "HIGH": 6, "MEDIUM": 10, "LOW": 0, "UNKNOWN": 2}}}
    (head,) = js({"mod": "rep", "fn": "renderHead", "args": [view]})
    assert "pygoat" in head and "analysed 2026-11-20 01:46" in head
    for k, v in (("CRITICAL", 0), ("HIGH", 6), ("MEDIUM", 10), ("LOW", 0), ("UNKNOWN", 2)):
        assert "%s %s" % (k, v) in head
    assert "/api/sbom/pygoat?format=cdx" in head and "/api/sbom/pygoat?format=spdx" in head
    assert "/api/sbom/pygoat?format=vex" in head and "/api/doc/pygoat" in head
    (bad,) = js({"mod": "rep", "fn": "renderHead", "args": [{"project": '<img src=x onerror=alert(1)>', "report": {"severity": {}}}]})
    assert "<img" not in bad and "&lt;img" in bad            # untrusted project names are escaped
    (empty,) = js({"mod": "rep", "fn": "renderHead", "args": [None]})
    assert "No project is selected" in empty


def test_governance_cards_builder():
    """AC: BSA-AC-541."""
    view = {"project": "pygoat", "plan_summary": {"plans": 12, "upgrade": 10, "no_fix": 2, "verified_clean": 7, "verified_dirty": 1, "unverified": 2, "major_bumps": 3}}
    coverage = {"status": "OK", "advisories": 18, "handled_pct": 0.5, "worklist": [{"id": "CVE-1"}]}
    conformance = {"status": "OK", "components": 41, "regimes": {"ntia-2021": {"status": "PASS"}, "cisa-2025-draft": {"status": "FAIL"}}, "fix_once": [1]}
    (cards,) = js({"mod": "rep", "fn": "renderGovCards", "args": [{"view": view, "coverage": coverage, "conformance": conformance}]})
    assert "safe upgrades" in cards and "major bumps 3" in cards
    assert "verified: clean 7" in cards and "dirty(reverted) 1" in cards
    assert "50%" in cards and "open worklist 1" in cards
    assert "regimes checked 2 (fail 1)" in cards
    for sv in ("fix-plan", "vex", "conformance"):
        assert 'data-sv="%s"' % sv in cards
    (loading,) = js({"mod": "rep", "fn": "renderGovCards", "args": [{"view": view, "coverage": None, "conformance": None}]})
    assert "bts-skel" in loading                       # loading is a skeleton now, not the word (AC: BSA-AC-610)
    (failed,) = js({"mod": "rep", "fn": "renderGovCards", "args": [{"view": view, "coverage": {"error": "HTTP 404"}, "conformance": {"error": "HTTP 500"}}]})
    assert "Not loaded: HTTP 404" in failed and "Not loaded: HTTP 500" in failed
    (escd,) = js({"mod": "rep", "fn": "renderGovCards", "args": [{"view": {"project": "<x>", "plan_summary": {}}, "coverage": {"error": "<script>"}, "conformance": None}]})
    assert "<script>" not in escd


def test_analysis_auto_switches_to_the_report_tab():
    """AC: BSA-AC-540."""
    con = _read("bts_console.js")
    assert re.search(r"var ok = job && job\.state === 'done';", con)         # done is decided once, before both consumers
    assert "if (ok) { activate('report'); }" in con                          # a done analysis switches to the Report tab on its own
    assert "$('#reportBanner')" in con and "$('#scaBanner')" in con          # scan status stays on the Scan tab
    assert "empty_project" in con and "data_status" in con                   # the two honest warning cases moved with it


def test_chat_dock_is_mounted_on_every_tab():
    """AC: BSA-AC-533. The Claude-Code-style bottom chat dock replaces the chat tab."""
    html = _read("index.html")
    con = _read("bts_console.js")
    assert "'chat': ['chat']" not in con, "the chat tab group must be gone from the sidebar"
    assert 'id="chatDock"' in html and 'class="bts-chatdock open"' in html   # the dock ships OPEN: the Claude-client main conversation surface (ADR-0027)
    assert os.path.exists(os.path.join(WEB, "bts_chat_panel.js")), "the dock script must exist"
    assert "/static/bts_chat_panel.js" in html and "/static/bts_stream.js" not in html


def test_pinned_platform_renderer_stays_byte_identical():
    """AC: BSA-AC-542."""
    html = _read("index.html")
    assert '/static/sca_app.js' in html                                      # the copied renderer is still the report body
    pinned = os.path.join(WEB, "PLATFORM_ASSETS.sha256")
    if os.path.exists(pinned):
        with open(pinned, "r", encoding="utf-8") as fh:
            rows = [ln.split("  ", 1) for ln in fh.read().splitlines() if ln.strip()]
        assert rows, "the pinned-asset ledger must not be empty"
        for digest, rel in rows:
            with open(os.path.join(WEB, *rel.split("/")), "rb") as fh:
                data = fh.read().replace(b"\r\n", b"\n")     # pins are over LF-normalised bytes (autocrlf-independent)
            assert hashlib.sha256(data).hexdigest() == digest, "pinned file changed: %s" % rel
