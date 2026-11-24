"""The Arch Intel pane's pure renderers (web/arch_intel_render.js) run under Node via tests/bts_sbom_app/js/
render_harness.js, on the JSON shape arch_api returns. Tests that need Node skip when it is not installed."""
from __future__ import annotations

import json
import os
import shutil
import subprocess

import pytest

from bts_sbom_app import server

HERE = os.path.dirname(os.path.abspath(__file__))
HARNESS = os.path.join(HERE, "js", "render_harness.js")
WEB = server.WEB_DIR


def js(*calls):
    """Run (module, function, args...) calls in Node; one result per call."""
    node = shutil.which("node")
    if not node:
        pytest.skip("node is not installed")
    payload = json.dumps([{"mod": m, "fn": f, "args": list(a)} for m, f, *a in calls])
    p = subprocess.run([node, HARNESS], input=payload, capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def render(fn, *args):
    return js(("arc", fn, *args))[0]


def result_doc():
    return {
        "schema": "bts-sbom.arch-intel.v1",
        "meta": {"id": "a" * 10, "source": "fix/repo", "kind": "local-copy", "name": "repo", "lang": "ko",
                 "distribution": "binary", "use_llm": False, "finished": "2026-11-21T10:00:00", "tool_version": "0.3.0"},
        "lineage": {"commit": "abc", "source": "local"},
        "license": {"project_license": "GPL-3.0-only", "project_license_source": "root license file",
                    "category": "strong-copyleft", "obligations": ["keep notices"],
                    "license_files": [{"file": "LICENSE", "license": "GPL-3.0-only", "detected": True}],
                    "vendored": [], "spdx_header_counts": {},
                    "notice": {"distribution": "binary", "network_clause": False,
                               "checklist": [{"clause": "GPL-3.0 §4", "req": "고지 유지"},
                                             {"clause": "GPL-3.0 §6", "req": "소스 제공"}],
                               "verdicts": [{"distribution": "binary", "verdict": "review", "why": "소스 제공 의무"},
                                            {"distribution": "saas", "verdict": "ok", "why": "배포 없음"},
                                            {"distribution": "internal", "verdict": "ok", "why": "내부 전용"}],
                               "note": "증거 도구"},
                    "compat": {"rows": [{"their": "GPL-3.0-only", "your": "MIT", "status": "compatible", "reason": "permissive into strong copyleft"},
                                        {"their": "GPL-3.0-only", "your": "GPL-3.0-only", "status": "compatible", "reason": "same"}],
                               "note": ""}},
        "structure": {"stack": {"languages": {"Python": {"files": 3, "loc": 40}, "Go": {"files": 1, "loc": 5}},
                               "files": 4, "loc": 45},
                      "graph": {"import_edges": 2, "cycle_count": 0, "cycles": []},
                      "clusters": [], "hotspots": [{"file": "app/main.py", "commits": 3, "score": 12.5}],
                      "runtime_eol": [], "notes": ["note one"],
                      "files_count": 4, "total_loc": 45,
                      "entry_points": [{"path": "app/__main__.py", "kind": "python-main", "note": ""}],
                      "key_files": [], "modules": [], "edges": []},
        "ai_source": "deterministic", "ai_model": "", "ai_note": "no LLM client configured", "ai_dropped": {},
        "analysis": {"overview": "요약", "license_note": "GPL 유의",
                     "components": [{"name": "<script>alert(1)</script>", "role": "role", "files": ["app/service.py"]}],
                     "scenarios": [{"name": "기동", "description": "", "participants": ["User", "app/__main__.py"],
                                    "steps": [{"actor": "User", "action": "run", "target": "app/__main__.py"},
                                              {"actor": "app/__main__.py", "action": "answer", "target": "User"}],
                                    "inferred": True}],
                     "activity": []},
        "diagrams": {"components": {"mermaid": "flowchart TD\n  c0[\"X\"]", "note": ""},
                     "sequence": [{"name": "기동", "mermaid": "sequenceDiagram\n  p1-->>p2: done", "steps": [], "inferred": True}],
                     "activity": []},
        "code": [{"path": "app/service.py", "role": "hotspot (3 commits)", "lang": "py", "total_lines": 5,
                  "start_line": 1, "end_line": 5, "truncated": False,
                  "html": '<span class="tok-kw">def</span> handle():\n  <span class="tok-str">"x"</span>',
                  "license": "GPL-3.0-only"}],
        "honesty": {"executed": False, "dynamic_view": "static inference", "prompt_contains_source": False},
    }


# ------------------------------------------------------------------- AC: BSA-AC-459
def test_result_escapes_a_hostile_component_name_and_lists_seven_items():
    """AC: BSA-AC-459"""
    html = render("result", result_doc())
    assert "<script>alert(1)</script>" not in html                     # the hostile name never lands raw
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html             # it is shown, escaped
    assert html.count('data-arc-open="') == 7                          # the model browser lists exactly 7 items
    assert html.count('<details class="arc-tgroup" open><summary>') == 5   # License, Overview, Diagrams, Components, Code
    assert 'data-arc-default="diagram_components"' in html             # one view opens by default


# ------------------------------------------------------------------- AC: BSA-AC-460
def test_every_diagram_block_carries_its_hidden_source_pre():
    """AC: BSA-AC-460"""
    html = render("result", result_doc())
    assert html.count('class="arc-dwrap"') == 2                        # component diagram + one sequence
    assert html.count('<pre class="arc-mermaid-src" hidden>') == 2
    assert "flowchart TD" in html and "sequenceDiagram" in html


def test_license_verdict_and_notice_render_the_checklist_and_matrix():
    html = render("licenseVerdict", result_doc()["license"])
    assert "GPL-3.0-only" in html and "Strong copyleft" in html
    assert "keep notices" in html and "compatible" in html          # obligations + the compat matrix rows
    note_html = render("notice", result_doc()["license"])
    assert "GPL-3.0 §4" in note_html and "GPL-3.0 §6" in note_html
    assert "clean-room" in note_html.lower()


def test_code_section_shows_highlighted_html_and_license_banner():
    doc = result_doc()
    html = render("codeView", doc["code"][0])
    assert '<pre class="arc-code">' in html and '<span class="tok-kw">def</span>' in html
    assert "GPL-3.0-only" in html                                      # the clean-room banner carries the license


def test_components_table_says_no_ai_scenario_analysis_when_the_ai_lane_is_absent():
    absent = render("componentsTable", {"overview": "요약", "components": [], "scenarios": [], "activity": []})
    assert "No AI scenario analysis" in absent                         # honest when the AI lane produced nothing
    present = render("componentsTable", result_doc()["analysis"])
    assert "No AI scenario analysis" not in present                    # scenarios exist → the note stays away


# ------------------------------------------------------------------- AC: BSA-AC-478
def test_result_lists_the_insights_item_with_its_style_and_honesty_note():
    """AC: BSA-AC-478"""
    doc = result_doc()
    doc["insights"] = {"flow_blockers": {"count": 1, "blockers": [{"kind": "cycle", "what": "a → b → a", "why": "순환 의존"}]},
                       "bounded_context_candidates": {"count": 1, "candidates": [{"name": "svc", "cohesion": 0.7,
                                                                                  "inbound": 1, "outbound": 2,
                                                                                  "modules": 2, "files": ["svc/x.py"]}]},
                       "style_hypothesis": {"style": "modular_monolith", "why": "단일 진입점", "signals": ["entry points: 1"]},
                       "antipattern_signals": {"count": 0, "signals": []}}
    html = render("result", doc)
    assert html.count('data-arc-open="') == 8                          # insights joins the model browser as 1 item
    assert 'data-arc-open="insights"' in html
    assert "modular_monolith" in html and "Heuristic readings" in html  # the style pill and the honesty note render
    assert '<details class="arc-tgroup" open><summary>Insights</summary>' in html


def test_history_renders_rows_and_a_verdict_pill():
    rows = [{"id": "a" * 10, "source": "fix/repo", "finished": "2026-11-21T10:00:00", "lang": "ko",
             "distribution": "binary", "overview": {"project_license": "GPL-3.0-only", "category": "strong-copyleft",
                                                    "files": 4, "loc": 45, "entry_points": 1, "ai_source": "deterministic"}}]
    html = render("history", rows)
    assert "fix/repo" in html and "GPL-3.0-only" in html and "deterministic" in html
    empty = render("history", [])
    assert "No Arch Intel runs yet" in empty


def test_the_page_wires_the_pane_and_its_scripts():
    with open(os.path.join(WEB, "index.html"), "r", encoding="utf-8") as fh:
        page = fh.read()
    assert 'data-sv="archintel"' in page and 'id="paneArchIntel"' in page
    for asset in ("/static/arch_intel_render.js", "/static/arch_intel.js", "/static/arch_intel.css"):
        assert os.path.isfile(os.path.join(WEB, asset.rsplit("/", 1)[1]))
    assert os.path.isfile(os.path.join(WEB, "vendor", "mermaid.min.js"))
    js_text = open(os.path.join(WEB, "arch_intel.js"), encoding="utf-8").read()
    assert "onclick" not in js_text and "javascript:" not in js_text   # CSP: no inline handlers anywhere
