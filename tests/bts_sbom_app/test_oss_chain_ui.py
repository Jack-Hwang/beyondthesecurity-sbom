"""Unified Scan landing (one form, one Analyze -> main pipeline + OSS scan together): static checks over
the landing markup and the console wiring."""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HTML = os.path.join(ROOT, "bts_sbom_app", "web", "index.html")
CONSOLE = os.path.join(ROOT, "bts_sbom_app", "web", "bts_console.js")
OSS = os.path.join(ROOT, "bts_sbom_app", "web", "oss_scanner.js")


def test_the_landing_carries_one_unified_form_with_the_oss_pieces_and_history():
    """AC: BSA-AC-565"""
    page = open(HTML, encoding="utf-8").read()
    git = page[page.index('data-sv="git"'):page.index('data-sv="report"')]          # the landing pane slice
    for fid in ("scaGitUrl", "ossBranch", "scaOssModes", "scaOssExcludes", "ossHistoryLanding", "scaBanner"):
        assert git.count('id="%s"' % fid) == 1, "landing node %s missing" % fid
    assert "Previous scans" in git                                                  # the history list lives on the landing
    assert "project.zip" in git                                                     # archive targets are first-class inputs now
    assert 'id="scaOss"' not in page                                                # the old checkbox is gone: chaining is the default
    assert 'data-sv="oss"' in page and 'id="paneOss"' in page                       # the results sub-tab still exists


def test_analyze_runs_the_oss_stage_through_btsoss_regardless_of_the_main_outcome():
    """AC: BSA-AC-533"""
    js = open(CONSOLE, encoding="utf-8").read()
    assert "$('#scaOss')" not in js                                                 # the checkbox gate is gone
    assert "window.BtsOss.readForm" in js                                           # modes/excludes/branch come from the unified form
    m = re.search(r"runJob\(\{ source: src[^}]+\}, 'Analysis'\)\.then\(function \(job\) \{(.*?)\n    \}\);", js, re.S)
    assert m, "the analyze chain body is missing"
    body = m.group(1)
    assert "if (ok) { activate('report'); }" in body                                # done -> its own Report tab
    assert "runOssChain(src, ossOpts, ok);" in body                                 # the OSS stage is NOT gated on the main outcome
    chain = re.search(r"function runOssChain\(src, opts, mainOk\) \{(.*?)\n  \}", js, re.S)
    assert chain, "runOssChain must take the form values and the main outcome"
    seg = chain.group(1)
    assert "window.BtsOss.start(src, opts)" in seg                                  # the engine screen's own start, form values included
    assert "OSS 단계는 실행되지 않았다" in seg                                       # engine script missing -> named, never silent
    assert "OSS 단계는 건너뛰었다" in seg                                            # zero modes selected -> named, never silent
    assert "r.superseded" in seg                                                    # a newer Analyze takes the stage over quietly


def test_banner_outcomes_are_honest_and_csp_clean():
    """AC: BSA-AC-533"""
    js = open(CONSOLE, encoding="utf-8").read()
    seg = js[js.index("function runOssChain"):]
    seg = seg[:seg.index("\n  function ", 10)]                                      # the chain function body only
    assert seg.count("esc(") >= 2                                                   # every dynamic value in the notes is escaped
    assert "메인 분석 결과는 정상" in seg and "메인 파이프라인도 이 대상은 분석하지 못했다" in seg
    assert "activate('oss')" in seg                                                 # success path offers the tab jump
    assert "addEventListener" in seg and "onclick" not in seg                       # CSP: real button node, no inline handler
    assert seg.count("note(") >= 3 and seg.count("banner.innerHTML") >= 3           # skip / fail / success all land in the banner


def test_the_results_subtab_and_the_cross_tab_jump_contract():
    """AC: BSA-AC-565"""
    oss = open(OSS, encoding="utf-8").read()
    con = open(CONSOLE, encoding="utf-8").read()
    assert "window.BtsOss = { readForm: readForm, start: start, open: openJob };" in oss
    assert "CustomEvent('bts:activate', { detail: 'oss' })" in oss                  # history Open jumps to the results sub-tab
    assert "addEventListener('bts:activate'" in con                                 # the console owns activate()
    assert "activate(t.getAttribute('data-sv'), t.classList.contains('scan-subchip'))" in con   # a sub-tab chip opens exactly that member (the landing stays reachable after visiting OSS 결과)
    assert "'git': ['git', 'oss', 'lock', 'container']" in con                      # the OSS Scanner group is absorbed into Scan
    assert "'oss': ['oss']" not in con                                              # no top-level OSS Scanner group anymore
