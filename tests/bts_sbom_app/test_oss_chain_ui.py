"""One-Analyze OSS chaining (scan entry-point integration): static checks over the console wiring."""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
HTML = os.path.join(ROOT, "bts_sbom_app", "web", "index.html")
CONSOLE = os.path.join(ROOT, "bts_sbom_app", "web", "bts_console.js")


def test_checkbox_exists_next_to_main_scan_inputs():
    """AC: BSA-AC-533"""
    page = open(HTML, encoding="utf-8").read()
    assert '<input type="checkbox" id="scaOss">' in page
    m = re.search(r'<label[^>]*title="[^"]*OSS Scanner로도[^"]*"[^>]*>\s*<input type="checkbox" id="scaOss">', page)
    assert m, "the checkbox title must say the same target is re-scanned and where the results land"
    assert "OSS 성과물" in page and "📜 OSS Scanner 탭에서" in page


def test_analyze_chains_oss_only_after_a_done_job():
    """AC: BSA-AC-533"""
    js = open(CONSOLE, encoding="utf-8").read()
    assert "$('#scaOss')" in js
    chain = re.search(r"runJob\(\{ source: src[^}]+\}, 'Analysis'\)\.then\(function \(job\) \{.*?"
                      r"if \(ossToo && job && job\.state === 'done'\) \{ runOssChain\(src\); \}", js, re.S)
    assert chain, "the chain must run only when the main job resolved and finished done"
    assert "api('/api/oss/scan', { target: src, modes: ['source', 'dependency', 'binary']" in js
    assert "api('/api/oss/jobs/' + encodeURIComponent(id))" in js               # same poll endpoint as the OSS screen
    assert "setTimeout(poll, 1200)" in js                                       # polling loop, not one-shot


def test_banner_outcomes_are_honest_and_csp_clean():
    """AC: BSA-AC-533"""
    js = open(CONSOLE, encoding="utf-8").read()
    seg = js[js.index("function runOssChain"):]
    seg = seg[:seg.index("\n  function ", 10)]                                  # the chain function body only
    assert seg.count("esc(") >= 3                                               # every dynamic value in the notes is escaped
    assert seg.count("메인 분석 결과는 정상") == 2                                # both failure notes keep the main result's standing
    assert "activate('oss')" in seg                                             # success path offers the tab jump
    assert "addEventListener" in seg and "onclick" not in seg                   # CSP: real button node, no inline handler
    assert seg.count("note(") >= 3 and seg.count("banner.innerHTML") >= 3       # three banner outcomes: fail / fail / success
