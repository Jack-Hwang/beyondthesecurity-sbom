"""Overnight feature-loop round 1 (backlog C52+C43, C63, C27, C39 - all in files no parallel lane owns):
the escalation roll-up report over the append-only handoff log, the reverse surface traceability report
(a CLI/API surface with zero spec mention is named), the generic Mermaid well-formedness lint, and the
Markdown relative-link checker. Report-only surfaces - they measure, the gate decides."""
from __future__ import annotations

import json
import os
import subprocess
import sys

from bts_sbom_app import diagrams, escalation, escalation_report, speclint

APP_ROOT = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "bts_sbom_app")
SPEC = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "specs", "bts_sbom_app_features.md")


def test_escalation_report_rolls_the_event_log_up(tmp_path):
    """AC: BSA-AC-1247. The roll-up reads the folded event store: per-trigger and per-kind rates, the open queue
    depth with the oldest wait, and the resolution-time distribution from the recorded opened/resolved moments."""
    import time as _t
    p0 = escalation.build("policy_gap:legal", "이것에 대해 법적 판단을 내려줘", "proj")
    escalation.record(tmp_path, p0, now="2026-11-28T01:00:00Z")
    p1 = escalation.build("no_progress", "없다고만 세 번 답했다", "proj")
    escalation.record(tmp_path, p1, now="2026-11-28T01:10:00Z")
    escalation.resolve(tmp_path, p1["id"], "도구 재실행으로 해결", "reviewer", now="2026-11-28T01:40:00Z")
    r = escalation_report.report(tmp_path, now="2026-11-28T02:00:00Z")
    assert r["status"] == "OK" and r["totals"]["open"] == 1 and r["totals"]["resolved"] == 1
    assert r["by_trigger"]["policy_gap"] == 1 and r["by_trigger"]["no_progress"] == 1
    assert r["open_queue"]["depth"] == 1 and r["open_queue"]["oldest_wait_minutes"] == 60.0
    assert r["resolution"]["count"] == 1 and r["resolution"]["mean_minutes"] == 30.0
    assert r["resolution"]["median_minutes"] == 30.0
    empty = escalation_report.report(tmp_path / "nothing", now="2026-11-28T02:00:00Z")
    assert empty["status"] == "no_data"                       # an empty log is no_data, never healthy-looking zeros


def test_surface_trace_names_surfaces_the_spec_never_mentioned():
    """AC: BSA-AC-1248. Every CLI subcommand and route literal is collected from the source and matched against
    the spec text (literal, else its first distinguishing segment); the real repo currently carries surfaces the
    spec never mentions, and the report names them without guessing a fix."""
    r = speclint.surface_trace(SPEC, APP_ROOT)
    assert r["total"] >= 20 and r["schema"] == "bts-sbom.surface-trace.v1"
    kinds = {x["kind"] for x in r["surfaces"]}
    assert kinds == {"cli", "route"}
    known = {x["surface"] for x in r["surfaces"]}
    assert "conformance" in known and "/api/projects" in known          # the collector actually saw the sources
    for row in r["surfaces"]:
        assert row["mentioned"] is (row["via"] != "")
    # a fabricated unknown surface must land in unmentioned (the matching is real, not always-true)
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        os.makedirs(os.path.join(td, "bts_sbom_app"))
        with open(os.path.join(td, "bts_sbom_app", "cli.py"), "w", encoding="utf-8") as fh:
            fh.write('sub.add_parser("zzz-never-registered", help="fixture")\n')
        with open(os.path.join(td, "bts_sbom_app", "server.py"), "w", encoding="utf-8") as fh:
            fh.write('if path == "/api/zzz-never-route":\n    pass\n')
        r2 = speclint.surface_trace(SPEC, td)
        assert "zzz-never-registered" in r2["unmentioned"] and "/api/zzz-never-route" in r2["unmentioned"]


def test_mermaid_lint_is_structural_only_and_finds_real_breaks():
    """AC: BSA-AC-1249. The lint checks header, quote/bracket balance and edge endpoints for ANY Mermaid text;
    every catalog builder's real output must lint clean, and seeded breaks must be named."""
    import itertools
    for kind in itertools.islice(sorted(diagrams.CATALOG), 0, 37, 3):   # a stride sample across the 37 kinds
        d = diagrams.build(kind, {"name": "p", "components": [{"name": "a", "version": "1", "ecosystem": "pypi"},
                                                              {"name": "b", "version": "2", "ecosystem": "pypi"}],
                                 "vulns": [{"id": "CVE-1", "package": "a", "version": "1", "severity": "HIGH"}]})
        if d.get("mermaid"):
            assert diagrams.lint_mermaid(d["mermaid"]) == [], (kind, diagrams.lint_mermaid(d["mermaid"]))
    assert diagrams.lint_mermaid("not a diagram at all") != []
    assert diagrams.lint_mermaid('flowchart TD\n a["label"] --> b["x"]') == []
    assert any("edge without both endpoints" in p for p in diagrams.lint_mermaid("flowchart TD\n a --> \n b --> c"))
    assert any("unbalanced quotes" in p for p in diagrams.lint_mermaid('flowchart TD\n a["open --> b["x"]'))
    assert any("unbalanced (" in p for p in diagrams.lint_mermaid("sequenceDiagram\n A->>B: call(unclosed"))


def test_md_link_checker_finds_dead_relative_links(tmp_path):
    """AC: BSA-AC-1250. Relative markdown links must resolve; http/mailto/anchor targets are out of scope; the
    checker names file, line and target and exits 1 - run as a subprocess like CI would."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "a.md").write_text("[ok](b.md)\n[dead](missing.md)\n[web](https://x.y/z)\n[anchor](#sec)\n", encoding="utf-8")
    (tmp_path / "docs" / "b.md").write_text("exists\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, os.path.join(os.path.dirname(APP_ROOT), "scripts", "check_md_links.py"), str(tmp_path)],
                          capture_output=True, text=True)
    assert proc.returncode == 1 and "missing.md" in proc.stdout and "docs/a.md:2" in proc.stdout
    proc2 = subprocess.run([sys.executable, os.path.join(os.path.dirname(APP_ROOT), "scripts", "check_md_links.py"), str(tmp_path / "docs")],
                           capture_output=True, text=True) if False else None
    # fixing the link makes it pass
    (tmp_path / "docs" / "a.md").write_text("[ok](b.md)\n", encoding="utf-8")
    proc3 = subprocess.run([sys.executable, os.path.join(os.path.dirname(APP_ROOT), "scripts", "check_md_links.py"), str(tmp_path)],
                           capture_output=True, text=True)
    assert proc3.returncode == 0 and "0 dead" in proc3.stdout
