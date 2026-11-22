"""TOP10 answer-quality scorecard (MetaNet appendix): deterministic gates over the offline chat set."""
from __future__ import annotations

import pytest

from bts_sbom_app import quality


def test_scorecard_gates_five_metrics_and_reports_paraphrase():
    """AC: BSA-AC-481"""
    rep = quality.top10_report()
    assert set(rep["gates"]) == {"faithfulness", "relevance", "completeness", "tool_accuracy", "over_refusal"}
    for g in rep["gates"].values():
        assert set(g) == {"value", "threshold", "pass"} and isinstance(g["pass"], bool)
    assert "paraphrase_routing_rate" in rep["metrics"]
    assert all("paraphrase" not in n for n in rep["gates"])          # reported, never gated


def test_apply_gates_pass_and_single_named_failure():
    """AC: BSA-AC-482"""
    metrics = dict(quality.THRESHOLDS, over_refusal=quality.THRESHOLDS["over_refusal"])
    ok = quality.apply_gates(metrics)
    assert ok["verdict"] == "pass" and ok["failures"] == []
    bad = dict(metrics, faithfulness=quality.THRESHOLDS["faithfulness"] - 0.01)
    fail = quality.apply_gates(bad)
    assert fail["verdict"] == "fail" and len(fail["failures"]) == 1
    assert fail["failures"][0]["metric"] == "faithfulness"


def test_thresholds_and_bounds():
    """AC: BSA-AC-483"""
    assert quality.THRESHOLDS == {"faithfulness": 0.90, "relevance": 0.25, "completeness": 0.90,
                                  "tool_accuracy": 0.95, "over_refusal": 0.05}
    g = quality.apply_gates(dict(quality.THRESHOLDS))["gates"]
    for name, gate in g.items():
        expect = gate["value"] <= gate["threshold"] if name == "over_refusal" else gate["value"] >= gate["threshold"]
        assert gate["pass"] is expect


def test_per_case_relevance_and_completeness_bounds():
    """AC: BSA-AC-484"""
    a = "CVE-2018-18074 affects requests, severity HIGH (CVSS 7.5)"
    r = quality.relevance("CVE-2018-18074 는 어떤 취약점이야", a)
    assert 0.0 <= r <= 1.0 and r > 0.0
    assert quality.relevance("CVE-2018-18074", "완전히 다른 주제의 문장") >= 0.0
    assert quality.completeness(a, ["CVE-2018-18074", "7.5"]) == 1.0
    assert quality.completeness(a, ["CVE-2018-18074", "없는것"]) == 0.5
    assert quality.completeness(a, []) == 1.0


def test_markdown_table_and_write(tmp_path):
    """AC: BSA-AC-485"""
    rep = quality.top10_report()
    md = quality.render_markdown(rep)
    assert md.count("| 지표 | 측정값 | 기준 | 통과 |") == 1
    assert len([ln for ln in md.splitlines() if ln.startswith("| ")]) == 6        # header + separator + 5 metric rows
    assert ("**pass**" if rep["verdict"] == "pass" else "**fail**") in md
    out = tmp_path / "top10.md"
    assert quality.write_report(rep, str(out)) == str(out)
    assert out.read_text(encoding="utf-8") == md


def test_live_scorecard_passes_all_gates():
    """AC: BSA-AC-481, BSA-AC-483 - the measured set must clear every course gate."""
    rep = quality.top10_report()
    assert rep["verdict"] == "pass" and rep["failures"] == [] and rep["misses"] == []
    assert rep["metrics"]["faithfulness"] >= 0.90 and rep["metrics"]["tool_accuracy"] >= 0.95
    assert rep["metrics"]["over_refusal"] <= 0.05
