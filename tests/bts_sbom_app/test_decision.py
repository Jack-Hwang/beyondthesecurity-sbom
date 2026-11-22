# -*- coding: utf-8 -*-
"""decision.py: the DMN-lite decision-table engine (ADR-0024; AC: BSA-AC-576). The engine is pure - tables in, verdicts out -
so these tests need no fixtures beyond the tables themselves."""
from bts_sbom_app import decision as dmn


def _policy():
    return dmn.remediation_policy()


def test_first_match_policy_picks_the_highest_priority_fired_rule():
    t = _policy()
    r = dmn.evaluate(t, {"severity": "critical", "malicious": False, "fixed_available": True})
    assert r["verdict"] == "decided" and r["matched"] == ["R2"], r
    assert "patch now" in r["outputs"]["action"]


def test_malware_rule_wins_over_everything():
    r = dmn.evaluate(_policy(), {"severity": "low", "malicious": True})
    assert r["matched"] == ["R1"] and r["outputs"]["priority"] == "P0"


def test_copyleft_in_binary_distribution_raises_the_license_review():
    r = dmn.evaluate(_policy(), {"severity": "high", "license_category": "copyleft",
                                 "distribution": "binary", "malicious": False, "fixed_available": False})
    assert r["matched"] == ["R3"], r
    assert "license review" in r["outputs"]["action"]


def test_severity_bands_compare_by_rank_not_alphabet():
    # "high" (rank 3) must satisfy ">= high" and must NOT satisfy ">= critical"; labels never compare as strings
    r = dmn.evaluate(_policy(), {"severity": "high", "malicious": False, "license_category": "permissive",
                                 "distribution": "internal", "fixed_available": False})
    assert r["matched"] == ["R4"], r


def test_catch_all_rule_means_no_verdict_is_still_a_decision():
    r = dmn.evaluate(_policy(), {})
    assert r["verdict"] == "decided" and r["matched"] == ["R8"], r     # R8 (*) is the documented fallback rule


def test_unique_hit_policy_reports_a_conflict_instead_of_picking_one():
    t = dmn.DecisionTable("u", {"a": ""}, {"x": ""}, [dmn.Rule("r1", {"a": "1"}, {"x": 1}),
                                                     dmn.Rule("r2", {"a": "1"}, {"x": 2})], hit_policy="U")
    r = dmn.evaluate(t, {"a": "1"})
    assert r["verdict"] == "conflict" and sorted(r["matched"]) == ["r1", "r2"]


def test_any_hit_policy_requires_agreement():
    t = dmn.DecisionTable("a", {"a": ""}, {"x": ""}, [dmn.Rule("r1", {"a": ">=1"}, {"x": 1}),
                                                     dmn.Rule("r2", {"a": "<=9"}, {"x": 1})], hit_policy="A")
    assert dmn.evaluate(t, {"a": 5})["verdict"] == "decided"
    t2 = dmn.DecisionTable("a2", {"a": ""}, {"x": ""}, [dmn.Rule("r1", {"a": ">=1"}, {"x": 1}),
                                                       dmn.Rule("r2", {"a": "<=9"}, {"x": 2})], hit_policy="A")
    assert dmn.evaluate(t2, {"a": 5})["verdict"] == "conflict"


def test_absent_fact_never_matches():
    t = dmn.DecisionTable("m", {"sev": ""}, {"x": ""}, [dmn.Rule("r1", {"sev": ">=high"}, {"x": 1})], hit_policy="F")
    r = dmn.evaluate(t, {})
    assert r["verdict"] == "none" and r["outputs"] is None
    assert r["trace"][0]["missing_inputs"] == ["sev"]


def test_condition_grammar_operators():
    t = dmn.DecisionTable("g", {"n": "", "s": "", "l": ""}, {"x": ""},
                          [dmn.Rule("r1", {"n": ">=2", "s": "in(a, b)", "l": "contains xy"}, {"x": 1})], hit_policy="F")
    assert dmn.evaluate(t, {"n": 3, "s": "b", "l": "wxyz"})["verdict"] == "decided"
    assert dmn.evaluate(t, {"n": 1, "s": "b", "l": "wxyz"})["verdict"] == "none"
    assert dmn.evaluate(t, {"n": 3, "s": "c", "l": "wxyz"})["verdict"] == "none"
    assert dmn.evaluate(t, {"n": 3, "s": "b", "l": "zzz"})["verdict"] == "none"


def test_bad_boolean_cell_is_a_literal_not_always_match():
    # "true"/"false" cells test the value (DMN literal); only * - and the empty cell mean "always"
    t = dmn.DecisionTable("b", {"m": ""}, {"x": ""}, [dmn.Rule("r1", {"m": "true"}, {"x": 1})], hit_policy="F")
    assert dmn.evaluate(t, {"m": False})["verdict"] == "none"
    assert dmn.evaluate(t, {"m": True})["verdict"] == "decided"


def test_table_lines_render_every_column():
    lines = dmn.table_lines(_policy())
    assert lines[0].startswith("[DMN-lite]") and "remediation-policy" in lines[0]
    assert any("R1" in ln and "malicious true" in ln for ln in lines)
