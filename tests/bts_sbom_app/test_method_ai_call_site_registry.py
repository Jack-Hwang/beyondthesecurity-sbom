"""AI-suitability registry: every direct EXAONE call site in bts_sbom_app/ai.py must be named in
AI_CALL_SITES with a fallback_test that is a real, collectible pytest node id (static AST check,
no execution). Closes audit gap w1s3:w1s3-13 (no checklist gating new AI call sites against a
rule-based alternative)."""
from __future__ import annotations

import ast
import os

from bts_sbom_app import ai

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _function_names(path: str) -> set:
    with open(path, encoding="utf-8") as fh:
        tree = ast.parse(fh.read(), filename=path)
    return {n.name for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def test_registry_has_no_problems_for_the_real_module():
    """AC: BSA-AC-95"""
    assert ai.check_registry() == []


def test_exactly_one_call_site_found_in_propose():
    """AC: BSA-AC-95"""
    assert ai._call_sites(ai.__file__) == ["propose"]


def test_every_registry_entry_names_a_collectible_fallback_test():
    """AC: BSA-AC-95"""
    assert ai.AI_CALL_SITES
    for key, entry in ai.AI_CALL_SITES.items():
        node_id = entry["fallback_test"]
        assert "::" in node_id, "%s: fallback_test must be a path::func pytest node id" % key
        path_part, func_part = node_id.split("::", 1)
        full_path = os.path.join(ROOT, path_part)
        assert os.path.isfile(full_path), "%s: fallback_test file missing: %s" % (key, path_part)
        assert func_part in _function_names(full_path), "%s: fallback_test function missing: %s" % (key, node_id)


def test_unregistered_call_site_is_flagged(tmp_path):
    """AC: BSA-AC-95"""
    bad = tmp_path / "bad_ai.py"
    bad.write_text("def sneaky_call(client):\n    return client.complete('s', 'u')\n", encoding="utf-8")
    problems = ai.check_registry(str(bad))
    assert any("unregistered" in p and "sneaky_call" in p for p in problems)


def test_missing_fallback_test_is_flagged(monkeypatch):
    """AC: BSA-AC-95"""
    monkeypatch.setitem(ai.AI_CALL_SITES, "propose.remediation_ranking",
                         {"site": "propose", "why_not_rule_based": "x",
                          "fallback_test": "tests/bts_sbom_app/test_does_not_exist.py::nope"})
    problems = ai.check_registry()
    assert any("fallback_test" in p for p in problems)


def test_registry_entries_give_a_non_empty_rationale():
    """AC: BSA-AC-95"""
    for key, entry in ai.AI_CALL_SITES.items():
        assert len(entry.get("why_not_rule_based", "")) >= 20, key
