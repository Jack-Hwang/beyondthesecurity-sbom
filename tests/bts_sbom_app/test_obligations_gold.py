"""Gold check: 12 license expressions -> category + binary scope (task 29, brief 2, AC 703)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import licenses, obligations

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_twelve_gold_expressions_match_category_and_binary_scope():
    """AC: BSA-AC-703"""
    gold = json.load(open(os.path.join(REPO, "evals", "obligations_gold.json"), encoding="utf-8"))
    assert len(gold["cases"]) == 12
    ok = 0
    for c in gold["cases"]:
        cat = licenses.category(c["license"])
        comp = {"name": "x", "version": "1", "license": c["license"], "license_category": cat}
        scope = obligations.assess([comp])["scenarios"]["binary"]["components"][0]["scope"]
        assert cat == c["category"], (c["license"], cat)
        assert scope == c["binary_scope"], (c["license"], scope)
        ok += 1
    assert ok == 12


def test_the_gold_file_declares_its_basis():
    gold = json.load(open(os.path.join(REPO, "evals", "obligations_gold.json"), encoding="utf-8"))
    assert "table row" in gold.get("note", "") and "not legal advice" in gold.get("note", "")
