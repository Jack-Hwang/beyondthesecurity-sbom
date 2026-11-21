"""Cost estimate tool: no invented prices, formula match, honest incompleteness (task 18, AC 533-537)."""
from __future__ import annotations

import json
import os

from tools.cost_estimate import estimate

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _inputs():
    return json.load(open(os.path.join(REPO, "docs", "cost_assumptions.json"), encoding="utf-8"))


def test_every_input_is_marked_assumed_and_no_price_is_invented():
    """AC: BSA-AC-533"""
    inputs = _inputs()
    for key, row in inputs.items():
        if isinstance(row, dict) and "assumed" in row:
            assert row["assumed"] is True, key
            if "price" in key or key.endswith("_per_call"):
                assert row["value"] is None, key              # 0 invented prices: null until the user fills it


def test_four_fake_prices_reproduce_the_documented_formula():
    """AC: BSA-AC-534"""
    inputs = _inputs()
    inputs["plan_price_per_hour"]["value"] = 0.1
    inputs["storage_price_per_gb_month"]["value"] = 0.2
    inputs["log_price_per_gb"]["value"] = 0.3
    inputs["llm_cost_per_call"]["value"] = 0.4
    inputs["bandwidth_price_per_gb"]["value"] = 0.5
    expected = (inputs["plan_hours_per_month"]["value"] * inputs["instances"]["value"] * 0.1
                + inputs["storage_gb"]["value"] * 0.2
                + inputs["log_gb"]["value"] * 0.3
                + inputs["llm_calls_per_day"]["value"] * 30 * 0.4
                + inputs["bandwidth_gb"]["value"] * 0.5)
    out = estimate(inputs)
    assert out["total"]["status"] == "estimated"
    assert abs(out["total"]["usd_per_month"] - expected) < 0.0001


def test_a_null_price_leaves_the_total_incomplete_and_the_input_unknown():
    """AC: BSA-AC-535"""
    inputs = _inputs()                                              # every price still null
    out = estimate(inputs)
    assert out["total"]["status"] == "incomplete" and out["total"]["usd_per_month"] is None
    assert len(out["unfilled_inputs"]) == 5
    assert {row["status"] for row in out["rows"]} == {"unknown"}


def test_the_output_states_it_is_an_estimate_never_a_bill():
    """AC: BSA-AC-536"""
    out = estimate(_inputs())
    blob = json.dumps(out)
    assert "estimate" in blob and "not a billed amount" in blob


def test_cost_md_carries_cleanup_and_the_budget_thresholds():
    """AC: BSA-AC-537"""
    doc = open(os.path.join(REPO, "docs", "COST.md"), encoding="utf-8").read()
    assert "azd down --purge" in doc
    for threshold in ("50%", "80%", "100%"):
        assert threshold in doc, threshold
