"""Monthly cost estimate from docs/cost_assumptions.json (task 18) - stdlib only, run with `python -I -X utf8 tools/cost_estimate.py`.

The documented formula (docs/COST.md):
    monthly ≈ plan_hours_per_month × instances × plan_price_per_hour
            + storage_gb × storage_price_per_gb_month
            + log_gb × log_price_per_gb
            + llm_calls_per_day × 30 × llm_cost_per_call
            + bandwidth_gb × bandwidth_price_per_gb

NO Azure price is invented here: price fields stay null in the assumptions file until the user fills them
from the Azure pricing calculator, and any unfilled input shows as "unknown" in the output (the total is
then "incomplete", never a number pretending to be money). The output always states that this is an
ESTIMATE, not a billed amount.
"""
from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_INPUT = os.path.join(os.path.dirname(HERE), "docs", "cost_assumptions.json")

FORMULA = [
    ("plan", lambda v: v["plan_hours_per_month"]["value"] * v["instances"]["value"] * v["plan_price_per_hour"]["value"]),
    ("storage", lambda v: v["storage_gb"]["value"] * v["storage_price_per_gb_month"]["value"]),
    ("logging", lambda v: v["log_gb"]["value"] * v["log_price_per_gb"]["value"]),
    ("llm", lambda v: v["llm_calls_per_day"]["value"] * 30 * v["llm_cost_per_call"]["value"]),
    ("bandwidth", lambda v: v["bandwidth_gb"]["value"] * v["bandwidth_price_per_gb"]["value"]),
]

PRICE_FIELDS = ("plan_price_per_hour", "storage_price_per_gb_month", "log_price_per_gb", "llm_cost_per_call", "bandwidth_price_per_gb")


def estimate(inputs: dict) -> dict:
    """The estimate dict: one row per formula term, the total, and the honesty banner fields."""
    rows = []
    unknowns = []
    total = 0.0
    for name, fn in FORMULA:
        try:
            value = fn(inputs)
            if value is None:
                raise TypeError
            rows.append({"term": name, "usd_per_month": round(float(value), 4), "status": "estimated"})
            total += float(value)
        except (KeyError, TypeError):
            rows.append({"term": name, "usd_per_month": None, "status": "unknown"})
            unknowns.append(name)
    missing = [f for f in PRICE_FIELDS if (inputs.get(f) or {}).get("value") is None]
    return {"rows": rows,
            "total": {"usd_per_month": round(total, 4) if not unknowns else None,
                      "status": "estimated" if not unknowns else "incomplete"},
            "unfilled_inputs": missing,
            "disclaimer": "estimate only - not a billed amount; every input is an assumption"}


def main(argv: list) -> int:
    path = argv[1] if len(argv) > 1 else DEFAULT_INPUT
    try:
        with open(path, "r", encoding="utf-8") as fh:
            inputs = json.load(fh)
    except (OSError, ValueError) as exc:
        print("cannot read the assumptions file: %s" % type(exc).__name__)
        return 2
    out = estimate(inputs)
    print("BTS-SBOM monthly cost estimate (ESTIMATE ONLY - not a billed amount)")
    print("formula: plan hours x instances x plan price + storage GB x price + log GB x price + LLM calls/day x 30 x price + egress GB x price")
    for row in out["rows"]:
        value = row["usd_per_month"]
        print("  %-10s %s" % (row["term"], ("USD %s" % value) if value is not None else "unknown (fill the price in docs/cost_assumptions.json)"))
    total = out["total"]
    print("  %-10s %s" % ("TOTAL", ("USD %s" % total["usd_per_month"]) if total["usd_per_month"] is not None else "INCOMPLETE - some prices are unknown"))
    if out["unfilled_inputs"]:
        print("  unfilled price inputs: %s" % ", ".join(out["unfilled_inputs"]))
    print("  disclaimer: %s" % out["disclaimer"])
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
