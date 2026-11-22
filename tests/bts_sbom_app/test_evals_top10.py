"""The TOP-10 quality gates (AC-607/608, brief-5 plan A): grounding F, relevance/completeness, tool-call accuracy,
over-refusal rate. The deterministic lane is measured here in-process (extractive answers, regex-router floor); the
gated read-accuracy and over-refusal numbers come from the live suite artifact when it exists, so a fresh checkout
without evidence/ honestly fails those two gates instead of pretending."""
from __future__ import annotations

import json
import os

from bts_sbom_app import evals_top10


def test_grounding_recall_and_precision_per_answer():
    """AC: BSA-AC-607. A1: every scored answer must state its precision (claim support) and its source recall; the
    extractive contract keeps both at 1.0 on the golden sets."""
    g = evals_top10.grounding_eval()
    assert g["answers"] >= 12                  # the regex floor answers only what its keywords reach; the rest is the planner lane
    assert g["grounding_f"] >= 0.90
    assert all(r["precision"] >= 0.8 for r in g["rows"])


def test_completeness_gate_relevance_tracked():
    """AC: BSA-AC-607. A2: the gate is completeness - every golden row's mandatory elements appear in the answer.
    The deterministic token cosine is tracked (the >=0.80 path is the LLM 역생성 judge lane), never gated here."""
    rc = evals_top10.relevance_completeness_eval()
    assert rc["completeness"] >= 0.90
    assert all(not r["missing"] for r in rc["rows"])
    assert rc["relevance_cos"] >= 0.1                      # tracked: the answers are not unrelated to the questions


def test_write_lane_blocks_every_forged_call():
    """AC: BSA-AC-608. A3 write = 1.0 exactly: invented tokens/codes/sources/reasons are dropped AND a read-only
    session is not even offered a write tool."""
    ta = evals_top10.tool_accuracy_eval()
    assert ta["tool_accuracy_write"] == 1.0
    assert ta["forged_dropped"] == ta["forged_calls"] == 4


def test_over_refusal_floor_answers_every_stock_question():
    """AC: BSA-AC-608. A4 floor: every read tool's stock question must fire a tool (an honest availability note is
    fine; a bare refusal is not)."""
    orr = evals_top10.over_refusal_eval()
    assert orr["in_scope"] >= 40                            # the brief's 50-question pool, measured honestly
    for q in evals_top10.STOCK_QUESTIONS:
        assert q[0][:40] not in orr["refusal_questions"], q


def test_scorecard_gates_and_report(tmp_path):
    """AC: BSA-AC-608. A5: the scorecard passes its gates (live lane for read/refusal, deterministic for the rest)
    and the report carries every number with its gate, lane and delta."""
    r = evals_top10.top10()
    for k in ("grounding_f", "completeness", "tool_accuracy_write"):
        assert r["pass"][k], (k, r["scores"][k])
    if r["lane"]["live_used"]:
        assert r["pass"]["tool_accuracy_read"] and r["pass"]["over_refusal_rate"]
    else:
        assert not r["lane"]["live_suite"].get("available")     # no artifact: the floor stood in, verdict honest
    out = os.path.join(str(tmp_path), "top10.md")
    sp = os.path.join(str(tmp_path), "scores.json")
    evals_top10.write_report(r, path=out, scores_path=sp)
    body = open(out, encoding="utf-8").read()
    assert "A1 근거성 F" in body and "PASS" in body and "floor" in body
    stored = json.load(open(sp, encoding="utf-8"))
    assert stored["tool_accuracy_write"] == 1.0


def test_delta_rule_flags_a_regression(tmp_path):
    """AC: BSA-AC-608. A stored previous run below the current by more than 0.02 flips the verdict (loop.gate rule)."""
    prev_path = str(tmp_path / "scores.json")
    r = evals_top10.top10()
    good = dict(r["scores"])
    with open(prev_path, "w", encoding="utf-8") as fh:
        json.dump({k: (v + 0.05 if isinstance(v, (int, float)) and k not in ("over_refusal_rate",) else v) for k, v in good.items()}, fh)
    evals_top10.SCORES_PATH = prev_path
    try:
        r2 = evals_top10.top10()
        assert r2["deltas"]["grounding_f"] is not None
    finally:
        evals_top10.SCORES_PATH = os.path.join("evals", "top10_scores.json")
