"""Error envelope + handoff schema (MetaNet 4주차 3차시).

A sub-agent (council member, chat tool, gate step) that fails is never silently dropped: the caller gets a
structured envelope saying what failed, how bad it is, what still completed, what partial result survived and
where the coverage gap now is. The handoff is the explicit contract passed DOWN to a stage (and reported UP):
schema_version, task, context, constraints and the list of gates that did not pass - nothing is inherited by
implication, so a stage that needed X and did not get it says so instead of guessing.

Pure functions only: the callers (council verdicts, chat stream events) adapt their own shapes onto these.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

SCHEMA_VERSION = "bts-sbom.handoff.v1"
SEVERITIES = ("warning", "recoverable", "fatal")          # warning: gap noted, answer fine; recoverable: partial
# result + gap; fatal: no usable result, needs_human territory.


def error_envelope(error_type: str, severity: str, *, retry_budget: int = 0,
                   completed_steps: Optional[Iterable[str]] = None,
                   partial_result: Any = None, coverage_gap: str = "") -> Dict[str, Any]:
    """The 4-3차시 envelope: {error_type, severity, retry_budget, completed_steps, partialResult, coverageGap}."""
    if severity not in SEVERITIES:
        raise ValueError("severity must be one of %s, got %r" % ("/".join(SEVERITIES), severity))
    return {"error_type": error_type, "severity": severity, "retry_budget": int(retry_budget),
            "completed_steps": list(completed_steps or []),
            "partialResult": partial_result, "coverage_gap": coverage_gap}


def handoff(task: str, context: Dict[str, Any], constraints: Iterable[str] = (),
            not_passed: Iterable[str] = ()) -> Dict[str, Any]:
    """Explicit stage-to-stage contract; ``not_passed`` lists every gate the next stage must know about."""
    return {"schema_version": SCHEMA_VERSION, "task": task, "context": dict(context),
            "constraints": list(constraints), "not_passed": list(not_passed)}


def council_envelope(verdict: Dict[str, Any], meta: Dict[str, Any], members: int) -> Optional[Dict[str, Any]]:
    """Adapt a council judge() result onto the envelope - None when nothing failed (no lie of an envelope).

    A verdict that rests on fewer than all members is recoverable (partial result + gap annotation); one that
    collapsed to needs_human because members died is fatal with whatever stage-1 answers survived."""
    errs = int(meta.get("errors", 0) or 0)
    if errs <= 0:
        return None
    completed = ["stage1:x%d" % (members - errs)] if members - errs > 0 else []
    if verdict.get("status") == "needs_human":
        return error_envelope("member_failure", "fatal", retry_budget=1, completed_steps=completed,
                              partial_result={"status": "needs_human", "reason": verdict.get("reason")},
                              coverage_gap="%d of %d members failed; no verdict" % (errs, members))
    return error_envelope("member_failure", "recoverable", retry_budget=1, completed_steps=completed,
                          partial_result={"status": verdict.get("status"), "license": verdict.get("license"),
                                          "members": meta.get("responded")},
                          coverage_gap="%d of %d members failed; verdict rests on partial evidence" % (errs, members))


def council_handoff(verdict: Dict[str, Any], meta: Dict[str, Any], envelope: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """The council -> chair/report handoff: what was asked, what the deterministic decision saw, what failed."""
    not_passed: List[str] = []
    if envelope:
        not_passed.append("full_member_quorum:%s" % envelope["coverage_gap"])
    if verdict.get("status") == "needs_human":
        not_passed.append("agreement:%s" % verdict.get("reason"))
    if verdict.get("applied") is False and verdict.get("status") != "needs_human":
        not_passed.append("applied:suggestion_only")
    return handoff("license_verdict", {"verdict": {k: verdict.get(k) for k in ("status", "license", "reason")},
                                       "meta": {k: meta.get(k) for k in ("members", "responded", "abstained", "invalid", "errors")}},
                   constraints=["decision is deterministic code, not the chairman",
                                "a verdict resting on a failed call is never cached or replayed"], not_passed=not_passed)
