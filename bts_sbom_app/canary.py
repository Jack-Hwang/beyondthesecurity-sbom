"""Canary deployment decision + machine-evaluated rollback triggers (backlog C82; course week 5 lesson 4: the
rollback trigger is a NUMBER in the runbook, not a feeling - "근거성·오류율이 기준선을 벗어남" evaluated by code).

Pure decision functions, stdlib only, no az subprocess inside the decision path (the command STRINGS are produced
for the operator; executing them stays an explicit human step, exactly like every effectful action here):

* :func:`evaluate` - the rollback trigger, machine-evaluated: compare the green revision's live measurements
  against the recorded baseline caps. Three verdicts: ``promote`` (every cap met), ``rollback`` (a cap broken -
  the verdict names WHICH metric and both numbers), ``hold`` (data missing: an absent metric is UNDECIDABLE,
  never silently treated as a pass - D1's "조용한 실패" rule).
* :func:`plan`     - the traffic-shift plan as command text (canary 10% -> 50% -> 100%, rollback = blue 100%).

The baseline caps live in the runbook the operator records (docs/AZURE_CANARY_RUNBOOK.md); a cap that is absent
from the baseline makes that metric hold - a gate nobody wrote is not a gate that passed.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

SCHEMA = "bts-sbom.canary.v1"
#: the caps a baseline must declare, and which direction is a violation (course 5-4 모니터링 신호 표)
CAPS = {"grounding_f": "min", "error_rate": "max", "p95_ms": "max"}


def evaluate(baseline: Optional[Dict[str, Any]], current: Optional[Dict[str, Any]]) -> Tuple[str, List[str]]:
    """(decision, reasons) - the machine-evaluated rollback trigger. ``baseline`` carries the caps
    ({"grounding_f": 0.9, "error_rate": 0.02, "p95_ms": 800}), ``current`` the green revision's measurements.
    Every declared cap is compared; a missing CURRENT metric is undecidable for that metric (hold unless another
    cap already forces a rollback); a missing BASELINE cap is simply not a gate and is named as such."""
    reasons: List[str] = []
    baseline = baseline or {}
    current = current or {}
    undecidable: List[str] = []
    broken: List[str] = []
    gated = 0
    for metric, direction in CAPS.items():
        cap = baseline.get(metric)
        if cap is None:
            reasons.append("no baseline cap recorded for %s - this run is not gated on it (write the cap)" % metric)
            continue
        val = current.get(metric)
        if not isinstance(val, (int, float)):
            undecidable.append("%s: measured %r is not a number" % (metric, val))
            continue
        gated += 1
        ok = val >= cap if direction == "min" else val <= cap
        if ok:
            reasons.append("%s ok: %s (cap %s %s)" % (metric, val, direction, cap))
        else:
            broken.append("%s %s violates the %s cap %s" % (metric, val, direction, cap))
    if broken:
        return "rollback", ["ROLLBACK: " + b for b in broken] + reasons
    if undecidable:
        return "hold", ["HOLD: " + u for u in undecidable] + reasons
    if gated < len(CAPS):                              # promote needs EVERY declared cap evaluated and met
        return "hold", ["HOLD: not every cap was evaluated (%d of %d)" % (gated, len(CAPS))] + reasons
    return "promote", reasons


def plan(blue: str, green: str, weight: int = 10, app: str = "bts-sbom-app", resource_group: str = "bts-sbom-rg") -> Dict[str, str]:
    """The traffic-shift command TEXT (never executed here): canary steps up and the rollback is the ratio going
    back - '롤백은 배포를 지우는 것이 아니라 비율을 되돌리는 것' (course 5-4)."""
    weight = max(0, min(100, int(weight)))
    return {
        "canary": "az containerapp update -g %s -n %s --traffic '%s=%d %s=%d'" % (resource_group, app, blue, 100 - weight, green, weight),
        "promote": "az containerapp update -g %s -n %s --traffic '%s=0 %s=100'" % (resource_group, app, blue, green),
        "rollback": "az containerapp update -g %s -n %s --traffic '%s=100 %s=0'" % (resource_group, app, blue, green),
    }
