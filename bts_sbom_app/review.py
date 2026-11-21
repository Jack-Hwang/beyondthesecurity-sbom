"""Independent patch review (advisory only): deterministic rules over the patch's outputs, not the planner's state.

Lecture 3 (AI DBA): the maker of a change is not its reviewer. ``review`` takes only artefacts - the planned
manifests, the changed files, the diff size, the four-quadrant impact and the upgrade list - and never the
planner's records. Its verdict is advice: it does NOT approve anything (approval stays the 16-digit digest
token gate in patch.py). Rules: R1 changed outside plan, R2 lockfile edited, R3 unacknowledged breaking
upgrade, R4 impact regression, R5 impact incomplete, R6 oversized diff.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from .impact import is_lockfile


def review(*, planned_files: Optional[List[str]], changed_files: List[str], diff_lines: int,
           impact: Optional[Dict[str, Any]], upgrades: List[Dict[str, Any]],
           ack_breaking: bool = False, max_diff_lines: int = 400) -> Dict[str, Any]:
    """Deterministic review of patch outputs. Priority: reject > changes_requested > approve."""
    findings: List[Dict[str, str]] = []
    planned = {str(f).replace("\\", "/") for f in (planned_files or [])}
    changed = {str(f).replace("\\", "/") for f in (changed_files or [])}
    if planned and not changed <= planned:
        extra = sorted(changed - planned)
        findings.append({"rule": "R1", "severity": "warn",
                         "detail": "changed files outside the planned manifests: %s" % ", ".join(extra[:5])})
    lock_edits = sorted(f for f in changed if is_lockfile(f))
    if lock_edits:
        findings.append({"rule": "R2", "severity": "warn",
                         "detail": "a lockfile was edited directly: %s (regenerate it from the manifest instead)" % ", ".join(lock_edits[:5])})
    breaking = [u for u in (upgrades or []) if str(u.get("breaking_risk") or "").lower() == "high"]
    if breaking and not ack_breaking:
        findings.append({"rule": "R3", "severity": "warn",
                         "detail": "major-version upgrade without acknowledgement: %s" % ", ".join(sorted({str(u.get("component")) for u in breaking})[:5])})
    verdict_impact = (impact or {}).get("verdict")
    if verdict_impact == "regression":
        findings.append({"rule": "R4", "severity": "error", "detail": "impact verdict is regression: revert or fix before proceeding"})
    elif verdict_impact == "incomplete" or verdict_impact is None:
        findings.append({"rule": "R5", "severity": "warn", "detail": "impact verdict is %s: some quadrants are unverified"
                         % (verdict_impact or "unavailable")})
    if diff_lines > max_diff_lines:
        findings.append({"rule": "R6", "severity": "warn", "detail": "diff of %d lines exceeds the review limit of %d" % (diff_lines, max_diff_lines)})
    if any(f["rule"] == "R4" for f in findings):
        verdict = "reject"
    elif findings:
        verdict = "changes_requested"
    else:
        verdict = "approve"
    return {"verdict": verdict, "findings": findings, "reviewer": "deterministic-v1", "independent": True}
