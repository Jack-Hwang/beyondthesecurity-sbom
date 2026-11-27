"""Independent, deterministic review of a patch PROPOSAL (course package B, lecture 3-3 p.54/56).

The patch pipeline is propose -> sandbox (work copy) -> approval token -> apply -> re-scan -> (this module) ->
human approval -> delivery. ``review()`` is the "independent review" step: it never sees the planner's
internal state (no ``rec``, no in-memory plan objects) - only the ARTIFACTS a reviewer in real life would be
handed: the approval digest, which files actually changed, a diff size, the impact classification
(:mod:`bts_sbom_app.impact`) and a plan summary (:func:`bts_sbom_app.remediate.summary`). That is what
"independent" means here: the review would reach the same verdict from a bundle of facts alone, with no
access to how the planner got there. See docs/adr/ADR-0012.

``review()`` is ADVISORY ONLY. It never applies, reverts or approves anything - the existing 16-character
approval-token gate in :mod:`bts_sbom_app.patch` is unchanged and still the only thing that authorises a
file write. A caller who ignores a ``reject`` and applies anyway is not blocked by this module; it is the
human's decision to make, with the finding in front of them.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

REVIEWER = "deterministic-v1"

_LOCKFILE_NAMES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock",
                    "gemfile.lock", "composer.lock", "go.sum", "poetry.lock", "pipfile.lock", "pubspec.lock",
                    "mix.lock", "gradle.lockfile", "packages.lock.json"}

APPROVE = "approve"
CHANGES_REQUESTED = "changes_requested"
REJECT = "reject"
_RANK = {APPROVE: 0, CHANGES_REQUESTED: 1, REJECT: 2}


def _basename(path: str) -> str:
    return str(path or "").replace("\\", "/").rsplit("/", 1)[-1].lower()


def _finding(rule: str, severity: str, detail: str, verdict: str) -> Dict[str, Any]:
    return {"rule": rule, "severity": severity, "detail": detail, "_verdict": verdict}


def _compat_findings(compat: Optional[Dict[str, Any]], runtime: Optional[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Rules over the MEASURED compatibility (bts_sbom_app.compat / compat_runtime). A plan the gate held back was not applied, so it
    is informational; a breaking plan that WAS applied (warn mode) is a reject; ``review`` findings ask for a human look;
    unverified is informational - absence of evidence is reported, never turned into a block."""
    out: List[Dict[str, Any]] = []
    if compat:
        held = set((compat.get("held") or {}).keys())
        plans = compat.get("plans") or []
        broke = [p for p in plans if p.get("status") == "breaking" and p.get("key") not in held]
        rev = [p for p in plans if p.get("status") == "review" and p.get("key") not in held]
        if broke:
            out.append(_finding("RV-COMPAT-BREAKING", "high", "%d applied upgrade(s) carry a breaking compatibility finding: %s" % (
                len(broke), ", ".join("%s %s->%s" % (p.get("component"), p.get("from"), p.get("to")) for p in broke[:8])), REJECT))
        if rev:
            out.append(_finding("RV-COMPAT-REVIEW", "medium", "%d applied upgrade(s) need a human look at the used API: %s" % (
                len(rev), ", ".join(str(p.get("component")) for p in rev[:8])), CHANGES_REQUESTED))
        if held:
            out.append(_finding("RV-COMPAT-HELD", "low", "%d upgrade(s) were held back by the compatibility gate and remain vulnerable until their call "
                                "sites or pins are adapted: %s" % (len(held), ", ".join(sorted(held)[:8])), APPROVE))
        unver = [p for p in plans if p.get("status") == "unverified"]
        if unver:
            out.append(_finding("RV-COMPAT-UNVERIFIED", "low", "%d upgrade(s) have no measured compatibility (offline, no archive or an unsupported "
                                "ecosystem): only the major-bump prior applies" % len(unver), APPROVE))
    if runtime:
        after = runtime.get("after") or {}
        if after.get("status") == "regression":
            out.append(_finding("RV-RUNTIME-REGRESSION", "high", "the project's own tests regressed on the patched pins: %s" % after.get("reason"), REJECT))
        elif (runtime.get("baseline") or {}).get("status") == "unverified":
            out.append(_finding("RV-RUNTIME-UNVERIFIED", "low", "runtime differential requested but not measurable: %s" % (runtime["baseline"].get("reason")), APPROVE))
    return out


def review(*, plan_digest: str, changed_files: Sequence[str], planned_manifests: Sequence[str],
           diff_stats: Optional[Dict[str, Any]], impact: Optional[Dict[str, Any]], plan_summary: Optional[Dict[str, Any]],
           major_bump_confirmed: bool = False, max_diff_lines: int = 400, compat: Optional[Dict[str, Any]] = None,
           compat_runtime: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Deterministic rule check over the patch ARTIFACTS (never the planner's internal state).

    changed_files        manifest paths patch.apply() actually edited (its "changed_files").
    planned_manifests    manifest paths the remediation plan said it would touch (union of every upgrade
                          plan's "files").
    diff_stats            {"lines_changed": int, ...} - a line-count summary of the applied diff; only
                          "lines_changed" is read.
    impact                bts_sbom_app.impact.classify() result ({"verdict": ..., ...}) or None/{} when it
                          could not be computed.
    plan_summary          bts_sbom_app.remediate.summary() result ({"major_bumps": int, ...}) or None.
    compat                bts_sbom_app.compat.assess() result (per-plan measured compatibility) or None. Optional: when absent no
                          compat rule fires, so older callers keep their verdicts.
    compat_runtime        the opt-in runtime differential record (baseline vs patched test run) or None.
    major_bump_confirmed  True only when a human explicitly confirmed a high-breaking-risk (major version)
                          upgrade; this function never infers consent from the plan itself.
    max_diff_lines        changed+added line cap before the diff is flagged as too large to rubber-stamp.

    Returns {"verdict": "approve"|"changes_requested"|"reject", "findings": [{"rule","severity","detail"}],
    "reviewer": "deterministic-v1", "independent": True}.
    """
    changed = set(str(f or "").replace("\\", "/") for f in (changed_files or []))
    planned = set(str(f or "").replace("\\", "/") for f in (planned_manifests or []))
    impact = impact or {}
    plan_summary = plan_summary or {}
    findings: List[Dict[str, Any]] = []

    out_of_scope = sorted(changed - planned)
    if out_of_scope:
        findings.append(_finding("RV-SCOPE", "high",
                                  "file(s) changed that were not part of the plan: " + ", ".join(out_of_scope[:20]), REJECT))

    lock_edits = sorted(f for f in changed if _basename(f) in _LOCKFILE_NAMES)
    if lock_edits:
        findings.append(_finding("RV-LOCKFILE", "high",
                                  "a lockfile was edited directly (lockfiles must be regenerated, not hand-edited): "
                                  + ", ".join(lock_edits[:20]), REJECT))

    major_bumps = int(plan_summary.get("major_bumps") or 0)
    if major_bumps and not major_bump_confirmed:
        findings.append(_finding("RV-MAJOR-BUMP", "medium",
                                  "%d upgrade(s) carry a high breaking-risk (major version) promotion with no explicit "
                                  "confirmation on record" % major_bumps, CHANGES_REQUESTED))

    impact_verdict = impact.get("verdict")
    if impact_verdict == "regression":
        findings.append(_finding("RV-IMPACT-REGRESSION", "high",
                                  "impact analysis reports a regression: " + str(impact.get("summary") or ""), REJECT))
    elif impact_verdict == "incomplete":
        findings.append(_finding("RV-IMPACT-INCOMPLETE", "medium",
                                  "impact analysis is incomplete (at least one quadrant unverified): "
                                  + str(impact.get("summary") or ""), CHANGES_REQUESTED))
    elif impact_verdict is None:
        findings.append(_finding("RV-IMPACT-MISSING", "medium",
                                  "no impact analysis was provided", CHANGES_REQUESTED))

    findings.extend(_compat_findings(compat, compat_runtime))

    lines_changed = int((diff_stats or {}).get("lines_changed") or 0)
    if lines_changed > max_diff_lines:
        findings.append(_finding("RV-DIFF-SIZE", "low",
                                  "diff is %d line(s), over the %d-line review cap" % (lines_changed, max_diff_lines), CHANGES_REQUESTED))

    if not plan_digest:
        findings.append(_finding("RV-NO-DIGEST", "low", "no approval digest was supplied with this review", CHANGES_REQUESTED))

    verdict = APPROVE
    for f in findings:
        if _RANK[f["_verdict"]] > _RANK[verdict]:
            verdict = f["_verdict"]
    public_findings = [{"rule": f["rule"], "severity": f["severity"], "detail": f["detail"]} for f in findings]
    return {"verdict": verdict, "findings": public_findings, "reviewer": REVIEWER, "independent": True}


__all__ = ["review", "REVIEWER", "APPROVE", "CHANGES_REQUESTED", "REJECT"]
