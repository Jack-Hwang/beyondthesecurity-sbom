"""MLOps maturity self-diagnostic as a MEASURED command (backlog C70; course week 3: Level 0 = manual notebook,
Level 1 = automated pipeline, Level 2 = CI/CD with automated training/deployment). The lecture asks 'what level
are we?' - most teams answer from memory. This answers from the repository: each dimension checks for its
ARTIFACT (level 1) and for its ENFORCEMENT (level 2 = a test or a CI step that fails when the artifact stops
working). The overall level is the MINIMUM - one manual dimension makes the whole loop manual, and the report
says which dimension is holding the rest back instead of averaging the shame away.

Every level here is binary evidence: the artifact path exists (or not), the enforcement string appears in a test
or workflow (or not). Nothing is self-attested.
"""
from __future__ import annotations

import glob
import os
from typing import Any, Dict, List, Optional

#: dimension -> (artifact glob relative to root, enforcement marker that must appear in tests/ or .github/workflows/)
DIMENSIONS = {
    "eval_sets_pinned": ("evals/top10_scores.json", ["evalguard.fingerprint", "top10_scores.json"]),
    "scheduled_drift": (".github/workflows/nightly-drift.yml", ["nightly-drift.yml", "evalsets --root"]),
    "quality_gate": ("evals/top10_report.md", ["evals_top10", "top10_scores.json"]),
    "rollback_machine": ("bts_sbom_app/canary.py", ["canary.evaluate"]),
    "monitoring": ("bts_sbom_app/escalation_report.py", ["escalation_report.report", "eval_candidates"]),
    "feedback_loop": ("bts_sbom_app/feedback.py", ["record_feedback"]),
    "prompt_lineage": ("evals/prompt_registry.json", ["prompt_registry.json", "promptreg.digest"]),
    "audit_trail": ("docs/ENFORCEMENT_MAP.md", ["ENFORCEMENT_MAP"]),
}


def _gate_present(root: str, markers: List[str]) -> Optional[str]:
    """The first file under tests/ or .github/workflows/ that mentions one of the markers (the dimension is
    enforced, not just present), else None."""
    for pat in ("tests/**/*.py", ".github/workflows/*.yml"):
        for p in glob.glob(os.path.join(root, pat), recursive=True):
            try:
                text = open(p, encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            for m in markers:
                if m in text:
                    return os.path.relpath(p, root).replace("\\", "/")
    return None


def diagnose(root: Optional[str] = None) -> Dict[str, Any]:
    """The measured maturity: per dimension {level, artifact, enforced_by}, the overall = min, and the blocking
    dimensions named. Levels: 0 = artifact absent, 1 = artifact present, 2 = artifact present AND enforced."""
    root = root or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    dims: Dict[str, Dict[str, Any]] = {}
    for name, (artifact, markers) in DIMENSIONS.items():
        path = os.path.join(root, *artifact.split("/"))
        present = os.path.exists(path)
        gate = _gate_present(root, markers) if present else None
        dims[name] = {"artifact": artifact, "artifact_present": present,
                      "enforced_by": gate, "level": 2 if (present and gate) else (1 if present else 0)}
    overall = min(d["level"] for d in dims.values())
    blockers = sorted(k for k, d in dims.items() if d["level"] == overall and overall < 2)
    return {"dimensions": dims, "overall_level": overall, "blockers": blockers,
            "scale": "L0 manual only / L1 artifact exists / L2 artifact enforced by a test or CI step",
            "honesty": "the level is measured from repo artifacts, not self-attested; the overall is the MINIMUM dimension"}
