"""Portfolio export: the 8 deliverable packages gathered FROM the canonical files (task 5b).

The lecture says "export, don't rewrite": each package lists existing canonical files with size + sha256;
a missing file is marked "missing" (nothing is fabricated), and the two human deliverables (demo video,
personal contribution sheet) are marked "human_required" with a checklist. The self-assessment carries only
measurable evidence (AC count, test files, doclint result, traceability summary) - no rubric scores, judgement
items are "human_review". File CONTENTS are never copied: paths and hashes only, the originals stay canonical.
"""
from __future__ import annotations

import hashlib
import json
import os
from typing import Any, Dict, List

PACKAGES: List[Dict[str, Any]] = [
    {"id": 1, "name": "README", "files": ["README.md", "CHANGELOG.md", "docs/WORKFLOW.md", "docs/ARCHITECTURE.md"]},
    {"id": 2, "name": "SDD 정본", "files": ["specs/bts_sbom_app_features.md", "specs/bts_sbom_features.md", "docs/adr/",
                                            "docs/LECTURE_MAPPING.md", "docs/ANALYSIS_2026-11-17.md", "docs/CORE_ISSUES.md"]},
    {"id": 3, "name": "소스·인프라·하네스", "files": ["bts_sbom/", "bts_sbom_app/", "tools/", "Dockerfile.bts-sbom-app",
                                                        "Dockerfile", ".github/workflows/bts_sbom_app_ci.yml", ".github/workflows/ci.yml",
                                                        ".github/workflows/deploy_azure.yml", "infra/", "pyproject.toml"]},
    {"id": 4, "name": "평가 리포트", "files": ["evals/", "docs/LOOP_LOG.md"]},
    {"id": 5, "name": "운영 증빙", "files": ["docs/RUNBOOK.md", "docs/COST.md", "tests/bts_sbom_app/test_ops_probes.py",
                                             "tests/bts_sbom_app/test_container_policy.py", "docs/RUNBOOK.md"],
     "note": "this product is a localhost tool: there is no public deployment URL to cite (stated honestly)"},
    {"id": 6, "name": "거버넌스", "files": ["docs/governance/", "docs/ENFORCEMENT_MAP.md", "SECURITY.md", "CONTRIBUTING.md"]},
    {"id": 7, "name": "데모 영상", "files": [],
     "human_required": True, "checklist": ["녹화: 스캔 → 승인 패치 → 챗 근거 → /metrics 를 5분 안에", "링크를 여기에 기록"]},
    {"id": 8, "name": "개인 기여 기술서·회고", "files": [],
     "human_required": True, "checklist": ["기여 요약(이 브랜치의 작업 1~22 맵)", "회고: 잘 된 것/아쉬운 것", "다음 반복 계획"]},
]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _files_under(root: str, rel: str) -> List[str]:
    full = os.path.join(root, rel)
    if os.path.isfile(full):
        return [rel]
    if os.path.isdir(full):
        out = []
        for dp, dns, fns in os.walk(full):
            dns[:] = sorted(d for d in dns if d not in ("__pycache__", ".pytest_cache"))
            for fn in sorted(fns):
                out.append(os.path.relpath(os.path.join(dp, fn), root).replace("\\", "/"))
        return out
    return []


def export(root: str, out_dir: str) -> Dict[str, Any]:
    """Write manifest.json + manifest.md into ``out_dir`` (must not exist yet). Paths + hashes only."""
    pkgs: List[Dict[str, Any]] = []
    for pkg in PACKAGES:
        sources: List[Dict[str, str]] = []
        for rel in pkg["files"]:
            for f in _files_under(root, rel):
                full = os.path.join(root, f)
                sources.append({"path": f, "bytes": os.path.getsize(full), "sha256": _sha256(full), "status": "present"})
        missing = [rel for rel in pkg["files"] if not os.path.exists(os.path.join(root, rel))]
        pkgs.append({"id": pkg["id"], "name": pkg["name"], "status": "human_required" if pkg.get("human_required") else
                     ("complete" if sources else "missing"), "sources": sources,
                     **({"missing": missing} if missing else {}),
                     **({"checklist": pkg["checklist"]} if pkg.get("checklist") else {}),
                     **({"note": pkg["note"]} if pkg.get("note") else {})})

    # measurable evidence only - no rubric scores, judgement items are human_review
    acs = _traceability_summary(root)
    doclint_problems = _doclint_summary(root)
    test_files = sorted(f for f in os.listdir(os.path.join(root, "tests", "bts_sbom_app")) if f.startswith("test_") and f.endswith(".py")) \
        if os.path.isdir(os.path.join(root, "tests", "bts_sbom_app")) else []
    self_assessment = {
        "evidence": {"spec_acs": acs.get("acs"), "acs_without_test": acs.get("without_test"),
                     "test_files": len(test_files), "doclint_strict_problems": doclint_problems,
                     "traceability": acs},
        "judgement": "human_review",
        "note": "no rubric numbers are invented here; a human fills the judgement",
    }
    manifest = {"packages": pkgs, "self_assessment": self_assessment}
    os.makedirs(out_dir, exist_ok=False)
    with open(os.path.join(out_dir, "manifest.json"), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(manifest, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    lines = ["# Portfolio manifest", "", "| # | package | status | files |", "|---|---|---|---|"]
    for p in pkgs:
        lines.append("| %d | %s | %s | %d |" % (p["id"], p["name"], p["status"], len(p["sources"])))
    lines += ["", "자기 평가: 판단 항목은 human_review (루브릭 점수 없음). 측정 가능한 증거는 manifest.json 의 self_assessment."]
    with open(os.path.join(out_dir, "manifest.md"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(lines) + "\n")
    return manifest


def _traceability_summary(root: str) -> Dict[str, Any]:
    from . import traceability
    try:
        return traceability.build(root)["summary"]
    except Exception:                                          # noqa: BLE001 - the manifest is evidence, never a crash
        return {}


def _doclint_summary(root: str) -> int:
    from . import doclint
    total = 0
    for kind, path in doclint.collect(root, []):
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            continue
        total += len(doclint.lint_doc(text, kind, strict=True))
    return total
