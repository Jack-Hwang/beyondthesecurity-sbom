"""License obligations & source-disclosure exposure report (task 23, brief 2) - stdlib only.

Answers the developer's real question that the category-level policy report cannot: WHICH component, under
WHICH use scenario (internal use / binary distribution / SaaS), raises WHICH kind of source-disclosure duty -
and what one could choose instead. The rules are REFERENCE rules ("reference" confidence: widely quoted in
public explanations, not checked against any license text here) and the whole output carries a disclaimer:
this is an engineering signal, NOT legal advice. An unresolved license is "unknown" in every scenario and is
never counted as none - absence of evidence is not a pass.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import licenses

SCHEMA = "bts-sbom.obligations.v1"
DISCLAIMER = "엔지니어링 신호이며 법률 자문이 아닙니다 — 법무 확인이 필요합니다 (engineering signal, not legal advice)"

SCENARIOS = ("internal", "binary", "saas")
# verdict / scope / why - reference rules, widely quoted in public explanations; legal review required
SCOPE: Dict[tuple, Dict[str, str]] = {
    ("public-domain", "internal"): {"verdict": "none", "scope": "none", "why": "no duty under these reference rules"},
    ("public-domain", "binary"): {"verdict": "none", "scope": "none", "why": "keep notices"},
    ("public-domain", "saas"): {"verdict": "none", "scope": "none", "why": "no duty under these reference rules"},
    ("permissive", "internal"): {"verdict": "none", "scope": "none", "why": "no duty under these reference rules"},
    ("permissive", "binary"): {"verdict": "none", "scope": "none", "why": "keep notices (notice duty stays)"},
    ("permissive", "saas"): {"verdict": "none", "scope": "none", "why": "no duty under these reference rules"},
    ("weak-copyleft", "internal"): {"verdict": "none", "scope": "none", "why": "no distribution under these reference rules"},
    ("weak-copyleft", "binary"): {"verdict": "offer", "scope": "library_only", "why": "distribute the library's source or object per the reference rules"},
    ("weak-copyleft", "saas"): {"verdict": "none", "scope": "none", "why": "no distribution under these reference rules"},
    ("strong-copyleft", "internal"): {"verdict": "none", "scope": "none", "why": "no distribution now - redistribution would change the result"},
    ("strong-copyleft", "binary"): {"verdict": "offer", "scope": "combined_work", "why": "the reference rules ask for the combined work's source on distribution"},
    ("strong-copyleft", "saas"): {"verdict": "none", "scope": "none", "why": "network provision is not distribution under the strong-copyleft reference rules"},
    ("network-copyleft", "internal"): {"verdict": "review", "scope": "unknown", "why": "internal users over the network may count - legal review required"},
    ("network-copyleft", "binary"): {"verdict": "offer", "scope": "combined_work_incl_network", "why": "the reference rules extend the source duty to network users"},
    ("network-copyleft", "saas"): {"verdict": "offer", "scope": "combined_work_incl_network", "why": "the reference rules apply to network provision itself"},
    ("restricted", "internal"): {"verdict": "review", "scope": "unknown", "why": "commercial/field-of-use restrictions - legal review required"},
    ("restricted", "binary"): {"verdict": "review", "scope": "unknown", "why": "commercial/field-of-use restrictions - legal review required"},
    ("restricted", "saas"): {"verdict": "review", "scope": "unknown", "why": "commercial/field-of-use restrictions - legal review required"},
}
UNKNOWN_RULE = {"verdict": "unknown", "scope": "unknown", "why": "license unresolved - identify the license first"}

# exactly these 5 compatibility reference rules; every other combination is no_rule (we never say "compatible")
COMPAT_RULES: Dict[tuple, Dict[str, str]] = {
    ("gpl-3.0-only", "mit"): "combined_work_follows_dependency", ("gpl-3.0-only", "bsd-2-clause"): "combined_work_follows_dependency",
    ("gpl-3.0-only", "bsd-3-clause"): "combined_work_follows_dependency", ("gpl-3.0-only", "isc"): "combined_work_follows_dependency",
    ("gpl-3.0-only", "apache-2.0"): "combined_work_follows_dependency",
    ("gpl-3.0-or-later", "mit"): "combined_work_follows_dependency", ("gpl-3.0-or-later", "bsd-2-clause"): "combined_work_follows_dependency",
    ("gpl-3.0-or-later", "bsd-3-clause"): "combined_work_follows_dependency", ("gpl-3.0-or-later", "isc"): "combined_work_follows_dependency",
    ("gpl-3.0-or-later", "apache-2.0"): "combined_work_follows_dependency",
    ("gpl-2.0-only", "apache-2.0"): "commonly_cited_incompatible",
    ("gpl-2.0-only", "gpl-3.0-only"): "commonly_cited_incompatible", ("gpl-3.0-only", "gpl-2.0-only"): "commonly_cited_incompatible",
    ("agpl-3.0-only", "*"): "network_clause_applies", ("agpl-3.0-or-later", "*"): "network_clause_applies",
    ("lgpl-2.0-only", "*"): "library_relink_duty", ("lgpl-2.1-only", "*"): "library_relink_duty",
    ("lgpl-2.1-or-later", "*"): "library_relink_duty", ("lgpl-3.0-only", "*"): "library_relink_duty", ("lgpl-3.0-or-later", "*"): "library_relink_duty",
}
COMPAT_NOTE = "공개 설명에 널리 인용되는 참고 규칙이며 원문 확인이 필요합니다 (widely quoted reference rule; verify the original text)"
_AGPL_LIKE = ("agpl-3.0-only", "agpl-3.0-or-later", "gpl-3.0-only", "gpl-3.0-or-later")

MITIGATION_IDS = ["replace", "isolate", "relicense_or_dual", "remove", "comply_with_disclosure"]
MITIGATION_TEXT = {
    "replace": "다른 라이선스의 대체 컴포넌트로 교체한다 — 대체 후보는 별도 확인 필요",
    "isolate": "별도 프로세스·서비스 경계로 분리 — 법적 효과는 사안별이므로 법무 확인",
    "relicense_or_dual": "업스트림에 재라이선스·이중 라이선스를 요청한다 — 업스트림 결정 사항",
    "remove": "컴포넌트를 제거하거나 기능을 자체 구현으로 바꾼다",
    "comply_with_disclosure": "요구되는 소스 공개를 이행한다 — 범위는 법무 확인",
}


def _cat(expr: str) -> str:
    """Lowercase SPDX id, keeping the -only/-or-later suffix (the rules distinguish them); "+" is the older
    or-later spelling, folded into -or-later."""
    s = str(expr or "").strip().lower()
    if s.endswith("+"):
        s = s[:-1] + "-or-later"
    return s


def compat_label(dependency: str, project_license: str) -> str:
    dep = _cat(dependency)
    proj = _cat(project_license)
    if not dep or not proj:
        return "no_rule"
    rule = COMPAT_RULES.get((dep, proj))
    if rule:
        return rule
    if dep in _AGPL_LIKE and proj not in _AGPL_LIKE:
        return "network_clause_applies"
    if dep in ("lgpl-2.0-only", "lgpl-2.1-only", "lgpl-2.1-or-later", "lgpl-3.0-only", "lgpl-3.0-or-later"):
        return "library_relink_duty"
    return "no_rule"


def _scenario_rows(components: List[Dict[str, Any]], scenario: str) -> Dict[str, Any]:
    rows = []
    counts = {"source_offer": 0, "review": 0, "unknown": 0, "none": 0}
    for c in sorted(components or [], key=lambda x: (str(x.get("name")).lower(), str(x.get("version")))):
        cat = str(c.get("license_category") or licenses.category(c.get("license") or ""))
        rule = SCOPE.get((cat, scenario), UNKNOWN_RULE)
        verdict = rule["verdict"]
        if verdict == "offer":
            counts["source_offer"] += 1
        elif verdict == "review":
            counts["review"] += 1
        elif verdict == "unknown":
            counts["unknown"] += 1
        else:
            counts["none"] += 1
        rows.append({"name": c.get("name"), "version": c.get("version"), "license": c.get("license") or "",
                     "category": cat, "verdict": verdict, "scope": rule["scope"], "why": rule["why"]})
    if counts["source_offer"]:
        status = "exposed"
    elif counts["unknown"] or counts["review"]:
        status = "incomplete"
    elif not rows:
        status = "no_data"
    else:
        status = "clean"
    return {"status": status, "counts": counts, "components": rows}


def assess(components: List[Dict[str, Any]], *, policy: Optional[Dict[str, Any]] = None,
           project_license: str = "", computed_on_read: bool = False) -> Dict[str, Any]:
    pol = dict(licenses.DEFAULT_POLICY, **(policy or {}))
    scenarios = {s: _scenario_rows(components, s) for s in SCENARIOS}
    compat: List[Dict[str, str]] = []
    if str(project_license or "").strip():
        for c in sorted(components or [], key=lambda x: (str(x.get("name")).lower(), str(x.get("version")))):
            label = compat_label(c.get("license") or "", project_license)
            if label == "no_rule":
                continue
            compat.append({"dependency": c.get("name"), "dependency_license": c.get("license") or "", "project_license": project_license,
                           "label": label, "confidence": "reference", "note": COMPAT_NOTE})
    mitigations: List[Dict[str, Any]] = []
    for s in SCENARIOS:
        for row in scenarios[s]["components"]:
            if row["verdict"] == "offer":
                mitigations.append({"component": row["name"], "scenario": s,
                                    "options": [{"id": mid, "text": MITIGATION_TEXT[mid], "needs_human": True} for mid in MITIGATION_IDS]})
    return {"schema": SCHEMA, "disclaimer": DISCLAIMER, "computed_on_read": bool(computed_on_read),
            "policy": pol, "scenarios": scenarios, "compatibility": compat,
            "compatibility_note": "" if str(project_license or "").strip() else "project license unknown",
            "mitigations": mitigations}
