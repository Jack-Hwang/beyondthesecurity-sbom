"""Reconcile a provider SBOM against the scanned artifacts (task 32, TR 8477 review P2-B, 5.2 cross-check) - stdlib only.

The provider's SBOM is DATA, not truth: the comparison answers which declared components the scan could not find,
which scanned components the SBOM did not declare (candidates only - binary string evidence is EVIDENCE, not
identification), where versions disagree, and how the BOM-based findings differ from the scan-based findings.
Never claims "compatible" or "clean" for a provider SBOM; every gap is stated with its evidence level.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

SCHEMA = "bts-sbom.reconcile.v1"
DISCLAIMER = "엔지니어링 신호이며 법률·적합성 판정이 아닙니다 — 독립 평가는 평가자의 몫입니다"
CANDIDATE_NOTE = "선언되지 않은 것으로 보인다(후보) — 바이너리 문자열은 식별이 아니라 증거다"


def _canon(name: str) -> str:
    return str(name or "").strip().lower()


def _sbom_components(doc: Dict[str, Any]) -> List[Dict[str, str]]:
    """(name, version, purl) rows from CycloneDX or SPDX JSON. Empty list when the format is unknown."""
    out: List[Dict[str, str]] = []
    if doc.get("bomFormat") == "CycloneDX" or doc.get("components"):
        for c in doc.get("components") or []:
            out.append({"name": str(c.get("name") or ""), "version": str(c.get("version") or ""), "purl": str(c.get("purl") or "")})
    elif doc.get("spdxVersion") or doc.get("packages"):
        for p in doc.get("packages") or []:
            out.append({"name": str(p.get("name") or ""), "version": str(p.get("version") or ""), "purl": str(p.get("packageFileName") or "")})
    return [r for r in out if r["name"] and r["name"].lower() not in ("", "the software", "unknown")]


def _vuln_ids(rec: Dict[str, Any]) -> List[Dict[str, str]]:
    """(id, package, version) of the scan-based findings."""
    return [{"id": v.get("id"), "package": v.get("package"), "version": v.get("version")} for v in rec.get("vulns") or []]


def _bom_vuln_ids(provider_doc: Optional[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Findings declared in the provider SBOM's vulnerabilities block (CycloneDX), when present."""
    out: List[Dict[str, str]] = []
    for v in (provider_doc or {}).get("vulnerabilities") or []:
        affects = (v.get("affects") or [{}])
        ref = affects[0].get("ref") if affects else ""
        pkg = str(ref).split("@")[0].replace("pkg:pypi/", "").replace("pkg:npm/", "")
        out.append({"id": v.get("id") or v.get("bom-ref"), "package": pkg, "version": str(ref).split("@")[1] if "@" in str(ref) else ""})
    return out


def reconcile(provider_sbom: Dict[str, Any], rec: Dict[str, Any], *, string_evidence: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Cross-check (TR 5.2): provider declaration vs the scanned artifacts. All gaps carry their evidence level."""
    declared = _sbom_components(provider_sbom)
    scanned = rec.get("components") or []
    declared_keys = {_canon(r["name"]): r for r in declared}
    scanned_keys = {_canon(str(c.get("name"))): c for c in scanned}

    undeclared_candidates: List[Dict[str, Any]] = []
    for c in scanned:
        if _canon(str(c.get("name"))) not in declared_keys:
            evidence_level = "candidate (string evidence is not identification)" if string_evidence else "candidate"
            undeclared_candidates.append({"name": c.get("name"), "version": c.get("version"), "evidence": evidence_level,
                                          "note": CANDIDATE_NOTE if string_evidence else "found by scanning the manifests the provider SBOM does not declare"})

    missing_from_artifacts: List[Dict[str, Any]] = []
    for name, row in sorted(declared_keys.items()):
        scanned_c = scanned_keys.get(name)
        if scanned_c is None:
            missing_from_artifacts.append({"name": row["name"], "declared_version": row["version"],
                                           "evidence": "not found in the scanned manifests (may be bundled, unused or renamed)"})
        elif row["version"] and scanned_c.get("version") and str(scanned_c.get("version")) != row["version"]:
            missing_from_artifacts.append({"name": row["name"], "declared_version": row["version"],
                                           "scanned_version": scanned_c.get("version"), "evidence": "version mismatch"})

    bom_vulns = _bom_vuln_ids(provider_sbom)
    scan_vulns = _vuln_ids(rec)
    bom_ids = {str(v.get("id")) for v in bom_vulns}
    scan_ids = {str(v.get("id")) for v in scan_vulns}
    only_in_scan = [v for v in scan_vulns if str(v.get("id")) not in bom_ids]
    only_in_bom = [v for v in bom_vulns if str(v.get("id")) not in scan_ids]

    return {"schema": SCHEMA, "disclaimer": DISCLAIMER,
            "declared_components": len(declared), "scanned_components": len(scanned),
            "undeclared_candidates": undeclared_candidates,
            "missing_from_artifacts": missing_from_artifacts,
            "vulns": {"only_in_scan": only_in_scan, "only_in_bom": only_in_bom,
                      "note": "BOM 기준 권고와 스캔 기준 권고의 차이 — 제공자가 다른 시점·다른 DB 를 조회했을 수 있다"},
            "verdict": "reconciliation findings only - no conformance verdict (assessor's judgement, TR annex A)"}
