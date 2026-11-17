# vendored from sca_guard/sectors.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""6-sector regulatory report engine — SBOM/VEX/EOL fields vs. each sector's
regulation, with honest verdicts only.

Maps REA `polyspace_re_docs/21_sca_sbom_oss_release.md` §3 (the 6-sector
regulation matrix) onto the existing BTS SCA/SBOM stack:

  ================  ============================================================
  sector            regulation / guide (research basis, 2025-11)
  ================  ============================================================
  cra               EU Cyber Resilience Act — Regulation (EU) 2024/2847,
                    in force 2024-12-10, vulnerability-reporting duties from
                    2026-09-11, FULL application 2027-12-11 (Annex I: secure
                    by design, SBOM, vulnerability handling, support period)
  fda               FD&C Act §524B (2023-03) — cyber devices submitted under
                    510(k)/PMA/De Novo must include an SBOM — plus the FDA
                    final guidance "Cybersecurity in Medical Devices: Quality
                    System Considerations and Content of Premarket
                    Submissions" (2025-06), which newly expects a per-component
                    SUPPORT STATUS + END-OF-SUPPORT DATE
  r155              UNECE R155 (CSMS) / R156 (SUMS) — RXSWIN software
                    identification, update impact analysis, supply-chain
                    vulnerability monitoring; full new-type coverage 2027
  dod               EO 14028 (2021-05-12) §4 · OMB M-22-18 · CISA SBOM
                    self-attestation common form · DoD Software Pathway (SWP)
  finance           금융보안원 「금융분야 OSS 활용·관리 안내서」 · KISA SW 공급망
                    보안 가이드라인 — OSS 거버넌스·취약점·SBOM 관리 체크리스트
  robot             KISA 로봇 보안모델·체크리스트 · ISO 10218-1:2025 (robot
                    security evaluation) · EU CRA overlap (robots are products
                    with digital elements)
  ================  ============================================================

HONESTY DISCIPLINE (the reason this module exists):
  * checks operate ONLY on real document fields. A requirement whose needed
    input is absent (no VEX document, no end-of-support input, ...) is
    ``not_evidence`` — never a pass and never an invented fail.
  * every row carries ``evidence`` with measured numbers (pcts, counts) or
    the absent-input reason. 0 fabricated passes.
  * NTIA minimum-element scoring is REUSED from ``bts_sbom._internal.ntia_check`` (both
    SPDX 2.3 and CycloneDX 1.5 go through its ``evaluate``) — the checker
    that already drives the product, not a re-implementation.

Interpretation choices (stated so reviewers can disagree):
  * supplier coverage threshold is 80% (CRA-style materiality); the measured
    pct is always in the evidence so a reader can apply a stricter bar.
  * end-of-support coverage: the ``eol`` input ({component: {"eol": ...,
    "status": ...}}) is primary; when it is absent the checker falls back to
    eol/eos markers embedded in the SBOM itself (CycloneDX component
    ``properties`` whose name mentions eol/end-of-support, SPDX package
    ``annotations`` whose annotationValue/comment mentions them).  If neither
    exists the requirement is ``not_evidence`` — the FDA 2025-06 expectation
    cannot be scored without it.
  * end-of-support and license-coverage counts include every package the
    document lists (including an SPDX described product — the product itself
    is exactly what CRA/FDA attach the support period to), while the NTIA
    reuse keeps its own documented product/dependency separation.
"""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from bts_sbom._internal import ntia_check
from bts_sbom._internal.license_spdx import SENTINELS as _SPDX_SENTINELS
# (vendored: the platform modules common.ntia_check / common.license.spdx
#  live in bts_sbom._internal here; every check behaves identically)

__all__ = ["SECTORS", "SECTOR_TITLES", "SECTOR_PROFILES", "sector_report",
           "write_evidence", "SCHEMA"]

SCHEMA = "bts-sector-report-1"

SECTORS = ("cra", "fda", "r155", "dod", "finance", "robot")

SECTOR_TITLES: Dict[str, str] = {
    "cra": "EU Cyber Resilience Act (Regulation (EU) 2024/2847)",
    "fda": "FDA FD&C §524B + 2025-06 final guidance (cyber devices)",
    "r155": "UNECE R155 CSMS / R156 SUMS",
    "dod": "EO 14028 · CISA attestation · DoD Software Pathway",
    "finance": "금융보안원 OSS 안내서 · KISA SW 공급망 가이드라인",
    "robot": "KISA 로봇 보안모델 · ISO 10218-1:2025 · CRA overlap",
}

#: license values that mean "we do not know" (license_spdx SENTINELS,
#: plus the empty string — same treatment as license_utils.py).
_UNKNOWN_LICENSE = {"", "NOASSERTION", "NONE", "UNKNOWN", "N/A"} | {
    s.upper() for s in _SPDX_SENTINELS}

_SUPPLIER_THRESHOLD_PCT = 80.0

_EOL_TOKENS = ("eol", "end-of-support", "end_of_support", "eos")

_ABSENT = ntia_check._ABSENT  # same "absent" vocabulary as the NTIA checker


# ── document structure helpers ────────────────────────────────────────────────

def _detect_format(sbom: dict) -> Optional[str]:
    """'SPDX' | 'CycloneDX' | None — same recognition rules as ntia_check."""
    if str(sbom.get("bomFormat", "")).lower() == "cyclonedx":
        return "CycloneDX"
    if str(sbom.get("spdxVersion", "")).upper().startswith("SPDX-"):
        return "SPDX"
    return None


def _components(sbom: dict) -> List[dict]:
    """Flat component/package list for coverage counting (both formats)."""
    if _detect_format(sbom) == "CycloneDX":
        return ntia_check._flatten_cdx(sbom.get("components") or [])
    return [p for p in (sbom.get("packages") or []) if isinstance(p, dict)]


def _component_name(comp: dict) -> str:
    return str(comp.get("name", ""))


def _annotations_text(comp: dict) -> str:
    """SPDX package annotations as one lowercase text blob."""
    parts = []
    for a in comp.get("annotations") or []:
        if isinstance(a, dict):
            parts.append(str(a.get("annotationValue", "")))
            parts.append(str(a.get("comment", "")))
    return " ".join(parts).lower()


def _comp_properties(comp: dict) -> List[tuple]:
    """CycloneDX component properties as (lowercase name, value) pairs."""
    out = []
    for p in comp.get("properties") or []:
        if isinstance(p, dict):
            out.append((str(p.get("name", "")).lower(), str(p.get("value", ""))))
    return out


def _embedded_eol(comp: dict) -> bool:
    """True when the SBOM itself carries an eol/eos marker for this component
    (CycloneDX property with a truthy value, or SPDX annotation text)."""
    text = _annotations_text(comp)
    if any(tok in text for tok in _EOL_TOKENS):
        return True
    for name, value in _comp_properties(comp):
        if any(tok in name for tok in _EOL_TOKENS) and value.strip().lower() not in _ABSENT:
            return True
    return False


def _properties_text(sbom: dict) -> List[tuple]:
    """Document-level (name, text) scan targets for markers like RXSWIN:
    CycloneDX metadata.properties + top-level properties, SPDX annotations
    and document comment."""
    targets: List[tuple] = []
    meta = sbom.get("metadata") or {}
    for src, label in ((meta.get("properties"), "metadata.properties"),
                       (sbom.get("properties"), "properties")):
        for p in src or []:
            if isinstance(p, dict):
                targets.append((label, str(p.get("name", "")).lower()
                                + " " + str(p.get("value", "")).lower()))
    targets.append(("comment", str(sbom.get("comment", "")).lower()))
    for a in sbom.get("annotations") or []:
        if isinstance(a, dict):
            targets.append(("annotations", str(a.get("annotationValue", "")).lower()
                            + " " + str(a.get("comment", "")).lower()))
    return targets


# ── measured facts reused from common.ntia_check ─────────────────────────────

def _ntia(sbom: dict) -> dict:
    return ntia_check.evaluate(sbom)


def _ntia_element(res: dict, eid: str) -> Optional[dict]:
    if res.get("status") != "OK":
        return None
    return next((e for e in res.get("elements", []) if e["id"] == eid), None)


# ── check functions (context → (verdict, detail, evidence)) ──────────────────
# verdict ∈ {"pass", "gap", "not_evidence"}; a check NEVER returns a verdict
# it cannot support: absent input → not_evidence, below threshold → gap.

def _check_format_declared(ctx: dict) -> tuple:
    fmt = ctx["format"]
    if fmt == "SPDX":
        return ("pass", "SPDX document declared (%s)" % ctx["sbom"].get("spdxVersion"),
                {"format": fmt, "declared": ctx["sbom"].get("spdxVersion")})
    if fmt == "CycloneDX":
        return ("pass", "CycloneDX document declared (%s)"
                % ctx["sbom"].get("specVersion", "unknown specVersion"),
                {"format": fmt, "declared": ctx["sbom"].get("specVersion")})
    return ("gap", "SBOM declares neither spdxVersion (SPDX) nor bomFormat "
            "(CycloneDX) — no machine-readable format declaration",
            {"format": None, "keys_present": sorted(k for k in ctx["sbom"])})


def _check_ntia_minimum(ctx: dict) -> tuple:
    res = ctx["ntia"]
    if res.get("status") != "OK":
        return ("not_evidence", "no scorable SBOM inventory: %s" % res.get("reason"),
                {"ntia_status": res.get("status"), "reason": res.get("reason")})
    total = len(ntia_check.ELEMENTS)
    pass_count = res.get("pass_count", 0)
    # "NTIA minimum elements met" means all 7 elements reach PASS (>=90% of
    # components, per ntia_check._status) -- not merely "no element below the
    # 60% FAIL floor" (that let a WARN-only, materially-incomplete document
    # through; see docs/BTS_SBOM_ANALYSIS.md appendix B, sectors.py:211).
    missing = [e["name"] for e in res.get("elements", []) if e.get("status") != "PASS"]
    ev = {"ntia_status": "OK", "format": res.get("format"),
          "component_count": res.get("component_count"),
          "total_score": res.get("total_score"), "grade": res.get("grade"),
          "pass_count": pass_count, "warn_count": res.get("warn_count"),
          "fail_count": res.get("fail_count"), "elements_total": total,
          "missing_elements": missing}
    if pass_count == total:
        return ("pass", "NTIA minimum elements: %d/%d elements PASS (score %.1f, grade %s)"
                % (pass_count, total, res.get("total_score", 0.0), res.get("grade")), ev)
    return ("gap", "NTIA minimum elements incomplete: %d/%d elements PASS (score %.1f, "
            "grade %s); missing/partial: %s" % (pass_count, total, res.get("total_score", 0.0),
                                                 res.get("grade"), ", ".join(missing)), ev)


def _check_supplier_coverage(ctx: dict) -> tuple:
    el = _ntia_element(ctx["ntia"], "supplier")
    if el is None:
        return ("not_evidence", "no scorable SBOM inventory: %s"
                % ctx["ntia"].get("reason"),
                {"ntia_status": ctx["ntia"].get("status")})
    ev = {"supplier_pct": el["compliance_pct"], "with_supplier": el["satisfied"],
          "components": ctx["ntia"].get("component_count"),
          "threshold_pct": _SUPPLIER_THRESHOLD_PCT, "basis": el["basis"]}
    if el["compliance_pct"] >= _SUPPLIER_THRESHOLD_PCT:
        return ("pass", "supplier declared for %d of %d components (%.1f%% >= %.0f%%)"
                % (el["satisfied"], ctx["ntia"].get("component_count", 0),
                   el["compliance_pct"], _SUPPLIER_THRESHOLD_PCT), ev)
    return ("gap", "supplier coverage %.1f%% is below the %.0f%% threshold "
            "(%d of %d components)" % (el["compliance_pct"], _SUPPLIER_THRESHOLD_PCT,
                                       el["satisfied"],
                                       ctx["ntia"].get("component_count", 0)), ev)


def _check_supplier_and_version(ctx: dict) -> tuple:
    verdict, detail, ev = _check_supplier_coverage(ctx)
    if verdict == "not_evidence":
        return verdict, detail, ev
    ver = _ntia_element(ctx["ntia"], "version")
    ev = dict(ev)
    ev["version_pct"] = ver["compliance_pct"] if ver else None
    if verdict != "pass":
        return verdict, detail, ev
    if ver and ver["compliance_pct"] >= _SUPPLIER_THRESHOLD_PCT:
        return ("pass", detail + "; version declared for %.1f%% of components"
                % ver["compliance_pct"], ev)
    return ("gap", "supplier coverage passes but version coverage is %.1f%% "
            "(below %.0f%%)" % (ver["compliance_pct"] if ver else 0.0,
                                _SUPPLIER_THRESHOLD_PCT), ev)


def _check_vex_present(ctx: dict) -> tuple:
    vex = ctx["vex"]
    if not isinstance(vex, dict):
        return ("not_evidence", "no VEX document provided — vulnerability handling "
                "cannot be assessed", {"vex_present": False})
    statements = vex.get("statements") or []
    vulnerabilities = vex.get("vulnerabilities") or []
    total = len(statements) + len(vulnerabilities)
    ev = {"vex_present": True, "statements": len(statements),
          "vulnerabilities": len(vulnerabilities), "total": total}
    if total >= 1:
        return ("pass", "VEX document present with %d statement(s)" % total, ev)
    return ("gap", "VEX document present but contains 0 statements", ev)


def _check_eol_coverage(ctx: dict) -> tuple:
    comps = ctx["components"]
    if not comps:
        return ("not_evidence", "SBOM lists no components — end-of-support "
                "coverage cannot be measured", {"components": 0})
    eol = ctx["eol"]
    if eol is None:                                   # fall back to the SBOM itself
        covered_names = [c for c in comps if _embedded_eol(c)]
        if not covered_names:
            return ("not_evidence", "no end-of-support input: no eol dict and no "
                    "eol/eos properties or annotations in the SBOM",
                    {"components": len(comps), "eol_source": None, "covered": 0})
        pct = round(len(covered_names) / len(comps) * 100, 1)
        ev = {"components": len(comps), "covered": len(covered_names),
              "eol_pct": pct, "eol_source": "sbom-properties"}
        return _eol_verdict(pct, ev, "SBOM-embedded eol/eos markers")
    covered = 0
    for comp in comps:                                # explicit eol dict is primary
        entry = eol.get(_component_name(comp)) or eol.get(comp.get("purl")) \
            or eol.get(comp.get("bom-ref")) or eol.get(comp.get("SPDXID"))
        if isinstance(entry, dict) and any(
                str(entry.get(k, "")).strip() for k in ("eol", "eos",
                                                        "end_of_support",
                                                        "end-of-support")):
            covered += 1
    pct = round(covered / len(comps) * 100, 1)
    ev = {"components": len(comps), "covered": covered, "eol_pct": pct,
          "eol_source": "eol-input"}
    return _eol_verdict(pct, ev, "eol input")


def _eol_verdict(pct: float, ev: dict, source_label: str) -> tuple:
    if pct >= 100.0:
        return ("pass", "end-of-support date present for %d of %d components "
                "(%.1f%%, %s)" % (ev["covered"], ev["components"], pct, source_label), ev)
    return ("gap", "end-of-support coverage %.1f%% (%d of %d components, %s) — "
            "a per-component date is expected" % (pct, ev["covered"], ev["components"],
                                                  source_label), ev)


def _check_rxswin_present(ctx: dict) -> tuple:
    targets = _properties_text(ctx["sbom"])
    hits = []
    for label, text in targets:
        if "rxswin" in text:
            hits.append(label)
    ev = {"locations_scanned": sorted({label for label, _ in targets}) or
          ["metadata.properties", "properties", "comment", "annotations"],
          "rxswin_found_in": sorted(set(hits))}
    if hits:
        return ("pass", "RXSWIN marker found in %s" % ", ".join(sorted(set(hits))), ev)
    return ("gap", "no rxswin marker found in document-level metadata/properties/"
            "annotations/comment", ev)


def _check_relationships_present(ctx: dict) -> tuple:
    sbom = ctx["sbom"]
    rels = [r for r in (sbom.get("relationships") or []) if isinstance(r, dict)]
    deps = [d for d in (sbom.get("dependencies") or []) if isinstance(d, dict)]
    ev = {"relationships": len(rels), "dependencies": len(deps), "format": ctx["format"]}
    if rels or deps:
        return ("pass", "dependency graph present (%d SPDX relationships / "
                "%d CycloneDX dependency entries)" % (len(rels), len(deps)), ev)
    return ("gap", "no relationships/dependencies in the SBOM — update impact "
            "analysis cannot be traced", ev)


def _check_creator_declared(ctx: dict) -> tuple:
    sbom = ctx["sbom"]
    ci = sbom.get("creationInfo") or {}
    creators = [c for c in (ci.get("creators") or []) if str(c).strip()]
    tools = (sbom.get("metadata") or {}).get("tools")
    if isinstance(tools, dict):                       # CycloneDX 1.5 shape
        tool_count = len(tools.get("components") or []) + len(tools.get("services") or [])
    else:
        tool_count = len(tools or [])
    ev = {"creators": creators, "metadata_tools": tool_count}
    if creators:
        return ("pass", "SBOM creator(s) declared: %s" % ", ".join(str(c) for c in creators), ev)
    if tool_count:
        return ("pass", "SBOM generator tool declared in metadata.tools (%d tool(s))"
                % tool_count, ev)
    return ("gap", "no creationInfo.creators (SPDX) and no metadata.tools "
            "(CycloneDX) — SBOM automation is not evidenced", ev)


def _check_doc_timestamp(ctx: dict) -> tuple:
    sbom = ctx["sbom"]
    created = (sbom.get("creationInfo") or {}).get("created")
    stamp = (sbom.get("metadata") or {}).get("timestamp")
    ev = {"creationInfo.created": created, "metadata.timestamp": stamp}
    if str(created or "").strip() not in _ABSENT:
        return ("pass", "document timestamp present (creationInfo.created)", ev)
    if str(stamp or "").strip() not in _ABSENT:
        return ("pass", "document timestamp present (metadata.timestamp)", ev)
    return ("gap", "no document timestamp (creationInfo.created / metadata.timestamp) "
            "— SBOM freshness/maintenance is not evidenced", ev)


def _check_license_known_ratio(ctx: dict) -> tuple:
    comps = ctx["components"]
    if not comps:
        return ("not_evidence", "SBOM lists no components — license inventory "
                "cannot be measured", {"components": 0})
    unknown = []
    for comp in comps:
        if not _license_known(comp):
            unknown.append(_component_name(comp))
    ratio = round(len(unknown) / len(comps), 4)
    ev = {"components": len(comps), "unknown_licenses": len(unknown),
          "noassertion_ratio": ratio, "unknown_components": sorted(unknown)[:20]}
    if ratio == 0.0:
        return ("pass", "all %d components carry a known license expression "
                "(0 NOASSERTION)" % len(comps), ev)
    return ("gap", "%d of %d components (%.1f%%) have NOASSERTION/unknown licenses"
            % (len(unknown), len(comps), ratio * 100), ev)


def _license_known(comp: dict) -> bool:
    """SPDX licenseDeclared/Concluded or CycloneDX licenses[] — known when a
    non-sentinel, non-empty value is present (reuse of the SPDX sentinel
    vocabulary from common.license.spdx)."""
    declared = str(comp.get("licenseDeclared") or comp.get("licenseConcluded")
                   or comp.get("license") or "").strip()
    if declared.upper() not in _UNKNOWN_LICENSE:
        return True
    for entry in comp.get("licenses") or []:
        if not isinstance(entry, dict):
            continue
        lic = entry.get("license") or {}
        expr = str(entry.get("expression", "")).strip()
        value = str(lic.get("id") or lic.get("name") or expr).strip()
        if value.upper() not in _UNKNOWN_LICENSE:
            return True
    return False


def _check_cra_readiness(ctx: dict) -> tuple:
    """CRA-overlap readiness = format declared AND end-of-support coverage
    measured at 100% (ISO 10218-1:2025 security-evaluation evidence can then
    be attached to the same component set)."""
    fmt_verdict, _fmt_detail, fmt_ev = _check_format_declared(ctx)
    comps = ctx["components"]
    if ctx["eol"] is None and not any(_embedded_eol(c) for c in comps):
        return ("not_evidence", "end-of-support input absent — CRA overlap "
                "readiness cannot be measured (format check: %s)" % fmt_verdict,
                {"format": fmt_ev.get("format"), "eol_source": None})
    eol_verdict, _eol_detail, eol_ev = _check_eol_coverage(ctx)
    ev = {"format": fmt_ev.get("format"), "eol_pct": eol_ev.get("eol_pct"),
          "covered": eol_ev.get("covered"), "components": eol_ev.get("components")}
    if fmt_verdict == "pass" and eol_verdict == "pass":
        return ("pass", "format declared and end-of-support date present for every "
                "component — CRA-overlap readiness evidenced", ev)
    return ("gap", "CRA-overlap readiness incomplete (format: %s, end-of-support: %s)"
            % (fmt_verdict, eol_verdict), ev)


# ── requirement profiles (data-driven) ───────────────────────────────────────
# Each def: {"id", "title", "basis", "check"} — the basis names the regulation
# clause the requirement maps to (REA 21 §3 sector matrix).

_BASIS_CRA = "EU Cyber Resilience Act (Regulation (EU) 2024/2847), Annex I — full application 2027-12-11"
_BASIS_FDA_524B = "FD&C Act §524B (2023-03) — premarket cyber-device submission"
_BASIS_FDA_2025 = ("FDA final guidance 'Cybersecurity in Medical Devices' (2025-06) — "
                   "support status + end-of-support date per component")
_BASIS_R155 = "UNECE R155 (CSMS) / R156 (SUMS) — full new-type coverage 2027"
_BASIS_DOD = "EO 14028 (2021-05-12) · CISA self-attestation common form · DoD Software Pathway"
_BASIS_FIN = "금융보안원 「금융분야 OSS 활용·관리 안내서」 · KISA SW 공급망 보안 가이드라인"
_BASIS_ROBOT = "KISA 로봇 보안모델·체크리스트 · ISO 10218-1:2025 · EU CRA overlap"
_BASIS_NTIA = "NTIA Minimum Elements for an SBOM (2021)"

SECTOR_PROFILES: Dict[str, List[Dict[str, str]]] = {
    "cra": [
        {"id": "CRA-01", "title": "Machine-readable SBOM format declared (SPDX/CycloneDX)",
         "basis": _BASIS_CRA, "check": "format_declared"},
        {"id": "CRA-02", "title": "Component inventory complete (NTIA minimum elements)",
         "basis": _BASIS_CRA + " · " + _BASIS_NTIA, "check": "ntia_minimum"},
        {"id": "CRA-03", "title": "Supplier coverage per component (>=80%)",
         "basis": _BASIS_CRA + " · " + _BASIS_NTIA, "check": "supplier_coverage"},
        {"id": "CRA-04", "title": "Vulnerability-handling evidence (VEX statements)",
         "basis": _BASIS_CRA + " — Art. 13-14 vulnerability handling; reporting from 2026-09-11",
         "check": "vex_present"},
        {"id": "CRA-05", "title": "End-of-support dates declared per component",
         "basis": _BASIS_CRA + " — support-period disclosure for the product and its components",
         "check": "eol_coverage"},
    ],
    "fda": [
        {"id": "FDA-01", "title": "Machine-readable SBOM (NTIA-cited SPDX/CycloneDX)",
         "basis": _BASIS_FDA_524B, "check": "format_declared"},
        {"id": "FDA-02", "title": "NTIA minimum elements satisfied",
         "basis": _BASIS_FDA_524B + " · " + _BASIS_NTIA, "check": "ntia_minimum"},
        {"id": "FDA-03", "title": "Supplier declared per component",
         "basis": _BASIS_FDA_524B + " · " + _BASIS_NTIA, "check": "supplier_coverage"},
        {"id": "FDA-04", "title": "Support status + end-of-support date per component (2025-06 NEW)",
         "basis": _BASIS_FDA_2025, "check": "eol_coverage"},
        {"id": "FDA-05", "title": "Known vulnerabilities documented (VEX statements)",
         "basis": _BASIS_FDA_524B, "check": "vex_present"},
    ],
    "r155": [
        {"id": "R155-01", "title": "RXSWIN identification present in SBOM metadata",
         "basis": _BASIS_R155 + " — RXSWIN software identification", "check": "rxswin_present"},
        {"id": "R155-02", "title": "Component inventory (NTIA minimum elements)",
         "basis": _BASIS_R155 + " · " + _BASIS_NTIA, "check": "ntia_minimum"},
        {"id": "R155-03", "title": "Vulnerability monitoring evidence (VEX statements)",
         "basis": _BASIS_R155 + " — CSMS supply-chain vulnerability monitoring",
         "check": "vex_present"},
        {"id": "R155-04", "title": "Update impact-analysis evidence (dependency graph)",
         "basis": _BASIS_R155 + " — SUMS update impact analysis", "check": "relationships_present"},
    ],
    "dod": [
        {"id": "DOD-01", "title": "SBOM automation evidenced (generator/creator tool declared)",
         "basis": _BASIS_DOD + " — SBOM automation", "check": "creator_declared"},
        {"id": "DOD-02", "title": "VEX triage evidence (statements present)",
         "basis": _BASIS_DOD + " · CISA VEX companion guidance", "check": "vex_present"},
        {"id": "DOD-03", "title": "Supplier fields declared per component",
         "basis": _BASIS_DOD + " · " + _BASIS_NTIA, "check": "supplier_coverage"},
        {"id": "DOD-04", "title": "NTIA minimum elements (CISA attestation form basis)",
         "basis": _BASIS_DOD + " · " + _BASIS_NTIA, "check": "ntia_minimum"},
    ],
    "finance": [
        {"id": "FIN-01", "title": "License inventory completeness (0 NOASSERTION)",
         "basis": _BASIS_FIN + " — OSS 라이선스 고지·관리", "check": "license_known_ratio"},
        {"id": "FIN-02", "title": "CVE matching coverage (VEX document present)",
         "basis": _BASIS_FIN + " — 취약점 관리", "check": "vex_present"},
        {"id": "FIN-03", "title": "SBOM maintenance evidence (document timestamp)",
         "basis": _BASIS_FIN + " — SBOM 관리·갱신", "check": "doc_timestamp"},
        {"id": "FIN-04", "title": "Supplier + version fields declared (NTIA)",
         "basis": _BASIS_FIN + " · " + _BASIS_NTIA, "check": "supplier_and_version"},
    ],
    "robot": [
        {"id": "ROB-01", "title": "Component vulnerability check (VEX statements)",
         "basis": _BASIS_ROBOT + " — 구성요소 취약점 점검", "check": "vex_present"},
        {"id": "ROB-02", "title": "Component inventory (NTIA minimum elements)",
         "basis": _BASIS_ROBOT + " · " + _BASIS_NTIA, "check": "ntia_minimum"},
        {"id": "ROB-03", "title": "CRA-overlap readiness (format + end-of-support coverage)",
         "basis": _BASIS_ROBOT + " — ISO 10218-1:2025 security-evaluation mapping onto CRA Annex I",
         "check": "cra_readiness"},
        {"id": "ROB-04", "title": "Machine-readable SBOM format declared",
         "basis": _BASIS_ROBOT + " — machine-readable component documentation",
         "check": "format_declared"},
    ],
}

_CHECKS = {
    "format_declared": _check_format_declared,
    "ntia_minimum": _check_ntia_minimum,
    "supplier_coverage": _check_supplier_coverage,
    "supplier_and_version": _check_supplier_and_version,
    "vex_present": _check_vex_present,
    "eol_coverage": _check_eol_coverage,
    "rxswin_present": _check_rxswin_present,
    "relationships_present": _check_relationships_present,
    "creator_declared": _check_creator_declared,
    "doc_timestamp": _check_doc_timestamp,
    "license_known_ratio": _check_license_known_ratio,
    "cra_readiness": _check_cra_readiness,
}

_HONESTY = ("Every verdict is computed only from the supplied SBOM/VEX/EOL documents; "
            "a requirement whose evidence is absent is not_evidence — never an inferred "
            "or fabricated pass. Measured percentages and counts are in each row's "
            "evidence so a reviewer can apply a stricter bar.")


# ── public API ────────────────────────────────────────────────────────────────

def sector_report(sector: str, sbom: dict, vex: dict | None = None,
                  eol: dict | None = None) -> dict:
    """Build the regulatory report for ``sector`` against real documents.

    ``sbom`` — a parsed SPDX 2.3 or CycloneDX 1.5 document (dict).
    ``vex``  — an optional VEX document (OpenVEX or CycloneDX-VEX shape).
    ``eol``  — optional {component: {"eol": date, "status": ...}} map; when
               absent, eol/eos markers embedded in the SBOM are used instead.

    Returns the ``bts-sector-report-1`` document; raises ValueError for an
    unknown sector or a non-dict sbom.
    """
    if sector not in SECTORS:
        raise ValueError("unknown sector %r; valid sectors: %s"
                         % (sector, ", ".join(SECTORS)))
    if not isinstance(sbom, dict):
        raise ValueError("sbom must be a parsed SPDX/CycloneDX document (dict), got %s"
                         % type(sbom).__name__)
    if eol is not None and not isinstance(eol, dict):
        raise ValueError("eol must be a {component: {'eol': ...}} dict or None")

    ctx = {"sbom": sbom, "vex": vex, "eol": eol,
           "format": _detect_format(sbom),
           "components": _components(sbom),
           "ntia": _ntia(sbom)}

    rows: List[Dict[str, Any]] = []
    for req in SECTOR_PROFILES[sector]:
        verdict, detail, evidence = _CHECKS[req["check"]](ctx)
        rows.append({"id": req["id"], "title": req["title"], "basis": req["basis"],
                     "verdict": verdict, "detail": detail, "evidence": evidence})
    rows.sort(key=lambda r: r["id"])

    summary = {"pass": sum(1 for r in rows if r["verdict"] == "pass"),
               "gap": sum(1 for r in rows if r["verdict"] == "gap"),
               "not_evidence": sum(1 for r in rows if r["verdict"] == "not_evidence")}
    return {"schema": SCHEMA, "sector": sector, "sector_title": SECTOR_TITLES[sector],
            "requirements": rows,
            "verdict": "ready" if summary["gap"] == 0 and summary["not_evidence"] == 0
            else "gaps",
            "summary": summary, "honesty": _HONESTY}


# ── evidence (ADR-0006 convention: latest + append-only timestamped history) ──

_EVIDENCE_DIR = Path.cwd() / "bts_sbom_evidence"


def write_evidence(report: dict, out_dir=None) -> dict:
    """Persist a sector report as evidence: ``sector_<name>_latest.json`` plus
    an append-only timestamped history copy under ``history/`` (ADR-0006 —
    no silent overwrite).  Returns both paths."""
    if not isinstance(report, dict) or report.get("schema") != SCHEMA:
        raise ValueError("write_evidence expects a bts-sector-report-1 document")
    sector = str(report.get("sector", ""))
    if sector not in SECTORS:
        raise ValueError("report sector %r is not one of %s" % (sector, ", ".join(SECTORS)))

    doc = {"schema": report.get("schema"), "sector": sector,
           "sector_title": report.get("sector_title"), "verdict": report.get("verdict"),
           "summary": report.get("summary", {}), "requirements": report.get("requirements", []),
           "honesty": report.get("honesty"),
           "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}

    out_dir = Path(out_dir) if out_dir else _EVIDENCE_DIR
    hist_dir = out_dir / "history"
    hist_dir.mkdir(parents=True, exist_ok=True)
    text = json.dumps(doc, ensure_ascii=False, indent=1)
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    hist = hist_dir / ("sector_%s_%s.json" % (sector, stamp))
    n = 0
    while hist.exists():                      # append-only even within one second
        n += 1
        hist = hist_dir / ("sector_%s_%s_%d.json" % (sector, stamp, n))
    latest = out_dir / ("sector_%s_latest.json" % sector)
    latest.write_text(text, encoding="utf-8")
    hist.write_text(text, encoding="utf-8")
    return {"latest": str(latest), "history": str(hist)}
