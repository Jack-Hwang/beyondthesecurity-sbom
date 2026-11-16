"""Industry coverage: the five target industries + EU CRA + robotics, over one SBOM/VEX evidence set.

  defense     -> bts_sbom sector "dod"      (EO 14028, CISA attestation, DoD Software Pathway)
  automotive  -> bts_sbom sector "r155"     (UNECE R155 CSMS / R156 SUMS)
  medical     -> bts_sbom sector "fda"      (FD&C 524B + 2025-06 guidance)
  finance     -> bts_sbom sector "finance"  (financial OSS management guidance)
  cra / robot -> bts_sbom sectors "cra" / "robot"
  maritime    -> implemented HERE (the core has no maritime profile): IACS UR E26/E27 SBOM-relevant evidence checks.

Honesty: every verdict is computed only from the supplied documents; absent evidence is ``not_evidence`` (never a pass).
The maritime profile is a DRAFT checklist pending review by a maritime-cyber expert - it is evidence-gathering
support, not an IACS conformity assessment (``draft=True`` in the report).
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from . import engine

INDUSTRY_TO_CORE = {"defense": "dod", "automotive": "r155", "medical": "fda", "finance": "finance", "cra": "cra", "robot": "robot"}
INDUSTRIES = ("defense", "automotive", "medical", "finance", "maritime", "cra", "robot")
_HONESTY = ("Every verdict is computed only from the supplied SBOM/VEX/EOL documents; a requirement whose evidence is absent "
            "is not_evidence - never an inferred or fabricated pass.")
_BASIS = ("IACS UR E26 (ship cyber resilience) / UR E27 (onboard systems and equipment), applicable to new-builds contracted "
          "on or after 2024-07-01; IMO MSC.428(98); IEC 62443-4-1/4-2 references - DRAFT checklist pending maritime-expert review")


def _components(doc: Dict[str, Any]) -> List[Dict[str, Any]]:
    return list(doc.get("components") or [])


def _known(c: Dict[str, Any]) -> bool:
    for e in c.get("licenses") or []:
        v = (e.get("license") or {}).get("id") or (e.get("license") or {}).get("name") or e.get("expression")
        if v and str(v).upper() not in ("", "NOASSERTION", "NONE", "UNKNOWN"):
            return True
    return False


def maritime_report(doc: Dict[str, Any], vex: Optional[Dict[str, Any]] = None, eol: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    comps = _components(doc)
    n = len(comps)
    rows: List[Dict[str, Any]] = []

    def row(i: str, title: str, verdict: str, detail: str, ev: Dict[str, Any]) -> None:
        rows.append({"id": i, "title": title, "basis": _BASIS, "verdict": verdict, "detail": detail, "evidence": ev})

    fmt = "CycloneDX" if doc.get("bomFormat") == "CycloneDX" else ("SPDX" if doc.get("spdxVersion") else None)
    row("MAR-01", "Machine-readable software inventory declared (SPDX/CycloneDX)", "pass" if fmt else "gap",
        "%s document declared" % fmt if fmt else "no machine-readable format declaration", {"format": fmt})
    if n == 0:
        row("MAR-02", "Name + version recorded for every software component", "not_evidence", "SBOM lists no components", {"components": 0})
    else:
        nv = sum(1 for c in comps if c.get("name") and c.get("version"))
        row("MAR-02", "Name + version recorded for every software component", "pass" if nv == n else "gap",
            "%d of %d components carry name and version" % (nv, n), {"components": n, "with_name_version": nv})
    if n == 0:
        row("MAR-03", "Supplier identified per component (>=80%)", "not_evidence", "SBOM lists no components", {"components": 0})
    else:
        sup = sum(1 for c in comps if (c.get("supplier") or {}).get("name") or c.get("publisher") or c.get("author"))
        pct = round(100.0 * sup / n, 1)
        row("MAR-03", "Supplier identified per component (>=80%)", "pass" if pct >= 80 else "gap",
            "%d of %d components (%.1f%%) name a supplier" % (sup, n, pct), {"components": n, "with_supplier": sup, "pct": pct})
    if not isinstance(vex, dict):
        row("MAR-04", "Vulnerability-management evidence (VEX statements)", "not_evidence", "no VEX document provided", {"vex_present": False})
    else:
        k = len(vex.get("statements") or [])
        row("MAR-04", "Vulnerability-management evidence (VEX statements)", "pass" if k else "gap",
            "VEX document with %d statement(s)" % k, {"vex_present": True, "statements": k})
    vulns = doc.get("vulnerabilities") or []
    if not vulns and not isinstance(vex, dict):
        row("MAR-05", "No unaddressed critical/high vulnerabilities", "not_evidence", "no vulnerability data supplied", {"vulnerabilities": 0})
    else:
        closed = set()
        for s in (vex or {}).get("statements") or []:
            if s.get("status") in ("fixed", "not_affected"):
                closed.add((s.get("vulnerability") or {}).get("name"))
        open_hi = [v for v in vulns if v.get("id") not in closed and any(r.get("severity") in ("critical", "high") for r in v.get("ratings") or [])]
        row("MAR-05", "No unaddressed critical/high vulnerabilities", "pass" if not open_hi else "gap",
            "%d critical/high finding(s) without a fixed/not_affected statement" % len(open_hi),
            {"open_critical_high": len(open_hi), "ids": sorted({v["id"] for v in open_hi})[:20]})
    if not isinstance(eol, dict):
        row("MAR-06", "Support status / end-of-support per component", "not_evidence", "no end-of-support input provided", {"eol_present": False})
    else:
        have = sum(1 for c in comps if c.get("name") in eol)
        pct = round(100.0 * have / n, 1) if n else 0.0
        row("MAR-06", "Support status / end-of-support per component", "pass" if n and have == n else "gap",
            "%d of %d components (%.1f%%) have end-of-support data" % (have, n, pct), {"components": n, "with_eol": have, "pct": pct})
    if n == 0:
        row("MAR-07", "License inventory complete", "not_evidence", "SBOM lists no components", {"components": 0})
    else:
        unk = [c["name"] for c in comps if not _known(c)]
        row("MAR-07", "License inventory complete", "pass" if not unk else "gap",
            "%d of %d components have no known license" % (len(unk), n), {"components": n, "unknown": len(unk), "sample": sorted(unk)[:15]})
    summary = {k: sum(1 for r in rows if r["verdict"] == k) for k in ("pass", "gap", "not_evidence")}
    return {"schema": "bts_sbom_app-sector-report-1", "sector": "maritime", "sector_title": "IACS UR E26/E27 SBOM evidence (DRAFT)",
            "draft": True, "requirements": rows, "summary": summary,
            "verdict": "ready" if summary["gap"] == 0 and summary["not_evidence"] == 0 else "gaps", "honesty": _HONESTY}


def industry_reports(doc: Dict[str, Any], vex: Optional[Dict[str, Any]] = None, eol: Optional[Dict[str, Any]] = None,
                     industries: Iterable[str] = INDUSTRIES) -> Dict[str, Dict[str, Any]]:
    core = engine._import_core()
    out: Dict[str, Dict[str, Any]] = {}
    for ind in industries:
        if ind == "maritime":
            out[ind] = maritime_report(doc, vex, eol)
        elif ind in INDUSTRY_TO_CORE:
            rep = core.sector_report(INDUSTRY_TO_CORE[ind], doc, vex=vex, eol=eol)
            rep["industry"] = ind
            out[ind] = rep
    return out


def matrix(reports: Dict[str, Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [{"industry": k, "title": r.get("sector_title"), "verdict": r.get("verdict"), **(r.get("summary") or {}),
             "draft": bool(r.get("draft"))} for k, r in reports.items()]
