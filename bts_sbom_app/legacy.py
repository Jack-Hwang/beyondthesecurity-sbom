"""Legacy / EOL component assessment (task 24, brief 2) - stdlib only.

Lecture-facing question: which dependency is a legacy you cannot simply upgrade? Two deterministic signals:
  * EOL - is the component's version cycle past its end-of-life date (endoflife.date, or the UNVERIFIED
    embedded table offline; an unresolvable mapping/version is "unknown", never "supported");
  * no_upstream_fix - OSV has no fixed version for the component's advisories (status no_fix, >= 1 advisory).
We do NOT call a package abandoned. Rows sort by risk then name; identical input yields identical bytes.
"""
from __future__ import annotations

import re
import threading
from typing import Any, Dict, List, Optional

from . import arch

SCHEMA = "bts-sbom.legacy.v1"
DISCLAIMER = "엔지니어링 신호이며 법률 자문이 아닙니다 — 법무 확인이 필요합니다 (engineering signal, not legal advice)"

SITE_THRESHOLD = 10                                        # (task 26 reads its own constant; kept here for the shared idea)

# ONLY these 5 seeds - adding entries from memory is forbidden by the brief. Slug/cycle notation may differ
# from endoflife.date reality; when it does the lookup must come back unknown, never supported (appendix B-1).
PRODUCTS: List[Dict[str, str]] = [
    {"ecosystem": "PyPI", "name": "django", "product": "django", "cycle_rule": "major.minor"},
    {"ecosystem": "npm", "name": "@angular/core", "product": "angular", "cycle_rule": "major"},
    {"ecosystem": "Maven", "name": "org.springframework.boot:spring-boot", "product": "spring-boot", "cycle_rule": "major.minor"},
    {"ecosystem": "RubyGems", "name": "rails", "product": "rails", "cycle_rule": "major.minor"},
    {"ecosystem": "Packagist", "name": "laravel/framework", "product": "laravel", "cycle_rule": "major"},
]

_LOCK = threading.Lock()
_LOAD_ERRORS: List[str] = []


def load_products() -> List[Dict[str, str]]:
    """Validated copy of the product map; an entry without product/cycle_rule is rejected (0 loaded)."""
    out: List[Dict[str, str]] = []
    _LOAD_ERRORS.clear()
    for entry in PRODUCTS:
        if not entry.get("product") or not entry.get("cycle_rule"):
            _LOAD_ERRORS.append("rejected entry without product/cycle_rule: %s" % (entry.get("name") or entry.get("ecosystem")))
            continue
        if entry["cycle_rule"] not in ("major", "major.minor"):
            _LOAD_ERRORS.append("rejected entry with bad cycle_rule: %s" % entry.get("name"))
            continue
        out.append(dict(entry))
    return out


def extract_cycle(version: str, rule: str) -> str:
    """major or major.minor cycle from a version, via the versions parser; "" when unparseable."""
    m = re.match(r"^v?(\d+)(?:\.(\d+))?", str(version or "").strip())
    if not m:
        return ""
    if rule == "major":
        return m.group(1) or ""
    return ("%s.%s" % (m.group(1), m.group(2) or "0")) if m.group(2) else m.group(1)


def _lookup(eco: str, name: str, version: str, online: bool) -> Optional[Dict[str, Any]]:
    for entry in load_products():
        if entry["ecosystem"] == eco and entry["name"].lower() == str(name).lower():
            cycle = extract_cycle(version, entry["cycle_rule"])
            if not cycle:
                return {"status": "unknown", "eol_date": "", "source": "version-unparseable", "product": entry["product"], "cycle": ""}
            res = arch.eol_lookup(entry["product"], cycle, online=online)
            res.setdefault("status", "unknown")
            res["product"], res["cycle"] = entry["product"], cycle
            return res
    return None


def _risk(eol_status: str, no_upstream_fix: bool, max_severity: str, advisories: int) -> str:
    sev_rank = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
    if eol_status == "eol":
        return "high"
    if no_upstream_fix:
        return "high" if sev_rank.get(max_severity, 0) >= 3 else "medium"
    if eol_status == "supported":
        return "low"
    if advisories:
        return "medium"                                   # unknown EOL but findings exist - never "low"
    return "unknown"


def assess(components: List[Dict[str, Any]], plans: List[Dict[str, Any]], *, online: bool = False,
           today: Optional[str] = None, policy: Optional[Dict[str, Any]] = None, computed_on_read: bool = False) -> Dict[str, Any]:
    plan_by_comp: Dict[str, Dict[str, Any]] = {}
    for p in plans or []:
        plan_by_comp[str(p.get("component")).lower()] = p
    rows: List[Dict[str, Any]] = []
    counts = {"high": 0, "medium": 0, "low": 0, "unknown": 0, "eol": 0, "no_upstream_fix": 0}
    findings: List[Dict[str, str]] = []
    tolerance = str((policy or {}).get("eol_tolerance") or "")
    for c in components or []:
        name, ver = str(c.get("name")), str(c.get("version"))
        plan = plan_by_comp.get(name.lower())
        no_fix = bool(plan) and plan.get("status") == "no_fix" and int(plan.get("cve_count") or 0) >= 1
        max_sev = str((plan or {}).get("max_severity") or "")
        advisories = int((plan or {}).get("cve_count") or 0)
        eol = _lookup(str(c.get("ecosystem")), name, ver, online=online)
        risk = _risk((eol or {}).get("status", "unknown"), no_fix, max_sev, advisories)
        reasons: List[str] = []
        if (eol or {}).get("status") == "eol":
            reasons.append("EOL: the version cycle ended %s" % (eol.get("eol_date") or "(date unknown)"))
        if (eol or {}).get("status") == "unknown":
            reasons.append("EOL unknown: no verified mapping for this product/cycle")
        if no_fix:
            reasons.append("OSV 에 수정 버전이 없음 (no fixed version in OSV)")
        if (eol or {}).get("source", "").find("UNVERIFIED") >= 0:
            reasons.append("source is the embedded table (UNVERIFIED)")
        counts[risk] = counts.get(risk, 0) + 1
        if (eol or {}).get("status") == "eol":
            counts["eol"] += 1
        if no_fix:
            counts["no_upstream_fix"] += 1
            if tolerance == "fail":
                findings.append({"component": name, "level": "HIGH", "kind": "no_upstream_fix"})
        if (eol or {}).get("status") == "eol":
            if tolerance == "fail":
                findings.append({"component": name, "level": "HIGH", "kind": "eol"})
            elif tolerance == "review":
                findings.append({"component": name, "level": "MEDIUM", "kind": "eol"})
        rows.append({"component": name, "version": ver, "ecosystem": c.get("ecosystem"),
                     "eol": eol, "no_upstream_fix": no_fix, "advisories": advisories, "max_severity": max_sev,
                     "risk": risk, "reasons": reasons})
    rank = {"high": 0, "medium": 1, "low": 2, "unknown": 3}
    rows.sort(key=lambda r: (rank.get(r["risk"], 9), str(r["component"]).lower()))
    return {"schema": SCHEMA, "disclaimer": DISCLAIMER, "computed_on_read": bool(computed_on_read),
            "rows": rows, "summary": counts, "findings": findings}
