"""Remediation planning: the lowest version of each package that clears ALL its advisories, verified against OSV.

plan()   one plan per (ecosystem, package, installed version): safe = max of the per-advisory fixed versions
         (each taken from the range that actually contains the installed version).
verify() re-queries OSV for the candidate (package, safe) itself; if it is still affected the plan bumps to the
         next fix and repeats (<= max_rounds). Outcomes are recorded, never assumed:
           verification.clean = True   OSV answered and knows no advisory for the candidate
           verification.clean = False  advisories remain (residual ids listed; an unfixable one stops the loop)
           verification.clean = None   OSV could not be reached - NOT treated as clean
"""
from __future__ import annotations

from typing import Any, Dict, List

from . import engine, osv, versions

_SEV = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0, "NONE": 0}


def plan(components: List[Dict[str, Any]], vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    comp_by = {(c["ecosystem"].lower(), engine._canon(c["ecosystem"], c["name"]), c["version"]): c for c in components}
    groups: Dict[tuple, List[Dict[str, Any]]] = {}
    for v in vulns:
        groups.setdefault((v["ecosystem"].lower(), engine._canon(v["ecosystem"], v["package"]), v["version"]), []).append(v)
    plans: List[Dict[str, Any]] = []
    for key, vs in groups.items():
        c = comp_by.get(key) or {}
        fixes = [v["fixed_version"] for v in vs if v.get("fixed_version")]
        safe = versions.max_version(fixes)
        cur = vs[0]["version"]
        clears = sorted({v["id"] for v in vs if v.get("fixed_version")})
        unc = sorted({v["id"] for v in vs if not v.get("fixed_version")})
        mj = bool(safe) and versions.major(safe) != versions.major(cur)
        plans.append({
            "component": vs[0]["package"], "ecosystem": vs[0]["ecosystem"], "current_version": cur,
            "safe_version": safe, "status": "upgrade" if safe else "no_fix", "clears": clears, "uncleared": unc,
            "cve_count": len(vs), "major_bump": mj, "breaking_risk": "high" if mj else "low",
            "relationship": c.get("relationship") or "", "files": c.get("files") or sorted({f for v in vs for f in v["files"]}),
            "max_severity": max((v["severity"] for v in vs), key=lambda s: _SEV.get(s, 0)),
            "max_cvss": max([v["cvss"] for v in vs if v.get("cvss") is not None] or [None]) if any(
                v.get("cvss") is not None for v in vs) else None,
            "verification": {"clean": None, "method": "not_run", "rounds": 0, "residual": []}})
    plans.sort(key=lambda p: (-_SEV.get(p["max_severity"], 0), -p["cve_count"], p["component"].lower()))
    return plans


def verify(plans: List[Dict[str, Any]], max_rounds: int = 3) -> List[Dict[str, Any]]:
    active = [p for p in plans if p.get("safe_version")]
    for p in active:
        p["verification"] = {"clean": None, "method": "osv_recheck", "rounds": 0, "residual": [], "bumped_from": None}
    for rnd in range(1, max_rounds + 1):
        pend = [p for p in active if p["verification"]["clean"] is None and not p["verification"].get("stopped")]
        if not pend:
            break
        res = osv.query_batch([(p["ecosystem"], p["component"], p["safe_version"]) for p in pend])
        need: Dict[int, Dict[str, Any]] = {}            # keyed by plan identity: two plans (e.g. lodash 4.13.1 and 4.17.11)
        for p in pend:                                  # can share the same package and candidate version
            ids = res.get((p["ecosystem"], p["component"], p["safe_version"]))
            p["verification"]["rounds"] = rnd
            if ids is None:                              # query failed -> stay unverified, stop retrying this plan
                p["verification"]["stopped"] = "osv_unreachable"
            elif not ids:
                p["verification"]["clean"] = True
            else:
                need[id(p)] = {"plan": p, "ids": ids}
        if not need:
            continue
        docs = osv.get_vulns([i for n in need.values() for i in n["ids"]])
        for n in need.values():
            p = n["plan"]
            bump: List[str] = []
            residual: List[str] = []
            for vid in n["ids"]:
                doc = docs.get(vid)
                if not doc:
                    residual.append(vid)
                    continue
                fx, hit = engine.fixed_versions(doc, p["component"], p["ecosystem"], p["safe_version"])
                if not hit:
                    continue                               # advisory id listed but this version is outside its ranges
                (bump.extend(fx) if fx else residual.append(vid))
            nv = versions.max_version(bump)
            if residual:
                p["verification"].update(clean=False, residual=sorted(set(residual)))
            if nv and versions.compare(nv, p["safe_version"]) > 0:
                p["verification"]["bumped_from"] = p["verification"].get("bumped_from") or p["safe_version"]
                p["safe_version"] = nv
                p["major_bump"] = versions.major(nv) != versions.major(p["current_version"])
                p["breaking_risk"] = "high" if p["major_bump"] else "low"
                if not residual:
                    p["verification"]["clean"] = None       # re-check the new candidate next round
            elif not residual:
                p["verification"]["clean"] = True           # ids listed but none applies to this version
    for p in active:
        if p["verification"]["clean"] is None and p["verification"].get("rounds", 0) >= max_rounds \
                and not p["verification"].get("stopped"):
            p["verification"]["stopped"] = "max_rounds"
    return plans


def summary(plans: List[Dict[str, Any]]) -> Dict[str, Any]:
    up = [p for p in plans if p["status"] == "upgrade"]
    return {"plans": len(plans), "upgrade": len(up), "no_fix": len(plans) - len(up),
            "verified_clean": sum(1 for p in up if p["verification"]["clean"] is True),
            "verified_dirty": sum(1 for p in up if p["verification"]["clean"] is False),
            "unverified": sum(1 for p in up if p["verification"]["clean"] is None),
            "major_bumps": sum(1 for p in up if p["major_bump"])}
