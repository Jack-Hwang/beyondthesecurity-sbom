"""Adapter between a BTS-SBOM project record and the platform's open-source security screen (``web/``).

``web/sca_app.js`` is a pure renderer (``ScaApp.render(mount, report, opts)``); this module builds the ``report`` it expects
from a record written by ``pipeline.persist`` and the extra pane data the page shows (architecture, industry reports, plans,
patch, history). Pure functions, no I/O, so everything here is unit-testable.

Honesty rule: a field BTS-SBOM does not compute (CISA KEV, EPSS, reachability, per-finding priority, VEX status) is LEFT OUT of
the report - never filled with a default - so the renderer shows it as absent instead of as "not exploited" / "score 0".
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, List, Optional

from . import licenses

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")
TRIAGE_STATUSES = ("open", "accepted", "wontfix", "false-positive", "fixed")
TRIAGE_MAX_ENTRIES = 5000
TRIAGE_MAX_KEY = 200
TRIAGE_MAX_NOTE = 500
_GPL_FAMILY = ("strong-copyleft", "network-copyleft")


def _sev(v: Any) -> str:
    s = str(v or "UNKNOWN").upper()
    return s if s in SEVERITIES else "UNKNOWN"


def _ids(v: Dict[str, Any]) -> Dict[str, Any]:
    """(cve, primary id, aliases) of one finding. The CVE, when there is one, is the label users search for."""
    every = [str(v.get("id") or "")] + [str(x) for x in (v.get("aliases") or [])] + [str(x) for x in (v.get("osv_ids") or [])]
    every = [x for x in dict.fromkeys(every) if x]
    cve = next((x for x in every if x.upper().startswith("CVE-")), "")
    other = next((x for x in every if not x.upper().startswith("CVE-")), "")
    primary = other or cve
    return {"cve": cve, "id": primary, "aliases": [x for x in every if x not in (cve, primary)]}


def _advisory_url(v: Dict[str, Any]) -> str:
    refs = [str(r) for r in (v.get("references") or []) if str(r).startswith(("http://", "https://"))]
    for r in refs:
        if "advisories" in r or "nvd.nist.gov" in r or "osv.dev" in r:
            return r
    return refs[0] if refs else ""


def triage_key(f: Dict[str, Any]) -> str:
    return str(f.get("cve") or f.get("id") or "")


def finding(v: Dict[str, Any], triage: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    ids = _ids(v)
    summary = str(v.get("summary") or "")
    if v.get("malicious"):
        summary = "[MALICIOUS PACKAGE] " + summary
    f: Dict[str, Any] = {"cve": ids["cve"], "id": ids["id"], "aliases": ids["aliases"], "name": v.get("package"), "version": v.get("version"),
                         "severity": _sev(v.get("severity")), "summary": summary, "ecosystem": v.get("ecosystem"),
                         "ref": v.get("purl") or "", "location": (v.get("files") or [""])[0], "url": _advisory_url(v),
                         "fixed": v.get("fixed_version") or ""}
    if v.get("cvss") is not None:
        f["score"] = v["cvss"]
    t = (triage or {}).get(triage_key(f))
    if t:
        f["triage_status"], f["triage_note"] = t.get("status", "open"), t.get("note", "")
    return f


def _by_package(vulns: List[Dict[str, Any]]) -> Dict[tuple, List[Dict[str, Any]]]:
    out: Dict[tuple, List[Dict[str, Any]]] = {}
    for v in vulns:
        out.setdefault((str(v.get("package") or "").lower(), v.get("version")), []).append(v)
    return out


def _worst(vs: List[Dict[str, Any]]) -> str:
    return min((_sev(v.get("severity")) for v in vs), key=SEVERITIES.index) if vs else ""


def dep_tree(rec: Dict[str, Any]) -> Dict[str, Any]:
    """Flat per-manifest dependency list (BTS-SBOM records components and the manifests they come from, not parent edges)."""
    vmap = _by_package(rec.get("vulns") or [])
    plans = {str(p.get("component") or "").lower(): p for p in rec.get("plans") or [] if p.get("status") == "upgrade"}
    manifests: Dict[str, Dict[str, Any]] = {}
    for c in rec.get("components") or []:
        vs = vmap.get((str(c.get("name") or "").lower(), c.get("version")), [])
        sevs = Counter(_sev(v.get("severity")) for v in vs)
        for path in c.get("files") or ["(unknown manifest)"]:
            m = manifests.setdefault(path, {"path": path, "ecosystems": set(), "total": 0, "direct": 0, "transitive": 0, "unknown": 0,
                                            "vulnerable": 0, "max_depth": 0, "children": []})
            rel = c.get("relationship") or "unknown"
            m["ecosystems"].add(c.get("ecosystem") or "")
            m["total"] += 1
            m["direct" if rel == "direct" else "transitive" if rel == "transitive" else "unknown"] += 1
            m["vulnerable"] += 1 if vs else 0
            m["max_depth"] = max(m["max_depth"], int(c.get("depth") or 0))
            m["children"].append({"name": c.get("name"), "version": c.get("version"), "ecosystem": c.get("ecosystem"), "relationship": rel,
                                  "depth": c.get("depth") or 0, "parents": [], "license": c.get("license") or "", "location": path,
                                  "vuln_count": len(vs), "severities": dict(sevs), "worst_severity": _worst(vs),
                                  "fixed_latest": (plans.get(str(c.get("name") or "").lower()) or {}).get("safe_version") or "",
                                  "children": []})
    out = []
    for m in sorted(manifests.values(), key=lambda x: x["path"]):
        m["ecosystems"] = sorted(e for e in m["ecosystems"] if e)
        out.append(m)
    return {"manifests": out}


def _licence_blocks(rec: Dict[str, Any]) -> Dict[str, Any]:
    comps = rec.get("components") or []
    lic = rec.get("license") or {}
    stats = lic.get("stats") or {}
    tree = lic.get("tree") or {}
    resolved = int(stats.get("resolved") or sum(1 for c in comps if c.get("license")))
    total = int(stats.get("total") or len(comps))
    cats = Counter(str(c.get("license_category") or "unknown") for c in comps)
    by_lic: Dict[str, Dict[str, Any]] = {}
    for f in tree.get("license_files") or []:
        if not f.get("detected") or not f.get("license"):
            continue
        e = by_lic.setdefault(f["license"], {"license": f["license"], "category": licenses.category(f["license"]), "count": 0})
        e["count"] += 1
    sl: Dict[str, Any] = {"licenses": sorted(by_lic.values(), key=lambda e: -e["count"]), "files_scanned": tree.get("source_files_scanned") or 0,
                          "policy_findings": lic.get("policy") or [], "notes": []}
    if tree.get("project_license"):
        sl["notes"].append("Project licence: %s (source: %s)." % (tree["project_license"], tree.get("project_license_source") or "unknown"))
    if tree.get("vendored"):
        sl["notes"].append("%d vendored component(s) carry their own licence files." % len(tree["vendored"]))
    # "deprecated" is not assessed by BTS-SBOM, so that chip is omitted instead of shown as 0.
    return {"licenses": {"summary": {"category_counts": dict(cats)}},
            "license_verification": {"summary": {"ok": resolved, "none": max(0, total - resolved), "invalid": len(stats.get("unmapped_raw") or {})}},
            "source_licenses": sl}


def to_report(rec: Dict[str, Any], triage: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    vulns = rec.get("vulns") or []
    comps = rec.get("components") or []
    eng = rec.get("engine") or {}
    st = eng.get("status") or {}
    sev = Counter(_sev(v.get("severity")) for v in vulns)
    severity: Dict[str, Any] = {k: sev.get(k, 0) for k in SEVERITIES}
    severity["total"] = len(vulns)
    severity["vulnerable_packages"] = len({(str(v.get("package") or "").lower(), v.get("version")) for v in vulns})
    packages = [{"name": c.get("name"), "version": c.get("version"), "license": c.get("license") or "", "dep_license": c.get("license_raw") or "",
                 "dependency_type": c.get("relationship") or "unknown", "ecosystem": c.get("ecosystem"),
                 "source_file": (c.get("files") or [""])[0],
                 "obligations": {"gpl_warning": c.get("license_category") in _GPL_FAMILY}} for c in comps]
    rep: Dict[str, Any] = {
        "source": rec.get("source") or rec.get("name"), "name": rec.get("name"), "components": len(comps), "severity": severity,
        # unverified = packages without an authoritative answer: never queried, version unresolved, or answered from the offline fallback
        "scan_status": {"mode": st.get("mode") or "unknown", "unqueried": int(st.get("unqueried") or 0) + int(st.get("version_unresolved") or 0),
                        "offline_no_data": int(st.get("network_fallback_offline") or 0)},
        "findings": [finding(v, triage) for v in vulns],
        "remediation": [{"component": p.get("component"), "current_version": p.get("current_version"), "safe_version": p.get("safe_version"),
                         "breaking_risk": p.get("breaking_risk"), "major_bump": p.get("major_bump")}
                        for p in rec.get("plans") or [] if p.get("status") == "upgrade"],
        "packages": packages, "dep_tree": dep_tree(rec),
        "bts": {"data_status": eng.get("data_status"), "vulnerability_presence": eng.get("vulnerability_presence"),
                "empty_project": eng.get("data_status") == "empty_project"},
    }
    rep.update(_licence_blocks(rec))
    return rep


def _trim_patch(p: Dict[str, Any]) -> Dict[str, Any]:
    keep = ("approved", "status", "note", "digest", "before", "after", "rescan_fixed_total", "applied_components", "estimated_fixed_by_plan",
            "regenerate", "branch", "commit", "diff", "delivery")
    out = {k: p[k] for k in keep if k in p}
    out["rounds"] = [{k: r.get(k) for k in ("round", "status", "applied", "blocked", "manual", "vulns_before", "vulns_after", "fixed", "introduced")}
                     for r in p.get("rounds") or []]
    out["plans"] = [{k: x.get(k) for k in ("component", "current_version", "safe_version", "breaking_risk")} for x in (p.get("plans") or [])[:60]]
    d = out.get("diff")                       # patch.diff() returns {"stat": str, "patch": str}; accept a bare string too
    if isinstance(d, str):
        d = {"stat": "", "patch": d}
    if isinstance(d, dict):
        out["diff"] = {"stat": str(d.get("stat") or "")[:4000], "patch": str(d.get("patch") or "")[:60000]}
    return out


def _sector(s: Dict[str, Any]) -> Dict[str, Any]:
    return {"title": s.get("sector_title"), "verdict": s.get("verdict"), "summary": s.get("summary") or {}, "honesty": s.get("honesty"),
            "requirements": [{"id": r.get("id"), "title": r.get("title"), "verdict": r.get("verdict"), "detail": r.get("detail"), "basis": r.get("basis")}
                             for r in s.get("requirements") or []]}


def build_view(rec: Dict[str, Any], triage: Optional[Dict[str, Dict[str, Any]]] = None, analysed_at: Optional[str] = None) -> Dict[str, Any]:
    """Everything the page needs for one project: the console report plus the data of the other panes."""
    arch = rec.get("arch") or {}
    g = arch.get("graph") or {}
    return {
        "project": rec.get("name"), "source": rec.get("source"), "analysed_at": analysed_at, "lineage": rec.get("lineage") or {},
        "report": to_report(rec, triage),
        "engine": {k: (rec.get("engine") or {}).get(k) for k in ("core", "status", "data_status", "vulnerability_presence", "adjustments", "notes")},
        "metrics": rec.get("metrics") or {}, "stage_errors": rec.get("stage_errors") or {},
        "arch": {"stack": arch.get("stack"), "history": arch.get("history"), "notes": arch.get("notes") or [],
                 "graph": {k: g.get(k) for k in ("modules", "import_edges", "cycle_count", "modules_in_cycles", "tangle_ratio", "max_depth", "fan_in_top")},
                 "cycles": (g.get("cycles") or [])[:10], "hotspots": (arch.get("hotspots") or [])[:15],
                 "coupling": ((arch.get("coupling") or {}).get("pairs") or [])[:15], "runtime_eol": arch.get("runtime_eol") or [],
                 "modernization": arch.get("modernization") or [], "clusters": (arch.get("clusters") or [])[:15]},
        "sectors": {k: _sector(v) for k, v in (rec.get("sectors") or {}).items()},
        "sbom_check": rec.get("sbom_check") or {}, "plan_summary": rec.get("plan_summary") or {},
        "plans": [{k: p.get(k) for k in ("component", "ecosystem", "current_version", "safe_version", "status", "cve_count", "max_severity", "max_cvss",
                                          "major_bump", "breaking_risk", "verification")} for p in rec.get("plans") or []],
        "patch": _trim_patch(rec.get("patch") or {}),
        "proposals": {k: (rec.get("proposals") or {}).get(k) for k in ("source", "model", "items", "summary", "llm_note")},
        "license": {"project_license": (rec.get("license") or {}).get("project_license"),
                    "project_license_source": (rec.get("license") or {}).get("project_license_source"),
                    "stats": {k: ((rec.get("license") or {}).get("stats") or {}).get(k) for k in ("by_source", "resolved", "total", "resolved_rate")},
                    "policy": (rec.get("license") or {}).get("policy") or [],
                    "unresolved": [c.get("name") + "@" + str(c.get("version")) for c in rec.get("components") or [] if not c.get("license")][:60]},
    }


def valid_triage(check_id: Any, status: Any, note: Any) -> Optional[str]:
    """None when the triage request is acceptable, else the reason (the server answers 400 with it)."""
    if not isinstance(check_id, str) or not check_id.strip() or len(check_id) > TRIAGE_MAX_KEY:
        return "check_id must be a non-empty string of at most %d characters" % TRIAGE_MAX_KEY
    if status not in TRIAGE_STATUSES:
        return "status must be one of %s" % ", ".join(TRIAGE_STATUSES)
    if note is not None and (not isinstance(note, str) or len(note) > TRIAGE_MAX_NOTE):
        return "note must be a string of at most %d characters" % TRIAGE_MAX_NOTE
    return None
