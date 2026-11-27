"""Across all analysed projects: "which of our products use this component / are hit by this CVE?" and a portfolio roll-up.

Why (FOSSLight Community Day 2026, Hub + Enterprise): when an advisory lands, the first question is not "what is in project X" but
"which projects are affected". Hub answers it with a search for the projects that use a given open source version; Enterprise adds
the cross-project view for governance. This module does both over the evidence folder - read-only, no network.

Honesty: a project that was analysed offline or whose scan had unqueried packages can only answer "not found among the findings
of the last analysis", so every answer lists the analysed projects it covers and the age of each analysis is the caller's to show.
A component without a version cannot be matched against a version range; it is reported as ``version_unknown`` instead of being
silently counted as unaffected.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from . import engine, gaps, licenses, versions

_OPS = ("==", "!=", "<=", ">=", "<", ">")
_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


def parse_spec(spec: Optional[str]) -> List[Tuple[str, str]]:
    """``"<2.0,>=1.0"`` -> [("<","2.0"),(">=","1.0")]. A bare version means ==; ``""`` / ``*`` mean any version. ValueError on junk."""
    s = str(spec or "").strip()
    if s in ("", "*"):
        return []
    out: List[Tuple[str, str]] = []
    for part in s.split(","):
        p = part.strip()
        op = next((o for o in _OPS if p.startswith(o)), "==")
        ver = p[len(op):].strip() if p.startswith(op) else p
        if not versions.is_version(ver):
            raise ValueError("not a version constraint: %r" % part)
        out.append((op, ver))
    return out


def in_spec(version: str, cons: List[Tuple[str, str]]) -> bool:
    for op, ver in cons:
        c = versions.compare(version, ver)
        if not {"==": c == 0, "!=": c != 0, "<": c < 0, "<=": c <= 0, ">": c > 0, ">=": c >= 0}[op]:
            return False
    return True


def _ids(v: Dict[str, Any]) -> set:
    return {str(x).upper() for x in [v.get("id")] + list(v.get("aliases") or []) + list(v.get("osv_ids") or []) if x}


def canon_name(name: str) -> str:
    """Ecosystem-agnostic name key: case-insensitive, with the PyPI separators (-_.) folded."""
    return engine._canon("pypi", name)


def affected(projects: Dict[str, Dict[str, Any]], *, vuln_id: Optional[str] = None, component: Optional[str] = None,
             version: Optional[str] = None) -> Dict[str, Any]:
    """Projects hit by an advisory id (any alias) and/or using a component (optionally within a version constraint)."""
    if not vuln_id and not component:
        raise ValueError("give an advisory id and/or a component name")
    cons = parse_spec(version)
    want_id = str(vuln_id).strip().upper() if vuln_id else ""
    want_c = canon_name(component) if component else ""
    rows: List[Dict[str, Any]] = []
    clean: List[str] = []
    for name in sorted(projects):
        rec = projects[name]
        matches: List[Dict[str, Any]] = []
        for v in rec.get("vulns") or []:
            if want_id and want_id not in _ids(v):
                continue
            if want_c and canon_name(str(v.get("package") or "")) != want_c:
                continue
            if cons and not in_spec(str(v.get("version") or ""), cons):
                continue
            if want_id:
                matches.append({"kind": "finding", "id": v.get("id"), "package": v.get("package"), "version": v.get("version"), "severity": v.get("severity"),
                                "fixed_version": v.get("fixed_version") or "", "files": list(v.get("files") or [])[:3]})
        if not want_id:                                           # component query: list the components themselves
            for c in rec.get("components") or []:
                if canon_name(str(c.get("name") or "")) != want_c:
                    continue
                ver = str(c.get("version") or "")
                if cons and not ver:
                    matches.append({"kind": "version_unknown", "package": c.get("name"), "version": "", "ecosystem": c.get("ecosystem"), "vulns": c.get("vulns", 0)})
                elif not cons or in_spec(ver, cons):
                    matches.append({"kind": "component", "package": c.get("name"), "version": ver, "ecosystem": c.get("ecosystem"),
                                    "relationship": c.get("relationship") or "unknown", "vulns": c.get("vulns", 0), "files": list(c.get("files") or [])[:3]})
        if matches:
            rows.append({"project": name, "matches": matches})
        else:
            clean.append(name)
    return {"query": {"id": want_id, "component": component or "", "version": version or ""}, "analysed_projects": len(projects), "project_count": len(rows),
            "match_count": sum(len(r["matches"]) for r in rows), "projects": rows, "not_found_in": clean,
            "not_verified": [{"project": n, "gaps": [g["code"] for g in gaps.of(projects[n])]} for n in clean if gaps.of(projects[n])],
            "note": "answers come from the findings and components of each project's last analysis; a project analysed offline may be missing findings"}


def _worst(vs: Iterable[Dict[str, Any]]) -> str:
    best = max((_RANK.get(str(v.get("severity")), 0) for v in vs), default=0)
    return {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: ""}[best]


def rollup(projects: Dict[str, Dict[str, Any]], top: int = 10) -> Dict[str, Any]:
    """Portfolio view: totals, projects ranked by weighted findings, advisories and components shared by several projects."""
    sev: Dict[str, int] = {}
    cats: Dict[str, int] = {}
    cve: Dict[str, Dict[str, Any]] = {}
    comp: Dict[Tuple[str, str], Dict[str, Any]] = {}
    rows: List[Dict[str, Any]] = []
    n_comp = n_vuln = 0
    for name, rec in sorted(projects.items()):
        vs, cs = rec.get("vulns") or [], rec.get("components") or []
        n_comp, n_vuln = n_comp + len(cs), n_vuln + len(vs)
        psev: Dict[str, int] = {}
        for v in vs:
            s = str(v.get("severity") or "UNKNOWN")
            sev[s] = sev.get(s, 0) + 1
            psev[s] = psev.get(s, 0) + 1
            e = cve.setdefault(str(v.get("id")), {"id": v.get("id"), "projects": set(), "worst": "", "fixed_version": v.get("fixed_version") or "", "package": v.get("package")})
            e["projects"].add(name)
            if _RANK.get(s, 0) > _RANK.get(e["worst"], 0):
                e["worst"] = s
        for c in cs:
            k = str(c.get("license_category") or (licenses.category(c["license"]) if c.get("license") else "unknown"))
            cats[k] = cats.get(k, 0) + 1
            ce = comp.setdefault((canon_name(str(c.get("name") or "")), str(c.get("version") or "")),
                                 {"name": c.get("name"), "version": c.get("version") or "", "projects": set(), "vulns": 0})
            ce["projects"].add(name)
            ce["vulns"] = max(ce["vulns"], int(c.get("vulns") or 0))
        rows.append({"project": name, "components": len(cs), "vulns": len(vs), "severity": psev, "worst": _worst(vs),
                     "weighted": sum(_WEIGHT.get(str(v.get("severity")), 0) for v in vs),
                     "unfixed": sum(1 for v in vs if not v.get("fixed_version")), "malicious": sum(1 for v in vs if v.get("malicious"))})
    rows.sort(key=lambda r: (-r["weighted"], r["project"]))
    shared_cve = sorted(({**e, "projects": sorted(e["projects"]), "project_count": len(e["projects"])} for e in cve.values()),
                        key=lambda e: (-e["project_count"], -_RANK.get(e["worst"], 0), str(e["id"])))[:top]
    shared_comp = sorted(({**e, "projects": sorted(e["projects"]), "project_count": len(e["projects"])} for e in comp.values() if len(e["projects"]) > 1),
                         key=lambda e: (-e["project_count"], -e["vulns"], str(e["name"])))[:top]
    return {"projects": len(projects), "components": n_comp, "vulns": n_vuln, "severity": sev, "license_categories": cats,
            "ranking": rows[:top], "ranking_basis": "weighted findings (CRITICAL 10, HIGH 5, MEDIUM 2, LOW 1) - an ordering aid, not a risk metric",
            "shared_advisories": shared_cve, "shared_components": shared_comp,
            "unfixed_findings": sum(r["unfixed"] for r in rows), "projects_with_malicious": [r["project"] for r in rows if r["malicious"]]}


def render_affected_md(res: Dict[str, Any]) -> str:
    q = res["query"]
    what = " ".join(x for x in (q["id"], q["component"] + ((" " + q["version"]) if q["version"] else "")) if x.strip())
    L = ["# Affected projects: %s" % what, "", "- %d of %d analysed project(s) match (%d match(es))" % (res["project_count"], res["analysed_projects"], res["match_count"]), ""]
    for r in res["projects"]:
        L.append("## %s" % r["project"])
        for m in r["matches"]:
            if m["kind"] == "finding":
                L.append("- %s: %s %s, %s%s" % (m["id"], m["package"], m["version"], m["severity"], (", fixed in " + m["fixed_version"]) if m["fixed_version"] else ", no fix known"))
            elif m["kind"] == "version_unknown":
                L.append("- %s: version unknown, cannot be matched against %s" % (m["package"], q["version"]))
            else:
                L.append("- %s %s (%s, %s, %s vulnerabilities)" % (m["package"], m["version"] or "?", m.get("ecosystem") or "?", m.get("relationship"), m.get("vulns")))
        L.append("")
    if res["not_found_in"]:
        L.append("Not found in: %s" % ", ".join(res["not_found_in"]))
    L += ["", "_%s_" % res["note"], ""]
    return "\n".join(L)


def render_rollup_md(r: Dict[str, Any]) -> str:
    L = ["# Portfolio", "", "- %d projects, %d components, %d findings (%s), %d without a known fix" % (
        r["projects"], r["components"], r["vulns"], ", ".join("%s %d" % (k, r["severity"][k]) for k in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN") if k in r["severity"]) or "none", r["unfixed_findings"]), "",
         "| project | components | findings | worst | weighted | unfixed |", "|---|---|---|---|---|---|"]
    L += ["| %s | %d | %d | %s | %d | %d |" % (x["project"], x["components"], x["vulns"], x["worst"] or "-", x["weighted"], x["unfixed"]) for x in r["ranking"]]
    if any(e["project_count"] > 1 for e in r["shared_advisories"]):
        L += ["", "## Advisories shared by several projects", ""] + ["- %s (%s, %s): %d project(s): %s" % (e["id"], e["package"], e["worst"] or "?", e["project_count"], ", ".join(e["projects"]))
                                                                  for e in r["shared_advisories"] if e["project_count"] > 1]
    if r["shared_components"]:
        L += ["", "## Components used by several projects", ""] + ["- %s %s: %d project(s)" % (e["name"], e["version"] or "?", e["project_count"]) for e in r["shared_components"]]
    L += ["", "_%s_" % r["ranking_basis"], ""]
    return "\n".join(L)


__all__ = ["affected", "rollup", "parse_spec", "in_spec", "canon_name", "render_affected_md", "render_rollup_md"]
