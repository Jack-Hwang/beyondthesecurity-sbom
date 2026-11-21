"""Patch-regression quadrants: direct / upstream / downstream / shared (stdlib only, pure functions).

Lecture 3 (AI DBA): every change is verified in 4 quadrants - direct (did the target improve), upstream (did
untouched siblings in the same manifest break), downstream (what the change pulls in: transitive dependencies and
the lockfiles that still pin old versions) and shared (other manifests and other projects declaring the same
component - "the most often missed quadrant"). A quadrant with no data is ``unverified``, never ok: absence of
evidence is not a pass. Verdict: any regression -> regression, else any unverified -> incomplete, else clean.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from . import fleet

LOCK_NAMES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "cargo.lock", "go.sum", "gemfile.lock", "poetry.lock", "composer.lock"}


def is_lockfile(path: str) -> bool:
    base = str(path).replace("\\", "/").rsplit("/", 1)[-1].lower()
    return base in LOCK_NAMES or base.endswith(".lock")


def _canon(name: str) -> str:
    return fleet.canon_name(str(name or ""))


def _quad(status: str, checked: bool, evidence: List[str], counts: Dict[str, Any]) -> Dict[str, Any]:
    return {"status": status, "checked": checked, "evidence": evidence[:20], "counts": counts}


def _vuln_key(v: Dict[str, Any]) -> str:
    return str(v.get("id") or "")


def _ids_for(vs: List[Dict[str, Any]], names: Set[str], files: Optional[Set[str]] = None) -> Set[str]:
    out: Set[str] = set()
    for v in vs:
        if _canon(v.get("package")) in names:
            if files is not None and not any(f in files for f in (v.get("files") or [])):
                continue
            out.add(_vuln_key(v))
    return out


def _components_named(comps: List[Dict[str, Any]], names: Set[str], *, files: Optional[Set[str]] = None,
                      relationship: Optional[str] = None) -> List[Dict[str, Any]]:
    out = []
    for c in comps or []:
        if _canon(c.get("name")) not in names:
            continue
        if files is not None and not any(f in files for f in (c.get("files") or [])):
            continue
        if relationship is not None and (c.get("relationship") or "direct") != relationship:
            continue
        out.append(c)
    return out


def classify(*, before_components: Optional[List[Dict[str, Any]]], before_vulns: Optional[List[Dict[str, Any]]],
             after_components: Optional[List[Dict[str, Any]]], after_vulns: Optional[List[Dict[str, Any]]],
             edited_files: Optional[Set[str]], results: List[Dict[str, Any]],
             fleet_projects: Optional[Dict[str, Dict[str, Any]]] = None, project_name: Optional[str] = None) -> Dict[str, Any]:
    """Four-quadrant regression verdict for one patch round set. Pure: reads only the given records."""
    edited = {str(f).replace("\\", "/") for f in (edited_files or set())}
    applied = [r for r in (results or []) if r.get("status") == "applied"]
    blocked = [r for r in (results or []) if r.get("status") == "blocked"]
    targets = {_canon(r.get("component")) for r in applied}
    old_version = {r.get("component"): str(r.get("from") or "") for r in applied}

    # ---- direct: did the upgraded components improve (cleared / remaining / introduced)?
    if before_vulns is None or after_vulns is None:
        direct = _quad("unverified", False, ["before/after findings unavailable"], {})
    elif not targets:
        direct = _quad("n/a", False, ["no component was upgraded"], {})
    else:
        b, a = _ids_for(before_vulns, targets), _ids_for(after_vulns, targets)
        cleared, introduced = sorted(b - a), sorted(a - b)
        remaining = sorted(b & a)
        ev = ["cleared: %s" % ", ".join(cleared[:8]) if cleared else "cleared: 0",
              "introduced: %s" % ", ".join(introduced[:8]) if introduced else "introduced: 0"]
        direct = _quad("regression" if introduced else "ok", True, ev,
                       {"cleared": len(cleared), "remaining": len(remaining), "introduced": len(introduced)})

    # ---- upstream: untouched siblings declared in the edited manifests must not gain advisories
    if before_components is None or after_components is None or before_vulns is None or after_vulns is None:
        upstream = _quad("unverified", False, ["before/after records unavailable"], {})
    else:
        siblings = {_canon(c.get("name")) for c in before_components if any(f in edited for f in (c.get("files") or []))} - targets
        b, a = _ids_for(before_vulns, siblings), _ids_for(after_vulns, siblings)
        new = sorted(a - b)
        ev = ["new advisory on untouched sibling: %s" % x for x in new[:5]]
        ev += ["blocked candidate (constraint, not a regression): %s -> %s" % (r.get("component"), r.get("detail", "")[:80]) for r in blocked[:5]]
        upstream = _quad("regression" if new else "ok", True, ev, {"siblings": len(siblings), "new": len(new), "blocked": len(blocked)})

    # ---- downstream: transitive components and the lockfiles that still pin upgraded versions
    if before_components is None or after_components is None or before_vulns is None or after_vulns is None:
        downstream = _quad("unverified", False, ["before/after records unavailable"], {})
    else:
        trans = {_canon(c.get("name")) for c in before_components if any(f in edited for f in (c.get("files") or []))
                 and (c.get("relationship") or "direct") != "direct"} - targets
        b, a = _ids_for(before_vulns, trans), _ids_for(after_vulns, trans)
        new = sorted(a - b)
        ev = ["new advisory on transitive dependency: %s" % x for x in new[:5]]
        # a lockfile we did not edit still pins an upgraded component: until it is regenerated the outcome is unknown
        stale_locks: Set[str] = set()
        for c in list(before_components) + list(after_components):
            if _canon(c.get("name")) in targets:
                stale_locks |= {f for f in (c.get("files") or []) if is_lockfile(f) and f not in edited}
        if stale_locks:
            ev += ["unedited lockfile still pins an upgraded version: %s" % f for f in sorted(stale_locks)[:5]]
        if new:
            status = "regression"
        elif stale_locks:
            status = "unverified"
        else:
            status = "ok"
        downstream = _quad(status, True, ev, {"transitive": len(trans), "new": len(new), "regenerate": sorted(stale_locks)})

    # ---- shared: the same component declared in other (non-lock) manifests, and other projects using it
    if before_components is None:
        shared = _quad("unverified", False, ["component records unavailable"], {})
    else:
        other_manifests: Set[str] = set()
        for c in before_components:
            if _canon(c.get("name")) in targets:
                other_manifests |= {f for f in (c.get("files") or []) if f not in edited and not is_lockfile(f)}
        ev = ["upgraded component still declared in an unpatched manifest: %s" % f for f in sorted(other_manifests)[:5]]
        op = {"checked": False, "count": 0}
        if fleet_projects is not None:
            hits: Set[str] = set()
            for comp, ver in old_version.items():
                try:
                    res = fleet.affected(fleet_projects, component=comp, version=ver or None)
                except (ValueError, KeyError):
                    continue
                hits |= {row.get("project") for row in res.get("projects") or []}
            hits.discard(project_name)
            op = {"checked": True, "count": len(hits)}
            if hits:
                ev.append("other projects still use the old version: %d" % len(hits))
        shared = _quad("regression" if other_manifests else "ok", True, ev,
                       {"unpatched_manifests": len(other_manifests), "other_projects": op})

    statuses = [direct["status"], upstream["status"], downstream["status"], shared["status"]]
    if "regression" in statuses:
        verdict = "regression"
    elif "unverified" in statuses:
        verdict = "incomplete"
    else:
        verdict = "clean"
    parts = ["direct=%s" % direct["status"], "upstream=%s" % upstream["status"], "downstream=%s" % downstream["status"], "shared=%s" % shared["status"]]
    return {"direct": direct, "upstream": upstream, "downstream": downstream, "shared": shared, "verdict": verdict,
            "summary": "; ".join(parts)}
