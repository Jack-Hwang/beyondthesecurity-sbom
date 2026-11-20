"""Patch regression impact across four quadrants (course package B, lecture 3-3 p.56).

``pipeline._patch_loop`` used to judge regression only on the findings of the files it edited ("scoped"
findings - see the comment in ``pipeline.py`` next to ``scoped()``). That answers "did the component we
touched get worse", nothing else. The lecture's database regression quadrants (direct/upstream/downstream/
shared - a changed query, its load step, its downstream consumers, and every OTHER place that reads the same
table) translate to a dependency patch as:

  direct      the upgraded component itself: findings resolved / still present / newly introduced.
  upstream    components declared in the SAME manifest(s) we edited but NOT themselves upgraded: did their
              findings increase, and how many upgrades were blocked by a manifest constraint (upper bound).
  downstream  transitive dependencies (``relationship != "direct"``) pulled in by the upgrade: new findings
              there, plus lockfiles/manifests that still need regenerating (so the dependency tree the
              installer actually resolves has not really changed yet).
  shared      the SAME component+version left unfixed in a DIFFERENT manifest of this project, and - when a
              fleet registry is given - in a DIFFERENT project. This is the quadrant the lecture says is
              missed most often (the DB anti-pattern: a query is "fixed" but another query reads the same
              table unexamined); see ADR-0012 and the test that reproduces it.

Every quadrant reports ``status`` in {"ok", "regression", "unverified", "n/a"} ("n/a" = nothing of this kind
applied to this patch, e.g. no upgrade plan at all), ``checked`` (False only for "unverified"), ``counts``
(small integers, the kind of "measured number" the EARS lint wants) and ``evidence`` (short human-readable
strings, never the full data - this module does not persist anything).

Honesty rule: a quadrant with missing data is "unverified", never silently "ok". The overall ``verdict`` is
"regression" if any quadrant regressed, else "incomplete" if any quadrant is unverified, else "clean" - never
"clean" while something is unverified (course gap: current AC set has 0 State-pattern ACs; see
specs/bts_sbom_app_features.md BSA-AC-320).

This module is pure: no network, no file IO, no mutation of its inputs.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import engine, fleet as fleetmod

STATUS_OK = "ok"
STATUS_REGRESSION = "regression"
STATUS_UNVERIFIED = "unverified"
STATUS_NA = "n/a"

Key = Tuple[str, str]


def _key(ecosystem: Any, name: Any) -> Key:
    eco = str(ecosystem or "")
    return eco.lower(), engine._canon(eco, str(name or ""))


def _quadrant(status: str, checked: bool, counts: Dict[str, Any], evidence: List[str]) -> Dict[str, Any]:
    return {"status": status, "checked": checked, "counts": counts, "evidence": evidence}


def _upgraded_keys(plans: Sequence[Dict[str, Any]]) -> set:
    return {_key(p.get("ecosystem"), p.get("component")) for p in plans if p.get("status") == "upgrade"}


def _upgraded_rows(plans: Sequence[Dict[str, Any]]) -> List[Tuple[str, str, str]]:
    return [(str(p.get("component") or ""), str(p.get("ecosystem") or ""), str(p.get("current_version") or ""))
            for p in plans if p.get("status") == "upgrade"]


def _blocked_count(plans: Sequence[Dict[str, Any]]) -> int:
    return sum(1 for p in plans if p.get("status") == "upgrade" and p.get("apply_status") == "blocked")


def _ids_for_keys(vulns: Iterable[Dict[str, Any]], keys: set) -> set:
    return {v["id"] for v in vulns if _key(v.get("ecosystem"), v.get("package")) in keys}


def _direct(before_vulns: List[Dict[str, Any]], after_vulns: Optional[List[Dict[str, Any]]],
            plans: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    keys = _upgraded_keys(plans)
    if not keys:
        return _quadrant(STATUS_NA, True, {"resolved": 0, "remaining": 0, "introduced": 0}, [])
    if after_vulns is None:
        return _quadrant(STATUS_UNVERIFIED, False, {"resolved": 0, "remaining": 0, "introduced": 0},
                          ["no post-patch re-scan is available for the upgraded component(s)"])
    before_ids = _ids_for_keys(before_vulns, keys)
    after_ids = _ids_for_keys(after_vulns, keys)
    resolved = sorted(before_ids - after_ids)
    remaining = sorted(before_ids & after_ids)
    introduced = sorted(after_ids - before_ids)
    counts = {"resolved": len(resolved), "remaining": len(remaining), "introduced": len(introduced)}
    evidence: List[str] = []
    if introduced:
        evidence.append("new finding(s) on the upgraded component(s): " + ", ".join(introduced[:20]))
    if resolved:
        evidence.append("resolved: " + ", ".join(resolved[:20]))
    if remaining:
        evidence.append("still present after the upgrade: " + ", ".join(remaining[:20]))
    status = STATUS_REGRESSION if introduced else STATUS_OK
    return _quadrant(status, True, counts, evidence)


def _others_in_changed_manifests(components: Optional[List[Dict[str, Any]]], upgraded: set, changed: set) -> set:
    out = set()
    for c in components or []:
        key = _key(c.get("ecosystem"), c.get("name"))
        if key in upgraded:
            continue
        if set(c.get("files") or []) & changed:
            out.add(key)
    return out


def _upstream(before_components: List[Dict[str, Any]], before_vulns: List[Dict[str, Any]],
              after_components: Optional[List[Dict[str, Any]]], after_vulns: Optional[List[Dict[str, Any]]],
              changed_files: Optional[Sequence[str]], plans: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    upgraded = _upgraded_keys(plans)
    changed = set(changed_files or [])
    blocked = _blocked_count(plans)
    if not changed:
        return _quadrant(STATUS_NA, True, {"other_components": 0, "new_findings": 0, "blocked": blocked}, [])
    other_keys = _others_in_changed_manifests(before_components, upgraded, changed) | \
        _others_in_changed_manifests(after_components, upgraded, changed)
    if not other_keys:
        return _quadrant(STATUS_NA, True, {"other_components": 0, "new_findings": 0, "blocked": blocked}, [])
    if after_vulns is None:
        return _quadrant(STATUS_UNVERIFIED, False, {"other_components": len(other_keys), "new_findings": 0, "blocked": blocked},
                          ["no post-patch re-scan is available for the untouched component(s) declared in " + ", ".join(sorted(changed))])
    before_ids = _ids_for_keys(before_vulns, other_keys)
    after_ids = _ids_for_keys(after_vulns, other_keys)
    new_ids = sorted(after_ids - before_ids)
    counts = {"other_components": len(other_keys), "new_findings": len(new_ids), "blocked": blocked}
    evidence: List[str] = []
    if new_ids:
        evidence.append("new finding(s) on untouched component(s) sharing " + ", ".join(sorted(changed)) + ": " + ", ".join(new_ids[:20]))
    if blocked:
        evidence.append("%d upgrade(s) blocked by a manifest constraint (upper bound)" % blocked)
    status = STATUS_REGRESSION if new_ids else STATUS_OK
    return _quadrant(status, True, counts, evidence)


def _relationship_map(before_components: Optional[List[Dict[str, Any]]],
                       after_components: Optional[List[Dict[str, Any]]]) -> Dict[Key, str]:
    rel: Dict[Key, str] = {}
    for c in list(before_components or []) + list(after_components or []):
        key = _key(c.get("ecosystem"), c.get("name"))
        cur = rel.get(key, "")
        new = str(c.get("relationship") or "")
        if cur != "direct" and new == "direct":
            rel[key] = "direct"
        elif key not in rel:
            rel[key] = new
    return rel


def _downstream(before_components: List[Dict[str, Any]], before_vulns: List[Dict[str, Any]],
                 after_components: Optional[List[Dict[str, Any]]], after_vulns: Optional[List[Dict[str, Any]]],
                 plans: Sequence[Dict[str, Any]], regenerate: Optional[Sequence[str]]) -> Dict[str, Any]:
    upgraded = _upgraded_keys(plans)
    regen = sorted({str(x) for x in (regenerate or [])})
    if not upgraded:
        return _quadrant(STATUS_NA, True, {"new_transitive_findings": 0, "regenerate_pending": len(regen)}, [])
    if after_vulns is None or after_components is None:
        return _quadrant(STATUS_UNVERIFIED, False, {"new_transitive_findings": 0, "regenerate_pending": len(regen)},
                          ["no post-patch re-scan is available to check transitive dependencies"])
    rel_map = _relationship_map(before_components, after_components)

    def transitive_ids(vulns: Iterable[Dict[str, Any]]) -> set:
        return {v["id"] for v in vulns if rel_map.get(_key(v.get("ecosystem"), v.get("package")), "") != "direct"}

    new_ids = sorted(transitive_ids(after_vulns) - transitive_ids(before_vulns))
    counts = {"new_transitive_findings": len(new_ids), "regenerate_pending": len(regen)}
    if new_ids:
        return _quadrant(STATUS_REGRESSION, True, counts,
                          ["new finding(s) on a transitive dependency: " + ", ".join(new_ids[:20])])
    if regen:
        return _quadrant(STATUS_UNVERIFIED, False, counts,
                          ["lockfile/manifest not regenerated, transitive closure unconfirmed: " + ", ".join(regen[:20])])
    return _quadrant(STATUS_OK, True, counts, [])


def _shared(before_components: List[Dict[str, Any]], after_components: Optional[List[Dict[str, Any]]],
            changed_files: Optional[Sequence[str]], plans: Sequence[Dict[str, Any]],
            fleet: Optional[Dict[str, Dict[str, Any]]]) -> Dict[str, Any]:
    upgraded = _upgraded_rows(plans)
    if not upgraded:
        return _quadrant(STATUS_NA, True, {"other_manifests_unfixed": 0, "fleet_projects_affected": None}, [])
    changed = set(changed_files or [])
    pool = list(before_components or []) + list(after_components or [])
    seen: set = set()
    other_manifest_hits = 0
    evidence: List[str] = []
    for name, eco, cur_ver in upgraded:
        key = _key(eco, name)
        for c in pool:
            if _key(c.get("ecosystem"), c.get("name")) != key:
                continue
            if str(c.get("version") or "") != cur_ver:
                continue
            files = tuple(sorted(c.get("files") or []))
            if not files or (set(files) & changed):
                continue                                   # no manifest on record, or it IS the one we fixed
            dedupe = (key, cur_ver, files)
            if dedupe in seen:
                continue
            seen.add(dedupe)
            other_manifest_hits += 1
            evidence.append("%s %s still declared, unfixed, in %s" % (name, cur_ver, ", ".join(files)))
    fleet_count: Optional[int] = None
    if fleet is not None:
        fleet_count = 0
        for name, eco, cur_ver in upgraded:
            res = fleetmod.affected(fleet, component=name, version=cur_ver)
            if res["project_count"]:
                fleet_count += res["project_count"]
                projects = ", ".join(sorted(r["project"] for r in res["projects"]))
                evidence.append("fleet: %s %s still used by %s" % (name, cur_ver, projects))
    counts = {"other_manifests_unfixed": other_manifest_hits, "fleet_projects_affected": fleet_count}
    if other_manifest_hits or (fleet_count or 0) > 0:
        status = STATUS_REGRESSION
    elif fleet is None:
        status = STATUS_UNVERIFIED
        evidence.append("no fleet registry given: other projects using the same component/version cannot be checked")
    else:
        status = STATUS_OK
    return _quadrant(status, status != STATUS_UNVERIFIED, counts, evidence)


def classify(before_components: Optional[List[Dict[str, Any]]], before_vulns: Optional[List[Dict[str, Any]]],
             after_components: Optional[List[Dict[str, Any]]], after_vulns: Optional[List[Dict[str, Any]]],
             changed_files: Optional[Sequence[str]], plans: Optional[Sequence[Dict[str, Any]]], *,
             regenerate: Optional[Sequence[str]] = None, fleet: Optional[Dict[str, Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Classify a dependency patch into the four regression quadrants.

    ``before_components``/``before_vulns`` are the pre-patch ``engine.analyze()`` output (e.g.
    ``rec["components"]``/``rec["vulns"]``). ``after_components``/``after_vulns`` are the output of the LAST
    post-patch re-scan, or ``None`` when no re-scan ran (nothing was applied) - a quadrant that needs the
    after-state is then "unverified", not silently "ok". ``changed_files`` are the manifest paths
    ``patch.apply()`` actually edited. ``plans`` are ``remediate.plan()`` records; a plan may carry an extra
    ``"apply_status"`` key (copied from the matching ``patch.apply()`` result, e.g. ``"blocked"``) - optional,
    used only to surface upper-bound blocks in the upstream quadrant. ``regenerate`` is the list of pending
    lockfile/manifest regeneration commands (``pipeline._patch_loop``'s own ``"regenerate"`` list).
    ``fleet`` is an OTHER-projects registry in ``fleet.affected()``'s ``projects`` shape
    (``{project_name: {"components": [...], "vulns": [...]}}``) - the caller must exclude the project being
    patched itself; ``None`` means "not available", which makes the shared quadrant "unverified" rather than
    silently clean.

    Returns ``{"direct": quadrant, "upstream": quadrant, "downstream": quadrant, "shared": quadrant,
    "summary": str, "verdict": "clean"|"incomplete"|"regression"}``. Each quadrant is
    ``{"status": "ok"|"regression"|"unverified"|"n/a", "checked": bool, "counts": {...}, "evidence": [str,...]}``.
    """
    before_components = before_components or []
    before_vulns = before_vulns or []
    plans = list(plans or [])
    direct = _direct(before_vulns, after_vulns, plans)
    upstream = _upstream(before_components, before_vulns, after_components, after_vulns, changed_files, plans)
    downstream = _downstream(before_components, before_vulns, after_components, after_vulns, plans, regenerate)
    shared = _shared(before_components, after_components, changed_files, plans, fleet)
    quadrants = {"direct": direct, "upstream": upstream, "downstream": downstream, "shared": shared}
    if any(q["status"] == STATUS_REGRESSION for q in quadrants.values()):
        verdict = "regression"
    elif any(q["status"] == STATUS_UNVERIFIED for q in quadrants.values()):
        verdict = "incomplete"
    else:
        verdict = "clean"
    summary = "verdict %s (direct %s, upstream %s, downstream %s, shared %s)" % (
        verdict, direct["status"], upstream["status"], downstream["status"], shared["status"])
    out: Dict[str, Any] = dict(quadrants)
    out["summary"] = summary
    out["verdict"] = verdict
    return out


__all__ = ["classify", "STATUS_OK", "STATUS_REGRESSION", "STATUS_UNVERIFIED", "STATUS_NA"]
