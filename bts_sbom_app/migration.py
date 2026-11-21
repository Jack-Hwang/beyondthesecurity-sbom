"""Migration / upgrade impact plan with waves (task 26, brief 2) - stdlib only, propose-only.

"Which of MY code does this upgrade touch, and what order?" - an upgrade plan row plus (when the source is
available and the dependency is direct) the bounded import-site count from contextpack. 0 sites is NEVER "no
impact": the import name may differ from the package name. Waves are deterministic: A = safe upgrades first,
B = needs code review (major jump / many sites / unknown jump), C = no upgrade path (no_fix or a high-risk
legacy row). Everything is needs_human; nothing is applied and the analysed tree is never written.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from . import contextpack, versions

SCHEMA = "bts-sbom.migration.v1"
DISCLAIMER = "엔지니어링 신호이며 법률 자문이 아닙니다 — 법무 확인이 필요합니다 (engineering signal, not legal advice)"
SITE_THRESHOLD = 10
C_OPTIONS = ("replace", "accept_risk", "pin", "monitor")
CHECKLIST_COMMON = [
    "릴리스 노트를 확인한다({cur} → {tgt}) — 이 도구는 변경 내역을 가져오지 않았다",
    "업그레이드 후 테스트를 실행한다 — 이 도구는 실행하지 않았다",
]


def _jump(current: str, target: str) -> str:
    if not current or not target:
        return "unknown"
    a, b = versions.major(current), versions.major(target)
    if a is None or b is None:
        return "unknown"
    if a == b:
        return "minor" if versions.compare(current, target) <= 0 else "patch"
    return "major"


def _sites(component: str, root: Optional[str], relationship: str, max_sites: int) -> Dict[str, Any]:
    if not root:
        return {"available": False, "files": 0, "sites": 0, "bounded": False, "note": "source not provided"}
    if relationship != "direct":
        return {"available": False, "files": 0, "sites": 0, "bounded": False, "note": "transitive dependency - no direct import"}
    try:
        pack = contextpack.build(root, component, max_sites=max_sites)
    except (ValueError, OSError):
        return {"available": False, "files": 0, "sites": 0, "bounded": False, "note": "source folder could not be read"}
    items = pack.get("items") or []
    # contextpack groups contiguous import lines into one item: count the import statements inside each item
    import re
    sites = 0
    files = set()
    for i in items:
        text = str(i.get("text") or "")
        n = sum(1 for ln in text.splitlines() if re.match(r"^\s*(?:import\s+[A-Za-z_]|from\s+[A-Za-z_])", ln))
        if n:
            sites += n
            files.add(i.get("path"))
        if sites >= max_sites:
            sites = max_sites
            break
    if sites == 0:
        return {"available": True, "files": 0, "sites": 0, "bounded": False,
                "note": "0 sites found - the import name may differ from the package name; this does not prove no impact"}
    return {"available": True, "files": len(files), "sites": sites, "bounded": sites >= max_sites,
            "note": "bounded by max_sites" if sites >= max_sites else ""}


def _wave(plan: Dict[str, Any], jump: str, sites: Dict[str, Any], legacy_risk: str) -> str:
    if plan.get("status") == "no_fix" or legacy_risk == "high":
        return "C"
    if jump == "major" or jump == "unknown" or sites.get("sites", 0) > SITE_THRESHOLD:
        return "B"
    return "A"


def plan(rec: Dict[str, Any], *, root: Optional[str] = None, max_sites_per_component: int = 40) -> Dict[str, Any]:
    """Build the migration plan from rec["plans"] (+ rec["legacy"] when present). Deterministic bytes."""
    legacy_rows: Dict[str, str] = {}
    for row in (rec.get("legacy") or {}).get("rows") or []:
        legacy_rows[str(row.get("component")).lower()] = str(row.get("risk"))
    items: List[Dict[str, Any]] = []
    waves = {"A": 0, "B": 0, "C": 0}
    for p in rec.get("plans") or []:
        component = str(p.get("component"))
        current, target = str(p.get("current_version") or ""), str(p.get("safe_version") or "")
        jump = _jump(current, target)
        rel = str(p.get("relationship") or "direct")
        sites = _sites(component, root, rel, max_sites_per_component)
        wave = _wave(p, jump, sites, legacy_rows.get(component.lower(), ""))
        if wave == "C":
            options = [{"id": o, "needs_human": True} for o in C_OPTIONS]
            options[1]["note"] = "accept_risk 는 VEX 결정 + 만료일(expires)로 기록한다 (bts_sbom_app/triage.py)"
            checklist = CHECKLIST_COMMON + ["업그레이드 경로가 없다: 대체·위험 수용(만료일 포함 VEX)·고정·모니터링 중 하나를 사람이 고른다"]
        else:
            options = [{"id": "upgrade", "needs_human": True}]
            checklist = [c.format(cur=current, tgt=target) for c in CHECKLIST_COMMON]
            if sites.get("available"):
                checklist.insert(1, "호출 위치 %d곳(%d 파일)을 검토한다" % (sites.get("sites", 0), sites.get("files", 0)))
            else:
                checklist.insert(1, "호출 위치를 직접 확인한다 — " + (sites.get("note") or "source not provided"))
        items.append({"component": component, "from": current, "to": target, "status": str(p.get("status")),
                      "jump": jump, "relationship": rel, "code_sites": sites, "wave": wave,
                      "options": options, "checklist": checklist, "needs_human": True})
        waves[wave] = waves.get(wave, 0) + 1
    items.sort(key=lambda i: ({"A": 0, "B": 1, "C": 2}[i["wave"]], i["component"].lower()))
    return {"schema": SCHEMA, "disclaimer": DISCLAIMER, "computed_on_read": False,
            "source_available": bool(root), "items": items, "waves": waves}
