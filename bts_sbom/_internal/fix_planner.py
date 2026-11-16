# vendored from common/fix_planner.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Fix planner (Tier 0-4) — the "suggested remediation" a commercial SCA emits, but
holding AutoGuard's "suggestions only, never edit files" discipline.

For each vulnerable component it computes the MINIMAL SAFE VERSION that clears all
of that component's in-scope CVEs (the highest fixed version required), flags a
likely-breaking MAJOR bump, orders by exploit-aware priority (reachable/P0 first),
and — only when explicitly asked (`emit_patch`) — renders a manifest version-bump
DIFF as text for the human to apply. It never writes to disk and never auto-commits.

Pure logic over CveVulnerability objects; uses version_cmp for ordering.
"""
from typing import List, Dict, Any, Optional

from bts_sbom._internal import version_cmp

_SUPPRESSED = {"not_affected", "false_positive", "accepted", "resolved"}
_PRIORITY_RANK = {"P0": 0, "P1": 1, "P2": 2, "P3": 3, "P4": 4}


def _major(v: str) -> Optional[str]:
    import re
    for run in re.split(r"[._\-+~:]", str(v or "")):
        m = re.match(r"\d+", run)
        if m:
            return m.group(0)
    return None


def _highest(versions: List[str]) -> Optional[str]:
    best = None
    for v in versions:
        if not v:
            continue
        if best is None or version_cmp.gt(v, best):
            best = v
    return best


def plan_fixes(vulns: List[Any], include_suppressed: bool = False) -> List[Dict[str, Any]]:
    """Group findings per component and produce a ranked list of fix plans.

    Each plan: {component, ecosystem, current_version, safe_version, status,
    clears[], uncleared[], major_bump, reachable, kev, max_priority}. status is
    'upgrade' (a safe version exists) or 'no_safe_upgrade' (no fixed version known
    for at least one CVE — reported honestly, not faked)."""
    groups: Dict[tuple, Dict[str, Any]] = {}
    for v in vulns:
        if not include_suppressed and getattr(v, "triage_status", "open") in _SUPPRESSED:
            continue
        key = (str(getattr(v, "package_name", "")).lower(), getattr(v, "ecosystem", "generic"))
        g = groups.setdefault(key, {
            "component": getattr(v, "package_name", ""),
            "ecosystem": getattr(v, "ecosystem", "generic"),
            "current_version": getattr(v, "package_version", ""),
            "fixed": [], "clears": [], "uncleared": [],
            "kev": 0, "reachable": False, "max_priority": "P4",
        })
        cve = getattr(v, "cve_id", "?")
        fv = getattr(v, "fixed_version", None)
        if fv:
            g["fixed"].append(fv)
            g["clears"].append(cve)
        else:
            g["uncleared"].append(cve)
        if getattr(v, "kev", False):
            g["kev"] += 1
        if getattr(v, "symbol_reachability", "") == "reachable" or getattr(v, "reachability", "") == "reachable":
            g["reachable"] = True
        label = getattr(v, "priority_label", "P4") or "P4"
        if _PRIORITY_RANK.get(label, 4) < _PRIORITY_RANK.get(g["max_priority"], 4):
            g["max_priority"] = label

    plans = []
    for g in groups.values():
        safe = _highest(g["fixed"])
        # A clean fix requires EVERY in-scope CVE to have a known fixed version.
        status = "upgrade" if (safe and not g["uncleared"]) else \
                 ("partial_upgrade" if safe else "no_safe_upgrade")
        cur_major, safe_major = _major(g["current_version"]), _major(safe) if safe else None
        major_bump = bool(safe and cur_major and safe_major and cur_major != safe_major)
        plans.append({
            "component": g["component"], "ecosystem": g["ecosystem"],
            "current_version": g["current_version"], "safe_version": safe,
            "status": status,
            "clears": sorted(set(g["clears"])),
            "uncleared": sorted(set(g["uncleared"])),
            "cve_count": len(set(g["clears"]) | set(g["uncleared"])),
            "major_bump": major_bump,
            "breaking_risk": "high" if major_bump else "low",
            "reachable": g["reachable"], "kev": g["kev"],
            "max_priority": g["max_priority"],
        })

    plans.sort(key=lambda p: (
        _PRIORITY_RANK.get(p["max_priority"], 4),
        0 if p["reachable"] else 1, -p["kev"], -p["cve_count"],
    ))
    return plans


# ── opt-in manifest patch rendering (text diff only — never written to disk) ──

def emit_requirements_patch(plan: Dict[str, Any], manifest_text: str) -> Optional[str]:
    """Render a unified-diff-style bump for a requirements.txt line. Returns None if
    the component isn't pinned in the file or has no safe version."""
    import re
    if not plan.get("safe_version"):
        return None
    comp = plan["component"].lower()
    for line in manifest_text.splitlines():
        m = re.match(r"^\s*([A-Za-z0-9._-]+)\s*==\s*([^\s#]+)", line)
        if m and m.group(1).lower() == comp:
            old = line.rstrip()
            new = f"{m.group(1)}=={plan['safe_version']}"
            return (f"--- requirements.txt\n+++ requirements.txt\n"
                    f"-{old}\n+{new}\n")
    return None


def emit_patch(plan: Dict[str, Any], manifest_text: str, ecosystem: str = "pypi") -> Optional[str]:
    """Dispatch to the ecosystem's manifest patch renderer (opt-in). Only pypi
    (requirements.txt) is rendered today; others return None (honest — no fake diff)."""
    if ecosystem in ("pypi", "python"):
        return emit_requirements_patch(plan, manifest_text)
    return None
