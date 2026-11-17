# round-2 engine feature E4 (REA 21 §7) — new module, stdlib-only.
"""
Guided remediation from OSV records (deps.dev "depup" pattern).

For one OSV vulnerability record and an installed version, suggest the
MINIMAL `fixed` version that clears the vulnerability:

  suggest_fixes(vuln, ecosystem, current="1.2.5")
    -> [{"package": "requests", "current": "1.2.5",
         "fixed_suggestion": "1.2.8", "constraint_source": "affected[0].ranges[0]
         .events[1].fixed (introduced 0, fixed 1.2.8)"}]

Selection rules (honest, deterministic):
  * one row per ``affected[]`` entry (per affected package);
  * candidates are the ``fixed`` events of that entry's ranges;
  * when `current` is given, candidates are filtered to those >= current
    under the ECOSYSTEM ordering (``version_match.eco_compare``: PEP 440 /
    SemVer / tolerant fallback) and the SMALLEST eligible one wins —
    the first version that both clears the advisory and does not skip
    more than necessary;
  * when `current` is None (record-only use), the smallest recorded
    `fixed` overall is suggested and `current` stays None;
  * ranges that end in ``last_affected`` with NO `fixed` event anywhere
    in the entry produce ``fixed_suggestion: None`` with
    ``constraint_source: "no-fixed-event"`` — a fix CANNOT be claimed
    from a last_affected bound (honesty: the advisory names no fix);
  * if every recorded `fixed` is < `current` (the version matched via an
    explicit versions list or a last_affected window), the row reports
    ``fixed_suggestion: None`` with ``constraint_source:
    "no-fixed-ge-current"`` — suggesting a downgrade would be wrong.

Ordering caveat (disclosed): ``eco_compare`` falls back to the tolerant
generic comparator when either version string is unparsable under the
ecosystem's grammar; such comparisons are best-effort ordering, not
spec-exact.

The scan integration lives in ``remediation_for_result``: it walks a scan
result (the ``results[].packages[].vulnerabilities`` shape) and emits one
deduplicated row per (advisory, affected-package). The CLI wires it as
``bts-sbom scan``'s ``remediation`` block (disable with
``--no-remediation``). Suggestions are ADVISORY ONLY — nothing here edits
a manifest.
"""
from typing import Any, Dict, List, Optional, Tuple

from bts_sbom._internal.version_match import eco_compare, family_for

SCHEMA = "bts-remediation/1"


def iter_fix_bounds(vuln: dict, name: Optional[str] = None
                    ) -> List[Dict[str, Any]]:
    """Collect the `fixed` events of an OSV record, optionally scoped to one
    package name. Each item: {package, ecosystem, fixed, introduced, source}."""
    out: List[Dict[str, Any]] = []
    for ai, aff in enumerate(vuln.get("affected", []) or []):
        pkg = aff.get("package", {}) or {}
        pkg_name = str(pkg.get("name", ""))
        if name is not None and pkg_name.lower() != str(name).lower():
            continue
        eco = str(pkg.get("ecosystem", "") or "")
        for ri, rng in enumerate(aff.get("ranges", []) or []):
            if str(rng.get("type") or "").upper() == "GIT":
                continue                         # a GIT range's "fixed" is a commit SHA, never an installable version
            introduced = "0"
            for ei, ev in enumerate(rng.get("events", []) or []):
                if not isinstance(ev, dict):
                    continue
                if "introduced" in ev:
                    introduced = str(ev.get("introduced") or "0")
                elif "fixed" in ev:
                    out.append({
                        "package": pkg_name, "ecosystem": eco,
                        "fixed": str(ev.get("fixed") or ""),
                        "introduced": introduced,
                        "source": "affected[%d].ranges[%d].events[%d].fixed"
                                  % (ai, ri, ei),
                    })
    return [b for b in out if b["fixed"]]


def suggest_fixes(vuln: dict, ecosystem: str,
                  current: Optional[str] = None) -> List[Dict[str, Any]]:
    """Per affected package: the minimal `fixed` version >= `current` (or the
    smallest recorded fix when `current` is None). Never raises on malformed
    records; malformed entries yield honest no-fix rows instead of guesses."""
    rows: List[Dict[str, Any]] = []
    for ai, aff in enumerate(vuln.get("affected", []) or []):
        pkg = aff.get("package", {}) or {}
        pkg_name = str(pkg.get("name", "") or "")
        if not pkg_name:
            continue
        aff_eco = str(pkg.get("ecosystem", "") or ecosystem or "")
        fam = family_for(aff_eco)
        bounds: List[Tuple[Dict[str, Any], str]] = []
        has_any_bound = False
        for ri, rng in enumerate(aff.get("ranges", []) or []):
            if str(rng.get("type") or "").upper() == "GIT":
                continue                         # commit SHAs are not versions (see iter_fix_bounds)
            introduced = "0"
            for ei, ev in enumerate(rng.get("events", []) or []):
                if not isinstance(ev, dict):
                    continue
                if "introduced" in ev:
                    introduced = str(ev.get("introduced") or "0")
                elif "fixed" in ev:
                    fixed = str(ev.get("fixed") or "")
                    if fixed:
                        has_any_bound = True
                        bounds.append((
                            {"fixed": fixed, "introduced": introduced},
                            "affected[%d].ranges[%d].events[%d].fixed "
                            "(introduced %s, fixed %s)" % (ai, ri, ei,
                                                           introduced, fixed)))
        row: Dict[str, Any] = {
            "package": pkg_name,
            "current": current,
            "fixed_suggestion": None,
            "constraint_source": "no-fixed-event",
            "ecosystem": aff_eco,
            "ordering": fam,
        }
        if not has_any_bound:
            # last_affected-only windows (or empty events): the advisory names
            # no fix — claim none.
            rows.append(row)
            continue
        if current:
            eligible = [(b, src) for (b, src) in bounds
                        if eco_compare(b["fixed"], current, aff_eco) >= 0]
            if not eligible:
                row["constraint_source"] = "no-fixed-ge-current"
                row["note"] = ("every recorded fixed bound sorts below the "
                               "installed version; no upgrade suggestion is "
                               "honestly derivable from this record")
                rows.append(row)
                continue
        else:
            eligible = bounds
        best_pair = eligible[0]
        for pair in eligible[1:]:
            if eco_compare(pair[0]["fixed"], best_pair[0]["fixed"],
                           aff_eco) < 0:
                best_pair = pair
        row["fixed_suggestion"] = best_pair[0]["fixed"]
        row["constraint_source"] = best_pair[1]
        rows.append(row)
    return rows


def remediation_for_result(result: Dict[str, Any]) -> Dict[str, Any]:
    """Walk a scan result (results[].packages[].vulnerabilities shape) and
    build the remediation block: one deduplicated suggestion per (advisory,
    affected-package), using the installed version as `current`."""
    suggestions: List[Dict[str, Any]] = []
    seen: set = set()
    for src in result.get("results", []) or []:
        for pe in src.get("packages", []) or []:
            pk = pe.get("package", {}) or {}
            eco = str(pk.get("ecosystem", "") or "")
            cur = str(pk.get("version", "") or "") or None
            for v in pe.get("vulnerabilities", []) or []:
                vid = str(v.get("id", "") or "")
                for row in suggest_fixes(v, eco, current=cur):
                    key = (vid, row["package"], row["ecosystem"],
                           row["fixed_suggestion"], row["constraint_source"])
                    if key in seen:
                        continue
                    seen.add(key)
                    suggestions.append({
                        "osv_id": vid,
                        "aliases": sorted(set(v.get("aliases", []) or [])),
                        "ecosystem": row["ecosystem"],
                        "package": row["package"],
                        "current": row["current"],
                        "fixed_suggestion": row["fixed_suggestion"],
                        "constraint_source": row["constraint_source"],
                        "ordering": row["ordering"],
                        **({"note": row["note"]} if row.get("note") else {}),
                    })
    suggestions.sort(key=lambda s: (s["osv_id"], s["package"], s["ecosystem"]))
    return {"schema": SCHEMA,
            "suggestion_count": len(suggestions),
            "suggestions": suggestions}


__all__ = ["SCHEMA", "iter_fix_bounds", "suggest_fixes",
           "remediation_for_result"]
