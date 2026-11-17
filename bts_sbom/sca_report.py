# vendored from sca_guard/sca_report.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
End-to-end OSS composition report: discover dependencies -> resolve licenses
(deps.dev) -> query OSV.dev for vulnerabilities -> emit a CycloneDX SBOM (with
embedded vulnerabilities) + a license-risk analysis + guided remediation + a
human-readable markdown report.

Ties together the existing honest plumbing (OsvScanner, common.license_utils,
common.depsdev, common.sbom) into one call the API/UI can render and download.
Nothing is fabricated: unqueried packages stay flagged, unresolved licenses stay
UNKNOWN, and empty results are reported as such — never as a verified pass.
"""
from typing import Dict, Any, List, Optional

from bts_sbom.osvscanner import OsvScanner, _osv_severity, _fixed_version, normalize_ecosystem
from bts_sbom._internal import sbom as sbom_mod


def _osv_url(vuln: Dict[str, Any]) -> Optional[str]:
    vid = vuln.get("id", "")
    for r in vuln.get("references", []) or []:
        u = r.get("url", "")
        if "osv.dev" in u or "/advisories/" in u or "nvd.nist.gov" in u:
            return u
    return f"https://osv.dev/vulnerability/{vid}" if vid else None


def _mismatch_alarm(packages: List[Dict[str, Any]],
                    source_licenses: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Compare registry-declared licenses (deps.dev) with in-tree detected licenses.

    Returns a list of alarm dicts when the declared and detected categories differ
    significantly — e.g. package declared MIT but LICENSE file contains GPL text.
    Never fabricates: if either side is unavailable the comparison is skipped.
    """
    from bts_sbom._internal.license_utils import classify_license

    # Build a per-file detected-license index from source_licenses findings
    detected: Dict[str, str] = {}  # file_stem -> license
    for f in source_licenses.get("findings", []) or []:
        lic = f.get("license", "")
        try:
            conf = float(f.get("confidence", 0) or 0)
        except (TypeError, ValueError):
            # non-numeric confidence ("high"/"certain" from a detector) counts
            # as confident — the license string itself is present
            conf = 1.0 if f.get("confidence") else 0.0
        if lic and conf >= 0.6:
            path = f.get("file", "")
            stem = path.lower().replace("\\", "/")
            detected[stem] = lic

    alarms: List[Dict[str, Any]] = []
    for p in packages:
        declared = p.get("license") or p.get("dep_license") or ""
        if not declared or declared.upper() in ("UNKNOWN", "NOASSERTION", ""):
            continue
        name = p.get("name", "")
        version = p.get("version", "")
        # Look for a license file near this package's source location
        src = (p.get("location") or "").lower().replace("\\", "/")
        pkg_dir = src.rsplit("/", 1)[0] if "/" in src else ""
        matched_detected = None
        for stem, det_lic in detected.items():
            if pkg_dir and stem.startswith(pkg_dir):
                matched_detected = det_lic
                break
        if not matched_detected:
            continue
        cat_declared = classify_license(declared)
        cat_detected = classify_license(matched_detected)
        # Alarm only when categories differ in a meaningful way
        _COPYLEFT = {"Strong Copyleft", "Network Copyleft", "Weak Copyleft"}
        _PERMISSIVE = {"Permissive"}
        def _group(cat: str) -> str:
            if cat in _COPYLEFT:
                return "copyleft"
            if cat in _PERMISSIVE:
                return "permissive"
            return "other"
        g_decl, g_det = _group(cat_declared), _group(cat_detected)
        if g_decl != g_det:
            severity = "HIGH" if g_det == "copyleft" and g_decl == "permissive" else "MEDIUM"
            alarms.append({
                "name": name, "version": version,
                "declared": declared, "declared_category": cat_declared,
                "detected": matched_detected, "detected_category": cat_detected,
                "severity": severity,
                "detail": (f"Registry says '{declared}' ({cat_declared}) but LICENSE file "
                           f"contains '{matched_detected}' ({cat_detected}). "
                           f"Verify which governs your distribution."),
            })
    return alarms


def _findings_from_result(result: Dict[str, Any], ref_index, loc_map=None) -> List[Dict[str, Any]]:
    loc_map = loc_map or {}
    findings: List[Dict[str, Any]] = []
    for src in result.get("results", []):
        for pe in src.get("packages", []):
            pk = pe.get("package", {})
            name, ver = pk.get("name", ""), pk.get("version", "")
            ref = ref_index.get((name.lower(), ver)) or f"pkg:{normalize_ecosystem(pk.get('ecosystem','')).lower()}/{name}@{ver}"
            location = loc_map.get((name.lower(), ver), "")
            for v in pe.get("vulnerabilities", []) or []:
                score, label, vector = _osv_severity(v)
                aliases = v.get("aliases", []) or []
                cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
                findings.append({
                    "ref": ref, "name": name, "version": ver,
                    "ecosystem": pk.get("ecosystem", ""),
                    "id": v.get("id", ""), "cve": cve, "aliases": aliases,
                    "score": score or None, "severity": label, "vector": vector,
                    "fixed": _fixed_version(v, name, ver),
                    "summary": v.get("summary") or v.get("details", "")[:200] or v.get("id", ""),
                    "url": _osv_url(v),
                    "location": location,
                    # advisory dates straight from the OSV record (vulnerability age)
                    "published": v.get("published") or None,
                    "modified": v.get("modified") or None,
                })
    _order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    findings.sort(key=lambda f: (_order.get(f["severity"], 4), -(f["score"] or 0), f["name"]))
    return findings


def _severity_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    s = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "total": len(findings)}
    for f in findings:
        s[f["severity"]] = s.get(f["severity"], 0) + 1
    s["vulnerable_packages"] = len({(f["name"], f["version"]) for f in findings})
    return s


def _priority_label(f: Dict[str, Any], epss_map: Dict[str, Dict]) -> str:
    """Return a triage priority string: PATCH NOW / HIGH / MEDIUM / LOW / UNKNOWN.

    A feed outage (epss_map entry with kev/epss == None, source "unavailable")
    is rendered as an honest UNKNOWN, never silently treated as "not KEV" /
    "zero EPSS" (which would deprioritize a possibly-critical CVE)."""
    cve = (f.get("cve") or "").upper()
    e = epss_map.get(cve, {})
    kev = e.get("kev", False)
    epss_score = e.get("epss", 0.0)
    sev = f.get("severity", "")
    if kev is None or epss_score is None:
        return "⚪ UNKNOWN"
    if kev:
        return "🔴 PATCH NOW"
    if epss_score >= 0.3 or sev == "CRITICAL":
        return "🟠 HIGH"
    if epss_score >= 0.1 or sev == "HIGH":
        return "🟡 MEDIUM"
    return "🟢 LOW"


def _intel_db_markdown(st: Optional[Dict[str, Any]]) -> str:
    """One honest line about the local vuln-intel DB — the offline equivalent
    of Snyk's 'tested using the DB of <date>' stamp. An absent DB is disclosed
    as such (the scan then ran on curated offline tables), never hidden."""
    if not st or st.get("error"):
        return "- Intel DB: _status unavailable_"
    if not st.get("available"):
        return ("- Intel DB: **not installed** — the platform bulk-intel DB is "
                "not part of bts-sbom; enrichment used the live EPSS/KEV API "
                "or the curated offline table")
    parts = []
    # 'osv' leads: it is the actual package->advisory lookup table (EPSS/KEV/
    # malware/vuln-meta are enrichment layers on top of it). Omitting it from
    # this disclosure line let a report look "healthy" on those four layers
    # while the underlying OSV corpus itself had never been imported.
    for key, label in (("osv", "OSV"), ("epss", "EPSS"), ("kev", "KEV"),
                       ("malware", "malware"), ("vuln_meta", "vuln-meta")):
        info = st.get(key) or {}
        age = info.get("age_days")
        age_s = f"{age:.1f}d old" if isinstance(age, (int, float)) else "never refreshed"
        flag = " **STALE**" if info.get("stale") else ""
        parts.append(f"{label} {info.get('count', 0)} rows ({age_s}{flag})")
    return "- Intel DB: " + " · ".join(parts)


def _markdown(target: str, packages, findings, sev, licenses, remediation, status,
              lic_enrich, epss_map: Optional[Dict] = None,
              mismatches: Optional[List[Dict]] = None,
              intel_status: Optional[Dict[str, Any]] = None) -> str:
    epss_map = epss_map or {}
    mismatches = mismatches or []
    out = [f"# OSS Composition Report — {target}", ""]
    kev_count = sum(1 for f in findings if epss_map.get((f.get("cve") or "").upper(), {}).get("kev"))
    unknown_count = sum(1 for f in findings
                         if epss_map.get((f.get("cve") or "").upper(), {}).get("kev") is None)
    out += [
        f"- Components: **{len(packages)}**",
        f"- Vulnerabilities: **{sev['total']}** "
        f"(CRITICAL {sev['CRITICAL']} · HIGH {sev['HIGH']} · MEDIUM {sev['MEDIUM']} · LOW {sev['LOW']} · UNKNOWN {sev['UNKNOWN']})",
        f"- Vulnerable components: **{sev['vulnerable_packages']}**",
        f"- CISA KEV (actively exploited): **{kev_count}**",
        f"- Licenses resolved (deps.dev): **{lic_enrich.get('resolved',0)}** new, "
        f"{lic_enrich.get('already_had',0)} pre-known, {lic_enrich.get('unresolved',0)} unresolved",
    ]
    if unknown_count:
        out.append(
            f"- WARNING: EPSS/KEV data **unavailable** for **{unknown_count}** CVE(s) "
            f"(feed outage, no offline data) — not counted as clean, treat as unknown risk"
        )
    if intel_status is not None:
        out.append(_intel_db_markdown(intel_status))
    out.append("")
    if findings:
        has_epss = bool(epss_map)
        out += ["## Vulnerabilities", ""]
        if has_epss:
            out.append("| Priority | Severity | OSV ID | CVE | EPSS | KEV | Package | Version | Fixed | Location |")
            out.append("|---|---|---|---|---|---|---|---|---|---|")
        else:
            out.append("| Severity | OSV ID | CVE | Package | Version | Fixed | Location |")
            out.append("|---|---|---|---|---|---|---|")
        for f in findings:
            sv = f"{f['severity']} {f['score']:.1f}" if f["score"] else f["severity"]
            cve = (f.get("cve") or "").upper()
            if has_epss:
                e = epss_map.get(cve, {})
                if e.get("kev") is None or e.get("epss") is None:
                    epss_str = "unknown"
                    kev_str = "unknown"
                else:
                    epss_str = f"{e['epss']:.3f}" if e.get("epss") else "-"
                    kev_str = "**KEV**" if e.get("kev") else "-"
                prio = _priority_label(f, epss_map)
                out.append(f"| {prio} | {sv} | {f['id']} | {f['cve']} | {epss_str} | {kev_str} | "
                           f"{f['name']} | {f['version']} | {f['fixed'] or '-'} | {f.get('location') or '-'} |")
            else:
                out.append(f"| {sv} | {f['id']} | {f['cve']} | {f['name']} | {f['version']} | "
                           f"{f['fixed'] or '-'} | {f.get('location') or '-'} |")
        out.append("")
    else:
        out += ["_No known vulnerabilities reported by OSV for the queried packages._", ""]

    if licenses and not licenses.get("error"):
        summ = licenses.get("summary", {})
        cc = summ.get("category_counts", {})
        out += ["## License analysis", ""]
        if cc:
            out.append("Categories: " + ", ".join(f"{k}={v}" for k, v in sorted(cc.items())))
            out.append("")
        for risk in licenses.get("findings", []) or []:
            out.append(f"- **{risk.get('severity','')}** — {risk.get('issue','')}: {risk.get('detail','')}")
        out.append("")

    if mismatches:
        out += ["## License mismatch alarms (declared vs. detected)", "",
                "| Severity | Package | Declared | Detected | Detail |",
                "|---|---|---|---|---|"]
        for m in mismatches:
            out.append(f"| {m['severity']} | {m['name']} {m.get('version','')} | "
                       f"{m['declared']} ({m['declared_category']}) | "
                       f"{m['detected']} ({m['detected_category']}) | {m['detail']} |")
        out.append("")

    if remediation:
        out += ["## Guided remediation (suggestions only)", "",
                "| Component | Current | Safe upgrade | Clears |", "|---|---|---|---|"]
        for p in remediation:
            out.append(f"| {p['component']} | {p['current_version']} | "
                       f"{p.get('safe_version') or '-'} | {len(p.get('clears', []))} |")
        out.append("")
    # honest status footer
    unq = status.get("unqueried", 0) + status.get("offline_no_data", 0)
    foot = (f"_Scanned {status.get('packages',0)} package(s) across {status.get('sources',0)} "
            f"source(s), mode={status.get('mode','?')}._")
    if unq:
        foot += f" _WARNING: {unq} package(s) NOT authoritatively queried — not verified clean._"
    out.append(foot)
    return "\n".join(out)


def _locate(name: str, version: str, lines: List[str]):
    """Best-effort line where a package is declared in its manifest. Prefers a line
    carrying BOTH the name and the version; falls back to the first name match.
    Returns a 1-based line number or None (never fabricated)."""
    last = (name or "").lower().split("/")[-1].split(":")[-1]
    if not last:
        return None
    ver = (version or "").lower()
    first = None
    for i, line in enumerate(lines, 1):
        low = line.lower()
        if last in low:
            if ver and ver in low:
                return i
            if first is None:
                first = i
    return first


def _stamp_epss(f: Dict[str, Any], epss: float, pct: float, kev: bool, source: str) -> None:
    f["epss"] = epss
    f["epss_percentile"] = pct
    f["kev"] = kev
    f["epss_source"] = source


def _enrich_findings_epss_kev(findings: List[Dict[str, Any]], offline: bool,
                              live_fn=None, fallback_fn=None) -> Dict[str, Dict]:
    """Stamp EPSS/KEV onto findings in place and return {CVE: {epss, percentile, kev}}.

    Order: live API (skipped when offline) -> offline fallback (bulk intel DB, then
    the curated table) -> honest "none"/"unavailable". Every finding gets epss,
    epss_percentile, kev and epss_source ("live-api" | "bulk-intel-db" |
    "offline-table" | "none" | "unavailable"). A CVE the curated table knows
    nothing about is labeled "none" (checked here), never presented as real
    zero-risk data. live_fn (epss_kev.enrich_cves by default) already performs
    its own outage-aware offline fallback and labels its own "source" per CVE
    (see epss_kev.py); this function trusts that label instead of overwriting
    it with "live-api" — a live-feed outage surfaces here as
    epss=None/kev=None/source="unavailable" (never a fabricated 0.0/False),
    which _stamp_epss()/_priority_label() render as an honest "unknown".
    """
    import logging
    log = logging.getLogger("sca_report")
    epss_map: Dict[str, Dict] = {}

    ids: List[str] = []
    for f in findings:
        cu = (f.get("cve") or "").upper()
        if cu.startswith("CVE-") and cu not in ids:
            ids.append(cu)

    live: Dict[str, Dict] = {}
    if ids and not offline:
        try:
            if live_fn is None:
                from bts_sbom._internal.epss_kev import enrich_cves as live_fn
            live = live_fn(list(ids)) or {}
        except Exception as e_live:
            log.warning("EPSS/KEV live enrichment failed, using offline fallback: %s", e_live)
            live = {}
        if not live:
            log.warning("EPSS/KEV live enrichment returned no data, using offline fallback")

    resolved: Dict[str, Dict] = {}
    for cu in ids:
        e = live.get(cu) if isinstance(live, dict) else None
        if e and e.get("source") == "unavailable":
            # Live call ran but the feed(s) are down AND the offline table has
            # nothing for this CVE either: an honest unknown, not a fallback
            # to the (possibly stale) local fallback_fn -- fetch_fn already
            # tried the real offline table internally.
            resolved[cu] = {"epss": None, "percentile": None, "kev": None,
                            "source": "unavailable", "reason": e.get("reason", "")}
            continue
        if e and e.get("source"):
            # live_fn (epss_kev.enrich_cves) already resolved this CVE, be it
            # from the live feed or its own internal offline fallback -- trust
            # its label instead of relabeling everything "live-api".
            resolved[cu] = {"epss": e.get("epss", 0.0), "percentile": e.get("percentile", 0.0),
                            "kev": bool(e.get("kev", False)), "source": e.get("source")}
            continue
        if e:
            # Back-compat: a custom live_fn stub without a "source" key is
            # assumed to be genuine live data.
            resolved[cu] = {"epss": e.get("epss", 0.0), "percentile": e.get("percentile", 0.0),
                            "kev": bool(e.get("kev", False)), "source": "live-api"}
            continue
        try:
            if fallback_fn is None:
                from bts_sbom._internal.epss_offline import epss_offline_lookup as fallback_fn
            r = fallback_fn(cu) or {}
            epss = r.get("epss", 0.0) or 0.0
            kev = bool(r.get("kev", False))
            src = r.get("source") or "none"
            if src == "offline-table" and epss == 0.0 and not kev:
                src = "none"  # curated table has no entry: do not present as real data
            resolved[cu] = {"epss": epss, "percentile": r.get("percentile", 0.0) or 0.0,
                            "kev": kev, "source": src}
        except Exception as e_fb:
            log.warning("EPSS/KEV offline fallback failed for %s: %s", cu, e_fb)
            resolved[cu] = {"epss": 0.0, "percentile": 0.0, "kev": False, "source": "none"}

    for f in findings:
        cu = (f.get("cve") or "").upper()
        r = resolved.get(cu)
        if r is None:
            _stamp_epss(f, 0.0, 0.0, False, "none")
            continue
        _stamp_epss(f, r["epss"], r["percentile"], r["kev"], r["source"])
        epss_map[cu] = {"epss": r["epss"], "percentile": r["percentile"], "kev": r["kev"]}
    return epss_map


def _ntia_brief(ev: Dict[str, Any]) -> Dict[str, Any]:
    """Compact NTIA result: overall score/grade plus per-element percentage."""
    return {"status": ev.get("status"), "total_score": ev.get("total_score"),
            "grade": ev.get("grade"), "reason": ev.get("reason"),
            "elements": {e["id"]: e["compliance_pct"] for e in ev.get("elements", [])},
            "weak": [e["id"] for e in ev.get("elements", [])
                     if e.get("status") in ("FAIL", "WARN")]}


def build_report(target_dir: str, timestamp: str, offline: bool = False,
                 source_label: str = "", sbom_author: str = "") -> Dict[str, Any]:
    """Run the full pipeline over a directory and return the composition report.

    ``sbom_author`` (optional) names the author of the SBOM data (NTIA "SBOM
    Author"); without it the document honestly carries only the generating tool."""
    import os
    from bts_sbom._internal import depsdev, license_utils

    scanner = OsvScanner(offline=offline)
    # 1) discover packages (with purl) for the SBOM
    sources = scanner.discover(target_dir)
    packages: List[Dict[str, Any]] = [p for s in sources for p in s.packages]

    # 1b) resolve each package's declaration site (manifest file : line) — real provenance
    loc_map: Dict = {}
    for s in sources:
        try:
            rel = os.path.relpath(s.path, target_dir).replace("\\", "/")
        except Exception:
            rel = os.path.basename(s.path)
        try:
            with open(s.path, "r", encoding="utf-8", errors="replace") as fh:
                lines = fh.read().splitlines()
        except Exception:
            lines = []
        for p in s.packages:
            ln = _locate(p.get("name", ""), p.get("version", ""), lines)
            loc = f"{rel}:{ln}" if ln else rel
            p["source_file"] = rel
            p["source_line"] = ln
            p["location"] = loc
            loc_map[(p.get("name", "").lower(), p.get("version", ""))] = loc

    # 2) resolve licenses (deps.dev) — best-effort, disclosed
    lic_enrich = depsdev.enrich(packages, offline=offline)

    # 2b) SBOM provenance: supplier (declared / curated / namespace - with its
    #     basis) and, online only, the registry-reported author + download URL.
    from bts_sbom._internal import supplier_resolve, registry_meta
    for p in packages:
        supplier_resolve.apply(p)
    registry_enrichment = registry_meta.enrich(packages, offline=offline)

    # 3) query OSV for vulnerabilities (+ guided remediation)
    result = scanner.scan(target_dir, guided_remediation=True)
    status = result.get("scan_status", {})

    # 4) license risk analysis over the enriched package set
    try:
        licenses = license_utils.analyze_licenses(packages)
    except Exception as e:
        licenses = {"error": str(e)}

    # 4a) compliance risk score (0-100, grade A-F)
    try:
        license_risk_score = license_utils.compute_compliance_risk_score(packages, licenses)
    except Exception as e:
        license_risk_score = {
            "score": 0,
            "grade": "A",
            "recommendation": "Low license risk — no analysis data available.",
            "breakdown": {},
            "category_counts": {},
            "total_components": 0,
            "conflict_count": 0,
            "error": str(e),
        }

    # 4b) FOSSology-style source-file license DETECTION (evidence: file:line).
    #     Complements the deps.dev DECLARED licenses above with what is actually
    #     present in the tree's own files (SPDX tags + license notice text +
    #     copyrights). Nothing guessed: a file with no license text yields nothing.
    try:
        from bts_sbom._internal import license_scan
        source_licenses = license_scan.scan_tree(target_dir)
    except Exception as e:
        source_licenses = {"error": str(e), "findings": [], "licenses": [],
                           "distinct_licenses": [], "license_files": [], "copyrights": [],
                           "policy": {}, "policy_findings": [], "notes": [f"scan error: {e}"]}

    # 5) build the SBOM + attach vulnerabilities
    label = source_label or target_dir
    _authors = [sbom_author] if (sbom_author or "").strip() else None
    doc, ref_index = sbom_mod.build_sbom(packages, label, timestamp, authors=_authors)
    findings = _findings_from_result(result, ref_index, loc_map)
    sbom_mod.attach_vulnerabilities(doc, findings)
    # carry the declaration site into the SBOM components (CycloneDX properties)
    _loc_by_ref = {ref_index.get((p.get("name", "").lower(), p.get("version", ""))): p.get("location")
                   for p in packages}
    for comp in doc.get("components", []):
        loc = _loc_by_ref.get(comp.get("bom-ref"))
        if loc:
            comp.setdefault("properties", []).append({"name": "sca:location", "value": loc})

    sev = _severity_summary(findings)
    remediation = result.get("experimental_remediation") or []
    # 5b) SPDX 2.3 SBOM (ISO 21434 / UN R155 friendly) + license-expression
    #     verification (canonicalize declared licenses, flag deprecated/invalid ids).
    try:
        from bts_sbom._internal import spdx_sbom, license_norm
        spdx_doc = spdx_sbom.build_spdx(packages, label, timestamp, vulns=findings,
                                        authors=_authors)
        license_verification = license_norm.verify_packages(packages)
    except Exception as e:
        spdx_doc = {"error": str(e)}
        license_verification = {"error": str(e), "summary": {}, "issues": []}

    # 6) EPSS + CISA KEV enrichment for triage prioritization
    epss_map: Dict[str, Any] = _enrich_findings_epss_kev(findings, offline)

    # SC-2: Supply-chain substitution-risk analysis (typosquatting / dep-confusion / homoglyph)
    try:
        from bts_sbom.supply_chain import SupplyChainAnalyzer
        _sc = SupplyChainAnalyzer()
        _sc_findings = _sc.analyze(packages)
        _sc_score = _sc.compute_risk_score(_sc_findings, len(packages))
        _sc_level = (
            "SAFE" if _sc_score < 0.05 else
            "MODERATE" if _sc_score < 0.20 else
            "HIGH" if _sc_score < 0.50 else "CRITICAL"
        )
        supply_chain = {
            "findings": _sc_findings,
            "risk_score": round(_sc_score, 3),
            "risk_level": _sc_level,
        }
    except Exception as _e_sc:
        import logging as _logging
        _logging.getLogger("sca_report").warning("supply-chain analysis failed: %s", _e_sc)
        supply_chain = {"findings": [], "risk_score": 0.0, "risk_level": "SAFE",
                        "error": str(_e_sc)}

    # SC-4: VEX status per finding (honest defaults derived from OSV data)
    # fixed version present -> "fixed"; unqueried -> "under_investigation"; else "affected"
    for f in findings:
        if f.get("fixed"):
            f["vex_status"] = "fixed"
        elif (f.get("id", "").startswith("UNQUERIED:") or
              status.get("unqueried", 0) > 0 and not f.get("url")):
            f["vex_status"] = "under_investigation"
        else:
            f["vex_status"] = "affected"

    # 7) Declared-vs-detected license mismatch alarm
    mismatches = _mismatch_alarm(packages, source_licenses)

    # 7b) Intel-DB age disclosure (the operator owns the DB, so the report
    #     states its age honestly instead of implying cloud freshness).
    # common.bulk_intel (the platform's offline intel-DB layer, bound to
    # config.settings) is deliberately NOT vendored into bts_sbom -- the
    # report discloses that absence instead of faking a DB status.
    intel_status = {"available": False,
                    "note": "bulk intel DB is a platform-only layer; "
                            "bts-sbom runs without it (EPSS/KEV use the live "
                            "API or the curated offline table)"}

    # 7c) SBOM quality against the NTIA minimum elements - computed from the two
    #     documents just built (the same evaluator the /api/sca/ntia-compliance
    #     endpoint uses), so a gap shows up here instead of in a customer audit.
    try:
        from bts_sbom._internal import ntia_check
        sbom_quality = {"cyclonedx": _ntia_brief(ntia_check.evaluate(doc)),
                        "spdx": _ntia_brief(ntia_check.evaluate(spdx_doc))}
    except Exception as _e_q:
        sbom_quality = {"error": str(_e_q)}

    md = _markdown(label, packages, findings, sev, licenses, remediation, status,
                   lic_enrich, epss_map=epss_map, mismatches=mismatches,
                   intel_status=intel_status)
    md += _source_license_markdown(source_licenses)

    return {
        "source": label,
        "packages": packages,
        "components": len(doc.get("components", [])),
        "findings": findings,
        "severity": sev,
        "licenses": licenses,
        "license_risk_score": license_risk_score,
        "license_enrichment": lic_enrich,
        "license_verification": license_verification,
        "source_licenses": source_licenses,
        "license_mismatches": mismatches,
        "epss_enrichment": epss_map,
        "intel_db": intel_status,           # DB age/staleness disclosure (P1-B2)
        "registry_enrichment": registry_enrichment,   # SBOM author/download lookups (disclosed)
        "sbom_quality": sbom_quality,       # NTIA minimum-elements score per format
        "supply_chain": supply_chain,       # SC-2
        "remediation": remediation,
        "scan_status": status,
        "notes": scanner.notes,
        "sbom": doc,
        "spdx_sbom": spdx_doc,
        "report_markdown": md,
    }


def _source_license_markdown(sl: Dict[str, Any]) -> str:
    """Markdown for the source-file license detection section (FOSSology-style)."""
    if not sl or sl.get("error"):
        return f"\n\n## Source-file licenses\n\n_scan unavailable: {sl.get('error') if sl else 'n/a'}_\n"
    lics = sl.get("licenses", []) or []
    lines = ["\n\n## Source-file licenses (detected in-tree, with evidence)",
             f"\nScanned **{sl.get('files_scanned', 0)}** text files. "
             f"Detected licenses are grounded in actual file bytes (SPDX tags + license notice text), "
             f"not registry metadata.\n"]
    if lics:
        lines.append("| License | Category | Files | Confidence |")
        lines.append("|---|---|---|---|")
        for e in lics:
            lines.append(f"| {e['license']} | {e['category']} | {e['count']} | {e.get('best_confidence','')} |")
    else:
        lines.append("_No license text or SPDX tag detected in the scanned files._")
    ev = [f for f in sl.get("findings", []) if f.get("kind") != "spdx-tag"][:12]
    tags = [f for f in sl.get("findings", []) if f.get("kind") == "spdx-tag"][:12]
    if tags or ev:
        lines.append("\n**Evidence (file:line):**\n")
        for f in tags + ev:
            lines.append(f"- `{f['file']}:{f['line']}` — **{f['license']}** ({f['kind']}, {f['confidence']})")
    if sl.get("copyrights"):
        lines.append("\n**Copyright holders:**\n")
        for c in sl["copyrights"][:15]:
            lines.append(f"- {c['holder']} — `{c['file']}:{c['line']}`")
    for n in sl.get("notes", []) or []:
        lines.append(f"\n> {n}")
    return "\n".join(lines) + "\n"
