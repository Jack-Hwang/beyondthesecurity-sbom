# vendored from common/sarif.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
SARIF 2.1.0 export for static-analysis findings.

SARIF is the OASIS-standard interchange format for static-analysis results;
GitHub code scanning, GitLab, Azure DevOps and most IDEs ingest it directly.
Emitting SARIF makes AutoGuard's MISRA/security findings consumable by the same
tooling that Coverity/CodeQL feed — a baseline expectation for a commercial tool.

Maps a MisraViolation list to one SARIF run with:
  - tool.driver.rules    : unique rule descriptors (rule_id, CWE tags)
  - results              : one per finding (ruleId, level, message, location)
Severity → SARIF level:  Mandatory→error, Required→warning, Advisory→note.
"""
import os
import json
import logging
from typing import List, Any, Optional, Dict

# (config.settings decoupled for the standalone package: output dir is
# env-overridable, defaulting to ./reports under the current directory)
REPORTS_DIR = os.environ.get("BTS_SBOM_REPORTS_DIR") or os.path.join(os.getcwd(), "reports")

logger = logging.getLogger("SARIF")

_LEVEL = {"mandatory": "error", "required": "warning", "advisory": "note"}

# Standard display name -> SARIF rule-ID prefix (per the integration guide §6).
_STD_PREFIX = {
    "MISRA C:2012": "MISRA-C-2012",
    # When service.py relabels C:2012 findings to C:2025 (misra_c2025 target),
    # the SARIF ruleId must reflect the new edition label, not fall back to the
    # raw rule_id without a prefix.
    "MISRA C:2025": "MISRA-C-2025",
    "MISRA C++:2023": "MISRA-CPP-2023",
    "AUTOSAR C++14": "AUTOSAR",
    "KISA Unix/Linux": "KISA",
}


def _std_rule_id(v: Any) -> str:
    """Standard-qualified SARIF ruleId, e.g. AUTOSAR-A5-2-4 or
    MISRA-CPP-2023-Rule-8.2.5. Falls back to the raw rule_id."""
    rid = v.rule_id or "unknown"
    prefix = _STD_PREFIX.get(getattr(v, "standard", "") or "")
    if not prefix:
        return rid
    token = rid.replace(" ", "-")
    # AUTOSAR ids already look like A5-2-4; MISRA ids look like "Rule 8.2.5".
    return f"{prefix}-{token}"


def _to_uri(path: str) -> str:
    return "file:///" + os.path.abspath(path).replace("\\", "/").lstrip("/")


def build_sarif(violations: List[Any], tool_name: str = "AutoGuard MISRA Guard",
                tool_version: str = "1.0.0", include_fp: bool = False) -> dict:
    rules: Dict[str, dict] = {}
    results = []

    for v in violations:
        if v.false_positive and not include_fp:
            continue
        rid = _std_rule_id(v)
        if rid not in rules:
            tags = ["misra"] if getattr(v, "finding_type", "misra") == "misra" else ["security"]
            std = getattr(v, "standard", None)
            if std:
                tags.append(std)
            cwe = getattr(v, "cwe", None)
            if cwe:
                tags.append(cwe)
            rules[rid] = {
                "id": rid,
                "name": rid.replace(" ", "_"),
                "shortDescription": {"text": rid},
                "properties": {
                    "tags": tags,
                    "engine": getattr(v, "engine", "cppcheck"),
                    "security-severity": _security_severity(v),
                },
            }
            if cwe:
                rules[rid].setdefault("relationships", []).append({
                    "target": {"id": cwe, "toolComponent": {"name": "CWE"}},
                })

        result = {
            "ruleId": rid,
            "level": _LEVEL.get(str(v.severity).lower(), "warning"),
            "message": {"text": v.description or rid},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": _to_uri(v.file)},
                    "region": {"startLine": max(1, int(v.line or 1))},
                }
            }],
            "properties": {
                "engine": getattr(v, "engine", "cppcheck"),
                "detected_by": getattr(v, "detected_by", None) or [],
                "verified": getattr(v, "verified", False),
                "confidence": getattr(v, "confidence", None),
                "cwe": getattr(v, "cwe", None),
                "is_new": getattr(v, "is_new", False),
                "suppressed": getattr(v, "suppressed", False),
            },
        }
        # A suppressed (documented-deviation) finding is annotated for SARIF
        # consumers that honor result.suppressions (GitHub hides these).
        if getattr(v, "suppressed", False) or getattr(v, "false_positive", False):
            result["suppressions"] = [{
                "kind": "external",
                "justification": getattr(v, "suppression_reason", None)
                or getattr(v, "rationale", None) or "documented deviation / false positive",
            }]
        # Interprocedural taint path → SARIF codeFlows (navigable in IDEs / GitHub
        # code scanning). Each step becomes a threadFlow location with its message.
        code_flow = _build_code_flow(v)
        if code_flow is not None:
            result["codeFlows"] = [code_flow]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": "https://autoguard.local",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _build_code_flow(v: Any) -> Optional[dict]:
    """Turn a finding's structured taint steps into one SARIF codeFlow.

    steps: [{"line": int, "desc": str}, ...] — all in the finding's file (the
    taint engine is single-translation-unit). SARIF nests
    codeFlow → threadFlows[] → locations[] → {location, message}."""
    steps = getattr(v, "taint_flow_steps", None)
    if not steps:
        return None
    uri = _to_uri(v.file)
    locations = []
    for step in steps:
        try:
            line = max(1, int(step.get("line", v.line or 1)))
        except (TypeError, ValueError):
            line = max(1, int(v.line or 1))
        locations.append({
            "location": {
                "physicalLocation": {
                    "artifactLocation": {"uri": uri},
                    "region": {"startLine": line},
                },
                "message": {"text": str(step.get("desc", ""))},
            }
        })
    if not locations:
        return None
    return {"threadFlows": [{"locations": locations}]}


def _security_severity(v: Any) -> str:
    """Approximate GitHub 'security-severity' (0-10) from MISRA severity/CWE."""
    base = {"mandatory": "8.8", "required": "5.5", "advisory": "3.1"}
    return base.get(str(v.severity).lower(), "5.0")


def export_sarif(violations: List[Any], out_path: Optional[str] = None) -> str:
    doc = build_sarif(violations)
    if out_path is None:
        out_dir = os.path.join(REPORTS_DIR, "misra")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "results.sarif")
    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        logger.info(f"SARIF written to {out_path} ({len(doc['runs'][0]['results'])} results).")
    except Exception as e:
        logger.error(f"Failed to write SARIF: {e}")
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# SCA / open-source-vulnerability SARIF — gives CVE findings the SAME first-class
# interchange treatment as MISRA findings (GitHub/GitLab dependency scanning
# ingest SARIF). Each CVE becomes a rule; each affected component an evidenced
# result carrying CPE, matched version range, match provenance and confidence.
# ─────────────────────────────────────────────────────────────────────────────

_CVSS_LEVEL_CUTS = [(9.0, "error"), (7.0, "error"), (4.0, "warning"), (0.0, "note")]


def _cve_level(v: Any) -> str:
    sev = str(getattr(v, "severity", "")).upper()
    if sev in ("CRITICAL", "HIGH"):
        return "error"
    if sev == "MEDIUM":
        return "warning"
    if sev == "LOW":
        return "note"
    score = float(getattr(v, "cvss_score", 0.0) or 0.0)
    for cut, level in _CVSS_LEVEL_CUTS:
        if score >= cut:
            return level
    return "note"


def build_sca_sarif(vulns: List[Any], tool_name: str = "AutoGuard SCA Guard",
                    tool_version: str = "1.0.0") -> dict:
    rules: Dict[str, dict] = {}
    results = []
    for v in vulns:
        cve = getattr(v, "cve_id", None) or "UNKNOWN"
        if cve not in rules:
            help_txt = (getattr(v, "description", "") or "")[:800]
            rules[cve] = {
                "id": cve,
                "name": cve.replace("-", "_"),
                "shortDescription": {"text": f"{cve} affecting {getattr(v, 'package_name', '')}"},
                "fullDescription": {"text": help_txt or cve},
                "helpUri": (getattr(v, "references", None) or [None])[0] or
                           f"https://nvd.nist.gov/vuln/detail/{cve}",
                "properties": {
                    "tags": ["security", "sca", "cve",
                             f"severity:{getattr(v, 'severity', 'UNKNOWN')}"],
                    "security-severity": f"{float(getattr(v, 'cvss_score', 0.0) or 0.0):.1f}",
                    "cwe": None,
                },
            }
        pkg = getattr(v, "package_name", "")
        ver = getattr(v, "package_version", "")
        msg = (f"{cve} affects {pkg} {ver} "
               f"(severity {getattr(v, 'severity', '?')}, CVSS {getattr(v, 'cvss_score', 0)}). "
               f"Match: {getattr(v, 'match_method', 'osv')} "
               f"[{getattr(v, 'match_confidence', 'high')} confidence].")
        fixed = getattr(v, "fixed_version", None)
        if fixed:
            msg += f" Fixed in {fixed}."
        # Locate the finding on the component's on-disk evidence when known, so the
        # result is navigable; else a logical location (the component coordinate).
        loc = _component_location(v)
        result = {
            "ruleId": cve,
            "level": _cve_level(v),
            "message": {"text": msg},
            "locations": [loc],
            # SARIF-native prioritization: 0.0-100.0, higher = more urgent. Lets a
            # code-scanning UI sort by exploit-aware priority, not just severity.
            "rank": float(getattr(v, "priority_score", 0.0) or 0.0),
            # A stable fingerprint so scanners can track a CVE/component across runs.
            "partialFingerprints": {
                "cveComponentVersion": f"{cve}:{pkg}:{ver}",
            },
            "properties": {
                "package": pkg,
                "version": ver,
                "cpe": getattr(v, "cpe", None),
                "severity": getattr(v, "severity", None),
                "cvss": getattr(v, "cvss_score", None),
                "epss": getattr(v, "epss_score", None),
                "kev": getattr(v, "kev", False),
                "priority": getattr(v, "priority_label", None),
                "priority_score": getattr(v, "priority_score", None),
                "priority_factors": getattr(v, "priority_factors", []),
                "fixed_version": fixed,
                "match_method": getattr(v, "match_method", "osv"),
                "match_detail": getattr(v, "match_detail", None),
                "match_confidence": getattr(v, "match_confidence", "high"),
                "corroborated_by": getattr(v, "corroborated_by", []),
                "component_source": getattr(v, "component_source", None),
                "component_evidence": getattr(v, "component_evidence", None),
                "reachability": getattr(v, "reachability", "unknown"),
                "symbol_reachability": getattr(v, "symbol_reachability", "unknown"),
                "symbol_evidence": getattr(v, "symbol_evidence", None),
                "relationship": getattr(v, "relationship", "unknown"),
                "triage_status": getattr(v, "triage_status", "open"),
                "auto_triaged": getattr(v, "auto_triaged", False),
                "triage_suggestion": getattr(v, "triage_suggestion", None),
            },
        }
        # A suppressed/resolved finding is annotated as such for SARIF consumers
        # that honor result.suppressions (GitHub code scanning hides these).
        if getattr(v, "triage_status", "open") in (
                "resolved", "not_affected", "false_positive", "accepted"):
            result["suppressions"] = [{
                "kind": "external",
                "justification": getattr(v, "triage_suggestion", None)
                or getattr(v, "triage_status", ""),
            }]
        results.append(result)

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": tool_version,
                "informationUri": "https://autoguard.local",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def _component_location(v: Any) -> dict:
    """A navigable location for a CVE: the component's evidence file if we have one
    (binary path / package DB path), else a logical component coordinate."""
    ev_file = getattr(v, "component_evidence_path", None)
    if ev_file:
        return {"physicalLocation": {"artifactLocation": {"uri": _to_uri(ev_file)},
                                     "region": {"startLine": 1}}}
    pkg = getattr(v, "package_name", "component")
    ver = getattr(v, "package_version", "")
    return {"logicalLocations": [{"name": f"{pkg}@{ver}",
                                  "kind": "package", "fullyQualifiedName": getattr(v, "cpe", None) or f"{pkg}@{ver}"}]}


def export_sca_sarif(vulns: List[Any], out_path: Optional[str] = None) -> str:
    doc = build_sca_sarif(vulns)
    if out_path is None:
        out_dir = os.path.join(REPORTS_DIR, "sca")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "results.sarif")
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        logger.info(f"SCA SARIF written to {out_path} ({len(doc['runs'][0]['results'])} results).")
    except Exception as e:
        logger.error(f"Failed to write SCA SARIF: {e}")
    return out_path


# ─────────────────────────────────────────────────────────────────────────────
# Combined AutoGuard SARIF — one document, one `runs[]` entry per subsystem that
# produced findings. SARIF is explicitly multi-run (one run per tool invocation),
# so a single .sarif can carry both the SCA (CVE) run and the MISRA/coding-standard
# run, letting a CI upload ingest the whole platform's results in one shot while
# GitHub still attributes each result to its own tool.driver.
# ─────────────────────────────────────────────────────────────────────────────

def build_combined_sarif(violations: Optional[List[Any]] = None,
                         vulns: Optional[List[Any]] = None) -> dict:
    """Merge a MISRA run and an SCA run into one multi-run SARIF 2.1.0 document.

    A subsystem with no input (None) contributes no run; passing an empty list
    still emits an (empty) run so the tool's presence is recorded.
    """
    runs = []
    if violations is not None:
        runs.extend(build_sarif(violations)["runs"])
    if vulns is not None:
        runs.extend(build_sca_sarif(vulns)["runs"])
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": runs,
    }


def export_combined_sarif(violations: Optional[List[Any]] = None,
                          vulns: Optional[List[Any]] = None,
                          out_path: Optional[str] = None) -> str:
    doc = build_combined_sarif(violations, vulns)
    if out_path is None:
        out_dir = os.path.join(REPORTS_DIR, "autoguard")
        os.makedirs(out_dir, exist_ok=True)
        out_path = os.path.join(out_dir, "results.sarif")
    try:
        os.makedirs(os.path.dirname(out_path) or ".", exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(doc, f, indent=2, ensure_ascii=False)
        total = sum(len(r.get("results", [])) for r in doc["runs"])
        logger.info(f"Combined SARIF written to {out_path} "
                    f"({len(doc['runs'])} runs, {total} results).")
    except Exception as e:
        logger.error(f"Failed to write combined SARIF: {e}")
    return out_path
