# round-2 engine features E3 + E5 (REA 21 §7) — new module, stdlib-only.
"""
Policy engine (Black Duck policy pattern) + VEX evaluation at decision point.

POLICY (E3)
-----------
A policy is a JSON document:

    {
      "name": "release-gate",                     # optional label
      "rules": {
        "severity_min": "HIGH",                   # CRITICAL|HIGH|MEDIUM|LOW
        "licenses_deny": ["GPL-2.0-only", "UNKNOWN"],
        "max_severity_score": 9.0                 # CVSS ceiling (exclusive)
      }
    }

``Policy.from_dict`` validates it (unknown rule keys and bad severity names
are errors, never silently ignored). ``Policy.evaluate(findings, components,
vex_doc=None)`` returns:

    {"verdict": "pass"|"fail",
     "violations": [{"rule", "component", "detail"}, ...],
     "summary": {...},
     "vex": {...}}                                # only when vex_doc given

Rule semantics (documented, deterministic):
  * severity_min — a finding violates when its severity label ranks at or
    above severity_min (severity_min HIGH fails HIGH and CRITICAL). A
    finding with an UNKNOWN severity cannot be ranked: it does NOT violate
    severity_min and is disclosed in summary.unknown_severity (honesty:
    unrankable is not silently conflated with a pass).
  * max_severity_score — a computed CVSS score STRICTLY ABOVE the ceiling
    violates (a score equal to the ceiling passes). Findings without a
    computable score are disclosed, not judged.
  * licenses_deny — SPDX ids or the token "UNKNOWN". A component violates
    when its license expression CONTAINS a denied id as a token, or when
    its license is absent/unstated (None, "", "UNKNOWN", "NOASSERTION")
    and "UNKNOWN" is denied. Expressions are matched conservatively: any
    OR/AND/WITH member matching a denied id violates; SPDX expression
    logic (which side of an OR actually applies) is NOT evaluated.

FINDINGS input shape (= ``bts-sbom scan --fmt json`` output; also accepted:
a bare list of finding dicts):
    {"results": [{"source": {"path", "type"},
                  "packages": [{"package": {"name", "version", "ecosystem",
                                            "purl"?},
                                "vulnerabilities": [{"id", "aliases"?,
                                                     "severity"?: [
                                                        {"type": "CVSS_V3"|
                                                         "CVSS_V4",
                                                         "score": "<vector>"}],
                                                     "database_specific"?}],
                                "query_status"?, "identity"?}]}],
     "scan_status"?, "completeness"?}
Severity labels/scores are recomputed from the advisory records with the
scanner's own CVSS v3.1/v4.0 code (osvscanner._osv_severity), so the gate
cannot be fooled by a stale label.

SBOM components (optional --sbom): SPDX 2.3 (packages[].licenseConcluded /
licenseDeclared / externalRefs purl) or CycloneDX 1.5 (components[].licenses
[].license.id|name|expression, purl). License rules evaluate against these.

VEX (E5)
--------
``vex_evaluate(findings, vex_doc)`` groups findings against VEX statements
AT THE DECISION POINT (Anchore/Sonatype VEX-workflow pattern):

    {"not_affected": n, "fixed": n, "under_investigation": n,
     "affected": n, "unmatched": n, "suppressed": [{finding, status,
     justification?}], "vex_error": str?}

Matching is case-insensitive on id+aliases and matches the product purl
with and without its version (package VexIndex semantics). Statements
with status not_affected/fixed SUPPRESS a finding (suppressed findings
are excluded from policy rule evaluation and listed with the VEX status
that silenced them — suppression is auditable, never silent);
under_investigation/affected findings stay policy-relevant. A malformed
VEX document does not fail the gate silently: it is reported in
"vex_error" and ALL findings stay unmatched (fail-closed — a broken VEX
must not suppress anything).
"""
import re
from typing import Any, Dict, List, Optional


SCHEMA = "bts-policy-eval/1"

# severity ranking: UNKNOWN is deliberately rank 0 — it cannot violate
# severity_min but is disclosed in the summary.
SEVERITY_RANK: Dict[str, int] = {"UNKNOWN": 0, "LOW": 1, "MEDIUM": 2,
                                 "HIGH": 3, "CRITICAL": 4}

_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")
_LICENSE_TOKEN_RE = re.compile(r"[A-Za-z0-9.\-]+")


class PolicyError(ValueError):
    """Raised for a malformed policy document (fail-closed)."""


def _unknown_license(lic: Any) -> bool:
    if lic is None:
        return True
    s = str(lic).strip()
    return s == "" or s.upper() in ("UNKNOWN", "NOASSERTION", "NONE")


# ── the policy object ─────────────────────────────────────────────────────────

class Policy:
    """Validated policy: severity_min / licenses_deny / max_severity_score."""

    def __init__(self, name: str, severity_min: Optional[str],
                 licenses_deny: List[str],
                 max_severity_score: Optional[float]):
        self.name = name
        self.severity_min = severity_min
        self.licenses_deny = [d.upper() for d in licenses_deny]
        self.max_severity_score = max_severity_score

    @classmethod
    def from_dict(cls, doc: Any) -> "Policy":
        if not isinstance(doc, dict):
            raise PolicyError("policy must be a JSON object")
        rules = doc.get("rules", doc.get("policy", None))
        if rules is None:
            raise PolicyError("policy is missing the 'rules' object")
        if not isinstance(rules, dict):
            raise PolicyError("'rules' must be an object")
        known = {"severity_min", "licenses_deny", "max_severity_score"}
        unknown = set(rules) - known
        if unknown:
            raise PolicyError("unknown rule key(s) %s — supported: %s"
                              % (sorted(unknown), sorted(known)))
        sev = rules.get("severity_min")
        if sev is not None:
            sev = str(sev).strip().upper()
            if sev not in _SEVERITIES:
                raise PolicyError(
                    "severity_min must be one of %s (severity_min=LOW would "
                    "fail on every advisory; use --gate-free policies by "
                    "omitting the rule)" % str(_SEVERITIES))
        deny = rules.get("licenses_deny") or []
        if not isinstance(deny, list) or \
                not all(isinstance(d, str) for d in deny):
            raise PolicyError("licenses_deny must be a list of SPDX id strings")
        cap = rules.get("max_severity_score")
        if cap is not None:
            try:
                cap = float(cap)
            except (TypeError, ValueError):
                raise PolicyError("max_severity_score must be a number")
            if not 0.0 <= cap <= 10.0:
                raise PolicyError("max_severity_score must be within [0, 10]")
        name = str(doc.get("name") or "unnamed-policy")
        return cls(name, sev, [str(d) for d in deny], cap)

    @classmethod
    def from_file(cls, path: str) -> "Policy":
        import json
        try:
            with open(path, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except OSError as exc:
            raise PolicyError("cannot read policy %r: %s" % (path, exc))
        except json.JSONDecodeError as exc:
            raise PolicyError("policy %r is not valid JSON: %s" % (path, exc))
        return cls.from_dict(doc)

    # ── evaluation ────────────────────────────────────────────────────────
    def evaluate(self, findings: Any, components: Any = None,
                 vex_doc: Any = None) -> Dict[str, Any]:
        """Evaluate the policy against scan findings (scan-output shape or a
        flat finding list) and optional SBOM components. Returns a verdict
        document; violations are per (rule, component) with a detail string."""
        finds = normalize_findings(findings)
        comps = normalize_components(components)
        vex_block: Optional[Dict[str, Any]] = None
        active: List[Dict[str, Any]] = finds
        if vex_doc is not None:
            vex_block = vex_evaluate(finds, vex_doc)
            suppressed_keys = set()
            for s in vex_block.get("suppressed", []):
                f = s.get("finding", {})
                suppressed_keys.add((f.get("component"), f.get("osv_id"),
                                     f.get("cve_id")))
            active = [f for f in finds
                      if (f.get("component"), f.get("osv_id"),
                          f.get("cve_id")) not in suppressed_keys]

        violations: List[Dict[str, Any]] = []
        unknown_sev = 0
        unscored = 0
        for f in active:
            comp = f.get("component", "")
            rank = SEVERITY_RANK.get(str(f.get("severity", "")).upper(), 0)
            if rank == 0:
                unknown_sev += 1
            if self.severity_min and rank == 0:
                pass                     # unrankable: disclosed, not judged
            elif self.severity_min and \
                    rank >= SEVERITY_RANK[self.severity_min]:
                violations.append({
                    "rule": "severity_min",
                    "component": comp,
                    "detail": "%s on %s is at/above the %s floor (%s)"
                              % (f.get("severity"), comp, self.severity_min,
                                 f.get("osv_id") or f.get("cve_id") or "id?")})
            score = f.get("cvss_score")
            if self.max_severity_score is not None:
                if score is None:
                    unscored += 1
                elif score > self.max_severity_score:
                    violations.append({
                        "rule": "max_severity_score",
                        "component": comp,
                        "detail": "CVSS %.1f exceeds the %.1f ceiling (%s)"
                                  % (score, self.max_severity_score,
                                     f.get("osv_id") or f.get("cve_id") or "id?")})
        for c in comps:
            lic = c.get("license")
            denied = self._denied_license(lic)
            if denied:
                violations.append({
                    "rule": "licenses_deny",
                    "component": c.get("component", ""),
                    "detail": ("license %r matches denied %s"
                               % (lic, denied)) if not _unknown_license(lic)
                    else "license is absent/unknown and 'UNKNOWN' is denied"})

        # conservative OR-expression note
        verdict = "fail" if violations else "pass"
        out: Dict[str, Any] = {
            "schema": SCHEMA,
            "policy": self.name,
            "verdict": verdict,
            "violations": violations,
            "summary": {
                "findings": len(finds),
                "findings_evaluated": len(active),
                "components": len(comps),
                "violation_count": len(violations),
                "unknown_severity_findings": unknown_sev,
                "unscored_findings": unscored,
            },
        }
        if vex_block is not None:
            out["vex"] = vex_block
        return out

    def _denied_license(self, lic: Any) -> Optional[str]:
        """Return the first denied id matched (case-insensitive token match),
        or the string 'UNKNOWN' when the license is absent and UNKNOWN is
        denied. None when no rule bites."""
        if _unknown_license(lic):
            return "UNKNOWN" if "UNKNOWN" in self.licenses_deny else None
        toks = {t.upper() for t in
                _LICENSE_TOKEN_RE.findall(str(lic))}
        for d in self.licenses_deny:
            if d == "UNKNOWN":
                continue
            if d in toks:
                return d
        return None


# ── input normalization ───────────────────────────────────────────────────────

def _finding_from_osv(v: Dict[str, Any], pk: Dict[str, Any],
                      src_path: str, eco: str) -> Dict[str, Any]:
    from bts_sbom.osvscanner import _osv_severity
    score, label, _vec = _osv_severity(v)
    aliases = sorted(set(v.get("aliases", []) or []))
    cve = next((a for a in aliases if a.startswith("CVE-")), None)
    purl = pk.get("purl") or ""
    name = str(pk.get("name", ""))
    version = str(pk.get("version", "") or "")
    component = purl or ("%s/%s@%s" % (eco.lower() or "?", name, version))
    return {
        "component": component,
        "name": name,
        "version": version,
        "ecosystem": eco,
        "purl": purl,
        "osv_id": str(v.get("id", "") or ""),
        "cve_id": cve,
        "aliases": aliases,
        "severity": label,
        "cvss_score": score if score > 0 else None,
        "source": src_path,
    }


def normalize_findings(findings: Any) -> List[Dict[str, Any]]:
    """Normalize the findings input to a flat list. Accepts the scan-output
    JSON shape (results[].packages[].vulnerabilities) or a bare list of
    finding/advisory dicts. Malformed entries are skipped (honest count in
    summary comes from what was actually evaluated)."""
    out: List[Dict[str, Any]] = []
    if isinstance(findings, list):
        for f in findings:
            if not isinstance(f, dict):
                continue
            if "vulnerabilities" in f and "package" in f:
                pk = f.get("package", {}) or {}
                eco = str(pk.get("ecosystem", "") or "")
                for v in f.get("vulnerabilities", []) or []:
                    if isinstance(v, dict):
                        out.append(_finding_from_osv(v, pk, "", eco))
            else:
                out.append(_finding_flat(f))
        return out
    if not isinstance(findings, dict):
        return out
    for src in findings.get("results", []) or []:
        spath = str((src.get("source", {}) or {}).get("path", ""))
        for pe in src.get("packages", []) or []:
            pk = pe.get("package", {}) or {}
            eco = str(pk.get("ecosystem", "") or "")
            for v in pe.get("vulnerabilities", []) or []:
                if isinstance(v, dict):
                    out.append(_finding_from_osv(v, pk, spath, eco))
    return out


def _finding_flat(f: Dict[str, Any]) -> Dict[str, Any]:
    """A pre-flattened finding dict: pass through known keys with defaults."""
    ids = [i for i in (f.get("osv_id"), f.get("cve_id"),
                       f.get("vuln_id")) if i]
    return {
        "component": str(f.get("component") or f.get("product")
                         or f.get("purl") or f.get("package") or ""),
        "name": str(f.get("name") or f.get("package") or ""),
        "version": str(f.get("version", "") or ""),
        "ecosystem": str(f.get("ecosystem", "") or ""),
        "purl": str(f.get("purl", "") or ""),
        "osv_id": str(f.get("osv_id") or f.get("vuln_id") or ""),
        "cve_id": f.get("cve_id"),
        "aliases": [str(a) for a in (f.get("aliases") or [])],
        "severity": str(f.get("severity", "") or "").upper(),
        "cvss_score": f.get("cvss_score"),
        "source": str(f.get("source", "") or ""),
        "vuln_ids": ids,
    }


def normalize_components(components: Any) -> List[Dict[str, Any]]:
    """Normalize SBOM component input: an SPDX 2.3 or CycloneDX document, a
    list of component dicts, or None. Each item -> {component, license,
    name, version, purl}."""
    out: List[Dict[str, Any]] = []
    if components is None:
        return out
    if isinstance(components, dict):
        doc = components
        if "spdxVersion" in doc or "SPDXID" in doc:          # SPDX 2.3
            for p in doc.get("packages", []) or []:
                if not isinstance(p, dict):
                    continue
                purl = ""
                for ref in p.get("externalRefs", []) or []:
                    if ref.get("referenceType") == "purl":
                        purl = str(ref.get("referenceLocator", ""))
                out.append({"component": purl or str(p.get("name", "")),
                            "license": p.get("licenseConcluded")
                            or p.get("licenseDeclared"),
                            "name": str(p.get("name", "")),
                            "version": str(p.get("versionInfo", "") or ""),
                            "purl": purl})
            return out
        if doc.get("bomFormat") == "CycloneDX" or "components" in doc:
            for c in doc.get("components", []) or []:
                if not isinstance(c, dict):
                    continue
                lic = None
                for entry in c.get("licenses", []) or []:
                    lic_obj = entry.get("license", {}) or {}
                    lic = (lic_obj.get("id") or lic_obj.get("name")
                           or entry.get("expression"))
                    if lic:
                        break
                out.append({"component": str(c.get("purl")
                                             or c.get("name", "")),
                            "license": lic,
                            "name": str(c.get("name", "")),
                            "version": str(c.get("version", "") or ""),
                            "purl": str(c.get("purl", "") or "")})
            return out
        # else: treat as a bare component map
        components = [components]
    if isinstance(components, list):
        for c in components:
            if isinstance(c, dict):
                out.append({
                    "component": str(c.get("component") or c.get("purl")
                                     or c.get("name") or ""),
                    "license": c.get("license"),
                    "name": str(c.get("name", "")),
                    "version": str(c.get("version", "") or ""),
                    "purl": str(c.get("purl", "") or "")})
    return out


# ── E5: VEX evaluation at the decision point ──────────────────────────────────

def vex_evaluate(findings: Any, vex_doc: Any) -> Dict[str, Any]:
    """Group findings against VEX statements:
    {not_affected, fixed, under_investigation, affected, unmatched,
     suppressed: [{finding, status, justification}]}.
    A malformed VEX document fails CLOSED: every finding is unmatched and
    the parse error is reported — a broken VEX never suppresses anything."""
    counts = {"not_affected": 0, "fixed": 0, "under_investigation": 0,
              "affected": 0, "unmatched": 0}
    suppressed: List[Dict[str, Any]] = []
    out: Dict[str, Any] = {**counts, "suppressed": suppressed}
    finds = findings if isinstance(findings, list) else \
        normalize_findings(findings)
    try:
        from bts_sbom.vex import VexError, parse_document
        doc = vex_doc if isinstance(vex_doc, dict) else None
        if doc is None:
            raise VexError("VEX input must be an OpenVEX/CycloneDX JSON object")
        index = parse_document(doc)
    except Exception as exc:                       # VexError and anything else
        out["vex_error"] = str(exc)
        out["unmatched"] = len(finds)
        return out
    for f in finds:
        ids = list(f.get("vuln_ids") or [])
        for i in (f.get("osv_id"), f.get("cve_id")):
            if i:
                ids.append(i)
        ids += list(f.get("aliases") or [])
        ids = [i for i in ids if i]
        # Product candidates, richest first: the finding's own purl/component
        # id plus purl-shaped syntheses (VEX products are conventionally
        # purls; a scan finding that carries no purl still matches one via
        # pkg:<ecosystem>/<name>[@<version>], with and without version —
        # VexIndex matches stripped-version forms).
        eco = str(f.get("ecosystem", "") or "").lower()
        name = str(f.get("name", "") or "")
        ver = str(f.get("version", "") or "")
        products = [f.get("purl") or "", f.get("component") or ""]
        if name:
            products.append("pkg:%s/%s" % (eco or "generic", name))
            if ver:
                products.append("pkg:%s/%s@%s" % (eco or "generic", name, ver))
        status, just = None, None
        for product in products:
            if not product:
                continue
            status, just = index.status_for(ids, product)
            if status is not None:
                break
        if status in counts:
            counts[status] += 1
            if status in ("not_affected", "fixed"):
                suppressed.append({"finding": f, "status": status,
                                   "justification": just})
        else:
            counts["unmatched"] += 1
    out.update(counts)
    return out


__all__ = ["SCHEMA", "Policy", "PolicyError", "SEVERITY_RANK",
           "normalize_findings", "normalize_components", "vex_evaluate"]
