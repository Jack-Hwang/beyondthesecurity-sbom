"""SBOM documents: CycloneDX 1.5 (with vulnerabilities + licenses), SPDX 2.3 (via the bts_sbom core), OpenVEX.

Honesty rules baked in:
  * a component without license evidence carries NO ``licenses`` entry (never an invented NOASSERTION pass);
  * the supplier is never invented - it is absent unless real evidence exists (NTIA coverage then reports the gap);
  * every vulnerability ``affects`` reference must resolve to a component ``bom-ref`` (checked by ``validate_cyclonedx``);
  * VEX statements are ``affected`` for open findings and ``fixed`` only for plans verified clean.
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set

from . import __version__, cvss, engine
from .util import now_iso

_SEV_MAP = {"CRITICAL": "critical", "HIGH": "high", "MEDIUM": "medium", "LOW": "low", "NONE": "none", "UNKNOWN": "unknown"}
_SPDX_ATOM = re.compile(r"^[A-Za-z0-9.+\-]+$")
_PHASES = ("design", "pre-build", "build", "post-build", "operations", "discovery", "decommission")


def _ref(c: Dict[str, Any]) -> str:
    return c.get("purl") or "pkg:generic/%s@%s" % (c["name"], c.get("version", ""))


def _license_entry(expr: str) -> Optional[List[Dict[str, Any]]]:
    if not expr:
        return None
    if _SPDX_ATOM.match(expr):
        return [{"license": {"id": expr}}]
    return [{"expression": expr}]


def cyclonedx(name: str, components: List[Dict[str, Any]], vulns: List[Dict[str, Any]], *,
              lineage: Optional[Dict[str, Any]] = None, created: Optional[str] = None,
              project_license: str = "", lifecycle: str = "") -> Dict[str, Any]:
    refs: Dict[tuple, str] = {}
    comps: List[Dict[str, Any]] = []
    used: Set[str] = set()
    for c in components:
        ref = _ref(c)
        if ref in used:                               # same purl from two manifests -> keep one component
            refs[(c["ecosystem"].lower(), engine._canon(c["ecosystem"], c["name"]), c["version"])] = ref
            continue
        used.add(ref)
        refs[(c["ecosystem"].lower(), engine._canon(c["ecosystem"], c["name"]), c["version"])] = ref
        item: Dict[str, Any] = {"type": "library", "bom-ref": ref, "name": c["name"], "version": c.get("version", ""), "purl": c.get("purl") or ref}
        lic = _license_entry(c.get("license", ""))
        if lic:
            item["licenses"] = lic
        props = [{"name": "bts-sbom:relationship", "value": c.get("relationship") or "unknown"}]
        if c.get("license_source"):
            props.append({"name": "bts-sbom:license-source", "value": c["license_source"]})
        if c.get("scope"):
            props.append({"name": "bts-sbom:scope", "value": str(c["scope"])})
        for f in (c.get("files") or [])[:3]:
            props.append({"name": "bts-sbom:manifest", "value": f})
        item["properties"] = props
        comps.append(item)
    root_ref = "app:" + name
    direct = [_ref(c) for c in components if c.get("relationship") == "direct"]
    vs: List[Dict[str, Any]] = []
    for v in vulns:
        key = (v["ecosystem"].lower(), engine._canon(v["ecosystem"], v["package"]), v["version"])
        ref = refs.get(key)
        if not ref:
            continue                                   # unresolvable -> never emit a dangling reference
        rating: Dict[str, Any] = {"source": {"name": "OSV"}, "severity": _SEV_MAP.get(v["severity"], "unknown")}
        ratings = [rating]
        if v.get("cvss") is not None:
            rating.update(score=v["cvss"], method="CVSSv4" if v.get("score_source") == "cvss_v4_vector" else "CVSSv31")
            other, method = (v.get("cvss_v3"), "CVSSv31") if v.get("score_source") == "cvss_v4_vector" else (v.get("cvss_v4"), "CVSSv4")
            if other is not None and other != v["cvss"]:                 # the advisory has both: keep both, the primary first
                ratings.append({"source": {"name": "OSV"}, "severity": _SEV_MAP.get(cvss.label(other), "unknown"), "score": other, "method": method})
        vs.append({"id": v["id"], "source": {"name": "OSV", "url": "https://osv.dev/vulnerability/" + (v.get("osv_ids") or [v["id"]])[0]},
                   "ratings": ratings, "description": v.get("summary", ""),
                   "recommendation": ("Upgrade %s to %s or later" % (v["package"], v["fixed_version"])) if v.get("fixed_version")
                   else "No fixed version is known - evaluate a replacement or document risk acceptance",
                   "advisories": [{"url": u} for u in (v.get("references") or [])[:3]],
                   "affects": [{"ref": ref}], "properties": [{"name": "bts-sbom:aliases", "value": ",".join(v.get("aliases") or [])}]})
    meta_comp: Dict[str, Any] = {"type": "application", "bom-ref": root_ref, "name": name}
    if project_license:
        lic = _license_entry(project_license)
        if lic:
            meta_comp["licenses"] = lic
    props = []
    for k, val in (lineage or {}).items():
        if val not in ("", None):
            props.append({"name": "bts-sbom:lineage:" + k, "value": str(val)})
    doc = {"bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
           "serialNumber": "urn:uuid:" + _uuid5(name + json.dumps(sorted(used))),
           "metadata": {"timestamp": created or now_iso(),
                        "tools": {"components": [{"type": "application", "name": "bts_sbom_app", "version": __version__}]},
                        "component": meta_comp, "properties": props},
           "components": comps, "dependencies": [{"ref": root_ref, "dependsOn": sorted(set(direct))}] +
                                              [{"ref": r, "dependsOn": []} for r in sorted(used)],
           "vulnerabilities": vs}
    if lifecycle in _PHASES:                           # CycloneDX 1.5 metadata.lifecycles: when in the lifecycle this SBOM was generated
        doc["metadata"]["lifecycles"] = [{"phase": lifecycle}]
    return doc


def _uuid5(s: str) -> str:
    h = hashlib.sha1(("bts-sbom:" + s).encode()).hexdigest()
    return "%s-%s-5%s-a%s-%s" % (h[:8], h[8:12], h[13:16], h[17:20], h[20:32])


def validate_cyclonedx(doc: Dict[str, Any]) -> List[str]:
    """Structural integrity checks (not the full JSON schema): returns a list of error strings, [] = ok."""
    errs: List[str] = []
    if doc.get("bomFormat") != "CycloneDX":
        errs.append("bomFormat must be CycloneDX")
    if doc.get("specVersion") != "1.5":
        errs.append("specVersion must be 1.5")
    if not isinstance(doc.get("version"), int):
        errs.append("version must be an integer")
    refs = [c.get("bom-ref") for c in doc.get("components") or []]
    root = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    if len(refs) != len(set(refs)):
        errs.append("duplicate component bom-ref")
    known = set(refs) | ({root} if root else set())
    for c in doc.get("components") or []:
        for k in ("type", "name", "bom-ref"):
            if not c.get(k):
                errs.append("component missing %s: %s" % (k, c.get("name")))
        for l in c.get("licenses") or []:
            if not (("license" in l and (l["license"].get("id") or l["license"].get("name"))) or "expression" in l):
                errs.append("bad license entry on %s" % c.get("name"))
    for v in doc.get("vulnerabilities") or []:
        if not v.get("id"):
            errs.append("vulnerability without id")
        for a in v.get("affects") or []:
            if a.get("ref") not in known:
                errs.append("vulnerability %s affects unknown ref %s" % (v.get("id"), a.get("ref")))
        for r in v.get("ratings") or []:
            if r.get("severity") not in ("critical", "high", "medium", "low", "info", "none", "unknown"):
                errs.append("bad severity %r on %s" % (r.get("severity"), v.get("id")))
    for d in doc.get("dependencies") or []:
        if d.get("ref") not in known:
            errs.append("dependency ref unknown: %s" % d.get("ref"))
        for x in d.get("dependsOn") or []:
            if x not in known:
                errs.append("dependsOn unknown ref: %s" % x)
    return errs


def ref_integrity(doc: Dict[str, Any]) -> Dict[str, Any]:
    refs = {c.get("bom-ref") for c in doc.get("components") or []}
    aff = [a.get("ref") for v in doc.get("vulnerabilities") or [] for a in v.get("affects") or []]
    ok = sum(1 for r in aff if r in refs)
    return {"affects": len(aff), "resolved": ok, "rate": round(ok / len(aff), 4) if aff else 1.0}


def spdx(name: str, components: List[Dict[str, Any]], *, created: Optional[str] = None) -> Dict[str, Any]:
    """SPDX 2.3 JSON via the bts_sbom core builder (validated by the core's own validator)."""
    core = engine._import_core()
    pkgs = [{"name": c["name"], "version": c.get("version", ""), "license": c.get("license") or None,
             "comment": ("license source: " + c["license_source"]) if c.get("license_source") else ""} for c in components]
    rels = [(name, c["name"]) for c in components if c.get("relationship") == "direct"]
    doc = core.build_spdx_document(pkgs, rels, doc_name=name, created=created, tool_version=__version__)
    # Workaround for bts-sbom 0.1.1 (see docs/CORE_ISSUES.md #2): its expression normaliser ends with .strip("()"), which also
    # removes the closing parenthesis of "A AND (B OR C)" and writes an unbalanced value that the core validator then rejects.
    # The original expression was produced by our own structure-preserving parser, so it is restored verbatim.
    orig = {(c["name"], c.get("version", "")): c.get("license") for c in components}
    for p in doc.get("packages") or []:
        lic = orig.get((p.get("name"), p.get("versionInfo", "")))
        cur = str(p.get("licenseConcluded") or "")
        if lic and cur not in ("NOASSERTION", "NONE", lic) and cur.count("(") != cur.count(")"):
            p["licenseConcluded"] = p["licenseDeclared"] = lic
    return doc


def validate_spdx(doc: Dict[str, Any]) -> List[str]:
    return list(engine._import_core().validate_spdx(doc))


def openvex(name: str, vulns: Iterable[Dict[str, Any]], *, fixed_ids: Iterable[str] = (), author: str = "bts_sbom_app",
            timestamp: Optional[str] = None, triage: Optional[Dict[str, Any]] = None, today: Optional[Any] = None) -> Dict[str, Any]:
    """OpenVEX for the findings. ``triage`` (the decision store, see ``triage.py``) refines ``affected`` statements fail-closed:
    ``not_affected`` only with a VEX justification and a reason, risk acceptances stay ``affected`` with an action statement."""
    from . import triage as triagemod
    fixed = set(fixed_ids)
    stmts: List[Dict[str, Any]] = []
    seen: Set[tuple] = set()
    for v in vulns:
        k = (v["id"], v.get("purl") or v["package"])
        if k in seen:
            continue
        seen.add(k)
        st: Dict[str, Any] = {"vulnerability": {"name": v["id"]}, "products": [{"@id": v.get("purl") or "pkg:generic/%s@%s" % (v["package"], v["version"])}]}
        if v["id"] in fixed:
            st["status"] = "fixed"
        else:
            st["status"] = "affected"
            st["action_statement"] = ("Upgrade %s to %s" % (v["package"], v["fixed_version"])) if v.get("fixed_version") \
                else "No fixed version known; evaluate replacement"
            dec = triagemod.decide(v, triage, today=today) if triage else None
            if dec:
                triagemod.apply_to_statement(st, dec)
        stmts.append(st)
    return {"@context": "https://openvex.dev/ns/v0.2.0", "@id": "https://bts_sbom_app.local/vex/" + _uuid5(name + str(len(stmts))),
            "author": author, "timestamp": timestamp or now_iso(), "version": 1, "statements": stmts}
