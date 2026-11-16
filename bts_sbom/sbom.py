# vendored from sca_guard/sbom.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""SPDX 2.3 SBOM generator (round 5: the customer-deliverable layer).

Turns what the toolchain actually knows - parsed manifests, resolver
dependency graphs, fused license evidence - into a spec-shaped SPDX 2.3 JSON
document a customer can ingest.

Honesty rules (same discipline as every verdict in this product):
  * ``downloadLocation`` / ``supplier`` / ``copyrightText`` default to
    NOASSERTION - offline we do NOT know provenance and never guess it.
  * a package's ``licenseConcluded``/``licenseDeclared`` carries an SPDX
    expression ONLY when our own parser accepts it; unparseable or CONFLICTING
    evidence yields NOASSERTION plus a ``comment`` saying why (the evidence
    stays inside the tool, never silently dropped).
  * relationships come from the resolver's node/edge graph (DEPENDS_ON) or
    from the manifest's direct dependencies - never inferred by name
    similarity.
  * the document namespace is derived from a digest of the CONTENT (stable
    for identical SBOMs, different for any change).
"""
from __future__ import annotations

import re
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

SPDX_VERSION = "SPDX-2.3"
DATA_LICENSE = "CC0-1.0"
TOOL_NAME = "bts-sbom"

_SAFE_ID = re.compile(r"[^A-Za-z0-9.-]")


def _now_iso(now: Optional[str] = None) -> str:
    if now:
        return now
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _spdx_ref(prefix: str, name: str, idx: int) -> str:
    base = _SAFE_ID.sub("-", str(name)) or "pkg"
    return "SPDXRef-%s-%s-%03d" % (prefix, base, idx)


def _content_digest(payload: str) -> str:
    import hashlib
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _valid_expression(expr: str) -> Tuple[bool, str]:
    """(ok, normalized-or-reason) - our own SPDX grammar is the judge."""
    if not expr or not str(expr).strip():
        return False, "empty license declaration"
    try:
        from bts_sbom._internal.license_spdx import SpdxParseError, expression_string, parse_expression
        node = parse_expression(str(expr))
        return True, expression_string(node).strip("()")
    except SpdxParseError as exc:
        return False, "not valid SPDX syntax: %s" % exc
    except Exception as exc:                       # pragma: no cover
        return False, "parse error: %s" % type(exc).__name__


def _license_value(license_expr: Optional[str], evidence_status: str = "consistent"
                   ) -> Tuple[str, str]:
    """(licenseConcluded value, comment) - NOASSERTION unless provable."""
    if evidence_status == "conflicting":
        return "NOASSERTION", "conflicting license declarations - legal review pending"
    if evidence_status == "insufficient":
        return "NOASSERTION", "no license evidence collected"
    ok, value = _valid_expression(license_expr or "")
    if not ok:
        return "NOASSERTION", value
    return value, ""


def build_spdx_document(packages: List[Dict[str, Any]],
                        relationships: List[Tuple[str, str]],
                        doc_name: str = "bts-sbom-sbom",
                        created: Optional[str] = None,
                        tool_version: str = "") -> Dict[str, Any]:
    """Assemble a valid SPDX 2.3 document.

    ``packages``: [{name, version, license?, license_evidence_status?,
                    supplier?, checksums? [{algorithm, value}], comment?}]
    ``relationships``: [(fromName, toName)] pairs rendered as DEPENDS_ON
    (names must match package names; unmatched ends are dropped and listed
    in the document comment - never silently kept).
    """
    pkgs = sorted((dict(p) for p in packages),
                  key=lambda p: (str(p.get("name", "")), str(p.get("version", ""))))
    ref_by_name: Dict[str, str] = {}
    seen_names = set()
    out_packages: List[Dict[str, Any]] = []
    for i, p in enumerate(pkgs):
        name = str(p.get("name", "")) or "unknown"
        version = str(p.get("version", "") or "")
        key = name if name not in seen_names else "%s@%s" % (name, version)
        seen_names.add(name)
        ref = _spdx_ref("Package", key, i)
        ref_by_name[key] = ref
        lic_val, lic_comment = _license_value(
            p.get("license"), p.get("license_evidence_status", "consistent"))
        checksums = [{"algorithm": str(c.get("algorithm", "")).upper(),
                      "checksumValue": str(c.get("value", ""))}
                     for c in (p.get("checksums") or [])
                     if c.get("algorithm") and c.get("value")]
        entry: Dict[str, Any] = {
            "name": name,
            "SPDXID": ref,
            "downloadLocation": str(p.get("download_location") or "").strip() or "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": lic_val,
            "licenseDeclared": lic_val,
            "copyrightText": "NOASSERTION",
        }
        if version:
            entry["versionInfo"] = version
        sup = str(p.get("supplier") or "").strip()
        if not sup:
            entry["supplier"] = "NOASSERTION"
        elif sup.split(":", 1)[0] in ("Person", "Organization") and ":" in sup:
            entry["supplier"] = sup
        else:                                  # SPDX requires a type prefix on supplier
            entry["supplier"] = "Organization: " + sup
        if checksums:
            entry["checksums"] = checksums
        comments = [c for c in (lic_comment, str(p.get("comment", "") or "")) if c]
        if comments:
            entry["comment"] = "; ".join(comments)
        out_packages.append(entry)

    out_rels: List[Dict[str, Any]] = []
    dropped: List[str] = []
    for src, dst in relationships or []:
        a = ref_by_name.get(src)
        b = ref_by_name.get(dst)
        if not a or not b:
            dropped.append("%s -> %s" % (src, dst))
            continue
        out_rels.append({"spdxElementId": a, "relationshipType": "DEPENDS_ON",
                         "relatedSpdxElement": b})
    for p in out_packages:                      # the document DESCRIBES every root
        out_rels.append({"spdxElementId": "SPDXRef-DOCUMENT",
                         "relationshipType": "DESCRIBES",
                         "relatedSpdxElement": p["SPDXID"]})
    out_rels.sort(key=lambda r: (r["spdxElementId"], r["relatedSpdxElement"]))

    doc_comment = ("Generated offline by %s from verified scan evidence; provenance "
                   "fields not asserted" % TOOL_NAME)
    if dropped:
        doc_comment += ("; DROPPED unmatched relationships: %s"
                        % ", ".join(sorted(set(dropped))[:10]))

    body = {"packages": out_packages, "relationships": out_rels}
    digest = _content_digest(__import__("json").dumps(body, sort_keys=True))
    doc = {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": doc_name,
        "documentNamespace": "https://bts-sbom.local/spdx/%s"
                             % uuid.uuid5(uuid.NAMESPACE_URL, digest),
        "creationInfo": {
            "created": _now_iso(created),
            "creators": ["Tool: %s%s" % (TOOL_NAME, ("-" + tool_version) if tool_version else "")],
        },
        "packages": out_packages,
        "relationships": out_rels,
        "documentDescribes": [p["SPDXID"] for p in out_packages],
        "comment": doc_comment,
    }
    return doc


def sbom_from_resolver_graph(graph: Dict[str, Any], doc_name: str = "bts-sbom-sbom",
                             licenses: Optional[Dict[str, str]] = None,
                             evidence_status: Optional[Dict[str, str]] = None,
                             created: Optional[str] = None) -> Dict[str, Any]:
    """SBOM from a resolver DependencyNode/Edge graph (see sca_guard.resolver).

    ``licenses``/``evidence_status``: per-package license expression /
    fusion status (common.license.evidence) when available."""
    licenses = licenses or {}
    evidence_status = evidence_status or {}
    nodes = (graph or {}).get("nodes") or []
    edges = (graph or {}).get("edges") or []
    names = set()
    packages: List[Dict[str, Any]] = []
    for n in nodes:
        name = str(n.get("name", ""))
        if not name or name in ("$root", "") or name in names:
            continue
        names.add(name)
        # npm `integrity` is a base64 SRI string; SPDX checksumValue must be lowercase
        # HEX.  (The raw base64 used to be copied through, producing an invalid
        # document.)  A malformed digest is dropped rather than "repaired".
        checksums = []
        from bts_sbom._internal.lockfile_facts import sri_to_hash
        h = sri_to_hash(n.get("integrity"))
        if h:
            checksums.append({"algorithm": h["alg"].replace("-", ""), "value": h["content"]})
        pkg_entry = {
            "name": name,
            "version": n.get("version", ""),
            "license": licenses.get(name),
            "license_evidence_status": evidence_status.get(name, "insufficient"
                                                           if name not in licenses else "consistent"),
            "checksums": checksums,
        }
        if n.get("resolved"):
            pkg_entry["download_location"] = str(n["resolved"])
        if n.get("ecosystem") or n.get("purl"):
            from bts_sbom._internal import supplier_resolve
            r = supplier_resolve.resolve({"name": name, "ecosystem": n.get("ecosystem", ""),
                                          "purl": n.get("purl", "")})
            if r:
                pkg_entry["supplier"] = r["name"]
        packages.append(pkg_entry)
    relationships: List[Tuple[str, str]] = []
    id_to_name: Dict[str, str] = {str(n.get("node_id", "")): str(n.get("name", ""))
                                  for n in nodes}
    for e in edges:
        a = id_to_name.get(str(e.get("from_node_id", "")))
        b = id_to_name.get(str(e.get("to_node_id", "")))
        if a and b and a != "$root" and b != "$root" and a != b:
            relationships.append((a, b))
    return build_spdx_document(packages, relationships, doc_name=doc_name,
                               created=created)


def sbom_from_manifest(path: str, doc_name: Optional[str] = None,
                       created: Optional[str] = None) -> Dict[str, Any]:
    """SBOM from one package manifest (direct dependencies only - transitive
    deps are NOT invented; they come from a real resolver run)."""
    from bts_sbom._internal.manifests import parse_file
    parsed = parse_file(path)
    packages = [{"name": p.name, "version": p.version,
                 "license": getattr(p, "license", None) or None}
                for p in parsed]
    import os
    return build_spdx_document(packages, [], doc_name=doc_name or
                               os.path.splitext(os.path.basename(path))[0],
                               created=created)


def validate_spdx(doc: Any) -> List[str]:
    """Structural SPDX 2.3 checks used by tests and the CLI (a local judge -
    not a substitute for a certified validator, and said so)."""
    errors: List[str] = []
    if not isinstance(doc, dict):
        return ["document is not a JSON object"]
    required = ["spdxVersion", "dataLicense", "SPDXID", "name",
                "documentNamespace", "creationInfo", "packages"]
    for key in required:
        if key not in doc:
            errors.append("missing required field: %s" % key)
    if doc.get("spdxVersion") != SPDX_VERSION:
        errors.append("spdxVersion must be %s" % SPDX_VERSION)
    if doc.get("dataLicense") != DATA_LICENSE:
        errors.append("dataLicense must be %s" % DATA_LICENSE)
    ci = doc.get("creationInfo") or {}
    if not ci.get("created") or not ci.get("creators"):
        errors.append("creationInfo needs created + creators")
    refs = set()
    for p in doc.get("packages") or []:
        for field in ("name", "SPDXID", "downloadLocation", "licenseConcluded",
                      "copyrightText"):
            if field not in p:
                errors.append("package %r missing %s" % (p.get("name"), field))
        if str(p.get("SPDXID", "")).startswith("SPDXRef-"):
            refs.add(p["SPDXID"])
        lic = p.get("licenseConcluded")
        if lic not in ("NOASSERTION", "NONE") and lic:
            ok, _why = _valid_expression(lic)
            if not ok:
                errors.append("package %s has a non-SPDX license value"
                              % p.get("name"))
    for r in doc.get("relationships") or []:
        for field in ("spdxElementId", "relationshipType", "relatedSpdxElement"):
            if field not in r:
                errors.append("relationship missing %s" % field)
        for end in (r.get("spdxElementId"), r.get("relatedSpdxElement")):
            if end != "SPDXRef-DOCUMENT" and end not in refs:
                errors.append("relationship references unknown element %s" % end)
    return errors


__all__ = ["build_spdx_document", "sbom_from_resolver_graph",
           "sbom_from_manifest", "validate_spdx", "TOOL_NAME"]
