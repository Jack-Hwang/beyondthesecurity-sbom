# vendored from common/ntia_check.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""NTIA minimum-elements check for a real SBOM document (CycloneDX or SPDX 2.3).

Replaces the endpoint's old behaviour: with no SBOM on disk it returned
hard-coded demo percentages (92 / 100 / 87.5 / ...), and with one it crashed
(`e` undefined).  Here every number is computed from the document, and a
missing / unreadable document is reported as ``NO_DATA`` - never a score.

NTIA "Minimum Elements for an SBOM" (2021): supplier name, component name,
version, other unique identifiers, dependency relationship, author of SBOM
data, timestamp.  Per-component elements are scored as the share of components
that carry them; document-level elements are 100 / 0.

Interpretation choices (stated so reviewers can disagree):
  * ``NOASSERTION`` / ``NONE`` / empty / ``unknown`` count as ABSENT.
  * unique identifier = purl, CPE or SWID (CycloneDX) / purl or cpe
    externalRef (SPDX).  ``bom-ref`` / SPDXID alone is an internal key.
  * dependency relationship: the component is the subject or a target of a
    dependency/relationship entry (an explicit empty ``dependsOn`` counts: the
    generator made a statement about it).
  * SBOM author: named ``authors`` (CycloneDX) / ``creators`` (SPDX).  A
    document that only names its generating tool is credited, with the basis
    recorded as ``tool-only``.
  * supplier: a component's ``supplier`` / ``publisher`` (CycloneDX) or
    ``supplier`` (SPDX) counts, and so does a reported author (CycloneDX
    ``authors``, SPDX ``originator``).  The score's ``basis`` says how many of
    the credited components rest on a supplier DERIVED from a package namespace
    (npm scope, Maven groupId, ...) and how many on an author only, so a reader
    can discount them.
  * SPDX: the package that SPDXRef-DOCUMENT DESCRIBES *and* that CONTAINS /
    DEPENDS_ON other packages is the described product, not a dependency, and is
    not scored as a component.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

NTIA_REFERENCE = "NTIA Minimum Elements for a Software Bill of Materials (2021)"

#: (id, display name, weight, scope).  Weights sum to 100.
ELEMENTS = [
    ("supplier", "Supplier Name", 15, "component"),
    ("comp_name", "Component Name", 15, "component"),
    ("version", "Component Version", 15, "component"),
    ("unique_id", "Unique Identifier", 15, "component"),
    ("dependency", "Dependency Relationships", 15, "component"),
    ("sbom_author", "SBOM Author", 12, "document"),
    ("timestamp", "Timestamp", 13, "document"),
]

_ABSENT = {"", "noassertion", "none", "unknown", "n/a"}


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, (list, tuple, set, dict)):
        return len(value) > 0
    return str(value).strip().lower() not in _ABSENT


def _status(pct: float) -> str:
    return "PASS" if pct >= 90 else ("WARN" if pct >= 60 else "FAIL")


def _grade(score: float) -> str:
    return ("A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60
            else "D" if score >= 45 else "F")


def _flatten_cdx(components: Iterable[dict]) -> List[dict]:
    out: List[dict] = []
    for c in components or []:
        if not isinstance(c, dict):
            continue
        out.append(c)
        out.extend(_flatten_cdx(c.get("components") or []))
    return out


def _prop(c: dict, name: str) -> str:
    for p in c.get("properties") or []:
        if isinstance(p, dict) and p.get("name") == name:
            return str(p.get("value") or "")
    return ""


def _cdx_supplier_kind(c: dict) -> Optional[str]:
    """None (absent) | 'named' | 'derived' (from a namespace) | 'author' (author only)."""
    sup = c.get("supplier")
    if (isinstance(sup, dict) and _present(sup.get("name"))) or _present(c.get("publisher")):
        # (vendored note: read both property namespaces -- bts-sbom writes
        #  "bts-sbom:supplier-basis", platform-generated documents carry
        #  "ecu-sentinel:supplier-basis"; the basis semantics are identical)
        basis = _prop(c, "bts-sbom:supplier-basis") or _prop(c, "ecu-sentinel:supplier-basis")
        return "derived" if basis.endswith("-namespace") else "named"
    authors = [a for a in (c.get("authors") or []) if isinstance(a, dict) and _present(a.get("name"))]
    if authors or _present(c.get("author")):
        return "author"
    return None


def _cdx_facts(doc: dict) -> Dict[str, Any]:
    comps = _flatten_cdx(doc.get("components") or [])
    deps = doc.get("dependencies") or []
    in_deps = set()
    for d in deps:
        if not isinstance(d, dict):
            continue
        if _present(d.get("ref")):
            in_deps.add(d["ref"])
        for t in d.get("dependsOn") or []:
            in_deps.add(t)
    meta = doc.get("metadata") or {}
    tools = meta.get("tools")
    if isinstance(tools, dict):                       # CycloneDX 1.5 shape
        tools = (tools.get("components") or []) + (tools.get("services") or [])
    authors = [a for a in (meta.get("authors") or []) if isinstance(a, dict) and _present(a.get("name"))]
    kinds = [_cdx_supplier_kind(c) for c in comps]
    per = {
        "supplier": [k is not None for k in kinds],
        "comp_name": [_present(c.get("name")) for c in comps],
        "version": [_present(c.get("version")) for c in comps],
        "unique_id": [_present(c.get("purl")) or _present(c.get("cpe")) or _present(c.get("swid"))
                      for c in comps],
        "dependency": [(c.get("bom-ref") in in_deps) if _present(c.get("bom-ref")) else False
                       for c in comps],
    }
    if authors:
        author, author_basis = True, "named author(s)"
    elif _present(tools):
        author, author_basis = True, "tool-only (no named author)"
    else:
        author, author_basis = False, "no authors or tools in metadata"
    return {"format": "CycloneDX", "components": len(comps), "per": per,
            "supplier_kinds": kinds,
            "doc": {"sbom_author": (author, author_basis),
                    "timestamp": (_present(meta.get("timestamp")),
                                  "metadata.timestamp")}}


def _spdx_supplier_kind(p: dict) -> Optional[str]:
    if _present(p.get("supplier")):
        return "derived" if "supplier derived from" in str(p.get("comment") or "") else "named"
    if _present(p.get("originator")):
        return "author"
    return None


_COMPONENT_RELS = {"CONTAINS", "DEPENDS_ON", "DEPENDENCY_OF", "STATIC_LINK", "DYNAMIC_LINK"}


def _spdx_described_products(doc: dict) -> set:
    """SPDXIDs that are DESCRIBED by the document AND have components of their
    own - i.e. the product the SBOM is about, not one of its dependencies."""
    described = set(doc.get("documentDescribes") or [])
    parents = set()
    for r in doc.get("relationships") or []:
        if not isinstance(r, dict):
            continue
        if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES":
            described.add(r.get("relatedSpdxElement"))
        elif r.get("relationshipType") in _COMPONENT_RELS:
            parents.add(r.get("spdxElementId"))
    return {d for d in described if d in parents}


def _spdx_facts(doc: dict) -> Dict[str, Any]:
    products = _spdx_described_products(doc)
    pkgs = [p for p in (doc.get("packages") or [])
            if isinstance(p, dict) and p.get("SPDXID") not in products]
    related = set()
    for r in doc.get("relationships") or []:
        if isinstance(r, dict):
            related.add(r.get("spdxElementId"))
            related.add(r.get("relatedSpdxElement"))
    per = {
        "supplier": [_spdx_supplier_kind(p) is not None for p in pkgs],
        "comp_name": [_present(p.get("name")) for p in pkgs],
        "version": [_present(p.get("versionInfo")) for p in pkgs],
        "unique_id": [any(isinstance(x, dict) and str(x.get("referenceType", "")).lower() in ("purl", "cpe23type", "cpe22type")
                          and _present(x.get("referenceLocator"))
                          for x in (p.get("externalRefs") or [])) for p in pkgs],
        "dependency": [p.get("SPDXID") in related for p in pkgs],
    }
    info = doc.get("creationInfo") or {}
    creators = [c for c in (info.get("creators") or []) if _present(c)]
    named = [c for c in creators if not str(c).lower().startswith("tool:")]
    if named:
        author, basis = True, "named creator(s)"
    elif creators:
        author, basis = True, "tool-only (no named author)"
    else:
        author, basis = False, "no creationInfo.creators"
    return {"format": "SPDX", "components": len(pkgs), "per": per,
            "supplier_kinds": [_spdx_supplier_kind(p) for p in pkgs],
            "doc": {"sbom_author": (author, basis),
                    "timestamp": (_present(info.get("created")), "creationInfo.created")}}


def evaluate(doc: Any) -> Dict[str, Any]:
    """Score ``doc`` (a parsed SBOM).  Returns ``status: NO_DATA`` for anything
    that is not a recognisable CycloneDX / SPDX document."""
    if not isinstance(doc, dict):
        return no_data("document is not a JSON object")
    if str(doc.get("bomFormat", "")).lower() == "cyclonedx":
        facts = _cdx_facts(doc)
    elif str(doc.get("spdxVersion", "")).upper().startswith("SPDX-"):
        facts = _spdx_facts(doc)
    else:
        return no_data("neither a CycloneDX (bomFormat) nor an SPDX (spdxVersion) document")

    n = facts["components"]
    if n == 0:
        return no_data("the SBOM lists no components, so no element can be scored")
    rows: List[Dict[str, Any]] = []
    for eid, name, weight, scope in ELEMENTS:
        if scope == "component":
            flags = facts["per"][eid]
            ok = sum(1 for f in flags if f)
            pct = round(ok / n * 100, 1)
            basis = "%d of %d components" % (ok, n)
            if eid == "supplier" and ok:
                kinds = facts.get("supplier_kinds") or []
                derived = sum(1 for k in kinds if k == "derived")
                author_only = sum(1 for k in kinds if k == "author")
                extra = []
                if derived:
                    extra.append("%d derived from a package namespace, not a verified organisation" % derived)
                if author_only:
                    extra.append("%d credited on a reported author only" % author_only)
                if extra:
                    basis += " (" + "; ".join(extra) + ")"
        else:
            satisfied, basis = facts["doc"][eid]
            pct, ok = (100.0 if satisfied else 0.0), int(bool(satisfied))
        rows.append({"id": eid, "name": name, "weight": weight, "scope": scope,
                     "compliance_pct": pct, "status": _status(pct),
                     "satisfied": ok, "basis": basis})
    score = round(sum(r["compliance_pct"] * r["weight"] / 100 for r in rows), 1)
    return {
        "status": "OK",
        "format": facts["format"],
        "component_count": n,
        "elements": rows,
        "total_score": score,
        "grade": _grade(score),
        "pass_count": sum(1 for r in rows if r["status"] == "PASS"),
        "warn_count": sum(1 for r in rows if r["status"] == "WARN"),
        "fail_count": sum(1 for r in rows if r["status"] == "FAIL"),
        "ntia_reference": NTIA_REFERENCE,
    }


def no_data(reason: str) -> Dict[str, Any]:
    """Honest empty result: no score, no grade, no per-element percentage."""
    return {
        "status": "NO_DATA",
        "reason": reason,
        "format": None,
        "component_count": 0,
        "elements": [{"id": i, "name": nm, "weight": w, "scope": sc,
                      "compliance_pct": None, "status": "NO_DATA",
                      "satisfied": None, "basis": reason}
                     for i, nm, w, sc in ELEMENTS],
        "total_score": None,
        "grade": None,
        "pass_count": 0, "warn_count": 0, "fail_count": 0,
        "ntia_reference": NTIA_REFERENCE,
    }
