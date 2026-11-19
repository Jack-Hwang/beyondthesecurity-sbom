"""SBOM conformance matrix: one SBOM document checked against several regimes at once.

Why (FOSSLight Community Day 2026, "changing SBOM regulations and trends"): the baseline moves faster than a single
checklist. NTIA 2021 (7 fields) is being extended by CISA's 2025 minimum-elements draft (hash, licence, tool, generation context),
the EU CRA asks for a machine-readable SBOM covering at least the top-level dependencies, and BSI TR-03183-2 spells out the
data fields a CRA-grade SBOM carries. The same missing field (hash, supplier, purl...) usually blocks several regimes at once, so
the output is a matrix plus a "fix once, satisfy many" ranking instead of one more pass/fail score.

Honesty rules (same contract as the rest of the app):
  * every number is computed from the document; an unrecognisable or empty document is ``NO_DATA`` - never a score;
  * NOASSERTION / NONE / empty / unknown count as ABSENT;
  * a regime is only ``conformant`` when EVERY element it names is satisfied by EVERY component (or the document, for
    document-level elements); partial coverage is reported as ``partial`` with its percentage;
  * the regimes are a CHECKED SUBSET of data fields with the date this table was last reviewed (``as_of``). Draft texts are
    flagged ``draft``. This is evidence-gathering support, not a legal conformity assessment - confirm against the official text.
"""
from __future__ import annotations

import datetime
import os
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .util import read_json

SCHEMA = "bts-sbom.conformance.v1"
#: when the regime table below was last checked against the official texts as a whole; a table older than STALE_AFTER_MONTHS is flagged
TABLE_REVIEWED = "2026-11"
STALE_AFTER_MONTHS = 6
_ABSENT = {"", "noassertion", "none", "unknown", "n/a"}
_LIFECYCLE = re.compile(r"\b(pre-?build|build|post-?build|design|operations|discovery|decommission)\b", re.I)
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")

#: element id -> {title, scope (component|document), hint}
ELEMENTS: Dict[str, Dict[str, str]] = {
    "machine_readable": {"title": "Machine-readable format (CycloneDX / SPDX)", "scope": "document",
                         "hint": "Emit CycloneDX JSON/XML or SPDX JSON; free-text lists and spreadsheets do not count."},
    "top_level_deps": {"title": "Top-level dependencies listed", "scope": "document",
                       "hint": "Declare at least the direct dependencies of the product (CycloneDX dependencies[] from the root, SPDX DEPENDS_ON/CONTAINS)."},
    "sbom_author": {"title": "SBOM author / creator named", "scope": "document",
                    "hint": "Name the person or organisation that produced the SBOM (CycloneDX metadata.authors, SPDX Person:/Organization: creator)."},
    "sbom_author_or_tool": {"title": "SBOM author or generating tool named", "scope": "document",
                            "hint": "Name the author, or at least the generating tool (metadata.tools / creator Tool:)."},
    "sbom_contact": {"title": "SBOM creator contact (e-mail)", "scope": "document",
                     "hint": "Add a contact e-mail for the SBOM creator (CycloneDX metadata.authors[].email, SPDX creator 'Organization: name (mail)')."},
    "tool_name": {"title": "Generating tool recorded", "scope": "document",
                  "hint": "Record the tool that generated the SBOM (CycloneDX metadata.tools, SPDX creator 'Tool: name-version')."},
    "timestamp": {"title": "Timestamp", "scope": "document",
                  "hint": "Set metadata.timestamp (CycloneDX) / creationInfo.created (SPDX) in RFC 3339 UTC."},
    "generation_context": {"title": "Generation context (when in the lifecycle the SBOM was made)", "scope": "document",
                           "hint": "CycloneDX 1.5 metadata.lifecycles[].phase (pre-build / build / post-build ...); SPDX has no field, so state it in creationInfo.comment."},
    "component_name": {"title": "Component name", "scope": "component", "hint": "Every component needs a name."},
    "version": {"title": "Component version", "scope": "component",
                "hint": "Record the exact version of every component; a missing version makes vulnerability matching unverifiable."},
    "unique_id": {"title": "Unique identifier (purl / CPE / SWID)", "scope": "component",
                  "hint": "Add a purl (preferred), CPE or SWID per component; bom-ref / SPDXID alone is only an internal key."},
    "purl": {"title": "Package URL (purl)", "scope": "component",
             "hint": "Add pkg:<type>/... purls: vulnerability databases and VEX statements key on them."},
    "supplier": {"title": "Supplier / producer", "scope": "component",
                 "hint": "Record the supplier or producer per component (CycloneDX supplier/publisher/manufacturer, SPDX supplier/originator); never invent one."},
    "hash": {"title": "Component hash", "scope": "component",
             "hint": "Record a cryptographic hash (SHA-256/SHA-512) per component; lockfile integrity fields already carry them."},
    "license": {"title": "Licence", "scope": "component",
                "hint": "Record the licence per component as an SPDX id/expression; leave it absent rather than NOASSERTION when unknown."},
    "dependency": {"title": "Dependency relationships", "scope": "component",
                   "hint": "Emit the dependency graph (CycloneDX dependencies[], SPDX relationships) so every component appears in it."},
}

_REVIEW = "Checked subset of the data fields; confirm against the current official text."

#: regime id -> metadata + the element ids it names. ``as_of`` = when this table was last reviewed.
REGIMES: Dict[str, Dict[str, Any]] = {
    "ntia-2021": {
        "title": "NTIA Minimum Elements for an SBOM (2021)", "authority": "US NTIA (EO 14028)", "stage": "published guidance", "as_of": "2021-07",
        "draft": False, "elements": ("supplier", "component_name", "version", "unique_id", "dependency", "sbom_author_or_tool", "timestamp"),
        "notes": "Baseline seven data fields. A document that only names its generating tool is credited for the author field, as in the core NTIA check."},
    "cisa-2025-draft": {
        "title": "CISA Minimum Elements for an SBOM (2025 draft)", "authority": "US CISA", "stage": "draft for public comment (2025-08)", "as_of": "2025-08",
        "draft": True, "elements": ("sbom_author", "supplier", "component_name", "version", "unique_id", "hash", "license", "dependency", "tool_name",
                                    "timestamp", "generation_context"),
        "notes": "Extends the NTIA baseline with component hash, licence, tool name and generation context. DRAFT: the final text may differ. " + _REVIEW},
    "eu-cra-annex-i": {
        "title": "EU Cyber Resilience Act, Annex I Part II(1)", "authority": "EU Regulation 2024/2847", "stage": "in force; obligations apply from 2027-12-11",
        "as_of": "2026-11", "draft": False, "elements": ("machine_readable", "top_level_deps", "component_name", "version"),
        "notes": "A machine-readable SBOM covering at the very least the top-level dependencies. " + _REVIEW},
    "bsi-tr-03183-2": {
        "title": "BSI TR-03183 Part 2 (SBOM requirements for CRA)", "authority": "German BSI", "stage": "technical guideline", "as_of": "2026-11", "draft": False,
        "elements": ("machine_readable", "sbom_author", "sbom_contact", "timestamp", "supplier", "component_name", "version", "dependency", "license",
                     "hash", "unique_id"),
        "notes": "Data fields of a CRA-grade SBOM; the guideline names SHA-512 for the component hash (this check accepts any recorded hash). " + _REVIEW},
    "vuln-ready": {
        "title": "Vulnerability / VEX readiness (BTS-SBOM)", "authority": "BTS-SBOM (not a regulation)", "stage": "internal baseline", "as_of": "2026-11",
        "draft": False, "elements": ("component_name", "version", "purl", "dependency"),
        "notes": "What a vulnerability scan and a VEX statement need to be unambiguous: an exact version and a purl for every component. "
                 "FOSSLight Hub shows no per-version vulnerability list for a component without a version; the same holds here."},
}

HONESTY = ("Computed only from the supplied document; absent evidence is a gap, never a pass. The regimes are a checked subset of data fields "
           "with a review date - evidence-gathering support, not a legal conformity assessment.")


def _present(v: Any) -> bool:
    if v is None:
        return False
    if isinstance(v, (list, tuple, set, dict)):
        return len(v) > 0
    return str(v).strip().lower() not in _ABSENT


def _status(pct: float, scope: str) -> str:
    if scope == "document":
        return "pass" if pct >= 100 else "gap"
    return "pass" if pct >= 100 else ("partial" if pct >= 50 else "gap")


# ------------------------------------------------------------------ CycloneDX
def _flatten(components: Iterable[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for c in components or []:
        if isinstance(c, dict):
            out.append(c)
            out.extend(_flatten(c.get("components") or []))
    return out


def _cdx_supplier(c: Dict[str, Any]) -> Optional[str]:
    sup = c.get("supplier")
    man = c.get("manufacturer")
    if (isinstance(sup, dict) and _present(sup.get("name"))) or _present(c.get("publisher")) or (isinstance(man, dict) and _present(man.get("name"))):
        basis = ""
        for p in c.get("properties") or []:
            if isinstance(p, dict) and p.get("name") in ("bts-sbom:supplier-basis", "ecu-sentinel:supplier-basis"):
                basis = str(p.get("value") or "")
        return "derived" if basis.endswith("-namespace") else "named"
    if any(isinstance(a, dict) and _present(a.get("name")) for a in c.get("authors") or []) or _present(c.get("author")):
        return "author"
    return None


def _cdx_license(c: Dict[str, Any]) -> bool:
    for e in c.get("licenses") or []:
        if not isinstance(e, dict):
            continue
        lic = e.get("license") if isinstance(e.get("license"), dict) else {}
        if _present(lic.get("id")) or _present(lic.get("name")) or _present(e.get("expression")):
            return True
    return False


def _cdx_facts(doc: Dict[str, Any]) -> Dict[str, Any]:
    comps = _flatten(doc.get("components") or [])
    deps = [d for d in doc.get("dependencies") or [] if isinstance(d, dict)]
    meta = doc.get("metadata") if isinstance(doc.get("metadata"), dict) else {}
    root = (meta.get("component") or {}).get("bom-ref") if isinstance(meta.get("component"), dict) else None
    in_graph = set()
    for d in deps:
        if _present(d.get("ref")):
            in_graph.add(d["ref"])
        in_graph.update(t for t in d.get("dependsOn") or [])
    tools = meta.get("tools")
    if isinstance(tools, dict):
        tools = list(tools.get("components") or []) + list(tools.get("services") or [])
    authors = [a for a in meta.get("authors") or [] if isinstance(a, dict) and _present(a.get("name"))]
    sup = meta.get("supplier") if isinstance(meta.get("supplier"), dict) else {}
    man = meta.get("manufacture") if isinstance(meta.get("manufacture"), dict) else (meta.get("manufacturer") if isinstance(meta.get("manufacturer"), dict) else {})
    org_named = _present(sup.get("name")) or _present(man.get("name"))
    emails = [a.get("email") for a in authors if _present(a.get("email"))]
    for o in (sup, man):
        emails += [x.get("email") for x in o.get("contact") or [] if isinstance(x, dict) and _present(x.get("email"))]
    phases = [lc.get("phase") for lc in meta.get("lifecycles") or [] if isinstance(lc, dict) and _present(lc.get("phase"))]
    prop_ctx = any(isinstance(p, dict) and p.get("name") == "bts-sbom:generation-context" and _present(p.get("value")) for p in meta.get("properties") or [])
    top = any(d.get("ref") == root and _present(d.get("dependsOn")) for d in deps) if root else any(_present(d.get("dependsOn")) for d in deps)
    kinds = [_cdx_supplier(c) for c in comps]
    per = {
        "component_name": [_present(c.get("name")) for c in comps],
        "version": [_present(c.get("version")) for c in comps],
        "unique_id": [_present(c.get("purl")) or _present(c.get("cpe")) or _present(c.get("swid")) for c in comps],
        "purl": [_present(c.get("purl")) for c in comps],
        "supplier": [k is not None for k in kinds],
        "hash": [any(isinstance(h, dict) and _present(h.get("content")) for h in c.get("hashes") or []) for c in comps],
        "license": [_cdx_license(c) for c in comps],
        "dependency": [(c.get("bom-ref") in in_graph) if _present(c.get("bom-ref")) else False for c in comps],
    }
    named_author = bool(authors) or org_named
    has_tool = _present(tools)
    docf = {
        "machine_readable": (True, "CycloneDX document"),
        "top_level_deps": (top, "dependencies[] from the root lists direct dependencies" if top else "no dependency edge from the root"),
        "sbom_author": (named_author, "named author/organisation" if named_author else "no metadata.authors / supplier / manufacture"),
        "sbom_author_or_tool": (named_author or has_tool, "named author" if named_author else ("tool-only" if has_tool else "no authors or tools in metadata")),
        "sbom_contact": (bool(emails), "creator e-mail present" if emails else "no e-mail in metadata.authors / supplier / manufacture"),
        "tool_name": (has_tool, "metadata.tools" if has_tool else "no metadata.tools"),
        "timestamp": (_present(meta.get("timestamp")), "metadata.timestamp"),
        "generation_context": (bool(phases) or prop_ctx, ("lifecycle phase " + str(phases[0])) if phases else ("generation-context property" if prop_ctx else "no metadata.lifecycles")),
    }
    return {"format": "CycloneDX", "components": len(comps), "per": per, "doc": docf, "supplier_kinds": kinds}


# ------------------------------------------------------------------ SPDX 2.x JSON
_COMPONENT_RELS = {"CONTAINS", "DEPENDS_ON", "DEPENDENCY_OF", "STATIC_LINK", "DYNAMIC_LINK"}


def _spdx_facts(doc: Dict[str, Any]) -> Dict[str, Any]:
    rels = [r for r in doc.get("relationships") or [] if isinstance(r, dict)]
    described = set(doc.get("documentDescribes") or [])
    parents = set()
    for r in rels:
        if r.get("spdxElementId") == "SPDXRef-DOCUMENT" and r.get("relationshipType") == "DESCRIBES":
            described.add(r.get("relatedSpdxElement"))
        elif r.get("relationshipType") in _COMPONENT_RELS:
            parents.add(r.get("spdxElementId"))
    products = {d for d in described if d in parents}
    pkgs = [p for p in doc.get("packages") or [] if isinstance(p, dict) and p.get("SPDXID") not in products]
    related = set()
    for r in rels:
        related.add(r.get("spdxElementId"))
        related.add(r.get("relatedSpdxElement"))
    info = doc.get("creationInfo") if isinstance(doc.get("creationInfo"), dict) else {}
    creators = [str(c) for c in info.get("creators") or [] if _present(c)]
    named = [c for c in creators if not c.lower().startswith("tool:")]
    tools = [c for c in creators if c.lower().startswith("tool:")]

    def refs(p: Dict[str, Any], kinds: Tuple[str, ...]) -> bool:
        return any(isinstance(x, dict) and str(x.get("referenceType", "")).lower() in kinds and _present(x.get("referenceLocator")) for x in p.get("externalRefs") or [])

    prim = {r.get("relatedSpdxElement") for r in rels if r.get("relationshipType") in _COMPONENT_RELS and r.get("spdxElementId") in described}
    prim |= {r.get("spdxElementId") for r in rels if r.get("relationshipType") == "DEPENDENCY_OF" and r.get("relatedSpdxElement") in described}
    per = {
        "component_name": [_present(p.get("name")) for p in pkgs],
        "version": [_present(p.get("versionInfo")) for p in pkgs],
        "unique_id": [refs(p, ("purl", "cpe22type", "cpe23type")) for p in pkgs],
        "purl": [refs(p, ("purl",)) for p in pkgs],
        "supplier": [_present(p.get("supplier")) or _present(p.get("originator")) for p in pkgs],
        "hash": [any(isinstance(h, dict) and _present(h.get("checksumValue")) for h in p.get("checksums") or []) for p in pkgs],
        "license": [_present(p.get("licenseConcluded")) or _present(p.get("licenseDeclared")) for p in pkgs],
        "dependency": [p.get("SPDXID") in related for p in pkgs],
    }
    docf = {
        "machine_readable": (True, "SPDX document"),
        "top_level_deps": (bool(prim), "relationships from the described package" if prim else "no dependency relationship from the described package"),
        "sbom_author": (bool(named), "named creator" if named else "no Person:/Organization: creator"),
        "sbom_author_or_tool": (bool(creators), "named creator" if named else ("tool-only" if tools else "no creationInfo.creators")),
        "sbom_contact": (any(_EMAIL.search(c) for c in named), "creator e-mail present" if any(_EMAIL.search(c) for c in named) else "no e-mail in a named creator"),
        "tool_name": (bool(tools), "Tool: creator" if tools else "no Tool: creator"),
        "timestamp": (_present(info.get("created")), "creationInfo.created"),
        "generation_context": (bool(_LIFECYCLE.search(str(info.get("comment") or ""))), "stated in creationInfo.comment" if _LIFECYCLE.search(str(info.get("comment") or "")) else "no lifecycle phase in creationInfo.comment"),
    }
    return {"format": "SPDX", "components": len(pkgs), "per": per, "doc": docf, "supplier_kinds": []}


def table_age(today: Optional[datetime.date] = None) -> Dict[str, Any]:
    """How old the regime table is. Regulations move (the CISA text is a draft); an old table must say so instead of passing as current."""
    t = today or datetime.date.today()
    y, m = int(TABLE_REVIEWED[:4]), int(TABLE_REVIEWED[5:7])
    months = max(0, (t.year - y) * 12 + t.month - m)
    return {"reviewed": TABLE_REVIEWED, "age_months": months, "stale": months >= STALE_AFTER_MONTHS,
            "note": "regime table last reviewed %s%s" % (TABLE_REVIEWED, " - REVIEW DUE: check it against the official texts" if months >= STALE_AFTER_MONTHS else "")}


def no_data(reason: str) -> Dict[str, Any]:
    return {"schema": SCHEMA, "status": "NO_DATA", "reason": reason, "format": None, "components": 0, "elements": {}, "regimes": {}, "fix_once": [],
            "honesty": HONESTY}


def evaluate(doc: Any, regimes: Optional[Iterable[str]] = None, today: Optional[datetime.date] = None) -> Dict[str, Any]:
    """Score ``doc`` (a parsed CycloneDX or SPDX JSON document) against ``regimes`` (default: all)."""
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
    wanted = list(regimes) if regimes is not None else list(REGIMES)
    unknown = [r for r in wanted if r not in REGIMES]
    if unknown:
        raise ValueError("unknown regime %s; known: %s" % (", ".join(unknown), ", ".join(REGIMES)))
    needed = {e for r in wanted for e in REGIMES[r]["elements"]}
    elements: Dict[str, Dict[str, Any]] = {}
    for eid in ELEMENTS:
        if eid not in needed:
            continue
        spec = ELEMENTS[eid]
        if spec["scope"] == "component":
            flags = facts["per"][eid]
            ok = sum(1 for f in flags if f)
            pct = round(ok / n * 100, 1)
            basis = "%d of %d components" % (ok, n)
            if eid == "supplier" and ok:
                kinds = facts.get("supplier_kinds") or []
                extra = []
                if sum(1 for k in kinds if k == "derived"):
                    extra.append("%d derived from a package namespace, not a verified organisation" % sum(1 for k in kinds if k == "derived"))
                if sum(1 for k in kinds if k == "author"):
                    extra.append("%d credited on a reported author only" % sum(1 for k in kinds if k == "author"))
                if extra:
                    basis += " (" + "; ".join(extra) + ")"
            missing = n - ok
        else:
            satisfied, basis = facts["doc"][eid]
            ok, pct, missing = int(bool(satisfied)), (100.0 if satisfied else 0.0), 0 if satisfied else 1
        elements[eid] = {"title": spec["title"], "scope": spec["scope"], "satisfied": ok, "total": n if spec["scope"] == "component" else 1,
                         "pct": pct, "status": _status(pct, spec["scope"]), "basis": basis, "missing": missing}
    out_regimes: Dict[str, Dict[str, Any]] = {}
    for rid in wanted:
        r = REGIMES[rid]
        st = {e: elements[e]["status"] for e in r["elements"]}
        n_pass = sum(1 for s in st.values() if s == "pass")
        n_gap = sum(1 for s in st.values() if s == "gap")
        verdict = "conformant" if n_pass == len(st) else ("gaps" if n_gap else "partial")
        out_regimes[rid] = {"title": r["title"], "authority": r["authority"], "stage": r["stage"], "as_of": r["as_of"], "draft": r["draft"],
                            "verdict": verdict, "elements": st, "pass": n_pass, "partial": len(st) - n_pass - n_gap, "gap": n_gap, "total": len(st),
                            "notes": r["notes"]}
    fix: List[Dict[str, Any]] = []
    for eid, e in elements.items():
        if e["status"] == "pass":
            continue
        unblocks = [rid for rid in wanted if eid in REGIMES[rid]["elements"] and out_regimes[rid]["verdict"] != "conformant"]
        fix.append({"element": eid, "title": e["title"], "status": e["status"], "pct": e["pct"], "missing": e["missing"], "scope": e["scope"],
                    "regimes": unblocks, "hint": ELEMENTS[eid]["hint"]})
    fix.sort(key=lambda f: (-len(f["regimes"]), f["pct"], f["element"]))
    return {"schema": SCHEMA, "status": "OK", "format": facts["format"], "components": n, "elements": elements, "regimes": out_regimes,
            "fix_once": fix, "table": table_age(today), "honesty": HONESTY}


def compact(res: Dict[str, Any]) -> Dict[str, Any]:
    """The part worth persisting in a project record (verdict per regime + the fix list)."""
    if res.get("status") != "OK":
        return {"schema": SCHEMA, "status": res.get("status"), "reason": res.get("reason")}
    return {"schema": SCHEMA, "status": "OK", "format": res["format"], "components": res["components"], "table": res.get("table"),
            "regimes": {k: {f: v[f] for f in ("title", "verdict", "pass", "partial", "gap", "total", "draft", "as_of")} for k, v in res["regimes"].items()},
            "elements": {k: {f: v[f] for f in ("status", "pct", "missing")} for k, v in res["elements"].items()},
            "fix_once": [{f: x[f] for f in ("element", "status", "pct", "missing", "regimes")} for x in res["fix_once"]]}


def load_document(path: str) -> Tuple[Optional[Dict[str, Any]], str]:
    """(document, note) from an SBOM file, or from a project record (its sibling CycloneDX file). (None, reason) when unreadable."""
    obj = read_json(path, None)
    if not isinstance(obj, dict):
        return None, "not a readable JSON file: %s" % path
    if obj.get("bomFormat") or obj.get("spdxVersion"):
        return obj, "sbom file"
    arts = obj.get("artifacts") if isinstance(obj.get("artifacts"), dict) else {}
    for cand in (arts.get("cdx"), os.path.join(os.path.dirname(path), os.path.basename(path)[:-5] + ".cdx.json")):
        if cand and os.path.isfile(cand):
            doc = read_json(cand, None)
            if isinstance(doc, dict):
                return doc, "CycloneDX of the project record"
    return None, "%s is neither an SBOM nor a project record with a CycloneDX file" % path


def render_md(res: Dict[str, Any]) -> str:
    if res.get("status") != "OK":
        return "# SBOM conformance\n\nNO_DATA: %s\n" % res.get("reason")
    L = ["# SBOM conformance (%s, %d components)" % (res["format"], res["components"]), "",
         "| regime | verdict | pass | partial | gap | stage | reviewed |", "|---|---|---|---|---|---|---|"]
    for rid, r in res["regimes"].items():
        L.append("| %s%s | %s | %d | %d | %d | %s | %s |" % (rid, " (draft)" if r["draft"] else "", r["verdict"], r["pass"], r["partial"], r["gap"], r["stage"], r["as_of"]))
    L += ["", "| element | status | coverage | basis |", "|---|---|---|---|"]
    for eid, e in res["elements"].items():
        L.append("| %s | %s | %s%% | %s |" % (eid, e["status"], e["pct"], e["basis"]))
    if res["fix_once"]:
        L += ["", "## Fix once, satisfy many", ""]
        for f in res["fix_once"]:
            L.append("- **%s** (%s%%, %s): blocks %s. %s" % (f["element"], f["pct"], f["status"], ", ".join(f["regimes"]) or "no open regime", f["hint"]))
    t = res.get("table") or {}
    if t:
        L += ["", "%s." % t["note"]]
    L += ["", "_%s_" % res["honesty"], ""]
    return "\n".join(L)


__all__ = ["ELEMENTS", "REGIMES", "evaluate", "compact", "load_document", "render_md", "no_data", "SCHEMA"]
