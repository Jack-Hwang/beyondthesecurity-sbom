# vendored from common/sbom.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
CycloneDX 1.6 SBOM builder — deterministic, dependency-free.

Turns a list of resolved packages (name / version / ecosystem / purl / license)
into a valid CycloneDX 1.6 JSON document, and optionally attaches OSV-derived
`vulnerabilities` entries mapped back to their components via bom-ref.

HONESTY: this module FABRICATES nothing. It only serializes packages that were
actually discovered from a manifest/lockfile and vulnerabilities that were
actually returned by OSV. A package with no license is emitted with no `licenses`
field (not a guessed one); a package with no purl gets a derived bom-ref that is
clearly a pkg-URL of the same coordinates. Pure functions: pass `timestamp` in so
the output is reproducible (no hidden clock).

Dependency graph honesty (CycloneDX 1.5/1.6 semantics): a component gets a
`dependencies` entry ONLY when its dependency table is actually known (taken from a
lockfile, `graph_known`).  An entry with an empty `dependsOn` means "this component
has no dependencies" - asserting that for a component whose dependencies we never
read would be a false statement, so unknown components are simply absent from the
graph and listed under a `compositions` block with aggregate `unknown`.  The root
depends on its direct dependencies (and on components whose relationship is not
known to be transitive), never on every transitive component.
"""
import re
from bts_sbom._version import __version__ as _BTS_VERSION
import uuid
import hashlib
from typing import List, Dict, Any, Optional, Tuple

from bts_sbom._internal import supplier_resolve
from bts_sbom._internal.lockfile_facts import hex_hash

_SPEC_VERSION = "1.6"  # CycloneDX 1.6 (2024): lifecycle, evidence.identity, licenses.acknowledgement
_ECO_PURL = {
    "PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo",
    "Maven": "maven", "RubyGems": "gem", "NuGet": "nuget", "Packagist": "composer",
    "Pub": "pub", "Hex": "hex", "Debian": "deb", "Ubuntu": "deb", "Alpine": "apk",
}
_SPDX_RE = re.compile(r"^[A-Za-z0-9.+-]+$")
_NON_SPDX = {"non-standard", "unknown", "none", "", "unlicensed"}

# Well-known supplier namespaces — maps purl/ecosystem prefix to supplier org name
_KNOWN_SUPPLIERS: List[Tuple[str, str]] = [
    ("pkg:pypi/django", "Django Software Foundation"),
    ("pkg:pypi/flask", "Pallets Projects"),
    ("pkg:pypi/requests", "Python Software Foundation"),
    ("pkg:pypi/numpy", "NumPy Developers"),
    ("pkg:npm/react", "Meta Platforms, Inc."),
    ("pkg:npm/vue", "Evan You"),
    ("pkg:npm/angular", "Google LLC"),
    ("pkg:npm/lodash", "OpenJS Foundation"),
    ("pkg:maven/org.springframework", "VMware, Inc."),
    ("pkg:maven/com.google", "Google LLC"),
    ("pkg:maven/com.microsoft", "Microsoft Corporation"),
    ("pkg:deb/", "Debian Project"),
    ("pkg:apk/", "Alpine Linux Project"),
]


def bom_ref(pkg: Dict[str, Any]) -> str:
    """Stable component identity: the purl if present, else a derived pkg-URL."""
    if pkg.get("purl"):
        return pkg["purl"]
    eco = _ECO_PURL.get(pkg.get("ecosystem", ""), (pkg.get("ecosystem") or "generic").lower())
    return f"pkg:{eco}/{pkg.get('name','')}@{pkg.get('version','')}"


def _license_obj(lic: str, acknowledgement: str = "declared") -> Optional[Dict[str, Any]]:
    lic = (lic or "").strip()
    if not lic or lic.lower() in _NON_SPDX:
        return None
    if re.search(r"\b(AND|OR|WITH)\b", lic):
        return {"expression": lic, "acknowledgement": acknowledgement}
    if _SPDX_RE.match(lic):
        return {"license": {"id": lic, "acknowledgement": acknowledgement}}
    return {"license": {"name": lic, "acknowledgement": acknowledgement}}


def _supplier(ref: str) -> Optional[Dict[str, Any]]:
    """Derive supplier org from the component purl, if recognizable."""
    for prefix, org in _KNOWN_SUPPLIERS:
        if ref.startswith(prefix):
            return {"name": org}
    return None


# CycloneDX 1.6 evidence.identity.methods.technique is an ENUM; free text such as
# "manifest:npm" (or a list of sources) is a schema violation.
_TECHNIQUES = ("source-code-analysis", "binary-analysis", "manifest-analysis", "ast-fingerprint",
               "hash-comparison", "instrumentation", "dynamic-analysis", "filename",
               "attestation", "other")


def _prov_text(provenance: Any) -> str:
    if isinstance(provenance, (list, tuple, set)):
        return ", ".join(sorted(str(x) for x in provenance))
    return str(provenance)


def _technique(provenance: Any) -> str:
    text = _prov_text(provenance).lower()
    if text in _TECHNIQUES:
        return text
    if any(k in text for k in ("manifest", "lock", "dpkg", "rpm", "apk", "yocto", "pom", "package-db")):
        return "manifest-analysis"
    if any(k in text for k in ("syft", "strings", "binary", "elf", "signature", "firmware")):
        return "binary-analysis"
    if "sbom" in text or "attest" in text:
        return "attestation"
    return "other"


def _hash_entries(pkg: Dict[str, Any]) -> List[Dict[str, str]]:
    """CycloneDX `hashes` from lockfile/registry digests (already hex) plus the
    legacy `sha256` field.  Malformed digests are dropped, never repaired."""
    out: List[Dict[str, str]] = []
    for h in pkg.get("hashes") or []:
        if not isinstance(h, dict):
            continue
        ok = hex_hash(str(h.get("alg", "")), h.get("content"))
        if ok and ok not in out:
            out.append(ok)
    sha256 = pkg.get("sha256") or pkg.get("hash_sha256")
    ok = hex_hash("sha256", sha256) if sha256 else None
    if ok and not any(h["alg"] == "SHA-256" for h in out):
        out.append(ok)
    return out


def _component(pkg: Dict[str, Any]) -> Dict[str, Any]:
    ref = bom_ref(pkg)
    c: Dict[str, Any] = {"type": "library", "bom-ref": ref, "name": pkg.get("name", "")}
    props: List[Dict[str, str]] = []
    if pkg.get("version"):
        c["version"] = pkg["version"]
    if pkg.get("purl"):
        c["purl"] = pkg["purl"]
    # Supplier (NTIA minimum element: "supplier name") - resolved WITH its basis
    # (declared / curated-table / <namespace>-namespace); legacy prefix table last.
    if pkg.get("supplier_basis") and pkg.get("supplier"):
        sup_name, sup_basis = str(pkg["supplier"]), str(pkg["supplier_basis"])
    else:
        r = supplier_resolve.resolve(pkg)
        sup_name, sup_basis = (r["name"], r["basis"]) if r else (None, None)
    if sup_name:
        c["supplier"] = {"name": sup_name}
        props.append({"name": "bts-sbom:supplier-basis", "value": sup_basis})
    else:
        legacy = _supplier(ref)
        if legacy:
            c["supplier"] = legacy
            props.append({"name": "bts-sbom:supplier-basis", "value": "curated-table"})
    if pkg.get("author"):          # registry-reported author: an AUTHOR, not an org supplier
        c["authors"] = [{"name": str(pkg["author"])}]
        props.append({"name": "bts-sbom:author-basis",
                      "value": str(pkg.get("author_basis") or "declared")})
    # License with CycloneDX 1.6 acknowledgement field
    lic_str = pkg.get("license") or pkg.get("dep_license")
    lo = _license_obj(lic_str, acknowledgement="declared") if lic_str else None
    if lo is not None:
        c["licenses"] = [lo]
    # Component hash (NTIA minimum element) - lockfile integrity / syft digest
    hashes = _hash_entries(pkg)
    if hashes:
        c["hashes"] = hashes
    # Where the artifact comes from, as the lockfile / registry states it
    dl = str(pkg.get("download_location") or "").strip()
    if dl and dl.upper() != "NOASSERTION":
        c["externalReferences"] = [{"type": "vcs" if dl.startswith("git+") else "distribution",
                                    "url": dl}]
    # CycloneDX 1.6 evidence.identity - record provenance of detection
    provenance = pkg.get("provenance") or pkg.get("source") or pkg.get("detection_source")
    if provenance:
        c["evidence"] = {"identity": [{"field": "version", "confidence": 0.8,
                                        "methods": [{"technique": _technique(provenance),
                                                     "confidence": 0.8,
                                                     "value": _prov_text(provenance)}]}]}
    if props:
        c["properties"] = props
    return c


def build_sbom(packages: List[Dict[str, Any]], target_name: str, timestamp: str,
               serial: Optional[str] = None,
               dep_graph: Optional[Dict[str, Any]] = None,
               authors: Optional[List[str]] = None) -> Tuple[Dict[str, Any], Dict[Tuple[str, str], str]]:
    """Return (cyclonedx_doc, ref_index).

    dep_graph (optional): {pkg_purl: [dep_purl, ...]} explicit adjacency list; when
    given it is used as-is (every component gets an entry).  When omitted the graph
    is derived from the packages' own lockfile evidence (`depends_on`, `graph_known`,
    `relationship`) - see the module docstring for what is and is not asserted.
    `authors` names the author(s) of the SBOM data (NTIA "SBOM Author").
    ref_index maps (name.lower, version) -> bom-ref so callers can attach vulnerabilities.
    """
    seen: Dict[str, Dict[str, Any]] = {}
    ref_index: Dict[Tuple[str, str], str] = {}
    for p in packages:
        if not p.get("name"):
            continue
        ref = bom_ref(p)
        ref_index[(p["name"].lower(), p.get("version", ""))] = ref
        if ref not in seen:
            seen[ref] = _component(p)
    components = [seen[k] for k in sorted(seen)]
    if serial is None:
        h = hashlib.sha256((target_name + "|" + timestamp).encode("utf-8")).hexdigest()
        serial = "urn:uuid:" + str(uuid.UUID(h[:32]))
    doc: Dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": _SPEC_VERSION,
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "timestamp": timestamp,
            "lifecycles": [{"phase": "build"}],  # CycloneDX 1.6: build-time SBOM
            "tools": [{"vendor": "BTS", "name": "bts-sbom", "version": _BTS_VERSION}],
            "component": {"type": "application", "name": target_name or "target",
                          "bom-ref": "root-app"},
        },
        "components": components,
    }
    named = [str(a).strip() for a in (authors or []) if str(a).strip()]
    if named:
        doc["metadata"]["authors"] = [{"name": a} for a in named]
    # CycloneDX `dependencies` section: NTIA minimum + enables copyleft propagation tools
    all_refs = {c["bom-ref"] for c in components}
    if dep_graph is not None:
        # explicit graph from the caller: used as given (legacy contract)
        dep_section = []
        for comp in components:
            ref = comp["bom-ref"]
            raw_deps = dep_graph.get(ref) or dep_graph.get(comp.get("name", "")) or []
            valid_deps = [d for d in raw_deps if d in all_refs and d != ref]
            dep_section.append({"ref": ref, "dependsOn": valid_deps})
        dep_section.insert(0, {"ref": "root-app", "dependsOn": sorted(all_refs)})
        doc["dependencies"] = dep_section
        return doc, ref_index

    known: Dict[str, set] = {}                # ref -> child refs (graph KNOWN for this component)
    root_deps: set = set()
    lock_rooted = True
    for p in packages:
        if not p.get("name"):
            continue
        ref = bom_ref(p)
        if p.get("relationship") != "transitive":
            root_deps.add(ref)                # direct, declared, or not known to be transitive
        if p.get("relationship_basis") != "lockfile-graph":
            lock_rooted = False
        if p.get("graph_known"):
            kids = set()
            for ch in p.get("depends_on") or []:
                cref = ref_index.get((str(ch.get("name", "")).lower(), str(ch.get("version", ""))))
                if cref and cref != ref and cref in all_refs:
                    kids.add(cref)
            known.setdefault(ref, set()).update(kids)
    dep_section = [{"ref": "root-app", "dependsOn": sorted(root_deps & all_refs)}]
    for ref in sorted(known):
        dep_section.append({"ref": ref, "dependsOn": sorted(known[ref])})
    doc["dependencies"] = dep_section
    comps: List[Dict[str, Any]] = []
    if known:
        comps.append({"aggregate": "complete", "dependencies": sorted(known)})
    unknown = sorted(all_refs - set(known))
    if unknown:
        comps.append({"aggregate": "unknown", "dependencies": unknown})
    comps.append({"aggregate": "complete" if lock_rooted and packages else "unknown",
                  "dependencies": ["root-app"]})
    doc["compositions"] = comps
    return doc, ref_index


def attach_vulnerabilities(doc: Dict[str, Any], vulns: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Attach CycloneDX `vulnerabilities` entries. Each `vulns` item:
    {ref, id, aliases, score, severity, vector, fixed, url, summary}."""
    out = []
    for v in vulns:
        entry: Dict[str, Any] = {"id": v.get("id", ""), "source": {"name": "OSV"}}
        if v.get("url"):
            entry["source"]["url"] = v["url"]
        if v.get("aliases"):
            entry["references"] = [{"id": a, "source": {"name": "OSV"}} for a in v["aliases"]]
        if v.get("score"):
            vec = v.get("vector", "")
            method = "CVSSv4" if ("CVSS:4" in (vec or "").upper()) else "CVSSv31"
            rating = {"source": {"name": "OSV"}, "score": v["score"],
                      "severity": (v.get("severity") or "unknown").lower(), "method": method}
            if vec:
                rating["vector"] = vec
            entry["ratings"] = [rating]
        elif v.get("severity") and v["severity"].lower() != "unknown":
            entry["ratings"] = [{"source": {"name": "OSV"}, "severity": v["severity"].lower()}]
        if v.get("summary"):
            entry["description"] = v["summary"]
        rec = {}
        if v.get("fixed"):
            rec["recommendation"] = f"Upgrade {v.get('name','')} to {v['fixed']} or later."
        entry.update(rec)
        entry["affects"] = [{"ref": v.get("ref", "")}]
        out.append(entry)
    if out:
        doc["vulnerabilities"] = out
    return doc
