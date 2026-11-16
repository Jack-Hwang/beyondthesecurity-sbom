# vendored from common/spdx_sbom.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
SPDX 2.3 SBOM builder — the ISO/SAE 21434 & UN R155-friendly SBOM format, alongside
our CycloneDX output. Deterministic and dependency-light: turns the same resolved
package list into a valid SPDX-2.3 JSON document. License fields are canonicalized
through `common.license_norm` (license_expression), and an unresolved license is
emitted as NOASSERTION — never guessed. Pass `timestamp` in for reproducibility.

Validity is proven in benchmark/spdx_sbom by round-tripping the output through the
official `spdx-tools` parser + full validator.

Provenance fields are filled ONLY from evidence the scan holds: ``supplier`` from a
declared value / curated table / package namespace (basis written to the package
``comment`` when it is a derived identifier), ``originator`` from a registry-reported
author, ``downloadLocation`` and ``checksums`` from the lockfile, and ``DEPENDS_ON``
relationships from the lockfile's own dependency table.  Everything else stays
NOASSERTION.
"""
import re
from bts_sbom._version import __version__ as _BTS_VERSION
import hashlib
from typing import List, Dict, Any, Optional

from bts_sbom._internal import license_norm, supplier_resolve
from bts_sbom._internal.lockfile_facts import hex_hash

_ECO_PURL = {
    "PyPI": "pypi", "npm": "npm", "Go": "golang", "crates.io": "cargo",
    "Maven": "maven", "RubyGems": "gem", "NuGet": "nuget", "Packagist": "composer",
    "Pub": "pub", "Hex": "hex", "Debian": "deb", "Ubuntu": "deb", "Alpine": "apk",
}
_SPDXID_BAD = re.compile(r"[^a-zA-Z0-9.\-]+")


def _purl(pkg: Dict[str, Any]) -> str:
    if pkg.get("purl"):
        return pkg["purl"]
    eco = _ECO_PURL.get(pkg.get("ecosystem", ""), (pkg.get("ecosystem") or "generic").lower())
    return f"pkg:{eco}/{pkg.get('name','')}@{pkg.get('version','')}"


def _spdxid(pkg: Dict[str, Any], idx: int) -> str:
    base = _SPDXID_BAD.sub("-", _purl(pkg)).strip("-")
    return f"SPDXRef-Package-{idx}-{base}"[:200]


def _creator(value: Any) -> str:
    """SPDX creators need a type prefix; a bare name is taken as an Organization
    (callers who mean a person pass "Person: Name")."""
    v = str(value).strip()
    return v if v.split(":", 1)[0] in ("Person", "Organization", "Tool") and ":" in v else "Organization: " + v


_SPDX_ALG = {"SHA-1": "SHA1", "SHA-256": "SHA256", "SHA-384": "SHA384", "SHA-512": "SHA512"}


def _checksums(pkg: Dict[str, Any]) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    cands = list(pkg.get("hashes") or [])
    sha256 = pkg.get("sha256") or pkg.get("hash_sha256")
    if sha256:
        cands.append({"alg": "SHA-256", "content": sha256})
    for h in cands:
        if not isinstance(h, dict):
            continue
        ok = hex_hash(str(h.get("alg", "")), h.get("content"))
        if ok:
            entry = {"algorithm": _SPDX_ALG[ok["alg"]], "checksumValue": ok["content"]}
            if entry not in out:
                out.append(entry)
    return out


def build_spdx(packages: List[Dict[str, Any]], target_name: str, timestamp: str,
               vulns: Optional[List[Dict[str, Any]]] = None,
               namespace: Optional[str] = None,
               authors: Optional[List[str]] = None) -> Dict[str, Any]:
    """Return a valid SPDX-2.3 document (dict) describing the packages."""
    # dedup by (name, version) preserving order
    seen = set()
    unique: List[Dict[str, Any]] = []
    for p in packages:
        if not p.get("name"):
            continue
        key = (p["name"].lower(), p.get("version", ""))
        if key in seen:
            continue
        seen.add(key)
        unique.append(p)

    # index vulnerabilities by the package purl (their bom-ref)
    vuln_by_purl: Dict[str, List[Dict[str, Any]]] = {}
    for v in vulns or []:
        vuln_by_purl.setdefault(v.get("ref", ""), []).append(v)

    root_id = "SPDXRef-Package-Root"
    spdx_packages: List[Dict[str, Any]] = [{
        "SPDXID": root_id,
        "name": target_name or "target",
        "downloadLocation": "NOASSERTION",
        "filesAnalyzed": False,
        "licenseConcluded": "NOASSERTION",
        "licenseDeclared": "NOASSERTION",
        "copyrightText": "NOASSERTION",
    }]
    relationships: List[Dict[str, Any]] = [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": root_id},
    ]

    sid_by_key: Dict[Any, str] = {}
    for i, p in enumerate(unique):
        sid = _spdxid(p, i)
        purl = _purl(p)
        dl = str(p.get("download_location") or "").strip()
        entry: Dict[str, Any] = {
            "SPDXID": sid,
            "name": p.get("name", ""),
            "downloadLocation": dl if dl else "NOASSERTION",
            "filesAnalyzed": False,
            "licenseConcluded": "NOASSERTION",
            "licenseDeclared": license_norm.to_spdx_field(p.get("license")),
            "copyrightText": "NOASSERTION",
        }
        if p.get("version"):
            entry["versionInfo"] = p["version"]
        comments: List[str] = []
        if p.get("supplier_basis") and p.get("supplier"):
            sup_name, sup_basis = str(p["supplier"]), str(p["supplier_basis"])
        else:
            r = supplier_resolve.resolve(p)
            sup_name, sup_basis = (r["name"], r["basis"]) if r else (None, None)
        if sup_name:
            entry["supplier"] = "Organization: %s" % sup_name
            if supplier_resolve.is_derived_basis(sup_basis):
                comments.append("supplier derived from %s (an identifier, not a verified "
                                "legal-entity name)" % sup_basis)
        if p.get("author"):
            entry["originator"] = "Person: %s" % p["author"]
            comments.append("originator reported by %s" % (p.get("author_basis") or "the manifest"))
        sums = _checksums(p)
        if sums:
            entry["checksums"] = sums
        if comments:
            entry["comment"] = "; ".join(comments)
        ext_refs: List[Dict[str, Any]] = [{
            "referenceCategory": "PACKAGE-MANAGER",
            "referenceType": "purl",
            "referenceLocator": purl,
        }]
        for v in vuln_by_purl.get(purl, []):
            loc = v.get("url") or v.get("id")
            if loc:
                ext_refs.append({
                    "referenceCategory": "SECURITY",
                    "referenceType": "advisory",
                    "referenceLocator": loc,
                    "comment": f"{v.get('id','')} ({v.get('severity','')})".strip(),
                })
        entry["externalRefs"] = ext_refs
        spdx_packages.append(entry)
        sid_by_key[(p["name"].lower(), p.get("version", ""))] = sid
        relationships.append({"spdxElementId": root_id, "relationshipType": "CONTAINS",
                              "relatedSpdxElement": sid})

    # Real dependency edges - only where the lockfile named them (never inferred).
    seen_edges = set()
    for p in unique:
        src = sid_by_key.get((p["name"].lower(), p.get("version", "")))
        if p.get("relationship") in ("direct",) and p.get("relationship_basis") == "lockfile-graph":
            seen_edges.add((root_id, src))
        for ch in p.get("depends_on") or []:
            dst = sid_by_key.get((str(ch.get("name", "")).lower(), str(ch.get("version", ""))))
            if src and dst and src != dst:
                seen_edges.add((src, dst))
    for a, b in sorted(e for e in seen_edges if e[0] and e[1]):
        relationships.append({"spdxElementId": a, "relationshipType": "DEPENDS_ON",
                              "relatedSpdxElement": b})

    ns = namespace or ("https://bts-sbom.local/spdx/" +
                       hashlib.sha256((f"{target_name}|{timestamp}").encode("utf-8")).hexdigest()[:32])
    vuln_count = len(vulns) if vulns else 0
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": target_name or "target",
        "documentNamespace": ns,
        "documentComment": (
            f"bts-sbom — open-source composition scan. "
            f"Target: {target_name}. Components: {len(unique)}. "
            f"Known vulnerabilities: {vuln_count}. Scanned: {timestamp}. "
            f"Spec: SPDX-2.3 (CC0-1.0). Unresolved licenses emitted as NOASSERTION."
        ),
        "creationInfo": {
            "created": timestamp,
            "creators": ["Tool: bts-sbom-" + _BTS_VERSION]
                        + [_creator(a) for a in (authors or []) if str(a).strip()],
        },
        "packages": spdx_packages,
        "relationships": relationships,
    }
