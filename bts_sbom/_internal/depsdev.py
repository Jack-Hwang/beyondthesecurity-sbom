# vendored from common/depsdev.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
License enrichment via deps.dev (Google Open Source Insights) — the same Google
data family as OSV. Manifests like requirements.txt carry no license, so to do a
REAL license analysis we resolve each package's declared license from deps.dev.

The same GetVersion call also carries ``publishedAt`` (release date -> component
age), ``isDeprecated`` / ``deprecatedReason`` (the registry's own deprecation flag)
and SLSA provenance / attestation lists; ``version_info`` / ``enrich`` keep them so
no extra request is needed.

HONESTY: best-effort and fully disclosed. A package deps.dev can't resolve (network
down, unknown version, or a "non-standard" declaration) is left with license=None
and counted in `unresolved` — it is never given a guessed license. Offline ⇒ no
network I/O at all, everything unresolved.
"""
import json
import logging
import urllib.request
import urllib.parse
from typing import List, Dict, Any, Optional

logger = logging.getLogger("depsdev")

# OSV ecosystem name -> deps.dev "system"
_SYSTEM = {
    "pypi": "pypi", "python": "pypi", "npm": "npm", "node": "npm",
    "go": "go", "golang": "go", "crates.io": "cargo", "cargo": "cargo",
    "maven": "maven", "gradle": "maven", "java": "maven",
    "nuget": "nuget", "dotnet": "nuget", ".net": "nuget",
}
_TIMEOUT = 8
_WORKERS = 8
_BASE = "https://api.deps.dev/v3/systems/{sys}/packages/{name}/versions/{ver}"
_NON_STD = {"non-standard", "unknown", ""}


def _get(url: str) -> Optional[Dict[str, Any]]:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "bts-sbom/0.1.0"})
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as r:
            if r.status != 200:
                return None
            return json.loads(r.read().decode("utf-8"))
    except Exception as e:
        logger.debug("deps.dev fetch failed for %s: %s", url, e)
        return None


def version_info(ecosystem: str, name: str, version: str) -> Optional[Dict[str, Any]]:
    """One deps.dev GetVersion call -> {license, published_at, deprecated,
    deprecated_reason, provenance_count, attestation_count}.  None when the
    ecosystem is unsupported, an argument is empty, or the lookup failed."""
    system = _SYSTEM.get((ecosystem or "").strip().lower())
    if not system or not name or not version:
        return None
    url = _BASE.format(sys=system,
                       name=urllib.parse.quote(name, safe=""),
                       ver=urllib.parse.quote(version, safe=""))
    data = _get(url)
    if not data:
        return None
    lics = [x for x in (data.get("licenses") or []) if x and x.lower() not in _NON_STD]
    lic = (" AND ".join(lics) if len(lics) > 1 else lics[0]) if lics else None
    return {
        "license": lic,
        "published_at": data.get("publishedAt") or None,
        "deprecated": bool(data.get("isDeprecated")),
        "deprecated_reason": data.get("deprecatedReason") or None,
        "provenance_count": len(data.get("slsaProvenances") or []),
        "attestation_count": len(data.get("attestations") or []),
    }


def license_for(ecosystem: str, name: str, version: str) -> Optional[str]:
    """Resolve one package's SPDX license expression from deps.dev, or None."""
    info = version_info(ecosystem, name, version)
    return info["license"] if info else None


def enrich_licenses(packages: List[Dict[str, Any]], offline: bool = False) -> Dict[str, Any]:
    """Fill pkg['license'] in place from deps.dev when missing. Returns a disclosure
    dict: {resolved, unresolved, already_had, source}. Never overwrites a license
    that a manifest/SBOM already provided."""
    resolved = unresolved = had = 0
    if offline:
        for p in packages:
            if not p.get("license"):
                unresolved += 1
            else:
                had += 1
        return {"resolved": 0, "unresolved": unresolved, "already_had": had,
                "source": "deps.dev", "note": "offline — license resolution skipped"}
    todo: List[Dict[str, Any]] = []
    for p in packages:
        if p.get("license"):
            had += 1
        else:
            todo.append(p)
    # One lookup per distinct (ecosystem, name, version); the lookups are network
    # bound, so they run in a small pool instead of one blocking round trip each.
    distinct = {}
    for p in todo:
        distinct.setdefault((p.get("ecosystem", ""), p.get("name", ""), p.get("version", "")), None)
    keys = list(distinct)
    workers = max(1, min(_WORKERS, len(keys)))
    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="depsdev") as pool:
            for key, lic in zip(keys, pool.map(lambda k: license_for(*k), keys)):
                distinct[key] = lic
    else:
        for key in keys:
            distinct[key] = license_for(*key)
    for p in todo:
        lic = distinct.get((p.get("ecosystem", ""), p.get("name", ""), p.get("version", "")))
        if lic:
            p["license"] = lic
            resolved += 1
        else:
            unresolved += 1
    return {"resolved": resolved, "unresolved": unresolved, "already_had": had,
            "source": "deps.dev"}


def enrich(packages: List[Dict[str, Any]], offline: bool = False,
           fetcher=None) -> Dict[str, Any]:
    """License AND release metadata in one deps.dev pass.

    Same disclosure contract as ``enrich_licenses`` (resolved / unresolved /
    already_had / source) plus ``metadata_resolved``.  Sets, only where deps.dev
    answered: ``published_at``, ``deprecated`` (+ ``deprecated_reason``),
    ``provenance_attested`` (a SLSA provenance or attestation is published).
    A manifest/SBOM-provided license is never overwritten.  ``fetcher`` is
    injectable for tests; offline performs no network I/O."""
    resolved = unresolved = had = meta = 0
    if offline:
        for p in packages:
            if p.get("license"):
                had += 1
            else:
                unresolved += 1
        return {"resolved": 0, "unresolved": unresolved, "already_had": had,
                "metadata_resolved": 0, "source": "deps.dev",
                "note": "offline - license / release metadata resolution skipped"}
    do = fetcher or version_info
    keys: Dict[Any, Any] = {}
    for p in packages:
        keys.setdefault((p.get("ecosystem", ""), p.get("name", ""), p.get("version", "")), None)
    ordered = list(keys)
    workers = max(1, min(_WORKERS, len(ordered)))
    if workers > 1:
        from concurrent.futures import ThreadPoolExecutor
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="depsdev") as pool:
            for key, info in zip(ordered, pool.map(lambda k: do(*k), ordered)):
                keys[key] = info
    else:
        for key in ordered:
            keys[key] = do(*key)
    counted = set()
    for p in packages:
        key = (p.get("ecosystem", ""), p.get("name", ""), p.get("version", ""))
        info = keys.get(key)
        if p.get("license"):
            had += 1
        elif info and info.get("license"):
            p["license"] = info["license"]
            resolved += 1
        else:
            unresolved += 1
        if info:
            if info.get("published_at"):
                p["published_at"] = info["published_at"]
            p["deprecated"] = bool(info.get("deprecated"))
            if info.get("deprecated_reason"):
                p["deprecated_reason"] = info["deprecated_reason"]
            p["provenance_attested"] = bool(info.get("provenance_count") or info.get("attestation_count"))
            if key not in counted:
                counted.add(key)
                meta += 1
    return {"resolved": resolved, "unresolved": unresolved, "already_had": had,
            "metadata_resolved": meta, "source": "deps.dev"}
