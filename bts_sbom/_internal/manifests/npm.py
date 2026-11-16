# vendored from common/manifests/npm.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""npm package-lock.json parser (lockfileVersion 2/3) — exact versions + tree."""
import json
from typing import List, Any

from bts_sbom._internal.models import DetectedPackage


def _mk(name, version, relationship, depth, parents):
    return DetectedPackage(
        name=name, version=version, ecosystem="npm",
        purl=f"pkg:npm/{name}@{version}", source="manifest:npm",
        provenance=["manifest:npm"], relationship=relationship, depth=depth,
        dependency_parents=parents, confidence="high",
    )


def parse(text: str, path: str = "") -> List[Any]:
    """Parse a package-lock.json (v2/v3). Direct = a dependency of the root package;
    transitive = nested under node_modules. Depth = node_modules nesting level."""
    try:
        data = json.loads(text)
    except Exception:
        return []

    out: List[Any] = []
    packages = data.get("packages")
    if isinstance(packages, dict):
        root = packages.get("", {}) or {}
        direct_names = set(root.get("dependencies", {}) or {}) \
            | set(root.get("devDependencies", {}) or {}) \
            | set(root.get("optionalDependencies", {}) or {})
        for pkg_path, meta in packages.items():
            if pkg_path == "" or not isinstance(meta, dict):
                continue
            # v3 lockfiles include workspace symlinks with "link": true.
            # These are local path aliases, not real npm packages; skip them.
            if meta.get("link"):
                continue
            version = meta.get("version")
            if not version:
                continue
            # "node_modules/a/node_modules/b" → name b, depth 2
            segs = [s for s in pkg_path.split("node_modules/") if s]
            name = segs[-1].strip("/") if segs else pkg_path
            depth = pkg_path.count("node_modules/")
            relationship = "direct" if (depth == 1 and name in direct_names) else "transitive"
            out.append(_mk(name, version, relationship, max(0, depth - 1), []))
        return out

    # lockfileVersion 1 fallback: nested "dependencies" tree.
    def walk(deps, depth, parents):
        for name, meta in (deps or {}).items():
            ver = meta.get("version")
            if ver:
                rel = "direct" if depth == 0 else "transitive"
                out.append(_mk(name, ver, rel, depth, parents))
            walk(meta.get("dependencies", {}), depth + 1, [name])
    walk(data.get("dependencies", {}), 0, [])
    return out


def parse_manifest(text: str, path: str = "") -> List[Any]:
    """Parse exact direct dependencies from ``package.json``.

    npm semver ranges cannot identify the installed version, so only literal
    versions (or an explicit ``=version``) are emitted. Projects with ranges must
    provide package-lock/yarn/pnpm lock data; returning an invented floor version
    would create false-negative vulnerability results.
    """
    try:
        data = json.loads(text)
    except Exception:
        return []

    exact = __import__("re").compile(r"^=?([0-9]+(?:\.[0-9A-Za-z-]+){1,3})$")
    out: List[Any] = []
    seen = set()
    for section in ("dependencies", "devDependencies", "optionalDependencies",
                    "peerDependencies"):
        deps = data.get(section) or {}
        if not isinstance(deps, dict):
            continue
        for name, spec in deps.items():
            match = exact.match(str(spec).strip())
            if not name or not match:
                continue
            version = match.group(1)
            key = (name, version)
            if key not in seen:
                seen.add(key)
                out.append(_mk(name, version, "direct", 0, []))
    return out
