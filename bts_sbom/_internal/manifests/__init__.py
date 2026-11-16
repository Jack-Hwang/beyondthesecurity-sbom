# vendored from common/manifests/__init__.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Manifest / lockfile dependency parsers (Tier 0-3).

Closes gap #5 (ecosystem breadth) — extends AutoGuard from firmware-only binary SCA
into Snyk Open Source's home turf: exact dependency versions + the direct-vs-
transitive graph from a project's lockfiles.

Each parser reads a lockfile/manifest and returns DetectedPackage objects with
provenance `manifest:<ecosystem>`, an ecosystem tag, and relationship/depth so the
CVE scanner can do ecosystem-aware OSV matching and upgrade-path resolution.

    from bts_sbom._internal import manifests
    pkgs = manifests.parse_file("package-lock.json")
"""
import os
from typing import List, Any

from bts_sbom._internal.manifests import npm, pip, gomod, extra, dpkg

# filename (lower) → parser module. Lockfiles preferred (exact + transitive).
_BY_NAME = {
    "package.json": npm.parse_manifest,
    "package-lock.json": npm.parse,
    "npm-shrinkwrap.json": npm.parse,
    "requirements.txt": pip.parse_requirements,
    "poetry.lock": pip.parse_poetry_lock,
    # pyproject.toml is parsed for [tool.poetry] dependency declarations.
    # When poetry.lock is also present it will be parsed separately and its
    # exact-version entries take priority through the source-priority merge.
    "pyproject.toml": extra.parse_pyproject_toml,
    "pipfile.lock": extra.parse_pipfile_lock,
    "go.mod": gomod.parse,
    "go.sum": extra.parse_go_sum,
    "cargo.lock": extra.parse_cargo_lock,
    "cargo.toml": extra.parse_cargo_toml,
    "gemfile.lock": extra.parse_gemfile_lock,
    "composer.lock": extra.parse_composer_lock,
    "pom.xml": extra.parse_pom_xml,
    "yarn.lock": extra.parse_yarn_lock,
    "packages.lock.json": extra.parse_nuget_lock,
    "gradle.lockfile": extra.parse_gradle_lock,
    "build.gradle": extra.parse_gradle_build,
    "build.gradle.kts": extra.parse_gradle_build,
    "pubspec.lock": extra.parse_pubspec_lock,
    "mix.lock": extra.parse_mix_lock,
    "conanfile.txt": extra.parse_conanfile_txt,
    "conanfile.py": extra.parse_conanfile_py,
    "vcpkg.json": extra.parse_vcpkg_json,
}

# Parsers keyed by a fixed RELATIVE-PATH SUFFIX rather than a bare basename.
# OS package-manager databases (dpkg's var/lib/dpkg/status) sit behind a
# basename ("status") far too generic to match blindly — any unrelated file
# in a scanned tree that happens to be named "status" would otherwise be
# mis-routed into the dpkg parser. These only fire when the full path ends
# with the distinctive directory structure, matched case-insensitively with
# forward slashes (so it works on both POSIX-extracted and Windows paths).
_BY_RELPATH_SUFFIX = {
    "var/lib/dpkg/status": dpkg.parse_dpkg_status,
}


def parser_for(filename: str):
    fn = _BY_NAME.get(os.path.basename(filename).lower())
    if fn is not None:
        return fn
    norm = (filename or "").replace("\\", "/").lower()
    for suffix, relfn in _BY_RELPATH_SUFFIX.items():
        if norm == suffix or norm.endswith("/" + suffix):
            return relfn
    return None


def is_supported_path(filename: str) -> bool:
    """True when ``filename`` (its basename OR its full path) matches a known
    manifest / package-database pattern. Manifest discovery uses this so
    path-keyed routes (dpkg's var/lib/dpkg/status) are found the same way
    basename-keyed routes (package.json, Cargo.lock, ...) already are."""
    return parser_for(filename) is not None


def parse_file(path: str) -> List[Any]:
    """Parse one manifest file → DetectedPackage list ([] if unsupported)."""
    fn = parser_for(path)
    if fn is None:
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            text = f.read()
    except Exception:
        return []
    return fn(text, path=path)


def supported_names() -> set:
    return set(_BY_NAME.keys())
