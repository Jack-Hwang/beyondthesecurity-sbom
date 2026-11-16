# vendored from common/manifests/cargo.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""
Raw-dict dependency parsers for Rust (Cargo.lock / Cargo.toml) and Java
(build.gradle / build.gradle.kts).  These return plain ``List[Dict]`` — not
DetectedPackage objects — so that SupplyChainAnalyzer and other callers that
operate on untyped records can consume them directly without importing
sca_guard.agent.state.

DetectedPackage-producing parsers for the manifest-pipeline live in extra.py;
these functions are separate and intended for supply-chain / namespace-confusion
analysis where the richer metadata (checksum, raw dep list, group) matters.
"""
import re
from typing import Dict, List, Optional

try:
    import tomllib          # Python 3.11+
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None          # type: ignore[assignment]


# ── Rust: Cargo.lock ─────────────────────────────────────────────────────────

def parse_cargo_lock(content: str) -> List[Dict]:
    """Parse all ``[[package]]`` sections from a Cargo.lock file.

    Returns a list of dicts:
      name         — crate name (str)
      version      — exact resolved version string (str; may be '' for virtual
                     workspace roots that Cargo records without a version)
      ecosystem    — 'crates.io' when the entry has a 'source' field,
                     'local' otherwise (workspace members / path crates).
                     'local' packages are returned but callers SHOULD skip
                     vulnerability scanning for them.
      checksum     — hex SHA-256 checksum string, or None when absent
      dependencies — list of *direct* dependency crate name strings extracted
                     from the dependencies array in this package's block

    Packages whose 'version' field is entirely absent are still returned with
    version='' so that callers can decide how to handle incomplete entries
    rather than silently dropping them.
    """
    if tomllib is not None:
        try:
            data = tomllib.loads(content)
        except Exception:
            data = None
        if data is not None:
            return _cargo_lock_from_dict(data)
    # Fallback: regex-based parser for environments without tomllib.
    return _cargo_lock_regex(content)


def _cargo_lock_from_dict(data: dict) -> List[Dict]:
    out: List[Dict] = []
    for pkg in data.get("package", []) or []:
        name = pkg.get("name")
        if not name:
            continue
        version: str = pkg.get("version") or ""
        has_source = bool(pkg.get("source"))
        ecosystem = "crates.io" if has_source else "local"
        checksum: Optional[str] = pkg.get("checksum") or None
        # Cargo.lock dep strings: "serde 1.0.193 (registry+...)" — keep only name.
        raw_deps = pkg.get("dependencies") or []
        deps: List[str] = []
        for d in raw_deps:
            if isinstance(d, str):
                deps.append(d.split()[0])
            else:
                deps.append(str(d))
        out.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "checksum": checksum,
            "dependencies": deps,
        })
    return out


# Matches one [[package]] block up to the next [[package]] or EOF.
_LOCK_PKG_RE = re.compile(
    r'\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)', re.DOTALL
)
# Scalar string fields: key = "value"
_LOCK_FIELD_RE = re.compile(r'^(\w+)\s*=\s*"([^"]*)"', re.MULTILINE)
# The dependencies = [ ... ] array block.
_LOCK_DEPS_RE = re.compile(
    r'^dependencies\s*=\s*\[(.*?)\]', re.DOTALL | re.MULTILINE
)


def _cargo_lock_regex(content: str) -> List[Dict]:
    """Regex-based Cargo.lock parser used when tomllib is unavailable."""
    out: List[Dict] = []
    for bm in _LOCK_PKG_RE.finditer(content):
        block = bm.group(1)
        fields: Dict[str, str] = dict(_LOCK_FIELD_RE.findall(block))
        name = fields.get("name")
        if not name:
            continue
        version: str = fields.get("version", "")
        has_source = "source" in fields
        ecosystem = "crates.io" if has_source else "local"
        checksum: Optional[str] = fields.get("checksum") or None
        deps: List[str] = []
        dm = _LOCK_DEPS_RE.search(block)
        if dm:
            for d in re.findall(r'"([^"]+)"', dm.group(1)):
                deps.append(d.split()[0])
        out.append({
            "name": name,
            "version": version,
            "ecosystem": ecosystem,
            "checksum": checksum,
            "dependencies": deps,
        })
    return out


# ── Rust: Cargo.toml ─────────────────────────────────────────────────────────

def parse_cargo_toml(content: str) -> List[Dict]:
    """Parse ``[dependencies]``, ``[dev-dependencies]``, and
    ``[build-dependencies]`` from a Cargo.toml file.

    Handles both simple and inline-table forms:
      serde = "1.0"
      serde = { version = "1.0", features = ["derive"] }

    Path and git dependencies (which have no resolvable semver version) are
    skipped so that callers never receive a fabricated version string.

    Returns the same dict format as ``parse_cargo_lock``:
      name, version (the spec string — may contain ``^``, ``~``, ``*``),
      ecosystem='crates.io', checksum=None, dependencies=[].
    """
    if tomllib is not None:
        try:
            data = tomllib.loads(content)
        except Exception:
            data = None
        if data is not None:
            return _cargo_toml_from_dict(data)
    return _cargo_toml_regex(content)


def _cargo_toml_from_dict(data: dict) -> List[Dict]:
    out: List[Dict] = []
    seen: set = set()
    for section in ("dependencies", "dev-dependencies", "build-dependencies"):
        block = data.get(section) or {}
        if not isinstance(block, dict):
            continue
        for name, spec in block.items():
            if name in seen:
                continue
            version = _cargo_spec_version(spec)
            if version is None:
                continue    # path / git dep — skip
            seen.add(name)
            out.append({
                "name": name,
                "version": version,
                "ecosystem": "crates.io",
                "checksum": None,
                "dependencies": [],
            })
    return out


def _cargo_spec_version(spec) -> Optional[str]:
    """Extract a semver spec string from a Cargo dependency spec, or None."""
    if isinstance(spec, str):
        return spec.strip()
    if isinstance(spec, dict):
        if "path" in spec or "git" in spec:
            return None     # local / VCS dep — no publishable version
        v = spec.get("version")
        return v.strip() if isinstance(v, str) else None
    return None


# Regex fallback for Cargo.toml without tomllib.
# Matches: name = "version"  (simple form)
_TOML_SIMPLE_RE = re.compile(
    r'^([A-Za-z0-9_\-]+)\s*=\s*"([^"]+)"', re.MULTILINE
)
# Matches: name = { ... }  (inline table)
_TOML_INLINE_RE = re.compile(
    r'^([A-Za-z0-9_\-]+)\s*=\s*\{([^}]*)\}', re.MULTILINE
)
_TOML_VER_IN_TABLE_RE = re.compile(r'version\s*=\s*"([^"]+)"')


def _cargo_toml_regex(content: str) -> List[Dict]:
    """Regex-based Cargo.toml parser when tomllib is unavailable."""
    out: List[Dict] = []
    seen: set = set()
    # Split on '[section]' headers.  Each chunk starts with the part after '['.
    chunks = re.split(r'^\[', content, flags=re.MULTILINE)
    for chunk in chunks:
        hm = re.match(
            r'(dependencies|dev-dependencies|build-dependencies)\]', chunk
        )
        if not hm:
            continue
        body = chunk[hm.end():]
        # Simple: name = "version"
        for m in _TOML_SIMPLE_RE.finditer(body):
            name, version = m.group(1), m.group(2)
            if name not in seen:
                seen.add(name)
                out.append({
                    "name": name, "version": version,
                    "ecosystem": "crates.io", "checksum": None, "dependencies": [],
                })
        # Inline table: name = { version = "...", ... }
        for m in _TOML_INLINE_RE.finditer(body):
            name, table_body = m.group(1), m.group(2)
            if name in seen:
                continue
            if "path" in table_body or "git" in table_body:
                continue    # skip local / VCS deps
            vm = _TOML_VER_IN_TABLE_RE.search(table_body)
            if vm:
                seen.add(name)
                out.append({
                    "name": name, "version": vm.group(1),
                    "ecosystem": "crates.io", "checksum": None, "dependencies": [],
                })
    return out


# ── Java: build.gradle / build.gradle.kts ────────────────────────────────────

# Matches dependency declarations using the common Gradle configuration keywords
# in both Groovy DSL (single or double quotes) and Kotlin DSL (double quotes).
_GRADLE_DEP_RE = re.compile(
    r"""(?x)
    (?:implementation|compile|testImplementation|testCompile|api|
       runtimeOnly|compileOnly|annotationProcessor|kapt|classpath|
       testRuntimeOnly|testCompileOnly|debugImplementation|releaseImplementation)
    \s*(?:\(\s*)?                 # Groovy whitespace or Kotlin call parenthesis
    ['"]                          # opening quote
    ([A-Za-z0-9.\-_]+)           # groupId
    :
    ([A-Za-z0-9.\-_]+)           # artifactId
    :
    ([A-Za-z0-9.\-_+$\{\}]+)    # version (allow ${var} placeholders)
    ['"]\s*\)?                   # closing quote / optional Kotlin parenthesis
    """,
    re.MULTILINE,
)


def parse_gradle_build(content: str) -> List[Dict]:
    """Parse dependency declarations from a ``build.gradle`` (Groovy DSL) or
    ``build.gradle.kts`` (Kotlin DSL) file.

    Recognised configuration keywords (both DSL flavours):
      implementation, compile, testImplementation, testCompile, api,
      runtimeOnly, compileOnly, annotationProcessor, kapt, classpath,
      testRuntimeOnly, testCompileOnly, debugImplementation,
      releaseImplementation.

    Version strings that contain ``${...}`` (Gradle property references) are
    included as-is — callers may choose to skip them if an exact version is
    required for vulnerability matching.

    Returns a list of dicts:
      name      — artifactId (str)
      version   — version string, which may be a ``${prop}`` reference (str)
      group     — groupId (str)
      ecosystem — 'maven'
    """
    out: List[Dict] = []
    seen: set = set()
    for m in _GRADLE_DEP_RE.finditer(content):
        group, artifact, version = m.group(1), m.group(2), m.group(3)
        key = (group, artifact, version)
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "name": artifact,
            "version": version,
            "group": group,
            "ecosystem": "maven",
        })
    return out
