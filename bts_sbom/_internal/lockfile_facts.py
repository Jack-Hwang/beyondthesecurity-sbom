# vendored from common/lockfile_facts.py (Apache-2.0 release) -- imports rewritten to bts_sbom._internal.
"""Per-component facts a lockfile really carries: download location, artifact
hash and the dependency EDGES.

Why this exists: the manifest parsers (common/manifests) return only
name/version/ecosystem, so every SBOM built from them said
``downloadLocation: NOASSERTION``, carried no hashes and - worst - asserted a
flat dependency graph (every component ``dependsOn: []`` = "has no
dependencies").  The lockfiles DO record all of that; this module reads it.

Honesty rules (same discipline as the rest of the engine):
  * a value appears only when the lockfile states it.  No registry guessing, no
    name-similarity edges; an edge exists only when the lockfile's own
    dependency table names it and the target resolves to exactly one component.
  * ``roots`` (the project's direct dependencies) is reported only when the
    lockfile (or the sibling manifest the lockfile is generated from) names the
    root requirement set.  Otherwise it is ``None`` and the caller keeps the
    parser's own classification - never a guess.
  * hashes are converted to lowercase HEX (npm ``integrity`` is base64 SRI;
    SPDX/CycloneDX both require hex).  A malformed digest is dropped, not
    "repaired".

Supported: npm package-lock v1/v2/v3 + npm-shrinkwrap, yarn.lock v1, Cargo.lock,
poetry.lock, composer.lock.  Everything else returns ``None`` (no facts) and the
limitation is visible downstream as ``graph_known: false``.
"""
from __future__ import annotations

import base64
import binascii
import json
import os
import re
from collections import deque
from typing import Any, Dict, List, Optional, Tuple

try:  # py3.11+
    import tomllib
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

Key = Tuple[str, str]          # (normalized name, version)

_SRI = re.compile(r"^(sha1|sha256|sha384|sha512)-([A-Za-z0-9+/]+={0,2})$")
_HEXLEN = {"sha1": 40, "sha256": 64, "sha384": 96, "sha512": 128}
_ALG_NAME = {"sha1": "SHA-1", "sha256": "SHA-256", "sha384": "SHA-384", "sha512": "SHA-512"}
_STRENGTH = ["sha1", "sha256", "sha384", "sha512"]


def norm_name(ecosystem: str, name: Any) -> str:
    n = str(name or "")
    if str(ecosystem).lower() in ("pypi", "python"):
        return re.sub(r"[-_.]+", "-", n).lower()
    return n.lower()


def hex_hash(alg: str, digest: Any) -> Optional[Dict[str, str]]:
    """{'alg': 'SHA-256', 'content': '<hex>'} or None when ``digest`` is not a
    well-formed hex digest of that algorithm."""
    a = str(alg or "").lower().replace("-", "")
    d = str(digest or "").strip().lower()
    if a in _HEXLEN and len(d) == _HEXLEN[a] and re.fullmatch(r"[0-9a-f]+", d):
        return {"alg": _ALG_NAME[a], "content": d}
    return None


def sri_to_hash(integrity: Any) -> Optional[Dict[str, str]]:
    """Subresource-Integrity string (``sha512-<base64>``, possibly several,
    space separated) -> strongest well-formed hash as hex, else None."""
    best: Optional[Tuple[int, Dict[str, str]]] = None
    for tok in str(integrity or "").split():
        m = _SRI.match(tok.strip())
        if not m:
            continue
        alg, b64 = m.group(1), m.group(2)
        try:
            raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        h = hex_hash(alg, raw.hex())
        if h and (best is None or _STRENGTH.index(alg) > best[0]):
            best = (_STRENGTH.index(alg), h)
    return best[1] if best else None


class LockFacts:
    __slots__ = ("ecosystem", "basis", "components", "roots", "graph_complete")

    def __init__(self, ecosystem: str, basis: str):
        self.ecosystem = ecosystem
        self.basis = basis
        #: Key -> {"name","version","download","hashes":[{alg,content}],
        #:         "children":[Key], "local":bool}
        self.components: Dict[Key, Dict[str, Any]] = {}
        #: direct dependencies of the project, or None when the root is unnamed
        self.roots: Optional[List[Key]] = None
        #: True when every component's own dependency table is present
        self.graph_complete = True

    def add(self, name: str, version: str, *, download: Optional[str] = None,
            hashes: Optional[List[Dict[str, str]]] = None, local: bool = False) -> Key:
        key = (norm_name(self.ecosystem, name), str(version))
        rec = self.components.setdefault(key, {
            "name": name, "version": str(version), "download": None,
            "hashes": [], "children": [], "local": local})
        if download and not rec["download"]:
            rec["download"] = download
        for h in hashes or []:
            if h not in rec["hashes"]:
                rec["hashes"].append(h)
        return key

    def link(self, parent: Key, child: Key) -> None:
        if parent == child or parent not in self.components or child not in self.components:
            return
        ch = self.components[parent]["children"]
        if child not in ch:
            ch.append(child)


# ----------------------------------------------------------------------- npm
def _npm_resolve(packages: Dict[str, Any], path: str, name: str) -> Optional[str]:
    """Node module resolution over a v2/v3 ``packages`` map: look in
    ``<path>/node_modules/<name>``, then climb one node_modules level at a time."""
    cur = path
    while True:
        cand = (cur + "/node_modules/" + name) if cur else ("node_modules/" + name)
        if cand in packages and isinstance(packages[cand], dict):
            return cand
        if not cur:
            return None
        idx = cur.rfind("node_modules/")
        cur = cur[:idx].rstrip("/") if idx >= 0 else ""


def _npm_name_from_path(pkg_path: str) -> str:
    segs = [s for s in pkg_path.split("node_modules/") if s]
    return segs[-1].strip("/") if segs else pkg_path


def _npm_v2(data: Dict[str, Any], facts: LockFacts) -> None:
    packages: Dict[str, Any] = data["packages"]
    path_key: Dict[str, Key] = {}
    for pkg_path, meta in packages.items():
        if pkg_path == "" or not isinstance(meta, dict) or meta.get("link"):
            continue
        version = meta.get("version")
        if not version:
            continue
        name = _npm_name_from_path(pkg_path)
        hashes = []
        h = sri_to_hash(meta.get("integrity"))
        if h:
            hashes.append(h)
        path_key[pkg_path] = facts.add(name, version, download=meta.get("resolved") or None,
                                       hashes=hashes)
    for pkg_path, key in path_key.items():
        meta = packages[pkg_path]
        for field in ("dependencies", "optionalDependencies", "peerDependencies"):
            for dep in (meta.get(field) or {}):
                target = _npm_resolve(packages, pkg_path, dep)
                if target in path_key:
                    facts.link(key, path_key[target])
    root = packages.get("") or {}
    names = set()
    for field in ("dependencies", "devDependencies", "optionalDependencies"):
        names |= set((root.get(field) or {}))
    if isinstance(packages.get(""), dict):
        roots = []
        for dep in sorted(names):
            target = _npm_resolve(packages, "", dep)
            if target in path_key and path_key[target] not in roots:
                roots.append(path_key[target])
        facts.roots = roots


def _npm_v1(data: Dict[str, Any], facts: LockFacts, lock_dir: str) -> None:
    top = data.get("dependencies") or {}
    node_key: Dict[int, Key] = {}

    def register(deps: Dict[str, Any]) -> None:
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict) or not meta.get("version"):
                continue
            h = sri_to_hash(meta.get("integrity"))
            node_key[id(meta)] = facts.add(name, meta["version"],
                                           download=meta.get("resolved") or None,
                                           hashes=[h] if h else [])
            register(meta.get("dependencies") or {})

    register(top)

    def lookup(name: str, chain: List[Dict[str, Any]]) -> Optional[Key]:
        for scope in reversed(chain):               # nearest enclosing node first
            m = (scope or {}).get(name)
            if isinstance(m, dict) and id(m) in node_key:
                return node_key[id(m)]
        return None

    def link_all(deps: Dict[str, Any], chain: List[Dict[str, Any]]) -> None:
        for name, meta in (deps or {}).items():
            if not isinstance(meta, dict) or id(meta) not in node_key:
                continue
            nested = meta.get("dependencies") or {}
            scopes = chain + [nested]
            for req in (meta.get("requires") or {}):
                child = lookup(req, scopes)
                if child:
                    facts.link(node_key[id(meta)], child)
            link_all(nested, scopes)

    link_all(top, [top])
    # v1 lockfiles do not name the root requirement set - take it from the
    # package.json the lockfile was generated from, when it is next to it.
    pj = os.path.join(lock_dir, "package.json") if lock_dir else ""
    if pj and os.path.isfile(pj):
        try:
            with open(pj, "r", encoding="utf-8-sig", errors="replace") as fh:
                root = json.load(fh)
        except Exception:
            root = None
        if isinstance(root, dict):
            roots = []
            for field in ("dependencies", "devDependencies", "optionalDependencies"):
                for dep in (root.get(field) or {}):
                    k = lookup(dep, [top])
                    if k and k not in roots:
                        roots.append(k)
            facts.roots = roots


def _npm(path: str, text: str) -> Optional[LockFacts]:
    try:
        data = json.loads(text)
    except Exception:
        return None
    if not isinstance(data, dict):
        return None
    if isinstance(data.get("packages"), dict):
        facts = LockFacts("npm", "npm lockfile v%s (node resolution over `packages`)"
                          % data.get("lockfileVersion", "2/3"))
        _npm_v2(data, facts)
        return facts
    if isinstance(data.get("dependencies"), dict):
        facts = LockFacts("npm", "npm lockfile v1 (nested `requires`)")
        _npm_v1(data, facts, os.path.dirname(path) if path else "")
        return facts
    return None


# ---------------------------------------------------------------------- yarn
_YARN_SPEC = re.compile(r'^(?P<name>@?[^@\s"]+)@(?P<rng>.+)$')


def _yarn_v1(path: str, text: str) -> Optional[LockFacts]:
    if "__metadata:" in text:                    # yarn berry: different grammar
        return None
    facts = LockFacts("npm", "yarn.lock v1 (`dependencies` blocks)")
    blocks: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    in_deps = False
    for raw in text.splitlines():
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        if not raw[0].isspace():
            if raw.rstrip().endswith(":"):
                specs = [s.strip().strip('"') for s in raw.rstrip()[:-1].split(",")]
                cur = {"specs": specs, "version": None, "resolved": None,
                       "integrity": None, "deps": []}
                blocks.append(cur)
                in_deps = False
            else:
                cur = None
            continue
        if cur is None:
            continue
        indent = len(raw) - len(raw.lstrip())
        line = raw.strip()
        if indent == 2:
            in_deps = line in ("dependencies:", "optionalDependencies:")
            m = re.match(r'^(version|resolved|integrity)\s+"?([^"]+?)"?\s*$', line)
            if m:
                cur[m.group(1)] = m.group(2)
        elif indent >= 4 and in_deps:
            m = re.match(r'^"?(@?[^"\s]+)"?\s+"?([^"]+?)"?\s*$', line)
            if m:
                cur["deps"].append((m.group(1), m.group(2)))
    spec_key: Dict[str, Key] = {}
    block_key: List[Optional[Key]] = []
    for b in blocks:
        if not b["version"]:
            block_key.append(None)
            continue
        m = _YARN_SPEC.match(b["specs"][0])
        name = m.group("name") if m else b["specs"][0]
        h = sri_to_hash(b["integrity"])
        url = (b["resolved"] or "").split("#", 1)[0] or None
        k = facts.add(name, b["version"], download=url, hashes=[h] if h else [])
        block_key.append(k)
        for s in b["specs"]:
            spec_key[s] = k
    for b, k in zip(blocks, block_key):
        if k is None:
            continue
        for dname, rng in b["deps"]:
            child = spec_key.get("%s@%s" % (dname, rng))
            if child:
                facts.link(k, child)
    pj = os.path.join(os.path.dirname(path), "package.json") if path else ""
    if pj and os.path.isfile(pj):
        try:
            with open(pj, "r", encoding="utf-8-sig", errors="replace") as fh:
                root = json.load(fh)
        except Exception:
            root = None
        if isinstance(root, dict):
            roots: List[Key] = []
            for field in ("dependencies", "devDependencies", "optionalDependencies"):
                for dname, rng in (root.get(field) or {}).items():
                    k = spec_key.get("%s@%s" % (dname, rng))
                    if k and k not in roots:
                        roots.append(k)
            facts.roots = roots
    return facts


# --------------------------------------------------------------------- cargo
_CRATES_SOURCES = ("registry+https://github.com/rust-lang/crates.io-index",
                   "sparse+https://index.crates.io/")


def _cargo_download(name: str, version: str, source: str) -> Optional[str]:
    if source.startswith(_CRATES_SOURCES):
        return "https://crates.io/api/v1/crates/%s/%s/download" % (name, version)
    if source.startswith("git+"):
        url, _, commit = source[4:].partition("#")
        url = url.split("?", 1)[0]
        return "git+%s%s" % (url, ("@" + commit) if commit else "")
    return None


def _cargo(path: str, text: str) -> Optional[LockFacts]:
    if tomllib is None:
        return None
    try:
        data = tomllib.loads(text)
    except Exception:
        return None
    pkgs = [p for p in (data.get("package") or []) if isinstance(p, dict)
            and p.get("name") and p.get("version")]
    if not pkgs:
        return None
    facts = LockFacts("crates.io", "Cargo.lock (`dependencies` tables)")
    keys: List[Key] = []
    by_name: Dict[str, List[Key]] = {}
    members: List[Key] = []
    for p in pkgs:
        source = str(p.get("source") or "")
        local = not source                        # no `source` = workspace member / path crate
        h = hex_hash("sha256", p.get("checksum"))
        k = facts.add(p["name"], p["version"], download=_cargo_download(p["name"], p["version"], source),
                      hashes=[h] if h else [], local=local)
        keys.append(k)
        by_name.setdefault(p["name"], []).append(k)
        if local:
            members.append(k)
    for p, k in zip(pkgs, keys):
        for dep in p.get("dependencies") or []:
            parts = str(dep).split()
            cands = by_name.get(parts[0], [])
            if len(parts) >= 2:
                cands = [c for c in cands if c[1] == parts[1]]
            if len(cands) == 1:
                facts.link(k, cands[0])
    roots: List[Key] = []
    for m in members:
        for c in facts.components[m]["children"]:
            if c not in roots and not facts.components[c]["local"]:
                roots.append(c)
    facts.roots = roots if members else None
    return facts


# -------------------------------------------------------------------- poetry
def _pep508_name(spec: str) -> str:
    m = re.match(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)", str(spec))
    return m.group(1) if m else ""


def _poetry_roots(lock_dir: str) -> Optional[List[str]]:
    pp = os.path.join(lock_dir, "pyproject.toml") if lock_dir else ""
    if not (pp and os.path.isfile(pp) and tomllib is not None):
        return None
    try:
        with open(pp, "rb") as fh:
            data = tomllib.load(fh)
    except Exception:
        return None
    names: List[str] = []
    poetry = (data.get("tool") or {}).get("poetry") or {}
    for n in (poetry.get("dependencies") or {}):
        if n.lower() != "python":
            names.append(n)
    for n in (poetry.get("dev-dependencies") or {}):
        names.append(n)
    for grp in (poetry.get("group") or {}).values():
        for n in ((grp or {}).get("dependencies") or {}):
            names.append(n)
    proj = data.get("project") or {}
    for spec in proj.get("dependencies") or []:
        n = _pep508_name(spec)
        if n:
            names.append(n)
    for specs in (proj.get("optional-dependencies") or {}).values():
        for spec in specs or []:
            n = _pep508_name(spec)
            if n:
                names.append(n)
    for specs in (data.get("dependency-groups") or {}).values():
        for spec in specs or []:
            if isinstance(spec, str):
                n = _pep508_name(spec)
                if n:
                    names.append(n)
    return names or None


def _poetry(path: str, text: str) -> Optional[LockFacts]:
    if tomllib is None:
        return None
    try:
        data = tomllib.loads(text)
    except Exception:
        return None
    pkgs = [p for p in (data.get("package") or []) if isinstance(p, dict)
            and p.get("name") and p.get("version")]
    if not pkgs:
        return None
    facts = LockFacts("pypi", "poetry.lock (`[package.dependencies]`)")
    by_name: Dict[str, List[Key]] = {}
    keys: List[Key] = []
    for p in pkgs:
        k = facts.add(p["name"], p["version"])
        keys.append(k)
        by_name.setdefault(k[0], []).append(k)
    for p, k in zip(pkgs, keys):
        for dep in (p.get("dependencies") or {}):
            cands = by_name.get(norm_name("pypi", dep), [])
            if len(cands) == 1:
                facts.link(k, cands[0])
    root_names = _poetry_roots(os.path.dirname(path) if path else "")
    if root_names:
        roots: List[Key] = []
        for n in root_names:
            cands = by_name.get(norm_name("pypi", n), [])
            if len(cands) == 1 and cands[0] not in roots:
                roots.append(cands[0])
        facts.roots = roots
    return facts


# one entry of a poetry [package.dependencies] table may be a list of markers
# variants; the name is the table key, which is all we use.

# ------------------------------------------------------------------ composer
def _composer(path: str, text: str) -> Optional[LockFacts]:
    try:
        data = json.loads(text)
    except Exception:
        return None
    entries: List[Dict[str, Any]] = []
    for sect in ("packages", "packages-dev"):
        for p in data.get(sect) or []:
            if isinstance(p, dict) and p.get("name") and p.get("version"):
                entries.append(p)
    if not entries:
        return None
    facts = LockFacts("composer", "composer.lock (`require` tables)")
    by_name: Dict[str, Key] = {}
    keys: List[Key] = []
    for p in entries:
        ver = p["version"]
        ver = ver[1:] if re.match(r"^v\d", ver) else ver          # same normalisation as the parser
        dist = p.get("dist") or {}
        h = hex_hash("sha1", dist.get("shasum"))
        k = facts.add(p["name"], ver, download=dist.get("url") or None,
                      hashes=[h] if h else [])
        keys.append(k)
        by_name[k[0]] = k
    for p, k in zip(entries, keys):
        for dep in (p.get("require") or {}):
            child = by_name.get(dep.lower())
            if child:
                facts.link(k, child)
    cj = os.path.join(os.path.dirname(path), "composer.json") if path else ""
    if cj and os.path.isfile(cj):
        try:
            with open(cj, "r", encoding="utf-8-sig", errors="replace") as fh:
                root = json.load(fh)
        except Exception:
            root = None
        if isinstance(root, dict):
            roots: List[Key] = []
            for field in ("require", "require-dev"):
                for dep in (root.get(field) or {}):
                    child = by_name.get(dep.lower())
                    if child and child not in roots:
                        roots.append(child)
            facts.roots = roots
    return facts


_DISPATCH = {
    "package-lock.json": _npm,
    "npm-shrinkwrap.json": _npm,
    "yarn.lock": _yarn_v1,
    "cargo.lock": _cargo,
    "poetry.lock": _poetry,
    "composer.lock": _composer,
}


def supported(path: str) -> bool:
    return os.path.basename(path or "").lower() in _DISPATCH


def extract(path: str, text: Optional[str] = None) -> Optional[LockFacts]:
    """Facts for one lockfile, or None when the format has no extractor (or the
    file does not parse - the caller's own parser already reports that)."""
    fn = _DISPATCH.get(os.path.basename(path or "").lower())
    if fn is None:
        return None
    if text is None:
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
        except Exception:
            return None
    try:
        return fn(path, text)
    except Exception:                              # an extractor bug must never fail a scan
        return None


def _bfs_depths(facts: LockFacts) -> Dict[Key, int]:
    depths: Dict[Key, int] = {}
    dq: deque = deque()
    for r in facts.roots or []:
        if r not in depths:
            depths[r] = 0
            dq.append(r)
    while dq:
        cur = dq.popleft()
        for ch in facts.components.get(cur, {}).get("children", []):
            if ch not in depths:
                depths[ch] = depths[cur] + 1
                dq.append(ch)
    return depths


def apply(facts: LockFacts, packages: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Merge ``facts`` into the parser's package dicts IN PLACE and return the
    list without local (source-less) components.

    Adds per package: ``download_location``, ``hashes``, ``depends_on``
    ([{name, version}]), ``graph_known``, ``dependency_parents`` (real parent
    names) and - only when the lockfile names the project's root requirements -
    a corrected ``relationship`` (direct/transitive) and BFS ``depth``."""
    eco = facts.ecosystem
    parents: Dict[Key, List[str]] = {}
    for k, rec in facts.components.items():
        for ch in rec["children"]:
            parents.setdefault(ch, []).append(rec["name"])
    depths = _bfs_depths(facts) if facts.roots is not None else {}
    root_set = set(facts.roots or [])
    kept: List[Dict[str, Any]] = []
    for p in packages:
        key = (norm_name(eco, p.get("name")), str(p.get("version", "")))
        rec = facts.components.get(key)
        if rec is None:
            p["graph_known"] = False
            kept.append(p)
            continue
        if rec["local"]:                           # the project's own crate, not a dependency
            continue
        if rec["download"]:
            p["download_location"] = rec["download"]
        if rec["hashes"]:
            p["hashes"] = list(rec["hashes"])
        p["depends_on"] = [{"name": facts.components[c]["name"],
                            "version": facts.components[c]["version"]} for c in rec["children"]]
        p["graph_known"] = bool(facts.graph_complete)
        p["graph_basis"] = facts.basis
        names = sorted(set(parents.get(key, [])))
        if names:
            p["dependency_parents"] = names
        if facts.roots is not None:
            if key in root_set:
                p["relationship"], p["depth"] = "direct", 0
            elif key in depths:
                p["relationship"], p["depth"] = "transitive", depths[key]
            else:                                  # in the lock but unreachable from the root
                p["relationship"] = "transitive"
                p["unreachable_from_root"] = True
            p["relationship_basis"] = "lockfile-graph"
        kept.append(p)
    return kept


__all__ = ["LockFacts", "extract", "apply", "supported", "sri_to_hash", "hex_hash", "norm_name"]
