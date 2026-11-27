"""Patch compatibility gate: will THIS project still work on the version the patch is about to install?

Why: ``remediate.plan`` picks the lowest version that clears the advisories and rates the break risk by one bit
(major bump = "high"). Nothing looked at what the project actually uses, so a patch that deletes a function the code
calls, or that makes pip's resolver fail, was only discovered after it was merged. This module measures it BEFORE the
manifest is edited, per upgrade plan, from three facts:

  1. USED API     the symbols of the package the project's own code really touches (``ast``: imports, attribute
                  chains, call sites with their positional/keyword shape, base classes);
  2. API DIFF     the public surface of the OLD and the NEW release (``ast`` over the wheel/sdist, never executed,
                  never imported) compared on exactly those symbols: removed, moved, call sites the new signature
                  rejects, newly deprecated;
  3. CONSTRAINTS  the new release's ``Requires-Dist`` against everything else the project pins, and every other pinned
                  package's ``Requires-Dist`` against the new release (the pip-resolver failure that actually blocks
                  upgrades).

Verdict per plan (never "compatible" on thin evidence - the repo's honesty rule):
  compatible   every used symbol was found in both releases, no finding;
  partial      no break found, but some used symbols could not be judged (dynamic modules, C extensions, results of
               calls whose type is unknown) - ``coverage`` says how much was;
  review       API still exists but moved/deprecated/changed shape where call sites could not be proven safe;
  breaking     a used symbol is gone, a call site is rejected by the new signature, or a pin constraint conflicts;
  unverified   no usable artifacts / offline / unsupported ecosystem / budget - the major-bump prior is all there is;
  not_direct   the project's own code never imports the package (transitive): only the constraint check applies.

Gate: with ``mode="block"`` a ``breaking`` plan is HELD (``patch.apply(hold=...)`` skips it, with the evidence as the
reason) while the safe plans still go through; ``warn`` only reports; ``off`` skips everything. ``unverified`` never
holds (absence of evidence is not evidence of a break) but is never reported as compatible either.

Everything here is static and offline-testable: artifacts come from an injectable provider, downloads are parsed in
memory (no extraction to disk, no path traversal surface) and bounded in size, member count and uncompressed bytes.
"""
from __future__ import annotations

import ast
import difflib
import io
import os
import re
import tarfile
import time
import zlib
import zipfile
from collections import Counter
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from . import compat_c, engine, net, resilience, versions

SCHEMA = "bts-sbom.compat.v1"
MODES = ("off", "warn", "block")
COMPATIBLE, PARTIAL, REVIEW, BREAKING, UNVERIFIED, NOT_DIRECT = (
    "compatible", "partial", "review", "breaking", "unverified", "not_direct")
HONESTY = [
    "static analysis: a behaviour change inside an unchanged signature is not detected (the opt-in runtime differential covers that)",
    "methods called on a RETURNED object are not tracked (no type inference): only symbols reachable from the package namespace are judged",
    "C extensions and dynamically built modules cannot be resolved: those symbols are counted as unresolved, never as compatible",
    "supported ecosystem: PyPI (Python source); other ecosystems stay unverified with the major-bump prior",
]

MAX_ARTIFACT_BYTES = 40_000_000
MAX_MEMBERS = 8000
MAX_FILE_BYTES = 1_500_000
MAX_TOTAL_BYTES = 80_000_000
MAX_UNCOMPRESSED = 160_000_000           # a gzip stream may not inflate past this (decompression-bomb guard)
MAX_SCAN_FILES = 4000
MAX_SITES = 4
MAX_FINDINGS = 14
DEFAULT_BUDGET_S = 180.0
_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "venv", ".venv", "env", "__pycache__", "site-packages", "build", "dist",
              ".tox", ".mypy_cache", ".pytest_cache", ".eggs"}
_NOT_PACKAGES = {"tests", "test", "testing", "docs", "doc", "examples", "example", "benchmarks", "scripts", "setup", "conftest", "tools"}
_TRANSPARENT_BASES = {"object"}
_BUILTIN_BASES = {"Exception", "BaseException", "ValueError", "RuntimeError", "TypeError", "KeyError", "LookupError", "OSError",
                  "dict", "list", "tuple", "set", "frozenset", "str", "int", "float", "bytes", "type", "Enum", "IntEnum",
                  "NamedTuple", "TypedDict", "Protocol", "Generic", "ABC"}


# ============================================================================================ artifacts
class Artifact:
    """One release as source: ``tree`` maps posix relpath -> python text; ``meta`` holds the few metadata files we read."""
    __slots__ = ("tree", "meta", "kind", "filename")

    def __init__(self, tree: Dict[str, str], meta: Dict[str, str], kind: str, filename: str):
        self.tree, self.meta, self.kind, self.filename = tree, meta, kind, filename


def _clean_member(name: str) -> Optional[str]:
    n = str(name).replace("\\", "/")
    while n.startswith("./"):
        n = n[2:]
    parts = [p for p in n.split("/") if p not in ("", ".")]
    if not parts or n.startswith("/") or ".." in parts or ":" in parts[0]:
        return None
    return "/".join(parts)


def _bounded_inflate(data: bytes) -> bytes:
    """gzip -> bytes with a hard output cap; a plain (already uncompressed) tar passes through. bz2/xz sdists are refused."""
    if data[:2] != b"\x1f\x8b":
        if data[:3] == b"BZh" or data[:6] == b"\xfd7zXZ\x00":
            raise ValueError("unsupported compression")
        return data
    d = zlib.decompressobj(16 + zlib.MAX_WBITS)
    out = d.decompress(data, MAX_UNCOMPRESSED + 1)
    if len(out) > MAX_UNCOMPRESSED:
        raise ValueError("archive inflates past the %d byte cap" % MAX_UNCOMPRESSED)
    return out


def parse_archive(data: bytes, filename: str, kind: str) -> Artifact:
    """wheel/sdist bytes -> Artifact, in memory. Bounded: members, per-file bytes and total uncompressed bytes; only
    ``.py`` text plus top_level.txt / METADATA / PKG-INFO are kept. An sdist's single top directory is stripped."""
    entries: List[Tuple[str, Any]] = []              # (clean name, reader callable)
    total = [0]
    if filename.lower().endswith((".whl", ".zip")):
        zf = zipfile.ZipFile(io.BytesIO(data))
        for info in zf.infolist()[:MAX_MEMBERS]:
            if info.is_dir():
                continue
            nm = _clean_member(info.filename)
            if nm:
                entries.append((nm, (lambda i=info: zf.read(i) if i.file_size <= MAX_FILE_BYTES else b""), info.file_size))
    else:
        tf = tarfile.open(fileobj=io.BytesIO(_bounded_inflate(data)), mode="r:")
        for m in tf.getmembers()[:MAX_MEMBERS]:
            if not m.isfile():                         # links/devices are never followed
                continue
            nm = _clean_member(m.name)
            if nm:
                entries.append((nm, (lambda mm=m: (tf.extractfile(mm).read() if mm.size <= MAX_FILE_BYTES else b"")), m.size))
    if kind == "sdist" and entries:
        firsts = {e[0].split("/", 1)[0] for e in entries}
        if len(firsts) == 1 and all("/" in e[0] for e in entries):
            entries = [(e[0].split("/", 1)[1], e[1], e[2]) for e in entries]
    tree: Dict[str, str] = {}
    meta: Dict[str, str] = {}
    for nm, reader, size in entries:
        base = nm.rsplit("/", 1)[-1]
        want_py = nm.endswith(".py")
        want_meta = base in ("top_level.txt", "METADATA", "PKG-INFO") and base not in meta
        if not (want_py or want_meta) or size > MAX_FILE_BYTES:
            continue
        total[0] += size
        if total[0] > MAX_TOTAL_BYTES:
            break
        try:
            text = reader().decode("utf-8", errors="replace")
        except Exception:                              # noqa: BLE001 - one unreadable member must not sink the release
            continue
        if want_py:
            tree[nm] = text
        else:
            meta[base] = text
    return Artifact(tree, meta, kind, filename)


def pick_file(files: Sequence[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Prefer a pure python wheel, then the sdist (source only - never built), then the smallest wheel; skip yanked/oversized."""
    ok = [f for f in files if f.get("url") and not f.get("yanked") and int(f.get("size") or 0) <= MAX_ARTIFACT_BYTES]
    pure = [f for f in ok if f.get("packagetype") == "bdist_wheel" and str(f.get("filename") or "").endswith(("none-any.whl",))]
    if pure:
        return sorted(pure, key=lambda f: int(f.get("size") or 0))[0]
    sd = [f for f in ok if f.get("packagetype") == "sdist"]
    if sd:
        return sd[0]
    wh = [f for f in ok if f.get("packagetype") == "bdist_wheel"]
    return sorted(wh, key=lambda f: int(f.get("size") or 0))[0] if wh else None


class PyPIProvider:
    """meta(): the version's JSON (requires_dist, files); artifact(): the chosen file parsed in memory. Both cached per instance
    and routed through net.py (retry, breaker, test transport). Returns None on any failure - callers report ``unverified``."""

    def __init__(self) -> None:
        self._meta: Dict[Tuple[str, str], Optional[Dict[str, Any]]] = {}
        self._art: Dict[Tuple[str, str], Optional[Artifact]] = {}

    def meta(self, name: str, version: str) -> Optional[Dict[str, Any]]:
        key = (engine._canon("pypi", name), version)
        if key not in self._meta:
            import urllib.parse
            oc = net.fetch_json("https://pypi.org/pypi/%s/%s/json" % (urllib.parse.quote(name, safe=""), urllib.parse.quote(version, safe="")))
            data = oc.data if oc.state in (resilience.SUCCESS, resilience.PARTIAL_RESULT) else None
            if isinstance(data, dict) and isinstance(data.get("info"), dict):
                info = data["info"]
                self._meta[key] = {"requires_dist": [str(x) for x in (info.get("requires_dist") or [])],
                                   "requires_python": str(info.get("requires_python") or ""),
                                   "files": [u for u in (data.get("urls") or []) if isinstance(u, dict)]}
            else:
                self._meta[key] = None
        return self._meta[key]

    def artifact(self, name: str, version: str) -> Optional[Artifact]:
        key = (engine._canon("pypi", name), version)
        if key not in self._art:
            self._art[key] = None
            m = self.meta(name, version)
            f = pick_file((m or {}).get("files") or [])
            if f:
                oc = net.fetch_bytes(str(f["url"]), limit=MAX_ARTIFACT_BYTES)
                if oc.state == resilience.SUCCESS and isinstance(oc.data, (bytes, bytearray)):   # a truncated archive is useless
                    try:
                        self._art[key] = parse_archive(bytes(oc.data), str(f.get("filename") or ""), "wheel" if f.get("packagetype") == "bdist_wheel" else "sdist")
                    except (zipfile.BadZipFile, tarfile.TarError, OSError, EOFError, ValueError, zlib.error):
                        self._art[key] = None
        return self._art[key]


# ============================================================================================ API surface (old/new release)
class Member:
    __slots__ = ("kind", "sig", "deprecated", "alias_of", "bases", "methods", "ctor", "ctor_known", "opaque", "owner", "decorators", "wrapped")

    def __init__(self, kind: str, owner: str = "") -> None:
        self.kind, self.owner = kind, owner
        self.sig: Optional[Dict[str, Any]] = None
        self.deprecated = False
        self.alias_of = ""
        self.bases: List[str] = []
        self.methods: Dict[str, "Member"] = {}
        self.ctor: Optional[Dict[str, Any]] = None
        self.ctor_known = False
        self.opaque = False
        self.decorators: List[str] = []
        self.wrapped = False                        # a decorator we do not know may change the call signature at runtime


class Module:
    __slots__ = ("name", "is_pkg", "members", "star_from", "dynamic", "all")

    def __init__(self, name: str, is_pkg: bool) -> None:
        self.name, self.is_pkg = name, is_pkg
        self.members: Dict[str, Member] = {}
        self.star_from: List[str] = []
        self.dynamic = False                        # module-level __getattr__ or a non-literal __all__: absence proves nothing
        self.all: Optional[List[str]] = None


class Res:
    __slots__ = ("status", "member")

    def __init__(self, status: str, member: Optional[Member] = None) -> None:
        self.status, self.member = status, member   # found | missing | dynamic | unknown_root


EMPTY_SIG = {"params": [], "vararg": False, "varkw": False}
# decorators that leave the call signature alone; any other decorator (click.command, app.route, ...) may rewrite it
_TRANSPARENT_DECORATORS = re.compile(r"(staticmethod|classmethod|abstractmethod|lru_cache|(^|\.)cache$|wraps|contextmanager|property|setter|getter|deleter|"
                                      r"overload|final|override|deprecat)", re.I)


def _dotted(node: ast.AST) -> Optional[str]:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _dotted(node.value)
        return (base + "." + node.attr) if base else None
    return None


def _sig(fn: Any, drop_first: bool) -> Dict[str, Any]:
    a = fn.args
    pos = [(x.arg, "posonly") for x in a.posonlyargs] + [(x.arg, "pos") for x in a.args]
    ndef = len(a.defaults)
    params: List[Dict[str, Any]] = []
    for i, (nm, kd) in enumerate(pos):
        params.append({"name": nm, "kind": kd, "default": i >= len(pos) - ndef})
    for x, d in zip(a.kwonlyargs, a.kw_defaults):
        params.append({"name": x.arg, "kind": "kwonly", "default": d is not None})
    if drop_first and params and params[0]["kind"] in ("posonly", "pos"):
        params = params[1:]
    return {"params": params, "vararg": a.vararg is not None, "varkw": a.kwarg is not None}


def _is_deprecated(node: Any, body: bool = True) -> bool:
    """A deprecation decorator, or (functions only) a warnings.warn(..., DeprecationWarning) in the body. A class is judged by its
    decorators and its __init__ only - one deprecated method must not mark the whole class."""
    for d in getattr(node, "decorator_list", []):
        t = _dotted(d.func if isinstance(d, ast.Call) else d) or ""
        if "deprecat" in t.lower():
            return True
    if not body:
        return False
    for sub in ast.walk(node):
        if isinstance(sub, ast.Call):
            t = _dotted(sub.func) or ""
            if t.endswith("warn") or t.endswith("warn_explicit"):
                for arg in list(sub.args) + [k.value for k in sub.keywords]:
                    nm = _dotted(arg) or ""
                    if nm.endswith(("DeprecationWarning", "FutureWarning", "PendingDeprecationWarning")):
                        return True
    return False


def _walk_body(body: Sequence[ast.stmt]) -> Iterable[ast.stmt]:
    """Statements of a module/class body, descending into if/try/with (conditional definitions) but never into defs."""
    for st in body:
        yield st
        if isinstance(st, ast.If):
            yield from _walk_body(st.body)
            yield from _walk_body(st.orelse)
        elif isinstance(st, ast.Try):
            for part in (st.body, st.orelse, st.finalbody):
                yield from _walk_body(part)
            for h in st.handlers:
                yield from _walk_body(h.body)
        elif isinstance(st, (ast.With, ast.AsyncWith)):
            yield from _walk_body(st.body)


def _function_member(fn: Any, owner: str, in_class: bool) -> Member:
    m = Member("func", owner)
    decs = [(_dotted(d.func if isinstance(d, ast.Call) else d) or "") for d in fn.decorator_list]
    m.decorators = decs
    m.wrapped = any(not _TRANSPARENT_DECORATORS.search(d) for d in decs)
    static = any(d.endswith("staticmethod") for d in decs)
    m.sig = _sig(fn, drop_first=in_class and not static)
    m.deprecated = _is_deprecated(fn)
    if any(d.endswith("property") or d.endswith("setter") or d.endswith("cached_property") for d in decs):
        m.kind = "var"                                  # a property is attribute access, not a call
        m.sig = None
    return m


def _class_member(node: ast.ClassDef, owner: str) -> Member:
    m = Member("class", owner)
    m.bases = [b for b in (_dotted(x) for x in node.bases) if b]
    m.opaque = bool(node.keywords) or len(m.bases) != len(node.bases)
    m.deprecated = _is_deprecated(node, body=False)
    decs = [(_dotted(d.func if isinstance(d, ast.Call) else d) or "") for d in node.decorator_list]
    m.decorators = decs
    fields: List[Dict[str, Any]] = []
    for st in _walk_body(node.body):
        if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
            mm = _function_member(st, owner, True)
            m.methods.setdefault(st.name, mm)
            if st.name == "__init__":
                m.ctor, m.ctor_known = mm.sig, True
                m.deprecated = m.deprecated or mm.deprecated
            elif st.name == "__new__":
                m.opaque = True
        elif isinstance(st, ast.ClassDef):
            m.methods.setdefault(st.name, _class_member(st, owner))
        elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
            m.methods.setdefault(st.target.id, Member("var", owner))
            has_default = st.value is not None and not (isinstance(st.value, ast.Call) and (_dotted(st.value.func) or "").endswith("field")
                                                        and not any(k.arg in ("default", "default_factory") for k in st.value.keywords))
            fields.append({"name": st.target.id, "kind": "pos", "default": has_default})
        elif isinstance(st, ast.Assign):
            for t in st.targets:
                if isinstance(t, ast.Name):
                    m.methods.setdefault(t.id, Member("var", owner))
    if not m.ctor_known and any(d.endswith("dataclass") for d in decs):
        m.ctor, m.ctor_known = {"params": fields, "vararg": False, "varkw": False}, True
    elif not m.ctor_known and decs and any(not d.endswith(("dataclass", "total_ordering", "final")) for d in decs):
        m.opaque = True                                  # attrs/pydantic-style class decorators synthesise __init__
    return m


class Surface:
    def __init__(self) -> None:
        self.modules: Dict[str, Module] = {}
        self.unparsed = 0
        self.files = 0
        self.root_missing = False                     # python packages exist in this release, but not the ones the project imports

    # --------------------------------------------------------------- build
    def add_module(self, name: str, is_pkg: bool, src: str) -> None:
        self.files += 1
        try:
            tree = ast.parse(src)
        except (SyntaxError, ValueError, RecursionError):
            self.unparsed += 1
            return
        mod = Module(name, is_pkg)
        self.modules[name] = mod
        for st in _walk_body(tree.body):
            if isinstance(st, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if st.name == "__getattr__":
                    mod.dynamic = True
                mod.members.setdefault(st.name, _function_member(st, name, False))
            elif isinstance(st, ast.ClassDef):
                mod.members.setdefault(st.name, _class_member(st, name))
            elif isinstance(st, ast.Assign):
                for t in st.targets:
                    if isinstance(t, ast.Name):
                        if t.id == "__all__":
                            mod.all = _literal_names(st.value)
                            if mod.all is None:
                                mod.dynamic = True
                        else:
                            mod.members.setdefault(t.id, Member("var", name))
            elif isinstance(st, ast.AnnAssign) and isinstance(st.target, ast.Name):
                mod.members.setdefault(st.target.id, Member("var", name))
            elif isinstance(st, ast.AugAssign) and isinstance(st.target, ast.Name) and st.target.id == "__all__":
                more = _literal_names(st.value)
                if more is None or mod.all is None:
                    mod.dynamic = True
                else:
                    mod.all = mod.all + more
            elif isinstance(st, ast.ImportFrom):
                base = _abs_from(st, name, is_pkg)
                if base is None:
                    continue
                for al in st.names:
                    if al.name == "*":
                        mod.star_from.append(base)
                    else:
                        m = Member("alias", name)
                        m.alias_of = base + "." + al.name
                        mod.members.setdefault(al.asname or al.name, m)
            elif isinstance(st, ast.Import):
                for al in st.names:
                    if al.asname:
                        m = Member("alias", name)
                        m.alias_of = al.name
                        mod.members.setdefault(al.asname, m)

    # --------------------------------------------------------------- resolve
    def resolve(self, dotted: str, _depth: int = 0) -> Res:
        if _depth > 10:
            return Res("dynamic")
        parts = dotted.split(".")
        k = len(parts)
        while k > 0 and ".".join(parts[:k]) not in self.modules:
            k -= 1
        if k == 0:
            return Res("unknown_root")
        mod = self.modules[".".join(parts[:k])]
        rest = parts[k:]
        if not rest:
            m = Member("module", mod.name)
            m.alias_of = mod.name
            return Res("found", m)
        return self._in_module(mod, rest, _depth)

    def _in_module(self, mod: Module, rest: List[str], depth: int) -> Res:
        name, tail = rest[0], rest[1:]
        m = mod.members.get(name)
        if m is None:
            m = self._via_star(mod, name, depth)
        if m is None:
            child = mod.name + "." + name
            if child in self.modules:                       # a submodule that is not imported by the package
                return self.resolve(".".join([child] + tail), depth + 1)
            if mod.dynamic or any(s not in self.modules for s in mod.star_from):
                return Res("dynamic")
            return Res("missing")
        return self._descend(m, tail, depth)

    def _via_star(self, mod: Module, name: str, depth: int) -> Optional[Member]:
        if depth > 10:
            return None
        for src in mod.star_from:
            sm = self.modules.get(src)
            if sm is None:
                continue
            public = sm.all if sm.all is not None else [n for n in sm.members if not n.startswith("_")]
            if name in public:
                return sm.members.get(name) or self._via_star(sm, name, depth + 1)
        return None

    def _descend(self, m: Member, tail: List[str], depth: int) -> Res:
        if m.kind == "alias":
            r = self.resolve(m.alias_of, depth + 1)
            if r.status != "found" or r.member is None:
                return Res("dynamic")                        # the name IS present (it is an import); only its target is unknown
            m = r.member
        if m.kind == "module":
            mod = self.modules.get(m.alias_of)
            if mod is None:
                return Res("dynamic")
            return self._in_module(mod, tail, depth + 1) if tail else Res("found", m)
        if not tail:
            return Res("found", m)
        if m.kind == "class":
            return self._class_attr(m, tail, depth)
        return Res("dynamic")                                # an attribute of a function/value: not judged

    def _class_attr(self, cls: Member, tail: List[str], depth: int) -> Res:
        name, rest = tail[0], tail[1:]
        if name in cls.methods:
            sub = cls.methods[name]
            return Res("found", sub) if not rest else self._descend(sub, rest, depth + 1)
        if depth > 10:
            return Res("dynamic")
        opaque = cls.opaque
        for b in cls.bases:
            if b in _TRANSPARENT_BASES:
                continue
            owner = self.modules.get(cls.owner)
            r = self._in_module(owner, b.split("."), depth + 1) if owner else Res("dynamic")
            if r.status == "found" and r.member is not None and r.member.kind == "class":
                rr = self._class_attr(r.member, tail, depth + 1)
                if rr.status != "missing":
                    return rr
            elif b in _BUILTIN_BASES:
                continue                                      # inherited builtin methods are unresolved, not removed
            else:
                opaque = True
        return Res("dynamic") if opaque or any(b in _BUILTIN_BASES for b in cls.bases) else Res("missing")

    def ctor(self, cls: Member, depth: int = 0) -> Optional[Dict[str, Any]]:
        """Constructor signature without ``self``; None when it cannot be known (synthesised, opaque or external base)."""
        if cls.ctor_known:
            return cls.ctor
        if cls.opaque or depth > 8:
            return None
        bases = [b for b in cls.bases if b not in _TRANSPARENT_BASES]
        if not bases:
            return EMPTY_SIG
        owner = self.modules.get(cls.owner)
        r = self._in_module(owner, bases[0].split("."), depth + 1) if owner else Res("dynamic")
        if r.status == "found" and r.member is not None and r.member.kind == "class":
            return self.ctor(r.member, depth + 1)
        return None


def _literal_names(node: ast.AST) -> Optional[List[str]]:
    if isinstance(node, (ast.List, ast.Tuple)) and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in node.elts):
        return [e.value for e in node.elts]
    return None


def _abs_from(node: ast.ImportFrom, modname: str, is_pkg: bool) -> Optional[str]:
    if node.level == 0:
        return node.module
    parts = modname.split(".") if is_pkg else modname.split(".")[:-1]
    up = node.level - 1
    if up > len(parts):
        return None
    base = parts[:len(parts) - up] if up else parts
    if node.module:
        base = base + node.module.split(".")
    return ".".join(base) if base else None


def find_roots(tree: Dict[str, str]) -> Tuple[str, List[str]]:
    """(source prefix, importable top-level names). A src/ or lib/ layout is detected; test/doc folders are not roots."""
    for prefix in ("", "src/", "lib/"):
        roots: Set[str] = set()
        for p in tree:
            if not p.startswith(prefix):
                continue
            rel = p[len(prefix):]
            parts = rel.split("/")
            if len(parts) > 1 and parts[0].isidentifier() and (prefix + parts[0] + "/__init__.py") in tree:
                roots.add(parts[0])
            elif len(parts) == 1 and rel.endswith(".py") and rel[:-3].isidentifier():
                roots.add(rel[:-3])
        roots = {r for r in roots if r not in _NOT_PACKAGES and r != "__init__"}
        if roots:
            return prefix, sorted(roots)
    return "", []


def build_surface(art: Artifact, roots: Sequence[str]) -> Surface:
    prefix, found = find_roots(art.tree)
    keep = set(roots) & set(found) if roots else set(found)
    surf = Surface()
    surf.root_missing = bool(roots) and bool(found) and not keep
    for path, src in art.tree.items():
        if not path.startswith(prefix):
            continue
        rel = path[len(prefix):]
        parts = rel[:-3].split("/")
        if parts[0] not in keep:
            continue
        is_pkg = parts[-1] == "__init__"
        dotted = ".".join(parts[:-1] if is_pkg else parts)
        if dotted:
            surf.add_module(dotted, is_pkg, src)
    return surf


def import_roots(art: Artifact, dist_name: str) -> List[str]:
    """Names the project would import for this distribution: top_level.txt, else the roots found in the source."""
    names = [ln.strip().split("/")[0].split(".")[0] for ln in (art.meta.get("top_level.txt") or "").splitlines() if ln.strip()]
    _, roots = find_roots(art.tree)
    out = list(dict.fromkeys(names or roots))
    if not out:
        out = [re.sub(r"[-.]+", "_", dist_name).lower()]
    return out


# ============================================================================================ the project's own use
class ProjectIndex:
    """The project's python files parsed once per run (every plan scans the same trees)."""

    def __init__(self, root: str) -> None:
        self.root = root
        self.files: List[Tuple[str, ast.AST]] = []
        self.unparsed = 0
        self.skipped_over_cap = 0
        for dp, dns, fns in os.walk(root):
            dns[:] = sorted(d for d in dns if d not in _SKIP_DIRS and not d.endswith(".egg-info"))
            for fn in sorted(fns):
                if not fn.endswith(".py"):
                    continue
                if len(self.files) + self.unparsed >= MAX_SCAN_FILES:
                    self.skipped_over_cap += 1
                    continue
                fp = os.path.join(dp, fn)
                try:
                    if os.path.getsize(fp) > MAX_FILE_BYTES:
                        self.unparsed += 1
                        continue
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        self.files.append((os.path.relpath(fp, root).replace("\\", "/"), ast.parse(fh.read())))
                except (OSError, SyntaxError, ValueError, RecursionError):
                    self.unparsed += 1


class _Use(ast.NodeVisitor):
    def __init__(self, roots: Set[str], rel: str, sink: Dict[str, Dict[str, Any]], dyn: List[str], attr_calls: Counter) -> None:
        self.roots, self.rel, self.sink, self.dyn, self.attr_calls = roots, rel, sink, dyn, attr_calls
        self.alias: Dict[str, str] = {}

    def prime(self, tree: ast.AST) -> None:
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for al in node.names:
                    if al.name.split(".")[0] in self.roots:
                        if al.asname:
                            self.alias[al.asname] = al.name
                        else:
                            self.alias[al.name.split(".")[0]] = al.name.split(".")[0]
                        self._rec(al.name, node.lineno, "import")
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module and node.module.split(".")[0] in self.roots:
                for al in node.names:
                    if al.name == "*":
                        self.dyn.append("%s:%d from %s import *" % (self.rel, node.lineno, node.module))
                        self._rec(node.module, node.lineno, "import")
                    else:
                        self.alias[al.asname or al.name] = node.module + "." + al.name
                        self._rec(node.module + "." + al.name, node.lineno, "import")

    def _rec(self, sym: str, line: int, ctx: str, call: Optional[Dict[str, Any]] = None) -> None:
        d = self.sink.setdefault(sym, {"calls": [], "refs": 0, "base": False, "sites": []})
        d["refs"] += 1
        if ctx == "base":
            d["base"] = True
        if len(d["sites"]) < MAX_SITES:
            d["sites"].append({"file": self.rel, "line": line})
        if call is not None:
            call.update(file=self.rel, line=line)
            d["calls"].append(call)

    def _chain(self, node: ast.AST) -> Optional[str]:
        t = _dotted(node)
        if not t:
            return None
        head, _, rest = t.partition(".")
        if head not in self.alias:
            return None
        return self.alias[head] + ("." + rest if rest else "")

    def visit_Call(self, node: ast.Call) -> None:
        ch = self._chain(node.func)
        if ch:
            self._rec(ch, node.lineno, "call", {
                "npos": sum(1 for a in node.args if not isinstance(a, ast.Starred)),
                "star": any(isinstance(a, ast.Starred) for a in node.args),
                "kw": [k.arg for k in node.keywords if k.arg],
                "dstar": any(k.arg is None for k in node.keywords)})
        else:
            if isinstance(node.func, ast.Attribute):
                self.attr_calls[node.func.attr] += 1
            fname = _dotted(node.func) or ""
            if fname in ("getattr", "hasattr") and node.args and self._chain(node.args[0]) is not None and len(node.args) > 1 \
                    and not (isinstance(node.args[1], ast.Constant) and isinstance(node.args[1].value, str)):
                self.dyn.append("%s:%d dynamic getattr on the package" % (self.rel, node.lineno))
            if fname.endswith(("import_module", "__import__")) and node.args and not isinstance(node.args[0], ast.Constant):
                self.dyn.append("%s:%d dynamic import" % (self.rel, node.lineno))
            self.visit(node.func)
        for a in node.args:
            self.visit(a)
        for k in node.keywords:
            self.visit(k.value)

    def visit_Attribute(self, node: ast.Attribute) -> None:
        ch = self._chain(node)
        if ch:
            self._rec(ch, node.lineno, "ref")
        else:
            self.generic_visit(node)

    def visit_Name(self, node: ast.Name) -> None:
        if isinstance(node.ctx, ast.Load) and node.id in self.alias:
            self._rec(self.alias[node.id], node.lineno, "ref")

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        for b in node.bases:
            ch = self._chain(b)
            if ch:
                self._rec(ch, node.lineno, "base")
            else:
                self.visit(b)
        for k in node.keywords:
            self.visit(k.value)
        for st in node.body + node.decorator_list:
            self.visit(st)


def scan_usage(index: ProjectIndex, roots: Sequence[str]) -> Dict[str, Any]:
    sink: Dict[str, Dict[str, Any]] = {}
    dyn: List[str] = []
    attr_calls: Counter = Counter()
    rs = set(roots)
    for rel, tree in index.files:
        v = _Use(rs, rel, sink, dyn, attr_calls)
        v.prime(tree)
        if v.alias:
            v.visit(tree)
    return {"symbols": sink, "dynamic": dyn[:10], "attr_calls": attr_calls, "files": len(index.files), "unparsed": index.unparsed}


# ============================================================================================ the diff
def call_problems(sig: Optional[Dict[str, Any]], call: Dict[str, Any]) -> Optional[List[str]]:
    """Why ``sig`` rejects this call shape (empty list = accepts); None when the signature is unknown."""
    if sig is None:
        return None
    pos = [p for p in sig["params"] if p["kind"] in ("posonly", "pos")]
    out: List[str] = []
    if not call["star"] and not sig["vararg"] and call["npos"] > len(pos):
        out.append("%d positional argument(s) passed, %d accepted" % (call["npos"], len(pos)))
    named = {p["name"] for p in sig["params"] if p["kind"] != "posonly"}
    for k in call["kw"]:
        if k not in named and not sig["varkw"]:
            out.append("keyword '%s' is not accepted" % k)
    if not call["star"] and not call["dstar"]:
        covered = {p["name"] for p in pos[:call["npos"]]} | set(call["kw"])
        for p in sig["params"]:
            if not p["default"] and p["name"] not in covered:
                out.append("required parameter '%s' is not supplied" % p["name"])
    return out


def _sig_of(surface: Surface, m: Member) -> Tuple[bool, Optional[Dict[str, Any]]]:
    """(callable?, signature or None when unknown) for a resolved member."""
    if m.kind == "func":
        return True, m.sig
    if m.kind == "class":
        return True, surface.ctor(m)
    return False, None


def _hint(new: Surface, sym: str) -> str:
    """Where a removed symbol went: other modules defining the same name, or similarly named members of its old module."""
    parts = sym.split(".")
    leaf = parts[-1]
    moved = [mn for mn, mod in new.modules.items() if leaf in mod.members and mod.members[leaf].kind in ("func", "class")][:3]
    close: List[str] = []
    owner = new.modules.get(".".join(parts[:-1]))
    if owner is not None:
        close = difflib.get_close_matches(leaf, [n for n in owner.members if not n.startswith("_")], n=2, cutoff=0.6)
    bits = []
    if moved:
        bits.append("now defined in " + ", ".join(moved))
    if close:
        bits.append("similar name(s): " + ", ".join(close))
    return ("; " + "; ".join(bits)) if bits else ""


def _finding(sym: str, level: str, rule: str, detail: str, sites: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {"symbol": sym, "level": level, "rule": rule, "detail": detail, "sites": list(sites)[:MAX_SITES]}


def compare(usage: Dict[str, Any], old: Surface, new: Surface) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    used = usage["symbols"]
    verified = unresolved = checked_calls = modules = 0
    for sym in sorted(used):
        info = used[sym]
        ro, rn = old.resolve(sym), new.resolve(sym)
        if ro.status != "found" or ro.member is None:
            unresolved += 1                                 # nothing to compare against: not a verified symbol
            continue
        if ro.member.kind == "module":                      # `import pkg` proves the package exists, not that any API survived:
            modules += 1                                    # modules are reported apart and never inflate the coverage
            if rn.status == "missing":
                findings.append(_finding(sym, BREAKING, "CMP-REMOVED", "the module exists in the current release but not in the target%s" % _hint(new, sym), info["sites"]))
            continue
        if rn.status == "unknown_root" and new.root_missing:
            findings.append(_finding(sym, BREAKING, "CMP-ROOT-GONE",
                                     "the target release no longer ships the package the project imports (renamed or split)", info["sites"]))
            continue
        if rn.status in ("dynamic", "unknown_root"):
            unresolved += 1
            continue
        if rn.status == "missing" or rn.member is None:
            findings.append(_finding(sym, BREAKING, "CMP-REMOVED",
                                     "the symbol exists in the current release but not in the target%s" % _hint(new, sym), info["sites"]))
            continue
        verified += 1
        mo, mn = ro.member, rn.member
        if mo.kind != mn.kind and {mo.kind, mn.kind} & {"func", "class"} and "module" not in (mo.kind, mn.kind):
            findings.append(_finding(sym, REVIEW, "CMP-KIND", "changed from a %s to a %s" % (mo.kind, mn.kind), info["sites"]))
            continue
        if mn.deprecated and not mo.deprecated:
            findings.append(_finding(sym, REVIEW, "CMP-DEPRECATED", "newly deprecated in the target release", info["sites"]))
        call_o, sig_o = _sig_of(old, mo)
        call_n, sig_n = _sig_of(new, mn)
        if not (call_o and call_n):
            continue
        broken: List[Tuple[Dict[str, Any], List[str]]] = []
        unchecked = 0
        for c in info["calls"]:
            if sig_o is None or sig_n is None:
                unchecked += 1
                continue
            po, pn = call_problems(sig_o, c), call_problems(sig_n, c)
            checked_calls += 1
            if not po and pn:
                broken.append((c, pn))
        wrapped = mo.wrapped or mn.wrapped
        for c, why in broken[:MAX_SITES]:
            findings.append(_finding(sym, REVIEW if wrapped else BREAKING, "CMP-CALL-DECORATED" if wrapped else "CMP-CALL",
                                     "the call at %s:%d is rejected by the new signature%s: %s" % (
                                         c["file"], c["line"], " (decorated: the runtime signature may differ from the source)" if wrapped else "", "; ".join(why)),
                                     [{"file": c["file"], "line": c["line"]}]))
        if not broken and sig_o is not None and sig_n is not None and _shape_changed(sig_o, sig_n):
            starred = any(c["star"] or c["dstar"] for c in info["calls"])
            if not info["calls"] or starred:
                findings.append(_finding(sym, REVIEW, "CMP-SIG", "the signature changed (%s)%s" % (
                    _shape_diff(sig_o, sig_n), "; calls use */** so they could not be checked" if starred else "; referenced, not called"), info["sites"]))
        if unchecked:
            findings.append(_finding(sym, REVIEW, "CMP-SIG-UNKNOWN", "%d call site(s) could not be checked: the signature is not statically known" % unchecked, info["sites"]))
        if mo.kind == "class" and mn.kind == "class":
            gone = sorted(n for n in mo.methods if not n.startswith("_") and n not in mn.methods)
            matched = [n for n in gone if usage["attr_calls"].get(n)]
            if matched and (not any(b in _BUILTIN_BASES for b in mn.bases)):
                findings.append(_finding(sym, REVIEW, "CMP-METHOD", "method(s) %s no longer exist on the class and the project calls attribute(s) with the same name" % ", ".join(matched[:5]), info["sites"]))
            elif info["base"] and gone:
                findings.append(_finding(sym, REVIEW, "CMP-BASE", "subclassed by the project; method(s) removed upstream: %s" % ", ".join(gone[:5]), info["sites"]))
    return {"findings": findings, "used": len(used) - modules, "modules": modules, "verified": verified, "unresolved": unresolved,
            "call_sites_checked": checked_calls}


def _shape_changed(a: Dict[str, Any], b: Dict[str, Any]) -> bool:
    ka = [(p["name"], p["kind"], p["default"]) for p in a["params"]]
    kb = [(p["name"], p["kind"], p["default"]) for p in b["params"]]
    return ka != kb or a["vararg"] != b["vararg"] or a["varkw"] != b["varkw"]


def _shape_diff(a: Dict[str, Any], b: Dict[str, Any]) -> str:
    na, nb = {p["name"]: p for p in a["params"]}, {p["name"]: p for p in b["params"]}
    bits = []
    gone = [n for n in na if n not in nb]
    new_req = [n for n in nb if n not in na and not nb[n]["default"]]
    added = [n for n in nb if n not in na and nb[n]["default"]]
    lost_default = [n for n in na if n in nb and na[n]["default"] and not nb[n]["default"]]
    if gone:
        bits.append("removed: " + ", ".join(gone[:4]))
    if new_req:
        bits.append("new required: " + ", ".join(new_req[:4]))
    if lost_default:
        bits.append("default dropped: " + ", ".join(lost_default[:4]))
    if added:
        bits.append("added optional: " + ", ".join(added[:4]))
    if [n for n in na if n in nb] != [n for n in nb if n in na]:
        bits.append("reordered")
    return "; ".join(bits) or "parameter kinds changed"


# ============================================================================================ pin constraints
_REQ = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(\(?[^;]*?\)?)\s*(?:;\s*(.*))?$")
_CLAUSE = re.compile(r"(===|==|~=|!=|<=|>=|<|>)\s*([A-Za-z0-9.*+!_-]+)")


def parse_requirement(line: str) -> Optional[Tuple[str, List[Tuple[str, str]], str]]:
    m = _REQ.match(line or "")
    if not m:
        return None
    return m.group(1), _CLAUSE.findall(m.group(2) or ""), (m.group(3) or "").strip()


def _release(v: str) -> List[int]:
    return [int(x) for x in re.findall(r"\d+", re.split(r"[a-zA-Z+!-]", versions._norm(v), 1)[0])] or [0]


def clause_ok(version: str, op: str, target: str) -> bool:
    if op in ("==", "!=") and target.endswith(".*"):
        pre = _release(target[:-2])
        has = _release(version)[:len(pre)] == pre
        return has if op == "==" else not has
    c = versions.compare(version, target)
    if op in ("==", "==="):
        return c == 0
    if op == "!=":
        return c != 0
    if op == "<":
        return c < 0
    if op == "<=":
        return c <= 0
    if op == ">":
        return c > 0
    if op == ">=":
        return c >= 0
    if op == "~=":
        parts = _release(target)
        if len(parts) < 2:
            return c >= 0
        upper = parts[:-1]
        upper[-1] += 1
        return c >= 0 and versions.compare(version, ".".join(str(x) for x in upper)) < 0
    return True


def satisfies(version: str, clauses: Sequence[Tuple[str, str]]) -> bool:
    return all(clause_ok(version, op, t) for op, t in clauses)


def check_constraints(plan: Dict[str, Any], pins: Dict[str, Tuple[str, str]], provider: Any, *, max_meta: int = 80,
                      deadline: Optional[float] = None) -> Dict[str, Any]:
    """Forward (target's Requires-Dist vs the project's pins) and reverse (every other pin's Requires-Dist vs the target).
    ``pins`` maps canonical name -> (display name, version AFTER the whole patch)."""
    name, to = plan["component"], plan["safe_version"]
    me = engine._canon("pypi", name)
    findings: List[Dict[str, Any]] = []
    meta = provider.meta(name, to)
    checked = failed = 0
    if meta is None:
        return {"findings": [], "checked": 0, "of": 0, "failed": 1, "requires_python": ""}
    for line in meta["requires_dist"]:
        pr = parse_requirement(line)
        if not pr:
            continue
        dep, clauses, marker = pr
        if "extra" in marker or not clauses:
            continue
        dk = engine._canon("pypi", dep)
        pin = pins.get(dk)
        if pin and dk != me and not satisfies(pin[1], clauses):
            lvl = REVIEW if marker else BREAKING
            findings.append(_finding(dep, lvl, "CMP-DEP-FORWARD", "%s %s requires %s%s but the project pins %s==%s%s" % (
                name, to, dep, "".join(op + t for op, t in clauses), pin[0], pin[1], " (conditional marker: %s)" % marker if marker else ""), []))
    others = [(k, v) for k, v in pins.items() if k != me][:max_meta]
    for canon, (disp, ver) in others:
        if deadline is not None and time.monotonic() > deadline:      # the assessment budget also bounds this loop
            failed += 1
            continue
        om = provider.meta(disp, ver)
        if om is None:
            failed += 1
            continue
        checked += 1
        for line in om["requires_dist"]:
            pr = parse_requirement(line)
            if not pr or engine._canon("pypi", pr[0]) != me:
                continue
            _, clauses, marker = pr
            if "extra" in marker or not clauses:
                continue
            if not satisfies(to, clauses):
                lvl = REVIEW if marker else BREAKING
                findings.append(_finding(disp, lvl, "CMP-DEP-REVERSE", "%s==%s requires %s%s which %s does not satisfy%s" % (
                    disp, ver, name, "".join(op + t for op, t in clauses), to, " (conditional marker: %s)" % marker if marker else ""), []))
    return {"findings": findings, "checked": checked, "of": len(pins) - (1 if me in pins else 0), "failed": failed,
            "requires_python": meta.get("requires_python") or ""}


# ============================================================================================ orchestration
def plan_key(p: Dict[str, Any]) -> str:
    """'ecosystem|canonical-name|current-version' - a string, so held/result maps stay JSON-serialisable."""
    eco = str(p.get("ecosystem") or "")
    return "|".join((eco.lower(), engine._canon(eco, str(p.get("component") or "")), str(p.get("current_version") or "")))


def _status(findings: List[Dict[str, Any]], used: int, verified: int, unresolved: int, dyn: int, modules: int = 0) -> str:
    if any(f["level"] == BREAKING for f in findings):
        return BREAKING
    if any(f["level"] == REVIEW for f in findings):
        return REVIEW
    if used == 0:
        return COMPATIBLE if modules else NOT_DIRECT       # only module imports, all still present / nothing imported at all
    if verified == 0:
        return UNVERIFIED
    return PARTIAL if (unresolved or dyn) else COMPATIBLE


def assess_plan(plan: Dict[str, Any], index: ProjectIndex, pins: Dict[str, Tuple[str, str]], provider: Any,
                deadline: Optional[float] = None) -> Dict[str, Any]:
    name, cur, to = plan["component"], plan["current_version"], plan["safe_version"]
    out: Dict[str, Any] = {"component": name, "from": cur, "to": to, "basis": "static-api-diff"}
    cons = check_constraints(plan, pins, provider, deadline=deadline)
    findings = list(cons["findings"])
    out["constraints"] = {k: cons[k] for k in ("checked", "of", "failed", "requires_python")}
    over = deadline is not None and time.monotonic() > deadline
    old, new = (None, None) if over else (provider.artifact(name, cur), provider.artifact(name, to))
    if old is None or new is None:
        miss = " and ".join(n for n, a in (("current", old), ("target", new)) if a is None)
        broke = [f for f in findings if f["level"] == BREAKING]
        out.update(status=BREAKING if broke else UNVERIFIED,
                   reason=("%d breaking pin-constraint finding(s): %s" % (len(broke), "; ".join(f["detail"] for f in broke)[:240])) if broke else
                   ("assessment budget exhausted before the release archives were fetched" if over else
                    "no readable source archive for the %s release (yanked, binary-only, too large or unreachable)" % miss),
                   findings=findings[:MAX_FINDINGS], counts={"used": 0, "verified": 0, "unresolved": 0, "call_sites_checked": 0})
        _fill_counts(out, findings)
        return out
    roots = import_roots(old, name)
    usage = scan_usage(index, roots)
    so, sn = build_surface(old, roots), build_surface(new, roots)
    cmpd = compare(usage, so, sn)
    findings = cmpd["findings"] + findings
    status = _status(findings, cmpd["used"], cmpd["verified"], cmpd["unresolved"], len(usage["dynamic"]), cmpd["modules"])
    out.update(status=status, findings=findings[:MAX_FINDINGS], import_names=roots,
               old={"kind": old.kind, "modules": len(so.modules), "unparsed": so.unparsed},
               new={"kind": new.kind, "modules": len(sn.modules), "unparsed": sn.unparsed},
               coverage=round(cmpd["verified"] / cmpd["used"], 3) if cmpd["used"] else None,
               dynamic_uses=usage["dynamic"][:5])
    out["counts"] = {"used": cmpd["used"], "modules": cmpd["modules"], "verified": cmpd["verified"], "unresolved": cmpd["unresolved"],
                     "call_sites_checked": cmpd["call_sites_checked"]}
    _fill_counts(out, findings)
    out["reason"] = _reason(out, usage, so)
    return out


def _fill_counts(out: Dict[str, Any], findings: List[Dict[str, Any]]) -> None:
    c = out.setdefault("counts", {})
    c["breaking"] = sum(1 for f in findings if f["level"] == BREAKING)
    c["review"] = sum(1 for f in findings if f["level"] == REVIEW)


def _reason(out: Dict[str, Any], usage: Dict[str, Any], so: Surface) -> str:
    st, c = out["status"], out["counts"]
    if st == BREAKING:
        return "%d breaking finding(s): %s" % (c["breaking"], "; ".join(f["detail"] for f in out["findings"] if f["level"] == BREAKING)[:240])
    if st == REVIEW:
        return "%d finding(s) need a human look" % c["review"]
    if st == NOT_DIRECT:
        return "the project's own code never imports %s (transitive or unused): only the pin constraints were checked" % "/".join(out.get("import_names") or [])
    if st == UNVERIFIED:
        return "none of the %d used symbol(s) could be resolved in the current release (%d module(s) unparsed, C extension or dynamic package)" % (c["used"], so.unparsed)
    if st == PARTIAL:
        return "%d of %d used symbol(s) verified; the rest are dynamic/C-extension/unknown-type and were not judged" % (c["verified"], c["used"])
    if not c["used"]:
        return "the project only imports the package module(s) (%d): they exist in both releases; no API symbol is used" % c.get("modules", 0)
    return "all %d used symbol(s) exist in both releases with compatible call shapes (%d call site(s) checked)" % (c["used"], c["call_sites_checked"])


def assess(root: str, plans: Sequence[Dict[str, Any]], components: Sequence[Dict[str, Any]], *, mode: str = "block", offline: bool = False,
           provider: Any = None, max_plans: int = 25, budget_s: float = DEFAULT_BUDGET_S, cache: Optional[Dict[tuple, Dict[str, Any]]] = None,
           c_provider: Any = None, compile_check: bool = True) -> Dict[str, Any]:
    """Assess every upgrade plan; returns {"mode", "plans": [...], "held": {key: reason}, "summary": {...}}. Never raises for a
    single plan: a failure is recorded on that plan as ``unverified`` with the error. ``cache`` carries results across rounds.
    PyPI plans use the Python source diff; C/C++ library plans (``compat_c.C_ECOSYSTEMS`` or ``language`` c/c++) use ``c_provider`` - an object
    with ``headers(name, version) -> {relpath: text} | None`` - for the public headers of both releases (+ the compiler differential)."""
    out: Dict[str, Any] = {"schema": SCHEMA, "mode": mode, "plans": [], "held": {}, "honesty": HONESTY}
    ups = [p for p in plans if p.get("status") == "upgrade" and p.get("safe_version")]
    if mode == "off" or not ups:
        out["summary"] = _summary(out["plans"], out["held"], mode)
        return out
    deadline = time.monotonic() + budget_s
    network = provider is None                      # ``offline`` only forbids the default (network) provider; an injected one is the caller's business
    provider = provider or PyPIProvider()
    index: Optional[ProjectIndex] = None
    after = {engine._canon("pypi", p["component"]): p["safe_version"] for p in ups if str(p.get("ecosystem") or "").lower() == "pypi"}
    pins = {}
    for c in components or []:
        if str(c.get("ecosystem") or "").lower() == "pypi" and c.get("version"):
            k = engine._canon("pypi", c["name"])
            pins[k] = (c["name"], after.get(k, c["version"]))
    done = 0
    for p in ups:
        key = plan_key(p)
        rk = (key, p["safe_version"])
        if cache is not None and rk in cache:
            res = cache[rk]
        else:
            res = {"component": p["component"], "from": p["current_version"], "to": p["safe_version"], "basis": "none"}
            eco = str(p.get("ecosystem") or "").lower()
            c_like = eco in compat_c.C_ECOSYSTEMS or str(p.get("language") or "").lower() in ("c", "c++", "cpp")
            if eco != "pypi" and c_like and c_provider is not None:
                if done >= max_plans or time.monotonic() > deadline:
                    res.update(status=UNVERIFIED, reason="assessment budget exhausted (%d plan(s) / %ds): not assessed" % (max_plans, int(budget_s)))
                else:
                    done += 1
                    try:
                        res = compat_c.assess_plan_c(p, root, c_provider, compile_check=compile_check)
                    except Exception as exc:              # noqa: BLE001 - recorded on the plan, never fatal
                        res.update(status=UNVERIFIED, reason="assessment error: %s: %s" % (type(exc).__name__, str(exc)[:160]))
            elif eco != "pypi" and c_like:
                res.update(status=UNVERIFIED, reason="C/C++ library %s: no header source was provided (pass a c_provider: a git tag, a vendored directory or an unpacked "
                                                      "tarball per release); the major-bump prior (%s) is all there is" % (p["component"], p.get("breaking_risk") or "?"))
            elif eco != "pypi":
                res.update(status=UNVERIFIED, reason="ecosystem %s is not covered by the static API diff yet; the major-bump prior (%s) is all there is" % (
                    p.get("ecosystem"), p.get("breaking_risk") or "?"))
            elif offline and network:
                res.update(status=UNVERIFIED, reason="offline: release archives and metadata were not fetched")
            elif done >= max_plans or time.monotonic() > deadline:
                res.update(status=UNVERIFIED, reason="assessment budget exhausted (%d plan(s) / %ds): not assessed" % (max_plans, int(budget_s)))
            else:
                done += 1
                try:
                    index = index or ProjectIndex(root)
                    res = assess_plan(p, index, pins, provider, deadline=deadline)
                except Exception as exc:                  # noqa: BLE001 - recorded on the plan, never swallowed, never fatal
                    res.update(status=UNVERIFIED, reason="assessment error: %s: %s" % (type(exc).__name__, str(exc)[:160]))
            res.setdefault("findings", [])
            res["key"] = key
            if cache is not None:
                cache[rk] = res
        out["plans"].append(res)
        if res["status"] == BREAKING and mode == "block":
            out["held"][key] = res.get("reason") or "breaking compatibility finding"
    out["summary"] = _summary(out["plans"], out["held"], mode)
    return out


def _summary(results: List[Dict[str, Any]], held: Dict[str, str], mode: str) -> Dict[str, Any]:
    cnt = Counter(r["status"] for r in results)
    return {"mode": mode, "assessed": len(results), "held": len(held), **{s: cnt.get(s, 0) for s in (COMPATIBLE, PARTIAL, REVIEW, BREAKING, UNVERIFIED, NOT_DIRECT)}}


def attach(plans: Sequence[Dict[str, Any]], result: Dict[str, Any]) -> None:
    """Copy each assessment onto its plan (``plan['compat']``) so the plan table and the record carry the measured risk."""
    by = {r.get("key"): r for r in result.get("plans") or []}
    for p in plans:
        r = by.get(plan_key(p))
        if r is not None:
            p["compat"] = {k: r.get(k) for k in ("status", "reason", "coverage", "counts", "findings", "constraints", "basis") if k in r}


__all__ = ["assess", "attach", "assess_plan", "compare", "build_surface", "scan_usage", "ProjectIndex", "PyPIProvider", "parse_archive",
           "check_constraints", "call_problems", "plan_key", "MODES", "SCHEMA", "HONESTY"]
