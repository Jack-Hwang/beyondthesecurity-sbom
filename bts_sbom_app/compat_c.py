"""Patch compatibility gate for C and C++ libraries (the backend ``compat.assess`` uses for non-Python upgrades).

Python gets its compatibility facts from ``ast``; for C/C++ they come from the library's PUBLIC HEADERS and from the real compiler:

  1. USED API       what the project's own C/C++ files use of the library: calls (with their argument count), macros, constants,
                    types, variables and struct fields (``cparse.scan_usage``).
  2. HEADER DIFF    the declarations of the current and the target release (``cparse``) compared on exactly those symbols:
                    removed function / macro / type / variable, a call whose argument count the new prototype rejects, a struct that
                    lost a field the project reads, an enumerator that vanished or changed value, a changed layout (ABI) - each with the
                    call site that proves it.
  3. COMPILER DIFF  every project source that includes the library is syntax-checked (``-fsyntax-only``) against the OLD headers and
                    against the NEW headers; an error that appears only with the new headers is a measured break, named with the
                    compiler's own message. Errors present in both (missing third-party headers, unrelated code) cancel out.

Same verdicts and honesty rules as ``compat`` (breaking / review / partial / unverified, never "compatible" on thin evidence). Header
trees come from an injectable provider (git tag, vendored directory, release tarball); nothing is built, linked or run.
Limits: no ABI/SONAME analysis of binaries, no overload resolution beyond argument counts, field accesses are matched by name (no type
inference), preprocessor conditionals are not evaluated (every branch of a header is read).
"""
from __future__ import annotations

import difflib
import os
import re
import shutil
import subprocess
import tempfile
from collections import Counter
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

from . import cparse

MAX_HEADERS = 600
MAX_PROJECT_FILES = 3000
MAX_COMPILE_FILES = 80
COMPILE_TIMEOUT = 40
MAX_FINDINGS = 14
BREAKING, REVIEW = "breaking", "review"
HONESTY = [
    "headers are read, not preprocessed: every #if branch counts, so a declaration that exists only under a configuration is treated as present",
    "struct fields are matched by NAME (no type inference): a same-named field of an unrelated struct is evidence, not proof",
    "no binary/ABI analysis (SONAME, symbol versions): a layout change is reported as review, never as proven ABI break",
    "the compiler differential needs gcc/clang and only sees sources whose other includes resolve the same way for old and new headers",
]
C_ECOSYSTEMS = {"conan", "conancenter", "vcpkg", "cmake", "c", "c++", "cpp", "oss-fuzz", "git", "generic", "yocto", "bitbake", "debian", "alpine", "meson"}


# ============================================================================================ header trees
def load_header_tree(root: str, cap: int = MAX_HEADERS) -> Dict[str, str]:
    """{relpath: text} of the public headers under ``root`` (test/doc/example/internal folders skipped, size-capped)."""
    tree: Dict[str, str] = {}
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d.lower() not in ("test", "tests", "testing", "doc", "docs", "example", "examples", "bench", "benchmarks",
                                                              ".git", "build", "cmake", "scripts", "contrib", "fuzz", "third_party", "3rdparty")
                        and not d.startswith("."))
        for fn in sorted(fns):
            if fn.lower().endswith(cparse.HEADER_EXT) and len(tree) < cap:
                fp = os.path.join(dp, fn)
                try:
                    if os.path.getsize(fp) > 1_500_000:
                        continue
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        tree[os.path.relpath(fp, root).replace("\\", "/")] = fh.read()
                except OSError:
                    continue
    return tree


class DirProvider:
    """Header trees from local directories: ``{(name, version): directory}`` (a vendored copy, an unpacked tarball, a git checkout)."""

    def __init__(self, dirs: Dict[Tuple[str, str], str]) -> None:
        self.dirs = {(k[0].lower(), k[1]): v for k, v in dirs.items()}

    def headers(self, name: str, version: str) -> Optional[Dict[str, str]]:
        d = self.dirs.get((name.lower(), version))
        return load_header_tree(d) if d and os.path.isdir(d) else None


class GitProvider:
    """Header trees from git tags: ``resolver(name, version) -> (repo_url, [tag candidates])``. Uses the git CLI with a shallow single-branch
    clone into a temp dir (hooks and submodules disabled); returns None on any failure."""

    def __init__(self, resolver: Any, timeout: float = 120.0) -> None:
        self.resolver, self.timeout = resolver, timeout
        self._cache: Dict[Tuple[str, str], Optional[Dict[str, str]]] = {}

    def headers(self, name: str, version: str) -> Optional[Dict[str, str]]:
        key = (name.lower(), version)
        if key in self._cache:
            return self._cache[key]
        out: Optional[Dict[str, str]] = None
        try:
            url, tags = self.resolver(name, version)
        except Exception:                                           # noqa: BLE001 - an unresolvable package is simply unverified
            url, tags = "", []
        for tag in tags:
            tmp = tempfile.mkdtemp(prefix="bts-chdr-")
            try:
                p = subprocess.run(["git", "-c", "core.hooksPath=/dev/null", "clone", "-q", "--depth", "1", "--no-recurse-submodules", "--branch", tag, url, tmp],
                                   capture_output=True, text=True, timeout=self.timeout)
                if p.returncode == 0:
                    out = load_header_tree(tmp)
                    break
            except (OSError, subprocess.TimeoutExpired):
                pass
            finally:
                shutil.rmtree(tmp, ignore_errors=True)
        self._cache[key] = out
        return out


def api_model(tree: Dict[str, str]) -> Dict[str, Any]:
    models = []
    for rel, text in sorted(tree.items()):
        try:
            models.append(cparse.parse(text, rel))
        except Exception:                                           # noqa: BLE001 - one unparsable header must not sink the release
            continue
    return cparse.merge(models) if models else {"functions": [], "types": [], "macros": [], "variables": [], "includes": [], "skipped": 0, "language": "c"}


# ============================================================================================ the project's own use
def project_sources(root: str, cap: int = MAX_PROJECT_FILES) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if d not in (".git", "node_modules", "build", "dist", "venv", ".venv", "__pycache__") and not d.startswith("."))
        for fn in sorted(fns):
            if fn.lower().endswith(cparse.ALL_EXT) and len(out) < cap:
                fp = os.path.join(dp, fn)
                try:
                    if os.path.getsize(fp) > 1_500_000:
                        continue
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        out.append((os.path.relpath(fp, root).replace("\\", "/"), fh.read()))
                except OSError:
                    continue
    return out


def usage_of(sources: Sequence[Tuple[str, str]], api: Dict[str, Any]) -> Dict[str, Any]:
    interest = cparse.interest_set(api)
    shadow: Set[str] = set()
    for rel, text in sources:
        if rel.lower().endswith(cparse.SOURCE_EXT):               # what the project DEFINES itself shadows a library name
            try:
                shadow |= cparse.local_definitions(text, rel)
            except Exception:                                       # noqa: BLE001
                continue
    lib_names = {f["name"] for f in api["functions"]} | {m["name"] for m in api["macros"]}
    shadow -= set()                                                 # a project that re-declares a library name in a HEADER keeps it as usage
    sink: Dict[str, Any] = {"symbols": {}, "fields": {}, "includes": []}
    for rel, text in sources:
        cparse.scan_usage(text, rel, interest, shadow if rel.lower().endswith(cparse.SOURCE_EXT) else set(), sink)
    sink["shadowed"] = sorted(shadow & lib_names)[:10]
    return sink


# ============================================================================================ the declaration diff
def _fn_index(api: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    idx: Dict[str, List[Dict[str, Any]]] = {}
    for f in api["functions"]:
        if f["kind"] in ("function", "method"):
            idx.setdefault(f["name"], []).append(f)
    return idx


def _accepts(fn: Dict[str, Any], argc: int) -> bool:
    req = sum(1 for p in fn["params"] if not p.get("default"))
    return argc >= req and (fn["variadic"] or argc <= len(fn["params"]))


def _finding(sym: str, level: str, rule: str, detail: str, sites: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    return {"symbol": sym, "level": level, "rule": rule, "detail": detail, "sites": list(sites)[:4]}


def _hint(name: str, new: Dict[str, Any]) -> str:
    pool = [f["name"] for f in new["functions"]] + [m["name"] for m in new["macros"] if not m["guard"]] + [t["name"] for t in new["types"] if t["name"]]
    close = difflib.get_close_matches(name, pool, n=2, cutoff=0.6)
    return ("; similar name(s) in the target: " + ", ".join(close)) if close else ""


def _type_changes(o: Dict[str, Any], n: Dict[str, Any]) -> Tuple[List[str], List[str], bool]:
    """(removed field names, retyped field names, layout changed) between two struct/union/class entries."""
    of = {f["name"]: f for f in o.get("fields") or []}
    nf = {f["name"]: f for f in n.get("fields") or []}
    removed = [k for k in of if k not in nf]
    retyped = [k for k in of if k in nf and (of[k].get("norm") != nf[k].get("norm") or of[k].get("array") != nf[k].get("array") or of[k].get("bits") != nf[k].get("bits"))]
    order_old = [k for k in of if k in nf]
    order_new = [k for k in nf if k in of]
    layout = bool(removed or retyped or order_old != order_new or [k for k in nf if k not in of and list(nf).index(k) < len(nf) - 1 and False])
    appended_only = not removed and not retyped and order_old == order_new
    return removed, retyped, layout and not appended_only


def compare(usage: Dict[str, Any], old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []
    used = usage["symbols"]
    ofn, nfn = _fn_index(old), _fn_index(new)
    omac = {m["name"]: m for m in old["macros"] if not m["guard"]}
    nmac = {m["name"]: m for m in new["macros"] if not m["guard"]}
    oenum = {e["name"]: (e, t) for t in old["types"] for e in (t.get("enumerators") or [])}
    nenum = {e["name"]: (e, t) for t in new["types"] for e in (t.get("enumerators") or [])}
    def _by_name(types: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        for t in sorted(types, key=lambda x: 0 if x["kind"] == "typedef" else 1):       # `typedef struct foo {...} foo;` - the struct (with fields) wins
            if t["name"]:
                out[t["name"]] = t
        return out
    otype, ntype = _by_name(old["types"]), _by_name(new["types"])
    ovar = {v["name"]: v for v in old["variables"]}
    nvar = {v["name"]: v for v in new["variables"]}
    verified = unresolved = calls_checked = 0
    for sym in sorted(used):
        info = used[sym]
        sites = info["sites"]
        if sym in ofn:
            nf = nfn.get(sym)
            nm = nmac.get(sym)
            if not nf and not (nm and nm["params"] is not None):
                if sym in nvar or sym in nenum:
                    verified += 1
                    continue
                findings.append(_finding(sym, BREAKING, "CMP-C-REMOVED", "function `%s` is declared in the current release but not in the target%s" % (sym, _hint(sym, new)), sites))
                continue
            verified += 1
            if nf:
                for c in info["calls"]:
                    calls_checked += 1
                    if any(_accepts(f, c["npos"]) for f in ofn[sym]) and not any(_accepts(f, c["npos"]) for f in nf):
                        findings.append(_finding(sym, BREAKING, "CMP-C-CALL", "the call at %s:%d passes %d argument(s) but the target prototype takes %s" % (
                            c["file"], c["line"], c["npos"], " or ".join(sorted({str(len(f["params"])) + ("+" if f["variadic"] else "") for f in nf}))),
                            [{"file": c["file"], "line": c["line"]}]))
                a, b = ofn[sym][0], nf[0]
                if len(a["params"]) == len(b["params"]) and [p["norm"] for p in a["params"]] != [p["norm"] for p in b["params"]]:
                    diff = [(x["norm"], y["norm"]) for x, y in zip(a["params"], b["params"]) if x["norm"] != y["norm"]]
                    findings.append(_finding(sym, REVIEW, "CMP-C-TYPE", "parameter type(s) changed: %s" % "; ".join("%s -> %s" % d for d in diff[:3]), sites))
                if a["ret_norm"] != b["ret_norm"]:
                    findings.append(_finding(sym, REVIEW, "CMP-C-RET", "return type changed: %s -> %s" % (a["ret_norm"], b["ret_norm"]), sites))
                if b.get("deprecated") and not a.get("deprecated"):
                    findings.append(_finding(sym, REVIEW, "CMP-C-DEPRECATED", "newly marked deprecated in the target", sites))
            continue
        if sym in omac:
            o = omac[sym]
            n = nmac.get(sym)
            if n is None:
                if sym in nfn or sym in nenum or sym in nvar:
                    verified += 1
                    continue
                findings.append(_finding(sym, BREAKING, "CMP-C-REMOVED", "macro `%s` is defined in the current release but not in the target%s" % (sym, _hint(sym, new)), sites))
                continue
            verified += 1
            if o["params"] is not None and n["params"] is not None:
                for c in info["calls"]:
                    calls_checked += 1
                    oa = c["npos"] == len(o["params"]) or o.get("variadic")
                    na = c["npos"] == len(n["params"]) or n.get("variadic")
                    if oa and not na:
                        findings.append(_finding(sym, BREAKING, "CMP-C-CALL", "macro call at %s:%d passes %d argument(s) but the target macro takes %d" % (
                            c["file"], c["line"], c["npos"], len(n["params"])), [{"file": c["file"], "line": c["line"]}]))
            elif o["value"] is not None and n["value"] is not None and o["value"] != n["value"]:
                findings.append(_finding(sym, REVIEW, "CMP-C-VALUE", "constant changed value: %s -> %s" % (o["value"], n["value"]), sites))
            continue
        if sym in oenum:
            eo, to = oenum[sym]
            if sym not in nenum:
                if sym in nmac or sym in nvar:
                    verified += 1
                    continue
                findings.append(_finding(sym, BREAKING, "CMP-C-REMOVED", "enumerator `%s` (enum %s) no longer exists in the target%s" % (sym, to.get("name") or "{...}", _hint(sym, new)), sites))
                continue
            verified += 1
            if eo.get("value") is not None and nenum[sym][0].get("value") is not None and eo["value"] != nenum[sym][0]["value"]:
                findings.append(_finding(sym, REVIEW, "CMP-C-VALUE", "enumerator value changed: %s -> %s (stored or exchanged values change meaning)" % (
                    eo["value"], nenum[sym][0]["value"]), sites))
            continue
        if sym in otype:
            o = otype[sym]
            n = ntype.get(sym)
            if n is None:
                findings.append(_finding(sym, BREAKING, "CMP-C-REMOVED", "type `%s` is declared in the current release but not in the target%s" % (sym, _hint(sym, new)), sites))
                continue
            verified += 1
            if o["kind"] in ("struct", "union", "class") and n["kind"] in ("struct", "union", "class"):
                removed, retyped, layout = _type_changes(o, n)
                touched = [f for f in removed if f in usage["fields"]]
                if o.get("fields") and not n.get("fields"):
                    findings.append(_finding(sym, BREAKING if usage["fields"] and any(f["name"] in usage["fields"] for f in o["fields"]) else REVIEW, "CMP-C-OPAQUE",
                                             "`%s` is opaque in the target (fields no longer public)" % sym, sites))
                for f in touched:
                    fs = usage["fields"][f]
                    findings.append(_finding(sym, BREAKING, "CMP-C-FIELD", "field `%s` of `%s` was removed; the project accesses a member of that name (%d site(s), name match)" % (f, sym, fs["count"]), fs["sites"]))
                if retyped:
                    findings.append(_finding(sym, REVIEW, "CMP-C-FIELD-TYPE", "field type changed in `%s`: %s" % (sym, ", ".join(retyped[:4])), sites))
                if layout and not touched:
                    findings.append(_finding(sym, REVIEW, "CMP-C-LAYOUT", "layout of `%s` changed (fields removed/reordered/retyped): every user must be recompiled; a shared library breaks its ABI" % sym, sites))
            elif o["kind"] == "typedef" and n["kind"] == "typedef" and o.get("norm") != n.get("norm"):
                findings.append(_finding(sym, REVIEW, "CMP-C-TYPEDEF", "typedef `%s` now refers to `%s` (was `%s`)" % (sym, n.get("target"), o.get("target")), sites))
            continue
        if sym in ovar:
            if sym not in nvar and sym not in nfn:
                findings.append(_finding(sym, BREAKING, "CMP-C-REMOVED", "variable `%s` is declared in the current release but not in the target%s" % (sym, _hint(sym, new)), sites))
                continue
            verified += 1
            continue
        unresolved += 1
    return {"findings": findings, "used": len(used), "verified": verified, "unresolved": unresolved, "call_sites_checked": calls_checked}


# ============================================================================================ the compiler differential
def _materialize(tree: Dict[str, str]) -> str:
    d = tempfile.mkdtemp(prefix="bts-chdr-")
    for rel, text in tree.items():
        fp = os.path.join(d, rel)
        os.makedirs(os.path.dirname(fp), exist_ok=True)
        with open(fp, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
    return d


_ERR = re.compile(r"^(.+?):(\d+):(?:\d+:)? (?:fatal )?error: (.*)$", re.M)


def _errors(cc: str, src: str, cwd: str, includes: List[str], lang: str) -> Optional[Set[Tuple[str, int, str]]]:
    cmd = [cc, "-fsyntax-only", "-w", "-std=gnu++17" if lang == "c++" else "-std=gnu11", "-fmax-errors=40", src]
    for d in includes:
        cmd += ["-I", d]
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=COMPILE_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        return None
    out: Set[Tuple[str, int, str]] = set()
    for m in _ERR.finditer(p.stderr or ""):
        msg = re.sub(r"\s+", " ", m.group(3)).strip()[:200]
        # Linux gcc prints Unicode quotes unconditionally since gcc 8 (locale does not change it):
        # normalize to ASCII so diagnostics match across platforms
        msg = msg.replace(chr(0x2018), "'").replace(chr(0x2019), "'")
        out.add((os.path.basename(m.group(1)), int(m.group(2)), msg))
    return out


def compile_diff(root: str, sources: Sequence[Tuple[str, str]], old_tree: Dict[str, str], new_tree: Dict[str, str], tc: Dict[str, Optional[str]],
                 extra_includes: Optional[List[str]] = None) -> Dict[str, Any]:
    """Syntax-check each project file that includes a library header against the old and against the new headers; report errors that are NEW."""
    if not (tc.get("cc") or tc.get("cxx")):
        return {"available": False, "reason": "no C/C++ compiler on PATH"}
    names = {os.path.basename(r) for r in old_tree} | set(old_tree)
    spells = set(old_tree) | {os.path.basename(r) for r in old_tree}
    cands: List[Tuple[str, str]] = []
    for rel, text in sources:
        if not rel.lower().endswith(cparse.SOURCE_EXT):
            continue
        for m in re.finditer(r'^[ \t]*#[ \t]*include[ \t]*[<"]([^>"]+)[>"]', text, re.M):
            inc = m.group(1)
            if inc in spells or any(inc.endswith("/" + r) or r.endswith("/" + inc) for r in old_tree):
                cands.append((rel, text))
                break
    cands = cands[:MAX_COMPILE_FILES]
    if not cands:
        return {"available": True, "checked": 0, "reason": "no project source includes a header of the library"}
    od, nd = _materialize(old_tree), _materialize(new_tree)

    def roots(d: str) -> List[str]:                                 # the tree root and its first-level folders (include/, inc/, src/ ...)
        return [d] + [os.path.join(d, x) for x in sorted(os.listdir(d)) if os.path.isdir(os.path.join(d, x))]
    proj_dirs = sorted({os.path.join(root, os.path.dirname(r)) for r, _ in sources if r.lower().endswith(cparse.HEADER_EXT)})[:30] + [root]
    regs: List[Dict[str, Any]] = []
    checked = base_errs = failed = 0
    try:
        for rel, _text in cands:
            lang = "c++" if rel.lower().endswith(cparse.CPP_EXT) else "c"
            cc = tc["cxx"] if lang == "c++" else tc["cc"]
            if not cc:
                continue
            src = os.path.join(root, rel)
            base_inc = list(extra_includes or []) + proj_dirs
            e_old = _errors(cc, src, root, base_inc + roots(od), lang)
            e_new = _errors(cc, src, root, base_inc + roots(nd), lang)
            if e_old is None or e_new is None:
                failed += 1
                continue
            checked += 1
            base_errs += len(e_old)
            fresh = sorted(e for e in e_new - e_old)
            old_msgs = {m for _f, _l, m in e_old}
            for f, line, msg in fresh:
                regs.append({"file": rel, "line": line, "message": msg, "in_header": f != os.path.basename(rel)})
    finally:
        shutil.rmtree(od, ignore_errors=True)
        shutil.rmtree(nd, ignore_errors=True)
    return {"available": True, "checked": checked, "failed": failed, "baseline_errors": base_errs, "new_errors": len(regs), "regressions": regs[:20]}


# ============================================================================================ one plan
def assess_plan_c(plan: Dict[str, Any], root: str, provider: Any, *, tc: Optional[Dict[str, Optional[str]]] = None, compile_check: bool = True) -> Dict[str, Any]:
    name, cur, to = plan["component"], plan["current_version"], plan["safe_version"]
    out: Dict[str, Any] = {"component": name, "from": cur, "to": to, "basis": "c-header-diff"}
    old_t, new_t = provider.headers(name, cur), provider.headers(name, to)
    if not old_t or not new_t:
        miss = " and ".join(n for n, t in (("current", old_t), ("target", new_t)) if not t)
        out.update(status="unverified", reason="no public headers could be obtained for the %s release (provider returned nothing)" % miss, findings=[],
                   counts={"used": 0, "verified": 0, "unresolved": 0, "breaking": 0, "review": 0, "call_sites_checked": 0})
        return out
    old, new = api_model(old_t), api_model(new_t)
    sources = project_sources(root)
    usage = usage_of(sources, old)
    cmp = compare(usage, old, new)
    findings = list(cmp["findings"])
    tcx = tc if tc is not None else _toolchain()
    cd: Dict[str, Any] = {"available": False, "reason": "compiler differential disabled"}
    if compile_check:
        cd = compile_diff(root, sources, old_t, new_t, tcx)
        for r in cd.get("regressions", [])[:8]:
            findings.append(_finding("compile", BREAKING, "CMP-C-COMPILE", "%s:%d fails to compile against the target headers: %s" % (r["file"], r["line"], r["message"]),
                                     [{"file": r["file"], "line": r["line"]}]))
    nb = sum(1 for f in findings if f["level"] == BREAKING)
    nr = sum(1 for f in findings if f["level"] == REVIEW)
    used, verified = cmp["used"], cmp["verified"]
    compiled = bool(cd.get("available") and cd.get("checked"))
    if nb:
        status = "breaking"
    elif nr:
        status = "review"
    elif used == 0 and not compiled:
        status = "not_direct"
    elif used and verified == 0 and not compiled:
        status = "unverified"
    elif cmp["unresolved"] and not compiled:
        status = "partial"
    else:
        status = "compatible" if (verified or compiled) else "partial"
    if status == "compatible" and cmp["unresolved"] and not compiled:
        status = "partial"
    reason = {"breaking": "%d breaking finding(s): %s" % (nb, "; ".join(f["detail"] for f in findings if f["level"] == BREAKING)[:240]),
              "review": "%d finding(s) need a human look" % nr,
              "not_direct": "the project's C/C++ sources use no symbol of this library's headers (transitive, or used only through another library)",
              "unverified": "none of the %d used symbol(s) could be matched against the current release's headers" % used,
              "partial": "%d of %d used symbol(s) verified against both header sets; the rest were not found in the headers" % (verified, used),
              "compatible": "%d used symbol(s) exist in both releases%s" % (verified, ("; %d source file(s) compile cleanly against the target headers (compiler differential)" % cd["checked"]) if compiled else "")}[status]
    out.update(status=status, reason=reason, findings=findings[:MAX_FINDINGS], coverage=round(verified / used, 3) if used else None,
               counts={"used": used, "verified": verified, "unresolved": cmp["unresolved"], "call_sites_checked": cmp["call_sites_checked"], "breaking": nb, "review": nr},
               compile=dict({k: cd.get(k) for k in ("available", "checked", "baseline_errors", "new_errors", "reason") if k in cd},
                            regressions=(cd.get("regressions") or [])[:10]),
               headers={"old": len(old_t), "new": len(new_t), "skipped_decls": [old.get("skipped", 0), new.get("skipped", 0)]},
               language=("c++" if old.get("language") == "c++" or new.get("language") == "c++" else "c"), honesty=HONESTY)
    return out


def _toolchain() -> Dict[str, Optional[str]]:
    return {"cc": os.environ.get("BTS_SBOM_CC") or shutil.which("gcc") or shutil.which("clang") or shutil.which("cc"),
            "cxx": os.environ.get("BTS_SBOM_CXX") or shutil.which("g++") or shutil.which("clang++") or shutil.which("c++")}


__all__ = ["assess_plan_c", "compare", "compile_diff", "api_model", "usage_of", "load_header_tree", "DirProvider", "GitProvider", "C_ECOSYSTEMS", "HONESTY"]
