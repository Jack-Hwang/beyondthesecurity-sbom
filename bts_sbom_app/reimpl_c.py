"""Clean-room reimplementation lane for C and C++ (the language backend behind ``reimpl.reimpl`` for .c/.cc/.cpp components).

Open source is mostly C/C++, so the lane has to work where the licence problem actually lives. Same legal spine as the Python
lane, rebuilt on a real toolchain instead of ``ast``:

  Wall 1 - READER   ``cparse`` reads the component and its paired public header(s) and exports ONLY the interface: prototypes,
                    the types/macros/constants the prototypes need, extern variables and the doc comments (contracts). Function
                    bodies are never stored by the parser, so they cannot leave the reader.
  Header            our OWN header is rendered deterministically from that interface (declarations are API facts; the
                    generator never writes it and never sees the original header text).
  Wall 2 - WRITER   the generator receives the spec only and returns a NEW ``<module>.c`` that ``#include``s the rendered header.
  Gate     copy     identifier-normalised token overlap over function BODIES (renaming a variable does not hide a copy;
                    numeric lookup tables are facts and excluded) plus a comment-stripped line-shingle overlap.
  Gate     compile  the real compiler (gcc/clang): -Wall -Wextra, implicit declarations are errors; ``nm`` proves every API
                    symbol is exported.
  Oracle            (1) the upstream test mains, compiled against the NEW module; (2) a generated DIFFERENTIAL driver that calls
                    the original and the new implementation with the same inputs (boundary integers, byte buffers, strings,
                    in/out buffers) and compares return values and output memory. Failing cases ride back to the generator as
                    behavioural facts. A module whose original cannot be built here gets NO oracle and the verdict says so
                    (``contract_only``) - it is never reported ``ok``.

Honest limits are listed in HONESTY below and returned with every record.
"""
from __future__ import annotations

import datetime
import os
import random
import re
import shutil
import subprocess
import sys
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

from . import __version__, arch_map, cparse

SCHEMA = "bts-sbom.reimpl.v1"
TOKEN_N = 12
TOKEN_THRESHOLD = 0.30
LINE_THRESHOLD = 0.05
LINE_N = 3
MIN_BODY_TOKENS = 60
COMPILE_TIMEOUT = 90
RUN_TIMEOUT = 30
MAX_CASES = 160
HONESTY = [
    "the copy gate measures the generated code against the given original only; a model may still reproduce code it memorised from elsewhere",
    "tiny function bodies (< %d tokens) share idioms with any implementation: their overlap is reported but marked unreliable" % MIN_BODY_TOKENS,
    "the differential oracle compares sampled inputs (boundary integers, random buffers, strings): equal outputs are evidence, not a proof",
    "functions with struct/function-pointer/double-pointer parameters are not comparable by the generated driver and are counted as skipped",
    "a module whose original cannot be compiled here has no differential oracle: the verdict is contract_only, never ok",
    "C++ classes are compile-checked only (the differential driver covers free and namespace functions)",
    "the rendered header reproduces declarations (names, signatures, layouts, constants) because API/ABI compatibility requires them",
]

_C_KEYWORDS = {"auto", "break", "case", "char", "const", "continue", "default", "do", "double", "else", "enum", "extern", "float", "for", "goto", "if",
               "inline", "int", "long", "register", "restrict", "return", "short", "signed", "sizeof", "static", "struct", "switch", "typedef", "union",
               "unsigned", "void", "volatile", "while", "_Bool", "bool", "true", "false", "NULL", "class", "public", "private", "protected", "namespace",
               "template", "typename", "new", "delete", "this", "operator", "virtual", "nullptr", "try", "catch", "throw", "using", "constexpr", "noexcept"}
_KERNEL_TYPES = {"u8": "uint8_t", "u16": "uint16_t", "u32": "uint32_t", "u64": "uint64_t", "s8": "int8_t", "s16": "int16_t", "s32": "int32_t",
                 "s64": "int64_t", "__u8": "uint8_t", "__u16": "uint16_t", "__u32": "uint32_t", "__u64": "uint64_t", "__s8": "int8_t",
                 "__s16": "int16_t", "__s32": "int32_t", "__s64": "int64_t", "uint": "unsigned int", "ulong": "unsigned long",
                 "ushort": "unsigned short", "uchar": "unsigned char", "__le16": "uint16_t", "__le32": "uint32_t", "__le64": "uint64_t",
                 "__be16": "uint16_t", "__be32": "uint32_t", "__be64": "uint64_t"}
# types the HOST libc already provides: a project header (kernel style) re-typedefs them differently, which cannot coexist with <stddef.h>/<stdint.h>
_HOST_TYPES = {"size_t", "ssize_t", "ptrdiff_t", "off_t", "bool", "_Bool", "wchar_t", "time_t", "clock_t", "int8_t", "int16_t", "int32_t", "int64_t",
               "uint8_t", "uint16_t", "uint32_t", "uint64_t", "intptr_t", "uintptr_t", "intmax_t", "uintmax_t", "dev_t", "ino_t", "mode_t", "nlink_t",
               "pid_t", "uid_t", "gid_t", "loff_t", "fd_set", "FILE", "va_list", "true", "false"}
# what kernel-style C expects from the arch layer / compiler.h; each is guarded, so the project's own definition still wins when it has one
_KERNEL_COMPAT = [
    "#ifndef BITS_PER_LONG", "#define BITS_PER_LONG (__SIZEOF_LONG__ * 8)", "#endif",
    "#ifndef BITS_PER_LONG_LONG", "#define BITS_PER_LONG_LONG 64", "#endif",
    "#ifndef __BITS_PER_LONG", "#define __BITS_PER_LONG (__SIZEOF_LONG__ * 8)", "#endif",
    "#ifndef __packed", "#define __packed __attribute__((packed))", "#endif",
    "#ifndef __aligned", "#define __aligned(x) __attribute__((aligned(x)))", "#endif",
    "#ifndef __maybe_unused", "#define __maybe_unused __attribute__((unused))", "#endif",
    "#ifndef __weak", "#define __weak __attribute__((weak))", "#endif",
    "#ifndef __noreturn", "#define __noreturn __attribute__((noreturn))", "#endif",
    "#ifndef __always_inline", "#define __always_inline inline __attribute__((always_inline))", "#endif",
    "#ifndef likely", "#define likely(x) __builtin_expect(!!(x), 1)", "#endif",
    "#ifndef unlikely", "#define unlikely(x) __builtin_expect(!!(x), 0)", "#endif",
    "#ifndef __iomem", "#define __iomem", "#endif", "#ifndef __user", "#define __user", "#endif", "#ifndef __force", "#define __force", "#endif",
    "#ifndef __init", "#define __init", "#endif", "#ifndef __exit", "#define __exit", "#endif",
]
_LIBC_FUNCS = set("strcpy strncpy strcat strncat strcmp strncmp strchr strrchr strstr strlen strnlen strspn strcspn strpbrk strtok memcpy memmove memset "
                  "memcmp memchr strdup strndup strcasecmp strncasecmp strsep strlcpy strlcat sprintf snprintf vsnprintf vsprintf sscanf printf puts putchar "
                  "getchar abs labs div ldiv qsort bsearch rand srand atoi atol strtol strtoul strtoll strtoull malloc calloc realloc free memdup".split())
_HOST_TYPES_ALIASES = {"__kernel_size_t", "__kernel_ssize_t", "__kernel_ptrdiff_t", "__kernel_off_t", "__kernel_time_t", "__kernel_pid_t"}
_INT_BASES = {"char", "signed char", "unsigned char", "short", "unsigned short", "int", "unsigned int", "unsigned", "long", "unsigned long", "long long",
              "unsigned long long", "size_t", "ssize_t", "ptrdiff_t", "intptr_t", "uintptr_t", "_Bool", "bool", "int8_t", "int16_t", "int32_t", "int64_t",
              "uint8_t", "uint16_t", "uint32_t", "uint64_t", "wchar_t", "off_t", "time_t"}
_SIGNED = {"char", "signed char", "short", "int", "long", "long long", "ssize_t", "ptrdiff_t", "intptr_t", "int8_t", "int16_t", "int32_t", "int64_t", "off_t", "time_t"}
_CHAR_LIKE = {"char", "signed char", "unsigned char", "uint8_t", "int8_t", "void"}
_LEN_NAMES = re.compile(r"^(len|length|size|sz|n|num|count|nbytes|bytes|siz|buflen|datalen|ilen|olen|chunk_sz|nmemb)$", re.I)
_OUT_NAMES = re.compile(r"^(out|dst|dest|output|result|res|buf|buffer|obuf|ob|to|ret)$", re.I)
_INT_POOL = [0, 1, 2, 3, 7, 8, 15, 16, 31, 32, 100, 127, 128, 255, 256, 1000, 32767, 32768, 65535, 65536, 0x7FFFFFFF, 0x80000000, 0xFFFFFFFF]
_LEN_POOL = [0, 1, 2, 3, 5, 8, 16, 31, 64, 100]
_STR_POOL = ["", "a", "hello world", "0x1f", "  42abc", "-17", "ABCdef012", "tab\tsep", "9999999999999999999999", "x=1;y=2"]


# ============================================================================================ toolchain
def _which(*names: str) -> Optional[str]:
    for n in names:
        p = shutil.which(n)
        if p:
            return p
    return None


def toolchain() -> Dict[str, Optional[str]]:
    """The C/C++ compiler and binutils found on this machine (BTS_SBOM_CC / BTS_SBOM_CXX override). None = not available."""
    return {"cc": os.environ.get("BTS_SBOM_CC") or _which("gcc", "clang", "cc"), "cxx": os.environ.get("BTS_SBOM_CXX") or _which("g++", "clang++", "c++"),
            "nm": _which("nm", "llvm-nm")}


def _run(cmd: List[str], cwd: Optional[str] = None, timeout: float = COMPILE_TIMEOUT) -> Dict[str, Any]:
    try:
        p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=timeout)
        return {"rc": p.returncode, "out": (p.stdout or ""), "err": (p.stderr or ""), "timeout": False}
    except subprocess.TimeoutExpired as exc:
        return {"rc": None, "out": "", "err": "timeout after %ds" % int(timeout), "timeout": True}
    except OSError as exc:
        return {"rc": None, "out": "", "err": "%s: %s" % (type(exc).__name__, exc), "timeout": False}


def _errors_only(stderr: str, limit: int = 1200) -> str:
    lines = [ln for ln in stderr.splitlines() if "error" in ln.lower() or "undefined reference" in ln or "fatal" in ln.lower()]
    return "\n".join(lines)[:limit] or stderr[-limit:]


# ============================================================================================ wall 1: interface (reader)
_LICENSE_LINE = re.compile(r"(spdx-license|copyright|\(c\)|all rights reserved|gnu general public|gpl|licensed under|warranty|free software)", re.I)


def clean_doc(doc: Optional[str], cap: int = 900) -> str:
    if not doc:
        return ""
    lines = [ln.rstrip() for ln in doc.splitlines()]
    kept = [ln for ln in lines if not _LICENSE_LINE.search(ln)]
    return "\n".join(kept).strip()[:cap]


def _index_headers(source_root: str, cap: int = 20000) -> Dict[str, List[str]]:
    idx: Dict[str, List[str]] = {}
    n = 0
    for dp, dns, fns in os.walk(source_root):
        dns[:] = [d for d in dns if d not in (".git", "node_modules", "build", ".svn") and not d.startswith(".")]
        for fn in fns:
            if fn.lower().endswith(cparse.HEADER_EXT):
                rel = os.path.relpath(os.path.join(dp, fn), source_root).replace("\\", "/")
                idx.setdefault(fn, []).append(rel)
                n += 1
                if n >= cap:
                    return idx
    return idx


def _resolve_include(inc: str, idx: Dict[str, List[str]], near: str) -> Optional[str]:
    base = os.path.basename(inc)
    cands = [c for c in idx.get(base, []) if c == inc or c.endswith("/" + inc)]
    if not cands:
        return None
    near = near.replace("\\", "/")
    cands.sort(key=lambda c: (0 if os.path.dirname(c) == os.path.dirname(near) else 1, len(c)))
    return cands[0]


def paired_headers(source_root: str, component: str, model: Dict[str, Any], idx: Dict[str, List[str]]) -> List[Tuple[str, str]]:
    """[(relpath of a header that declares this module's API, the include spelling the .c uses)]."""
    names = {f["name"] for f in model["functions"] if f["defined"] and not f["static"]}
    out: List[Tuple[str, str]] = []
    seen: Set[str] = set()
    base = os.path.splitext(os.path.basename(component))[0]
    cands: List[Tuple[Optional[str], str]] = []
    for inc in model.get("includes") or []:
        cands.append((_resolve_include(inc["path"], idx, component), inc["path"]))
    for h in idx.get(base + ".h", []) + idx.get(base + ".hpp", []):
        cands.append((h, os.path.basename(h)))
    for rel, spelled in cands:
        if not rel or rel in seen:
            continue
        seen.add(rel)
        try:
            hm = cparse.parse_file(os.path.join(source_root, rel))
        except OSError:
            continue
        declared = {f["name"] for f in hm["functions"]}
        decl_vars = {v["name"] for v in hm["variables"]}
        defined_vars = {v["name"] for v in model["variables"] if "static" not in v.get("storage", [])}
        if declared & names or decl_vars & defined_vars or os.path.splitext(os.path.basename(rel))[0] == base:
            out.append((rel, spelled))
    return out[:4]


def _words(text: str) -> Set[str]:
    return set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text))


def _type_universe(source_root: str, idx: Dict[str, List[str]], start: List[str], depth: int = 3, cap: int = 40) -> Dict[str, Any]:
    """Types visible to the module: the paired headers and, breadth-first, the project headers they include (a prototype's typedef is often
    defined one include away). Bounded: <= ``cap`` headers, ``depth`` levels."""
    seen: Set[str] = set()
    models: List[Dict[str, Any]] = []
    frontier = list(dict.fromkeys(start))
    for _ in range(depth):
        nxt: List[str] = []
        for rel in frontier:
            if rel in seen or len(seen) >= cap:
                continue
            seen.add(rel)
            try:
                m = cparse.parse_file(os.path.join(source_root, rel))
            except OSError:
                continue
            models.append(m)
            for inc in m["includes"]:
                r2 = _resolve_include(inc["path"], idx, rel)
                if r2 and r2 not in seen:
                    nxt.append(r2)
        frontier = nxt
    return cparse.merge(models) if models else {"types": [], "functions": [], "macros": [], "variables": [], "includes": []}


def extract_interface_c(source_root: str, component: str) -> Dict[str, Any]:
    """Public interface of one C/C++ component. Implementation bodies are never read into the result (the parser does not keep them)."""
    path = os.path.join(source_root, component)
    model = cparse.parse_file(path)
    module = os.path.splitext(os.path.basename(component))[0]
    idx = _index_headers(source_root)
    pairs = paired_headers(source_root, component, model, idx)
    hmodels = [cparse.parse_file(os.path.join(source_root, rel)) for rel, _ in pairs]
    hdr = cparse.merge(hmodels) if hmodels else {"functions": [], "types": [], "macros": [], "variables": [], "includes": []}
    decl_by_name: Dict[str, List[Dict[str, Any]]] = {}
    for f in hdr["functions"]:
        decl_by_name.setdefault(f["qualified"], []).append(f)
    functions: List[Dict[str, Any]] = []
    for f in model["functions"]:
        if not f["defined"] or f["static"] or f["kind"] not in ("function", "method", "ctor", "dtor") or f["template"]:
            continue
        cands = decl_by_name.get(f["qualified"], [])
        d = next((c for c in cands if len(c["params"]) == len(f["params"])), cands[0] if cands else None)
        src = d or f
        doc = clean_doc((d or {}).get("doc")) or clean_doc(f.get("doc"))
        if d and f.get("doc") and len(clean_doc(f["doc"])) > len(doc):
            doc = clean_doc(f["doc"])
        functions.append({"name": f["name"], "qualified": f["qualified"], "kind": f["kind"], "ret": src["ret"], "params": src["params"], "variadic": src["variadic"],
                          "proto": src["proto"], "doc": doc, "in_header": d is not None, "scope": f["scope"], "const": f.get("const", False),
                          "defined_in": component.replace("\\", "/")})
    # extern variables the component defines (data tables are part of the interface)
    variables = []
    own_vars = {v["name"]: v for v in model["variables"] if "static" not in v.get("storage", []) and not v.get("extern")}
    for v in hdr["variables"]:
        if v["name"] in own_vars:
            variables.append({"name": v["name"], "type": v["type"], "array": v.get("array"), "const": v.get("const", False), "doc": clean_doc(v.get("doc"))})
    # the types / macros the prototypes need (transitive through field declarations)
    need = set()
    for f in functions:
        need |= _words(f["proto"])
    for v in variables:
        need |= _words(v["type"])
    types: List[Dict[str, Any]] = []
    uni = _type_universe(source_root, idx, [p[0] for p in pairs] + [r for r in (_resolve_include(i["path"], idx, component) for i in model.get("includes") or []) if r])
    by_name: Dict[str, List[Dict[str, Any]]] = {}
    for t in uni["types"]:                                          # a struct tag and its typedef share a name: BOTH are needed (definition, then alias)
        if t["name"] and t["name"] not in _HOST_TYPES and t["name"] not in _KERNEL_TYPES and not t["name"].startswith("__kernel") \
                and not (t["kind"] == "typedef" and _words(t.get("target", "")) & _HOST_TYPES_ALIASES):
            by_name.setdefault(t["name"], []).append(t)
    taken: Set[str] = set()
    work = sorted(need & set(by_name))
    depth = 0
    while work and depth < 4:
        nxt: Set[str] = set()
        for nm in work:
            if nm in taken:
                continue
            taken.add(nm)
            for t in by_name[nm]:
                types.append(t)
                for fld in t.get("fields") or []:
                    nxt |= (_words(fld.get("decl") or fld["type"]) & set(by_name)) - taken
                if t["kind"] == "typedef":
                    nxt |= (_words(t["target"]) & set(by_name)) - taken
        work = sorted(nxt)
        depth += 1
    macros = [m for m in hdr["macros"] if not m["guard"] and m["params"] is None and (m["value"] is not None or m["body"])][:60]
    return {"module": module, "language": model["language"], "path": component.replace("\\", "/"), "functions": functions, "variables": variables,
            "types": types, "macros": macros, "kernel_types": [], "paired_headers": [p[0] for p in pairs], "include_spellings": [p[1] for p in pairs],
            "imports": sorted({i["path"] for i in model["includes"] if i["system"]})[:12], "skipped": model["skipped"]}


# ============================================================================================ the rendered header + spec
def _fn_name_c(f: Dict[str, Any]) -> str:
    return f["name"]


def _order_types(types: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Dependency order: a type is emitted after every other listed type its declaration mentions (cycles fall back to input order)."""
    names = {t["name"] for t in types if t["name"]}
    deps: Dict[int, Set[str]] = {}
    for i, t in enumerate(types):
        text = " ".join([t.get("target", "")] + [f.get("decl") or f["type"] for f in t.get("fields") or []] + [e.get("expr", "") for e in t.get("enumerators") or []])
        deps[i] = (_words(text) & names) - {t["name"]}
    done: Set[str] = set()
    out: List[Dict[str, Any]] = []
    left = list(range(len(types)))
    while left:
        progressed = False
        for i in list(left):
            if deps[i] <= done:
                out.append(types[i])
                done.add(types[i]["name"])
                left.remove(i)
                progressed = True
        if not progressed:                                           # a cycle: emit the first remaining one and go on
            i = left.pop(0)
            out.append(types[i])
            done.add(types[i]["name"])
    return out


def render_header(iface: Dict[str, Any]) -> str:
    """Our own header from the interface model: declarations only, deterministic, never written by the generator. Self-contained: forward
    declarations for every struct/union tag, types in dependency order, kernel-style integer typedefs (u8, __u32 ...) defined when used."""
    mod = re.sub(r"[^A-Za-z0-9]", "_", iface["module"]).upper()
    cpp = iface["language"] == "c++"
    defined = {t["name"] for t in iface.get("types", []) if t["name"]}
    body: List[str] = []
    for m in iface.get("macros", []):
        plain = bool(re.fullmatch(r"(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*", m.get("body") or ""))
        val = m["body"] if plain else (("0x%X" % m["value"]) if (m.get("value") is not None and m["value"] >= 0) else
                                       (str(m["value"]) if m.get("value") is not None else m["body"]))
        body.append("#define %s %s" % (m["name"], val))
    if iface.get("macros"):
        body.append("")
    order = _order_types(list(iface.get("types", [])))
    tags = [t for t in order if t["kind"] in ("struct", "union") and t["name"] and not t.get("anon_typedef")]
    for t in tags:
        body.append("%s %s;" % (t["kind"], t["name"]))
    if tags:
        body.append("")
    for t in order:
        body.append(_render_type(t))
    if order:
        body.append("")
    for v in iface.get("variables", []):
        body.append("extern %s %s%s;" % (v["type"], v["name"], v.get("array") or ""))
    if iface.get("variables"):
        body.append("")
    for f in iface["functions"]:
        body.append("%s;" % f["proto"])
    text = "\n".join(body)
    kernel = sorted(w for w in _words(text) if w in _KERNEL_TYPES and w not in defined)
    out = ["/* clean-room interface header for %s - declarations only, rendered from the interface model */" % iface["module"],
           "#ifndef BTS_CR_%s_H" % mod, "#define BTS_CR_%s_H" % mod, "", "#include <stddef.h>", "#include <stdint.h>"]
    out += ["#ifndef __cplusplus", "#include <stdbool.h>", "#endif", ""]
    if not cpp:
        out += ["#ifdef __cplusplus", 'extern "C" {', "#endif", ""]
    out += ["typedef %s %s;" % (_KERNEL_TYPES[k], k) for k in kernel]
    if kernel:
        out.append("")
    out += body
    out.append("")
    if not cpp:
        out += ["#ifdef __cplusplus", "}", "#endif", ""]
    out.append("#endif /* BTS_CR_%s_H */" % mod)
    return "\n".join(out) + "\n"


def _render_type(t: Dict[str, Any]) -> str:
    kind = t["kind"]
    if kind == "typedef":
        return (t.get("decl") or ("typedef %s %s" % (t.get("target", "int"), t["name"]))) + ";"
    anon = bool(t.get("anon_typedef"))
    if kind == "enum":
        body = ", ".join("%s%s" % (e["name"], (" = " + e["expr"]) if e.get("expr") else "") for e in t.get("enumerators") or [])
        return ("typedef enum { %s } %s;" % (body, t["name"])) if anon else "enum %s { %s };" % (t["name"], body)
    fields = "\n".join("    %s;" % (f.get("decl") or "%s %s" % (f["type"], f["name"])) for f in t.get("fields") or [])
    if not fields:
        return ("typedef %s { int _opaque; } %s;" % (kind, t["name"])) if anon else "%s %s;" % (kind, t["name"])
    bases = (" : public " + ", public ".join(t["bases"])) if t.get("bases") else ""
    if anon:
        return "typedef %s {\n%s\n} %s;" % (kind, fields, t["name"])
    return "%s %s%s {\n%s\n};" % (kind, t["name"], bases, fields)


def spec_document_c(iface: Dict[str, Any], why: str, header_name: str) -> str:
    out = ["# Clean-room spec (C%s): %s" % ("++" if iface["language"] == "c++" else "", iface["module"]), "",
           "Why reimplementation: %s" % why, "",
           "## Requirements", "",
           "- write a NEW %s source file `%s%s` that defines every external function listed below, with exactly these signatures" % (
               "C++" if iface["language"] == "c++" else "C", iface["module"], ".cpp" if iface["language"] == "c++" else ".c"),
           "- start with `#include \"%s\"`: it declares the types, constants and prototypes below (generated from this spec - do not redeclare them)" % header_name,
           "- use only the C standard library (<string.h>, <stdint.h>, <stddef.h>, <limits.h>, <stdlib.h> ...) - no other project headers",
           "- helper functions must be `static`; export nothing that is not listed",
           "- the file must compile warning-free with `-Wall -Wextra`", ""]
    if iface.get("macros") or iface.get("types"):
        out += ["## Constants and types (declared in the header)", ""]
        for m in iface.get("macros", [])[:30]:
            out.append("- `%s` = %s" % (m["name"], m["value"] if m.get("value") is not None else m["body"]))
        for t in iface.get("types", [])[:30]:
            out.append("- %s `%s`%s" % (t["kind"], t["name"], (": " + clean_doc(t.get("doc"), 160).replace("\n", " ")) if t.get("doc") else ""))
        out.append("")
    if iface.get("variables"):
        out += ["## Variables to define", ""]
        for v in iface["variables"]:
            out.append("- `%s %s%s`%s" % (v["type"], v["name"], v.get("array") or "", (": " + v["doc"].replace("\n", " ")[:200]) if v.get("doc") else ""))
        out.append("")
    out += ["## Function contracts", ""]
    for f in iface["functions"]:
        out.append("- `%s`:" % f["proto"])
        if f["doc"]:
            for ln in f["doc"].split("\n"):
                out.append("  " + ln.strip())
        else:
            out.append("  (contract unspecified - implement the obvious behaviour of the name and signature)")
    out += ["", "## Clean-room rule", "", "Write original code. Do not reproduce any existing implementation text.", ""]
    return "\n".join(out)


def scaffold_c(iface: Dict[str, Any], header_name: str) -> str:
    out = ['/* SCAFFOLD ONLY: deterministic clean-room skeleton for %s - implementation bodies need the LLM lane */' % iface["module"],
           '#include "%s"' % header_name, ""]
    for v in iface.get("variables", []):
        out.append("%s %s%s;" % (v["type"], v["name"], v.get("array") or ("[1]" if False else "")))
    for f in iface["functions"]:
        ret = f["ret"].strip()
        body = "    return 0;" if ret and ret != "void" and "*" in ret or ret in ("int", "unsigned int", "unsigned", "long", "unsigned long", "size_t", "bool", "char") else \
            ("" if ret == "void" or not ret else "    static %s zero;\n    return zero;" % re.sub(r"\bconst\b", "", ret).strip())
        out += ["%s {" % f["proto"], body or "    /* nothing to do */", "}", ""]
    return "\n".join(out)


def llm_generate_c(spec: str, client: Any, language: str, prior_fail: Optional[str] = None) -> str:
    system = ("You are the implementation team inside a clean-room process. Below is a SPEC only. Write a NEW %s implementation that satisfies it. "
              "Return JSON {\"code\": string} where code is the complete source file. The original code was never shown to you and must not be "
              "guessed at or quoted." % ("C++" if language == "c++" else "C"))
    if prior_fail:
        system += (" IMPORTANT: your previous implementation failed verification. Facts observed from running the reference behaviour:\n%s\n\n"
                   "Fix exactly those behaviours while keeping the rest of the contract." % prior_fail[:1800])
    raw = client.complete(system + "\n\nRespond with ONLY valid JSON, no prose, no code fences.", "SPEC:\n" + spec, max_tokens=16384, json_mode=True)
    from . import ai
    obj = ai._parse_json(raw)
    code = obj.get("code")
    if not isinstance(code, str) or len(code.strip()) < 10:
        raise ValueError("the model returned no usable code field")
    return code


# ============================================================================================ the copy gate
def _strip_tables(toks: List[cparse.Tok]) -> List[cparse.Tok]:
    out: List[cparse.Tok] = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t.kind == "p" and t.text == "{" and out and out[-1].text == "=":
            j = cparse._match(toks, i, "{", "}")
            inner = toks[i + 1:j]
            if len(inner) >= 16 and not any(x.text in (";", "{") and x.kind == "p" for x in inner if x is not inner[0]):
                out.append(cparse.Tok("p", "{TABLE}", t.line))
                i = j + 1
                continue
        out.append(t)
        i += 1
    return out


def body_tokens(code: str) -> List[str]:
    """Identifier-normalised tokens of all function BODIES (numeric tables removed; 0/1 literals kept, other numbers -> NUM)."""
    toks, _pps = cparse.tokenize(code)
    toks = _strip_tables(toks)
    out: List[str] = []
    depth = 0
    in_body = 0
    n = len(toks)
    i = 0
    while i < n:
        t = toks[i]
        if t.kind == "p" and t.text == "{":
            if depth == 0 and i > 0 and toks[i - 1].text in (")", "const", "noexcept", "override"):
                in_body = 1
            depth += 1
        elif t.kind == "p" and t.text == "}":
            depth -= 1
            if depth == 0:
                in_body = 0
                out.append("|")
            i += 1
            continue
        if in_body and depth >= 1 and not (depth == 1 and t.text == "{"):
            if t.kind == "id":
                out.append(t.text if t.text in _C_KEYWORDS else "ID")
            elif t.kind == "num":
                out.append(t.text if t.text in ("0", "1") else "NUM")
            elif t.kind in ("str", "chr"):
                out.append("STR")
            else:
                out.append(t.text)
        i += 1
    return out


def _grams(seq: List[str], n: int) -> Set[Tuple[str, ...]]:
    return {tuple(seq[i:i + n]) for i in range(max(0, len(seq) - n + 1)) if "|" not in seq[i:i + n]}


def token_overlap(new_code: str, orig_code: str, n: int = TOKEN_N) -> Dict[str, Any]:
    a, b = body_tokens(new_code), body_tokens(orig_code)
    ga, gb = _grams(a, n), _grams(b, n)
    ov = round(len(ga & gb) / len(ga), 4) if ga and gb else 0.0
    return {"overlap": ov, "new_tokens": len([x for x in a if x != "|"]), "orig_tokens": len([x for x in b if x != "|"]),
            "reliable": len([x for x in a if x != "|"]) >= MIN_BODY_TOKENS and len([x for x in b if x != "|"]) >= MIN_BODY_TOKENS}


def _strip_comments(code: str) -> str:
    code = re.sub(r"/\*.*?\*/", " ", code, flags=re.S)
    return re.sub(r"//[^\n]*", "", code)


_NUMERIC_ROW = re.compile(r"(?:[-+~]?(?:0[xX][0-9a-fA-F]+|\d+)[uUlL]*\s*(?:[,|<>^&+-]|<<|>>)?\s*)+")


def _norm_line(s: str) -> str:
    return re.sub(r"\s*([(),;*{}])\s*", r"\1", re.sub(r"\s+", " ", s.strip()))


def line_overlap(new_code: str, orig_code: str, n: int = LINE_N, ignore: Optional[Set[str]] = None) -> float:
    """Comment-stripped line shingles. Lines the INTERFACE forces on every implementation (the API prototypes) and pure punctuation lines
    ({ } ) are not evidence of copying and are dropped first."""
    ignore = {_norm_line(x) for x in (ignore or set())}

    def sh(text: str) -> Set[Tuple[str, ...]]:
        lines = [_norm_line(ln) for ln in _strip_comments(text).splitlines()]
        lines = [ln for ln in lines if ln and not ln.startswith("#") and ln not in ignore and not re.fullmatch(r"[{}();,\s]*", ln) and len(ln) > 3
                 and not _NUMERIC_ROW.fullmatch(ln)]                 # a row of a numeric table (CRC/CTYPE/S-box) is a fact, not expression
        return {tuple(lines[i:i + n]) for i in range(max(1, len(lines) - n + 1))} if len(lines) >= n else set()
    a, b = sh(new_code), sh(orig_code)
    return round(len(a & b) / len(a), 4) if a and b else 0.0


def copy_gate(code: str, original: str, threshold: float = TOKEN_THRESHOLD, ignore_lines: Optional[Set[str]] = None) -> Dict[str, Any]:
    from . import reimpl
    tok = token_overlap(code, original)
    ln = line_overlap(code, original, ignore=ignore_lines)
    lic = reimpl.license_strings_in(code)
    over_tok = tok["reliable"] and tok["overlap"] > threshold
    return {"overlap": max(tok["overlap"], ln), "token_overlap": tok["overlap"], "line_overlap": ln, "threshold": threshold, "line_threshold": LINE_THRESHOLD,
            "reliable": tok["reliable"], "body_tokens": [tok["new_tokens"], tok["orig_tokens"]], "license_strings": lic,
            "passed": not over_tok and ln <= LINE_THRESHOLD and not lic}


# ============================================================================================ compile + export checks
def _lang_of(path: str) -> str:
    return "c++" if path.lower().endswith(cparse.CPP_EXT) else "c"


def compile_object(tc: Dict[str, Optional[str]], src: str, obj: str, include_dirs: List[str], defines: List[str], lang: Optional[str] = None,
                   extra: Optional[List[str]] = None, warn: bool = True, after_dirs: Optional[List[str]] = None, relaxed: bool = False) -> Dict[str, Any]:
    """``after_dirs`` are searched AFTER the system headers (-idirafter): a freestanding project that ships its own string.h / stdint.h must not
    shadow the host's libc when its sources are built standalone here."""
    lang = lang or _lang_of(src)
    cc = tc["cxx"] if lang == "c++" else tc["cc"]
    if not cc:
        return {"ok": False, "toolchain_missing": True, "err": "no %s compiler on PATH" % ("C++" if lang == "c++" else "C")}
    cmd = [cc, "-std=gnu++17" if lang == "c++" else "-std=gnu11", "-O1", "-c", src, "-o", obj] + (["-Wall", "-Wextra"] if warn else ["-w"])
    if lang == "c" and not relaxed:
        cmd.append("-Werror=implicit-function-declaration")
    if relaxed:                                              # the ORIGINAL was written for another toolchain/era: accept what that one accepted
        cmd += ["-fpermissive", "-Wno-implicit-function-declaration", "-Wno-implicit-int", "-Wno-int-conversion", "-Wno-incompatible-pointer-types"]
    for d in include_dirs:
        cmd += ["-I", d]
    for d in after_dirs or []:
        cmd += ["-idirafter", d]
    cmd += ["-D" + d for d in defines] + list(extra or [])
    r = _run(cmd, cwd=os.path.dirname(os.path.abspath(src)))
    warnings = len(re.findall(r"warning:", r["err"]))
    return {"ok": r["rc"] == 0 and os.path.exists(obj), "rc": r["rc"], "err": r["err"], "errors": _errors_only(r["err"]) if r["rc"] != 0 else "", "warnings": warnings,
            "cmd": " ".join(cmd[:3])}


def exported_symbols(tc: Dict[str, Optional[str]], obj: str, cpp: bool = False) -> Optional[Set[str]]:
    if not tc.get("nm"):
        return None
    r = _run([tc["nm"]] + (["-C"] if cpp else []) + ["--defined-only", obj], timeout=30)
    if r["rc"] != 0:
        return None
    out: Set[str] = set()
    for ln in r["out"].splitlines():
        parts = ln.split(None, 2)
        if len(parts) == 3 and parts[1] in ("T", "D", "B", "R", "C", "W", "V"):
            out.add(parts[2].strip().lstrip("_") if parts[2].startswith("_") and not cpp and parts[2][1:2].isalpha() and False else parts[2].strip())
    return out


def export_check(syms: Optional[Set[str]], iface: Dict[str, Any]) -> Dict[str, Any]:
    if syms is None:
        return {"checked": False, "reason": "nm is not available"}
    cpp = iface["language"] == "c++"
    want = [f["name"] for f in iface["functions"] if f["kind"] == "function"] + [v["name"] for v in iface.get("variables", [])]
    if cpp:
        have = {re.split(r"[(<]", s)[0].split("::")[-1] for s in syms}
    else:
        have = set(syms) | {s[1:] for s in syms if s.startswith("_")}
    missing = sorted(set(want) - have)
    extra = sorted(s for s in (have - set(want)) if not s.startswith(("__", ".", "_GLOBAL")) and not s.startswith("_Z"))[:12]
    return {"checked": True, "wanted": len(want), "missing": missing, "extra_exports": extra, "ok": not missing}


def gen_contract_test_c(iface: Dict[str, Any], header_name: str) -> str:
    fns = [f for f in iface["functions"] if f["kind"] == "function" and not f["variadic"] or (f["kind"] == "function" and f["variadic"])]
    out = ["/* generated linkage test for %s: every API symbol resolves and has an address */" % iface["module"],
           '#include "%s"' % header_name, "#include <stdio.h>", "", "int main(void) {", "    int fail = 0;"]
    syms = ["(const void *)&%s" % f["name"] for f in fns] + ["(const void *)&%s" % v["name"] for v in iface.get("variables", [])]
    if syms:
        out.append("    const void *syms[] = { %s };" % ", ".join(syms))
        out.append("    for (unsigned i = 0; i < sizeof syms / sizeof syms[0]; i++) if (!syms[i]) fail++;")
    out += ['    printf("contract: %d symbols, %d failed\\n", ' + str(len(syms)) + ", fail);", "    return fail ? 1 : 0;", "}", ""]
    return "\n".join(out)


def _link_run(tc: Dict[str, Optional[str]], sources: List[str], exe: str, include_dirs: List[str], defines: List[str], lang: str, cwd: str,
              timeout: float = RUN_TIMEOUT, extra: Optional[List[str]] = None) -> Dict[str, Any]:
    cc = tc["cxx"] if lang == "c++" else tc["cc"]
    if not cc:
        return {"ok": False, "built": False, "err": "no compiler", "out": ""}
    cmd = [cc, "-std=gnu++17" if lang == "c++" else "-std=gnu11", "-O1", "-w"] + sources + ["-o", exe]
    for d in include_dirs:
        cmd += ["-I", d]
    cmd += ["-D" + d for d in defines] + list(extra or []) + (["-lm"] if lang == "c" and os.name != "nt" else [])
    b = _run(cmd, cwd=cwd)
    if b["rc"] != 0:
        return {"ok": False, "built": False, "err": _errors_only(b["err"]), "out": ""}
    r = _run([exe], cwd=cwd, timeout=timeout)
    return {"ok": r["rc"] == 0, "built": True, "rc": r["rc"], "out": (r["out"] + r["err"])[-3000:], "timeout": r["timeout"]}


# ============================================================================================ the original, built here (oracle side)
def _repair_prelude(errors: str, prelude: Dict[str, Any]) -> bool:
    """Error-driven fix of the host mismatch: unknown kernel-style typedefs get a typedef, unknown marker words (__rcode, __init ...) an empty
    macro. True when the prelude changed (worth another attempt)."""
    changed = False
    for m in re.finditer(r"^(.+?):(\d+):(\d+): error: unknown type name '(\w+)'", errors, re.M):
        name = m.group(4)
        if name in prelude["typedefs"] or name in prelude["empty"]:
            continue
        try:
            with open(m.group(1), "r", encoding="utf-8", errors="replace") as fh:
                line = fh.read().split("\n")[int(m.group(2)) - 1]
        except (OSError, IndexError):
            line = ""
        after = line[max(0, int(m.group(3)) - 1):].split()
        nxt = after[1] if len(after) > 1 else ""
        if name in _KERNEL_TYPES:
            prelude["typedefs"][name] = _KERNEL_TYPES[name]
        elif line.lstrip().startswith("typedef") or name.endswith("_t"):
            prelude["typedefs"][name] = "unsigned long"             # a type from a header we do not have: integer-like is the usual case
        elif nxt in ("static", "extern", "inline", "const", "unsigned", "signed", "int", "char", "void", "short", "long", "struct", "union", "enum",
                     "double", "float", "volatile") or name.startswith("__"):
            prelude["empty"].add(name)                              # a marker word in front of a declaration (__rcode, __init ...)
        else:
            continue                                                # a real project type we cannot invent: not repairable here
        changed = True
    # `#if CONFIG_IS_ENABLED(FOO)` with the macro undefined: "missing binary operator before token '('" - the offending line names the macro
    for m in re.finditer(r"^(.+?):(\d+):(\d+): error: missing binary operator before token '\('", errors, re.M):
        try:
            with open(m.group(1), "r", encoding="utf-8", errors="replace") as fh:
                line = fh.read().split("\n")[int(m.group(2)) - 1]
        except (OSError, IndexError):
            continue
        for name in re.findall(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(", line):
            if name not in ("defined", "sizeof") and name not in prelude["fnmacros"]:
                prelude["fnmacros"].add(name)
                changed = True
    # `__rcode static int f(...)`: an unknown marker word in front of a declaration reads as "expected ';' before 'static'" - the word that ends
    # just before the reported column is the marker
    for m in re.finditer(r"^(.+?):(\d+):(\d+): error: expected [^\n]*? before '(\w+)'", errors, re.M):
        try:
            with open(m.group(1), "r", encoding="utf-8", errors="replace") as fh:
                line = fh.read().split("\n")[int(m.group(2)) - 1]
        except (OSError, IndexError):
            continue
        words = re.findall(r"[A-Za-z_]\w*", line[:max(0, int(m.group(3)) - 1)])
        word = words[-1] if words else ""
        if word and word not in _C_KEYWORDS and word not in prelude["empty"] and word not in prelude["typedefs"] and (word.startswith("__") or word.isupper()):
            prelude["empty"].add(word)
            changed = True
    return changed


def _spelling_under(path: str, dirs: List[str]) -> Optional[str]:
    """The include spelling (relative path) of ``path`` under the MOST SPECIFIC directory in ``dirs`` that contains it (include/ beats the
    project root: ``linux/types.h``, not ``include/linux/types.h``)."""
    p = os.path.normcase(os.path.normpath(path))
    best: Optional[Tuple[int, str]] = None
    for d in dirs:
        dd = os.path.normcase(os.path.normpath(d))
        if p.startswith(dd + os.sep) and (best is None or len(dd) > best[0]):
            best = (len(dd), os.path.relpath(path, d).replace("\\", "/"))
    return best[1] if best else None


def _prelude_text(prelude: Dict[str, Any]) -> str:
    out = ["#include <stddef.h>", "#include <stdint.h>", "#include <stdbool.h>", "#include <string.h>"]
    out += list(_KERNEL_COMPAT)
    out += ["typedef %s %s;" % (v, k) for k, v in sorted(prelude["typedefs"].items())]
    out += ["#define %s" % n for n in sorted(prelude["empty"])]
    out += ["#define %s(...) 0" % n for n in sorted(prelude.get("fnmacros", ()))]        # feature tests: IS_ENABLED(CONFIG_X) -> 0
    return "\n".join(out) + "\n"


def compile_original(tc: Dict[str, Optional[str]], source_root: str, component: str, iface: Dict[str, Any], header_text: str, work: str,
                     idx: Dict[str, List[str]], max_attempts: int = 24) -> Dict[str, Any]:
    """Build the ORIGINAL module to an object whose API symbols are renamed ``orig_<name>`` (``-Dname=orig_name``). Attempt 1 uses the project's
    own headers; later attempts shadow the paired header with our rendered one (the original .c only needs the declarations) and repair the
    host mismatch error by error. Failure is returned, never hidden - the lane then has no differential oracle."""
    path = os.path.join(source_root, component)
    lang = _lang_of(path)
    obj = os.path.join(work, "orig_%s.o" % iface["module"])
    inc_dirs = [os.path.dirname(path), source_root, os.path.join(source_root, "include")]
    for sp in iface.get("include_spellings", []):
        rel = _resolve_include(sp, idx, component)
        if rel and rel.endswith(sp):
            inc_dirs.append(os.path.join(source_root, rel[:-len(sp)].rstrip("/")) if rel[:-len(sp)].rstrip("/") else source_root)
    for rel_list in idx.values():
        pass
    inc_dirs = [d for i, d in enumerate(inc_dirs) if os.path.isdir(d) and d not in inc_dirs[:i]]
    rename = ["%s=orig_%s" % (f["name"], f["name"]) for f in iface["functions"] if f["kind"] == "function"] + \
             ["%s=orig_%s" % (v["name"], v["name"]) for v in iface.get("variables", [])]
    shim = os.path.join(work, "shim")
    os.makedirs(shim, exist_ok=True)
    log: List[str] = []
    attempt = 0
    for mode, budget in (("project headers", max_attempts), ("shadowed header", max_attempts)):
        prelude: Dict[str, Any] = {"typedefs": {}, "empty": set(), "fnmacros": set()}
        for _ in range(budget):
            attempt += 1
            dirs = list(inc_dirs)
            if mode != "project headers":
                for sp in iface.get("include_spellings", []):
                    dst = os.path.join(shim, sp)
                    os.makedirs(os.path.dirname(dst), exist_ok=True)
                    with open(dst, "w", encoding="utf-8", newline="\n") as fh:
                        fh.write(header_text)
                dirs = [shim] + dirs
            pre = os.path.join(shim, "bts_prelude.h")
            with open(pre, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(_prelude_text(prelude))
            lead = [d for d in dirs if d == shim]
            r = compile_object(tc, path, obj, lead, rename, lang=lang, extra=["-include", pre], warn=False, after_dirs=[d for d in dirs if d != shim], relaxed=True)
            if r.get("toolchain_missing"):
                return {"ok": False, "reason": r["err"], "attempts": attempt}
            if r["ok"]:
                return {"ok": True, "obj": obj, "attempts": attempt, "mode": mode, "prelude": {"typedefs": dict(prelude["typedefs"]), "empty": sorted(prelude["empty"])},
                        "include_dirs": dirs, "log": log[-3:]}
            err = r["err"]
            log.append("attempt %d (%s): %s" % (attempt, mode, _errors_only(err, 240).replace("\n", " | ")))
            m = re.search(r"fatal error: ([^\s:]+): No such file or directory", err)
            if m:
                stub = os.path.join(shim, m.group(1))
                if not os.path.exists(stub):
                    os.makedirs(os.path.dirname(stub), exist_ok=True)
                    open(stub, "w").close()
                    if shim not in inc_dirs:
                        inc_dirs.insert(0, shim)
                    continue
            # a project header that re-typedefs a HOST type (size_t, uintptr_t, bool ...) cannot coexist with <stddef.h>: replace that header by an
            # empty stub - the prelude (host libc + repaired kernel typedefs) provides what it declared
            conf = re.search(r"^(.+?):\d+:\d+: error: (?:conflicting types for|redefinition of|'?_Bool'? cannot be defined via)[^'\n]*'(\w+)'", err, re.M)
            if conf and (conf.group(2) in _HOST_TYPES or conf.group(2) in _KERNEL_TYPES or conf.group(2) in _LIBC_FUNCS):
                spelled = _spelling_under(conf.group(1), inc_dirs + [shim])
                if spelled:
                    stub = os.path.join(shim, spelled)
                    if not os.path.exists(stub) or os.path.getsize(stub):
                        os.makedirs(os.path.dirname(stub), exist_ok=True)
                        open(stub, "w").close()
                        if shim not in inc_dirs:
                            inc_dirs.insert(0, shim)
                        continue
            if _repair_prelude(err, prelude):
                continue
            break                                                   # nothing left to repair in this mode: try the next one
    return {"ok": False, "reason": "the original could not be compiled standalone on this host", "attempts": attempt, "log": log[-4:]}


# ============================================================================================ the differential driver
def _resolve_base(tname: str, tmap: Dict[str, str], depth: int = 0) -> str:
    t = cparse.normalize_type(tname)
    if depth > 6:
        return t
    if t in tmap:
        return _resolve_base(tmap[t], tmap, depth + 1)
    if t in _KERNEL_TYPES:
        return cparse.normalize_type(_KERNEL_TYPES[t])
    return t


def classify_param(p: Dict[str, Any], tmap: Dict[str, str], enums: Set[str]) -> Dict[str, Any]:
    """How the driver feeds one parameter: int / float / cstr / inbuf / outbuf / outscalar / other."""
    raw = p["type"]
    if p.get("funcptr"):
        return {"kind": "other", "why": "function pointer"}
    stars = raw.count("*") + raw.count("[")
    base_txt = raw.replace("*", " ").split("[")[0]
    is_const = bool(re.search(r"\bconst\b", raw))
    base = _resolve_base(re.sub(r"\b(?:const|volatile|struct|enum|union)\b", " ", base_txt), tmap)
    if re.search(r"\benum\b", raw) or base in enums:
        base = "int"
    if stars == 0:
        if base in _INT_BASES or base in ("int", "unsigned int"):
            return {"kind": "int", "base": base, "signed": base in _SIGNED or base == "int"}
        if base in ("float", "double", "long double"):
            return {"kind": "float", "base": base}
        return {"kind": "other", "why": "by-value %s" % base}
    if stars > 1:
        return {"kind": "other", "why": "pointer to pointer"}
    if base in ("char", "signed char", "unsigned char", "uint8_t", "int8_t", "void"):
        if is_const:
            return {"kind": "cstr" if base == "char" else "inbuf", "base": base}
        return {"kind": "outbuf", "base": base}
    if base in _INT_BASES:
        return {"kind": "inscalar" if is_const else "outscalar", "base": base, "signed": base in _SIGNED}
    return {"kind": "other", "why": "pointer to %s" % base}


def _c_lit(v: int, base: str, signed: bool) -> str:
    if signed:
        v = ((v + 2 ** 31) % 2 ** 32) - 2 ** 31 if base in ("int", "int32_t") else v
        return "(%s)%dLL" % (base, v)
    return "(%s)%dULL" % (base, v)


def build_differential(iface: Dict[str, Any], seed: int = 7) -> Dict[str, Any]:
    """The C driver source + bookkeeping. Calls orig_<f> and <f> with identical inputs and compares returns and output memory."""
    rnd = random.Random(seed)
    tmap = {t["name"]: t.get("target", "") for t in iface.get("types", []) if t["kind"] == "typedef"}
    enums = {t["name"] for t in iface.get("types", []) if t["kind"] == "enum"}
    pool = bytes(rnd.randrange(256) for _ in range(512))
    lines: List[str] = []
    comparable: List[str] = []
    skipped: List[Dict[str, str]] = []
    decls: List[str] = []
    ncases = 0
    for f in iface["functions"]:
        if f["kind"] != "function" or f["variadic"]:
            skipped.append({"function": f["name"], "why": "variadic" if f["variadic"] else f["kind"]})
            continue
        cls = [classify_param(p, tmap, enums) for p in f["params"]]
        bad = next((c for c in cls if c["kind"] == "other"), None)
        ret_norm = _resolve_base(f["ret"], tmap)
        ret_stars = f["ret"].count("*")
        ret_kind = "void" if ret_norm == "void" and not ret_stars else "ptr" if ret_stars else "int" if (ret_norm in _INT_BASES or ret_norm in enums) else \
            "float" if ret_norm in ("float", "double") else "other"
        if bad or ret_kind == "other":
            skipped.append({"function": f["name"], "why": (bad or {}).get("why", "return type %s" % ret_norm)})
            continue
        comparable.append(f["name"])
        decls.append("extern %s orig_%s(%s);" % (f["ret"] or "void", f["name"], ", ".join(p["text"] for p in f["params"]) or "void"))
        cases = min(MAX_CASES, 24 + 12 * len(f["params"]))
        for ci in range(cases):
            blk: List[str] = ["    { /* %s #%d */" % (f["name"], ci), "      static unsigned char ob[1024], nb[1024]; (void)ob; (void)nb;"]       # >= 4 bytes of output per input byte (len <= 150)
            blk.append("      memset(ob, 0xA5, sizeof ob); memset(nb, 0xA5, sizeof nb);")
            args_o: List[str] = []
            args_n: List[str] = []
            has_ob = False
            desc: List[str] = []
            pre: List[str] = []
            outs: List[str] = []
            for pi, (p, c) in enumerate(zip(f["params"], cls)):
                k = c["kind"]
                nxt = f["params"][pi + 1] if pi + 1 < len(f["params"]) else None
                prev_buf = pi > 0 and cls[pi - 1]["kind"] in ("inbuf", "outbuf")
                if k == "int":
                    is_len = bool(_LEN_NAMES.match(p["name"] or "")) and (prev_buf or (nxt is None and any(x["kind"] in ("inbuf", "outbuf", "cstr") for x in cls)))
                    v = rnd.choice(_LEN_POOL if is_len else _INT_POOL)
                    if is_len:
                        v = min(v, 150)
                    lit = _c_lit(v, c["base"], c["signed"])
                    args_o.append(lit)
                    args_n.append(lit)
                    desc.append("%s=%d" % (p["name"] or "p%d" % pi, v))
                elif k == "float":
                    v = rnd.choice([0.0, 1.5, -2.25, 1e10, 3.14159])
                    args_o.append("(%s)%r" % (c["base"], v))
                    args_n.append("(%s)%r" % (c["base"], v))
                    desc.append("%s=%r" % (p["name"] or "p%d" % pi, v))
                elif k == "cstr":
                    s = rnd.choice(_STR_POOL)
                    lit = '"%s"' % s.replace("\\", "\\\\").replace('"', '\\"').replace("\t", "\\t")
                    args_o.append(lit)
                    args_n.append(lit)
                    desc.append("%s=%s" % (p["name"] or "s", lit))
                elif k == "inbuf":
                    off = rnd.randrange(0, 300)
                    expr = "(%s)(pool + %d)" % ("const void *" if c["base"] == "void" else "const unsigned char *", off)
                    args_o.append(expr)
                    args_n.append(expr)
                    desc.append("%s=pool+%d" % (p["name"] or "buf", off))
                elif k == "outbuf":
                    args_o.append("(void *)ob" if c["base"] == "void" else "(%s *)ob" % ("char" if c["base"] == "char" else "unsigned char"))
                    args_n.append("(void *)nb" if c["base"] == "void" else "(%s *)nb" % ("char" if c["base"] == "char" else "unsigned char"))
                    outs.append("memcmp(ob, nb, sizeof ob)")
                    has_ob = True
                    desc.append("%s=outbuf" % (p["name"] or "out"))
                elif k in ("outscalar", "inscalar"):
                    init = rnd.choice([0, 1, 255, 65535])
                    pre.append("      %s so%d = %d, sn%d = %d;" % (c["base"], pi, init, pi, init))
                    args_o.append("&so%d" % pi)
                    args_n.append("&sn%d" % pi)
                    outs.append("(so%d != sn%d)" % (pi, pi))
                    desc.append("%s=&%d" % (p["name"] or "p%d" % pi, init))
            blk += pre
            call_o = "orig_%s(%s)" % (f["name"], ", ".join(args_o))
            call_n = "%s(%s)" % (f["name"], ", ".join(args_n))
            if ret_kind == "void":
                blk += ["      %s;" % call_o, "      %s;" % call_n]
                cond = " || ".join(outs) or "0"
                shown = ""
            elif ret_kind == "ptr":
                blk += ["      const void *ro = (const void *)%s;" % call_o, "      const void *rn = (const void *)%s;" % call_n]
                cond = " || ".join(["((ro == 0) != (rn == 0))"] + outs)
                shown = ', (unsigned long long)(ro != 0), (unsigned long long)(rn != 0)'
            elif ret_kind == "float":
                blk += ["      double ro = (double)%s;" % call_o, "      double rn = (double)%s;" % call_n]
                cond = " || ".join(["(ro != rn && !(ro != ro && rn != rn))"] + outs)
                shown = ", (unsigned long long)(long long)ro, (unsigned long long)(long long)rn"
            else:
                blk += ["      unsigned long long ro = (unsigned long long)%s;" % call_o, "      unsigned long long rn = (unsigned long long)%s;" % call_n]
                cond = " || ".join(["(ro != rn)"] + outs)
                shown = ", ro, rn"
            label = ("%s(%s)" % (f["name"], ", ".join(desc))).replace("%", "%%").replace("\\", "\\\\").replace('"', '\\"')
            diff_at = "int di = first_diff(ob, nb, 1024); unsigned ob_b = di >= 0 ? ob[di] : 0, nb_b = di >= 0 ? nb[di] : 0;" if has_ob else \
                "int di = -1; unsigned ob_b = 0, nb_b = 0;"
            tail_fmt = " out_diff_at=%d orig_byte=%u new_byte=%u"       # a C format fragment (substituted as a value, not re-formatted)
            if ret_kind == "void":
                blk.append('      total++; if (%s) { mism++; if (shown_%s < 4) { %s shown_%s++; printf("MISMATCH %s:%s\\n", di, ob_b, nb_b); } }' % (
                    cond, f["name"], diff_at, f["name"], label, tail_fmt))
            else:
                blk.append('      total++; if (%s) { mism++; if (shown_%s < 4) { %s shown_%s++; printf("MISMATCH %s: orig=%%llu new=%%llu%s\\n"%s, di, ob_b, nb_b); } }' % (
                    cond, f["name"], diff_at, f["name"], label, tail_fmt, shown))
            blk.append("    }")
            lines += blk
            ncases += 1
    # data the API publishes (lookup tables, constants): compared byte for byte, sized by the declared array bound
    compared_vars: List[str] = []
    for v in iface.get("variables", []):
        arr = (v.get("array") or "").strip()
        if arr and not re.fullmatch(r"\[\s*\d+\s*\]", arr):
            skipped.append({"function": v["name"], "why": "array bound is not a literal"})
            continue
        if re.search(r"\*|\bstruct\b|\bunion\b", v["type"]):
            skipped.append({"function": v["name"], "why": "pointer/struct variable"})
            continue
        decls.append("extern %s orig_%s%s;" % (v["type"], v["name"], arr))
        compared_vars.append(v["name"])
        lines.append('    { total++; if (memcmp(&orig_%s, &%s, sizeof(%s))) { mism++; printf("MISMATCH %s: the published data differs from the reference\\n"); } }' % (
            v["name"], v["name"], v["name"], v["name"]))
    comparable += compared_vars
    src = ["/* generated differential driver: original vs clean-room implementation, same inputs */",
           '#include "%s"' % ("%s_cr.h" % iface["module"]), "#include <stdio.h>", "#include <string.h>", "#include <stdlib.h>", ""]
    src += decls
    src.append("static const unsigned char pool[] = {%s};" % ",".join(str(b) for b in pool))
    src += ["static int total = 0, mism = 0;"] + ["static int shown_%s = 0;" % n for n in comparable]
    src += ["static int first_diff(const unsigned char *a, const unsigned char *b, int n) {",
            "    for (int i = 0; i < n; i++) if (a[i] != b[i]) return i;", "    return -1;", "}"]
    src += ["", "int main(void) {"] + lines + ['    printf("DIFF-SUMMARY functions=%d cases=%d total=%d mismatches=%d\\n", ' + str(len(comparable)) + ", " + str(ncases) + ", total, mism);",
                                              "    return mism ? 1 : 0;", "}", ""]
    return {"source": "\n".join(src), "comparable": comparable, "skipped": skipped, "cases": ncases}


def run_differential(tc: Dict[str, Optional[str]], iface: Dict[str, Any], orig_obj: str, new_src: str, header_path: str, work: str, header_name: str,
                     ) -> Dict[str, Any]:
    spec = build_differential(iface)
    if not spec["comparable"]:
        return {"ran": False, "reason": "no function is comparable by the generated driver (%s)" % "; ".join("%s: %s" % (s["function"], s["why"]) for s in spec["skipped"][:4]),
                "skipped": spec["skipped"]}
    drv = os.path.join(work, "diff_driver.c")
    with open(drv, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(spec["source"])
    exe = os.path.join(work, "diff_driver.exe" if os.name == "nt" else "diff_driver")
    r = _link_run(tc, [drv, new_src, orig_obj], exe, [work], [], "c", work)
    if not r.get("built"):
        return {"ran": False, "reason": "the differential driver did not link: %s" % r["err"][:300], "skipped": spec["skipped"]}
    m = re.search(r"DIFF-SUMMARY functions=(\d+) cases=(\d+) total=(\d+) mismatches=(\d+)", r["out"])
    mism = [ln for ln in r["out"].splitlines() if ln.startswith("MISMATCH")]
    if not m or r.get("rc") not in (0, 1):                         # no summary / a signal / a runtime abort: the NEW code crashed the driver
        return {"ran": True, "ok": False, "crashed": True, "functions": len(spec["comparable"]), "compared": spec["comparable"], "skipped": spec["skipped"],
                "total_cases": 0, "mismatches": None, "examples": ["CRASH: the differential driver exited abnormally (rc=%s): %s" % (r.get("rc"), r["out"][-200:].strip())],
                "tail": r["out"][-600:], "timeout": r.get("timeout", False)}
    return {"ran": True, "ok": bool(m) and int(m.group(4)) == 0 and r.get("rc") == 0, "functions": len(spec["comparable"]), "compared": spec["comparable"],
            "skipped": spec["skipped"], "total_cases": int(m.group(3)) if m else 0, "mismatches": int(m.group(4)) if m else None,
            "examples": mism[:8], "tail": r["out"][-600:], "timeout": r.get("timeout", False)}


# ============================================================================================ upstream tests as the oracle
def discover_adopted_c(source_root: str, iface: Dict[str, Any], cap: int = 12) -> List[str]:
    fnames = {f["name"] for f in iface["functions"]}
    found: List[str] = []
    for dp, dns, fns in os.walk(source_root):
        dns[:] = [d for d in dns if d not in (".git", "build", "node_modules") and not d.startswith(".")]
        depth = os.path.relpath(dp, source_root).count(os.sep)
        if depth > 4:
            dns[:] = []
        for fn in fns:
            low = fn.lower()
            if not low.endswith(cparse.C_EXT + cparse.CPP_EXT) or not ("test" in low or low.startswith("check")):
                continue
            fp = os.path.join(dp, fn)
            try:
                txt = open(fp, "r", encoding="utf-8", errors="replace").read()
            except OSError:
                continue
            if re.search(r"\bmain\s*\(", txt) and (_words(txt) & fnames):
                found.append(fp)
                if len(found) >= cap:
                    return found
    return found


def run_adopted_c(tc: Dict[str, Optional[str]], tests: List[str], new_src: str, include_dirs: List[str], work: str) -> Dict[str, Any]:
    ran, ok, skipped, tails = 0, 0, [], []
    for t in tests:
        exe = os.path.join(work, "adopted_%d.exe" % ran if os.name == "nt" else "adopted_%d" % ran)
        r = _link_run(tc, [t, new_src], exe, [work, os.path.dirname(t)] + include_dirs, [], _lang_of(t), work)
        if not r.get("built"):
            skipped.append({"file": os.path.basename(t), "why": r["err"][:160]})
            continue
        ran += 1
        ok += 1 if r["ok"] else 0
        tails.append("%s -> %s" % (os.path.basename(t), "OK" if r["ok"] else "FAILED") + ("" if r["ok"] else "\n" + r["out"][-300:]))
    return {"ran": ran, "passed": ok, "ok": ran > 0 and ok == ran, "skipped": skipped, "tail": "\n".join(tails)[-1200:]}


# ============================================================================================ orchestrator
def _emit(progress: Optional[Callable[[Dict[str, Any]], None]], event: str, **fields: Any) -> None:
    if progress:
        try:
            progress({"event": event, "ts": datetime.datetime.now().astimezone().isoformat(timespec="seconds"), **fields})
        except Exception:                                          # noqa: BLE001 - telemetry never kills the lane
            pass


def _write(path: str, text: str) -> None:
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def run(source_root: str, component: str, out_dir: str, *, client: Any = None, why: str = "", copy_threshold: float = TOKEN_THRESHOLD,
        publish_dest: Optional[str] = None, allow_inplace: bool = False, attempts: int = 2, pattern_pack: Optional[Dict[str, Any]] = None,
        patterns_provider: Optional[Callable[[Dict[str, Any]], Dict[str, Any]]] = None, progress: Optional[Callable[[Dict[str, Any]], None]] = None,
        base: Optional[Dict[str, Any]] = None, toolchain_override: Optional[Dict[str, Optional[str]]] = None) -> Dict[str, Any]:
    """The whole C/C++ lane; returns the same verdict-record shape as the Python lane (+ language/toolchain/compile/export/oracle)."""
    from . import reimpl
    res: Dict[str, Any] = dict(base or {"schema": SCHEMA, "tool": "bts-sbom-app reimpl", "version": __version__, "source": os.path.abspath(source_root),
                                        "component": component, "started": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
                                        "copy_threshold": copy_threshold, "stages": []})
    res.update(language="c++" if _lang_of(component) == "c++" else "c", copy_threshold=copy_threshold)
    tc = toolchain_override or toolchain()
    res["toolchain"] = {k: (os.path.basename(v) if v else None) for k, v in tc.items()}
    os.makedirs(out_dir, exist_ok=True)
    src_path = os.path.join(source_root, component)
    module = os.path.splitext(os.path.basename(component))[0]
    why = why or "compliance-risky license (clean-room reimplementation)"

    iface = extract_interface_c(source_root, component)
    res["interface"] = {"functions": [f["name"] for f in iface["functions"]], "classes": [t["name"] for t in iface["types"] if t["kind"] in ("class", "struct")],
                        "imports": iface["imports"], "variables": [v["name"] for v in iface["variables"]], "paired_headers": iface["paired_headers"],
                        "types": len(iface["types"]), "macros": len(iface["macros"])}
    if not iface["functions"] and not iface["variables"]:
        res.update(verdict="refused", reason="no external function or variable was found in %s (nothing to reimplement)" % component)
        _emit(progress, "refused", reason=res["reason"])
        return res
    _emit(progress, "interface_ready", functions=[f["name"] for f in iface["functions"]], classes=res["interface"]["classes"])

    header_name = "%s_cr.h" % module
    header_text = render_header(iface)
    pack: Optional[Dict[str, Any]] = pattern_pack
    if pack is None and patterns_provider is not None:
        try:
            pack = patterns_provider(dict(iface, functions=[dict(f, docstring=f["doc"]) for f in iface["functions"]], classes=[]))
        except Exception as exc:                                    # noqa: BLE001 - inference failure degrades honestly
            res["pattern_error"] = str(exc)[:160]
    spec = spec_document_c(iface, why, header_name)
    if isinstance(pack, dict) and pack.get("patterns"):
        res["patterns"] = {"tier": pack.get("tier"), "patterns": [{"name": p.get("name"), "ref": p.get("ref")} for p in pack["patterns"]]}
        _emit(progress, "patterns_ready", tier=pack.get("tier"), count=len(pack["patterns"]))
        section = reimpl.patterns_section(pack)
        if section:
            spec = spec + "\n\n" + section
    dgml = arch_map.to_dgml("Reimplementation of %s" % component, sorted({module, *iface["imports"]}), [(module, d) for d in iface["imports"]])
    spec_path, dgml_path, hdr_path = (os.path.join(out_dir, n) for n in ("spec.md", "dependencies.dgml", header_name))
    _write(spec_path, spec)
    _write(dgml_path, dgml)
    _write(hdr_path, header_text)
    res["artifacts"] = {"spec": spec_path, "dgml": dgml_path, "header": hdr_path}
    _emit(progress, "spec_ready", spec=spec_path)
    _emit(progress, "diagram_ready", dgml=dgml_path)

    work = os.path.join(out_dir, "work")
    os.makedirs(work, exist_ok=True)
    _write(os.path.join(work, header_name), header_text)
    ext = ".cpp" if res["language"] == "c++" else ".c"
    code_path = os.path.join(out_dir, module + ext)
    original_src = open(src_path, "r", encoding="utf-8", errors="replace").read()
    test_src = gen_contract_test_c(iface, header_name)
    idx = _index_headers(source_root)
    verdict: Optional[str] = None
    prior_fail: Optional[str] = None
    attempt = 0
    orig: Optional[Dict[str, Any]] = None                           # the original, built once (it does not change between attempts)
    while True:
        attempt += 1
        res.pop("verdict", None)                                    # a retry starts clean: only the LAST attempt's verdict stands
        res.pop("reason", None)
        code, generated_by = "", "scaffold"
        if client is not None:
            try:
                code = llm_generate_c(spec, client, res["language"], prior_fail=prior_fail)
                generated_by = "llm"
            except Exception as exc:                                # noqa: BLE001 - degrade honestly to the scaffold
                res["llm_error"] = str(exc)[:160]
        if generated_by == "scaffold":
            code = scaffold_c(iface, header_name)
        _write(code_path, code)
        res.update(generated_by=generated_by, attempts=attempt)
        res["artifacts"]["code"] = code_path
        _emit(progress, "code_ready", by=generated_by, path=code_path, attempt=attempt)

        gate = copy_gate(code, original_src, copy_threshold, ignore_lines={f["proto"] for f in iface["functions"]})
        res["copy_gate"] = gate
        _emit(progress, "copy_gate", overlap=gate["overlap"], passed=gate["passed"])
        if not gate["passed"]:
            res.update(verdict="rejected", reason="copy gate failed: token overlap %.3f (limit %.2f), line overlap %.3f (limit %.2f)%s" % (
                gate["token_overlap"], copy_threshold, gate["line_overlap"], LINE_THRESHOLD, " and/or license strings present" if gate["license_strings"] else ""))
            _emit(progress, "copy_gate_failed", overlap=gate["overlap"])
            break

        # stage E: compile + export + linkage test
        shutil.copyfile(code_path, os.path.join(work, module + ext))
        _write(os.path.join(work, "test_%s.c" % module), test_src)
        _emit(progress, "tests_running", module=module)
        obj = os.path.join(work, module + ".o")
        cr = compile_object(tc, os.path.join(work, module + ext), obj, [work], [])
        res["compile"] = {k: cr.get(k) for k in ("ok", "warnings", "errors", "cmd")}
        if cr.get("toolchain_missing"):
            res.update(verdict="toolchain_missing", reason=cr["err"] + " - install gcc/clang to compile and verify the generated code")
            _emit(progress, "tests_failed", tail=cr["err"][:200])
            break
        if not cr["ok"]:
            res.update(verdict="tests_failed", reason="the generated code does not compile")
            _emit(progress, "tests_failed", tail=cr["errors"][:200])
            if client is not None and attempt < max(1, attempts):
                prior_fail = "compiler errors:\n" + cr["errors"][:900]
                continue
            break
        ex = export_check(exported_symbols(tc, obj, res["language"] == "c++"), iface)
        res["export"] = ex
        lk = None
        if res["language"] == "c" and not ex.get("missing"):
            exe = os.path.join(work, "test_%s.exe" % module if os.name == "nt" else "test_%s" % module)
            lk = _link_run(tc, [os.path.join(work, "test_%s.c" % module), os.path.join(work, module + ext)], exe, [work], [], "c", work)
            res["tests"] = {"ok": lk.get("ok", False), "tail": (lk.get("out") or lk.get("err") or "")[-300:]}
        else:
            res["tests"] = {"ok": not ex.get("missing"), "tail": "missing exports: %s" % ", ".join(ex.get("missing") or []) if ex.get("missing") else "compile-only (C++)"}
        ok_contract = ex.get("ok", True) and res["tests"]["ok"]
        _emit(progress, "tests_passed" if ok_contract else "tests_failed", tail=res["tests"]["tail"][:200])
        if not ok_contract:
            res.update(verdict="tests_failed", reason="the generated module does not export its API (missing: %s)" % ", ".join(ex.get("missing") or ["link failure"]))
            if client is not None and attempt < max(1, attempts):
                prior_fail = "the build exports a different symbol set; required API symbols missing: %s" % ", ".join(ex.get("missing") or [])
                continue
            break

        # stage E2: the oracle - upstream tests first, then the differential driver against the ORIGINAL built here
        oracle: Dict[str, Any] = {}
        res["oracle"] = oracle
        adopted = discover_adopted_c(source_root, iface)
        inc_for_tests = [os.path.join(source_root, d) for d in ("include", "inc", "src")] + [os.path.dirname(src_path)]
        if adopted:
            _emit(progress, "adopted_tests_running", files=len(adopted))
            ar = run_adopted_c(tc, adopted, os.path.join(work, module + ext), [d for d in inc_for_tests if os.path.isdir(d)], work)
            oracle["adopted"] = ar
            res["adopted_tests"] = {"files": [os.path.basename(x) for x in adopted], "ok": ar["ok"], "tail": ar["tail"]}
        if res["language"] == "c" and iface["functions"]:
            if orig is None:
                orig = compile_original(tc, source_root, component, iface, header_text, work, idx)
            oracle["original_build"] = {k: orig.get(k) for k in ("ok", "mode", "attempts", "reason", "log")}
            if orig.get("ok"):
                _emit(progress, "adopted_tests_running", files=len(adopted))
                dr = run_differential(tc, iface, orig["obj"], os.path.join(work, module + ext), hdr_path, work, header_name)
                oracle["differential"] = dr
            else:
                # carry the compiler's own words into the differential record: the verdict reason
                # interpolates dr["reason"] and the tail-join reads dr["log"] - dropping them here is
                # how the generic "could not be compiled standalone" hid the real cause (measured on CI)
                oracle["differential"] = {"ran": False, "reason": orig.get("reason", "original not built"),
                                          "log": orig.get("log") or ([orig.get("err")] if orig.get("err") else [])}
        ad_ran = bool(oracle.get("adopted", {}).get("ran"))
        ad_ok = oracle.get("adopted", {}).get("ok")
        dr = oracle.get("differential") or {}
        dr_ran = bool(dr.get("ran"))
        dr_ok = dr.get("ok")
        failing = (ad_ran and not ad_ok) or (dr_ran and not dr_ok)
        if failing:
            tail = ((oracle.get("adopted") or {}).get("tail", "") if (ad_ran and not ad_ok) else "") + "\n".join(dr.get("examples") or [])
            _emit(progress, "adopted_tests_failed", tail=tail[:200])
            res["adopted_tests"] = dict(res.get("adopted_tests") or {}, ok=False, tail=tail[-600:])
            res.update(verdict="compatibility_failed", reason="the oracle found behavioural differences against the original (%s)" % (
                "%d of %d sampled cases differ" % (dr.get("mismatches") or 0, dr.get("total_cases") or 0) if dr_ran and not dr_ok else "upstream tests failed"))
            if client is not None and attempt < max(1, attempts):
                prior_fail = ("differences between the reference and your code, as (call -> reference result vs yours):\n" + "\n".join(dr.get("examples") or [])) if dr_ran and not dr_ok \
                    else "upstream tests failed:\n" + tail[-700:]
                _emit(progress, "regenerating", failed=dr.get("mismatches") or 1)
                continue
            break
        if ad_ran or dr_ran:
            _emit(progress, "adopted_tests_passed", tail=("differential: %s functions, %s cases" % (dr.get("functions"), dr.get("total_cases"))) if dr_ran else "upstream tests passed")
            res["adopted_tests"] = dict(res.get("adopted_tests") or {}, ok=True, tail=("differential: %s functions, %s cases, 0 mismatches" % (dr.get("functions"), dr.get("total_cases"))) if dr_ran else
                                        (res.get("adopted_tests") or {}).get("tail", ""))
            verdict = "ok"
        else:
            verdict = "contract_only"
            reason = (dr.get("reason") or "no upstream tests and no differential") if dr else "no upstream tests"
            logtail = " / ".join([x for x in (dr.get("log") or []) if x][-2:])   # the compiler's own words: WHY standalone failed
            if logtail:
                reason += " | compile tail: " + logtail
            res["reason"] = "compiled and exports its API, but no oracle was available (%s) - behaviour is NOT verified" % reason
        break

    if verdict == "ok" and publish_dest:
        dest = os.path.abspath(publish_dest)
        if os.path.abspath(source_root) == dest and not allow_inplace:
            res.update(verdict="publish_refused", reason="inplace publish needs allow_inplace=True")
            _emit(progress, "publish_refused", reason=res["reason"])
            return res
        os.makedirs(dest, exist_ok=True)
        for fn in (module + ext, header_name, "test_%s.c" % module):
            src = os.path.join(work, fn) if os.path.exists(os.path.join(work, fn)) else os.path.join(out_dir, fn)
            if os.path.exists(src):
                shutil.copyfile(src, os.path.join(dest, fn))
        res["published_to"] = dest
        _emit(progress, "published", dest=dest)
    if not res.get("verdict"):
        res["verdict"] = verdict or "error"
    res["honesty"] = HONESTY
    return res
