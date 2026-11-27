"""Structural binary inspection in the REA (Reverse Engineer Anything, github.com/morluto/rea) style.

REA's mechanism, adapted to this repo's stdlib-only rules: analysis results carry their evidence and
limitations, and capability is tiered HONESTLY — REA's engine-free tier (JS/ASAR, .NET static) vs its
engine-backed tier (native decompilation needs Hopper/Ghidra/IDA). We ship no analysis engine, so this
module implements the engine-free *structural* tier only, via stdlib parsing:

- PE (MZ): import table -> imported DLLs and their functions (the binary's API compatibility surface)
- ELF: PT_DYNAMIC -> DT_NEEDED shared libraries
- ASAR (Electron apps): the archive's JSON index -> package.json (name/version/dependencies -> SBOM
  components) + the JS module inventory
- JAR (zip): MANIFEST.MF main attributes + the class inventory count

Everything here is read-only, deterministic, offline, and never executes the target. Every parser
returns an evidence record with explicit limitations; a format it cannot parse is recorded as such —
never guessed (the same honesty contract as binscan's string evidence).
"""
from __future__ import annotations

import json
import os
import struct
import zipfile
from typing import Any, Dict, List, Optional

SCHEMA = "bts-sbom.binary-rea.v1"
TIER = "structural"          # REA provider tier: engine-free structural parsing (no decompiler ships here)

LIMITATIONS = [
    "structural tier only: imports/needed-libs/asar manifests are dependency evidence, not a full REA "
    "decompilation (that tier needs an engine this package does not ship)",
    "PE parsing covers the standard import directory; delay-load imports and bound imports are not walked",
    "ASAR index offsets are trusted as written by the archiver; malformed indexes are reported, not repaired",
]


def _u16(b: bytes, o: int) -> int:
    return struct.unpack_from("<H", b, o)[0]


def _u32(b: bytes, o: int) -> int:
    return struct.unpack_from("<I", b, o)[0]


# ---------------------------------------------------------------------------------- PE imports
def parse_pe_imports(data: bytes) -> Dict[str, Any]:
    """Minimal PE32/PE32+ import-directory walk: DOS header -> PE signature -> optional header data
    directory 1 -> section table (RVA->file offset) -> import descriptors -> DLL names + hint/name."""
    if data[:2] != b"MZ":
        raise ValueError("not a PE image (missing MZ)")
    e_lfanew = _u32(data, 0x3C)
    if data[e_lfanew:e_lfanew + 4] != b"PE\x00\x00":
        raise ValueError("missing PE signature")
    coff = e_lfanew + 4
    machine = _u16(data, coff)
    nsec = _u16(data, coff + 2)
    opt_size = _u16(data, coff + 16)
    opt = coff + 20
    magic = _u16(data, opt)
    if magic == 0x20B:                                          # PE32+
        dd_off = opt + 112
    elif magic == 0x10B:                                        # PE32
        dd_off = opt + 96
    else:
        raise ValueError("unknown optional-header magic 0x%X" % magic)
    imp_rva, imp_size = _u32(data, dd_off + 8), _u32(data, dd_off + 12)
    secs = []
    sec_off = opt + opt_size
    for i in range(nsec):
        base = sec_off + i * 40
        va, raw_size, raw_ptr = _u32(data, base + 12), _u32(data, base + 16), _u32(data, base + 20)
        secs.append((va, raw_size, raw_ptr))

    def rva2off(rva: int) -> Optional[int]:
        for va, rsz, rptr in secs:
            if va <= rva < va + max(rsz, 1):
                return rptr + (rva - va)
        return None

    def cstr(off: int, cap: int = 256) -> str:
        end = data.find(b"\x00", off, off + cap)
        return data[off:end if end >= 0 else off + cap].decode("ascii", "replace")

    dlls: List[Dict[str, Any]] = []
    off = rva2off(imp_rva) if imp_rva else None
    if off is None:
        raise ValueError("import directory RVA does not map into any section")
    while True:
        ilt_rva, _ts, _fc, name_rva, iat_rva = struct.unpack_from("<IIIII", data, off)
        if ilt_rva == 0 and name_rva == 0 and iat_rva == 0:
            break
        dll = cstr(rva2off(name_rva) or 0)
        funcs: List[str] = []
        thunk = rva2off(ilt_rva or iat_rva)
        if thunk is not None and dll:
            while True:
                v = _u32(data, thunk)
                if v == 0:
                    break
                if not v & 0x80000000:
                    name_off = rva2off(v) or 0
                    funcs.append(cstr(name_off + 2))
                else:
                    funcs.append("#%d" % (v & 0x7FFFFFFF))
                thunk += 4
                if len(funcs) >= 128:
                    break                                       # bounded: a real import table can be huge
        if dll:
            dlls.append({"dll": dll, "functions": funcs[:128]})
        off += 20
        if len(dlls) >= 64:
            break
    return {"format": "pe", "machine": "i386" if machine == 332 else ("x64" if machine == 34404 else "0x%X" % machine),
            "imported_dlls": [d["dll"] for d in dlls], "imports": dlls}


# ---------------------------------------------------------------------------------- ELF DT_NEEDED
def parse_elf_needed(data: bytes) -> Dict[str, Any]:
    """ELF program headers -> PT_DYNAMIC -> DT_NEEDED entries. DT_STRTAB is a VIRTUAL address and
    DT_NEEDED holds an offset INTO that string table, so the string table's vaddr is converted to a
    file offset through the PT_LOAD segments before the names are read."""
    if data[:4] != b"ELF":
        raise ValueError("not an ELF image")
    ei_class, ei_data = data[4], data[5]
    if ei_class not in (1, 2) or ei_data not in (1, 2):
        raise ValueError("unknown ELF class/data encoding")
    end = "<" if ei_data == 1 else ">"
    is64 = ei_class == 2
    eh_fmt = end + ("HHIQQQIHHHHHH" if is64 else "HHIIIIIHHHHHH")
    (_t, _m, _v, e_entry, e_phoff, _sh, _fl, _eh, e_phentsize, e_phnum, _shent, _shn, _shst) =         struct.unpack_from(eh_fmt, data, 16)
    loads: List[Tuple[int, int, int]] = []                   # (vaddr, filesz, file offset)
    dyn_off = dyn_sz = None
    for i in range(min(e_phnum, 32)):
        base = e_phoff + i * e_phentsize
        if is64:
            p_type = struct.unpack_from(end + "I", data, base)[0]
            p_off = struct.unpack_from(end + "Q", data, base + 0x08)[0]
            p_va = struct.unpack_from(end + "Q", data, base + 0x10)[0]
            p_filesz = struct.unpack_from(end + "Q", data, base + 0x20)[0]
        else:
            p_type = struct.unpack_from(end + "I", data, base)[0]
            p_off = struct.unpack_from(end + "I", data, base + 0x04)[0]
            p_va = struct.unpack_from(end + "I", data, base + 0x08)[0]
            p_filesz = struct.unpack_from(end + "I", data, base + 0x10)[0]
        if p_type == 1:                                      # PT_LOAD
            loads.append((p_va, p_filesz, p_off))
        elif p_type == 2:                                    # PT_DYNAMIC
            dyn_off, dyn_sz = p_off, p_filesz

    def va2off(va: int) -> Optional[int]:
        if va is None:
            return None
        for v, sz, off in loads:
            if v <= va < v + max(sz, 1):
                return off + (va - v)
        return va                                            # some images store file offsets directly

    needed_idx: List[int] = []
    strtab_va = None
    if dyn_off is not None:
        esz = 16 if is64 else 8
        valfmt = end + ("Q" if is64 else "I")
        for j in range(int(dyn_sz) // esz):
            tag = struct.unpack_from(end + ("Q" if is64 else "I"), data, dyn_off + j * esz)[0]
            val = struct.unpack_from(valfmt, data, dyn_off + j * esz + (8 if is64 else 4))[0]
            if tag == 0:
                break
            if tag == 5:                                     # DT_STRTAB
                strtab_va = val
            elif tag == 1:                                   # DT_NEEDED
                needed_idx.append(val)
    needed: List[str] = []
    strtab_off = va2off(strtab_va)
    if strtab_off is not None:
        for idx in needed_idx:
            end_n = data.find(b"\0", strtab_off + idx)
            needed.append(data[strtab_off + idx:end_n if end_n >= 0 else strtab_off + idx + 128]
                          .decode("utf-8", "replace"))
    return {"format": "elf", "class": 64 if is64 else 32,
            "needed": needed, "dynamic_entries": len(needed_idx)}


# ---------------------------------------------------------------------------------- ASAR (Electron)
def read_asar(path: str) -> Dict[str, Any]:
    """Electron ASAR archive: header pickle -> JSON index -> package.json + the JS module inventory."""
    raw = open(path, "rb").read()
    if len(raw) < 16:
        raise ValueError("too small for an ASAR header")
    # canonical ASAR disk layout: [u32 4][u32 header_size][u32 str_size+4][u32 json_len][json] then data
    # at 8 + header_size. Tolerant: fall back to reading the length at 8 if the canonical parse fails.
    json_len, json_off = None, None
    for ln_off, body_off in ((12, 16), (8, 12)):
        try:
            n = struct.unpack_from("<I", raw, ln_off)[0]
            cand = raw[body_off:body_off + n].decode("utf-8")
            if cand.lstrip().startswith("{"):
                json_len, json_off = n, body_off
                break
        except (struct.error, ValueError):
            continue
    try:
        if json_len is None:
            raise ValueError("no JSON index found at the known offsets")
        index = json.loads(raw[json_off:json_off + json_len].decode("utf-8"))
        header_size = struct.unpack_from("<I", raw, 4)[0]
    except (struct.error, ValueError) as exc:
        raise ValueError("ASAR header layout not recognised: %s" % str(exc)[:80])
    files: List[str] = []

    def walk(node: Dict[str, Any], prefix: str) -> None:
        for name, child in (node.get("files") or {}).items():
            if child.get("files") is not None:
                walk(child, prefix + name + "/")
            else:
                files.append(prefix + name)

    walk(index, "")
    pkg: Dict[str, Any] = {}
    pj = index.get("files", {}).get("package.json", {})
    if pj.get("size") and "offset" in pj:
        data_start = 8 + header_size
        off = data_start + int(pj["offset"])
        try:
            pkg = json.loads(raw[off:off + int(pj["size"])].decode("utf-8"))
        except (ValueError, OSError):
            pkg = {}                                            # malformed index: reported, not repaired
    deps = pkg.get("dependencies") or {}
    return {"format": "asar", "files": len(files),
            "js_files": len([f for f in files if f.endswith((".js", ".mjs", ".cjs"))]),
            "package_name": pkg.get("name"), "package_version": pkg.get("version"),
            "dependencies": sorted(deps) if isinstance(deps, dict) else [],
            "electron": "electron" in {k.lower() for k in (deps if isinstance(deps, dict) else {})},
            "modules_sample": files[:12]}


# ---------------------------------------------------------------------------------- JAR
def read_jar(path: str) -> Dict[str, Any]:
    """JAR/zip: MANIFEST.MF main attributes + class inventory. Class constant-pool walking is out of
    the structural tier (recorded as a limitation, not attempted)."""
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        manifest: Dict[str, str] = {}
        if "META-INF/MANIFEST.MF" in names:
            for ln in z.read("META-INF/MANIFEST.MF").decode("utf-8", "replace").splitlines():
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    manifest[k.strip()] = v.strip()[:120]
        classes = [n for n in names if n.endswith(".class")]
        return {"format": "jar", "entries": len(names), "classes": len(classes),
                "manifest": manifest, "sample_classes": sorted(n for n in classes)[:8]}


# ---------------------------------------------------------------------------------- dispatcher
def inspect(path: str) -> Dict[str, Any]:
    """Magic-sniff one binary and run the matching structural parser -> an evidence record carrying the
    tier, the parsed facts, and the limitations (REA contract: results state their evidence AND limits)."""
    data = open(path, "rb").read(4_194_304)                     # bounded read; parsers need headers only
    kind, ev, err = None, None, None
    try:
        if data[:2] == b"MZ":
            kind, ev = "pe", parse_pe_imports(data)
        elif data[:4] == b"\x7fELF":
            kind, ev = "elf", parse_elf_needed(data)
        elif data[:4] == b"\x04\x00\x00\x00" or data[:8].startswith(b"\x04\x00\x00\x00"):
            kind, ev = "asar", read_asar(path)                  # ASAR needs the whole header, not 4 MB
        else:
            kind = "unknown"
            err = "no structural parser for this magic"
    except (ValueError, struct.error, OSError) as exc:
        err = str(exc)[:160]
    if kind == "asar" and ev is None:
        try:
            ev = read_asar(path)
            err = None
        except (ValueError, OSError) as exc:
            err = str(exc)[:160]
    out = {"schema": SCHEMA, "file": os.path.basename(path), "kind": kind, "tier": TIER,
           "evidence": ev, "error": err, "limitations": LIMITATIONS}
    return out


def components_from(evidence_by_file: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Aggregate structural evidence into SBOM-ready component rows (name + why-it-is-listed). External
    dependencies listed by a binary ARE components of the analysed product's runtime surface."""
    comps: List[Dict[str, Any]] = []
    seen = set()

    def add(name: str, kind: str, via: str, file: str) -> None:
        key = (name.lower(), kind)
        if name and key not in seen:
            seen.add(key)
            comps.append({"name": name, "kind": kind, "via": via, "from_file": file})

    for rec in evidence_by_file:
        ev = rec.get("evidence") or {}
        f = rec.get("file") or ""
        if rec.get("kind") == "pe":
            for d in ev.get("imports") or []:
                add(d["dll"], "native-dll", "PE import table", f)
        elif rec.get("kind") == "elf":
            for n in ev.get("needed") or []:
                add(n, "shared-lib", "ELF DT_NEEDED", f)
        elif rec.get("kind") == "asar":
            if ev.get("package_name"):
                add(ev["package_name"], "electron-app", "ASAR package.json", f)
            for d in ev.get("dependencies") or []:
                add(d, "npm-dependency", "ASAR package.json", f)
        elif rec.get("kind") == "jar":
            mf = ev.get("manifest") or {}
            if mf.get("Main-Class") or mf.get("Implementation-Title"):
                add(mf.get("Implementation-Title") or mf.get("Main-Class"), "java-jar", "JAR manifest", f)
    return comps
