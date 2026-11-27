"""Structural binary inspection (REA-style engine-free tier): PE imports, ELF DT_NEEDED, ASAR, JAR —
synthetic fixtures built byte-by-byte so the parsers are proven against known layouts."""
from __future__ import annotations

import json
import os
import struct
import zipfile

from bts_sbom_app import binary_rea, binscan


def _u32(v):
    return struct.pack("<I", v)


def _build_pe(dlls):
    """PE32, one section (raw 0x200 <-> VA 0x1000). Two-pass layout: hint/name strings first (each thunk
    RVA points at the 2-byte hint; the parser reads the name at +2), then the descriptor table."""
    DESC = 0x1000
    desc_size = (len(dlls) + 1) * 20
    STR = DESC + desc_size
    str_blob = bytearray()
    name_rvas, thunk_lists = [], []
    for dll, funcs in dlls:
        name_rvas.append(STR + len(str_blob))
        str_blob += dll.encode("ascii") + b"\0\x00"           # the DLL name itself
        frvas = []
        for f in funcs:
            frvas.append(STR + len(str_blob))          # hint RVA; the name sits at +2
            str_blob += struct.pack("<H", 0) + f.encode("ascii") + b"\x00"
        thunk_lists.append(frvas)
    THUNK = STR + len(str_blob)
    thunk_blob = bytearray()
    thunk_starts = []
    for rvas in thunk_lists:
        thunk_starts.append(THUNK + len(thunk_blob))
        for r in rvas:
            thunk_blob += _u32(r)
        thunk_blob += _u32(0)
    desc_blob = bytearray()
    for n_rva, t in zip(name_rvas, thunk_starts):
        desc_blob += _u32(t) + _u32(0) + _u32(0) + _u32(n_rva) + _u32(t)
    desc_blob += b"\x00" * 20
    body = bytes(desc_blob) + bytes(str_blob) + bytes(thunk_blob)
    dos = bytearray(0x40)
    dos[:2] = b"MZ"
    struct.pack_into("<I", dos, 0x3C, 0x40)
    pe = bytearray(b"PE\x00\x00")
    pe += struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x2102)          # COFF: i386, 1 section
    pe += struct.pack("<H", 0x10B)                                          # PE32 optional magic
    pe += b"\x00" * 94                                                      # optional fields (only DD walked)
    dd = bytearray(16 * 8)
    struct.pack_into("<II", dd, 1 * 8, 0x1000, len(body))                   # import dir RVA/size
    pe += dd
    sec = bytearray(40)
    sec[0:8] = b".text\x00\x00\x00"
    struct.pack_into("<IIII", sec, 8, 0x200, 0x1000, 0x200, 0x200)          # vsize, va, rawsize, rawptr
    pe += sec
    blob = bytes(dos) + bytes(pe) + b"\x00" * (0x200 - len(dos) - len(pe)) + body
    return bytes(blob)


def _build_elf():
    """ELF64 LE: header(64B) + 1 PT_DYNAMIC program header(56B) + strtab + dynamic table.
    DT_STRTAB points at the string table vaddr; DT_NEEDED values are offsets INTO it."""
    strtab_off = 64 + 56
    strtab = b"libfoo.so.1\x00libbar.so.2\x00"
    dyn_off = strtab_off + len(strtab)
    dyn = struct.pack("<QQ", 5, strtab_off)                    # DT_STRTAB (vaddr == file offset here)
    dyn += struct.pack("<QQ", 1, 0)                            # DT_NEEDED -> strtab offset 0
    dyn += struct.pack("<QQ", 1, len(b"libfoo.so.1\x00"))      # DT_NEEDED -> strtab offset 12
    dyn += struct.pack("<QQ", 10, len(strtab))                 # DT_STRSZ
    dyn += struct.pack("<QQ", 0, 0)                            # DT_NULL
    eh = bytearray(64)
    eh[0:4] = b"\x7fELF"
    eh[4], eh[5] = 2, 1                                        # 64-bit, little-endian
    struct.pack_into("<H", eh, 0x36, 56)                       # e_phentsize
    struct.pack_into("<H", eh, 0x38, 1)                        # e_phnum
    struct.pack_into("<Q", eh, 0x20, 64)                       # e_phoff
    ph = struct.pack("<IIQQQQQQ", 2, 4, dyn_off, dyn_off, dyn_off, len(dyn), len(dyn), 8)  # PT_DYNAMIC
    return bytes(eh) + ph + strtab + dyn


def _build_asar(pkg):
    index = {"files": {
        "package.json": {"size": 0, "offset": "0"},
        "app": {"files": {"main.js": {"size": 10, "offset": "0"}, "ui.js": {"size": 5, "offset": "5"}}},
    }}
    pkg_b = json.dumps(pkg).encode()
    index["files"]["package.json"]["size"] = len(pkg_b)
    json_b = json.dumps(index).encode()
    header_size = 8 + len(json_b)                              # framing(8) + json, per the canonical layout
    hdr = _u32(4) + _u32(header_size) + _u32(len(json_b) + 4) + _u32(len(json_b)) + json_b
    return bytes(hdr) + pkg_b + b"\x00" * 32, index


def test_pe_imports_parse_synthetic_and_real_bootstrapper():
    """AC: BSA-AC-621"""
    pe = _build_pe([("FOO.dll", ["FnOne", "FnTwo"]), ("BAR.DLL", ["BarFn"])])
    r = binary_rea.parse_pe_imports(pe)
    assert r["format"] == "pe" and r["machine"] == "i386"
    assert r["imported_dlls"] == ["FOO.dll", "BAR.DLL"]
    assert r["imports"][0]["functions"] == ["FnOne", "FnTwo"]
    boot = "downloads/vs2026/vs_Enterprise_ltsc.exe"
    if os.path.exists(boot):
        real = binary_rea.parse_pe_imports(open(boot, "rb").read(4_194_304))
        assert "KERNEL32.DLL" in [d.upper() for d in real["imported_dlls"]]   # the real Microsoft binary


def test_elf_needed_parse_synthetic():
    """AC: BSA-AC-621"""
    r = binary_rea.parse_elf_needed(_build_elf())
    assert r["format"] == "elf" and r["class"] == 64
    assert r["needed"] == ["libfoo.so.1", "libbar.so.2"]


def test_asar_read_and_component_extraction(tmp_path):
    """AC: BSA-AC-622"""
    out = tmp_path / "app.asar"
    out.write_bytes(_build_asar({"name": "legacy-electron-app", "version": "1.2.3",
                                 "dependencies": {"electron": "13.0.0", "left-pad": "1.0.0"}})[0])
    r = binary_rea.read_asar(str(out))
    assert r["format"] == "asar" and r["files"] == 3 and r["js_files"] == 2
    assert r["package_name"] == "legacy-electron-app" and r["electron"] is True
    assert "left-pad" in r["dependencies"]
    comps = binary_rea.components_from([{"kind": "asar", "file": "app.asar", "evidence": r}])
    names = {c["name"] for c in comps}
    assert {"legacy-electron-app", "electron", "left-pad"} <= names


def test_jar_manifest_and_classes(tmp_path):
    """AC: BSA-AC-622"""
    jar = tmp_path / "legacy.jar"
    with zipfile.ZipFile(jar, "w") as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\nImplementation-Title: legacy-tool\n")
        z.writestr("com/legacy/Main.class", b"\xca\xfe\xba\xbe")
        z.writestr("com/legacy/Util.class", b"\xca\xfe\xba\xbe")
    r = binary_rea.read_jar(str(jar))
    assert r["format"] == "jar" and r["classes"] == 2
    assert r["manifest"].get("Implementation-Title") == "legacy-tool"


def test_inspect_dispatches_by_magic_and_reports_unknown_honestly(tmp_path):
    """AC: BSA-AC-623"""
    pe = tmp_path / "prog.exe"
    pe.write_bytes(_build_pe([("A.dll", ["f"])]))
    elf = tmp_path / "lib.so"
    elf.write_bytes(_build_elf())
    junk = tmp_path / "blob.bin"
    junk.write_bytes(b"\xde\xad\xbe\xef" * 4)
    pev, eev, jv = binary_rea.inspect(str(pe)), binary_rea.inspect(str(elf)), binary_rea.inspect(str(junk))
    assert pev["kind"] == "pe" and pev["tier"] == "structural" and pev["evidence"]["imported_dlls"] == ["A.dll"]
    assert eev["kind"] == "elf" and eev["evidence"]["needed"] == ["libfoo.so.1", "libbar.so.2"]
    assert jv["kind"] == "unknown" and jv["error"] and jv["evidence"] is None   # unknown: stated, never guessed
    assert all(l for l in (pev["limitations"], eev["limitations"], jv["limitations"])) and any("structural" in l for l in jv["limitations"])


def test_binscan_integrates_structural_components(tmp_path):
    """AC: BSA-AC-624"""
    src = tmp_path / "legacy"
    src.mkdir()
    (src / "prog.exe").write_bytes(_build_pe([("MYLIB.dll", ["FnOne"])]))
    (src / "lib.so").write_bytes(_build_elf())
    asar_b, _ = _build_asar({"name": "old-electron", "dependencies": {"electron": "13"}})
    (src / "app.asar").write_bytes(asar_b)
    c = binscan.build(str(src), max_binaries=16)
    names = {x["name"] for x in c.get("components") or []}
    assert {"MYLIB.dll", "libfoo.so.1", "old-electron", "electron"} <= names               # all three formats feed the SBOM
    assert c["component_count"] >= 4
    entry = next(b for b in c["binaries"] if b["file"] == "prog.exe")
    assert entry["structure"]["imported_dlls"] == ["MYLIB.dll"] and entry["structure_tier"] == "structural"
    md = binscan.to_md(c)
    assert "Structural components" in md                                                  # the report shows the new tier
