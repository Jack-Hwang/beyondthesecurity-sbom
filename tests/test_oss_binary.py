"""Tests for bts_sbom._internal.oss_binary (offline, no network, no external tools, no execution of scanned data)."""
from __future__ import annotations

import hashlib
import json
import os
import struct
import zipfile
import zlib

import pytest

from bts_sbom._internal import oss_binary
from bts_sbom.ossreport import OssReport


# ===================================================================================================== builders
def _elf_header(shoff=0, shentsize=0, shnum=0, shstrndx=0, e_type=2, machine=0x3E) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0, 0]) + b"\x00" * 7
    assert len(ident) == 16
    rest = struct.pack("<HHIQQQIHHHHHH", e_type, machine, 1, 0, 0, shoff, 0, 64, 0, 0, shentsize, shnum, shstrndx)
    hdr = ident + rest
    assert len(hdr) == 64
    return hdr


def build_elf64(sections=None, tail: bytes = b"") -> bytes:
    """A minimal, syntactically valid ELF64-LE file with an optional section table."""
    sections = sections or {}
    off = 64
    data_chunks = []
    entries = []
    for name, data in sections.items():
        entries.append({"name": name, "offset": off, "size": len(data)})
        data_chunks.append(data)
        off += len(data)

    shstrtab = bytearray(b"\x00")
    for e in entries:
        e["name_off"] = len(shstrtab)
        shstrtab += e["name"].encode("ascii") + b"\x00"
    shstrtab_name_off = len(shstrtab)
    shstrtab += b".shstrtab\x00"
    shstrtab_offset = off
    off += len(shstrtab)

    shnum = 1 + len(entries) + 1
    shstrndx = shnum - 1

    sh_table = bytearray()
    sh_table += struct.pack("<IIQQQQIIQQ", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)       # NULL section
    for e in entries:
        sh_table += struct.pack("<IIQQQQIIQQ", e["name_off"], 1, 0, 0, e["offset"], e["size"], 0, 0, 1, 0)
    sh_table += struct.pack("<IIQQQQIIQQ", shstrtab_name_off, 3, 0, 0, shstrtab_offset, len(shstrtab), 0, 0, 1, 0)

    sh_table_offset = off
    header = _elf_header(shoff=sh_table_offset, shentsize=64, shnum=shnum, shstrndx=shstrndx)
    return header + b"".join(data_chunks) + bytes(shstrtab) + bytes(sh_table) + tail


def build_pe(opt_magic=0x20B, com_rva=0, com_size=0, tail: bytes = b"") -> bytes:
    """A minimal, syntactically valid MZ+PE(+) header, optionally with a non-zero CLR (COM descriptor) directory."""
    dos = bytearray(b"\x00" * 0x40)
    dos[0:2] = b"MZ"
    e_lfanew = 0x40
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    ndirs = 16
    dirs_off = 96 if opt_magic == 0x10B else 112
    opt_size = dirs_off + ndirs * 8
    coff = struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, opt_size, 0x0022)
    opt = bytearray(opt_size)
    struct.pack_into("<H", opt, 0, opt_magic)
    com_off = dirs_off + 14 * 8
    struct.pack_into("<II", opt, com_off, com_rva, com_size)

    pe_sig = b"PE\x00\x00"
    return bytes(dos) + pe_sig + coff + bytes(opt) + tail


def build_note(name: bytes, desc: bytes, ntype: int) -> bytes:
    def pad4(b):
        return b + b"\x00" * ((-len(b)) % 4)
    return struct.pack("<III", len(name), len(desc), ntype) + pad4(name) + pad4(desc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()


# ========================================================================================================== magic
def test_elf_detection_sha256_and_version_banner_needs_check(tmp_path):
    data = build_elf64() + b"\x00" * 20 + b"OpenSSL 1.0.2k-fips more text around it\x00" + b"\x00" * 20
    p = tmp_path / "libfoo.so"
    p.write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    assert len(r.items) == 1
    it = r.items[0]
    assert it.kind == "bin" and it.checksum == _sha256(data) and it.extra["sha1"] == _sha1(data)
    assert it.extra["binary_format"] == "elf"
    assert it.oss_name == "OpenSSL" and it.version == "1.0.2k"
    assert it.needs_check is True
    assert any("version banner" in e for e in it.evidence)
    assert "not verified" in it.comment
    assert it.licenses == [], "no explicit SPDX-License-Identifier tag was present: no license is claimed"


def test_elf_with_spdx_tag_is_the_only_case_a_banner_gets_a_license(tmp_path):
    data = build_elf64() + b"zlib 1.2.11 deflate engine\x00" + b"SPDX-License-Identifier: Zlib\x00"
    p = tmp_path / "libz.so"
    p.write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = next(i for i in r.items if i.oss_name == "zlib")
    assert it.licenses == ["Zlib"]
    assert any("SPDX-License-Identifier" in e for e in it.evidence)


def test_license_phrase_in_strings_is_evidence_only_never_a_confirmed_license(tmp_path):
    mit_text = b"Permission is hereby granted, free of charge, to any person obtaining a copy of this software"
    data = build_elf64() + mit_text
    p = tmp_path / "nolicenseinfo.bin"
    p.write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = r.items[0]
    assert it.licenses == []
    assert "evidence only" in it.comment and "MIT" in it.comment
    assert any("license phrase" in e for e in it.evidence)


def test_pe_detection_version_banner_and_dotnet_clr_header(tmp_path):
    data = build_pe(com_rva=0x2000, com_size=72) + b"zlib 1.2.11 \x00"
    p = tmp_path / "app.exe"
    p.write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = next(i for i in r.items if i.oss_name == "zlib")
    assert it.extra["binary_format"] == "pe"
    assert it.extra["dotnet_clr_header"] is True
    assert it.version == "1.2.11"


def test_pe_without_clr_directory_is_not_flagged_dotnet(tmp_path):
    data = build_pe(com_rva=0, com_size=0) + b"libcurl/7.68.0 \x00"
    p = tmp_path / "plain.exe"
    p.write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = next(i for i in r.items if i.oss_name == "libcurl")
    assert it.extra["dotnet_clr_header"] is False


def test_dotnet_deps_json_sibling_is_read(tmp_path):
    p = tmp_path / "MyApp.dll"
    p.write_bytes(build_pe())
    deps = {
        "libraries": {
            "Newtonsoft.Json/13.0.1": {"type": "package", "serviceable": True},
            "MyApp/1.0.0": {"type": "project"},
        }
    }
    (tmp_path / "MyApp.deps.json").write_text(json.dumps(deps), encoding="utf-8")
    r = oss_binary.scan(str(tmp_path))
    nj = next(i for i in r.items if i.oss_name == "Newtonsoft.Json")
    assert nj.version == "13.0.1" and nj.purl == "pkg:nuget/Newtonsoft.Json@13.0.1"
    assert not any(i.oss_name == "MyApp" for i in r.items), 'the "project" type entry is not a package dependency'


def test_macho_thin_and_fat_detection(tmp_path):
    (tmp_path / "thin.dylib").write_bytes(b"\xfe\xed\xfa\xce" + b"\x00" * 24)
    (tmp_path / "universal.dylib").write_bytes(b"\xca\xfe\xba\xbe" + struct.pack(">I", 2) + b"\x00" * 40)
    r = oss_binary.scan(str(tmp_path))
    formats = {i.source_path: i.extra["binary_format"] for i in r.items}
    assert formats[oss_binary.oss_common.norm("thin.dylib")] == "macho"
    assert formats[oss_binary.oss_common.norm("universal.dylib")] == "macho-fat"


def test_class_file_is_not_detected_despite_cafebabe_collision(tmp_path):
    (tmp_path / "Foo.class").write_bytes(b"\xca\xfe\xba\xbe" + b"\x00\x00\x00\x34" + b"\x00" * 16)
    r = oss_binary.scan(str(tmp_path))
    assert r.items == []


def test_ar_archive_detection_and_string_banner(tmp_path):
    data = b"!<arch>\n" + b"BusyBox v1.30.1 multi-call binary\x00" + b"\x00" * 10
    (tmp_path / "libstatic.a").write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = next(i for i in r.items if i.oss_name == "BusyBox")
    assert it.extra["binary_format"] == "ar" and it.version == "1.30.1"


def test_dex_and_wasm_detected_but_not_deep_analysed(tmp_path):
    (tmp_path / "classes.dex").write_bytes(b"dex\n035\x00" + b"\x00" * 40)
    (tmp_path / "mod.wasm").write_bytes(b"\x00asm" + b"\x01\x00\x00\x00" + b"\x00" * 20)
    r = oss_binary.scan(str(tmp_path))
    assert {i.extra["binary_format"] for i in r.items} == {"dex", "wasm"}
    assert all(i.oss_name == "" and "no open source identified" in i.comment for i in r.items)


def test_non_binary_files_are_not_reported(tmp_path):
    (tmp_path / "readme.txt").write_text("just some text, not a binary", encoding="utf-8")
    (tmp_path / "data.json").write_text("{}", encoding="utf-8")
    r = oss_binary.scan(str(tmp_path))
    assert r.items == []


# ================================================================================================= default exclude
def test_default_excluded_binary_is_reported_but_not_deep_analysed(tmp_path):
    d = tmp_path / "test"
    d.mkdir()
    (d / "fixture.so").write_bytes(build_elf64() + b"OpenSSL 1.0.2k-fips \x00")
    r = oss_binary.scan(str(tmp_path))
    it = r.items[0]
    assert it.exclude is True and it.comment == "test directory"
    assert it.oss_name == "", "excluded binaries are not deep-analysed for string banners"


# ====================================================================================================== JAR / zip
def test_jar_with_manifest_and_pom_is_identified(tmp_path):
    jar = tmp_path / "demo-lib-2.3.4.jar"
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nImplementation-Title: demo-lib\nImplementation-Version: 2.3.4\n"
                    "Implementation-Vendor: Example Corp\n")
        zf.writestr("META-INF/maven/com.example/demo-lib/pom.properties",
                    "version=2.3.4\ngroupId=com.example\nartifactId=demo-lib\n")
        zf.writestr("META-INF/maven/com.example/demo-lib/pom.xml",
                    '<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">'
                    "<groupId>com.example</groupId><artifactId>demo-lib</artifactId><version>2.3.4</version>"
                    "<licenses><license><name>Apache-2.0</name></license></licenses></project>")
    r = oss_binary.scan(str(tmp_path))
    assert len(r.items) == 1
    it = r.items[0]
    assert it.oss_name == "demo-lib" and it.version == "2.3.4"
    assert it.purl == "pkg:maven/com.example/demo-lib@2.3.4"
    assert it.licenses == ["Apache-2.0"]
    assert any("pom.properties in jar" in e for e in it.evidence)
    assert "Example Corp" in it.comment


def test_shaded_jar_gets_one_item_per_embedded_artifact(tmp_path):
    jar = tmp_path / "app-all.jar"
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("META-INF/MANIFEST.MF",
                    "Manifest-Version: 1.0\nImplementation-Title: shaded-app\nImplementation-Version: 1.0.0\n")
        zf.writestr("META-INF/maven/com.example/one/pom.properties", "groupId=com.example\nartifactId=one\nversion=1.1\n")
        zf.writestr("META-INF/maven/com.other/two/pom.properties", "groupId=com.other\nartifactId=two\nversion=2.2\n")
    r = oss_binary.scan(str(tmp_path))
    assert len(r.items) == 3
    base = next(i for i in r.items if i.oss_name == "shaded-app")
    assert "2 embedded artifacts" in base.comment
    embedded = sorted((i.oss_name, i.version) for i in r.items if i is not base)
    assert embedded == [("one", "1.1"), ("two", "2.2")]
    for i in r.items:
        if i is not base:
            assert i.comment == "embedded in app-all.jar"
            assert any(e == "embedded in app-all.jar" for e in i.evidence)
    assert all(i.checksum == _sha256((tmp_path / "app-all.jar").read_bytes()) for i in r.items)


def test_jar_with_absurd_declared_size_is_rejected_not_trusted(tmp_path):
    jar = tmp_path / "lying.jar"
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\n")
    raw = bytearray(jar.read_bytes())
    cdfh = raw.find(b"PK\x01\x02")
    assert cdfh != -1
    struct.pack_into("<I", raw, cdfh + 24, 500_000_000)        # lie about the uncompressed size
    jar.write_bytes(bytes(raw))

    r = oss_binary.scan(str(tmp_path))
    assert len(r.items) == 1
    assert r.items[0].oss_name == "" and "no open source identified" in r.items[0].comment
    assert any("declares oversized content" in w for w in r.warnings)


def test_jar_with_too_many_entries_or_declared_zip_bomb_is_rejected(tmp_path):
    jar = tmp_path / "manyentries.jar"
    with zipfile.ZipFile(jar, "w", zipfile.ZIP_STORED) as zf:
        for i in range(5):
            zf.writestr("f%d.txt" % i, "x")
    saved = oss_binary.MAX_ZIP_ENTRIES
    oss_binary.MAX_ZIP_ENTRIES = 3
    try:
        r = oss_binary.scan(str(tmp_path))
    finally:
        oss_binary.MAX_ZIP_ENTRIES = saved
    assert r.items[0].oss_name == ""
    assert any("more than" in w and "entries" in w for w in r.warnings)


def test_corrupted_zip_does_not_crash(tmp_path):
    (tmp_path / "broken.jar").write_bytes(b"PK\x03\x04" + os.urandom(200))
    r = oss_binary.scan(str(tmp_path))
    assert len(r.items) == 1
    assert any("not a valid zip" in w for w in r.warnings)


# ================================================================================================= knowledge base
def test_hash_match_via_csv_knowledge_base(tmp_path):
    data = build_elf64() + b"\x00" * 8
    p = tmp_path / "known.so"
    p.write_bytes(data)
    digest = _sha256(data)
    kb = tmp_path / "kb.csv"
    kb.write_text("sha256,oss_name,version,licenses,download_location,homepage,copyright\n"
                 "%s,myelf,9.9.9,MIT|Apache-2.0,https://example.com/dl,https://example.com,(c) Example\n" % digest,
                 encoding="utf-8")
    r = oss_binary.scan(str(tmp_path), kb_files=[str(kb)])
    it = r.items[0]
    assert it.oss_name == "myelf" and it.version == "9.9.9"
    assert it.licenses == ["MIT", "Apache-2.0"]
    assert it.download_location == "https://example.com/dl" and it.copyright == "(c) Example"
    assert any("hash match in" in e and "kb.csv" in e for e in it.evidence)
    assert r.info["scanners"]["binary"]["counts"]["matched_hash"] == 1


def test_hash_match_via_json_knowledge_base_list_form_and_sha1(tmp_path):
    data = build_elf64() + b"\x11" * 4
    p = tmp_path / "known2.so"
    p.write_bytes(data)
    digest1 = _sha1(data)
    kb = tmp_path / "kb.json"
    kb.write_text(json.dumps([{"sha1": digest1, "oss_name": "fromjson", "version": "1.0",
                               "licenses": ["BSD-3-Clause"]}]), encoding="utf-8")
    r = oss_binary.scan(str(tmp_path), kb_files=[str(kb)])
    it = r.items[0]
    assert it.oss_name == "fromjson" and it.licenses == ["BSD-3-Clause"]


def test_knowledge_base_dict_form_and_bad_kb_file_is_warned_not_fatal(tmp_path):
    data = build_elf64()
    p = tmp_path / "known3.so"
    p.write_bytes(data)
    digest = _sha256(data)
    kb = tmp_path / "kb2.json"
    kb.write_text(json.dumps({digest: {"oss_name": "dictform", "version": "2.0"}}), encoding="utf-8")
    bad = tmp_path / "bad.json"
    bad.write_text("not json at all {{{", encoding="utf-8")
    r = oss_binary.scan(str(tmp_path), kb_files=[str(kb), str(bad)])
    it = next(i for i in r.items if i.source_path.endswith("known3.so"))
    assert it.oss_name == "dictform"
    assert any("could not be parsed" in w for w in r.warnings)


# ========================================================================================= hostile / bounds inputs
def test_truncated_elf_does_not_crash(tmp_path):
    (tmp_path / "truncated.so").write_bytes(b"\x7fELF\x02\x01\x01")
    r = oss_binary.scan(str(tmp_path))
    assert len(r.items) == 1
    assert r.items[0].oss_name == "" and "no open source identified" in r.items[0].comment


def test_garbage_file_with_elf_magic_only_does_not_crash(tmp_path):
    (tmp_path / "garbage.so").write_bytes(b"\x7fELF" + os.urandom(500))
    r = oss_binary.scan(str(tmp_path))
    assert len(r.items) == 1


def test_symlinks_are_never_followed(tmp_path):
    real = tmp_path / "real.so"
    real.write_bytes(build_elf64() + b"OpenSSL 1.0.2k-fips \x00")
    link = tmp_path / "link.so"
    try:
        os.symlink(real, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not supported in this environment")
    r = oss_binary.scan(str(tmp_path))
    assert not any("link.so" in i.source_path for i in r.items)
    assert any("real.so" in i.source_path for i in r.items)


def test_strings_are_bounded_by_strings_limit(tmp_path):
    header = _elf_header()                     # bare 64-byte header, no section table padding
    body = b"OpenSSL 1.0.1a here\x00" + b"\x00" * 5000 + b"OpenSSL 9.9.9z there\x00"
    p = tmp_path / "bounded.so"
    p.write_bytes(header + body)
    r = oss_binary.scan(str(tmp_path), strings_limit=len(header) + 40)
    it = next(i for i in r.items if i.oss_name == "OpenSSL")
    assert it.version == "1.0.1a", "the match beyond strings_limit must never be seen"
    assert any("string scan bounded" in w for w in r.warnings)


def test_max_files_limit_is_reported(tmp_path):
    for i in range(3):
        (tmp_path / ("f%d.so" % i)).write_bytes(build_elf64())
    r = oss_binary.scan(str(tmp_path), max_files=1)
    assert any("max_files" in w for w in r.warnings)


# =================================================================================================== embedded SBOM
def test_elf_note_package_systemd_metadata(tmp_path):
    desc = json.dumps({"type": "rpm", "name": "somepkg", "version": "1.2.3"}).encode()
    note = build_note(b"FDO\x00", desc, 0xCAFE1A7E)
    data = build_elf64(sections={".note.package": note})
    (tmp_path / "pkgmeta.so").write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = next(i for i in r.items if i.oss_name == "somepkg")
    assert it.version == "1.2.3" and it.purl == "pkg:rpm/somepkg@1.2.3"
    assert any(".note.package" in e for e in it.evidence)


def test_elf_cargo_auditable_dep_v0_section(tmp_path):
    payload = json.dumps({"packages": [{"name": "libc", "version": "0.2.100", "source": "registry"}]}).encode()
    compressed = zlib.compress(payload)
    data = build_elf64(sections={".dep-v0": compressed})
    (tmp_path / "rustbin").write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = next(i for i in r.items if i.oss_name == "libc")
    assert it.version == "0.2.100" and it.purl == "pkg:cargo/libc@0.2.100"


def test_elf_dep_v0_invalid_zlib_payload_is_skipped_not_guessed(tmp_path):
    data = build_elf64(sections={".dep-v0": b"not a valid zlib stream"})
    (tmp_path / "rustbin_bad").write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    assert r.items[0].oss_name == ""
    assert any("could not be decoded" in w for w in r.warnings)


def test_go_buildinfo_dependency_line_best_effort(tmp_path):
    blob = (b"\xff Go buildinf:" + b"\x08\x02\x00\x00" +
            b"go1.21.3\npath\texample.com/main\nmod\texample.com/main\t(devel)\t\n"
            b"dep\tgolang.org/x/text\tv0.9.0\th1:abc=\n")
    data = build_elf64() + blob
    (tmp_path / "gobin").write_bytes(data)
    r = oss_binary.scan(str(tmp_path))
    it = next(i for i in r.items if i.oss_name == "golang.org/x/text")
    assert it.version == "v0.9.0" and it.needs_check is True
    assert it.purl == "pkg:golang/golang.org/x/text@v0.9.0"


# ======================================================================================================== purls_for
def test_purls_for_collects_distinct_purls_in_order():
    from bts_sbom.ossreport import OssItem
    r = OssReport(items=[
        OssItem(kind="bin", purl="pkg:maven/a/b@1"),
        OssItem(kind="bin", purl="pkg:cargo/libc@0.2.100"),
        OssItem(kind="bin", purl="pkg:maven/a/b@1"),
        OssItem(kind="bin", purl=""),
        OssItem(kind="src", purl="pkg:npm/should-not-appear@1"),
    ])
    assert oss_binary.purls_for(r) == ["pkg:maven/a/b@1", "pkg:cargo/libc@0.2.100"]


def test_scanner_info_and_report_shape(tmp_path):
    (tmp_path / "a.so").write_bytes(build_elf64())
    r = oss_binary.scan(str(tmp_path))
    info = r.info["scanners"]["binary"]
    assert "not_supported" in info and any("TLSH" in s for s in info["not_supported"])
    assert info["counts"]["binaries_found"] == 1
    assert r.info["analyzed_path"] == str(tmp_path)
