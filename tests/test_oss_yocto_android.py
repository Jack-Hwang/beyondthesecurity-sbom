"""Tests for the Yocto and Android OSS scanners (offline; no real bitbake/Android build, no network)."""
from __future__ import annotations

import gzip
import hashlib
import json
import os
import sys

import pytest

from bts_sbom import ossreport
from bts_sbom._internal import oss_android, oss_yocto


def _write(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)


def _write_json(path, obj):
    _write(path, json.dumps(obj))


def _write_bytes(path, data):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as fh:
        fh.write(data)


def _symlink_or_skip(target, link):
    try:
        os.symlink(target, link)
    except (OSError, NotImplementedError):
        pytest.skip("symlinks are not supported/permitted in this environment")


# ================================================================================================= license conversion
def test_yocto_license_operator_conversion_and_unknown_tokens():
    expr, unknown = oss_yocto._convert_yocto_license("GPLv2 & FooBarLicense")
    assert expr == "GPL-2.0-only AND FooBarLicense"
    assert unknown == ["FooBarLicense"]

    expr2, unknown2 = oss_yocto._convert_yocto_license("(GPLv2+ | LGPLv3) & GPLv3+")
    assert expr2 == "(GPL-2.0-or-later OR LGPL-3.0-only) AND GPL-3.0-or-later"
    assert unknown2 == []

    expr3, unknown3 = oss_yocto._convert_yocto_license("MIT & Zlib")
    assert expr3 == "MIT AND Zlib" and unknown3 == []

    assert oss_yocto._convert_yocto_license("") == ("", [])


# ================================================================================================= bom.json decoding
def test_decode_bom_json_accepts_list_dict_and_bracket_less_shapes():
    recs, trouble = oss_yocto._decode_bom_json('[{"recipe": "a", "pv": "1"}, {"recipe": "b", "pv": "2"}]')
    assert not trouble and [r["recipe"] for r in recs] == ["a", "b"]

    recs2, trouble2 = oss_yocto._decode_bom_json('{"a": {"pv": "1"}, "b": {"pv": "2"}}')
    assert not trouble2 and sorted(r["recipe"] for r in recs2) == ["a", "b"]

    # the real fosslight_yocto bom.bbclass fixture shape: concatenated JSON objects with NO enclosing brackets
    bracketless = '{"recipe": "a", "pv": "1"},{"recipe": "b", "pv": "2"},'
    recs3, trouble3 = oss_yocto._decode_bom_json(bracketless)
    assert not trouble3 and [r["recipe"] for r in recs3] == ["a", "b"]

    # malformed tail: recover what parses, flag the rest instead of crashing
    recs4, trouble4 = oss_yocto._decode_bom_json('{"recipe": "a", "pv": "1"}, {not valid json')
    assert trouble4 and [r["recipe"] for r in recs4] == ["a"]

    assert oss_yocto._decode_bom_json("") == ([], False)


# ================================================================================================= yocto scan: bom.json (list) + buildhistory + installed lists
def test_yocto_scan_bom_json_list_shape_with_buildhistory_and_installed_lists(tmp_path):
    root = tmp_path
    _write_json(str(root / "bom.json"), [
        {"recipe": "m4", "pv": "1.4.18", "license": "GPLv3",
         "src_uri": "http://ftp.gnu.org/gnu/m4/m4-1.4.18.tar.gz file://ac_config_links.patch",
         "packages": "m4-dbg m4", "file": "/oe-core/meta/recipes-devtools/m4/m4_1.4.18.bb"},
        {"recipe": "zlib", "pv": "1.2.11", "license": "Zlib", "src_uri": "http://zlib.net/zlib-1.2.11.tar.gz",
         "packages": "zlib zlib-dev", "pkg_lic": {"zlib-dev": "Zlib"}},
    ])
    _write(str(root / "installed-package-names.txt"), "m4\nzlib\nzlib-dev\n")
    _write(str(root / "installed-packages.txt"),
           "m4_1.4.18-r0_qemux86.ipk\nzlib_1.2.11-r0_qemux86.ipk\n")
    _write(str(root / "buildhistory" / "packages" / "qemux86" / "zlib" / "zlib-dev" / "latest"),
           "PV = 1.2.11\nPR = r0\nRDEPENDS = zlib\nPKGSIZE = 1234\n")
    _write(str(root / "buildhistory" / "packages" / "qemux86" / "bash" / "latest"),
           "PN = bash\nPV = 5.0\nPR = r0\nLICENSE = GPL-3.0-or-later\n")

    report = oss_yocto.scan(str(root))

    by_name = {i.oss_name: i for i in report.of_kind("src")}
    assert set(by_name) == {"m4", "zlib", "bash"}

    m4 = by_name["m4"]
    assert m4.version == "1.4.18" and m4.licenses == ["GPL-3.0-only"]
    assert m4.download_location == "http://ftp.gnu.org/gnu/m4/m4-1.4.18.tar.gz"
    assert m4.source_path == "bom.json"

    zlib_item = by_name["zlib"]
    assert zlib_item.licenses == ["Zlib"] and zlib_item.extra["pkg_lic"] == {"zlib-dev": "Zlib"}
    bh_pkgs = zlib_item.extra.get("buildhistory_packages") or []
    assert any(p.get("_package") == "zlib-dev" and p.get("PKGSIZE") == "1234" for p in bh_pkgs)

    bash = by_name["bash"]
    assert bash.version == "5.0" and bash.licenses == ["GPL-3.0-or-later"]
    assert "bash" in bash.evidence[0]

    assert oss_yocto._KERNEL_WARNING in report.warnings
    summary = report.info["scanners"]["yocto"]
    assert summary["recipes"] == 3 and summary["installed_names"] == 3 and summary["buildhistory_files"] == 2


def test_yocto_scan_bom_json_dict_shape(tmp_path):
    root = tmp_path
    _write_json(str(root / "bom.json"), {
        "libfoo": {"pv": "2.0", "license": "MIT & BSD-3-Clause", "src_uri": "https://example.org/libfoo-2.0.tar.gz",
                   "packages": "libfoo libfoo-dev"},
    })
    _write(str(root / "installed-package-names.txt"), "libfoo\n")

    report = oss_yocto.scan(str(root))
    items = report.of_kind("src")
    assert len(items) == 1
    it = items[0]
    assert it.oss_name == "libfoo" and it.version == "2.0"
    assert it.licenses == ["MIT AND BSD-3-Clause"]
    assert it.download_location == "https://example.org/libfoo-2.0.tar.gz"


def test_yocto_scan_license_manifest_is_the_fallback_source_when_bom_json_is_absent(tmp_path):
    root = tmp_path
    _write(str(root / "tmp" / "deploy" / "licenses" / "my-image" / "license.manifest"), """
PACKAGE NAME: busybox
PACKAGE VERSION: 1.31.1
RECIPE NAME: busybox
LICENSE: GPLv2 & FooBarLicense1

PACKAGE NAME: openssl
PACKAGE VERSION: 1.1.1
RECIPE NAME: openssl
LICENSE: MIT | BSD-3-Clause
""")
    report = oss_yocto.scan(str(root))
    by_name = {i.oss_name: i for i in report.of_kind("src")}
    assert by_name["busybox"].version == "1.31.1"
    assert by_name["busybox"].licenses == ["GPL-2.0-only AND FooBarLicense1"]
    assert by_name["openssl"].licenses == ["MIT OR BSD-3-Clause"]
    assert report.info["scanners"]["yocto"]["source"] == "license.manifest"


def test_yocto_bom_json_truncated_or_malformed_is_reported_not_crashed(tmp_path):
    root = tmp_path
    _write(str(root / "bom.json"), '{"recipe": "ok1", "pv": "1"}, {totally not json at all')
    report = oss_yocto.scan(str(root))
    assert any(i.oss_name == "ok1" for i in report.items)
    assert any("could not be parsed" in w for w in report.warnings)


def test_yocto_symlinked_buildhistory_latest_file_is_not_followed(tmp_path):
    root = tmp_path
    real_dir = root / "buildhistory" / "packages" / "qemux86" / "real_recipe"
    real_dir.mkdir(parents=True)
    _write(str(real_dir / "latest"), "PN = real_recipe\nPV = 1.0\nLICENSE = MIT\n")
    link_dir = root / "buildhistory" / "packages" / "qemux86" / "linked_recipe"
    link_dir.mkdir(parents=True)
    _symlink_or_skip(str(real_dir / "latest"), str(link_dir / "latest"))

    report = oss_yocto.scan(str(root))
    names = {i.oss_name for i in report.of_kind("src")}
    assert "real_recipe" in names
    assert "linked_recipe" not in names


# ================================================================================================= yocto: sbom-info override
def test_yocto_sbom_info_override_replaces_recipe_derived_info(tmp_path):
    root = tmp_path
    _write_json(str(root / "bom.json"), [
        {"recipe": "libidn", "pv": "1.33", "license": "LGPLv2.1+", "packages": "libidn"},
    ])
    _write(str(root / "installed-package-names.txt"), "libidn\n")
    _write(str(root / "sbom-info.yaml"), """
libidn-override:
- version: "1.34"
  license:
  - LGPL-2.1-or-later
  download location: "https://ftp.gnu.org/gnu/libidn/libidn-1.34.tar.gz"
  comment: confirmed by hand
  yocto_recipe: libidn
""")
    report = oss_yocto.scan(str(root))
    items = report.of_kind("src")
    assert len(items) == 1
    it = items[0]
    assert it.oss_name == "libidn-override" and it.version == "1.34"
    assert it.licenses == ["LGPL-2.1-or-later"]
    assert it.download_location == "https://ftp.gnu.org/gnu/libidn/libidn-1.34.tar.gz"
    assert "confirmed by hand" in it.comment
    assert report.info["scanners"]["yocto"]["overrides_applied"] == 1


def test_yocto_sbom_info_override_can_exclude_a_recipe(tmp_path):
    root = tmp_path
    _write_json(str(root / "bom.json"), [{"recipe": "proprietary-blob", "pv": "1", "license": "Proprietary",
                                          "packages": "proprietary-blob"}])
    _write(str(root / "installed-package-names.txt"), "proprietary-blob\n")
    _write(str(root / "sbom-info.yaml"), """
'-':
- version: ''
  exclude: True
  yocto_recipe: proprietary-blob
""")
    report = oss_yocto.scan(str(root))
    it = next(i for i in report.items if i.extra.get("recipe_name") == "proprietary-blob")
    assert it.exclude is True


# ================================================================================================= yocto: no binary scanner
def test_yocto_scan_without_binary_root_warns_and_does_not_crash(tmp_path):
    root = tmp_path
    _write_json(str(root / "bom.json"), [{"recipe": "a", "pv": "1", "license": "MIT", "packages": "a"}])
    report = oss_yocto.scan(str(root))
    assert not report.of_kind("bin")
    assert any("binary_root" in w for w in report.warnings)


def test_yocto_scan_with_binary_root_but_missing_oss_binary_module_warns(tmp_path, monkeypatch):
    # sys.modules[name] = None is the standard way to force "import X" to raise ImportError,
    # simulating the sibling oss_binary scanner not being available yet.
    monkeypatch.setitem(sys.modules, "bts_sbom._internal.oss_binary", None)
    root = tmp_path
    (root / "rootfs").mkdir()
    _write_json(str(root / "bom.json"), [{"recipe": "a", "pv": "1", "license": "MIT", "packages": "a"}])
    report = oss_yocto.scan(str(root), binary_root=str(root / "rootfs"))
    assert any("oss_binary" in w for w in report.warnings)


def test_yocto_scan_with_binary_root_and_real_oss_binary_module_merges_bin_items(tmp_path):
    pytest.importorskip("bts_sbom._internal.oss_binary")
    root = tmp_path
    (root / "rootfs").mkdir()
    _write_json(str(root / "bom.json"), [{"recipe": "a", "pv": "1", "license": "MIT", "packages": "a"}])
    report = oss_yocto.scan(str(root), binary_root=str(root / "rootfs"))
    # an empty rootfs legitimately yields zero binaries; the call must simply not crash and must be reflected
    assert isinstance(report.info["scanners"]["yocto"]["bin_items"], int)
    assert not any("oss_binary is not available" in w for w in report.warnings)


# ================================================================================================= android: module-info.json + MODULE_LICENSE + NOTICE -> 4 states
@pytest.fixture
def android_tree(tmp_path):
    root = tmp_path

    def module_src(name, notice=False, license_marker=None):
        d = root / "src" / "external" / name
        d.mkdir(parents=True)
        if notice:
            _write(str(d / "NOTICE"), "Copyright Example\n")
        if license_marker:
            _write(str(d / ("MODULE_LICENSE_" + license_marker)), "")
        return "src/external/%s" % name

    toybox_path = module_src("toybox", notice=True, license_marker="BSD")
    foolib_path = module_src("foolib", notice=False, license_marker=None)
    privlib_path = module_src("privlib", notice=True, license_marker="MIT")
    pubtool_path = module_src("pubtool", notice=False, license_marker=None)

    installed = {
        "toybox": "out/target/product/generic/system/bin/toybox",
        "foolib": "out/target/product/generic/system/lib/libfoo.so",
        "privlib": "out/target/product/generic/system/lib/libpriv.so",
        "pubtool": "out/target/product/generic/system/bin/pubtool",
    }
    for rel in installed.values():
        _write_bytes(str(root / rel), b"binary-content-" + rel.encode())

    module_info = {
        "toybox": {"path": [toybox_path], "installed": [installed["toybox"]], "class": ["EXECUTABLES"]},
        "foolib": {"path": [foolib_path], "installed": [installed["foolib"]], "class": ["SHARED_LIBRARIES"]},
        "privlib": {"path": [privlib_path], "installed": [installed["privlib"]], "class": ["SHARED_LIBRARIES"]},
        "pubtool": {"path": [pubtool_path], "installed": [installed["pubtool"]], "class": ["EXECUTABLES"]},
        "evilmod": {"path": ["../../etc/passwd"], "installed": ["../../etc/passwd"], "class": ["ETC"]},
    }
    _write_json(str(root / "out" / "module-info.json"), module_info)

    _write(str(root / "out" / "foolib.meta_lic"),
           'package_name: "foolib"\nlicense_kinds: "SPDX-license-identifier-Apache-2.0"\nlicense_conditions: "notice"\n')

    # mentions toybox and pubtool (by name) -> "included in final NOTICE"; foolib/privlib are never mentioned
    _write(str(root / "out" / "NOTICE.html"),
           "<html><body><h3>toybox</h3><p>...</p><h3>pubtool</h3><p>...</p></body></html>")

    return root, installed


def test_android_scan_four_notice_states(android_tree):
    root, installed = android_tree
    report = oss_android.scan(str(root))
    by_name = {i.oss_name: i for i in report.items}

    assert by_name["toybox"].notice_status == "ok"          # source NOTICE present + mentioned in final NOTICE
    assert by_name["foolib"].notice_status == "nok"         # no source NOTICE, not mentioned
    assert by_name["privlib"].notice_status == "nok(NA)"    # source NOTICE present, NOT mentioned
    assert by_name["pubtool"].notice_status == "ok(NA)"     # no source NOTICE, but mentioned

    assert by_name["foolib"].licenses == ["Apache-2.0"]       # from foolib.meta_lic SPDX-license-identifier-
    assert by_name["privlib"].licenses == ["MIT"]             # from MODULE_LICENSE_MIT
    assert by_name["toybox"].licenses == []                   # MODULE_LICENSE_BSD is ambiguous -> never guessed
    assert by_name["toybox"].needs_check is True
    assert "MODULE_LICENSE_BSD" in by_name["toybox"].comment

    assert all(it.kind == "bin" for it in report.items)
    assert "evilmod" not in by_name
    summary = report.info["scanners"]["android"]
    assert summary["rejected_paths"] == 2
    assert any("rejected" in w for w in report.warnings)


def test_android_binary_name_and_source_path_are_recorded(android_tree):
    root, installed = android_tree
    report = oss_android.scan(str(root))
    toybox = next(i for i in report.items if i.oss_name == "toybox")
    assert toybox.source_path == installed["toybox"]
    assert toybox.extra["binary_name"] == "toybox"
    assert toybox.extra["source_code_path"] == "src/external/toybox"
    assert len(toybox.checksum) == 64


def test_android_symlinked_module_license_marker_is_not_followed(tmp_path):
    root = tmp_path
    real_dir = root / "src" / "external" / "realmod"
    real_dir.mkdir(parents=True)
    _write(str(real_dir / "MODULE_LICENSE_APACHE2"), "")

    sym_dir = root / "src" / "external" / "symmod"
    sym_dir.mkdir(parents=True)
    _symlink_or_skip(str(real_dir / "MODULE_LICENSE_APACHE2"), str(sym_dir / "MODULE_LICENSE_APACHE2"))
    _write_bytes(str(root / "out" / "bin" / "symbin"), b"content")

    _write_json(str(root / "out" / "module-info.json"), {
        "symmod": {"path": ["src/external/symmod"], "installed": ["out/bin/symbin"], "class": ["EXECUTABLES"]},
    })
    report = oss_android.scan(str(root))
    it = next(i for i in report.items if i.oss_name == "symmod")
    assert it.licenses == [], "a symlinked MODULE_LICENSE_* marker must not be followed/trusted"
    assert it.needs_check is True


def test_android_dedupe_against_prior_scan_marks_excluded(tmp_path):
    content = b"identical-binary-content"
    checksum = hashlib.sha256(content).hexdigest()

    prior = ossreport.OssReport(items=[
        ossreport.OssItem(kind="bin", oss_name="dupmod", source_path="out/bin/dupbin", checksum=checksum),
    ])
    prior_path = str(tmp_path / "prior.json")
    ossreport.write_report(prior, "json", prior_path)

    root = tmp_path / "scan2"
    _write_bytes(str(root / "out" / "bin" / "dupbin"), content)
    _write_json(str(root / "out" / "module-info.json"), {
        "dupmod": {"path": ["src/dupmod"], "installed": ["out/bin/dupbin"], "class": ["EXECUTABLES"]},
    })
    (root / "src" / "dupmod").mkdir(parents=True)

    report = oss_android.scan(str(root), dedupe_against=prior_path)
    it = next(i for i in report.items if i.oss_name == "dupmod")
    assert it.exclude is True and "duplicate" in it.comment
    assert report.info["scanners"]["android"]["duplicates_marked"] == 1


def test_android_packaging_config_flags_prohibited_files(android_tree):
    root, installed = android_tree
    cfg = {"prohibited_extensions": ["so"], "prohibited_names": [], "prohibited_paths": []}
    report = oss_android.scan(str(root), packaging_config=cfg)
    foolib = next(i for i in report.items if i.oss_name == "foolib")
    assert foolib.needs_check is True
    assert "improper packaging" in foolib.comment
    assert report.info["scanners"]["android"]["improper_packaging"] >= 1


# ================================================================================================= android: gzip bomb bound
def test_gunzip_bounded_caps_decompressed_output(tmp_path):
    bomb_path = tmp_path / "NOTICE.xml.gz"
    payload = b"A" * 5_000_000   # highly compressible -> tiny .gz, large decompressed size
    with gzip.open(str(bomb_path), "wb") as fh:
        fh.write(payload)
    assert os.path.getsize(str(bomb_path)) < 50_000   # confirms this really is a small file inflating hugely

    text, truncated = oss_android._gunzip_bounded(str(bomb_path), max_compressed=1_000_000, max_decompressed=100_000)
    assert truncated is True
    assert len(text.encode("utf-8", "replace")) <= 100_000


def test_android_scan_reads_small_notice_xml_gz(tmp_path):
    root = tmp_path
    (root / "src" / "mod").mkdir(parents=True)
    _write_bytes(str(root / "out" / "bin" / "mod"), b"x")
    _write_json(str(root / "out" / "module-info.json"), {
        "mod": {"path": ["src/mod"], "installed": ["out/bin/mod"], "class": ["EXECUTABLES"]},
    })
    with gzip.open(str(root / "out" / "NOTICE.xml.gz"), "wb") as fh:
        fh.write(b"<notice>mod</notice>")
    report = oss_android.scan(str(root))
    it = next(i for i in report.items if i.oss_name == "mod")
    assert it.notice_status == "ok(NA)"
    assert report.info["scanners"]["android"]["notice_source"] == "out/NOTICE.xml.gz"
