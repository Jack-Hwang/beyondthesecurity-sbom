"""SOURCE scanner: FOSSLight Source Scanner behaviour, reimplemented offline - see bts_sbom._internal.oss_source."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom._internal import oss_source

MIT_TEXT = ("MIT License\n\nCopyright (c) 2024 Example Author\n\n"
           "Permission is hereby granted, free of charge, to any person obtaining a copy "
           "of this software and associated documentation files (the \"Software\"), to deal "
           "in the Software without restriction...\n")

GPL2_TEXT = ("                    GNU GENERAL PUBLIC LICENSE\n"
            "                       Version 2, June 1991\n\n"
            "This program is distributed in the hope that it will be useful under the terms "
            "of the GNU GENERAL PUBLIC LICENSE Version 2 as published by the Free Software "
            "Foundation.\n")


def _write(tmp_path, rel, content, binary=False):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    if binary:
        p.write_bytes(content)
    else:
        p.write_text(content, encoding="utf-8", newline="")  # no CRLF translation on Windows
    return p


def _item(report, path):
    return next(i for i in report.items if i.source_path == path.replace("\\", "/"))


# =================================================================================== license text detection
def test_spdx_tag_detected_with_file_line_evidence(tmp_path):
    _write(tmp_path, "src/foo.py", "# SPDX-License-Identifier: Apache-2.0\nprint('hi')\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/foo.py")
    assert it.licenses == ["Apache-2.0"]
    assert any("SPDX-License-Identifier tag (Apache-2.0) at src/foo.py:1" in e for e in it.evidence)
    assert it.exclude is False


def test_mit_header_text_detected_in_a_plain_source_file(tmp_path):
    _write(tmp_path, "src/bar.py", "'''\n" + MIT_TEXT + "\n'''\nprint('ok')\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/bar.py")
    assert it.licenses == ["MIT"]
    assert any("license header/notice text signature" in e for e in it.evidence)


def test_gpl_header_text_detected(tmp_path):
    _write(tmp_path, "src/baz.c", "/*\n" + GPL2_TEXT + "\n*/\nint main(){return 0;}\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/baz.c")
    assert it.licenses == ["GPL-2.0-only"]


# ====================================================================================== REUSE layout
def test_reuse_layout_supplies_the_components_own_license_text(tmp_path):
    _write(tmp_path, "LICENSES/MIT.txt", MIT_TEXT)
    _write(tmp_path, "src/reuse.c",
          "// SPDX-License-Identifier: MIT\n// SPDX-FileCopyrightText: 2024 Jane Doe\nint x;\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/reuse.c")
    assert it.licenses == ["MIT"]
    assert "SPDX-FileCopyrightText: 2024 Jane Doe" in it.copyright
    assert it.extra["license_texts"]["MIT"].strip() == MIT_TEXT.strip()
    assert any("REUSE license file" in e for e in it.evidence)


# ====================================================================================== copyright variants
def test_copyright_variants_are_captured_and_deduplicated(tmp_path):
    _write(tmp_path, "src/cr.js",
          "// Copyright (c) 2020 Alice Holder\n"
          "// (C) 2021 Bob Holder\n"
          "// Copyright (c) 2020 Alice Holder\n"  # duplicate, must collapse
          "console.log('x');\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/cr.js")
    assert "Alice Holder" in it.copyright and "Bob Holder" in it.copyright
    assert it.copyright.count("Alice Holder") == 1
    assert it.licenses == [], "no license text/tag here - never guessed"


def test_spdx_filecopyrighttext_tag_is_captured(tmp_path):
    _write(tmp_path, "src/cr2.js", "// SPDX-FileCopyrightText: 2022 Carol Holder\nconsole.log('x');\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/cr2.js")
    assert "SPDX-FileCopyrightText: 2022 Carol Holder" in it.copyright


# ====================================================================================== default exclusions
@pytest.mark.parametrize("path,expected_reason", [
    ("tests/sample.py", "test directory"),
    ("docs/readme_helper.py", "documentation directory"),
    ("sub/.hidden/inner.py", "hidden directory"),
    ("Makefile", "build script"),
])
def test_default_exclusions_are_flagged_not_dropped(tmp_path, path, expected_reason):
    _write(tmp_path, path, "plain content, no license text here\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, path)
    assert it.exclude is True
    assert expected_reason in it.comment
    scanners = r.info["scanners"]["source"]
    assert scanners["excluded_by_default"].get(expected_reason, 0) >= 1


def test_binary_file_is_flagged_excluded_and_not_content_scanned(tmp_path):
    _write(tmp_path, "bin/data.bin", b"\x00\x01\x02binary\xffpayload" * 10, binary=True)
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "bin/data.bin")
    assert it.exclude is True and "binary file" in it.comment
    assert it.licenses == [] and it.copyright == ""
    assert r.info["scanners"]["source"]["files_binary_skipped"] == 1


# ====================================================================================== sbom-info.yaml corrections
def test_sbom_info_yaml_at_root_corrects_a_matching_item(tmp_path):
    _write(tmp_path, "src/lib.c", "// SPDX-License-Identifier: MIT\nint x;\n")
    _write(tmp_path, "sbom-info.yaml", """
mylib:
- version: "2.0"
  source name or path:
  - "src/lib.c"
  license: [MIT]
  comment: confirmed by hand
""")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/lib.c")
    assert it.oss_name == "mylib" and it.version == "2.0"
    assert "confirmed by hand" in it.comment
    assert r.info["scanners"]["source"]["corrections"]["corrected"] == 1


def test_correction_false_disables_corrections(tmp_path):
    _write(tmp_path, "src/lib.c", "// SPDX-License-Identifier: MIT\nint x;\n")
    _write(tmp_path, "sbom-info.yaml", """
mylib:
- version: "2.0"
  source name or path:
  - "src/lib.c"
  license: [MIT]
""")
    r = oss_source.scan(str(tmp_path), correction=False)
    it = _item(r, "src/lib.c")
    assert it.oss_name == ""
    assert "corrections" not in r.info["scanners"]["source"]


def test_correction_accepts_an_explicit_path(tmp_path):
    _write(tmp_path, "src/lib.c", "// SPDX-License-Identifier: MIT\nint x;\n")
    alt = _write(tmp_path, "elsewhere/custom-sbom-info.yaml", """
mylib:
- version: "9.9"
  source name or path:
  - "src/lib.c"
  license: [MIT]
""")
    r = oss_source.scan(str(tmp_path), correction=str(alt))
    assert _item(r, "src/lib.c").version == "9.9"


def test_malformed_sbom_info_yaml_raises_correction_error(tmp_path):
    _write(tmp_path, "src/lib.c", "// SPDX-License-Identifier: MIT\nint x;\n")
    _write(tmp_path, "sbom-info.yaml", "pkg:\n- license: MIT\n")  # missing required 'version' key
    from bts_sbom import ossreport
    with pytest.raises(ossreport.CorrectionError):
        oss_source.scan(str(tmp_path))


# ====================================================================================== package identity
def test_package_metadata_is_inferred_from_the_nearest_enclosing_manifest(tmp_path):
    _write(tmp_path, "package.json",
          json.dumps({"name": "demo-pkg", "version": "1.2.3", "homepage": "https://example.com/demo",
                     "repository": {"type": "git", "url": "git+https://example.com/demo.git"}}))
    _write(tmp_path, "src/index.js", "// SPDX-License-Identifier: MIT\nmodule.exports = {};\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/index.js")
    assert it.oss_name == "demo-pkg" and it.version == "1.2.3"
    assert it.homepage == "https://example.com/demo"
    assert it.download_location == "https://example.com/demo.git"
    assert any("package identity from package.json" in e for e in it.evidence)


def test_malformed_package_json_leaves_identity_empty_not_crashing(tmp_path):
    _write(tmp_path, "package.json", "{ not valid json ")
    _write(tmp_path, "src/index.js", "// SPDX-License-Identifier: MIT\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/index.js")
    assert it.oss_name == ""  # never guessed


# ====================================================================================== notice / license text
def test_notice_and_license_text_are_captured_from_the_package_directory(tmp_path):
    _write(tmp_path, "package.json", json.dumps({"name": "demo", "version": "1.0.0"}))
    _write(tmp_path, "LICENSE", MIT_TEXT)
    _write(tmp_path, "NOTICE", "This product includes software developed by Example Corp.\n")
    _write(tmp_path, "src/a.py", "# SPDX-License-Identifier: MIT\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/a.py")
    assert it.extra["license_texts"]["MIT"].strip() == MIT_TEXT.strip()
    assert "Example Corp" in it.extra["notice_file"]


def test_huge_license_file_is_bounded_to_200kb(tmp_path):
    huge = MIT_TEXT + ("A" * 500_000)
    _write(tmp_path, "LICENSE", huge)
    _write(tmp_path, "src/a.py", "# SPDX-License-Identifier: MIT\n")
    r = oss_source.scan(str(tmp_path))
    it = _item(r, "src/a.py")
    assert len(it.extra["license_texts"]["MIT"]) <= 200_000


def test_truncated_flag_and_warning_when_max_files_is_hit(tmp_path):
    for n in range(5):
        _write(tmp_path, "src/f%d.py" % n, "# SPDX-License-Identifier: MIT\n")
    r = oss_source.scan(str(tmp_path), max_files=2)
    assert r.info["scanners"]["source"]["truncated"] is True
    assert any("truncated" in w for w in r.warnings)


# ====================================================================================== symlinks (hostile input)
def _can_symlink(tmp_path):
    try:
        target = tmp_path / "_sym_target.txt"
        target.write_text("x", encoding="utf-8")
        link = tmp_path / "_sym_test"
        os.symlink(str(target), str(link))
        link.unlink()
        target.unlink()
        return True
    except (OSError, NotImplementedError):
        return False


def test_symlinked_source_file_is_never_followed(tmp_path):
    if not _can_symlink(tmp_path):
        pytest.skip("symlinks are not permitted in this environment")
    outside = tmp_path.parent / "oss_source_secret.txt"
    outside.write_text("SECRET\n# SPDX-License-Identifier: MIT\n", encoding="utf-8")
    try:
        (tmp_path / "src").mkdir(parents=True, exist_ok=True)
        os.symlink(str(outside), str(tmp_path / "src" / "linked.py"))
        r = oss_source.scan(str(tmp_path))
        assert not any(i.source_path == "src/linked.py" for i in r.items)
        assert r.info["scanners"]["source"]["symlinks_skipped"] >= 1
    finally:
        if outside.exists():
            outside.unlink()


def test_symlinked_reuse_license_file_is_never_read(tmp_path):
    if not _can_symlink(tmp_path):
        pytest.skip("symlinks are not permitted in this environment")
    outside = tmp_path.parent / "oss_source_secret_license.txt"
    outside.write_text("TOP SECRET LICENSE TEXT\n", encoding="utf-8")
    try:
        (tmp_path / "LICENSES").mkdir(parents=True, exist_ok=True)
        os.symlink(str(outside), str(tmp_path / "LICENSES" / "MIT.txt"))
        _write(tmp_path, "src/reuse.c", "// SPDX-License-Identifier: MIT\n")
        r = oss_source.scan(str(tmp_path))
        it = _item(r, "src/reuse.c")
        texts = it.extra.get("license_texts", {})
        assert "SECRET" not in json.dumps(texts)
    finally:
        if outside.exists():
            outside.unlink()


# ====================================================================================== scancode engine
def test_scancode_engine_with_injected_runner_maps_findings(tmp_path):
    _write(tmp_path, "src/a.py", "print('hi')\n")
    canned = {"files": [{"path": "src/a.py", "type": "file",
                        "licenses": [{"spdx_license_key": "MIT"}],
                        "copyrights": [{"copyright": "Copyright 2020 Someone"}]}]}

    def fake_runner(cmd):
        assert cmd[0] == "scancode"
        return 0, json.dumps(canned)

    r = oss_source.scan(str(tmp_path), engine="scancode", runner=fake_runner)
    assert r.info["scanners"]["source"]["engine"] == "scancode"
    it = _item(r, "src/a.py")
    assert it.licenses == ["MIT"] and "Someone" in it.copyright
    assert it.evidence == ["scancode"]


def test_scancode_engine_missing_tool_warns_and_does_not_fall_back(tmp_path, monkeypatch):
    monkeypatch.setattr(oss_source.shutil, "which", lambda _name: None)
    _write(tmp_path, "src/a.py", "# SPDX-License-Identifier: MIT\n")
    r = oss_source.scan(str(tmp_path), engine="scancode")
    assert r.items == []
    assert r.info["scanners"]["source"]["available"] is False
    assert any("scancode" in w for w in r.warnings)


def test_unknown_engine_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        oss_source.scan(str(tmp_path), engine="nope")



def test_vendored_code_with_its_own_license_does_not_inherit_the_enclosing_package(tmp_path):
    from bts_sbom._internal import oss_source
    (tmp_path / "package.json").write_text('{"name": "mine", "version": "1.0.0"}', encoding="utf-8")
    (tmp_path / "LICENSE").write_text("MIT License\nPermission is hereby granted, free of charge", encoding="utf-8")
    (tmp_path / "own.c").write_text("/* SPDX-License-Identifier: MIT */\n", encoding="utf-8")
    v = tmp_path / "third_party" / "zlib"
    v.mkdir(parents=True)
    (v / "LICENSE").write_text("zlib License\n(C) Jean-loup Gailly", encoding="utf-8")
    (v / "z.c").write_text("/* SPDX-License-Identifier: Zlib */\n", encoding="utf-8")
    rep = oss_source.scan(str(tmp_path), correction=False)
    own = next(i for i in rep.items if i.source_path == "own.c")
    vend = next(i for i in rep.items if i.source_path == "third_party/zlib/z.c")
    assert (own.oss_name, own.version) == ("mine", "1.0.0")
    assert (vend.oss_name, vend.version) == ("", "") and any("NOT inherited" in e for e in vend.evidence)


def test_sbom_info_yaml_is_not_analysed_as_source(tmp_path):
    from bts_sbom._internal import oss_source
    (tmp_path / "sbom-info.yaml").write_text("libfoo:\n- version: '1'\n  copyright text: Copyright (C) 2020 Foo\n", encoding="utf-8")
    rep = oss_source.scan(str(tmp_path), correction=False)
    it = next(i for i in rep.items if i.source_path == "sbom-info.yaml")
    assert it.exclude and "correction file" in it.comment
