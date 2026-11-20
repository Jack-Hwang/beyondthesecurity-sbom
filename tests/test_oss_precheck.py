"""REUSE-style precheck: lint, add_headers, convert, download_licenses, scan -- all offline, all on tmp_path trees."""
from __future__ import annotations

import os

import pytest

from bts_sbom import ossreport
from bts_sbom._internal import oss_precheck


def _write(tmp_path, rel, content, encoding="utf-8"):
    """Write exactly ``content`` (no newline translation) so byte-level production code sees what the test wrote."""
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(str(p), "w", encoding=encoding, newline="") as fh:
        fh.write(content)
    return p


def _write_bytes(tmp_path, rel, data: bytes):
    p = tmp_path / rel
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_bytes(data)
    return p


# ============================================================================================================ lint
def test_lint_compliant_tree_with_header_tags(tmp_path):
    _write(tmp_path, "src/a.py", "# SPDX-FileCopyrightText: 2024 Jane Doe\n# SPDX-License-Identifier: MIT\nprint(1)\n")
    _write(tmp_path, "LICENSES/MIT.txt", "MIT License text ...\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["compliant"] is True
    assert res["missing_copyright"] == res["missing_license"] == res["missing_both"] == []
    assert res["license_texts_missing"] == []
    assert res["licenses"] == {"MIT": 1}
    assert res["files_checked"] == 1


def test_lint_missing_declarations_are_bucketed(tmp_path):
    _write(tmp_path, "a.py", "# SPDX-FileCopyrightText: 2024 Jane Doe\nprint(1)\n")   # copyright, no license
    _write(tmp_path, "b.py", "# SPDX-License-Identifier: MIT\nprint(1)\n")             # license, no copyright
    _write(tmp_path, "c.py", "print(1)\n")                                             # neither
    res = oss_precheck.lint(str(tmp_path))
    assert res["compliant"] is False
    assert res["missing_license"] == ["a.py"]
    assert res["missing_copyright"] == ["b.py"]
    assert res["missing_both"] == ["c.py"]
    assert res["files_checked"] == 3


def test_lint_sidecar_license_file_covers_the_primary_file(tmp_path):
    _write(tmp_path, "data.csv", "a,b,c\n1,2,3\n")
    _write(tmp_path, "data.csv.license", "SPDX-FileCopyrightText: 2022 Example Co\nSPDX-License-Identifier: CC0-1.0\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["missing_both"] == [] and res["missing_copyright"] == [] and res["missing_license"] == []
    assert res["licenses"] == {"CC0-1.0": 1}
    assert res["files_checked"] == 1, "the sidecar .license file itself is not a file subject to the rule"


def test_lint_dep5_coverage(tmp_path):
    _write(tmp_path, ".reuse/dep5", """Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: demo

Files: third_party/lib/*
Copyright: 2015 Someone Else
License: Apache-2.0
""")
    _write(tmp_path, "third_party/lib/a.c", "int main(void) { return 0; }\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["missing_both"] == [] and "third_party/lib/a.c" not in res["missing_copyright"] + res["missing_license"]
    assert res["licenses"] == {"Apache-2.0": 1}
    assert res["license_texts_missing"] == ["Apache-2.0"], "no LICENSES/Apache-2.0.txt was provided"


def test_lint_reuse_toml_coverage(tmp_path):
    _write(tmp_path, "REUSE.toml", """version = 1

[[annotations]]
path = "src/vendor/*"
SPDX-FileCopyrightText = "2020 Vendor Inc."
SPDX-License-Identifier = "BSD-3-Clause"
""")
    _write(tmp_path, "src/vendor/a.c", "int x;\n")
    _write(tmp_path, "LICENSES/BSD-3-Clause.txt", "BSD text\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["missing_both"] == [] and res["license_texts_missing"] == []
    assert res["licenses"] == {"BSD-3-Clause": 1}


def test_lint_reuse_toml_fallback_without_tomllib(tmp_path, monkeypatch):
    monkeypatch.setattr(oss_precheck, "tomllib", None)
    _write(tmp_path, "REUSE.toml", """version = 1

[[annotations]]
path = "src/vendor/*"
SPDX-FileCopyrightText = "2020 Vendor Inc."
SPDX-License-Identifier = "BSD-3-Clause"
""")
    _write(tmp_path, "src/vendor/a.c", "int x;\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["licenses"] == {"BSD-3-Clause": 1}, "the regex fallback must find the same annotation"


def test_lint_malformed_reuse_toml_does_not_crash(tmp_path):
    _write(tmp_path, "REUSE.toml", "version = 1\n[[annotations]\npath = unterminated string\n")
    _write(tmp_path, "a.py", "print(1)\n")
    res = oss_precheck.lint(str(tmp_path))          # must not raise
    assert res["files_checked"] == 1
    assert res["missing_both"] == ["a.py"]


def test_lint_malformed_dep5_is_tolerant(tmp_path):
    _write(tmp_path, ".reuse/dep5", "this is not : a valid\n   stanza at all\n\n\xff\xfe garbage\n")
    _write(tmp_path, "a.py", "print(1)\n")
    res = oss_precheck.lint(str(tmp_path))          # must not raise
    assert res["files_checked"] == 1


def test_lint_default_exclusions(tmp_path):
    _write(tmp_path, ".git/config", "junk")
    _write(tmp_path, "node_modules/pkg/index.js", "junk")
    _write(tmp_path, "venv/lib/site.py", "junk")
    _write(tmp_path, "assets/logo.png", "not really png bytes")
    _write(tmp_path, "src/ok.py", "# SPDX-FileCopyrightText: 2024 A\n# SPDX-License-Identifier: MIT\nprint(1)\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["files_checked"] == 1
    assert res["excluded"].get("hidden directory", 0) >= 1
    assert res["excluded"].get("node_modules", 0) == 1
    assert res["excluded"].get("venv", 0) == 1
    assert res["excluded"].get("binary or generated file", 0) == 1


def test_lint_binary_content_without_a_recognised_extension_is_excluded(tmp_path):
    _write_bytes(tmp_path, "weird.dat", b"\x00\x01\x02\x03binary stuff")
    res = oss_precheck.lint(str(tmp_path))
    assert res["files_checked"] == 0
    assert res["excluded"].get("binary content", 0) == 1


def test_lint_invalid_utf8_header_does_not_crash(tmp_path):
    _write_bytes(tmp_path, "weird.py", b"# comment with invalid bytes: \xff\xfe not valid utf-8\nprint(1)\n")
    res = oss_precheck.lint(str(tmp_path))          # must not raise despite the undecodable bytes
    assert res["files_checked"] == 1
    assert res["missing_both"] == ["weird.py"]


def test_lint_never_follows_a_symlink(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("# SPDX-FileCopyrightText: 2024 A\n# SPDX-License-Identifier: MIT\n", encoding="utf-8")
    link = tmp_path / "link.py"
    os.symlink(str(target), str(link))
    res = oss_precheck.lint(str(tmp_path))
    assert res["files_checked"] == 1, "the symlink itself must not be scanned as a second file"
    assert any("symlink" in w for w in res["warnings"])


def test_lint_sbom_info_exclude_true_removes_matching_paths(tmp_path):
    _write(tmp_path, "sbom-info.yaml", """'-':
- version: ''
  source name or path:
  - "generated/*"
  exclude: True
""")
    _write(tmp_path, "generated/out.py", "print(1)\n")
    _write(tmp_path, "src/ok.py", "# SPDX-FileCopyrightText: 2024 A\n# SPDX-License-Identifier: MIT\nprint(1)\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["sbom_info_files"] == ["sbom-info.yaml"]
    assert res["excluded"].get("excluded by sbom-info.yaml", 0) == 1
    assert res["files_checked"] == 1, "only src/ok.py (not sbom-info.yaml, not generated/out.py) is checked"


def test_lint_malformed_sbom_info_is_reported_not_raised(tmp_path):
    _write(tmp_path, "sbom-info.yaml", "pkg:\n- license: MIT\n")     # missing required 'version' key
    res = oss_precheck.lint(str(tmp_path))           # must not raise
    assert any("sbom-info.yaml" in w for w in res["warnings"])


def test_lint_hostile_license_id_is_never_turned_into_a_path_escape(tmp_path):
    _write(tmp_path, "a.py", "# SPDX-FileCopyrightText: 2024 A\n# SPDX-License-Identifier: ../../../evil\nprint(1)\n")
    res = oss_precheck.lint(str(tmp_path))
    assert "../../../evil" not in res["license_texts_missing"]
    assert any("not a safe file name" in w for w in res["warnings"])
    assert not os.path.exists(tmp_path.parent / "evil.txt")


def test_lint_include_hidden_opts_into_scanning_hidden_files(tmp_path):
    _write(tmp_path, ".hidden.py", "print(1)\n")
    default_res = oss_precheck.lint(str(tmp_path))
    assert default_res["files_checked"] == 0
    opt_res = oss_precheck.lint(str(tmp_path), include_hidden=True)
    assert opt_res["files_checked"] == 1
    assert opt_res["missing_both"] == [".hidden.py"]


# ============================================================================================================ scan
def test_scan_returns_an_ossreport_with_scanner_info(tmp_path):
    _write(tmp_path, "a.py", "# SPDX-FileCopyrightText: 2024 A\n# SPDX-License-Identifier: MIT\nprint(1)\n")
    _write(tmp_path, "b.py", "print(1)\n")
    report = oss_precheck.scan(str(tmp_path), excludes=("c/*",))
    assert isinstance(report, ossreport.OssReport)
    names = {i.source_path: i for i in report.items}
    assert names["a.py"].licenses == ["MIT"] and names["a.py"].evidence
    assert "REUSE precheck" in names["b.py"].comment
    info = report.info["scanners"]["precheck"]
    assert info["files_checked"] == 2 and info["compliant"] is False
    assert report.info["excluded"] == ["c/*"]
    assert any("b.py" in w for w in report.warnings)


# ===================================================================================================== add_headers
def test_add_headers_dry_run_does_not_write(tmp_path):
    p = _write(tmp_path, "a.py", "print(1)\n")
    before = p.read_bytes()
    out = oss_precheck.add_headers(str(tmp_path), ["a.py"], license="MIT", copyright="2024 Jane Doe")
    assert out[0]["action"] == "would add" and out[0]["written"] is False
    assert p.read_bytes() == before, "dry_run defaults to True and must never write"


def test_add_headers_hash_style_with_shebang_preserved(tmp_path):
    p = _write(tmp_path, "a.py", "#!/usr/bin/env python\nprint(1)\n")
    out = oss_precheck.add_headers(str(tmp_path), ["a.py"], license="MIT", copyright="2024 Jane Doe", dry_run=False)
    text = p.read_text(encoding="utf-8")
    lines = text.splitlines()
    assert lines[0] == "#!/usr/bin/env python"
    assert lines[1] == "# SPDX-FileCopyrightText: 2024 Jane Doe"
    assert lines[2] == "# SPDX-License-Identifier: MIT"
    assert "print(1)" in text
    assert out[0]["written"] is True and out[0]["style"] == "hash"


def test_add_headers_slash_style_no_shebang(tmp_path):
    p = _write(tmp_path, "a.js", "console.log(1);\n")
    oss_precheck.add_headers(str(tmp_path), ["a.js"], license="Apache-2.0", copyright="2024 A", dry_run=False)
    lines = p.read_text(encoding="utf-8").splitlines()
    assert lines[0] == "// SPDX-FileCopyrightText: 2024 A"
    assert lines[1] == "// SPDX-License-Identifier: Apache-2.0"
    assert lines[-1] == "console.log(1);"


def test_add_headers_block_c_style_for_css(tmp_path):
    p = _write(tmp_path, "a.css", "body{color:red}\n")
    oss_precheck.add_headers(str(tmp_path), ["a.css"], license="MIT", copyright="2024 A", dry_run=False)
    text = p.read_text(encoding="utf-8")
    assert "/*" in text and " * SPDX-FileCopyrightText: 2024 A" in text and " * SPDX-License-Identifier: MIT" in text
    assert text.index("/*") < text.index("body{color:red}")


def test_add_headers_xml_style_preserves_xml_declaration(tmp_path):
    p = _write(tmp_path, "a.xml", '<?xml version="1.0" encoding="UTF-8"?>\n<root/>\n')
    oss_precheck.add_headers(str(tmp_path), ["a.xml"], license="MIT", copyright="2024 A", dry_run=False,
                             download_location="https://example.com/a")
    lines = p.read_text(encoding="utf-8").splitlines()
    assert lines[0] == '<?xml version="1.0" encoding="UTF-8"?>'
    assert lines[1] == "<!--"
    assert "SPDX-FileCopyrightText: 2024 A" in lines[2]
    assert "SPDX-PackageDownloadLocation: https://example.com/a" in lines[4]
    assert "<root/>" in lines


def test_add_headers_dash_and_semi_styles(tmp_path):
    sql = _write(tmp_path, "a.sql", "SELECT 1;\n")
    lisp = _write(tmp_path, "a.lisp", "(print 1)\n")
    oss_precheck.add_headers(str(tmp_path), ["a.sql", "a.lisp"], license="MIT", copyright="2024 A", dry_run=False)
    assert sql.read_text(encoding="utf-8").splitlines()[0] == "-- SPDX-FileCopyrightText: 2024 A"
    assert lisp.read_text(encoding="utf-8").splitlines()[0] == ";; SPDX-FileCopyrightText: 2024 A"


def test_add_headers_preserves_crlf(tmp_path):
    p = tmp_path / "a.py"
    with open(str(p), "wb") as fh:
        fh.write(b"print(1)\r\nprint(2)\r\n")
    oss_precheck.add_headers(str(tmp_path), ["a.py"], license="MIT", copyright="2024 A", dry_run=False)
    raw = p.read_bytes()
    assert b"\r\n# SPDX-License-Identifier: MIT\r\n" in raw
    assert b"\n\n" not in raw.replace(b"\r\n", b"")[:0] or True   # sanity: no exception raised above
    assert raw.count(b"\n") == raw.count(b"\r\n"), "every newline stayed CRLF"


def test_add_headers_preserves_bom(tmp_path):
    p = tmp_path / "a.py"
    with open(str(p), "wb") as fh:
        fh.write(b"\xef\xbb\xbfprint(1)\n")
    oss_precheck.add_headers(str(tmp_path), ["a.py"], license="MIT", copyright="2024 A", dry_run=False)
    raw = p.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")
    assert b"# SPDX-License-Identifier: MIT" in raw


def test_add_headers_skips_files_that_already_declare_tags(tmp_path):
    original = "# SPDX-FileCopyrightText: 2019 Someone\n# SPDX-License-Identifier: Apache-2.0\nprint(1)\n"
    p = _write(tmp_path, "a.py", original)
    out = oss_precheck.add_headers(str(tmp_path), ["a.py"], license="MIT", copyright="2024 A", dry_run=False)
    assert out[0]["reason"] == "already declares SPDX tags" and out[0]["written"] is False
    assert p.read_text(encoding="utf-8") == original


def test_add_headers_skips_files_covered_by_a_sidecar(tmp_path):
    p = _write(tmp_path, "a.bin.py", "print(1)\n")
    _write(tmp_path, "a.bin.py.license", "SPDX-FileCopyrightText: 2019 Someone\nSPDX-License-Identifier: Apache-2.0\n")
    out = oss_precheck.add_headers(str(tmp_path), ["a.bin.py"], license="MIT", copyright="2024 A", dry_run=False)
    assert "sidecar" in out[0]["reason"] and out[0]["written"] is False


def test_add_headers_skips_binary_files(tmp_path):
    _write_bytes(tmp_path, "a.py", b"\x00\x01binary")
    out = oss_precheck.add_headers(str(tmp_path), ["a.py"], license="MIT", copyright="2024 A", dry_run=False)
    assert out[0]["reason"] == "binary file"


def test_add_headers_skips_unknown_extensions(tmp_path):
    _write(tmp_path, "a.unknownext", "whatever\n")
    out = oss_precheck.add_headers(str(tmp_path), ["a.unknownext"], license="MIT", copyright="2024 A", dry_run=False)
    assert "no known comment style" in out[0]["reason"]


def test_add_headers_refuses_path_traversal(tmp_path):
    (tmp_path / "inside").mkdir()
    outside = tmp_path.parent / ("outside_%s.py" % tmp_path.name)
    out = oss_precheck.add_headers(str(tmp_path / "inside"), ["../../%s" % outside.name],
                                   license="MIT", copyright="2024 A", dry_run=False)
    assert out[0]["written"] is False and "escapes root" in out[0]["reason"]
    assert not outside.exists()


def test_add_headers_refuses_to_follow_or_write_through_a_symlink(tmp_path):
    target = tmp_path / "target.py"
    target.write_text("print(1)\n", encoding="utf-8")
    link = tmp_path / "link.py"
    os.symlink(str(target), str(link))
    out = oss_precheck.add_headers(str(tmp_path), ["link.py"], license="MIT", copyright="2024 A", dry_run=False)
    assert out[0]["written"] is False and "symlink" in out[0]["reason"]
    assert target.read_text(encoding="utf-8") == "print(1)\n", "the symlink target must stay untouched"


def test_add_headers_leaves_oversized_files_untouched(tmp_path, monkeypatch):
    monkeypatch.setattr(oss_precheck, "MAX_HEADER_FILE_SIZE", 10)
    p = _write(tmp_path, "a.py", "print(1)\nprint(2)\nprint(3)\n")   # > 10 bytes
    before = p.read_bytes()
    out = oss_precheck.add_headers(str(tmp_path), ["a.py"], license="MIT", copyright="2024 A", dry_run=False)
    assert "larger than" in out[0]["reason"] and out[0]["written"] is False
    assert p.read_bytes() == before


def test_add_headers_missing_file_is_reported(tmp_path):
    out = oss_precheck.add_headers(str(tmp_path), ["does_not_exist.py"], license="MIT", copyright="2024 A")
    assert out[0]["reason"] == "not a regular file"


def test_add_headers_write_cannot_be_redirected_by_a_path_swapped_after_the_check(tmp_path, monkeypatch):
    """TOCTOU: the checked path is replaced by a symlink to a file outside the root just before it is opened."""
    outside = tmp_path / "outside"
    outside.mkdir()
    victim = outside / "victim.py"
    victim.write_text("print('victim')\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    target = root / "a.py"
    target.write_text("print(1)\n", encoding="utf-8")
    real_open = os.open
    swapped = []

    def swapping_open(path, flags, *a, **kw):
        if os.path.normcase(str(path)) == os.path.normcase(str(target)) and not swapped:
            swapped.append(True)
            os.remove(str(target))
            os.symlink(str(victim), str(target))
        return real_open(path, flags, *a, **kw)

    monkeypatch.setattr(os, "open", swapping_open)
    try:
        out = oss_precheck.add_headers(str(root), ["a.py"], license="MIT", copyright="2024 A", dry_run=False)
    except OSError:
        out = [{"written": False}]       # O_NOFOLLOW platforms refuse the open outright - also a pass
    assert swapped, "the race was not exercised"
    assert out[0]["written"] is False
    assert victim.read_text(encoding="utf-8") == "print('victim')\n", "the file outside the root must stay untouched"


def test_add_headers_refuses_to_write_a_hard_linked_file(tmp_path):
    outside = tmp_path / "elsewhere.py"
    outside.write_text("print('x')\n", encoding="utf-8")
    root = tmp_path / "root"
    root.mkdir()
    link = root / "a.py"
    try:
        os.link(str(outside), str(link))
    except (OSError, NotImplementedError):
        pytest.skip("hard links are not available here")
    out = oss_precheck.add_headers(str(root), ["a.py"], license="MIT", copyright="2024 A", dry_run=False)
    assert out[0]["written"] is False and "hard-linked" in out[0]["reason"]
    assert outside.read_text(encoding="utf-8") == "print('x')\n"
    # a dry run only reads, so it is allowed to report what it would do
    out = oss_precheck.add_headers(str(root), ["a.py"], license="MIT", copyright="2024 A", dry_run=True)
    assert out[0]["action"] == "would add"


def test_lint_keeps_the_with_exception_and_requires_its_text(tmp_path):
    _write(tmp_path, "src/a.java",
           "// SPDX-FileCopyrightText: 2024 Jane Doe\n"
           "// SPDX-License-Identifier: GPL-2.0-only WITH Classpath-exception-2.0\n")
    _write(tmp_path, "LICENSES/GPL-2.0-only.txt", "GPL text\n")
    res = oss_precheck.lint(str(tmp_path))
    assert "GPL-2.0-only WITH Classpath-exception-2.0" in res["licenses"]
    assert "Classpath-exception-2.0" in res["license_texts_missing"], "the exception text is required too"
    assert "GPL-2.0-only" not in res["license_texts_missing"]
    assert res["compliant"] is False
    _write(tmp_path, "LICENSES/Classpath-exception-2.0.txt", "exception text\n")
    res = oss_precheck.lint(str(tmp_path))
    assert res["license_texts_missing"] == [] and res["compliant"] is True


# ========================================================================================================= convert
def test_convert_builds_one_item_per_path(tmp_path):
    _write(tmp_path, "sbom-info.yaml", """left-pad:
- version: "1.3.0"
  source name or path:
  - "package.json"
  license:
  - MIT
newlib:
- version: "2.0"
  source name or path:
  - "third_party/newlib/a.c"
  - "third_party/newlib/b.c"
  license: BSD-3-Clause
""")
    report = oss_precheck.convert(str(tmp_path))
    assert len(report.items) == 3
    paths = sorted(i.source_path for i in report.items)
    assert paths == ["package.json", "third_party/newlib/a.c", "third_party/newlib/b.c"]
    assert all("sbom-info.yaml" in i.evidence[0] for i in report.items)
    info = report.info["scanners"]["precheck_convert"]
    assert info["version_blocks"] == 2 and info["items"] == 3
    assert info["sbom_info_files_found"] == ["sbom-info.yaml"]


def test_convert_with_no_sbom_info_file_warns_and_is_empty(tmp_path):
    report = oss_precheck.convert(str(tmp_path))
    assert report.items == []
    assert any("no sbom-info.yaml" in w for w in report.warnings)


def test_convert_malformed_sbom_info_is_reported_not_raised(tmp_path):
    _write(tmp_path, "oss-pkg-info.yaml", "pkg:\n- license: MIT\n")    # missing required 'version'
    report = oss_precheck.convert(str(tmp_path))                      # must not raise
    assert report.items == []
    assert any("oss-pkg-info.yaml" in w for w in report.warnings)


# =============================================================================================== download_licenses
def test_download_licenses_offline_by_default_does_not_fetch(tmp_path):
    calls = []

    def fetcher(url):
        calls.append(url)
        return "should never be used"

    res = oss_precheck.download_licenses(str(tmp_path), ["MIT"], fetcher=fetcher)
    assert calls == [] and res == {"written": [], "skipped_existing": [], "skipped_offline": ["MIT"],
                                   "invalid_id": [], "failed": []}
    assert not (tmp_path / "LICENSES").exists()


def test_download_licenses_online_with_injected_fetcher_writes_the_file(tmp_path):
    def fetcher(url):
        assert url.endswith("/MIT.txt")
        return "MIT License text\n"

    res = oss_precheck.download_licenses(str(tmp_path), ["MIT"], online=True, fetcher=fetcher)
    assert res["written"] == ["MIT"]
    assert (tmp_path / "LICENSES" / "MIT.txt").read_text(encoding="utf-8") == "MIT License text\n"


def test_download_licenses_never_overwrites_an_existing_file(tmp_path):
    licdir = tmp_path / "LICENSES"
    licdir.mkdir()
    (licdir / "MIT.txt").write_text("ORIGINAL TEXT\n", encoding="utf-8")
    calls = []

    def fetcher(url):
        calls.append(url)
        return "FETCHED TEXT\n"

    res = oss_precheck.download_licenses(str(tmp_path), ["MIT"], online=True, fetcher=fetcher)
    assert res["skipped_existing"] == ["MIT"] and calls == []
    assert (licdir / "MIT.txt").read_text(encoding="utf-8") == "ORIGINAL TEXT\n"


def test_download_licenses_rejects_hostile_ids(tmp_path):
    res = oss_precheck.download_licenses(str(tmp_path), ["../../evil", "", "has space", "MIT"], online=True,
                                         fetcher=lambda url: "text\n")
    assert "../../evil" in res["invalid_id"] and "" in res["invalid_id"] and "has space" in res["invalid_id"]
    assert res["written"] == ["MIT"]
    assert not (tmp_path.parent / "evil.txt").exists()


def test_download_licenses_failed_fetch_is_reported(tmp_path):
    res = oss_precheck.download_licenses(str(tmp_path), ["GPL-2.0-only"], online=True, fetcher=lambda url: None)
    assert res["failed"] == ["GPL-2.0-only"]
    assert not (tmp_path / "LICENSES" / "GPL-2.0-only.txt").exists()


def test_download_licenses_caps_huge_fetched_text(tmp_path, monkeypatch):
    monkeypatch.setattr(oss_precheck, "MAX_LICENSE_TEXT", 10)
    res = oss_precheck.download_licenses(str(tmp_path), ["MIT"], online=True, fetcher=lambda url: "0123456789" * 50)
    assert res["written"] == ["MIT"]
    text = (tmp_path / "LICENSES" / "MIT.txt").read_text(encoding="utf-8")
    assert len(text) <= 11          # capped length + trailing newline
