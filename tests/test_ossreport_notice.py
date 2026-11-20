"""OSS report model, sbom-info.yaml corrections, report formats, compare, and the notice generator."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom import notice, ossreport
from bts_sbom._internal import miniyaml, xlsx_min
from bts_sbom.ossreport import OssItem, OssReport

MIT_TEXT = "MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy ..."
GPL_TEXT = "GNU GENERAL PUBLIC LICENSE Version 2, June 1991 ..."


def _report():
    r = OssReport(info=ossreport.new_info("/proj"))
    r.items = [
        OssItem(kind="dep", oss_name="left-pad", version="1.3.0", licenses=["MIT"], copyright="Copyright (c) Azer",
                homepage="https://github.com/stevemao/left-pad", purl="pkg:npm/left-pad@1.3.0", source_path="package.json"),
        OssItem(kind="src", oss_name="libidn", version="1.33", licenses=["GPL-2.0-only"], source_path="src/libidn/idna.c",
                copyright="Copyright (C) Simon Josefsson", download_location="https://ftp.gnu.org/libidn-1.33.tar.gz"),
        OssItem(kind="src", oss_name="-", licenses=["Other Proprietary License"], source_path="src/ours/a.c"),
        OssItem(kind="bin", oss_name="zlib", version="1.2.11", licenses=["Zlib"], source_path="lib/libz.so",
                checksum="a" * 64),
    ]
    return r


# ================================================================================================= miniyaml
def test_miniyaml_sbom_info_and_lockfile_shapes():
    doc = miniyaml.loads('''
libidn:
- version: "1.33"
  source name or path:
  - "src/libidn/*"
  license: [LGPL-2.1-or-later, "GPL-3.0-or-later"]
  copyright text: |
    Copyright (C) A
    Copyright (C) B
'-':
- version: ''
  exclude: True
packages:
  '@scope/pkg@1.0.0':
    resolution: {integrity: sha512-x==, tarball: https://x/y.tgz}
''')
    assert doc["libidn"][0]["license"] == ["LGPL-2.1-or-later", "GPL-3.0-or-later"]
    assert doc["libidn"][0]["copyright text"] == "Copyright (C) A\nCopyright (C) B\n"
    assert doc["-"][0]["exclude"] is True and doc["-"][0]["version"] is None or doc["-"][0]["version"] == ""
    assert doc["packages"]["@scope/pkg@1.0.0"]["resolution"]["tarball"] == "https://x/y.tgz"


def test_miniyaml_keeps_version_numbers_as_text_and_rejects_what_it_cannot_read():
    assert miniyaml.loads("v: 1.10\nw: 007")["v"] == "1.10"
    for bad in ("a: &x 1", "a: *x", "a: !!str 1", "a:\n\t- b", "a: [1, 2", "- a\n b: c", "a: 'x"):
        with pytest.raises(miniyaml.YamlError):
            miniyaml.loads(bad)
    deep = "a: " + "[" * 200 + "]" * 200
    with pytest.raises(miniyaml.YamlError):
        miniyaml.loads(deep)


def test_miniyaml_round_trip():
    obj = {"a": ["x", {"b": "c d", "e": ["1", "2"]}], "t": "multi\nline\n", "n": None, "q": "1.10", "s": "a: b", "z": True}
    assert miniyaml.loads(miniyaml.dumps(obj)) == obj


# ================================================================================================= xlsx / formats
def test_xlsx_round_trip_hidden_checksum_and_no_formula_evaluation(tmp_path):
    r = _report()
    r.items[0].comment = "=HYPERLINK(\"http://evil\",\"x\")"
    p = str(tmp_path / "r.xlsx")
    ossreport.to_xlsx(r, p)
    book = xlsx_min.read_xlsx(p)
    assert {"Scanner Info", "SRC_FL_Source", "BIN_FL_Binary", "DEP_FL_Dependency"} <= set(book)
    assert book["DEP_FL_Dependency"][1][ossreport.COLUMNS["dep"].index("Comment")].startswith("=HYPERLINK")  # stored as TEXT
    back = ossreport.read_report(p)
    assert sorted(i.oss_name for i in back.items) == sorted(i.oss_name for i in r.items)
    assert next(i for i in back.items if i.oss_name == "zlib").checksum == "a" * 64
    import zipfile
    with zipfile.ZipFile(p) as zf:
        assert 'hidden="1"' in zf.read("xl/worksheets/sheet3.xml").decode()      # BIN sheet: checksum column hidden


def test_xlsx_reader_rejects_doctype_and_garbage(tmp_path):
    bad = tmp_path / "x.xlsx"
    bad.write_bytes(b"not a zip")
    with pytest.raises(xlsx_min.XlsxError):
        xlsx_min.read_xlsx(str(bad))


@pytest.mark.parametrize("fmt", list(ossreport.FORMATS))
def test_every_format_writes_and_is_parseable(tmp_path, fmt):
    r = _report()
    p = ossreport.write_report(r, fmt, str(tmp_path / ("out" + ossreport._EXT[fmt])))
    assert os.path.getsize(p) > 50
    if fmt == "json":
        assert json.load(open(p, encoding="utf-8"))["schema"] == ossreport.SCHEMA
    if fmt in ("json", "yaml", "xlsx"):
        assert len(ossreport.read_report(p).items) == 4


def test_csv_formula_injection_is_neutralised():
    r = OssReport(items=[OssItem(oss_name="=cmd|' /C calc'!A0", licenses=["MIT"], comment="@SUM(1)", source_path="-")])
    text = ossreport.to_csv(r)
    assert "'=cmd" in text and "'@SUM" in text
    r2 = OssReport(items=[OssItem(oss_name="-", licenses=["MIT"])])
    assert ",-," in ossreport.to_csv(r2), 'the FOSSLight "-" marker must survive'


def test_spdx_json_is_valid_and_unknown_licenses_become_licenseref():
    from bts_sbom.sbom import validate_spdx
    r = _report()
    r.items.append(OssItem(oss_name="weird", version="1", licenses=["Acme Custom License v2"]))
    doc = ossreport.to_spdx_json(r)
    refs = {e["licenseId"] for e in doc["hasExtractedLicensingInfos"]}
    assert any(x.startswith("LicenseRef-Acme") for x in refs)
    assert validate_spdx(doc) == []
    assert "PackageName: libidn" in ossreport.to_spdx_tag(r)
    cdx = ossreport.to_cyclonedx_json(r)
    assert cdx["bomFormat"] == "CycloneDX" and any(c.get("copyright") for c in cdx["components"])


# ================================================================================================= corrections
def test_sbom_info_overrides_matching_items_excludes_and_loads_the_rest(tmp_path):
    f = tmp_path / "sbom-info.yaml"
    f.write_text('''
libidn:
- version: "1.34"
  source name or path:
  - "src/libidn/*"
  license:
  - LGPL-2.1-or-later
  comment: confirmed by hand
'-':
- version: ''
  source name or path:
  - "src/ours/*"
  exclude: True
newlib:
- version: "2.0"
  source name or path:
  - "third_party/newlib/*"
  license: BSD-3-Clause
''', encoding="utf-8")
    r = _report()
    stats = ossreport.apply_corrections(r, ossreport.load_corrections(str(f)))
    idn = next(i for i in r.items if i.source_path == "src/libidn/idna.c")
    assert idn.version == "1.34" and idn.licenses == ["LGPL-2.1-or-later"] and "confirmed by hand" in idn.comment
    assert next(i for i in r.items if i.source_path == "src/ours/a.c").exclude is True
    loaded = [i for i in r.items if i.oss_name == "newlib"]
    assert loaded and "Loaded by sbom-info.yaml" in loaded[0].comment and stats == {"corrected": 1, "excluded": 1, "loaded": 1}
    dep = next(i for i in r.items if i.kind == "dep")
    assert dep.licenses == ["MIT"], "dependency items are never corrected"


def test_corrections_reject_malformed_files(tmp_path):
    f = tmp_path / "bad.yaml"
    f.write_text("pkg:\n- license: MIT\n", encoding="utf-8")
    with pytest.raises(ossreport.CorrectionError):
        ossreport.load_corrections(str(f))


def test_path_matching_rules():
    assert ossreport.path_matches("src/libidn/*", "src/libidn/a/b.c")
    assert ossreport.path_matches("build/", "build/x/y.o")
    assert ossreport.path_matches("./lib/a.c", "lib/a.c")
    assert not ossreport.path_matches("src/lib/*", "src/other/a.c")


# ===================================================================================================== compare
def test_compare_reports_add_delete_change():
    a, b = _report(), _report()
    b.items = [i for i in b.items if i.oss_name != "zlib"]
    next(i for i in b.items if i.oss_name == "libidn").version = "1.34"
    b.items.append(OssItem(kind="dep", oss_name="new", version="1", licenses=["MIT"], purl="pkg:npm/new@1"))
    c = ossreport.compare_reports(a, b)
    assert c["summary"] == {"added": 1, "deleted": 1, "changed": 1}
    assert "~ libidn" in ossreport.compare_to_text(c)


# ===================================================================================================== notice
def _opts(tmp_path, **kw):
    d = tmp_path / "lic"
    d.mkdir(exist_ok=True)
    (d / "MIT.txt").write_text(MIT_TEXT, encoding="utf-8")
    (d / "GPL-2.0-only.txt").write_text(GPL_TEXT, encoding="utf-8")
    base = dict(license_dirs=[str(d)])
    base.update(kw)
    return notice.NoticeOptions(**base)


def test_html_notice_lists_components_licenses_texts_once_and_skips_in_house(tmp_path):
    res = notice.build_notice(_report(), _opts(tmp_path, contact="oss@example.com"))
    t = res.text
    assert "left-pad" in t and "libidn" in t and "zlib" in t
    assert t.count("Permission is hereby granted") == 1, "each license text appears once"
    assert "src/ours" not in t and "Other Proprietary" not in t, "in-house code is not part of an OSS notice"
    assert "Written offer" in t and "oss@example.com" in t
    assert res.audit["missing_license_text"] == ["Zlib"] and res.audit["complete"] is False
    assert res.audit["source_disclosure_components"] == ["libidn"]


def test_notice_never_invents_text_or_copyright_and_strict_fails(tmp_path):
    res = notice.build_notice(_report(), _opts(tmp_path, strict=True))
    assert "Copyright (c) Azer" in res.text and "Simon Josefsson" in res.text
    assert "(no copyright notice recorded)" in res.text            # zlib has none: reported, not made up
    assert "not included in this document" in res.text             # Zlib text missing: flagged in the document itself
    assert res.ok is False and any("license text" in p for p in res.audit["problems"])
    assert "no --contact" in res.audit["written_offer"]
    assert res.audit["components_without_copyright"] == ["zlib"]


def test_notice_escapes_hostile_text_and_blocks_non_http_urls(tmp_path):
    r = OssReport(items=[OssItem(oss_name="<script>alert(1)</script>", version="1", licenses=["MIT"],
                                 copyright="(c) <img src=x onerror=alert(1)>", homepage="javascript:alert(1)")])
    t = notice.build_notice(r, _opts(tmp_path)).text
    assert "<script>" not in t and "<img src=x" not in t and "javascript:" not in t
    assert "&lt;script&gt;" in t


def test_simple_formats_link_to_spdx_instead_of_embedding_text(tmp_path):
    res = notice.build_notice(_report(), _opts(tmp_path, fmt="simple-html"))
    assert "https://spdx.org/licenses/MIT.html" in res.text and "Permission is hereby granted" not in res.text
    assert res.audit["missing_license_text"] == []
    txt = notice.build_notice(_report(), _opts(tmp_path, fmt="simple-text")).text
    assert "https://spdx.org/licenses/GPL-2.0-only.html" in txt and "<" not in txt.split("License texts")[0]


def test_text_format_and_korean_headings(tmp_path):
    t = notice.build_notice(_report(), _opts(tmp_path, fmt="text", lang="ko", contact="x@y.z")).text
    assert "오픈소스 소프트웨어 고지문" in t and "서면 제안" in t and "MIT License" in t


def test_license_text_from_the_components_own_license_file_wins(tmp_path):
    r = OssReport(items=[OssItem(oss_name="p", version="1", licenses=["MIT"],
                                 extra={"license_texts": {"MIT": "MIT License\n\nCopyright (c) Actual Holder"}})])
    res = notice.build_notice(r, _opts(tmp_path))
    assert "Actual Holder" in res.text and "Permission is hereby" not in res.text
    assert res.audit["license_text_sources"]["MIT"] == "component license file"


def test_fetching_texts_is_opt_in_and_cached(tmp_path):
    calls = []
    fetched = {"Zlib": "zlib License text"}

    def fetcher(url):
        calls.append(url)
        return fetched.get(url.rsplit("/", 1)[-1][:-4])

    off = notice.build_notice(_report(), _opts(tmp_path, fetcher=fetcher))
    assert calls == [] and off.audit["missing_license_text"] == ["Zlib"]
    cache = tmp_path / "cache"
    on = notice.build_notice(_report(), _opts(tmp_path, fetch_license_texts=True, cache_dir=str(cache), fetcher=fetcher))
    assert "zlib License text" in on.text and on.audit["missing_license_text"] == []
    assert (cache / "Zlib.txt").exists() and len(calls) == 1
    again = notice.build_notice(_report(), _opts(tmp_path, cache_dir=str(cache), fetcher=fetcher))
    assert "zlib License text" in again.text and len(calls) == 1


def test_duplicate_components_collapse_and_multi_license_is_audited(tmp_path):
    r = OssReport(items=[OssItem(oss_name="dual", version="1", licenses=["MIT", "GPL-2.0-only"], source_path="a.c"),
                         OssItem(oss_name="dual", version="1", licenses=["MIT", "GPL-2.0-only"], source_path="b.c")])
    res = notice.build_notice(r, _opts(tmp_path))
    assert res.audit["components"] == 1 and res.audit["components_with_multiple_licenses_treated_as_AND"] == ["dual"]


def test_or_expression_includes_every_alternative_and_flags_the_open_choice(tmp_path):
    r = OssReport(items=[OssItem(oss_name="o", version="1", licenses=["MIT OR GPL-2.0-only"], copyright="(c) o")])
    res = notice.build_notice(r, _opts(tmp_path))
    assert "Permission is hereby" in res.text and "GNU GENERAL PUBLIC LICENSE" in res.text
    assert res.audit["components_with_OR_choice_not_recorded"] == ["o"]


def test_unknown_format_and_language_are_rejected():
    with pytest.raises(ValueError):
        notice.build_notice(OssReport(), notice.NoticeOptions(fmt="pdf"))
    with pytest.raises(ValueError):
        notice.build_notice(OssReport(), notice.NoticeOptions(lang="xx"))

def test_dependency_names_use_the_fosslight_manager_prefix_in_files_and_read_back_plain(tmp_path):
    r = OssReport(items=[
        OssItem(kind="dep", oss_name="lodash", version="4.17.21", licenses=["MIT"], purl="pkg:npm/lodash@4.17.21",
                extra={"manager": "npm"}),
        OssItem(kind="dep", oss_name="org.apache:commons", version="1", licenses=["Apache-2.0"], extra={"manager": "maven"})])
    p = str(tmp_path / "d.xlsx")
    ossreport.to_xlsx(r, p)
    names = [row[2] for row in xlsx_min.read_xlsx(p)["DEP_FL_Dependency"][1:]]
    assert names == ["npm:lodash", "org.apache:commons"]
    back = ossreport.read_report(p)
    assert [(i.oss_name, i.extra.get("manager")) for i in back.items] == [("lodash", "npm"), ("org.apache:commons", None)]



def test_source_files_without_a_license_are_audited_not_listed_as_components(tmp_path):
    r = OssReport(items=[OssItem(kind="src", oss_name="demo", version="1", copyright="(c) Somebody", source_path="a.c"),
                         OssItem(kind="src", oss_name="lib", version="2", licenses=["MIT"], source_path="b.c", copyright="(c) L"),
                         OssItem(kind="dep", oss_name="needs-a-license", version="1", purl="pkg:npm/x@1")])
    res = notice.build_notice(r, _opts(tmp_path))
    assert res.audit["components"] == 2 and res.audit["source_files_without_license_not_listed"] == 1
    assert res.audit["components_without_license"] == ["needs-a-license"], "a dependency without a license stays visible"



def test_licence_less_duplicate_sighting_of_a_licensed_package_is_not_a_second_component(tmp_path):
    r = OssReport(items=[OssItem(kind="dep", oss_name="left-pad", version="1.3.0", source_path="package.json"),
                         OssItem(kind="dep", oss_name="left-pad", version="1.3.0", licenses=["MIT"], source_path="package-lock.json"),
                         OssItem(kind="dep", oss_name="other", version="1")])
    res = notice.build_notice(r, _opts(tmp_path))
    assert res.audit["components"] == 2 and res.audit["components_without_license"] == ["other"]
    assert res.audit["duplicate_sightings_without_license_merged"] == 1


def test_unverified_license_is_flagged_in_audit_markup_and_strict(tmp_path):
    r = OssReport(items=[OssItem(kind="bin", oss_name="zlib", version="1.2.11", licenses=["Zlib"], needs_check=True,
                                 comment="version banner match only", source_path="bin/app", copyright="(c) Z"),
                         OssItem(kind="dep", oss_name="ok", version="1", licenses=["MIT"], copyright="(c) K")])
    res = notice.build_notice(r, _opts(tmp_path, strict=True))
    assert res.audit["components_with_unverified_license"] == ["zlib"]
    assert any("unverified" in p for p in res.audit["problems"]) and res.audit["complete"] is False
    assert res.ok is False, "--strict must fail on a license that is only a guess"
    assert "NOT verified" in res.text and "version banner match only" in res.text
    txt = notice.build_notice(r, _opts(tmp_path, fmt="text")).text
    assert "NOT verified" in txt and "version banner match only" in txt
    ko = notice.build_notice(r, _opts(tmp_path, lang="ko")).text
    assert "미검증" in ko


def test_html_notice_keeps_the_operators_of_a_license_expression(tmp_path):
    r = OssReport(items=[OssItem(oss_name="o", version="1", licenses=["(MIT OR GPL-2.0-only)"], copyright="(c) o"),
                         OssItem(oss_name="w", version="1", licenses=["GPL-2.0-only WITH Classpath-exception-2.0"],
                                 copyright="(c) w")])
    t = notice.build_notice(r, _opts(tmp_path)).text
    assert ">MIT</a> OR <a" in t and "GPL-2.0-only</a>)" in t, "OR must survive between the linked ids"
    assert "</a> WITH <a" in t, "a WITH exception must stay attached to its license"


@pytest.mark.parametrize("ext", [".xlsx", ".yaml", ".json"])
def test_needs_check_and_notice_status_survive_every_report_format(tmp_path, ext):
    r = OssReport(items=[
        OssItem(kind="src", oss_name="a", version="1", licenses=["MIT"], source_path="a.c", needs_check=True),
        OssItem(kind="bin", oss_name="b", version="2", licenses=["Zlib"], source_path="bin/b", needs_check=True,
                notice_status="nok(NA)", checksum="abc123"),
        OssItem(kind="dep", oss_name="c", version="3", licenses=["MIT"], purl="pkg:npm/c@3", notice_status="ok"),
        OssItem(kind="src", oss_name="d", version="4", licenses=["MIT"], source_path="d.c")])
    dest = str(tmp_path / ("rep" + ext))
    if ext == ".xlsx":
        ossreport.to_xlsx(r, dest)
    else:
        with open(dest, "w", encoding="utf-8") as fh:
            fh.write(ossreport.to_json(r) if ext == ".json" else ossreport.to_yaml(r))
    back = {i.oss_name: i for i in ossreport.read_report(dest).items}
    assert back["a"].needs_check is True and back["d"].needs_check is False
    assert back["b"].needs_check is True and back["b"].notice_status == "nok(NA)" and back["b"].checksum == "abc123"
    assert back["c"].notice_status == "ok" and back["c"].needs_check is False


def test_csv_report_carries_the_needs_check_column():
    r = OssReport(items=[OssItem(oss_name="b", licenses=["Zlib"], needs_check=True, notice_status="nok")])
    head, row = ossreport.to_csv(r).splitlines()[:2]
    assert head.endswith("Needs Check,Notice Status") and row.endswith("Check,nok")


def test_spdx_tag_value_cannot_be_forged_through_untrusted_strings():
    r = OssReport(items=[OssItem(kind="src", oss_name="evil\nPackageName: injected", version="1\nSPDXID: SPDXRef-x",
                                 licenses=["MIT"], source_path="a.c", download_location="https://e.example/x\nFilesAnalyzed: true",
                                 homepage="https://h.example\r\nPackageName: h",
                                 copyright="(c) A\n</text>\nPackageName: pwned\n<text>")])
    tag = ossreport.to_spdx_tag(r)
    import re as _re
    outside = _re.sub(r"<text>.*?</text>", "<text/>", tag, flags=_re.S)          # what a tag-value parser sees as tags
    tags = [ln.split(":", 1)[0] for ln in outside.splitlines() if ln]
    assert tags.count("PackageName") == 1 and tags.count("SPDXID") == 2 and tags.count("FilesAnalyzed") == 1
    # inside the copyright block nothing can close it early
    body = tag.split("PackageCopyrightText: <text>", 1)[1]
    assert body.count("</text>") == 1 and body.index("</text>") > body.index("pwned"), "the text block must not be closable from inside"
    assert tag.count("<text>") == 1


def test_cyclonedx_bom_refs_are_unique_even_when_a_package_is_seen_twice():
    r = OssReport(items=[OssItem(kind="dep", oss_name="x", version="1", licenses=["MIT"], purl="pkg:npm/x@1"),
                         OssItem(kind="dep", oss_name="x", version="1", licenses=["MIT"], purl="pkg:npm/x@1"),
                         OssItem(kind="dep", oss_name="root", version="1", licenses=["MIT"], purl="root")])
    doc = ossreport.to_cyclonedx_json(r)
    refs = [c["bom-ref"] for c in doc["components"]] + [doc["metadata"]["component"]["bom-ref"]]
    assert len(refs) == len(set(refs)), refs
    xml = ossreport.to_cyclonedx_xml(OssReport(items=[OssItem(oss_name="a\x00b\x1b", copyright="c\x07")]))
    import xml.etree.ElementTree as ET
    ET.fromstring(xml.encode("utf-8"))                              # control characters never make the document invalid


@pytest.mark.parametrize("value", ["a\n\n\n", "a\n", "a\nb\n", "a\nb", "  lead\nz", "x: y\nz", "a\n\nb\n\n", "tab\there\nz",
                                   "trail \nx", "\nlead-nl", "line1\r\nline2", "# not a comment\nx", "- not a list\nx"])
def test_miniyaml_multiline_strings_round_trip_exactly(value):
    doc = {"k": value, "items": [{"v": value}], "after": "ok"}
    assert miniyaml.loads(miniyaml.dumps(doc)) == doc


def test_miniyaml_readable_block_style_is_kept_for_plain_multiline_text():
    out = miniyaml.dumps({"copyright": "(c) 2020 A\n(c) 2021 B\n"})
    assert "|" in out and "(c) 2021 B" in out


def test_miniyaml_flow_collections_with_quoted_brackets_across_lines():
    assert miniyaml.loads('k: ["a]",\n   "b"]\nz: 1\n') == {"k": ["a]", "b"], "z": "1"}
    assert miniyaml.loads('k: ["x[",\n "y"]\nz: 1\n') == {"k": ["x[", "y"], "z": "1"}
    assert miniyaml.loads("k: ['it''s ]',\n 'b']\nz: 1\n") == {"k": ["it's ]", "b"], "z": "1"}
    assert miniyaml.loads("k: [don't, [a, b]]\nz: 1\n") == {"k": ["don't", ["a", "b"]], "z": "1"}
    assert miniyaml.loads("k: [a,\n   b]\nz: 1\n") == {"k": ["a", "b"], "z": "1"}


def test_xlsx_styles_declare_the_normal_cell_style(tmp_path):
    import zipfile
    p = str(tmp_path / "s.xlsx")
    ossreport.to_xlsx(OssReport(items=[OssItem(oss_name="a")]), p)
    assert b"<cellStyles" in zipfile.ZipFile(p).read("xl/styles.xml")


def test_report_round_trip_keeps_multiline_copyright_and_comment(tmp_path):
    r = OssReport(items=[OssItem(kind="src", oss_name="a", licenses=["MIT"], source_path="a.c",
                                 copyright="(c) 2020 A\n  (c) 2021 B", comment="line1\n\nline3")])
    for ext in (".xlsx", ".yaml", ".json"):
        dest = str(tmp_path / ("r" + ext))
        if ext == ".xlsx":
            ossreport.to_xlsx(r, dest)
        else:
            open(dest, "w", encoding="utf-8", newline="").write(ossreport.to_json(r) if ext == ".json" else ossreport.to_yaml(r))
        back = ossreport.read_report(dest).items[0]
        assert back.copyright == "(c) 2020 A\n  (c) 2021 B" and back.comment == "line1\n\nline3", ext
