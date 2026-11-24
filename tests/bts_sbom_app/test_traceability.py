"""AC | EARS pattern | spec section (module) | test traceability matrix (BSA-AC-381..387, 400).

Every test here builds its OWN fake ``specs/bts_sbom_app_features.md`` + ``tests/bts_sbom_app/`` + ``bts_sbom_app/``
tree under ``tmp_path`` - never the real repository - except the one real-repo smoke test (BSA-AC-400), which only
checks that the tool processes the real spec without crashing and names every real AC id at least once (no AC
count is asserted, because that count changes as other packages add their own AC lines).
"""
from __future__ import annotations

import json
import os

from bts_sbom_app import cli, speclint, traceability
from conftest import ROOT


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _spec(root, text):
    _write(root / "specs" / "bts_sbom_app_features.md", text)


def _test_file(root, name, text):
    _write(root / "tests" / "bts_sbom_app" / name, text)


def _module(root, name):
    _write(root / "bts_sbom_app" / name, "")


def test_trace_output_is_byte_identical_across_two_runs(tmp_path):
    """AC: BSA-AC-381"""
    _spec(tmp_path, "## Demo (bts_sbom_app/a.py)\n\n- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n")
    _test_file(tmp_path, "test_demo.py", 'def test_one():\n    """AC: BSA-AC-1"""\n    assert True\n')
    r1 = traceability.build(str(tmp_path))
    r2 = traceability.build(str(tmp_path))
    assert r1 == r2
    assert traceability.render_md(r1) == traceability.render_md(r2)
    assert traceability.render_json(r1) == traceability.render_json(r2)


def test_untested_ac_is_listed_and_the_tested_one_is_not(tmp_path):
    """AC: BSA-AC-382"""
    _spec(tmp_path, "## Demo (bts_sbom_app/a.py)\n\n"
                    "- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n"
                    "- BSA-AC-2 [Event] When it runs twice it shall report 2 things.\n")
    _test_file(tmp_path, "test_demo.py", 'def test_one():\n    """AC: BSA-AC-1"""\n    assert True\n')
    result = traceability.build(str(tmp_path))
    assert result["summary"]["untested_acs"] == ["BSA-AC-2"]
    row1 = next(r for r in result["rows"] if r["id"] == "BSA-AC-1")
    assert row1["tests"] == ["tests/bts_sbom_app/test_demo.py::test_one"]


def test_test_reference_to_an_unknown_ac_is_reported_without_a_row(tmp_path):
    """AC: BSA-AC-383"""
    _spec(tmp_path, "## Demo (bts_sbom_app/a.py)\n\n- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n")
    _test_file(tmp_path, "test_demo.py",
               'def test_one():\n    """AC: BSA-AC-1"""\n    assert True\n\n\n'
               'def test_extra():\n    """AC: BSA-AC-99"""\n    assert True\n')
    result = traceability.build(str(tmp_path))
    assert result["summary"]["unknown_test_refs"] == ["BSA-AC-99"]
    assert [r["id"] for r in result["rows"]] == ["BSA-AC-1"]


def test_module_named_by_no_section_is_reported_undeclared(tmp_path):
    """AC: BSA-AC-384"""
    _spec(tmp_path, "## Demo (bts_sbom_app/a.py)\n\n- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n")
    _module(tmp_path, "a.py")
    _module(tmp_path, "b.py")
    result = traceability.build(str(tmp_path))
    assert result["summary"]["undeclared_modules"] == ["bts_sbom_app/b.py"]


def test_state_pattern_warning_only_when_absent(tmp_path):
    """AC: BSA-AC-385"""
    r1, r2 = tmp_path / "no_state", tmp_path / "has_state"
    _spec(r1, "## Demo (bts_sbom_app/a.py)\n\n- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n")
    _spec(r2, "## Demo (bts_sbom_app/a.py)\n\n"
              "- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n"
              "- BSA-AC-2 [State] While it is running it shall keep reporting 1 thing per second.\n")
    assert traceability.build(str(r1))["summary"]["state_pattern_warning"] != ""
    assert traceability.build(str(r2))["summary"]["state_pattern_warning"] == ""


def test_pattern_counts_sum_to_the_ac_count(tmp_path):
    """AC: BSA-AC-386"""
    _spec(tmp_path, "## Demo (bts_sbom_app/a.py)\n\n"
                    "- BSA-AC-1 [Ubiquitous] The system shall always report 1 thing.\n"
                    "- BSA-AC-2 [Event] When asked it shall report 1 thing.\n"
                    "- BSA-AC-3 [Event] When asked twice it shall report 2 things.\n"
                    "- BSA-AC-4 [State] While busy it shall keep reporting 1 thing.\n"
                    "- BSA-AC-5 [Optional] Where configured it shall report 1 extra thing.\n"
                    "- BSA-AC-6 [Unwanted] If broken it shall report 0 things.\n")
    s = traceability.build(str(tmp_path))["summary"]
    assert s["ac_count"] == 6
    assert sum(s["pattern_counts"].values()) == 6
    assert s["pattern_counts"] == {"Ubiquitous": 1, "Event": 2, "State": 1, "Optional": 1, "Unwanted": 1}


def test_cli_trace_writes_md_and_json_files(tmp_path):
    """AC: BSA-AC-387"""
    _spec(tmp_path, "## Demo (bts_sbom_app/a.py)\n\n- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n")
    out_md, out_json = tmp_path / "trace.md", tmp_path / "trace.json"
    assert cli.main(["--root", str(tmp_path), "trace", "--format", "md", "--out", str(out_md)]) == 0
    assert cli.main(["--root", str(tmp_path), "trace", "--format", "json", "--out", str(out_json)]) == 0
    md_text = out_md.read_text(encoding="utf-8")
    assert "| AC | Pattern | Section | Modules | Tests |" in md_text and "BSA-AC-1" in md_text
    parsed = json.loads(out_json.read_text(encoding="utf-8"))
    assert parsed["summary"]["ac_count"] == 1


def test_cli_trace_covers_every_real_ac_id_without_asserting_their_count():
    """AC: BSA-AC-400"""
    spec_path = os.path.join(ROOT, "specs", "bts_sbom_app_features.md")
    ids = speclint.parse(spec_path)
    assert "BSA-AC-381" in ids                                    # this package's own ACs are in the real spec
    import tempfile
    with tempfile.TemporaryDirectory() as td:
        out_md, out_json = os.path.join(td, "trace.md"), os.path.join(td, "trace.json")
        assert cli.main(["--root", ROOT, "trace", "--format", "md", "--out", out_md]) == 0
        assert cli.main(["--root", ROOT, "trace", "--format", "json", "--out", out_json]) == 0
        with open(out_md, "r", encoding="utf-8") as fh:
            md_text = fh.read()
        with open(out_json, "r", encoding="utf-8") as fh:
            json_text = fh.read()
    missing_md = [i for i in ids if i not in md_text]
    missing_json = [i for i in ids if i not in json_text]
    assert not missing_md and not missing_json
