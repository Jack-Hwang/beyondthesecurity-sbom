"""Traceability matrix determinism + gap detection (task 5b, AC 381-385)."""
from __future__ import annotations

import os

from bts_sbom_app import traceability

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

NL = chr(10)
Q3 = chr(34) * 3
# citation strings are assembled so THIS file itself never carries a plain "AC: BSA-AC-n" reference
C901 = "AC" + ": BSA-AC-901"
C903 = "BSA-AC-903"                                   # second id in the same citation: bare id, no AC: prefix
C999 = "AC" + ": BSA-AC-999"
C904 = "AC" + ": BSA-AC-904"


def _fake_root(tmp_path):
    """A tiny spec + test tree with one known gap per case."""
    root = str(tmp_path)
    os.makedirs(os.path.join(root, "specs"), exist_ok=True)
    os.makedirs(os.path.join(root, "tests"), exist_ok=True)
    os.makedirs(os.path.join(root, "bts_sbom_app"), exist_ok=True)
    spec = (NL.join([
        "## Alpha section (alpha.py)",
        "",
        "- BSA-AC-901 [Event] When x happens, the system shall do y (1 of 1).",
        "- BSA-AC-902 [State] While x holds, the system shall do y (1 of 1).",
        "- BSA-AC-903 [Event] When z happens, the system shall do w (2 of 2).",
        "",
        "## Beta section (alpha.py, beta.py)",
        "",
        "- BSA-AC-904 [Unwanted] If q, the system shall not r (0 occurrences).",
        "",
    ]))
    open(os.path.join(root, "specs", "bts_sbom_app_features.md"), "w", encoding="utf-8", newline=NL).write(spec)
    tests = NL.join([
        "from bts_sbom_app import speclint",
        "",
        "",
        "def test_cites_901_and_903():",
        "    " + Q3 + C901 + ", " + C903 + Q3,
        "",
        "",
        "def test_cites_unknown():",
        "    " + Q3 + C999 + Q3,
        "",
        "",
        "def test_cites_904():",
        "    " + Q3 + C904 + Q3,
        "",
    ])
    open(os.path.join(root, "tests", "test_alpha.py"), "w", encoding="utf-8", newline=NL).write(tests)
    open(os.path.join(root, "bts_sbom_app", "alpha.py"), "w", encoding="utf-8", newline=NL).write("x = 1" + NL)
    open(os.path.join(root, "bts_sbom_app", "beta.py"), "w", encoding="utf-8", newline=NL).write("y = 2" + NL)
    open(os.path.join(root, "bts_sbom_app", "gamma.py"), "w", encoding="utf-8", newline=NL).write("z = 3" + NL)
    return root


def test_the_matrix_is_byte_identical_across_two_runs(tmp_path):
    """AC: BSA-AC-381"""
    root = _fake_root(tmp_path)
    a = traceability.render_md(traceability.build(root))
    b = traceability.render_md(traceability.build(root))
    assert a == b
    ja = traceability.render_json(traceability.build(root))
    jb = traceability.render_json(traceability.build(root))
    assert ja == jb


def test_one_ac_without_a_test_is_reported(tmp_path):
    """AC: BSA-AC-382"""
    root = _fake_root(tmp_path)
    m = traceability.build(root)
    assert m["summary"]["without_test"] == 1                       # BSA-AC-902 is cited by no test
    assert "BSA-AC-902" in [r["ac"] for r in m["rows"] if not r["tests"]]


def test_a_test_citing_an_unknown_ac_is_listed(tmp_path):
    """AC: BSA-AC-383"""
    root = _fake_root(tmp_path)
    m = traceability.build(root)
    assert m["summary"]["unknown_refs"] == 1


def test_a_module_in_no_section_is_listed(tmp_path):
    """AC: BSA-AC-384"""
    root = _fake_root(tmp_path)
    m = traceability.build(root)
    assert "gamma.py" in m["summary"]["unspecified_modules"]
    assert "alpha.py" not in m["summary"]["unspecified_modules"]
    assert "beta.py" not in m["summary"]["unspecified_modules"]


def test_zero_state_patterns_raise_the_warning(tmp_path):
    """AC: BSA-AC-385"""
    root = _fake_root(tmp_path)
    spec_path = os.path.join(root, "specs", "bts_sbom_app_features.md")
    text = open(spec_path, encoding="utf-8").read().replace("[State]", "[Event]")
    open(spec_path, "w", encoding="utf-8", newline=NL).write(text)
    m = traceability.build(root)
    assert m["summary"]["state_pattern_warning"], "0 State-pattern ACs must warn"


def test_the_real_repo_matrix_builds():
    """The tool handles the real spec (variable counts are not asserted)."""
    m = traceability.build(REPO)
    assert m["summary"]["acs"] > 300 and m["summary"]["without_test"] == 0
