"""Doc lint: ADRs, governance docs, runbook, enforcement map. Pure string-in/problems-out checks, plus the
enforcement map's dangling-reference check against a small real file tree, and a final pass over this repository's
own docs/ in --strict mode (the lint this package ships must actually pass on what it ships)."""
from __future__ import annotations

import os
import re

import pytest

from bts_sbom_app import doclint

# ---------------------------------------------------------------- complete, passing documents (one per kind)
ADR_OK = """# ADR-0099: Example decision

## Status

Accepted.

## 근거 (Context)

Some context.

## 결정 (Decision)

Some decision.

## 기각 대안 (Rejected alternatives)

- Option A, rejected because of reason A.

## 결과 (Consequences)

Some consequence.
"""

IMPACT_OK = """# AI Impact Assessment

## 1. 시스템 개요

text

## 2. 고영향 AI 여부

text

## 3. 이해관계자

text

## 4. 위험 식별

text

## 5. 완화 조치

text

## 6. 사람 감독

text

## 7. 모니터링

text

## 8. 잔여 위험

text
"""

MODELCARD_OK = """# Model Card

## 모델 개요 (Model details)

text

## 사용 목적과 범위 (Intended use)

text

## 데이터·평가 (Evaluation)

text

## 한계 (Limitations)

text

## 윤리·위험 (Risks)

text
"""

LINEAGE_OK = """# Origin Lineage

## 출처 표 (Sources)

text

## 수집 방법 (Collection)

text

## 갱신·신선도 (Freshness)

text

## 실패 시 동작 (Failure behavior)

text

## 이용 조건 (Terms)

text
"""

DATACONTRACT_OK = """# Data Contract

## 스키마 (Schema)

text

## 불변식 (Invariants)

text

## 버전 (Versioning)

text

## 호환 (Compatibility)

text
"""

RUNBOOK_OK = """# Runbook

## Delivery State

text

## Deployment

text

## Rollback

text

## Monitoring

text
"""

ENFORCEMENT_HEADER = "| 위험 | 강제 수단 | 위치 | 검증 테스트 |\n|---|---|---|---|\n"


def _enforcement_row(loc: str, test: str) -> str:
    return "| risk | mechanism | `%s` | `%s` |\n" % (loc, test)


# ================================================================== AC-361
def test_detect_kind_covers_all_seven_kinds():
    """AC: BSA-AC-361"""
    names = {
        "ADR-0007-stdlib-only.md": "adr",
        "AI_IMPACT_ASSESSMENT.md": "impact",
        "MODEL_CARD.md": "modelcard",
        "ORIGIN_LINEAGE.md": "lineage",
        "DATA_CONTRACT.md": "datacontract",
        "RUNBOOK.md": "runbook",
        "ENFORCEMENT_MAP.md": "enforcement",
    }
    got = {name: doclint.detect_kind(name) for name in names}
    assert got == names
    assert sum(1 for name, kind in got.items() if kind == names[name]) == 7


# ================================================================== AC-362
ADR_SECTION_HEADINGS = {
    "Status": "## Status\n\nAccepted.\n",
    "Context": "## 근거 (Context)\n\nSome context.\n",
    "Decision": "## 결정 (Decision)\n\nSome decision.\n",
    "Rejected alternatives": "## 기각 대안 (Rejected alternatives)\n\n- Option A, rejected because of reason A.\n",
    "Consequences": "## 결과 (Consequences)\n\nSome consequence.\n",
}


def _adr_missing(label: str) -> str:
    parts = ["# ADR-0099: Example decision\n"] + [v for k, v in ADR_SECTION_HEADINGS.items() if k != label]
    return "\n".join(parts)


@pytest.mark.parametrize("label", list(ADR_SECTION_HEADINGS))
def test_adr_missing_each_section_reports_one_problem(label):
    """AC: BSA-AC-362"""
    probs = doclint.lint_text(_adr_missing(label), "adr")
    assert len(probs) == 1
    assert "missing section" in probs[0].lower()


def test_adr_complete_document_has_zero_problems():
    """AC: BSA-AC-362"""
    assert doclint.lint_text(ADR_OK, "adr") == []


# ================================================================== AC-363
def test_adr_rejected_alternatives_without_list_item_is_flagged():
    """AC: BSA-AC-363"""
    bad = ADR_OK.replace("- Option A, rejected because of reason A.\n", "No list here, just prose.\n")
    probs_bad = doclint.lint_text(bad, "adr")
    assert len(probs_bad) == 1 and "list item" in probs_bad[0]
    probs_ok = doclint.lint_text(ADR_OK, "adr")
    assert probs_ok == []


# ================================================================== AC-364
IMPACT_LABELS = ["시스템 개요", "고영향 AI 여부", "이해관계자", "위험 식별", "완화 조치", "사람 감독", "모니터링", "잔여 위험"]


def test_impact_all_sections_present_vs_all_absent():
    """AC: BSA-AC-364"""
    assert doclint.lint_text(IMPACT_OK, "impact") == []
    empty = "# AI Impact Assessment\n\nNo sections here at all.\n"
    probs = doclint.lint_text(empty, "impact")
    assert len(probs) == 8


# ================================================================== AC-365
MODELCARD_LABELS = ["Model details", "Intended use", "Evaluation", "Limitations", "Risks"]


def _modelcard_missing(label: str) -> str:
    blocks = {
        "Model details": "## 모델 개요 (Model details)\n\ntext\n",
        "Intended use": "## 사용 목적과 범위 (Intended use)\n\ntext\n",
        "Evaluation": "## 데이터·평가 (Evaluation)\n\ntext\n",
        "Limitations": "## 한계 (Limitations)\n\ntext\n",
        "Risks": "## 윤리·위험 (Risks)\n\ntext\n",
    }
    return "# Model Card\n\n" + "\n".join(v for k, v in blocks.items() if k != label)


@pytest.mark.parametrize("label", MODELCARD_LABELS)
def test_modelcard_each_missing_section(label):
    """AC: BSA-AC-365"""
    assert len(doclint.lint_text(_modelcard_missing(label), "modelcard")) == 1


def test_modelcard_complete_document_has_zero_problems():
    """AC: BSA-AC-365"""
    assert doclint.lint_text(MODELCARD_OK, "modelcard") == []


# ================================================================== AC-366
LINEAGE_LABELS = ["Sources", "Collection", "Freshness", "Failure behavior", "Terms"]


def _lineage_missing(label: str) -> str:
    blocks = {
        "Sources": "## 출처 표 (Sources)\n\ntext\n",
        "Collection": "## 수집 방법 (Collection)\n\ntext\n",
        "Freshness": "## 갱신·신선도 (Freshness)\n\ntext\n",
        "Failure behavior": "## 실패 시 동작 (Failure behavior)\n\ntext\n",
        "Terms": "## 이용 조건 (Terms)\n\ntext\n",
    }
    return "# Origin Lineage\n\n" + "\n".join(v for k, v in blocks.items() if k != label)


@pytest.mark.parametrize("label", LINEAGE_LABELS)
def test_lineage_each_missing_section(label):
    """AC: BSA-AC-366"""
    assert len(doclint.lint_text(_lineage_missing(label), "lineage")) == 1


def test_lineage_complete_document_has_zero_problems():
    """AC: BSA-AC-366"""
    assert doclint.lint_text(LINEAGE_OK, "lineage") == []


# ================================================================== AC-367
DATACONTRACT_LABELS = ["Schema", "Invariants", "Versioning", "Compatibility"]


def _datacontract_missing(label: str) -> str:
    blocks = {
        "Schema": "## 스키마 (Schema)\n\ntext\n",
        "Invariants": "## 불변식 (Invariants)\n\ntext\n",
        "Versioning": "## 버전 (Versioning)\n\ntext\n",
        "Compatibility": "## 호환 (Compatibility)\n\ntext\n",
    }
    return "# Data Contract\n\n" + "\n".join(v for k, v in blocks.items() if k != label)


@pytest.mark.parametrize("label", DATACONTRACT_LABELS)
def test_datacontract_each_missing_section(label):
    """AC: BSA-AC-367"""
    assert len(doclint.lint_text(_datacontract_missing(label), "datacontract")) == 1


def test_datacontract_complete_document_has_zero_problems():
    """AC: BSA-AC-367"""
    assert doclint.lint_text(DATACONTRACT_OK, "datacontract") == []


# ================================================================== AC-368
RUNBOOK_LABELS = ["Delivery State", "Deployment", "Rollback", "Monitoring"]


def _runbook_missing(label: str) -> str:
    blocks = {b: "## %s\n\ntext\n" % b for b in RUNBOOK_LABELS}
    return "# Runbook\n\n" + "\n".join(v for k, v in blocks.items() if k != label)


@pytest.mark.parametrize("label", RUNBOOK_LABELS)
def test_runbook_each_missing_block(label):
    """AC: BSA-AC-368"""
    assert len(doclint.lint_text(_runbook_missing(label), "runbook")) == 1


def test_runbook_complete_document_has_zero_problems():
    """AC: BSA-AC-368"""
    assert doclint.lint_text(RUNBOOK_OK, "runbook") == []


# ================================================================== AC-369
def test_enforcement_missing_column_reports_one_problem_each():
    """AC: BSA-AC-369"""
    full_header = ["위험", "강제 수단", "위치", "검증 테스트"]
    for i in range(4):
        header = [c for j, c in enumerate(full_header) if j != i]
        text = "| %s |\n|%s|\n" % (" | ".join(header), "---|" * len(header))
        probs = doclint.lint_text(text, "enforcement")
        assert len(probs) == 1 and "column" in probs[0]


# ================================================================== AC-370 / AC-371 / AC-372
def test_enforcement_dangling_location_file(tmp_path):
    """AC: BSA-AC-370"""
    ok_file = tmp_path / "pkg"
    ok_file.mkdir()
    (ok_file / "mod.py").write_text("def f():\n    pass\n", encoding="utf-8")
    test_dir = tmp_path / "tests"
    test_dir.mkdir()
    (test_dir / "test_x.py").write_text("def test_y():\n    pass\n", encoding="utf-8")

    good = ENFORCEMENT_HEADER + _enforcement_row("pkg/mod.py:f", "tests/test_x.py::test_y")
    assert doclint.lint_text(good, "enforcement", repo_root=str(tmp_path)) == []

    bad = ENFORCEMENT_HEADER + _enforcement_row("pkg/missing.py", "tests/test_x.py::test_y")
    probs = doclint.lint_text(bad, "enforcement", repo_root=str(tmp_path))
    assert len(probs) == 1 and "does not exist" in probs[0]


def test_enforcement_dangling_location_function(tmp_path):
    """AC: BSA-AC-371"""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("def f():\n    pass\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_y():\n    pass\n", encoding="utf-8")

    good = ENFORCEMENT_HEADER + _enforcement_row("pkg/mod.py:f", "tests/test_x.py::test_y")
    assert doclint.lint_text(good, "enforcement", repo_root=str(tmp_path)) == []

    bad = ENFORCEMENT_HEADER + _enforcement_row("pkg/mod.py:nope", "tests/test_x.py::test_y")
    probs = doclint.lint_text(bad, "enforcement", repo_root=str(tmp_path))
    assert len(probs) == 1 and "function/class was not found" in probs[0]


def test_enforcement_dangling_test_file_and_function(tmp_path):
    """AC: BSA-AC-372"""
    (tmp_path / "pkg").mkdir()
    (tmp_path / "pkg" / "mod.py").write_text("def f():\n    pass\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_x.py").write_text("def test_y():\n    pass\n", encoding="utf-8")

    missing_file = ENFORCEMENT_HEADER + _enforcement_row("pkg/mod.py:f", "tests/test_missing.py::test_y")
    probs1 = doclint.lint_text(missing_file, "enforcement", repo_root=str(tmp_path))
    assert len(probs1) == 1 and "does not exist" in probs1[0]

    missing_func = ENFORCEMENT_HEADER + _enforcement_row("pkg/mod.py:f", "tests/test_x.py::test_nope")
    probs2 = doclint.lint_text(missing_func, "enforcement", repo_root=str(tmp_path))
    assert len(probs2) == 1 and "test function was not found" in probs2[0]

    good = ENFORCEMENT_HEADER + _enforcement_row("pkg/mod.py:f", "tests/test_x.py::test_y")
    assert doclint.lint_text(good, "enforcement", repo_root=str(tmp_path)) == []


# ================================================================== AC-373
@pytest.mark.parametrize("snippet", ["TODO: fill this in", "FIXME later", "<fill me in>"])
def test_strict_flags_todo_fixme_and_placeholder(snippet):
    """AC: BSA-AC-373"""
    text = ADR_OK + "\n" + snippet + "\n"
    assert doclint.lint_text(text, "adr", strict=False) == []
    probs = doclint.lint_text(text, "adr", strict=True)
    assert len(probs) == 1


# ================================================================== AC-374
def test_discover_and_lint_this_repositorys_own_docs_strict_mode_clean():
    """AC: BSA-AC-374"""
    root = doclint._repo_root()
    found, missing = doclint.discover(root)
    assert found, "expected at least the ADRs and governance docs written by this package to be discoverable"
    bad = []
    for path, kind in found:
        probs = doclint.lint_file(path, kind=kind, strict=True, repo_root=root)
        if probs:
            bad.append((path, probs))
    assert bad == []
    acceptable_missing = [m for m in missing if "RUNBOOK" not in m]
    assert acceptable_missing == [], "only the runbook (owned by another package) may be absent: %s" % missing


# ================================================================== AC-375 (State)
def test_unknown_kind_without_override_reports_one_problem(tmp_path):
    """AC: BSA-AC-375"""
    assert doclint.detect_kind("README.md") is None
    p = tmp_path / "README.md"
    p.write_text("# nothing recognisable\n", encoding="utf-8")
    probs = doclint.lint_file(str(p))
    assert len(probs) == 1 and "README.md" in probs[0] and "cannot determine document kind" in probs[0]


# ================================================================== AC-376
def test_explicit_kind_overrides_filename(tmp_path):
    """AC: BSA-AC-376"""
    p = tmp_path / "weird_name.md"
    p.write_text(RUNBOOK_OK, encoding="utf-8")
    assert doclint.detect_kind(str(p)) is None
    probs = doclint.lint_file(str(p), kind="runbook")
    assert probs == []


# ================================================================== AC-377
def test_missing_file_reports_one_problem_not_raise(tmp_path):
    """AC: BSA-AC-377"""
    missing = str(tmp_path / "does_not_exist.md")
    probs = doclint.lint_file(missing, kind="runbook")
    assert len(probs) == 1 and missing in probs[0]


# ================================================================== AC-378
def test_main_cli_exit_code_reflects_problems(tmp_path, capsys):
    """AC: BSA-AC-378"""
    ok_path = tmp_path / "RUNBOOK.md"
    ok_path.write_text(RUNBOOK_OK, encoding="utf-8")
    bad_path = tmp_path / "MODEL_CARD.md"
    bad_path.write_text("# Model Card\n\nnothing here\n", encoding="utf-8")

    rc = doclint.main([str(ok_path), str(bad_path)])
    assert rc == 1

    bad_path.write_text(MODELCARD_OK, encoding="utf-8")
    rc2 = doclint.main([str(ok_path), str(bad_path)])
    assert rc2 == 0


# ================================================================== AC-379
def test_discover_notes_missing_groups(tmp_path):
    """AC: BSA-AC-379"""
    adr_dir = tmp_path / "docs" / "adr"
    adr_dir.mkdir(parents=True)
    (adr_dir / "ADR-0001-x.md").write_text(ADR_OK, encoding="utf-8")
    found, missing = doclint.discover(str(tmp_path))
    assert [kind for _, kind in found] == ["adr"]
    assert len(missing) == 6


# ================================================================== AC-380
def test_ci_workflow_has_doclint_step_after_speclint():
    """AC: BSA-AC-380"""
    root = doclint._repo_root()
    with open(os.path.join(root, ".github", "workflows", "bts_sbom_app_ci.yml"), "r", encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    doclint_idx = [i for i, ln in enumerate(lines) if "python -m bts_sbom_app.doclint --strict" in ln]
    speclint_idx = [i for i, ln in enumerate(lines) if re.search(r"Spec lint", ln)]
    evalrag_idx = [i for i, ln in enumerate(lines) if "evalrag" in ln]
    assert len(doclint_idx) == 1
    assert speclint_idx and evalrag_idx
    assert speclint_idx[0] < doclint_idx[0] < evalrag_idx[0]


# ================================================================== robustness: a referenced file that is not valid
# UTF-8 (e.g. a dangling enforcement-map reference that happens to hit a binary file) must be reported as a lint
# problem, not crash the whole run with an uncaught UnicodeDecodeError.
def test_func_defined_handles_non_utf8_file_gracefully(tmp_path):
    (tmp_path / "bad.py").write_bytes(b"\xff\xfe\x00def f(): pass")
    assert doclint._func_defined(str(tmp_path), "bad.py", "f") is False


def test_lint_file_handles_non_utf8_file_gracefully(tmp_path):
    p = tmp_path / "RUNBOOK.md"
    p.write_bytes(b"\xff\xfe\x00not valid utf-8")
    probs = doclint.lint_file(str(p), kind="runbook")
    assert len(probs) == 1 and "could not read" in probs[0]


def test_strict_placeholders_ignore_code_templates_but_flag_prose():
    """Command/URL templates in `inline code` or fenced blocks are documentation; a bare <placeholder> in prose is not."""
    ok = "Open `/api/jobs/<id>/events` first.\n\n```\ncurl http://127.0.0.1:8800/api/jobs/<id>\n```\n"
    assert doclint.check_placeholders(ok) == []
    bad = "Fill in <project name> before release.\n"
    assert len(doclint.check_placeholders(bad)) == 1
