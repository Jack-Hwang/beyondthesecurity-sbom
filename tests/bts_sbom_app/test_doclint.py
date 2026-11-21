"""doclint: document kinds, strict markers, enforcement-map references (task 5a, AC 361-372)."""
from __future__ import annotations

import os


from bts_sbom_app import doclint

REPO = doclint.os.environ.get("BTS_SBOM_REPO_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _adr(**overrides) -> str:
    body = """# ADR-XXXX: title

## Status
Accepted.

## 근거 (Context)
why

## 결정 (Decision)
what

## 기각 대안 (Rejected alternatives)
- alternative: reason

## 결과 (Consequences)
later
"""
    for old, new in overrides.items():
        body = body.replace(old, new)
    return body


def test_an_adr_without_rejected_alternatives_items_is_flagged():
    """AC: BSA-AC-361"""
    body = _adr(**{"- alternative: reason": "no items here"})
    problems = doclint.lint_doc(body, "adr")
    assert any("no list item" in p for p in problems)


def test_every_repo_adr_passes_all_five_sections():
    """AC: BSA-AC-362"""
    adr_dir = os.path.join(REPO, "docs", "adr")
    checked = 0
    for fn in sorted(os.listdir(adr_dir)):
        if not fn.endswith(".md"):
            continue
        text = open(os.path.join(adr_dir, fn), encoding="utf-8").read()
        assert doclint.lint_doc(text, "adr") == [], fn
        checked += 1
    assert checked >= 11


def _missing(kind: str) -> str:
    """A document of ``kind`` with exactly one required section removed."""
    docs = {
        "impact": "# AI 영향평가서\n## 시스템 개요\nx\n## 고영향 여부\nx\n## 이해관계자\nx\n## 위험 식별\nx\n## 완화 조치\nx\n## 사람 감독\nx\n## 모니터링\nx\n## 잔여 위험\nx\n",
        "modelcard": "# card\n## Model details\nx\n## Intended use\nx\n## Evaluation\nx\n## Limitations\nx\n## Risks\nx\n",
        "lineage": "# lineage\n## Sources\nx\n## Collection\nx\n## Freshness\nx\n## Failure behavior\nx\n## Terms\nx\n",
        "datacontract": "# dc\n## Schema\nx\n## Invariants\nx\n## Versioning\nx\n## Compatibility\nx\n",
        "runbook": "# rb\n## Delivery State\nx\n## Deployment\nx\n## Rollback\nx\n## Monitoring\nx\n",
    }
    drop = {"impact": "## 잔여 위험\nx\n", "modelcard": "## Risks\nx\n", "lineage": "## Terms\nx\n",
            "datacontract": "## Compatibility\nx\n", "runbook": "## Monitoring\nx\n"}
    return docs[kind].replace(drop[kind], "")


def test_one_removed_section_is_one_problem_for_each_of_the_five_kinds():
    """AC: BSA-AC-367"""
    for kind in ("impact", "modelcard", "lineage", "datacontract", "runbook"):
        problems = doclint.lint_doc(_missing(kind), kind)
        assert len(problems) == 1, (kind, problems)


def test_a_dangling_test_reference_in_the_enforcement_map_is_flagged():
    """AC: BSA-AC-363"""
    rows = ["| r | m | bts_sbom_app/net.py | tests/bts_sbom_app/test_resilience.py::test_open_circuit_sends_zero_requests_and_reports_circuit_open |",
            "| r | m | bts_sbom_app/net.py | tests/bts_sbom_app/test_resilience.py::definitely_not_a_test_that_exists |"] * 12
    problems = doclint.lint_doc("| a | b | c | d |\n" + "|---|---|---|---|\n" + "\n".join(rows), "enforcement")
    assert any("definitely_not_a_test_that_exists" in p for p in problems)


def test_strict_mode_flags_a_todo_marker():
    """AC: BSA-AC-364"""
    problems = doclint.lint_doc("# ADR\n## Status\nTODO finish me\n" + "## 근거 (Context)\nx\n## 결정 (Decision)\nx\n"
                                "## 기각 대안 (Rejected alternatives)\n- a: b\n## 결과 (Consequences)\nx\n", "adr", strict=True)
    assert any("placeholder" in p for p in problems)


def test_an_absent_document_is_reported_not_present_and_counts_zero_passes():
    """AC: BSA-AC-365"""
    root = os.path.join(REPO, "tests", "bts_sbom_app", "_doclint_missing_fixture")
    os.makedirs(root, exist_ok=True)
    try:
        targets = doclint.collect(root, [])
        assert any(kind == "impact" and not os.path.exists(path) for kind, path in targets), "the fixture root has no governance docs"
    finally:
        os.rmdir(root)


def test_the_real_repository_documents_pass_strict_lint():
    """AC: BSA-AC-366"""
    total = 0
    for kind, path in doclint.collect(REPO, []):
        try:
            text = open(path, encoding="utf-8").read()
        except OSError:
            continue
        total += len(doclint.lint_doc(text, kind, strict=True))
    assert total == 0, total


def test_the_enforcement_map_has_12_rows_with_existing_locations_and_tests():
    """AC: BSA-AC-368"""
    text = open(os.path.join(REPO, "docs", "ENFORCEMENT_MAP.md"), encoding="utf-8").read()
    assert doclint.lint_doc(text, "enforcement") == []


def test_the_ci_workflow_has_exactly_one_doclint_step():
    """AC: BSA-AC-369"""
    wf = open(os.path.join(REPO, ".github", "workflows", "bts_sbom_app_ci.yml"), encoding="utf-8").read()
    assert wf.count("bts_sbom_app.doclint") == 1


def test_the_impact_assessment_is_self_assessment_and_carries_all_sections():
    """AC: BSA-AC-370"""
    text = open(os.path.join(REPO, "docs", "governance", "AI_IMPACT_ASSESSMENT.md"), encoding="utf-8").read()
    assert "자체 평가" in text and "법률 자문" in text
    assert doclint.lint_doc(text, "impact") == []


def test_the_model_card_qualifies_the_readme_figures_as_in_sample():
    """AC: BSA-AC-371"""
    text = open(os.path.join(REPO, "docs", "governance", "MODEL_CARD.md"), encoding="utf-8").read()
    assert "표본 내" in text and "in-sample" in text


def test_the_lineage_sources_cover_every_host_the_code_calls():
    """AC: BSA-AC-372"""
    lineage = open(os.path.join(REPO, "docs", "governance", "ORIGIN_LINEAGE.md"), encoding="utf-8").read()
    for host in ("api.osv.dev", "api.deps.dev", "pypi.org", "registry.npmjs.org", "repo1.maven.org",
                 "endoflife.date", "api.exaone.ai", "github.com/FIRSTdotorg/cvss-v4-calculator"):
        assert host in lineage, host
