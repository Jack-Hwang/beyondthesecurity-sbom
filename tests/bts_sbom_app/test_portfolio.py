"""Portfolio manifest (8 packages, no fabrication, no rubric scores) + the proof command (task 5b, AC 386-394)."""
from __future__ import annotations

import json
import os
import shutil


from bts_sbom_app import portfolio, proof

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def test_the_exported_manifest_lists_8_packages_with_status_and_sources(tmp_path):
    """AC: BSA-AC-386"""
    out = str(tmp_path / "pf")
    manifest = portfolio.export(REPO, out)
    assert len(manifest["packages"]) == 8
    for p in manifest["packages"]:
        assert p["status"] in ("complete", "missing", "human_required") and "sources" in p


def test_a_missing_source_is_marked_and_nothing_is_fabricated(tmp_path):
    """AC: BSA-AC-387"""
    root = str(tmp_path / "thin")
    shutil.copytree(REPO, root, ignore=shutil.ignore_patterns("__pycache__", ".pytest_cache", ".git", "docs", ".github", "knowledge", "evals"))
    out = str(tmp_path / "pf")
    manifest = portfolio.export(root, out)
    missing_pkgs = [p for p in manifest["packages"] if p.get("missing")]
    assert missing_pkgs, "a stripped tree must produce missing entries"
    for p in missing_pkgs:
        for rel in p["missing"]:
            assert not os.path.exists(os.path.join(root, rel))
        for s in p["sources"]:
            assert os.path.exists(os.path.join(root, s["path"]))


def test_packages_7_and_8_are_human_required_with_a_checklist(tmp_path):
    """AC: BSA-AC-388"""
    manifest = portfolio.export(REPO, str(tmp_path / "pf"))
    humans = [p for p in manifest["packages"] if p["status"] == "human_required"]
    assert [p["id"] for p in humans] == [7, 8]
    assert all(p.get("checklist") for p in humans)


def test_the_self_assessment_has_no_scores_and_marks_judgement_human_review(tmp_path):
    """AC: BSA-AC-389"""
    manifest = portfolio.export(REPO, str(tmp_path / "pf"))
    sa = manifest["self_assessment"]
    blob = json.dumps(sa)
    assert sa["judgement"] == "human_review"
    assert not any(k in blob for k in ("score", "grade", "points", "star"))


def test_a_failing_runner_classifies_fail_and_the_overall_is_fail():
    """AC: BSA-AC-390 (runner-cannot-execute is NOT RUN), FAIL via a non-zero exit"""
    def runner(cmd):
        return 2, "some summary line", ""
    rec = proof.run(runner=runner, commands=[{"name": "pytest", "cmd": "x"}])
    assert rec["results"][0]["status"] == "FAIL" and rec["overall"] == "fail"


def test_zero_fails_all_pass_and_zero_not_run_is_pass():
    """AC: BSA-AC-391"""
    rec = proof.run(runner=lambda cmd: (0, "ok line", ""), commands=[{"name": "pytest", "cmd": "x"}, {"name": "speclint", "cmd": "y"}])
    assert rec["overall"] == "pass"


def test_a_missing_command_is_not_run_and_the_overall_is_incomplete():
    """AC: BSA-AC-390"""
    rec = proof.run(runner=lambda cmd: (127, "", "not found"), commands=[{"name": "pytest", "cmd": "x"}])
    assert rec["results"][0]["status"] == "NOT RUN" and rec["overall"] == "incomplete"


def test_the_sidecar_overwrites_the_summary_and_accumulates_runs(tmp_path):
    """AC: BSA-AC-392"""
    out = str(tmp_path / "proof")
    proof.run(runner=lambda cmd: (0, "l", ""), commands=[{"name": "pytest", "cmd": "x"}], out_dir=out)
    proof.run(runner=lambda cmd: (1, "l", ""), commands=[{"name": "pytest", "cmd": "x"}], out_dir=out)
    summary = json.load(open(os.path.join(out, "proof-results.json"), encoding="utf-8"))
    assert summary["overall"] == "fail"                                        # the LAST run overwrote the summary
    runs = os.listdir(os.path.join(out, "proof-runs"))
    assert len(runs) == 2


def test_two_runs_in_one_second_write_two_distinct_files(tmp_path):
    """AC: BSA-AC-393"""
    out = str(tmp_path / "proof")
    proof.run(runner=lambda cmd: (0, "", ""), commands=[{"name": "a", "cmd": "x"}], out_dir=out)
    proof.run(runner=lambda cmd: (0, "", ""), commands=[{"name": "a", "cmd": "x"}], out_dir=out)
    runs = os.listdir(os.path.join(out, "proof-runs"))
    assert len(runs) == 2 and len(set(runs)) == 2


def test_the_cli_offers_trace_portfolio_proof_and_verifydev_and_keeps_earlier_ones(tmp_path):
    """AC: BSA-AC-394"""
    from bts_sbom_app import cli
    ap = cli.build_parser()
    for sub in ("trace", "portfolio", "proof", "verify-dev"):
        assert any(sp == sub for sp, _act in ap._subparsers._group_actions[0].choices.items()), sub
    for earlier in ("scan", "patch", "serve", "chat", "conformance", "fleet"):   # the earlier sub-commands are unchanged
        assert any(sp == earlier for sp, _act in ap._subparsers._group_actions[0].choices.items()), earlier
