"""Portfolio export (BSA-AC-388..391, 399) and proof evidence sidecar (BSA-AC-392..398).

``portfolio.export`` and ``portfolio.proof`` are both exercised against fake, temporary roots built in this file -
never the real repository and never a real subprocess: ``proof`` takes an injected fake ``runner`` throughout
(the default, real ``subprocess.run``-based runner is only reached through the CLI, and the CLI tests below
replace ``portfolio.proof`` itself with a fake so no real pytest/speclint/doclint/evalrag process is spawned).
"""
from __future__ import annotations

import json

from bts_sbom_app import cli, portfolio


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _full_root(tmp_path, with_runbook=True):
    """A fake root where every original file of portfolio packages 1-6 exists."""
    root = tmp_path / "repo"
    _write(root / "README.md", "# demo\n")
    _write(root / "specs" / "bts_sbom_app_features.md", "## Demo (bts_sbom_app/a.py)\n\n- BSA-AC-1 [Event] When it runs it shall report 1 thing.\n")
    _write(root / "docs" / "adr" / "ADR-0001-demo.md", "# ADR-0001: demo\n")
    _write(root / "docs" / "ARCHITECTURE.md", "# architecture\n")
    _write(root / "docs" / "WORKFLOW.md", "# workflow\n")
    _write(root / "bts_sbom" / "__init__.py", "")
    _write(root / "bts_sbom_app" / "a.py", "")
    _write(root / "bts_sbom_app" / "web" / "app.js", "")
    _write(root / "Dockerfile.bts-sbom-app", "FROM scratch\n")
    _write(root / ".github" / "workflows" / "ci.yml", "name: ci\n")
    _write(root / "tools" / "check.py", "")
    _write(root / "evals" / "e2e.json", "{}")
    _write(root / "docs" / "LOOP_LOG.md", "# log\n")
    _write(root / "evidence" / "loop" / "history.json", "[]")
    _write(root / "evidence" / "loop" / "rag_history.json", "[]")
    if with_runbook:
        _write(root / "docs" / "RUNBOOK.md", "# runbook\n")
    _write(root / "tests" / "bts_sbom_app" / "test_server_cli.py", "def test_x():\n    assert True\n")
    _write(root / "docs" / "governance" / "AI_IMPACT.md", "# impact\n")
    _write(root / "docs" / "ENFORCEMENT_MAP.md", "# map\n")
    return root


def test_export_reports_found_for_six_packages_and_human_required_for_two(tmp_path):
    """AC: BSA-AC-388"""
    root = _full_root(tmp_path)
    manifest = portfolio.export(str(root), str(tmp_path / "out"))
    by_n = {p["n"]: p for p in manifest["packages"]}
    for n in range(1, 7):
        pkg = by_n[n]
        assert pkg["status"] == "found", (n, pkg)
        for item in pkg["items"]:
            assert item["status"] == "found"
            assert isinstance(item["size"], int) and isinstance(item["sha256"], str) and len(item["sha256"]) == 64
    for n in (7, 8):
        assert by_n[n]["status"] == "human_required"
        assert by_n[n]["checklist"]


def test_missing_original_is_reported_missing_with_no_fabricated_fields(tmp_path):
    """AC: BSA-AC-389"""
    root = _full_root(tmp_path, with_runbook=False)
    manifest = portfolio.export(str(root), str(tmp_path / "out"))
    pkg5 = next(p for p in manifest["packages"] if p["n"] == 5)
    missing_item = next(it for it in pkg5["items"] if it["path"] == "docs/RUNBOOK.md")
    assert missing_item["status"] == "missing"
    assert missing_item["size"] is None and missing_item["sha256"] is None
    assert pkg5["status"] == "partial" and pkg5["missing"] == 1


def test_export_is_deterministic_across_two_runs(tmp_path):
    """AC: BSA-AC-390"""
    root = _full_root(tmp_path)
    out = tmp_path / "out"
    portfolio.export(str(root), str(out))
    manifest1 = (out / "portfolio-manifest.json").read_bytes()
    readme1 = (out / "README.md").read_bytes()
    portfolio.export(str(root), str(out))
    manifest2 = (out / "portfolio-manifest.json").read_bytes()
    readme2 = (out / "README.md").read_bytes()
    assert manifest1 == manifest2
    assert readme1 == readme2


def test_self_assessment_has_no_rubric_score_and_judgment_rows_are_human_review(tmp_path):
    """AC: BSA-AC-391"""
    root = _full_root(tmp_path)
    manifest = portfolio.export(str(root), str(tmp_path / "out"))
    sa = manifest["self_assessment"]
    assert set(sa["measured"]) == {"ac_count", "untested_ac_count", "test_file_count", "speclint_problem_count"}
    for k, v in sa["measured"].items():
        assert v is None or isinstance(v, int), (k, v)
    assert set(sa["judgment"]) == {"design_rationale_quality", "documentation_clarity", "contribution_originality"}
    assert all(v == "human_review" for v in sa["judgment"].values())
    assert not any("score" in k for k in sa["measured"]) and not any("score" in k for k in sa["judgment"])


# --------------------------------------------------------------------------------------------- proof (injected runner)
def _queue_runner(canned):
    it = iter(canned)

    def _run(cmd, cwd, timeout):
        return next(it)
    return _run


def test_proof_classifies_missing_module_as_not_run_not_pass(tmp_path):
    """AC: BSA-AC-392"""
    runner = _queue_runner([(0, "ok\n", ""), (0, "ok\n", ""), (0, "ok\n", "")])   # pytest, speclint, evalrag (no doclint.py in this root)
    doc = portfolio.proof(str(tmp_path), runner=runner, out_dir=str(tmp_path / "ev"))
    assert doc["counts"] == {"PASS": 3, "FAIL": 0, "NOT RUN": 1}
    assert doc["status"] == "incomplete"
    doclint = next(r for r in doc["results"] if r["name"] == "doclint")
    assert doclint["status"] == "NOT RUN" and doclint["reason"] == "module not found"


def test_not_run_from_a_missing_module_and_a_timeout_both_stay_incomplete(tmp_path):
    """AC: BSA-AC-393"""
    runner = _queue_runner([(0, "ok\n", ""), (0, "ok\n", ""), (124, "", "timeout after 600s")])
    doc = portfolio.proof(str(tmp_path), runner=runner, out_dir=str(tmp_path / "ev"))
    assert doc["counts"]["NOT RUN"] == 2 and doc["counts"]["PASS"] == 2
    assert doc["status"] == "incomplete"


def test_proof_all_pass_is_overall_pass(tmp_path):
    """AC: BSA-AC-394"""
    _write(tmp_path / "bts_sbom_app" / "doclint.py", "")          # module present this time: all 4 commands go through the runner
    runner = _queue_runner([(0, "", "")] * 4)
    doc = portfolio.proof(str(tmp_path), runner=runner, out_dir=str(tmp_path / "ev"))
    assert doc["counts"] == {"PASS": 4, "FAIL": 0, "NOT RUN": 0}
    assert doc["status"] == "pass"


def test_one_failing_command_makes_the_whole_proof_fail(tmp_path):
    """AC: BSA-AC-395"""
    _write(tmp_path / "bts_sbom_app" / "doclint.py", "")
    runner = _queue_runner([(1, "", "boom"), (0, "", ""), (0, "", ""), (0, "", "")])
    doc = portfolio.proof(str(tmp_path), runner=runner, out_dir=str(tmp_path / "ev"))
    assert doc["counts"]["FAIL"] == 1 and doc["counts"]["PASS"] == 3
    assert doc["status"] == "fail"


def test_sidecar_overwrites_summary_and_accumulates_runs(tmp_path):
    """AC: BSA-AC-396"""
    out_dir = tmp_path / "ev" / "proof"
    portfolio.proof(str(tmp_path), runner=_queue_runner([(0, "", "")] * 3), out_dir=str(out_dir))
    doc2 = portfolio.proof(str(tmp_path), runner=_queue_runner([(1, "", "boom"), (0, "", ""), (0, "", "")]), out_dir=str(out_dir))
    saved = json.loads((out_dir / "proof-results.json").read_text(encoding="utf-8"))
    assert saved["status"] == doc2["status"] == "fail"             # the sidecar summary reflects only the latest run
    runs = list((out_dir / "proof-runs").glob("*.json"))
    assert len(runs) == 2                                         # both runs were kept


def test_proof_sidecar_entries_hold_no_raw_command_output(tmp_path):
    """AC: BSA-AC-397"""
    runner = _queue_runner([(1, "SECRET_TOKEN_abc123\nline2\n", ""), (0, "", ""), (0, "", "")])
    doc = portfolio.proof(str(tmp_path), runner=runner, out_dir=str(tmp_path / "ev"))
    assert "SECRET_TOKEN_abc123" not in json.dumps(doc)
    for r in doc["results"]:
        assert set(r.keys()) == {"name", "cmd", "exit_code", "status", "reason", "summary_lines"}
    assert doc["results"][0]["summary_lines"] == 2


def test_cli_proof_only_runs_one_command_and_maps_pass_fail_to_exit_code(tmp_path, monkeypatch):
    """AC: BSA-AC-398"""
    calls = []

    def fake_proof(root, runner=None, out_dir=None, only=None, timeout=600.0):
        calls.append(only)
        doc = {"root": root, "results": [], "counts": {"PASS": 1, "FAIL": 0, "NOT RUN": 0}, "status": "pass"} if only == "pytest" else \
              {"root": root, "results": [], "counts": {"PASS": 3, "FAIL": 1, "NOT RUN": 0}, "status": "fail"}
        return doc
    monkeypatch.setattr(portfolio, "proof", fake_proof)
    assert cli.main(["--root", str(tmp_path), "proof", "--out", str(tmp_path / "ev"), "--only", "pytest"]) == 0
    assert cli.main(["--root", str(tmp_path), "proof", "--out", str(tmp_path / "ev")]) == 1
    assert calls == ["pytest", None]


def test_cli_portfolio_export_writes_two_files_naming_eight_kinds(tmp_path):
    """AC: BSA-AC-399"""
    root = tmp_path / "root"
    root.mkdir()
    out = tmp_path / "out"
    assert cli.main(["--root", str(root), "portfolio", "export", "--out", str(out)]) == 0
    assert (out / "README.md").exists()
    data = json.loads((out / "portfolio-manifest.json").read_text(encoding="utf-8"))
    assert sorted(p["n"] for p in data["packages"]) == list(range(1, 9))
    manifest1 = (out / "portfolio-manifest.json").read_bytes()
    assert cli.main(["--root", str(root), "portfolio", "export", "--out", str(out)]) == 0
    manifest2 = (out / "portfolio-manifest.json").read_bytes()
    assert manifest1 == manifest2
