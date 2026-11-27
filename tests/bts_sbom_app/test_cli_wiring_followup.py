"""CLI surface of the follow-up upgrades: calibrate, batch retry, govgate, secretscan, audit, prompt re-pin flags, evalsets gates."""
from __future__ import annotations

import json
import os

from bts_sbom_app import batch, cli, evalguard, evals, govgate


def _vulns_and_store(n=40):
    sevs = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    vulns, store = [], {}
    for i in range(n):
        vid = "CVE-2024-%04d" % i
        vulns.append({"id": vid, "package": "pkg%d" % i, "version": "1.0", "ecosystem": "PyPI", "severity": sevs[i % 4]})
        if i % 4 in (0, 2):
            store[vid] = {"status": "accepted", "note": "reviewed and accepted risk for this release cycle", "by": "alice"}
    return vulns, store


def test_evalrag_calibrate_prints_both_verdicts_writes_the_table_and_exits_on_the_exact_check(monkeypatch, capsys):
    """AC: BSA-AC-1201"""
    written = {}
    monkeypatch.setattr(cli, "write_json", lambda path, obj: written.update(path=path, obj=obj))
    assert cli.main(["evalrag", "--calibrate"]) == 0
    out = capsys.readouterr().out
    assert "bucket check:" in out and "exact per-item check: safe" in out and "committed min_bm25=12.0" in out                 # both verdicts, never collapsed
    assert written["path"].replace("\\", "/").endswith("evidence/calibration/rag_gate.json") and len(written["obj"]["table"]) == 5 and written["obj"]["check"]["exact_safe"] is True
    from bts_sbom_app import calibrate
    monkeypatch.setattr(calibrate, "check_threshold", lambda **k: dict(calibrate.check_threshold.__wrapped__(**k) if hasattr(calibrate.check_threshold, "__wrapped__") else {
        "min_bm25": 12.0, "bucket_safe": False, "bucket_false_accept_rate": 0.5, "exact_safe": False, "exact_ood_false_accept_rate": 0.5, "safe_range": None, "note": "n"}))
    assert cli.main(["evalrag", "--calibrate"]) == 1                                                                       # the exact check failing is the exit code


def test_batch_retry_failed_reruns_only_through_retry_failed_and_a_plain_batch_still_runs_everything(tmp_path, monkeypatch, capsys):
    """AC: BSA-AC-1202"""
    srcs = tmp_path / "sources.json"
    srcs.write_text(json.dumps([{"name": "a", "src": "x"}, {"name": "b", "src": "y"}]), encoding="utf-8")
    calls = []
    shape = {"summary": {"schema": "bts-sbom.batch.v1", "projects": 2, "status": "success", "failed_sources": [], "tag": "t", "summary": {}}, "records": []}
    monkeypatch.setattr(batch, "retry_failed", lambda s, prior, out, **k: calls.append(("retry", prior, len(s))) or shape)
    monkeypatch.setattr(batch, "run_batch", lambda s, out, **k: calls.append(("run", len(s))) or shape)
    from bts_sbom_app import report
    monkeypatch.setattr(report, "batch_md", lambda summary, records: "batch report")
    assert cli.main(["--root", str(tmp_path), "batch", str(srcs), "--no-llm", "--retry-failed", str(tmp_path / "prior")]) == 0
    assert calls == [("retry", str(tmp_path / "prior"), 2)]
    assert cli.main(["--root", str(tmp_path), "batch", str(srcs), "--no-llm"]) == 0
    assert calls[1] == ("run", 2) and "batch report" in capsys.readouterr().out


def test_govgate_prints_the_table_and_its_exit_code_follows_the_gates(monkeypatch, capsys):
    """AC: BSA-AC-1203"""
    ok = {"ok": True, "gates": [{"name": "Spec", "ok": True, "detail": "ok"}]}
    bad = {"ok": False, "gates": [{"name": "Spec", "ok": False, "detail": "2 problems"}]}
    monkeypatch.setattr(govgate, "render", lambda r: "TABLE ok=%s" % r["ok"])
    monkeypatch.setattr(govgate, "evaluate", lambda root=None: ok)
    assert cli.main(["govgate"]) == 0 and "TABLE ok=True" in capsys.readouterr().out
    monkeypatch.setattr(govgate, "evaluate", lambda root=None: bad)
    assert cli.main(["govgate", "--json"]) == 1 and json.loads(capsys.readouterr().out)["ok"] is False


def test_secretscan_reports_file_line_rule_never_the_value_and_a_partial_scan_is_not_a_clean_pass(tmp_path, capsys):
    """AC: BSA-AC-1204"""
    secret = "AKIA" + "ABCD1234EFGH5678"                                                                     # an AWS access key id shape
    (tmp_path / "config.py").write_text("x = 1\nTOKEN = '%s'\n" % secret, encoding="utf-8")
    assert cli.main(["secretscan", str(tmp_path)]) == 1
    out = capsys.readouterr().out
    assert "config.py:2 [" in out and secret not in out and secret[:8] not in out and "1 finding(s)" in out
    assert cli.main(["secretscan", str(tmp_path), "--json"]) == 1
    obj = json.loads(capsys.readouterr().out)
    assert secret not in json.dumps(obj) and obj["findings"][0]["line"] == 2 and obj["summary"]["coverage_limited"] is False
    clean = tmp_path / "clean"
    clean.mkdir()
    (clean / "a.py").write_text("print('ok')\n", encoding="utf-8")
    assert cli.main(["secretscan", str(clean)]) == 0                                                                   # nothing found, nothing skipped
    (clean / "blob.bin").write_bytes(b"\x00\x01\x02" * 100)
    assert cli.main(["secretscan", str(clean)]) == 1 and "COVERAGE LIMITED" in capsys.readouterr().out               # a skipped file: 0 findings is not clean
    assert cli.main(["secretscan", str(tmp_path / "missing")]) == 2


def test_audit_samples_licence_resolutions_by_source_and_closed_decisions_by_lane_deterministically(tmp_path, capsys):
    """AC: BSA-AC-1205"""
    comps = [{"name": "p%d" % i, "version": "1.0", "ecosystem": "npm", "license": "MIT", "license_source": src}
             for i, src in enumerate(["lockfile", "deps.dev"] * 10)]
    vulns, store = _vulns_and_store(40)
    rec = tmp_path / "rec.json"
    rec.write_text(json.dumps({"name": "demo", "components": comps, "vulns": vulns}), encoding="utf-8")
    tri = tmp_path / "triage.json"
    tri.write_text(json.dumps(store), encoding="utf-8")
    assert cli.main(["audit", str(rec), "--seed", "3", "--json"]) == 0
    a = json.loads(capsys.readouterr().out)
    assert a["by_source"] == {"lockfile": 10, "deps.dev": 10} and a["sampled"] == {"lockfile": 1, "deps.dev": 1} and len(a["queue"]) == 2
    assert cli.main(["audit", str(rec), "--seed", "3", "--json"]) == 0 and json.loads(capsys.readouterr().out)["queue"] == a["queue"]     # same seed, same queue
    assert cli.main(["audit", str(rec), "--kind", "triage", "--triage", str(tri), "--seed", "3", "--json"]) == 0
    t = json.loads(capsys.readouterr().out)
    assert t["closed_total"] == 20 and sorted(t["lanes"]) == ["CRITICAL", "MEDIUM"] and set(t["sampled"]) == {"CRITICAL", "MEDIUM"} and 0 < len(t["queue"]) < 20
    assert cli.main(["audit", str(tmp_path / "nope.json")]) == 2


def test_prompts_update_can_demand_loop_evidence_and_evalsets_gate_on_the_injection_holdout(tmp_path, monkeypatch, capsys):
    """AC: BSA-AC-1206"""
    root = tmp_path / "repo"
    (root / "bts_sbom_app").mkdir(parents=True)
    (root / "evals").mkdir()
    (root / "bts_sbom_app" / "m.py").write_text('SYSTEM = ("%s")\n' % ("You are a careful reviewer. Use ONLY the evidence JSON and never invent identifiers. " * 2), encoding="utf-8")
    base = ["--root", str(root), "prompts", "--update", "--reason", "initial pin of the prompts"]
    assert cli.main(base + ["--require-loop-evidence"]) == 2 and "loop" in capsys.readouterr().err.lower()                # no evidence/loop pass: refused
    assert cli.main(base) == 0                                                                                       # the default behaviour is unchanged
    capsys.readouterr()
    low = {"recall": 0.5, "precision": 0.5, "benign_false_positive_rate": 0.0, "misses": [], "false_positives": [], "by_lang": {}, "attack_n": 2, "benign_n": 2}
    monkeypatch.setattr(evalguard, "injection_eval", lambda samples: low)
    assert cli.main(["evalsets", "--json"]) == 1                                                                     # holdout recall 0.5 < 0.90 fails the command
    rep = json.loads(capsys.readouterr().out)
    assert rep["injection"]["gate"]["pass"] is False and rep["injection"]["holdout"]["recall"] == 0.5 and "english" in rep and rep["english"]["queries"] >= 12
    monkeypatch.setattr(evalguard, "injection_eval", lambda samples: dict(low, recall=1.0))
    assert cli.main(["evalsets"]) == 0 and "injection guard:" in capsys.readouterr().out
    assert os.path.exists(os.path.join(evals.repo_root(), "evals", "injection_holdout.jsonl"))
