"""Supply-chain gate (MetaNet 4주차 1차시): honest plan, gate decision, fixed evidence paths."""
from __future__ import annotations

import importlib.util
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_spec = importlib.util.spec_from_file_location(
    "supply_chain_gate", os.path.join(ROOT, "scripts", "supply_chain_gate.py"))
gate = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate)


def test_plan_honest_skips_and_exact_commands():
    """AC: BSA-AC-514"""
    nothing = gate.plan({"docker": False, "trivy": False, "python": False})
    assert [s["state"] for s in nothing] == ["skipped", "skipped", "skipped", "skipped", "skipped"]
    assert all(s.get("why") for s in nothing if s["state"] == "skipped")      # every skip carries a reason
    docker_only = gate.plan({"docker": True, "trivy": False, "python": True})
    scan = next(s for s in docker_only if s["name"] == "scan")
    assert scan["cmd"][0] == "docker" and any("aquasec/trivy" in c for c in scan["cmd"])  # trivy hosted by docker
    assert "--severity" in scan["cmd"] and "CRITICAL" in scan["cmd"] and "--exit-code" in scan["cmd"]
    native = gate.plan({"docker": True, "trivy": True, "python": True})
    assert next(s for s in native if s["name"] == "scan")["cmd"][0] == "trivy"
    reuse = gate.plan({"docker": True, "trivy": True, "python": True}, skip_build=True)
    assert next(s for s in reuse if s["name"] == "build")["why"] == "skipped by flag"


def test_aggregate_gate_decision_and_critical_accounting():
    """AC: BSA-AC-515"""
    def entry(name, state, code=None):
        e = {"name": name, "state": state}
        if state == "done":
            e["run"] = {"code": code}
        return e
    ok = gate.aggregate([entry("build", "done", 0), entry("scan", "done", 0), entry("sbom", "done", 0)])
    assert ok == {"verdict": "pass", "critical_found": 0}
    dirty = gate.aggregate([entry("build", "done", 0), {"name": "scan", "state": "failed", "run": {"code": 1}}])
    assert dirty["verdict"] == "fail" and dirty["critical_found"] == -1        # CRITICAL>0 (count unknown), as main labels it
    broken = gate.aggregate([entry("scan", "failed", 2)])
    assert broken["verdict"] == "fail"
    unknown = gate.aggregate([entry("scan", "skipped", None), entry("bench", "done", 0)])
    assert unknown == {"verdict": "pass", "critical_found": None}              # scan skipped -> honest unknown
    vanished = gate.aggregate([{"name": "scan", "state": "skipped", "run": {"code": 127}}, entry("bench", "done", 0)])
    assert vanished["verdict"] == "pass" and vanished["critical_found"] is None  # 127 = tool missing mid-run, not a vuln


def test_bench_measures_three_latency_classes(tmp_path):
    """AC: BSA-AC-521"""
    cmd = [sys.executable, "-X", "utf8", "-m", "bts_sbom_app", "--root", ROOT, "serve",
           "--host", "127.0.0.1", "--port", "8898", "--evidence", str(tmp_path / "runs")]
    res = gate._bench(cmd, 8898, requests_n=6)
    assert res["ok"] is True and res["requests_per_path"] == 6
    eps = res["endpoints"]
    assert set(eps) == {"/healthz", "/readyz", "/api/history"}               # no-check / probe / file-reading
    for path, e in eps.items():
        assert e["http_status"] == 200 and e["requests"] == 6
        assert e["p50_ms"] >= 0 and e["p95_ms"] >= e["p50_ms"] and e["max_ms"] >= e["p95_ms"]
    # no cross-path latency relation is asserted: under a loaded host a checking endpoint can be arbitrarily
    # slower than a no-check one - the contract is the recorded percentiles, not a host-specific ratio


def test_main_writes_fixed_evidence_paths(tmp_path, monkeypatch):
    """AC: BSA-AC-516"""
    monkeypatch.setattr(gate, "EVIDENCE", str(tmp_path / "supply_chain"))
    monkeypatch.setattr(gate, "_have", lambda tool: False)                     # all tools absent -> every step skips
    monkeypatch.setattr(gate, "_run", lambda cmd, timeout=900, full=False: {
        "cmd": " ".join(cmd), "code": 0, "seconds": 0.0, "stdout_tail": "", "stderr_tail": ""})
    monkeypatch.setattr(gate, "_bench", lambda cmd, port, requests_n=60: {
        "requests": 3, "http_status": 200, "p50_ms": 1.0, "p95_ms": 2.0, "max_ms": 3.0, "ok": True})
    rc = gate.main(["--skip-bench"])
    assert rc == 0
    report_file = [f for f in os.listdir(str(tmp_path / "supply_chain")) if f.startswith("gate_")][0]
    rep = json.loads((tmp_path / "supply_chain" / report_file).read_text(encoding="utf-8"))
    assert rep["schema"] == "bts-sbom.supply-chain.v1" and rep["verdict"] == "pass"
    assert rep["critical_found"] is None                                       # scan skipped -> honest unknown
    states = {s["name"]: s["state"] for s in rep["steps"]}
    assert states["bench"] == "skipped" and states["self_sbom"] == "done"      # python exists, docker/trivy do not
    bench_dir = tmp_path / "supply_chain" / "bench"
    names = sorted(os.listdir(str(bench_dir)))
    assert "bench_latest.json" in names and len([n for n in names if n.startswith("bench_2")]) == 1
