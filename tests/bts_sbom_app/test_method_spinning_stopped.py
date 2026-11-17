"""Regression test for pipeline._patch_loop's spinning_stopped guard (pipeline.py: identical plan set twice -> stop).

Before this test, grep over tests/ found zero references to "spinning_stopped" anywhere in the suite: the guard existed
in the code but no test exercised it, so a future refactor could silently drop it without turning any test red.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

from bts_sbom_app import pipeline


def test_identical_plan_set_twice_stops_the_loop(monkeypatch, tmp_path):
    """AC: BSA-AC-209

    patch.apply() succeeds once (fixing one vulnerability) but the recomputed plan for round 2 is
    byte-for-byte the same (component, safe_version) set as round 1's: no progress is possible, so the
    guard at pipeline.py must stop the loop with status == "spinning_stopped" instead of spinning forever.
    """
    plan = {"component": "flask", "ecosystem": "PyPI", "current_version": "1.0", "safe_version": "1.0.1",
             "status": "upgrade", "verification": {"clean": None}}
    vuln_fixed = {"id": "VULN-A", "package": "requests", "version": "2.19.1", "files": []}
    vuln_remaining = {"id": "VULN-B", "package": "flask", "version": "1.0", "files": []}
    rec: Dict[str, Any] = {"vulns": [vuln_fixed, vuln_remaining], "plans": [plan]}

    apply_calls = {"n": 0}

    def fake_apply(path: str, plans: List[Dict[str, Any]], *, approved: bool, token: Optional[str] = None) -> Dict[str, Any]:
        apply_calls["n"] += 1
        return {"status": "applied", "results": [{"component": "flask", "status": "applied"}],
                "changed_files": [], "branch": "bts-sbom/auto-fix", "commit": "deadbeef", "digest": "x"}

    def fake_analyze(path: str, offline: bool = True, scanner: Any = None, **kw: Any) -> Dict[str, Any]:
        return {"components": [], "vulns": [vuln_remaining]}          # requests fixed, flask's finding persists

    def fake_plan(components: List[Dict[str, Any]], vulns: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        return [plan]                                                 # identical (component, safe_version) set again

    monkeypatch.setattr(pipeline.patchmod, "apply", fake_apply)
    monkeypatch.setattr(pipeline.engine, "analyze", fake_analyze)
    monkeypatch.setattr(pipeline.remediate, "plan", fake_plan)

    out = pipeline._patch_loop(rec, str(tmp_path), approved=True, token=None, rounds=2, offline=True, scanner=None, verify_rounds=1)

    assert out["status"] == "spinning_stopped"
    assert apply_calls["n"] == 1                                      # round 2 never calls apply(): the guard fires first
    assert len(out["rounds"]) == 1
