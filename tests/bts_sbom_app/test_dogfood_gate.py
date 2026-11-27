"""AC: BSA-AC-1251, BSA-AC-1252. Nightly-ops round 2 (backlog C09 + C12): the self-dogfood gate — the product scans its own source tree
offline and the gate asserts the self-SBOM is machine-valid and non-empty, recording the NTIA verdict as the
drift baseline — and the fixture-level test of that gate logic. The nightly GitHub workflow itself is YAML,
checked by a parse test so a typo cannot ship a broken schedule."""
from __future__ import annotations

import json
import os
import subprocess
import sys

APP_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GATE = os.path.join(os.path.dirname(APP_ROOT), "scripts", "dogfood_gate.py")


def test_dogfood_gate_runs_offline_and_validates_its_own_sbom(tmp_path):
    """AC: BSA-AC-1251. On a tiny synthetic source tree the gate scans offline, emits a machine-valid CycloneDX
    self-SBOM, records the NTIA verdict (and its named gap elements) as the drift baseline, and exits 0 — the
    gate's pass condition is validity + non-empty, never an invented supplier."""
    src = tmp_path / "pkg_src"
    (src / "sub").mkdir(parents=True)
    (src / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    (src / "pyproject.toml").write_text('[project]\nname = "fixture-pkg"\nversion = "0.1.0"\n', encoding="utf-8")
    (src / "mod.py").write_text("VALUE = 1\n", encoding="utf-8")
    (src / "sub" / "util.py").write_text("import os\n\n\ndef u() -> int:\n    return 1\n", encoding="utf-8")
    proc = subprocess.run([sys.executable, GATE, "--target", str(src), "--out", str(tmp_path / "ev")],
                          capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stdout[-400:]
    summary = json.loads(proc.stdout)
    assert summary["checks"]["mode"] == "offline"
    assert summary["checks"]["components"] >= 1
    assert summary["checks"]["cyclonedx_valid"] is True
    assert "ntia_2021" in summary["checks"]                          # the drift baseline is recorded, gated or not
    stamp_dir = sorted(os.listdir(tmp_path / "ev"))[-1]
    assert os.path.isfile(os.path.join(tmp_path / "ev", stamp_dir, "self.cdx.json"))


def test_nightly_workflow_is_wellformed_yaml_with_the_decoupled_schedule():
    """AC: BSA-AC-1252. The nightly drift workflow parses as YAML, carries ONLY schedule + manual dispatch
    triggers (decoupled from push/PR by design), and its steps name the offline battery it promises."""
    import re
    path = os.path.join(os.path.dirname(APP_ROOT), ".github", "workflows", "nightly-drift.yml")
    text = open(path, encoding="utf-8").read()
    try:
        import yaml
        doc = yaml.safe_load(text)
        on = doc[True] if True in doc else doc["on"]                 # YAML 1.1 parses a bare `on:` as boolean True
        assert set(on) == {"schedule", "workflow_dispatch"}
        assert any("cron" in str(x) for x in (on["schedule"] or []))
    except ImportError:
        assert re.search(r"^\s+schedule:", text, re.M) and "workflow_dispatch" in text and "push:" not in text.split("jobs:")[0]
    for step in ("dogfood_gate.py", "evalrag", "check_md_links.py", "speclint", "escalation_report"):
        assert step in text
    assert "paths:" not in text.split("jobs:")[0]                    # no push/PR path filters: the trigger is the clock
