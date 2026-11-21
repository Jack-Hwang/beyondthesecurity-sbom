"""State-pattern AC for the ported secret scanner (task 9, AC 440)."""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCANNER = ROOT / "tools" / "secret_scan.py"

# deliberately shape-like but fake, and assembled from parts so this test file
# itself never contains a contiguous secret shape for the scanner to flag
AWS_KEY = "AKIA" + "FAKEEXAMPLE99999"


def _run_scanner(target: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, "-I", str(SCANNER), target], cwd=str(ROOT),
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=60)


def test_state_one_planted_aws_key_reports_one_finding_without_the_value():
    """AC: BSA-AC-440"""
    with tempfile.TemporaryDirectory() as tmp:
        (Path(tmp) / "creds.py").write_text('AWS_ACCESS_KEY_ID = "' + AWS_KEY + '"\n', encoding="utf-8")
        result = _run_scanner(tmp)
    findings = [ln for ln in result.stdout.splitlines() if "creds.py:" in ln]
    assert len(findings) == 1, (findings, result.stdout)
    assert ":1: AWS_ACCESS_KEY" in findings[0]
    assert AWS_KEY not in result.stdout + result.stderr
    assert result.returncode == 1
