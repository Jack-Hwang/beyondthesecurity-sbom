"""Regression tests for the defects found by the 0.2.0 end-to-end lanes (one test per acceptance criterion)."""
from __future__ import annotations

import io
import json
import re
import subprocess
import sys
from pathlib import Path

import pytest

from bts_sbom_app import __version__, cli, llm, net, pipeline, report, util

REPO = Path(__file__).resolve().parents[2]


def _core_version() -> str:
    txt = (REPO / "bts_sbom" / "_version.py").read_text(encoding="utf-8")
    return re.search(r'__version__\s*=\s*"([^"]+)"', txt).group(1)


def test_one_version_everywhere():
    """AC: BSA-AC-79"""
    core = _core_version()
    assert __version__ == core
    assert net.UA.startswith("bts-sbom-app/" + core + " ")
    assert '"User-Agent": "bts-sbom-app/" + __version__' in Path(llm.__file__).read_text(encoding="utf-8")
    r = subprocess.run([sys.executable, "-m", "bts_sbom_app", "--version"], capture_output=True, text=True, cwd=REPO, timeout=120)
    assert r.returncode == 0 and r.stdout.strip() == "bts_sbom_app " + core
    from bts_sbom_app import sbom as app_sbom
    assert app_sbom.__version__ == core                 # the CycloneDX/SPDX tool entries read this module attribute


@pytest.mark.parametrize("status,code", [("digest_mismatch", 1), ("regression_reverted", 1), ("blocked", 1), ("error", 1),
                                         ("not_approved", 0), ("applied", 0), ("dry_run", 0), ("nothing_applied", 0)])
def test_patch_rejection_is_visible_in_the_exit_code(status, code, monkeypatch, tmp_path, capsys):
    """AC: BSA-AC-80"""
    rec = {"name": "x", "error": None, "metrics": {}, "patch": {"status": status, "digest": "abc"}, "artifacts": {}, "stage_errors": {}}
    monkeypatch.setattr(pipeline, "run_project", lambda *a, **k: rec)
    rc = cli.main(["--root", str(tmp_path), "patch", str(tmp_path), "--no-llm", "--json"])
    capsys.readouterr()
    assert rc == code


@pytest.mark.parametrize("enc,keeps_hangul", [("utf-8", True), ("cp949", True), ("ascii", False), ("cp1252", False)])
def test_console_text_keeps_what_the_stream_can_show(enc, keeps_hangul):
    """AC: BSA-AC-81"""
    text = "caf" + chr(0xE9) + " " + chr(0x2014) + " " + chr(0xAE08) + chr(0xC735) + " " + chr(0x2192) + " ok"
    stream = io.TextIOWrapper(io.BytesIO(), encoding=enc)
    out = util.console_text(text, stream)
    out.encode(enc)                                        # must be encodable: never an exception on write
    assert ("" + chr(0xAE08) + chr(0xC735) in out) == keeps_hangul
    if enc in ("utf-8", "cp949"):
        assert out == text if enc == "utf-8" else chr(0xAE08) + chr(0xC735) in out
    else:
        assert " - " in out and " -> " in out              # typographic punctuation became ASCII, not '?'
    assert util.console_text("plain") == "plain"


def test_reports_embed_no_python_repr():
    """AC: BSA-AC-82"""
    m = {"components": 3, "vulns": 2, "severity": {"high": 1, "low": 1}, "license_resolved": 2, "license_total": 3,
         "license_resolved_rate": 0.67, "license_sources": {"registry": 2, "unresolved": 1}}
    md = report.project_md({"name": "p", "metrics": m, "patch": {}, "components": [], "vulns": []})
    assert "{'" not in md and "[{" not in md and "high 1, low 1" in md
    s = {"projects": 1, "errors": 0, "components": 3, "vulns": 2, "severity": {"high": 1}, "license_resolved_rate": 0.67,
         "license_sources": {"registry": 2}, "plans_verified_clean": 1, "plans_upgrade": 2, "patch": {"projects_patched": 1, "nested": {"a": 1}},
         "analysis_s_avg": 1.5, "proposals": {"exaone": 1, "keep": {"rate": 0.9}}}
    bmd = report.batch_md({"tag": "t", "summary": s}, [{"name": "p", "metrics": m}])
    assert "{'" not in bmd and "{" not in bmd.split("| project")[0]
    assert util.kv({"b": 2, "a": {"x": 1}}) == "a (x 1), b 2" and util.kv(None) == "-"


def test_web_pins_are_line_ending_independent():
    """AC: BSA-AC-83"""
    import hashlib
    web = REPO / "bts_sbom_app" / "web"
    rows = [ln.split("  ", 1) for ln in (web / "PLATFORM_ASSETS.sha256").read_text(encoding="utf-8").splitlines() if ln.strip()]
    ok = 0
    for digest, rel in rows:
        raw = (web / rel).read_bytes()
        lf = raw.replace(b"\r\n", b"\n")
        crlf = lf.replace(b"\n", b"\r\n")
        ok += hashlib.sha256(lf).hexdigest() == digest and hashlib.sha256(crlf.replace(b"\r\n", b"\n")).hexdigest() == digest
    assert ok == 6
    assert "bts_sbom_app/web/** text eol=lf" in (REPO / ".gitattributes").read_text(encoding="utf-8")
    assert "deterministic" in (web / "sca_app.js").read_text(encoding="utf-8") and "decisionmatic" not in (web / "sca_app.js").read_text(encoding="utf-8")
    json.dumps(rows)
