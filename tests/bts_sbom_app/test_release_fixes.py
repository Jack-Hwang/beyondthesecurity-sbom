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


# ═══ wave 2 ═══════════════════════════════════════════════════════════════════

def test_fully_blocked_patch_is_reported_as_blocked(make_repo):
    """AC: BSA-AC-84"""
    from conftest import FakeScanner
    repo = make_repo({"requirements.txt": "flask>=0.12,<1.0" + chr(10)})
    plan = {"component": "flask", "ecosystem": "PyPI", "current_version": "0.12", "safe_version": "3.1.3", "status": "upgrade",
            "files": ["requirements.txt"], "verification": {"clean": True}}
    rec = {"vulns": [{"id": "X", "package": "flask", "version": "0.12", "files": ["requirements.txt"]}], "plans": [plan]}
    out = pipeline._patch_loop(rec, repo, approved=True, token=None, rounds=2, offline=True, scanner=FakeScanner(), verify_rounds=1)
    assert out["status"] == "blocked" and "blocked by manifest constraints" in out["note"]


def test_chat_says_why_exaone_was_not_used():
    """AC: BSA-AC-85"""
    from bts_sbom_app import chat as chatmod, evals
    idx = evals.build_index(str(REPO), [])
    for q in ("What is a CycloneDX SBOM?", "zebra quantum mango recipe"):          # one answerable, one outside the corpus
        r = chatmod.Chatbot(idx, {}, None).ask(q, use_llm=True)
        assert r["answer_source"] != "exaone" and "unavailable" in r["llm_note"] and "EXAONE_API_KEY" in r["llm_note"], q
        assert chatmod.Chatbot(idx, {}, None).ask(q, use_llm=False)["llm_note"] == ""


def test_loop_gate_boundary_is_exact():
    """AC: BSA-AC-86"""
    from bts_sbom_app import loop
    k = loop.HIGHER[0] if isinstance(loop.HIGHER, (list, tuple)) else next(iter(loop.HIGHER))
    for b, c in ((0.917, 0.897), (1.0, 0.98), (0.869, 0.849), (0.738, 0.718)):
        assert loop.gate({k: b}, {k: c})["pass"] is True, (b, c)         # a drop of exactly 0.02 is allowed
    assert loop.gate({k: 1.0}, {k: 0.9799})["pass"] is False             # more than 0.02 fails


def test_batch_accepts_bare_strings_and_reports_entries_without_a_source(monkeypatch, tmp_path):
    """AC: BSA-AC-87"""
    from bts_sbom_app import batch
    seen = []

    def fake(src, **kw):
        seen.append(src)
        return {"name": "n-" + str(len(seen)), "error": "stub", "metrics": {}}

    monkeypatch.setattr(pipeline, "run_project", fake)
    out = batch.run_batch([str(tmp_path), {"name": "no-source"}], out_root=str(tmp_path / "o"), tag="t", client=None)
    recs = out["records"] if isinstance(out, dict) and "records" in out else out[1] if isinstance(out, tuple) else []
    assert seen == [str(tmp_path)]
    assert any("needs a source" in str(r.get("error")) for r in recs)
