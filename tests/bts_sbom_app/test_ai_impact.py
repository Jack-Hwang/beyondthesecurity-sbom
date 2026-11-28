"""AI Impact Assessment export + staleness gate (course week 5 lesson 4, backlog C85): the assessment is an EXPORT of
artifacts the repository already produces - every cited path is resolved at build time so a ghost cannot be cited,
and the committed document is machine-checked for staleness (a cited artifact that moved, an AC id that renumbered,
a version stamp that predates the release) instead of quietly passing as current."""
import json
import os
import re

from bts_sbom_app import __version__, ai_impact, cli


# ------------------------------------------------------------------ assess: resolution, never invention
def test_assess_resolves_only_existing_artifacts_with_measured_detail():
    """AC: BSA-AC-1264"""
    p = ai_impact.assess()
    assert p["schema"] == ai_impact.SCHEMA and p["app_version"] == __version__
    assert p["risk"]["classification"] and len(p["risk"]["reason"]) > 40            # the classification is declared WITH its reasoning
    assert p["evidence"], "the repo has artifacts; the payload must list them"
    for row in p["evidence"]:
        assert os.path.exists(os.path.join(*row["path"].split("/"))), row["path"]   # every cited path exists - no ghost citations
        assert row["detail"].strip() and isinstance(row["acs"], list)
    rels = {r["path"] for r in p["evidence"]}
    assert "docs/ENFORCEMENT_MAP.md" in rels and any(r.startswith("evals/") for r in rels) and ".github/workflows/nightly-drift.yml" in rels


def test_render_covers_the_required_sections_and_never_invents_a_path():
    """AC: BSA-AC-1264"""
    p = ai_impact.assess()
    md = ai_impact.render(p)
    for s in ai_impact.SECTIONS:
        assert re.search(r"^## (?:\d+\. )?%s\s*$" % re.escape(s), md, re.M), s
    known = {r["path"] for r in p["evidence"]}
    for m in ai_impact._PATHY.finditer(md):
        assert m.group(1) in known, m.group(1)                                          # paths in the doc come from resolved evidence only
    assert "app_version: %s" % __version__ in md and "미확인 (기록된 근거 없음)" not in md      # this repo's slots are filled; an empty one would say 미확인


# ------------------------------------------------------------------ gate: staleness is caught, named, and exits non-zero
def _write_doc(path, md):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(md, encoding="utf-8")


def test_the_committed_document_passes_the_live_gate():
    """AC: BSA-AC-1264"""
    r = ai_impact.gate()
    assert r["ok"] is True and r["findings"] == [], r["findings"]


def test_gate_names_each_staleness_cause_instead_of_passing(tmp_path):
    """AC: BSA-AC-1264"""
    md = ai_impact.render(ai_impact.assess())
    gone = md.replace("docs/ENFORCEMENT_MAP.md", "docs/ENFORCEMENT_MAP_MOVED.md")
    _write_doc(tmp_path / "a.md", gone)
    r1 = ai_impact.gate(tmp_path, str(tmp_path / "a.md"))
    assert any("ENFORCEMENT_MAP_MOVED.md" in f and "stale" in f for f in r1["findings"]) and r1["ok"] is False
    renum = md.replace("BSA-AC-14, BSA-AC-15", "BSA-AC-9876, BSA-AC-9877")             # an id that is actually rendered into the doc
    _write_doc(tmp_path / "b.md", renum)
    r2 = ai_impact.gate(tmp_path, str(tmp_path / "b.md"))
    assert any("BSA-AC-9876" in f and "renumbered" in f for f in r2["findings"])
    old = md.replace("app_version: %s" % __version__, "app_version: 0.0.1")
    _write_doc(tmp_path / "c.md", old)
    r3 = ai_impact.gate(tmp_path, str(tmp_path / "c.md"))
    assert any("0.0.1" in f and "predates" in f for f in r3["findings"])
    nogate = md.replace("| Spec | `bts_sbom_app/speclint.py` (AC 없는 표면·미지정 AC 기계 검출) |", "| Spec | (설명만 있음) |")
    _write_doc(tmp_path / "d.md", nogate)
    r4 = ai_impact.gate(tmp_path, str(tmp_path / "d.md"))
    assert any("Spec" in f and "no evidence" in f for f in r4["findings"])            # a gate row must cite evidence or say 미확인
    r_missing = ai_impact.gate(tmp_path, str(tmp_path / "missing.md"))
    assert r_missing["ok"] is False and "missing" in r_missing["findings"][0]
    nosecs = "# AI 영향평가서\n\n빈 문서다.\n"
    _write_doc(tmp_path / "e.md", nosecs)
    r5 = ai_impact.gate(tmp_path, str(tmp_path / "e.md"))
    assert sum("required section missing" in f for f in r5["findings"]) == len(ai_impact.SECTIONS)


# ------------------------------------------------------------------ the command surface
def test_the_ai_impact_command_prints_writes_and_checks(capsys, tmp_path):
    """AC: BSA-AC-1264"""
    assert cli.main(["ai-impact", "--check"]) == 0                                     # the committed doc is current
    assert cli.main(["ai-impact", "--write", str(tmp_path / "out.md")]) == 0
    assert (tmp_path / "out.md").exists() and "app_version:" in (tmp_path / "out.md").read_text(encoding="utf-8")
    capsys.readouterr()
    assert cli.main(["ai-impact", "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["schema"] == ai_impact.SCHEMA and payload["evidence"]
    assert cli.main(["ai-impact"]) == 0
    assert "# AI 영향평가서" in capsys.readouterr().out
