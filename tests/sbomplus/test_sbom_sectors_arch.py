"""SBOM documents, industry reports and architecture analysis."""
from __future__ import annotations

import copy

from sbomplus import arch, engine, sbom, sectors
from conftest import FakeScanner


def _doc(tmp_path):
    d = tmp_path / "s"
    d.mkdir(exist_ok=True)
    (d / "requirements.txt").write_text("requests==2.19.1\nflask==0.12\n", encoding="utf-8")
    ana = engine.analyze(str(d), scanner=FakeScanner())
    comps = ana["components"]
    next(c for c in comps if c["name"] == "requests").update(license="Apache-2.0", license_source="deps.dev")   # flask stays unresolved
    return comps, ana["vulns"], sbom.cyclonedx("demo", comps, ana["vulns"], lineage={"commit": "abc"})


def test_cyclonedx_refs_all_resolve(tmp_path):
    """AC: SP-AC-23"""
    comps, vulns, doc = _doc(tmp_path)
    assert doc["vulnerabilities"] and sbom.ref_integrity(doc)["rate"] == 1.0
    assert sbom.validate_cyclonedx(doc) == []


def test_no_license_evidence_means_no_license_entry(tmp_path):
    """AC: SP-AC-24"""
    comps, vulns, doc = _doc(tmp_path)
    by = {c["name"]: c for c in doc["components"]}
    assert "licenses" in by["requests"] and "licenses" not in by["flask"]


def test_validator_catches_dangling_reference(tmp_path):
    """AC: SP-AC-25"""
    _, _, doc = _doc(tmp_path)
    bad = copy.deepcopy(doc)
    bad["vulnerabilities"][0]["affects"] = [{"ref": "pkg:pypi/ghost@0"}]
    assert len(sbom.validate_cyclonedx(bad)) >= 1


def test_spdx_passes_core_validator(tmp_path):
    """AC: SP-AC-26"""
    comps, _, _ = _doc(tmp_path)
    assert sbom.validate_spdx(sbom.spdx("demo", comps)) == []


def test_maritime_without_vex_or_eol_is_not_evidence(tmp_path):
    """AC: SP-AC-27"""
    _, _, doc = _doc(tmp_path)
    rep = sectors.maritime_report(doc, None, None)
    rows = {r["id"]: r["verdict"] for r in rep["requirements"]}
    assert rows["MAR-04"] == "not_evidence" and rows["MAR-06"] == "not_evidence"
    assert sum(1 for k in ("MAR-04", "MAR-06") if rows[k] == "pass") == 0 and rep["draft"] is True


def test_seven_industries_from_one_sbom(tmp_path):
    """AC: SP-AC-28"""
    _, vulns, doc = _doc(tmp_path)
    vex = sbom.openvex("demo", vulns)
    reps = sectors.industry_reports(doc, vex, None)
    assert set(reps) == {"defense", "automotive", "medical", "finance", "maritime", "cra", "robot"} and len(reps) == 7


def test_import_cycle_detected(tmp_path):
    """AC: SP-AC-29"""
    (tmp_path / "a.py").write_text("import b\n\ndef f():\n    return b.g()\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("import a\n\ndef g():\n    return a\n", encoding="utf-8")
    res = arch.analyze(str(tmp_path))
    cyc = res["graph"]["cycles"]
    assert len(cyc) >= 1 and sorted(cyc[0]) == ["a.py", "b.py"]


def test_hotspot_ranks_frequent_complex_file_first(make_repo):
    """AC: SP-AC-30"""
    hot = "def f(x):\n" + "".join("    if x > %d:\n        x -= 1\n" % i for i in range(40)) + "    return x\n"
    repo = make_repo({"hot.py": hot + "# 0\n", "cold.py": "x = 0\n"},
                     extra_commits=[{"hot.py": hot + "# 1\n"}, {"hot.py": hot + "# 2\n", "cold.py": "x = 2\n"},
                                    {"hot.py": hot + "# 3\n"}, {"hot.py": hot + "# 4\n"}])
    res = arch.analyze(repo)
    assert res["history"]["commits"] == 5
    assert res["hotspots"][0]["file"] == "hot.py" and res["hotspots"][0]["commits"] == 5


def test_no_git_skips_hotspots_without_fabrication(tmp_path):
    """AC: SP-AC-31"""
    (tmp_path / "m.py").write_text("x = 1\n", encoding="utf-8")
    res = arch.analyze(str(tmp_path))
    assert res["hotspots"] == [] and sum(1 for n in res["notes"] if "hotspots/coupling skipped" in n) == 1


def test_eol_runtime_from_dockerfile_is_marked_unverified(tmp_path):
    """AC: SP-AC-32"""
    (tmp_path / "Dockerfile").write_text("FROM python:3.7-slim\nRUN true\n", encoding="utf-8")
    rts = arch.runtimes(str(tmp_path), online=False)
    assert len(rts) == 1 and rts[0]["status"] == "eol" and "UNVERIFIED" in rts[0]["source"]


def test_ruby_require_relative_ring_is_a_cycle_and_marked_partial(tmp_path):
    """AC: SP-AC-58"""
    for a, b in (("a", "b"), ("b", "c"), ("c", "a")):
        src = "\n".join(["require_relative '%s'" % b, "", "class %s; end" % a.upper(), ""])
        (tmp_path / (a + ".rb")).write_text(src, encoding="utf-8")
    res = arch.analyze(str(tmp_path))
    assert res["graph"]["import_edges"] == 3 and res["graph"]["cycle_count"] >= 1
    assert sum(1 for n in res["notes"] if n.startswith("ruby:")) == 1
