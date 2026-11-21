"""Migration plan waves and honest site accounting (task 26, brief 2, AC 646-657)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import migration
from bts_sbom_app.util import tree_hash
from conftest import FakeScanner

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _plan(component="lib", status="upgrade", current="1.2.0", target="1.3.0", rel="direct"):
    return {"component": component, "status": status, "current_version": current, "safe_version": target, "relationship": rel}


def _rec(plans, legacy=None):
    return {"plans": plans, "legacy": legacy or {}}


def _source(tmp_path, files):
    root = tmp_path / "src"
    (root / "pkg").mkdir(parents=True)
    for name, body in files.items():
        (root / name).write_text(body, encoding="utf-8", newline="\n")
    return str(root)


def test_minor_jump_with_few_sites_is_wave_a(tmp_path):
    """AC: BSA-AC-646"""
    root = _source(tmp_path, {"pkg/app.py": "import lib\n\nlib.run()\nimport lib\nimport lib\n"})
    res = migration.plan(_rec([_plan(target="1.3.0")]), root=root)
    item = res["items"][0]
    assert item["wave"] == "A" and item["jump"] == "minor"
    assert item["code_sites"]["available"] is True and item["code_sites"]["sites"] == 3 and item["code_sites"]["files"] == 1


def test_major_jump_or_many_sites_is_wave_b(tmp_path):
    """AC: BSA-AC-647"""
    root = _source(tmp_path, {"pkg/app.py": "".join("import lib\n" for _ in range(12))})
    res = migration.plan(_rec([_plan(target="2.0.0")]), root=root)
    assert res["items"][0]["wave"] == "B" and res["items"][0]["jump"] == "major"
    res2 = migration.plan(_rec([_plan(target="1.4.0")]), root=root)      # minor jump, 12 sites > 10
    assert res2["items"][0]["wave"] == "B"
    res3 = migration.plan(_rec([_plan(current="abc", target="def")]), root=str(tmp_path))  # unparseable -> unknown jump
    assert res3["items"][0]["jump"] == "unknown" and res3["items"][0]["wave"] == "B"


def test_no_fix_or_high_legacy_is_wave_c_with_the_four_options(tmp_path):
    """AC: BSA-AC-648"""
    res = migration.plan(_rec([_plan(status="no_fix")]))
    item = res["items"][0]
    assert item["wave"] == "C" and [o["id"] for o in item["options"]] == list(migration.C_OPTIONS)
    assert any("VEX" in o.get("note", "") for o in item["options"])
    res2 = migration.plan(_rec([_plan()], legacy={"rows": [{"component": "lib", "risk": "high"}]}))
    assert res2["items"][0]["wave"] == "C"


def test_missing_source_reports_available_false_never_zero_sites(tmp_path):
    """AC: BSA-AC-649"""
    res = migration.plan(_rec([_plan(), _plan("lib2"), _plan("lib3")]))
    assert all(i["code_sites"]["available"] is False and i["code_sites"]["note"] == "source not provided" for i in res["items"])
    assert all(i["code_sites"]["sites"] == 0 for i in res["items"])       # 0 sites WITH available=false only


def test_zero_sites_in_a_given_source_carries_the_honest_note(tmp_path):
    """AC: BSA-AC-650"""
    root = _source(tmp_path, {"pkg/app.py": "import os\nprint(1)\n"})    # no import of `lib`
    res = migration.plan(_rec([_plan()]), root=root)
    note = res["items"][0]["code_sites"]["note"]
    assert "does not prove no impact" in note


def test_transitive_dependency_reports_no_direct_import(tmp_path):
    """AC: BSA-AC-651"""
    root = _source(tmp_path, {"pkg/app.py": "import lib\n"})
    res = migration.plan(_rec([_plan(rel="transitive")]), root=root)
    assert res["items"][0]["code_sites"]["available"] is False
    assert res["items"][0]["code_sites"]["note"] == "transitive dependency - no direct import"


def test_nothing_is_written_into_the_source(tmp_path):
    """AC: BSA-AC-652"""
    root = _source(tmp_path, {"pkg/app.py": "import lib\n"})
    before = tree_hash(root)
    migration.plan(_rec([_plan(target="9.9.9")]), root=root)
    assert tree_hash(root) == before
    assert all(i["needs_human"] is True for i in migration.plan(_rec([_plan()]), root=root)["items"])


def test_site_cap_is_reported_as_bounded(tmp_path):
    """AC: BSA-AC-653"""
    root = _source(tmp_path, {"pkg/app.py": "".join("import lib\n" for _ in range(15))})
    res = migration.plan(_rec([_plan()]), root=root, max_sites_per_component=10)
    cs = res["items"][0]["code_sites"]
    assert cs["sites"] == 10 and cs["bounded"] is True


def test_a_raising_migration_stage_is_recorded(tmp_path, make_repo, world, monkeypatch):
    """AC: BSA-AC-654"""
    from bts_sbom_app import pipeline
    from conftest import FakeScanner
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    monkeypatch.setattr(migration, "plan", lambda *a, **kw: (_ for _ in ()).throw(RuntimeError("boom")))
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False,
                               scanner=FakeScanner(), run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    assert rec["error"] is None and "migration" in rec["stage_errors"]


def test_the_api_computes_on_read_without_source(tmp_path, make_repo, world):
    """AC: BSA-AC-655"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    from bts_sbom_app import pipeline
    pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                         run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    res = migration.plan({"plans": []}, root=None)
    assert res["source_available"] is False and res["computed_on_read"] is False


def test_the_cli_reads_only_the_given_folder(tmp_path, make_repo, world):
    """AC: BSA-AC-656"""
    from bts_sbom_app import cli, pipeline
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"))
    src = _source(tmp_path, {"pkg/app.py": "import lib\n"})
    outside = tmp_path / "outside.txt"
    outside.write_text("secret", encoding="utf-8")
    before = tree_hash(str(tmp_path))
    rc = cli.main(["--root", os.getcwd(), "migration", rec["name"], "--evidence", ev, "--source", src, "--json"])
    assert rc == 0
    assert tree_hash(str(tmp_path)) == before and os.path.exists(outside)          # nothing changed, nothing read outside


def test_bytes_are_identical_and_the_disclaimer_is_on_three_surfaces(tmp_path):
    """AC: BSA-AC-657"""
    rec = _rec([_plan()], legacy={"rows": [{"component": "lib", "risk": "high"}]})
    a = json.dumps(migration.plan(rec), sort_keys=True)
    b = json.dumps(migration.plan(rec), sort_keys=True)
    assert a == b and migration.DISCLAIMER in json.dumps(migration.plan(rec), ensure_ascii=False)
    from bts_sbom_app import cli_ext
    assert "migration" in cli_ext.COMMANDS                               # CLI surface registered
    from bts_sbom_app import report
    md = report.project_md({"name": "x", "metrics": {}, "error": None, "license": {}, "migration": migration.plan(rec), "vulns": [], "plans": [], "lineage": {}})
    assert migration.DISCLAIMER in md
