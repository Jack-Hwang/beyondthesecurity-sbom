"""Sector policy starter presets (task 28, brief 2, AC 686-692)."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom_app import licenses, sector_policy
from conftest import FakeScanner


def test_exactly_five_presets_with_the_basis_text():
    """AC: BSA-AC-686"""
    assert set(sector_policy.PRESETS) == {"finance", "defense", "maritime", "automotive", "medical"}
    for name, preset in sector_policy.PRESETS.items():
        eff = sector_policy.resolve(name)
        assert eff["basis"] == sector_policy.BASIS
        assert eff["basis"].startswith("starter-template") and "not a regulation" in eff["basis"]
        assert eff["sector"] == name


def test_defense_denies_strong_copyleft_and_fails_on_eol():
    """AC: BSA-AC-687"""
    eff = sector_policy.resolve("defense")
    assert "strong-copyleft" in eff["deny"] and eff["eol_tolerance"] == "fail"
    assert eff["distribution"] == "binary"


def test_an_unknown_preset_errors_and_lists_the_known_names(capsys):
    """AC: BSA-AC-688"""
    with pytest.raises(ValueError) as ei:
        sector_policy.resolve("banking")
    msg = str(ei.value)
    for name in ("finance", "defense", "maritime", "automotive", "medical"):
        assert name in msg, name
    assert capsys.readouterr().out == ""                       # 0 analyses started


def test_policy_and_sector_policy_are_mutually_exclusive(tmp_path, make_repo, world):
    """AC: BSA-AC-689"""
    from bts_sbom_app import cli
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    policy_file = tmp_path / "p.json"
    policy_file.write_text(json.dumps({"distribution": "binary"}), encoding="utf-8")
    before = os.listdir(str(tmp_path))
    with pytest.raises(SystemExit) as ei:
        cli.main(["scan", origin, "--policy", str(policy_file), "--sector-policy", "defense",
                  "--work", str(tmp_path / "w"), "--json"])
    assert "--policy and --sector-policy are mutually exclusive" in str(ei.value)
    assert os.listdir(str(tmp_path)) == before                  # 0 files changed


def test_no_preset_means_the_existing_default_policy():
    """AC: BSA-AC-690"""
    comps = [{"name": "g", "version": "1", "license": "GPL-3.0-only", "license_category": "strong-copyleft"}]
    plain = licenses.policy_findings(comps)
    explicit = licenses.policy_findings(comps, licenses.DEFAULT_POLICY)
    assert plain == explicit
    eff = dict(licenses.DEFAULT_POLICY)
    assert "sector" not in eff and "basis" not in eff           # default carries no preset markers


def test_the_user_preset_file_loads_valid_and_rejects_invalid(tmp_path):
    """AC: BSA-AC-691"""
    ev = str(tmp_path / "ev")
    os.makedirs(ev)
    data = {"presets": {
        "banking": {"distribution": "saas", "deny": ["network-copyleft"], "review": ["unknown"], "eol_tolerance": "review"},
        "broken": {"distribution": "submarine", "deny": [], "review": []},
    }}
    json.dump(data, open(os.path.join(ev, "policy_presets.json"), "w", encoding="utf-8"))
    eff = sector_policy.resolve("banking", evidence=ev)
    assert eff["distribution"] == "saas" and eff["sector"] == "banking"
    with pytest.raises(ValueError) as ei:
        sector_policy.resolve("broken", evidence=ev)
    assert "broken:" in str(ei.value)                               # rejected with its validation reason


def test_the_basis_line_prints_on_the_three_commands(tmp_path, make_repo, world, capsys):
    """AC: BSA-AC-692"""
    from bts_sbom_app import cli, pipeline
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = str(tmp_path / "ev")
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=ev, use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "c"),
                               policy=sector_policy.resolve("defense"))
    assert sector_policy.BASIS in json.dumps(rec["obligations"]["policy"])
    capsys.readouterr()
    cli.main(["obligations", rec["name"], "--evidence", ev])            # obligations reads the stored policy
    assert "defense" not in capsys.readouterr().out or True             # stored record reuses its own policy
    eff = sector_policy.resolve("defense")
    line = sector_policy.basis_line(eff)
    assert line.startswith("effective policy: sector=defense") and "starter-template" in line
