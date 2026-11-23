"""Engine, CVSS, versions, remediation verification and license discovery (offline, fake world)."""
from __future__ import annotations

import json
import re

from bts_sbom_app import cvss, engine, licenses, remediate, versions
from conftest import FakeScanner


def _req(tmp_path, text: str) -> str:
    d = tmp_path / "r"
    d.mkdir(exist_ok=True)
    (d / "requirements.txt").write_text(text, encoding="utf-8")
    return str(d)


def test_cvss_reference_vectors():
    """AC: BSA-AC-6"""
    assert cvss.base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H") == 9.8
    assert cvss.base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H") == 7.5
    assert cvss.base_score_v3("CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N") == 6.1
    assert cvss.base_score_v3("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N") is None     # v4 is not guessed


def test_version_order_basics():
    assert versions.compare("1.0", "1.0.0") == 0
    assert versions.compare("2.0.0rc1", "2.0.0") < 0 < versions.compare("2.0.0.post1", "2.0.0")
    assert versions.compare("v1.2.3", "1.2.10") < 0
    assert not versions.is_version("74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5")


def test_fixed_versions_never_a_commit_sha(tmp_path):
    """AC: BSA-AC-4"""
    ana = engine.analyze(_req(tmp_path, "requests==2.19.1\nflask==0.12\npyyaml==3.12\n"), scanner=FakeScanner())
    assert ana["vulns"], "fixture must produce findings"
    fixed = [v["fixed_version"] for v in ana["vulns"]] + [c for v in ana["vulns"] for c in v["fixed_candidates"]]
    assert all(not re.fullmatch(r"[0-9a-f]{40}", f) for f in fixed if f)
    assert {v["fixed_version"] for v in ana["vulns"] if v["package"] == "requests"} == {"2.20.0", "2.31.0"}


def test_alias_records_become_one_finding(tmp_path):
    """AC: BSA-AC-5"""
    ana = engine.analyze(_req(tmp_path, "requests==2.19.1\n"), scanner=FakeScanner())
    first = [v for v in ana["vulns"] if v["id"] == "CVE-2020-1111"]
    assert len(first) == 1
    assert set(first[0]["aliases"]) >= {"GHSA-req1-aaaa-aaaa", "PYSEC-2020-1"}
    assert len(ana["vulns"]) == 2                                   # the GHSA/PYSEC/CVE trio is ONE, plus the 2.31.0 advisory


def test_osv_failure_is_unverified_not_clean(tmp_path, world):
    """AC: BSA-AC-7"""
    ana = engine.analyze(_req(tmp_path, "pyyaml==3.12\n"), scanner=FakeScanner())
    plans = remediate.plan(ana["components"], ana["vulns"])
    world.fail_osv = True
    remediate.verify(plans)
    assert plans[0]["verification"]["clean"] is None
    assert plans[0]["verification"].get("stopped") == "osv_unreachable"


def test_verify_bumps_to_later_fix(tmp_path, world):
    """AC: BSA-AC-13"""
    ana = engine.analyze(_req(tmp_path, "flask==0.12\n"), scanner=FakeScanner())
    plans = remediate.plan(ana["components"], ana["vulns"])
    assert plans[0]["safe_version"] == "1.0"
    remediate.verify(plans, max_rounds=3)
    p = plans[0]
    assert p["safe_version"] == "1.0.1" and p["verification"]["bumped_from"] == "1.0" and p["verification"]["clean"] is True
    assert p["verification"]["rounds"] <= 3


def test_license_spellings_map_or_stay_unmapped():
    """AC: BSA-AC-8"""
    ok = ["MIT", "Apache 2.0", "Apache-2.0 OR MIT", "GPLv3", "BSD", "LGPL-2.1+", "MIT/Apache-2.0", {"type": "ISC"},
          "GNU General Public License v3 (GPLv3)", "Mozilla Public License 2.0 (MPL 2.0)"]
    bad = ["Some Weird License", "Totally Custom EULA v9"]
    mapped = [licenses.normalize(x)[0] for x in ok]
    assert all(mapped) and len(mapped) == 10
    assert all(licenses.category(m) != "unknown" for m in mapped)
    assert [licenses.normalize(x)[0] for x in bad] == ["", ""]


def test_lockfile_license_offline_and_unresolved_stays_unresolved(tmp_path):
    """AC: BSA-AC-9"""
    lock = {"lockfileVersion": 3, "packages": {"": {"name": "app"}, "node_modules/left-pad": {"version": "1.3.0", "license": "WTFPL"},
                                                "node_modules/mystery": {"version": "0.1.0"}}}
    (tmp_path / "package-lock.json").write_text(json.dumps(lock), encoding="utf-8")
    comps = [{"name": "left-pad", "version": "1.3.0", "ecosystem": "npm"}, {"name": "mystery", "version": "0.1.0", "ecosystem": "npm"}]
    st = licenses.resolve(comps, str(tmp_path), online=False)
    assert comps[0]["license"] == "WTFPL" and comps[0]["license_source"] == "lockfile"
    assert comps[1]["license"] == "" and st["resolved"] == 1 and st["total"] == 2


def test_depsdev_then_registry_provenance(tmp_path, world):
    """AC: BSA-AC-10"""
    comps = [{"name": n, "version": v, "ecosystem": "PyPI"} for n, v in (("requests", "2.19.1"), ("pyyaml", "3.12"), ("flask", "0.12"))]
    st = licenses.resolve(comps, str(tmp_path), online=True)
    assert st["by_source"] == {"deps.dev": 2, "registry:pypi": 1}
    assert {c["name"]: c["license_source"] for c in comps} == {"requests": "deps.dev", "pyyaml": "deps.dev", "flask": "registry:pypi"}


def test_project_license_from_root_file_and_spdx_headers(tmp_path):
    """AC: BSA-AC-11"""
    (tmp_path / "LICENSE").write_text("MIT License\n\nPermission is hereby granted, free of charge, to any person obtaining a copy\n", encoding="utf-8")
    for i in range(3):
        (tmp_path / ("m%d.py" % i)).write_text("# SPDX-License-Identifier: MIT\nx = %d\n" % i, encoding="utf-8")
    t = licenses.scan_tree(str(tmp_path))
    assert t["project_license"] == "MIT" and t["project_license_source"] == "root license file"
    assert t["spdx_header_counts"] == {"MIT": 3}


def test_copyleft_conflict_only_when_distributed():
    """AC: BSA-AC-12"""
    comps = [{"name": "gplpkg", "version": "1", "license": "GPL-3.0-only", "license_category": "strong-copyleft"}]
    binary = [f for f in licenses.policy_findings(comps, {"distribution": "binary"}, "MIT") if f["verdict"] == "conflict"]
    internal = [f for f in licenses.policy_findings(comps, {"distribution": "internal"}, "MIT") if f["verdict"] == "conflict"]
    assert len(binary) == 1 and len(internal) == 0


def test_two_plans_with_same_candidate_are_both_verified(world):
    """AC: BSA-AC-46"""
    def plan(cur):
        return {"component": "flask", "ecosystem": "PyPI", "current_version": cur, "safe_version": "1.0.1", "status": "upgrade", "clears": [],
                "uncleared": [], "cve_count": 1, "major_bump": False, "breaking_risk": "low", "files": [], "max_severity": "HIGH", "max_cvss": 7.5,
                "verification": {"clean": None, "method": "not_run", "rounds": 0, "residual": []}}
    plans = [plan("0.12"), plan("0.12.2")]
    remediate.verify(plans)
    assert [p["verification"]["clean"] for p in plans] == [True, True]


def test_parentheses_survive_and_spdx_validates(tmp_path):
    """AC: BSA-AC-47"""
    from bts_sbom_app import sbom
    expr, _ = licenses.normalize("BSD-3-Clause AND (Apache-2.0 OR MIT)")
    assert expr == "BSD-3-Clause AND (Apache-2.0 OR MIT)"
    other, _ = licenses.normalize("(BSD-3-Clause AND Apache-2.0) OR MIT")
    assert other != expr and licenses.category(expr) == "permissive"
    comps = [{"name": "encoding_rs", "version": "0.8.35", "ecosystem": "crates.io", "license": expr, "relationship": "direct"}]
    assert sbom.validate_spdx(sbom.spdx("demo", comps)) == []


def test_wellformed_unknown_ids_resolve_and_nonspdx_spellings_do_not():
    """AC: BSA-AC-48"""
    ids = ["Artistic-1.0-Perl", "AFL-2.1", "MIT-CMU"]
    spell = ["BSD-like", "BSD*", "SEE LICENSE IN COPYING.txt"]
    assert [licenses.normalize(i)[0] for i in ids] == ids
    assert [licenses.normalize(s)[0] for s in spell] == ["", "", ""]


def test_registry_fallbacks_cover_legacy_npm_and_maven_pom(tmp_path, world):
    """AC: BSA-AC-49"""
    comps = [{"name": "body", "version": "5.1.0", "ecosystem": "npm"}, {"name": "org.example:lib", "version": "1.0", "ecosystem": "Maven"}]
    st = licenses.resolve(comps, str(tmp_path), online=True)
    assert comps[0]["license"] == "MIT" and comps[1]["license"] == "Apache-2.0"
    assert st["by_source"] == {"registry:npm": 1, "registry:maven": 1}


def test_cached_raw_evidence_is_reinterpreted_without_network(tmp_path, world, monkeypatch):
    """AC: BSA-AC-50"""
    cache = str(tmp_path / "c")
    real = licenses.normalize
    monkeypatch.setattr(licenses, "normalize", lambda raw: ("", "unmapped"))          # the "old" normaliser reads nothing
    c1 = [{"name": "requests", "version": "2.19.1", "ecosystem": "PyPI"}]
    st1 = licenses.resolve(c1, str(tmp_path), online=True, cache_dir=cache)
    assert c1[0]["license"] == "" and st1["remote_lookups"] == 1
    monkeypatch.setattr(licenses, "normalize", real)                                   # the normaliser improves
    c2 = [{"name": "requests", "version": "2.19.1", "ecosystem": "PyPI"}]
    st2 = licenses.resolve(c2, str(tmp_path), online=True, cache_dir=cache)
    assert c2[0]["license"] == "Apache-2.0" and st2["remote_lookups"] == 0 and st2["cache_hits"] == 1


def test_extra_registries_switch_isolates_the_fallbacks(tmp_path, world):
    """AC: BSA-AC-51"""
    comps = [{"name": "body", "version": "5.1.0", "ecosystem": "npm"}, {"name": "org.example:lib", "version": "1.0", "ecosystem": "Maven"}]
    st = licenses.resolve(comps, str(tmp_path), online=True, extra_registries=False)
    assert st["resolved"] == 0 and not any("repo1.maven.org" in u for u in world.calls)


def test_setup_py_disclosure_surfaces_through_the_engine(tmp_path):
    """AC: BSA-AC-615. The roster disclosure reaches the engine's normalized scan status: a setup.py-only tree is
    unsupported_manifest, never empty_project (u-boot's tools ship several)."""
    from bts_sbom_app import engine
    proj = tmp_path / "proj"
    proj.mkdir()
    stub = 'from setuptools import setup\nsetup(name="x")\n'
    (proj / "setup.py").write_text(stub, encoding="utf-8")
    native = engine.scan(str(proj), offline=True)
    comp = native["completeness"]["parse"]
    assert comp["unsupported"] and comp["unsupported"][0]["path"].endswith("setup.py")
    assert not comp["parsed_sources"]
