"""Engine corrections found by the first real e2e passes: duplicate findings, Ruby platform variants, go.sum-only versions."""
from __future__ import annotations

from bts_sbom_app import engine
from conftest import V3_98, adv


def _pkg(eco, name, ver, vulns=()):
    return {"package": {"name": name, "version": ver, "ecosystem": eco},
            "identity": {"name": name, "ecosystem": eco, "version": ver, "purl": "pkg:%s/%s@%s" % (eco.lower(), name, ver), "relationship": "direct", "depth": 0},
            "query_status": "queried_online", "vulnerabilities": list(vulns)}


def _native(*sources):
    return {"results": [{"source": {"path": path, "type": "lockfile"}, "packages": pkgs} for path, pkgs in sources],
            "scan_status": {}, "completeness": {}, "notes": []}


def test_same_advisory_from_two_manifests_is_one_finding(tmp_path):
    """AC: BSA-AC-52"""
    doc = adv("GHSA-lod1-aaaa-aaaa", ["CVE-2019-0001"], "lodash", "npm", "0", "4.17.11", V3_98)
    nat = _native((str(tmp_path / "package.json"), [_pkg("npm", "lodash", "4.17.4", [doc])]),
                  (str(tmp_path / "package-lock.json"), [_pkg("npm", "lodash", "4.17.4", [doc])]))
    ana = engine.normalize(nat, str(tmp_path))
    assert len(ana["vulns"]) == 1 and sorted(ana["vulns"][0]["files"]) == ["package-lock.json", "package.json"]
    assert ana["adjustments"]["duplicate_findings_merged"] == 1
    assert len(engine.normalize(nat, str(tmp_path), dedupe=False)["vulns"]) == 2          # the switch really isolates it


def test_ruby_platform_variants_are_one_component(tmp_path):
    """AC: BSA-AC-53"""
    pk = [_pkg("RubyGems", "ffi", v) for v in ("1.17.3", "1.17.3-arm64-darwin", "1.17.3-x86_64-linux")]
    ana = engine.normalize(_native((str(tmp_path / "Gemfile.lock"), pk)), str(tmp_path))
    assert len(ana["components"]) == 1 and sorted(ana["components"][0]["platforms"]) == ["arm64-darwin", "x86_64-linux"]
    assert ana["adjustments"]["ruby_platform_variants_merged"] == 2
    assert len(engine.normalize(_native((str(tmp_path / "Gemfile.lock"), pk)), str(tmp_path), merge_ruby_platforms=False)["components"]) == 3


def test_go_sum_only_version_is_not_an_installed_package(tmp_path):
    """AC: BSA-AC-54"""
    gomod = ["module x", "", "go 1.22", "", "require (", "\tgolang.org/x/sys v0.47.0", ")", ""]
    (tmp_path / "go.mod").write_text("\n".join(gomod), encoding="utf-8")
    pk = [_pkg("Go", "golang.org/x/sys", "v0.47.0"), _pkg("Go", "golang.org/x/sys", "v0.6.0")]
    ana = engine.normalize(_native((str(tmp_path / "go.sum"), pk)), str(tmp_path))
    assert [c["version"] for c in ana["components"]] == ["v0.47.0"] and ana["adjustments"]["go_sum_only_dropped"] == 1
    assert len(engine.normalize(_native((str(tmp_path / "go.sum"), pk)), str(tmp_path), go_mvs=False)["components"]) == 2


def test_malware_advisory_is_critical(tmp_path):
    """AC: BSA-AC-60"""
    doc = adv("MAL-2023-462", ["GHSA-xv2f-5jw4-v95m"], "fsevents", "npm", "0", None, V3_98)
    doc["severity"] = []                                      # malicious-package records carry no CVSS vector
    ana = engine.normalize(_native((str(tmp_path / "package-lock.json"), [_pkg("npm", "fsevents", "1.2.4", [doc])])), str(tmp_path))
    v = ana["vulns"][0]
    assert v["severity"] == "CRITICAL" and v["score_source"] == "malware-advisory" and v["malicious"] is True
