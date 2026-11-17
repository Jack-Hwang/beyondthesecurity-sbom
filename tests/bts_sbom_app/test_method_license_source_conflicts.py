"""Method test (PP-56 / AG-034): disclose disagreeing license-resolution sources instead of silently
keeping the first one. licenses.resolve() must still let the first readable source win for
c["license"]/c["license_source"] (unchanged default), but when a later source's normalized license
differs it must be surfaced in stats["conflicts"] rather than discarded."""
from __future__ import annotations

from bts_sbom_app import licenses


def test_conflicting_remote_sources_are_disclosed_not_discarded(tmp_path, monkeypatch):
    """AC: BSA-AC-208"""
    monkeypatch.setattr(licenses, "_depsdev", lambda eco, name, version: "MIT")
    monkeypatch.setattr(licenses, "_registry", lambda eco, name, version, extra=True: "Apache-2.0")
    comps = [{"name": "pkgx", "version": "1.0.0", "ecosystem": "PyPI"}]
    st = licenses.resolve(comps, str(tmp_path), online=True)
    # first-source-wins (deps.dev before registry) is unchanged - this is additive, not a behavior change
    assert comps[0]["license"] == "MIT" and comps[0]["license_source"] == "deps.dev"
    assert st["conflicts"] == [{"component": "pkgx@1.0.0", "value_a": "MIT", "source_a": "deps.dev",
                                 "value_b": "Apache-2.0", "source_b": "registry:pypi"}]


def test_agreeing_remote_sources_produce_no_conflict_entry(tmp_path, monkeypatch):
    """AC: BSA-AC-208"""
    monkeypatch.setattr(licenses, "_depsdev", lambda eco, name, version: "MIT")
    monkeypatch.setattr(licenses, "_registry", lambda eco, name, version, extra=True: "MIT")
    comps = [{"name": "pkgy", "version": "2.0.0", "ecosystem": "PyPI"}]
    st = licenses.resolve(comps, str(tmp_path), online=True)
    assert comps[0]["license"] == "MIT"
    assert st["conflicts"] == []


def test_single_source_components_never_produce_a_conflict(tmp_path, monkeypatch):
    """AC: BSA-AC-208"""
    monkeypatch.setattr(licenses, "_depsdev", lambda eco, name, version: "MIT")
    monkeypatch.setattr(licenses, "_registry", lambda eco, name, version, extra=True: None)
    comps = [{"name": "pkgz", "version": "3.0.0", "ecosystem": "PyPI"}]
    st = licenses.resolve(comps, str(tmp_path), online=True)
    assert comps[0]["license"] == "MIT"
    assert st["conflicts"] == []
