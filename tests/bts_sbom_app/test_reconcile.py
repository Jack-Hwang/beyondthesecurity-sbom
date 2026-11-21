"""Reconcile: provider SBOM vs scanned artifacts (task 32, TR 8477 P2-B / 5.2, AC 741-748)."""
from __future__ import annotations

import json

from bts_sbom_app import reconcile

CDX = {"bomFormat": "CycloneDX", "components": [
    {"name": "requests", "version": "2.19.1", "purl": "pkg:pypi/requests@2.19.1"},
    {"name": "flask", "version": "2.0.0", "purl": "pkg:pypi/flask@2.0.0"},
    {"name": "ghostpkg", "version": "9.9", "purl": "pkg:pypi/ghostpkg@9.9"},
]}
REC = {"name": "proj", "components": [
    {"name": "requests", "version": "2.20.0"},                       # version mismatch
    {"name": "flask", "version": "2.0.0"},                            # matches
    {"name": "undeclared-lib", "version": "1.0"},                     # not in the provider SBOM
], "vulns": [{"id": "CVE-2020-1111", "package": "requests", "version": "2.20.0"}]}
CDX_VULNS = {"bomFormat": "CycloneDX", "components": CDX["components"],
             "vulnerabilities": [{"id": "CVE-2020-2222", "affects": [{"ref": "pkg:pypi/flask@2.0.0"}]}]}


def test_undeclared_scanned_components_are_candidates():
    """AC: BSA-AC-741"""
    res = reconcile.reconcile(CDX, REC)
    cand = [c for c in res["undeclared_candidates"] if c["name"] == "undeclared-lib"]
    assert len(cand) == 1 and "candidate" in cand[0]["evidence"]


def test_declared_but_unscanned_components_are_reported(tmp_path):
    """AC: BSA-AC-742"""
    res = reconcile.reconcile(CDX, REC)
    missing = {m["name"] for m in res["missing_from_artifacts"]}
    assert "ghostpkg" in missing


def test_version_mismatch_is_reported_with_both_sides():
    """AC: BSA-AC-743"""
    res = reconcile.reconcile(CDX, REC)
    mm = [m for m in res["missing_from_artifacts"] if m.get("evidence") == "version mismatch"]
    assert any(m["name"] == "requests" and m["declared_version"] == "2.19.1" and m["scanned_version"] == "2.20.0" for m in mm)


def test_bom_vulns_vs_scan_vulns_diff_both_ways():
    """AC: BSA-AC-744"""
    res = reconcile.reconcile(CDX_VULNS, REC)
    only_scan = {v["id"] for v in res["vulns"]["only_in_scan"]}
    only_bom = {v["id"] for v in res["vulns"]["only_in_bom"]}
    assert "CVE-2020-1111" in only_scan and "CVE-2020-2222" in only_bom


def test_string_evidence_stays_candidate_not_identification():
    """AC: BSA-AC-745"""
    res = reconcile.reconcile(CDX, REC, string_evidence=[{"path": "bin/app.exe", "text": "undeclared-lib"}])
    cand = [c for c in res["undeclared_candidates"] if c["name"] == "undeclared-lib"]
    assert cand and "not identification" in cand[0]["evidence"]


def test_no_conformance_verdict_is_ever_issued():
    """AC: BSA-AC-746"""
    blob = json.dumps(reconcile.reconcile(CDX, REC)).lower()
    assert "conformance verdict" not in blob.replace("no conformance verdict", "")
    assert "no conformance verdict" in json.dumps(reconcile.reconcile(CDX, REC))


def test_counts_and_disclaimer_on_the_json():
    """AC: BSA-AC-747"""
    res = reconcile.reconcile(CDX, REC)
    assert res["declared_components"] == 3 and res["scanned_components"] == 3
    assert res["disclaimer"] == reconcile.DISCLAIMER and res["schema"] == reconcile.SCHEMA


def test_deterministic_bytes():
    """AC: BSA-AC-748"""
    a = json.dumps(reconcile.reconcile(CDX, REC), sort_keys=True)
    b = json.dumps(reconcile.reconcile(CDX, REC), sort_keys=True)
    assert a == b
