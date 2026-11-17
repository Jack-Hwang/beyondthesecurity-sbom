"""Regression: a component without a usable ecosystem must not be reported as 'queried, no vulnerabilities'."""
from __future__ import annotations

import json

from bts_sbom import osvscanner
from bts_sbom.osvscanner import OsvScanner, gate_exit_code


def _sbom(tmp_path, with_purl):
    comp = {"type": "library", "name": "mystery-lib", "version": "1.0"}
    if with_purl:
        comp["purl"] = "pkg:pypi/mystery-lib@1.0"
    f = tmp_path / "app.cdx.json"
    f.write_text(json.dumps({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": [comp]}), encoding="utf-8")
    return str(f)


def test_catch_all_ecosystem_answer_is_not_evidence_of_a_clean_component(tmp_path, monkeypatch):
    calls = []

    def answered_zero(self, name, version, eco):
        calls.append(eco)
        return [], "queried_online"                       # what OSV really answers for an unknown name: 200 and nothing

    monkeypatch.setattr(OsvScanner, "_query_package", answered_zero)
    res = OsvScanner(osv_mode="single").scan(_sbom(tmp_path, with_purl=False))
    assert calls == ["OSS-Fuzz"]                          # the defect path: no ecosystem -> catch-all
    comp = res["completeness"]
    assert comp["data_status"] != "complete" and comp["vulnerability_presence"] != "none"
    assert res["scan_status"].get("unqueried") == 1 and res["scan_status"].get("queried_online", 0) == 0
    assert gate_exit_code(res) != 0                       # never a green gate on an unverified component
    entry = res["results"][0]["packages"][0]
    assert entry["query_status"] == "unqueried" and entry.get("scan_status") == "unqueried"


def test_a_real_ecosystem_answer_is_still_a_valid_clean_result(tmp_path, monkeypatch):
    monkeypatch.setattr(OsvScanner, "_query_package", lambda self, name, version, eco: ([], "queried_online"))
    res = OsvScanner(osv_mode="single").scan(_sbom(tmp_path, with_purl=True))
    assert res["scan_status"].get("queried_online") == 1 and res["scan_status"].get("unqueried", 0) == 0
    assert res["completeness"]["data_status"] == "complete" and res["completeness"]["vulnerability_presence"] == "none"


def test_a_real_catch_all_hit_is_still_reported(tmp_path, monkeypatch):
    advisory = {"id": "OSV-2024-1", "aliases": [], "summary": "x", "affected": [], "modified": "2024-01-01T00:00:00Z"}
    monkeypatch.setattr(OsvScanner, "_query_package", lambda self, name, version, eco: ([advisory], "queried_online"))
    res = OsvScanner(osv_mode="single").scan(_sbom(tmp_path, with_purl=False))
    assert res["scan_status"].get("queried_online") == 1                  # an actual advisory is real evidence
    assert res["completeness"]["vulnerability_presence"] == "found"
    assert osvscanner.ANSWERED_STATUSES
