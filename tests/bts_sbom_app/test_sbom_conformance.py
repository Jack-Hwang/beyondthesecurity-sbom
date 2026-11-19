"""SBOM conformance matrix (NTIA 2021 / CISA 2025 draft / EU CRA / BSI TR-03183-2 / vulnerability readiness)."""
from __future__ import annotations

import copy
import datetime
import json

import pytest

from bts_sbom_app import cli, conformance, pipeline, sbom
from conftest import FakeScanner

FULL_CDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "version": 1,
    "metadata": {"timestamp": "2026-11-17T00:00:00Z", "tools": {"components": [{"type": "application", "name": "gen", "version": "1"}]},
                 "authors": [{"name": "ACME Security", "email": "sec@acme.example"}], "lifecycles": [{"phase": "pre-build"}],
                 "component": {"type": "application", "name": "app", "bom-ref": "app"}},
    "components": [{"type": "library", "bom-ref": r, "name": n, "version": v, "purl": "pkg:pypi/%s@%s" % (n, v), "supplier": {"name": "ACME"},
                    "hashes": [{"alg": "SHA-512", "content": "ab" * 64}], "licenses": [{"license": {"id": "MIT"}}]}
                   for r, n, v in (("a", "requests", "2.31.0"), ("b", "idna", "3.4"))],
    "dependencies": [{"ref": "app", "dependsOn": ["a", "b"]}, {"ref": "a", "dependsOn": []}, {"ref": "b", "dependsOn": []}],
}
SPDX_FULL = {
    "spdxVersion": "SPDX-2.3", "dataLicense": "CC0-1.0", "SPDXID": "SPDXRef-DOCUMENT", "name": "app",
    "creationInfo": {"created": "2026-11-17T00:00:00Z", "creators": ["Organization: ACME (sec@acme.example)", "Tool: gen-1"]},
    "packages": [{"SPDXID": "SPDXRef-app", "name": "app", "versionInfo": "1"},
                 {"SPDXID": "SPDXRef-a", "name": "requests", "versionInfo": "2.31.0", "supplier": "Organization: PSF", "licenseConcluded": "Apache-2.0",
                  "checksums": [{"algorithm": "SHA256", "checksumValue": "ab"}],
                  "externalRefs": [{"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": "pkg:pypi/requests@2.31.0"}]}],
    "relationships": [{"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES", "relatedSpdxElement": "SPDXRef-app"},
                      {"spdxElementId": "SPDXRef-app", "relationshipType": "DEPENDS_ON", "relatedSpdxElement": "SPDXRef-a"}],
}


def _own_sbom():
    comps = [{"name": "requests", "version": "2.19.1", "ecosystem": "PyPI", "purl": "pkg:pypi/requests@2.19.1", "relationship": "direct", "license": "Apache-2.0",
              "license_source": "deps.dev", "files": ["requirements.txt"], "scope": None},
             {"name": "idna", "version": "2.7", "ecosystem": "PyPI", "purl": "pkg:pypi/idna@2.7", "relationship": "transitive", "license": "", "files": ["requirements.txt"], "scope": None}]
    return sbom.cyclonedx("demo", comps, [])


def test_matrix_reports_five_regimes_and_ranks_the_field_that_blocks_most_regimes_first():
    """AC: BSA-AC-150"""
    r = conformance.evaluate(_own_sbom())
    assert r["status"] == "OK" and sorted(r["regimes"]) == sorted(conformance.REGIMES) and len(r["regimes"]) == 5
    assert r["regimes"]["ntia-2021"]["verdict"] == "gaps" and r["regimes"]["ntia-2021"]["gap"] == 1
    assert [e for e, s in r["regimes"]["ntia-2021"]["elements"].items() if s == "gap"] == ["supplier"]
    assert r["regimes"]["eu-cra-annex-i"]["verdict"] == "conformant" and r["regimes"]["vuln-ready"]["verdict"] == "conformant"
    assert r["regimes"]["cisa-2025-draft"]["draft"] is True
    first = r["fix_once"][0]
    assert first["element"] == "supplier" and len(first["regimes"]) == 3
    assert r["elements"]["license"]["pct"] == 50.0 and r["elements"]["license"]["status"] == "partial"        # absent = not a pass: 1 of 2 components


def test_unrecognised_or_empty_documents_get_no_score_and_an_unknown_regime_raises():
    """AC: BSA-AC-151"""
    for bad in ("text", {"hello": 1}, dict(FULL_CDX, components=[])):
        r = conformance.evaluate(bad)
        assert r["status"] == "NO_DATA" and r["elements"] == {} and r["regimes"] == {}
    with pytest.raises(ValueError):
        conformance.evaluate(FULL_CDX, ["not-a-regime"])


def test_complete_cyclonedx_is_conformant_everywhere_and_spdx_misses_only_the_generation_context():
    """AC: BSA-AC-152"""
    r = conformance.evaluate(FULL_CDX)
    assert [k for k, v in r["regimes"].items() if v["verdict"] == "conformant"] == list(conformance.REGIMES) and r["fix_once"] == []
    s = conformance.evaluate(SPDX_FULL)
    assert s["format"] == "SPDX" and s["components"] == 1
    assert sorted(k for k, v in s["regimes"].items() if v["verdict"] == "conformant") == sorted(set(conformance.REGIMES) - {"cisa-2025-draft"})
    assert s["regimes"]["cisa-2025-draft"]["elements"]["generation_context"] == "gap"
    only = conformance.evaluate(FULL_CDX, ["eu-cra-annex-i"])
    assert list(only["regimes"]) == ["eu-cra-annex-i"] and set(only["elements"]) == set(conformance.REGIMES["eu-cra-annex-i"]["elements"])
    stripped = copy.deepcopy(FULL_CDX)
    for c in stripped["components"]:
        c["hashes"] = [{"alg": "SHA-1", "content": ""}]
    assert conformance.evaluate(stripped)["elements"]["hash"]["pct"] == 0.0                                    # an empty hash value does not count


def test_pipeline_records_the_matrix_and_declares_the_generation_context(tmp_path, make_repo, world):
    """AC: BSA-AC-153"""
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(tmp_path / "ev"), use_llm=False, scanner=FakeScanner(), run_arch=False,
                               cache_dir=str(tmp_path / "c"))
    assert rec["error"] is None and rec["conformance"]["status"] == "OK" and len(rec["conformance"]["regimes"]) == 5
    doc = json.load(open(rec["artifacts"]["cdx"], encoding="utf-8"))
    assert doc["metadata"]["lifecycles"] == [{"phase": "pre-build"}] and sbom.validate_cyclonedx(doc) == []
    assert rec["conformance"]["elements"]["generation_context"]["status"] == "pass"

    class SbomScanner(FakeScanner):
        def scan(self, path, **kw):
            res = super().scan(path, **kw)
            for r in res["results"]:
                r["source"]["type"] = "sbom"
            return res

    other = make_repo({"requirements.txt": "requests==2.19.1\n"}, name="other")
    rec2 = pipeline.run_project(other, work_root=str(tmp_path / "w2"), out_dir=str(tmp_path / "ev2"), use_llm=False, scanner=SbomScanner(), run_arch=False,
                                cache_dir=str(tmp_path / "c"))
    doc2 = json.load(open(rec2["artifacts"]["cdx"], encoding="utf-8"))
    assert "lifecycles" not in doc2["metadata"] and rec2["conformance"]["elements"]["generation_context"]["status"] == "gap"


def test_cli_require_gates_on_a_regime(tmp_path, capsys):
    """AC: BSA-AC-173"""
    p = tmp_path / "own.cdx.json"
    p.write_text(json.dumps(_own_sbom()), encoding="utf-8")
    assert cli.main(["conformance", str(p), "--require", "ntia-2021"]) == 1
    assert cli.main(["conformance", str(p), "--require", "vuln-ready", "--regime", "vuln-ready"]) == 0
    out = capsys.readouterr().out
    assert "vuln-ready" in out and "ntia-2021" in out and "| vuln-ready | conformant |" in out
    assert cli.main(["conformance", str(tmp_path / "missing.json")]) == 2
    assert cli.main(["conformance", str(p), "--json", "--regime", "eu-cra-annex-i"]) == 0
    assert json.loads(capsys.readouterr().out)["regimes"]["eu-cra-annex-i"]["verdict"] == "conformant"


def test_an_old_regime_table_says_so_instead_of_passing_as_current():
    """AC: BSA-AC-210"""
    fresh = conformance.evaluate(FULL_CDX, today=datetime.date(2026, 11, 30))
    assert fresh["table"] == {"reviewed": "2026-11", "age_months": 0, "stale": False, "note": "regime table last reviewed 2026-11"}
    edge = conformance.evaluate(FULL_CDX, today=datetime.date(2027, 4, 30))
    assert edge["table"]["age_months"] == 5 and edge["table"]["stale"] is False
    old = conformance.evaluate(FULL_CDX, today=datetime.date(2027, 5, 1))
    assert old["table"]["age_months"] == 6 and old["table"]["stale"] is True and "REVIEW DUE" in conformance.render_md(old)
    assert "REVIEW DUE" not in conformance.render_md(fresh) and conformance.compact(old)["table"]["stale"] is True
    rec = {"name": "demo", "conformance": conformance.compact(old)}
    from bts_sbom_app import chat
    assert any("overdue for a review" in x for x in chat.run_tool(rec, "sbom_conformance", {})[0]["lines"])
    assert conformance.no_data("x").get("table") is None                                              # no data: no table claim either
