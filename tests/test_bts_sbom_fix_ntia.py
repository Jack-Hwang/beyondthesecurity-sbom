"""Regression test for the NTIA "minimum elements met" sector-check honesty bug.

docs/ANALYSIS_2026-11-17.md appendix B (report section 3, item 7):
``bts_sbom/sectors.py:211`` -- ``_check_ntia_minimum`` returned verdict
``"pass"`` whenever ``fail_count == 0`` (no element below the 60% FAIL floor),
even when most of the 7 NTIA elements sat in the 60-89% WARN band rather than
actually PASS-ing (>=90%). The requirement titles all read "NTIA minimum
elements met/satisfied/complete", so a document where only 3 of 7 elements
truly PASS (score 76, grade B in the analyst's own repro) was reported as a
full pass -- a self-contradictory, fabricated "pass" on materially incomplete
NTIA compliance.

Fix: ``_check_ntia_minimum`` now passes only when every one of the 7 NTIA
elements reaches PASS; otherwise it reports a ``gap`` with the measured
present/total count and the list of missing/partial element names, in both
the human-readable detail text and the ``evidence`` dict
(``missing_elements``). An SBOM the NTIA checker cannot recognise/score at all
(neither CycloneDX nor SPDX, or no components) was already, and remains,
``not_evidence`` -- never a pass and never an invented gap score. This mirrors
how ``bts_sbom/_internal/ntia_check.py`` itself grades a document (PASS/WARN/
FAIL per element), reusing that scorer's own per-element ``status`` instead of
re-deriving a looser bar in sectors.py.

Every sector profile wired to the ``ntia_minimum`` check must behave the same
way, so this test discovers that set directly from ``SECTOR_PROFILES`` (not
hard-coded) and parametrizes over it: at the time of writing that is CRA-02,
FDA-02, R155-02, DOD-04 and ROB-02 (cra/fda/r155/dod/robot sectors). The
``finance`` sector's FIN-04 uses a different check (``supplier_and_version``,
titled "Supplier + version fields declared", not "minimum elements met") and
is out of scope for this defect.
"""
from __future__ import annotations

import pytest

import bts_sbom
from bts_sbom import sectors
from bts_sbom._internal import ntia_check

# Every sector-profile requirement wired to the ntia_minimum check, as
# (sector, requirement_id) pairs -- read from the live profile table so the
# test still covers the right set if sector wiring changes later.
_NTIA_MINIMUM_REQS = [
    (sector, row["id"])
    for sector, rows in sectors.SECTOR_PROFILES.items()
    for row in rows
    if row["check"] == "ntia_minimum"
]

assert _NTIA_MINIMUM_REQS, "no sector profile uses the ntia_minimum check -- test would be vacuous"


# ── fixtures: CycloneDX documents with a controlled, element-by-element NTIA score ──

# All 7 NTIA elements PASS: supplier (publisher), component name, version,
# unique id (purl), dependency relationship (bom-ref + dependencies entry),
# SBOM author (metadata.authors) and timestamp (metadata.timestamp) are all
# present for both components / at document level.
_COMPLETE_CDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {"timestamp": "2026-01-01T00:00:00Z",
                 "authors": [{"name": "Jane Doe"}]},
    "components": [
        {"name": "pkg-a", "version": "1.0.0", "publisher": "Acme",
         "bom-ref": "pkg-a", "purl": "pkg:generic/pkg-a@1.0.0"},
        {"name": "pkg-b", "version": "2.0.0", "publisher": "Acme",
         "bom-ref": "pkg-b", "purl": "pkg:generic/pkg-b@2.0.0"},
    ],
    "dependencies": [{"ref": "pkg-a", "dependsOn": ["pkg-b"]},
                      {"ref": "pkg-b", "dependsOn": []}],
}

# Exactly 3 of 7 elements PASS: comp_name, sbom_author and timestamp are
# fully present (100%); supplier/version/unique_id/dependency are each
# populated for only 3 of 5 components (60%) -- WARN, not FAIL, so
# fail_count == 0 while pass_count == 3 (matches the analyst's own repro:
# score 76.0, grade B). This is the exact shape of the original bug: the old
# "fail_count == 0 -> pass" gate let a WARN-heavy, materially-incomplete
# document through as a fabricated full pass.
_PARTIAL_COMPONENTS = []
_PARTIAL_DEPS = []
for _i in range(5):
    _c = {"name": "pkg-%d" % _i, "bom-ref": "pkg-%d" % _i}
    if _i < 3:
        _c["publisher"] = "Acme"
        _c["version"] = "1.0.0"
        _c["purl"] = "pkg:generic/pkg-%d@1.0.0" % _i
        _PARTIAL_DEPS.append({"ref": "pkg-%d" % _i, "dependsOn": []})
    _PARTIAL_COMPONENTS.append(_c)

_PARTIAL_CDX = {
    "bomFormat": "CycloneDX", "specVersion": "1.5",
    "metadata": {"timestamp": "2026-01-01T00:00:00Z",
                 "authors": [{"name": "Jane Doe"}]},
    "components": _PARTIAL_COMPONENTS,
    "dependencies": _PARTIAL_DEPS,
}

_PARTIAL_MISSING = {"Supplier Name", "Component Version", "Unique Identifier",
                     "Dependency Relationships"}

# Neither a CycloneDX (bomFormat) nor an SPDX (spdxVersion) document -- the
# NTIA checker cannot score it at all.
_UNUSABLE = {"not_a_real_sbom": True, "components": "nonsense"}


def test_fixtures_actually_exercise_3_of_7_and_7_of_7():
    """Sanity check on the fixtures themselves, independent of sectors.py, so
    this test suite fails loudly (not silently) if ntia_check's own scoring
    ever changes under it."""
    complete = ntia_check.evaluate(_COMPLETE_CDX)
    assert complete["status"] == "OK"
    assert complete["pass_count"] == len(ntia_check.ELEMENTS) == 7
    assert complete["fail_count"] == 0

    partial = ntia_check.evaluate(_PARTIAL_CDX)
    assert partial["status"] == "OK"
    assert partial["pass_count"] == 3
    assert partial["warn_count"] == 4
    assert partial["fail_count"] == 0          # the old "fail_count == 0 -> pass" gate's blind spot
    assert partial["total_score"] == 76.0 and partial["grade"] == "B"
    missing = {e["name"] for e in partial["elements"] if e["status"] != "PASS"}
    assert missing == _PARTIAL_MISSING

    assert ntia_check.evaluate(_UNUSABLE)["status"] == "NO_DATA"


@pytest.mark.parametrize("sector,req_id", _NTIA_MINIMUM_REQS)
def test_ntia_minimum_passes_only_when_all_seven_elements_present(sector, req_id):
    """AC: BSA-AC-NTIA-1 -- a complete SBOM (all 7 NTIA elements PASS) is
    reported as 'pass' for the NTIA-minimum-elements requirement, for every
    sector profile wired to the ntia_minimum check."""
    report = bts_sbom.sector_report(sector, _COMPLETE_CDX)
    row = next(r for r in report["requirements"] if r["id"] == req_id)
    assert row["verdict"] == "pass"
    assert row["evidence"]["pass_count"] == row["evidence"]["elements_total"] == 7
    assert row["evidence"]["missing_elements"] == []


@pytest.mark.parametrize("sector,req_id", _NTIA_MINIMUM_REQS)
def test_ntia_minimum_gap_with_missing_elements_when_incomplete(sector, req_id):
    """AC: BSA-AC-NTIA-2 -- an SBOM where only 3 of 7 NTIA elements actually
    PASS is reported as a 'gap' (never 'pass'), with the measured
    present/total count and the specific missing element names surfaced in
    both the evidence dict and the human-readable detail text."""
    report = bts_sbom.sector_report(sector, _PARTIAL_CDX)
    row = next(r for r in report["requirements"] if r["id"] == req_id)
    assert row["verdict"] == "gap"
    ev = row["evidence"]
    assert ev["pass_count"] == 3
    assert ev["elements_total"] == 7
    assert set(ev["missing_elements"]) == _PARTIAL_MISSING
    assert "3/7" in row["detail"]
    for name in ev["missing_elements"]:
        assert name in row["detail"]


@pytest.mark.parametrize("sector,req_id", _NTIA_MINIMUM_REQS)
def test_ntia_minimum_not_evidence_when_sbom_unusable(sector, req_id):
    """AC: BSA-AC-NTIA-3 -- an SBOM the NTIA checker cannot recognise/score
    (neither CycloneDX nor SPDX) is reported as 'not_evidence', never a
    fabricated pass and never a fabricated gap score."""
    report = bts_sbom.sector_report(sector, _UNUSABLE)
    row = next(r for r in report["requirements"] if r["id"] == req_id)
    assert row["verdict"] == "not_evidence"
    assert row["evidence"]["ntia_status"] == "NO_DATA"
