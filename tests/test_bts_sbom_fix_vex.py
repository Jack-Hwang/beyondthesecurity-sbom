"""Regression tests for the vex-honesty defect cluster (report section 3, items 2 and 3):

(a) bts_sbom/vex.py VexIndex version collapse — a not_affected/fixed statement pinned to
    one product version must not suppress a finding for a DIFFERENT version of the same
    product; a statement whose product carries NO version applies to every version.
(b) bts_sbom/vex.py load_vex_file() CycloneDX path must enforce the same not_affected
    justification/impact_statement rule that _validate_statement() enforces for OpenVEX,
    staying fail-closed (VexError) on a malformed statement.

These tests live in their own file (never touch tests/test_bts_sbom_pkg.py) so parallel
fix branches never conflict.
"""
from __future__ import annotations

import json

import pytest

from bts_sbom import vex


# ── (a) VexIndex must not widen a versioned statement to other versions ────────

def _openvex_doc(statements):
    return {
        "@context": "https://openvex.dev/ns/v0.2.0",
        "@id": "https://bts-sbom.local/vex/test",
        "author": "bts-sbom",
        "timestamp": "2026-01-01T00:00:00Z",
        "version": 1,
        "statements": statements,
    }


def test_versioned_not_affected_statement_does_not_suppress_a_different_version():
    """A not_affected statement pinned to requests@9.9.9 must not suppress a finding
    for the still-vulnerable requests@1.0.0 (report: bts_sbom/vex.py:394-406)."""
    doc = _openvex_doc([
        vex.statement("CVE-2024-9999", ["pkg:pypi/requests@9.9.9"], "not_affected",
                      justification="vulnerable_code_not_present"),
    ])
    index = vex.parse_document(doc)

    # The exact pinned version is legitimately suppressed.
    status, just = index.status_for("CVE-2024-9999", "pkg:pypi/requests@9.9.9")
    assert status == "not_affected"

    # A DIFFERENT, still-vulnerable version must NOT be suppressed.
    status, just = index.status_for("CVE-2024-9999", "pkg:pypi/requests@1.0.0")
    assert status is None and just is None

    # apply_to_findings() must keep the v1.0.0 finding active, not suppressed.
    findings = [{"cve_id": "CVE-2024-9999", "product": "pkg:pypi/requests@1.0.0"}]
    result = vex.apply_to_findings(findings, index)
    assert result["suppressed_count"] == 0
    assert result["active_count"] == 1


def test_version_less_statement_still_applies_to_every_version():
    """A not_affected statement whose product carries NO version (package-level
    assertion) must still suppress findings for any version of that product."""
    doc = _openvex_doc([
        vex.statement("CVE-2024-8888", ["pkg:pypi/requests"], "not_affected",
                      justification="vulnerable_code_not_present"),
    ])
    index = vex.parse_document(doc)

    for version in ("1.0.0", "9.9.9", "2.0.0"):
        status, just = index.status_for("CVE-2024-8888", "pkg:pypi/requests@%s" % version)
        assert status == "not_affected", "version-less statement should cover @%s" % version


def test_versioned_fixed_statement_also_does_not_widen():
    """Same version-pinning discipline applies to 'fixed' statements, not just
    not_affected (both are in VexIndex._SUPPRESSING)."""
    doc = _openvex_doc([
        {"vulnerability": {"name": "CVE-2024-7777"},
         "products": [{"@id": "pkg:pypi/flask@3.0.0"}],
         "status": "fixed"},
    ])
    index = vex.parse_document(doc)
    assert index.status_for("CVE-2024-7777", "pkg:pypi/flask@3.0.0")[0] == "fixed"
    assert index.status_for("CVE-2024-7777", "pkg:pypi/flask@0.12")[0] is None


# ── (b) load_vex_file() CycloneDX path must validate statements (fail-closed) ──

def _cyclonedx_vex_doc(analysis_extra=None):
    analysis = {"state": "not_affected"}
    if analysis_extra:
        analysis.update(analysis_extra)
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "vulnerabilities": [
            {
                "id": "CVE-2024-6666",
                "analysis": analysis,
                "affects": [{"ref": "pkg:pypi/demo@1.0.0",
                            "versions": [{"status": "not_affected"}]}],
            }
        ],
    }


def test_cyclonedx_bare_not_affected_is_rejected_fail_closed(tmp_path):
    """A CycloneDX not_affected with no justification/detail must raise VexError,
    exactly like the OpenVEX path already does (report: vex.py:514-577)."""
    path = tmp_path / "cdx-vex.json"
    path.write_text(json.dumps(_cyclonedx_vex_doc()), encoding="utf-8")
    with pytest.raises(vex.VexError):
        vex.load_vex_file(str(path))


def test_cyclonedx_not_affected_with_justification_mapping_is_accepted(tmp_path):
    """A conformant CycloneDX not_affected (justification maps to the OpenVEX vocab)
    must still load cleanly — the fix must not reject valid documents."""
    path = tmp_path / "cdx-vex-ok.json"
    path.write_text(json.dumps(_cyclonedx_vex_doc({"justification": "code_not_present"})),
                    encoding="utf-8")
    statements = vex.load_vex_file(str(path))
    assert len(statements) == 1
    assert statements[0].status == "not_affected"
    assert statements[0].justification == "vulnerable_code_not_present"


def test_cyclonedx_not_affected_with_detail_only_is_accepted(tmp_path):
    """impact_statement (CycloneDX 'detail') alone is sufficient evidence, same as
    the OpenVEX rule in _validate_statement()."""
    path = tmp_path / "cdx-vex-detail.json"
    path.write_text(json.dumps(_cyclonedx_vex_doc({"detail": "verified not reachable"})),
                    encoding="utf-8")
    statements = vex.load_vex_file(str(path))
    assert len(statements) == 1
    assert statements[0].impact_statement == "verified not reachable"
