"""Regression test for the vex-honesty defect cluster (report section 3 item 3,
sub-part (c)): bts_sbom_app/sectors.py maritime_report() MAR-05 closed a
critical/high finding on a bare VEX not_affected statement that carried no
justification/impact_statement, and still reported verdict='pass'.

Lives in its own file (never touch tests/test_bts_sbom_pkg.py or other test
files) so parallel fix branches never conflict.
"""
from __future__ import annotations

from bts_sbom_app import sectors

_CRITICAL_DOC = {
    "bomFormat": "CycloneDX",
    "components": [{"name": "demo", "version": "1.0.0"}],
    "vulnerabilities": [
        {"id": "CVE-2024-1111", "ratings": [{"severity": "critical"}]},
    ],
}


def _not_affected_vex(justification=None, impact_statement=None):
    st = {"status": "not_affected", "vulnerability": {"name": "CVE-2024-1111"}}
    if justification:
        st["justification"] = justification
    if impact_statement:
        st["impact_statement"] = impact_statement
    return {"statements": [st]}


# Three equivalent shapes of a "bare" not_affected closing statement: missing
# key entirely, an explicitly empty justification, and an explicit None — all
# of them carry no real evidence and must not be allowed to close a finding.
_UNJUSTIFIED_CLOSING_STATEMENTS = [
    _not_affected_vex(),
    _not_affected_vex(justification=""),
    _not_affected_vex(justification=None, impact_statement=""),
]


def test_bare_not_affected_closing_statement_never_yields_pass():
    """AC: BSA-AC-89

    Unwanted: If a marine-profile closing statement has no justification, the
    verdict shall not be pass (N of N).
    """
    total = len(_UNJUSTIFIED_CLOSING_STATEMENTS)
    not_pass = 0
    for vex_doc in _UNJUSTIFIED_CLOSING_STATEMENTS:
        rep = sectors.maritime_report(_CRITICAL_DOC, vex_doc, None)
        mar05 = next(r for r in rep["requirements"] if r["id"] == "MAR-05")
        if mar05["verdict"] != "pass":
            not_pass += 1
        # The statement must be measured/disclosed, never silently dropped.
        assert mar05["evidence"].get("unjustified_not_affected", 0) >= 1
        assert mar05["evidence"]["open_critical_high"] >= 1
    assert not_pass == total, (
        "%d of %d unjustified closing statements incorrectly produced a 'pass' verdict"
        % (total - not_pass, total)
    )


def test_not_affected_with_real_justification_still_closes_the_finding():
    """Counter-case: a conformant not_affected (valid justification) must keep
    closing the finding exactly as before the fix — no regression."""
    vex_doc = _not_affected_vex(justification="vulnerable_code_not_present")
    rep = sectors.maritime_report(_CRITICAL_DOC, vex_doc, None)
    mar05 = next(r for r in rep["requirements"] if r["id"] == "MAR-05")
    assert mar05["verdict"] == "pass"
    assert mar05["evidence"].get("unjustified_not_affected", 0) == 0


def test_not_affected_with_impact_statement_only_still_closes_the_finding():
    """impact_statement alone is valid OpenVEX evidence too (same rule as
    bts_sbom.vex._validate_statement) and must still close the finding."""
    vex_doc = _not_affected_vex(impact_statement="verified not reachable on this platform")
    rep = sectors.maritime_report(_CRITICAL_DOC, vex_doc, None)
    mar05 = next(r for r in rep["requirements"] if r["id"] == "MAR-05")
    assert mar05["verdict"] == "pass"


def test_fixed_statement_does_not_need_a_justification():
    """'fixed' statements are untouched by this fix — OpenVEX does not require a
    justification for 'fixed', only for 'not_affected'."""
    vex_doc = {"statements": [{"status": "fixed", "vulnerability": {"name": "CVE-2024-1111"}}]}
    rep = sectors.maritime_report(_CRITICAL_DOC, vex_doc, None)
    mar05 = next(r for r in rep["requirements"] if r["id"] == "MAR-05")
    assert mar05["verdict"] == "pass"
    assert mar05["evidence"].get("unjustified_not_affected", 0) == 0
