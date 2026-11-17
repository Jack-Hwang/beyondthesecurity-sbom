"""Regression test for the reachability result-overwrite defect
(report section 3 item 8 / Appendix B `bts_sbom/reachability.py:591`).

Bug: ``enrich_sca_vulns`` keyed its internal ``results`` lookup by ``cve_id``
alone (``by_cve = {r.cve_id: r for r in results}``).  Two different packages
whose SCA findings share one CVE id collided on that key, so only the
LAST-processed package's verdict survived -- a proven REACHABLE for one
package was silently discarded and replaced by a weaker
REACHABILITY_UNKNOWN verdict that actually belonged to a completely
different package. This violates the module's own documented "HONEST
VERDICT CONTRACT" (a found path is real code and must never be downgraded).

Fix: key by (cve_id, package, version) -- the real component identity --
and never let an UNKNOWN verdict for a given key replace an already more
informative (REACHABLE/UNREACHABLE) verdict recorded for that same key.

This file is new (per workflow rules, tests for this cluster live only
here); it does not modify tests/test_bts_sbom_pkg.py.
"""
from __future__ import annotations

import types
from pathlib import Path

from bts_sbom.reachability import (
    VERDICT_REACHABLE,
    VERDICT_UNKNOWN,
    enrich_sca_vulns,
)
from bts_sbom.vex import from_cve_reachability

SHARED_CVE = "CVE-9999-0001"


def _write_sources(tmp_path: Path) -> list[str]:
    """Two translation units: pkgA's vulnerable function IS reachable from
    main(); pkgB's vulnerable function is defined but never called anywhere."""
    file_a = tmp_path / "pkg_a.c"
    file_a.write_text(
        "int funcA(void) { return 1; }\n"
        "int main(void) { return funcA(); }\n",
        encoding="utf-8",
    )
    file_b = tmp_path / "pkg_b.c"
    file_b.write_text(
        "int funcB(void) { return 2; }\n",
        encoding="utf-8",
    )
    return [str(file_a), str(file_b)]


def _two_package_vulns() -> list[dict]:
    """Two DIFFERENT packages, both carrying the SAME CVE id."""
    return [
        {
            "cve_id": SHARED_CVE,
            "package": "libfoo",
            "version": "1.0.0",
            "affected_functions": ["funcA"],
        },
        {
            "cve_id": SHARED_CVE,
            "package": "libbar",
            "version": "2.0.0",
            "affected_functions": ["funcB"],
        },
    ]


def test_same_cve_different_packages_keep_independent_verdicts(tmp_path):
    """AC: BSA-AC-1 -- Two SCA findings for different packages that share one
    CVE id must each keep their OWN reachability verdict: a proven REACHABLE
    for one package is never overwritten by a weaker verdict that belongs to
    a different package sharing the same CVE id."""
    sources = _write_sources(tmp_path)
    vulns = _two_package_vulns()

    enrich_sca_vulns(vulns, sources)

    by_pkg = {v["package"]: v for v in vulns}

    # pkgA: funcA is directly called from main() -> must be REACHABLE, with
    # the real call path reported.
    assert by_pkg["libfoo"]["reachability"] == VERDICT_REACHABLE
    assert by_pkg["libfoo"]["reachability_path"] == ["main", "funcA"]

    # pkgB: funcB exists but has no caller anywhere -> cannot be proven
    # REACHABLE (and, with the default ad-hoc build model, cannot be proven
    # UNREACHABLE either) -> REACHABILITY_UNKNOWN. Critically, this must NOT
    # have clobbered pkgA's REACHABLE verdict above.
    assert by_pkg["libbar"]["reachability"] == VERDICT_UNKNOWN

    # Each vuln dict keeps its own package/version identity untouched.
    assert by_pkg["libfoo"]["version"] == "1.0.0"
    assert by_pkg["libbar"]["version"] == "2.0.0"


def test_unknown_never_clobbers_a_more_informative_verdict_same_key(tmp_path):
    """AC: BSA-AC-2 -- Even for the SAME (cve_id, package, version) identity,
    if one analysis pass produced a proven REACHABLE and a later entry for
    that identical key is only REACHABILITY_UNKNOWN, the UNKNOWN entry must
    not downgrade the stored verdict; a verdict for a genuinely different
    key is left untouched either way."""
    sources = _write_sources(tmp_path)
    # Two entries sharing the EXACT SAME (cve_id, package, version) identity:
    # one with a resolvable vulnerable function (REACHABLE), one where the
    # function-level mapping is absent (UNKNOWN) for the identical identity.
    vulns = [
        {
            "cve_id": SHARED_CVE,
            "package": "libfoo",
            "version": "1.0.0",
            "affected_functions": ["funcA"],
        },
        {
            "cve_id": SHARED_CVE,
            "package": "libfoo",
            "version": "1.0.0",
            "affected_functions": [],  # no mapping -> UNKNOWN for analyze()
        },
        # A genuinely different package/CVE identity must be unaffected.
        {
            "cve_id": "CVE-9999-0002",
            "package": "libbar",
            "version": "2.0.0",
            "affected_functions": ["funcB"],
        },
    ]

    enrich_sca_vulns(vulns, sources)

    # Both entries keyed on (SHARED_CVE, libfoo, 1.0.0) must report the more
    # informative REACHABLE verdict -- the UNKNOWN sibling must not have
    # downgraded it.
    assert vulns[0]["reachability"] == VERDICT_REACHABLE
    assert vulns[1]["reachability"] == VERDICT_REACHABLE

    # The unrelated package/CVE is untouched.
    assert vulns[2]["reachability"] == VERDICT_UNKNOWN


def test_vex_generation_keeps_both_verdicts_distinct(tmp_path):
    """AC: BSA-AC-3 -- Downstream VEX generation (from_cve_reachability) must
    end up with two independent statements for the two packages sharing one
    CVE id: pkgA's proven-reachable verdict must surface as 'affected', and
    pkgB's unknown verdict must surface as 'under_investigation' -- neither
    collapses into the other's status."""
    sources = _write_sources(tmp_path)
    vulns = _two_package_vulns()
    enrich_sca_vulns(vulns, sources)

    def _as_cve_obj(v: dict) -> types.SimpleNamespace:
        return types.SimpleNamespace(
            cve_id=v["cve_id"],
            osv_id=None,
            ecosystem="generic",
            package_name=v["package"],
            package_version=v["version"],
            symbol_reachability=v["reachability"],
            reachability="present_only",
            fixed_version=None,
        )

    cve_objs = [_as_cve_obj(v) for v in vulns]
    doc = from_cve_reachability(cve_objs, timestamp="2026-01-01T00:00:00Z")

    statements = doc["statements"]
    assert len(statements) == 2

    by_product = {}
    for st in statements:
        for p in st["products"]:
            by_product[p["@id"]] = st

    foo_statement = by_product["pkg:generic/libfoo@1.0.0"]
    bar_statement = by_product["pkg:generic/libbar@2.0.0"]

    assert foo_statement["status"] == "affected"
    assert bar_statement["status"] == "under_investigation"
    # Both statements still reference the same shared CVE id -- distinct
    # products, not a merged/duplicate-dropped statement.
    assert foo_statement["vulnerability"]["name"] == SHARED_CVE
    assert bar_statement["vulnerability"]["name"] == SHARED_CVE


def test_enrich_sca_vulns_still_handles_vulns_missing_package_identity(tmp_path):
    """Backwards compatibility: callers that only ever set cve_id (no
    package/version) keep working exactly as before -- the function still
    enriches every vuln and never raises."""
    sources = _write_sources(tmp_path)
    vulns = [{"cve_id": SHARED_CVE, "affected_functions": ["funcA"]}]

    result = enrich_sca_vulns(vulns, sources)

    assert result is vulns  # same list, mutated in place (documented contract)
    assert vulns[0]["reachability"] == VERDICT_REACHABLE
