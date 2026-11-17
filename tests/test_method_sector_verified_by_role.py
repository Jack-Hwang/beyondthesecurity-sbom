"""Method w1s3-11 / w2s3-45 gap-closer: every row of the 6-sector regulatory
report must name which stakeholder role verifies it (regulator / operator /
dev), not only carry verdict/detail/evidence as it does today.

RED (before this change): bts_sbom.sectors has no VERIFIED_BY map and
sector_report() rows have no "verified_by_role" key.
GREEN (after): every row of every one of the 6 sectors carries a non-empty
verified_by_role in {"regulator", "operator", "dev"}, and the already-present
evidence field is still non-empty (this method's verification also checks
the pre-existing field, per the audit plan).
"""
from __future__ import annotations

import bts_sbom.sectors as sectors

_ROLES = {"regulator", "operator", "dev"}

_SBOM = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "method-fixture-fw",
    "documentNamespace": "https://bts-sbom.local/spdx/method-fixture",
    "creationInfo": {"created": "2025-06-01T00:00:00Z",
                     "creators": ["Tool: bts-sbom-0.1.0"]},
    "packages": [
        {"name": "openssl", "SPDXID": "SPDXRef-Package-openssl",
         "versionInfo": "1.1.1w", "downloadLocation": "NOASSERTION",
         "filesAnalyzed": False, "licenseConcluded": "Apache-2.0",
         "licenseDeclared": "Apache-2.0", "copyrightText": "NOASSERTION",
         "supplier": "Organization: OpenSSL Software Foundation"},
        {"name": "zlib", "SPDXID": "SPDXRef-Package-zlib",
         "versionInfo": "1.3", "downloadLocation": "NOASSERTION",
         "filesAnalyzed": False, "licenseConcluded": "Zlib",
         "licenseDeclared": "Zlib", "copyrightText": "NOASSERTION",
         "supplier": "Organization: Zlib"},
    ],
    "relationships": [
        {"spdxElementId": "SPDXRef-DOCUMENT", "relationshipType": "DESCRIBES",
         "relatedSpdxElement": "SPDXRef-Package-openssl"},
    ],
}

_VEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://bts-sbom.local/vex/method-fixture",
    "author": "bts-sbom",
    "timestamp": "2025-06-01T00:00:00Z",
    "version": 1,
    "statements": [
        {"vulnerability": {"name": "CVE-2022-0778"},
         "products": [{"@id": "pkg:pypi/openssl@1.1.1w"}],
         "status": "fixed",
         "action_statement": "Upgrade openssl to 3.0.2 or later."},
    ],
}

_EOL = {"openssl": {"eol": "2026-01-01"}, "zlib": {"eol": "2026-01-01"}}


def test_every_row_across_all_6_sectors_carries_a_verified_by_role():
    """Acceptance: sector_report() over all 6 sectors yields 100% of rows
    with a non-empty verified_by_role in {regulator, operator, dev}
    (0% carried it before this change)."""
    total_rows = 0
    for sector in sectors.SECTORS:
        report = sectors.sector_report(sector, _SBOM, vex=_VEX, eol=_EOL)
        rows = report["requirements"]
        assert rows, "sector %r produced no rows" % sector
        for row in rows:
            total_rows += 1
            role = row.get("verified_by_role")
            assert role in _ROLES, (
                "row %s/%s has no valid verified_by_role (got %r)"
                % (sector, row.get("id"), role))
            # the already-present field this method's verification also covers
            assert isinstance(row.get("evidence"), dict) and row["evidence"], (
                "row %s/%s has an empty evidence dict" % (sector, row.get("id")))
    assert total_rows >= 26, "expected all 26 SECTOR_PROFILES rows to be exercised"


def test_verified_by_role_map_covers_every_sector_profile_entry():
    """VERIFIED_BY must be defined for every id across all 6 SECTOR_PROFILES
    (26 requirement ids total), not just for the ones exercised above."""
    seen = set()
    for profiles in sectors.SECTOR_PROFILES.values():
        for req in profiles:
            seen.add(req["id"])
            assert req["id"] in sectors.VERIFIED_BY, (
                "VERIFIED_BY is missing an entry for %s" % req["id"])
            assert sectors.VERIFIED_BY[req["id"]] in _ROLES
    assert len(seen) == len(sectors.VERIFIED_BY), (
        "VERIFIED_BY has stale/extra entries not matching SECTOR_PROFILES ids")
