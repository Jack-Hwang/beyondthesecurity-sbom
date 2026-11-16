"""bts_sbom standalone-package smoke tests (STEP 2/3 gates).

Everything here exercises the PACKAGE, not the platform sca_guard/common
copies: import surface, CLI (subprocess, cwd = repo root), honest exit codes
(0 ok / 2 usage), SBOM build from a minimal lockfile, a 6-sector report
round-trip, and a stdlib-only dependency audit of every vendored module.
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]

# ── fixtures: small, real documents ──────────────────────────────────────────

SPDX_SBOM = {
    "spdxVersion": "SPDX-2.3",
    "dataLicense": "CC0-1.0",
    "SPDXID": "SPDXRef-DOCUMENT",
    "name": "demo-device-fw",
    "documentNamespace": "https://bts-sbom.local/spdx/demo",
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

OPENVEX = {
    "@context": "https://openvex.dev/ns/v0.2.0",
    "@id": "https://bts-sbom.local/vex/demo",
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


@pytest.fixture()
def sbom_file(tmp_path):
    p = tmp_path / "sbom.json"
    p.write_text(json.dumps(SPDX_SBOM), encoding="utf-8")
    return p


@pytest.fixture()
def vex_file(tmp_path):
    p = tmp_path / "vex.json"
    p.write_text(json.dumps(OPENVEX), encoding="utf-8")
    return p


def run_cli(*args, cwd=REPO):
    return subprocess.run([sys.executable, "-m", "bts_sbom", *args],
                          capture_output=True, text=True, cwd=cwd, timeout=120)


# ── import surface ────────────────────────────────────────────────────────────

def test_import_surface_and_version():
    import bts_sbom
    assert bts_sbom.__version__ == "0.1.0"
    for name in ("sector_report", "write_evidence", "SECTORS", "SCHEMA",
                 "build_spdx_document", "sbom_from_manifest", "validate_spdx",
                 "OsvScanner", "scan", "gate_exit_code", "build_report",
                 "SupplyChainAnalyzer", "ReachabilityEngine", "enrich_sca_vulns",
                 "VexIndex", "load_vex_file", "parse_document", "VexError"):
        assert callable(getattr(bts_sbom, name)) or isinstance(
            getattr(bts_sbom, name), (frozenset, tuple, str)), name
    assert bts_sbom.SECTORS == ("cra", "fda", "r155", "dod", "finance", "robot")


def test_package_compiles_and_is_stdlib_only():
    """Every module in the package imports only stdlib or bts_sbom itself."""
    import bts_sbom
    pkg_dir = Path(bts_sbom.__file__).parent
    allowed_roots = set(sys.stdlib_module_names) | {"bts_sbom"}
    offenders = []
    for py in pkg_dir.rglob("*.py"):
        if "__pycache__" in py.parts:
            continue
        tree = ast.parse(py.read_text(encoding="utf-8"), str(py))
        for node in ast.walk(tree):
            roots = []
            if isinstance(node, ast.Import):
                roots = [a.name.split(".")[0] for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module:
                roots = [node.module.split(".")[0]]
            for root in roots:
                if root not in allowed_roots:
                    offenders.append("%s: import %s" % (py.relative_to(pkg_dir), root))
    assert not offenders, "third-party imports found: %s" % offenders


# ── CLI: help / version / exit-code contract ─────────────────────────────────

def test_cli_help():
    r = run_cli("--help")
    assert r.returncode == 0
    for sub in ("sbom", "sector", "scan", "vex", "selfsbom"):
        assert sub in r.stdout


def test_cli_version():
    r = run_cli("--version")
    assert r.returncode == 0 and "0.1.0" in r.stdout


def test_cli_bare_invocation_runs_self_sbom():
    r = run_cli()
    assert r.returncode == 0
    doc = json.loads(r.stdout)
    assert doc["bomFormat"] == "CycloneDX"
    assert doc["metadata"]["component"]["name"] == "bts-sbom"
    # honesty: zero third-party runtime dependencies, asserted complete
    assert doc["dependencies"][0]["dependsOn"] == []
    assert doc["compositions"][0]["aggregate"] == "complete"


def test_cli_usage_error_exit_code_2():
    assert run_cli("sector", "--sector", "not-a-sector",
                   "--sbom", "x.json").returncode == 2
    assert run_cli("sbom", "does-not-exist.lock").returncode == 2
    assert run_cli("vex").returncode == 2


# ── CLI: sector report round-trip ─────────────────────────────────────────────

def test_cli_sector_cra_roundtrip(sbom_file, vex_file, tmp_path):
    out = tmp_path / "cra-report.json"
    r = run_cli("sector", "--sector", "cra", "--sbom", str(sbom_file),
                "--vex", str(vex_file), "--out", str(out))
    assert r.returncode == 0, r.stderr
    report = json.loads(out.read_text(encoding="utf-8"))
    assert report["schema"] == "bts-sector-report-1"
    assert report["sector"] == "cra"
    assert report["verdict"] in ("ready", "gaps")
    ids = [row["id"] for row in report["requirements"]]
    assert ids == sorted(ids) and ids  # deterministic, non-empty requirement set
    for row in report["requirements"]:
        assert row["verdict"] in ("pass", "gap", "not_evidence")
        assert "basis" in row and "evidence" in row


def test_cli_sector_all_six_sectors(sbom_file):
    for sector in ("cra", "fda", "r155", "dod", "finance", "robot"):
        r = run_cli("sector", "--sector", sector, "--sbom", str(sbom_file))
        assert r.returncode == 0, (sector, r.stderr)
        report = json.loads(r.stdout)
        assert report["sector"] == sector
        assert report["summary"]["pass"] + report["summary"]["gap"] \
            + report["summary"]["not_evidence"] > 0


def test_sector_report_honesty_absent_evidence(sbom_file):
    """No VEX / no EOL input → those rows are not_evidence, never pass."""
    import bts_sbom
    report = bts_sbom.sector_report(
        "cra", json.loads(sbom_file.read_text(encoding="utf-8")))
    by_id = {row["id"]: row for row in report["requirements"]}
    assert by_id["CRA-04"]["verdict"] == "not_evidence"   # no VEX document
    assert report["verdict"] == "gaps"
    assert report["summary"]["not_evidence"] >= 1
    # a fabricated pass would show up as 'ready'
    assert "not_evidence" in json.dumps(report)


# ── CLI: sbom build from a minimal lockfile ──────────────────────────────────

def test_cli_sbom_from_lockfile(tmp_path):
    lock = tmp_path / "requirements.txt"
    # parser contract: only PINNED (==) lines yield a versioned package
    lock.write_text("requests==2.31.0\nurllib3==2.0.3\n", encoding="utf-8")
    r = run_cli("sbom", str(lock), "--name", "demo")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert doc["spdxVersion"] == "SPDX-2.3"
    names = {p["name"] for p in doc["packages"]}
    assert {"requests", "urllib3"} <= names
    # honesty: offline generation asserts NOASSERTION provenance, never guesses
    assert all(p["downloadLocation"] == "NOASSERTION" for p in doc["packages"])
    # the generated document passes the package's own structural validator
    import bts_sbom
    assert bts_sbom.validate_spdx(doc) == []


def test_cli_sbom_unsupported_manifest_is_honest(tmp_path):
    weird = tmp_path / "not-a-manifest.txt"
    weird.write_text("hello\n", encoding="utf-8")
    r = run_cli("sbom", str(weird))
    assert r.returncode == 2
    assert "bts-sbom" in r.stderr


# ── CLI: scan (dry-run = zero network) and vex ───────────────────────────────

def test_cli_scan_dry_run_is_honest(tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("requests==2.31.0\n", encoding="utf-8")
    r = run_cli("scan", str(proj), "--dry-run")
    assert r.returncode == 0, r.stderr
    # substitution rule: discovery-only is NOT a verified clean pass
    assert "NOT a verified clean pass" in r.stdout
    assert "query_missing" in r.stdout


def test_cli_vex_roundtrip(tmp_path, sbom_file):
    # a scan result drives from_scan_result; here we exercise --check on a doc
    r = run_cli("vex", "--check", str(tmp_path / "vex.json"))
    assert r.returncode == 2  # file does not exist -> honest usage error
    vex = tmp_path / "vex.json"
    vex.write_text(json.dumps(OPENVEX), encoding="utf-8")
    r = run_cli("vex", "--check", str(vex))
    assert r.returncode == 0, r.stderr
    summary = json.loads(r.stdout)
    assert summary["statements"] == 1
    assert summary["statuses"] == {"fixed": 1}


def test_vex_fail_closed_on_bare_not_affected():
    import bts_sbom as b
    with pytest.raises(b.VexError):
        b.statement("CVE-2024-0001", ["pkg:pypi/x@1.0"], "not_affected")


def test_sector_report_and_evidence_roundtrip(sbom_file, tmp_path):
    import bts_sbom
    report = bts_sbom.sector_report(
        "fda", json.loads(sbom_file.read_text(encoding="utf-8")),
        eol={"openssl": {"eol": "2026-09-11", "status": "supported"},
             "zlib": {"eol": "2027-01-01", "status": "supported"}})
    by_id = {row["id"]: row for row in report["requirements"]}
    assert by_id["FDA-04"]["verdict"] in ("pass", "gap")
    paths = bts_sbom.write_evidence(report, out_dir=tmp_path / "ev")
    latest = Path(paths["latest"])
    assert latest.is_file() and json.loads(latest.read_text(
        encoding="utf-8"))["sector"] == "fda"
    assert Path(paths["history"]).parent.name == "history"
