"""bts_sbom standalone-package smoke tests (STEP 2/3 gates).

Everything here exercises the PACKAGE, not the platform sca_guard/common
copies: import surface, CLI (subprocess, cwd = repo root), honest exit codes
(0 ok / 2 usage), SBOM build from a minimal lockfile, a 6-sector report
round-trip, and a stdlib-only dependency audit of every vendored module.
"""
from __future__ import annotations

import ast
import json
import re
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
    assert re.fullmatch(r"\d+\.\d+\.\d+", bts_sbom.__version__)
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
    for sub in ("sbom", "sector", "scan", "vex", "policy", "selfsbom"):
        assert sub in r.stdout


@pytest.mark.parametrize("enc", ["ascii", "cp949", "cp1252"])
def test_cli_help_survives_non_utf8_console(enc):
    """Regression: `--help` crashed with UnicodeEncodeError on a Korean Windows
    console (cp949) because help text held U+2014/U+2192; CI hid it via PYTHONUTF8."""
    import os
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUTF8"}
    env["PYTHONIOENCODING"] = enc
    for argv in (["--help"], ["scan", "--help"], ["policy", "--help"], ["sector", "--help"],
                 ["vex", "--help"], ["sbom", "--help"], ["selfsbom", "--help"]):
        r = subprocess.run([sys.executable, "-m", "bts_sbom", *argv], capture_output=True,
                           text=True, cwd=REPO, timeout=120, env=env, encoding=enc, errors="replace")
        assert r.returncode == 0, (enc, argv, r.stderr[-300:])
        assert "Traceback" not in r.stderr


_HELP_ARGVS = (["--help"], ["scan", "--help"], ["policy", "--help"], ["sector", "--help"],
               ["vex", "--help"], ["sbom", "--help"], ["selfsbom", "--help"])


def _env_without_utf8(enc):
    import os
    env = {k: v for k, v in os.environ.items() if k != "PYTHONUTF8"}
    env["PYTHONIOENCODING"] = enc
    return env


def test_help_text_is_pure_ascii():
    """The help text itself must be ASCII (not merely survive via errors=replace):
    a '?' on a cp949/ascii console would otherwise hide a lossy help page."""
    for argv in _HELP_ARGVS:
        r = subprocess.run([sys.executable, "-m", "bts_sbom", *argv], capture_output=True, text=True,
                           cwd=REPO, timeout=120, env=_env_without_utf8("utf-8"), encoding="utf-8")
        assert r.returncode == 0, (argv, r.stderr[-300:])
        assert r.stdout.isascii(), (argv, [c for c in r.stdout if ord(c) > 127][:8])


@pytest.mark.parametrize("enc", ["ascii", "cp1252"])
def test_json_stdout_is_lossless_on_non_utf8_console(enc, sbom_file):
    """Regression (audit): errors=replace alone turned Korean text in JSON on stdout into '?'.
    Machine-readable output must round-trip exactly on any console encoding."""
    from bts_sbom import sector_report
    expected = sector_report("finance", json.loads(sbom_file.read_text(encoding="utf-8")))
    r = subprocess.run([sys.executable, "-m", "bts_sbom", "sector", "--sector", "finance",
                        "--sbom", str(sbom_file)], capture_output=True, cwd=REPO, timeout=120,
                       env=_env_without_utf8(enc))
    assert r.returncode == 0, r.stderr[-300:]
    got = json.loads(r.stdout.decode(enc))          # strict decode: stdout bytes are pure ASCII/1252
    assert got["sector_title"] == expected["sector_title"]
    assert any(ord(c) > 127 for c in expected["sector_title"])   # the test really covers non-ASCII data
    assert "?" not in got["sector_title"]


def test_stdout_safe_helper(monkeypatch):
    import io
    from bts_sbom import cli
    doc = {"title": "caf" + chr(0xE9) + " " + chr(0xAE08) + chr(0xC735), "n": 3, "ok": True}
    text = json.dumps(doc, indent=2, ensure_ascii=False)
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="ascii"))
    safe = cli._stdout_safe(text, True)
    assert safe.isascii() and json.loads(safe) == doc          # lossless, still valid JSON
    assert cli._stdout_safe(text, False) == text               # human text: left to errors=replace
    assert cli._stdout_safe("plain ascii", True) == "plain ascii"
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(io.BytesIO(), encoding="utf-8"))
    assert cli._stdout_safe(text, True) == text                # UTF-8 console keeps real characters


def test_cli_version():
    r = run_cli("--version")
    import bts_sbom
    assert r.returncode == 0 and bts_sbom.__version__ in r.stdout


def test_version_has_a_single_source_of_truth():
    """pyproject(s), `_version.py`, the package attribute and the CHANGELOG head must agree."""
    import bts_sbom
    from bts_sbom import _version
    assert bts_sbom.__version__ == _version.__version__
    seen = 0
    for toml in (REPO / "pyproject.toml", REPO / "bts_sbom" / "pyproject.toml"):
        if not toml.is_file():
            continue
        txt = toml.read_text(encoding="utf-8")
        if not re.search(r'(?m)^name\s*=\s*"bts-sbom"', txt):
            continue                      # the platform repo's own root pyproject is not ours
        m = re.search(r'(?m)^version\s*=\s*"([^"]+)"', txt)
        assert m and m.group(1) == bts_sbom.__version__, (str(toml), m and m.group(1))
        seen += 1
    assert seen >= 1
    for log_path in (REPO / "bts_sbom" / "CHANGELOG.md", REPO / "CHANGELOG.md"):
        if not log_path.is_file():
            continue
        log = log_path.read_text(encoding="utf-8")
        if "All notable changes to bts-sbom" not in log:
            continue                      # not this package's changelog
        assert re.search(r"(?m)^## " + re.escape(bts_sbom.__version__) + r"\b", log), str(log_path)
    for readme in (REPO / "bts_sbom" / "README.md", REPO / "README.md"):
        if readme.is_file():
            txt = readme.read_text(encoding="utf-8")
            for found in re.findall(r"pkg:pypi/bts-sbom@([0-9][^\"\s,]*)", txt):
                assert found == bts_sbom.__version__, (str(readme), found)   # documented sample output


def test_emitted_sboms_carry_the_real_tool_version():
    """Regression: CycloneDX tools[] and SPDX creators hard-coded 0.1.0 through 0.1.1."""
    import bts_sbom
    from bts_sbom._internal.sbom import build_sbom
    from bts_sbom._internal.spdx_sbom import build_spdx
    pk = [{"name": "demo", "version": "1.0", "license": "MIT"}]
    cdx, _ = build_sbom(pk, "t", "2026-01-01T00:00:00Z")
    assert cdx["metadata"]["tools"][0]["version"] == bts_sbom.__version__
    out = build_spdx(pk, "t", "2026-01-01T00:00:00Z")
    doc = out[0] if isinstance(out, tuple) else out
    assert "Tool: bts-sbom-" + bts_sbom.__version__ in doc["creationInfo"]["creators"]
    # the path behind the user-facing `bts-sbom sbom` command (audit finding: it emitted no version at all)
    from bts_sbom import build_spdx_document
    assert "Tool: bts-sbom-" + bts_sbom.__version__ in build_spdx_document(pk, [])["creationInfo"]["creators"]


def test_cli_sbom_command_stamps_tool_version(tmp_path):
    import bts_sbom
    req = tmp_path / "requirements.txt"
    req.write_text("requests==2.31.0\n", encoding="utf-8")
    r = run_cli("sbom", str(req), "--name", "demo")
    assert r.returncode == 0, r.stderr[-300:]
    assert json.loads(r.stdout)["creationInfo"]["creators"][0] == "Tool: bts-sbom-" + bts_sbom.__version__


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


# ═══ round 2 (REA 21 §7): E2 version matching ════════════════════════════════

def test_version_match_pep440():
    from bts_sbom._internal.version_match import match_range as m
    cases = [
        # ~= compatible-release operator
        ("1.4.2", ["~=1.4.2"], True), ("1.4.1", ["~=1.4.2"], False),
        ("1.4.9", ["~=1.4.2"], True), ("1.5.0", ["~=1.4.2"], False),
        ("1.4.2rc1", ["~=1.4.2"], False),          # rc sorts below the release
        # wildcard equality / inequality
        ("2.2.1", ["==2.2.*"], True), ("2.2.0", ["==2.2.*"], True),
        ("2.2.1rc1", ["==2.2.*"], True), ("2.3.0", ["==2.2.*"], False),
        ("2.2.0", ["!=2.2.*"], False), ("2.3.1", ["!=2.2.*"], True),
        # ordered ops with PEP 440 ordering (post/dev/pre)
        ("1.0.post1", [">=1.0"], True), ("1.0rc1", [">=1.0"], False),
        ("2.0.dev1", ["<2.0"], True),
        # specifier sets (comma conjunction)
        ("1.9.9", [">=1.0,<2.0"], True), ("2.0.0", [">=1.0,<2.0"], False),
        # epochs order correctly through the sort key
        ("1!2.0", ["<2.0"], False), ("1!2.0", [">=1.9"], True),
    ]
    for ver, cons, want in cases:
        assert m(ver, cons, "pip") is want, (ver, cons, want)


def test_version_match_semver_npm_cargo_go():
    from bts_sbom._internal.version_match import match_range as m
    cases = [
        # npm caret with leftmost-non-zero bump
        ("1.2.3", ["^1.2.3"], "npm", True),
        ("1.9.9", ["^1.2.3"], "npm", True),
        ("2.0.0", ["^1.2.3"], "npm", False),
        ("0.2.5", ["^0.2.3"], "npm", True),
        ("0.3.0", ["^0.2.3"], "npm", False),
        ("0.0.3", ["^0.0.3"], "npm", True),
        ("0.0.4", ["^0.0.3"], "npm", False),
        # npm tilde
        ("1.2.5", ["~1.2.3"], "npm", True),
        ("1.3.0", ["~1.2.3"], "npm", False),
        ("1.2.9", ["~1.2"], "npm", True), ("1.3.0", ["~1.2"], "npm", False),
        # x-ranges, wildcard, exact
        ("1.5.2", ["1.x"], "npm", True), ("2.0", ["1.x"], "npm", False),
        ("9.9.9", ["*"], "npm", True),
        ("1.2.3", ["=1.2.3"], "npm", True),
        # node-semver partial ordered bounds: >1.2 == >=1.3.0
        ("1.3.0", [">1.2"], "npm", True), ("1.2.9", [">1.2"], "npm", False),
        ("1.2.9", ["<=1.2"], "npm", True), ("1.3.0", ["<=1.2"], "npm", False),
        # AND conjunction
        ("1.3.0", [">=1.0.0 <2.0.0"], "npm", True),
        ("2.0.1", [">=1.0.0 <2.0.0"], "npm", False),
        # npm prerelease opt-in rule
        ("1.2.3-rc1", ["^1.2.3-rc1"], "npm", True),
        ("1.2.3-rc1", ["^1.2.3"], "npm", False),
        ("1.2.3-rc1", ["*"], "npm", False),
        # cargo: bare version is a caret range; wildcards are x-ranges
        ("1.9.0", ["1.2.3"], "cargo", True),
        ("2.0.0", ["1.2.3"], "cargo", False),
        ("1.2.9", ["1.2.*"], "cargo", True),
        ("1.3.0", ["1.2.*"], "cargo", False),
        ("1.2.3", ["=1.2.3"], "cargo", True),
        # go: semver-ish, v-prefix, pseudo-versions order as prereleases
        ("v1.2.3", [">=v1.2.0"], "go", True),
        ("v1.1.0", [">=v1.2.0"], "go", False),
        ("v1.2.4", ["< v1.2.5"], "go", True),
        ("v0.0.0-20240201-abcdef012345",
         [">=v0.0.0-20230101-000000000000"], "go", True),
    ]
    for ver, cons, eco, want in cases:
        assert m(ver, cons, eco) is want, (ver, cons, eco, want)


def test_version_match_fail_closed_and_explain():
    from bts_sbom._internal.version_match import explain_match, match_range
    # fail-closed: unsupported syntax never guesses a match
    assert match_range("1.2.3", ["||1.0"], "npm") is False
    assert match_range("1.2.3", ["~=2"], "pip") is False      # invalid PEP 440
    assert match_range("anything", [], "pip") is True         # no constraints
    ex = explain_match("1.2.9", [">=1.0.0", "<1.2.5"], "npm")
    assert ex["verdict"] is False
    assert ex["constraint"] == "<1.2.5"                        # FIRST failing
    assert "1.2.5" in ex["reason"]
    assert ex["family"] == "npm" and ex["version"] == "1.2.9"
    ok = explain_match("1.2.4", [">=1.0.0", "<1.2.5"], "npm")
    assert ok["verdict"] is True and ok["constraint"] == ">=1.0.0"
    assert len(ok["all"]) == 2
    assert isinstance(ok["approx"], bool)


# ═══ round 2: E4 guided remediation ═══════════════════════════════════════════

def _multiwindow_vuln():
    return {"id": "GHSA-abcd-efgh-ijkl", "aliases": ["CVE-2026-1001"],
            "affected": [{"package": {"name": "requests", "ecosystem": "PyPI"},
                          "ranges": [{"type": "ECOSYSTEM",
                                      "events": [{"introduced": "0"},
                                                 {"fixed": "2.20.0"},
                                                 {"introduced": "2.28.0"},
                                                 {"fixed": "2.31.0"}]}]}]}


def test_remediation_smallest_fixed():
    from bts_sbom._internal.remediation import remediation_for_result, suggest_fixes
    vuln = _multiwindow_vuln()
    rows = suggest_fixes(vuln, "pypi", current="2.29.0")
    assert rows[0]["fixed_suggestion"] == "2.31.0"     # the CONTAINING window
    assert "ranges[0]" in rows[0]["constraint_source"]
    rows = suggest_fixes(vuln, "pypi", current="1.2.0")
    assert rows[0]["fixed_suggestion"] == "2.20.0"     # smallest >= current
    rows = suggest_fixes(vuln, "pypi", current=None)
    assert rows[0]["fixed_suggestion"] == "2.20.0" and rows[0]["current"] is None
    # last_affected-only window: no fixed version may be claimed
    la = {"id": "GO-2026-0001", "affected": [
        {"package": {"name": "golang.org/x/net", "ecosystem": "Go"},
         "ranges": [{"type": "SEMVER", "events": [{"introduced": "0"},
                                                  {"last_affected": "0.33.0"}]}]}]}
    rows = suggest_fixes(la, "go", current="0.30.0")
    assert rows[0]["fixed_suggestion"] is None
    assert rows[0]["constraint_source"] == "no-fixed-event"
    # every recorded fix sorts below current -> no honest upgrade exists
    stale = {"id": "CVE-2026-1002", "affected": [
        {"package": {"name": "a", "ecosystem": "npm"},
         "versions": ["1.5.0"],
         "ranges": [{"events": [{"introduced": "0"}, {"fixed": "1.2.0"}]}]}]}
    rows = suggest_fixes(stale, "npm", current="1.5.0")
    assert rows[0]["constraint_source"] == "no-fixed-ge-current"
    # scan-result walker: dedup + installed current
    result = {"results": [{"source": {"path": "r", "type": "lockfile"},
                           "packages": [{"package": {"name": "requests",
                                                     "version": "2.29.0",
                                                     "ecosystem": "PyPI"},
                                         "vulnerabilities": [vuln]}]}]}
    blk = remediation_for_result(result)
    assert blk["schema"] == "bts-remediation/1"
    assert blk["suggestion_count"] == 1
    row = blk["suggestions"][0]
    assert (row["osv_id"], row["package"], row["current"],
            row["fixed_suggestion"]) == \
        ("GHSA-abcd-efgh-ijkl", "requests", "2.29.0", "2.31.0")


def test_cli_scan_remediation_block_and_flag(tmp_path):
    lock = tmp_path / "requirements.txt"
    lock.write_text("requests==2.31.0\n", encoding="utf-8")
    r = run_cli("scan", str(lock), "--offline", "--fmt", "json")
    assert r.returncode == 0, r.stderr
    doc = json.loads(r.stdout)
    assert "remediation" in doc            # attached by default
    r = run_cli("scan", str(lock), "--offline", "--fmt", "json",
                "--no-remediation")
    doc = json.loads(r.stdout)
    assert "remediation" not in doc        # --no-remediation omits it
    r = run_cli("scan", str(lock), "--dry-run", "--fmt", "json")
    doc = json.loads(r.stdout)
    assert "remediation" not in doc        # no query -> no suggestions


# ═══ round 2: E3 policy engine ════════════════════════════════════════════════

CRIT_FINDINGS = {
    "results": [{"source": {"path": "requirements.txt", "type": "lockfile"},
                 "packages": [{"package": {"name": "requests",
                                           "version": "2.28.0",
                                           "ecosystem": "PyPI"},
                               "vulnerabilities": [
                                   {"id": "CVE-2026-9999",
                                    "aliases": [],
                                    "severity": [{"type": "CVSS_V3",
                                                  "score": "CVSS:3.1/AV:N/AC:L/"
                                                           "PR:N/UI:N/S:U/C:H/I:H/"
                                                           "A:H"}]}],
                               "groups": []}]}],
}


def test_policy_cli_exit_codes(tmp_path):
    pf = tmp_path / "policy.json"
    ff = tmp_path / "findings.json"
    ff.write_text(json.dumps(CRIT_FINDINGS), encoding="utf-8")
    pf.write_text(json.dumps({"name": "gate",
                              "rules": {"severity_min": "HIGH",
                                        "max_severity_score": 9.0}}),
                   encoding="utf-8")
    r = run_cli("policy", "--policy", str(pf), "--findings", str(ff))
    assert r.returncode == 1                      # CI gate: fail -> exit 1
    ev = json.loads(r.stdout)
    assert ev["verdict"] == "fail" and ev["violations"]
    assert ev["violations"][0]["rule"] == "severity_min"
    # severity/score are recomputed from the CVSS vector (9.8 > 9.0 ceiling)
    assert any(v["rule"] == "max_severity_score" for v in ev["violations"])
    # pass case: no rules bite
    pf.write_text(json.dumps({"name": "open", "rules": {}}), encoding="utf-8")
    r = run_cli("policy", "--policy", str(pf), "--findings", str(ff))
    assert r.returncode == 0
    assert json.loads(r.stdout)["verdict"] == "pass"
    # usage error: unreadable policy -> 2 (never a fabricated verdict)
    r = run_cli("policy", "--policy", str(tmp_path / "nope.json"),
                "--findings", str(ff))
    assert r.returncode == 2 and "bts-sbom" in r.stderr


def test_policy_license_rule_over_sbom(tmp_path):
    from bts_sbom._internal.policy import Policy
    policy = Policy.from_dict({"rules": {"licenses_deny": ["Zlib", "UNKNOWN"]}})
    components = [{"name": "zlib", "license": "Zlib"},
                  {"name": "mystery", "license": None}]
    ev = policy.evaluate({"results": []}, components)
    assert ev["verdict"] == "fail"
    rules = {v["component"]: v["rule"] for v in ev["violations"]}
    assert rules.get("zlib") == "licenses_deny"
    assert rules.get("mystery") == "licenses_deny"     # UNKNOWN denied
    # clean components pass the license rule
    ev = policy.evaluate({"results": []}, [{"name": "openssl",
                                            "license": "Apache-2.0"}])
    assert ev["verdict"] == "pass"
    # SPDX document input also works
    ev = policy.evaluate({"results": []}, json.loads(
        json.dumps(SPDX_SBOM)))
    assert ev["verdict"] == "fail"                     # zlib is in the SBOM


def test_policy_cli_vex_suppression(tmp_path):
    pf = tmp_path / "policy.json"
    ff = tmp_path / "findings.json"
    vf = tmp_path / "vex.json"
    ff.write_text(json.dumps(CRIT_FINDINGS), encoding="utf-8")
    pf.write_text(json.dumps({"rules": {"severity_min": "HIGH"}}),
                  encoding="utf-8")
    vex = {"@context": "https://openvex.dev/ns/v0.2.0",
           "@id": "https://bts-sbom.local/vex/t", "author": "t",
           "timestamp": "2026-01-01T00:00:00Z", "version": 1,
           "statements": [{"vulnerability": {"name": "CVE-2026-9999"},
                           "products": [{"@id": "pkg:pypi/requests"}],
                           "status": "not_affected",
                           "justification": "vulnerable_code_not_present",
                           "impact_statement": "triaged not present"}]}
    vf.write_text(json.dumps(vex), encoding="utf-8")
    r = run_cli("policy", "--policy", str(pf), "--findings", str(ff),
                "--vex", str(vf))
    assert r.returncode == 0                          # suppressed -> pass
    ev = json.loads(r.stdout)
    assert ev["vex"]["not_affected"] == 1 and ev["vex"]["unmatched"] == 0
    assert ev["vex"]["suppressed"][0]["finding"]["osv_id"] == "CVE-2026-9999"
    # `affected` statements never suppress
    vex["statements"][0]["status"] = "affected"
    del vex["statements"][0]["justification"]
    vex["statements"][0]["action_statement"] = "upgrade"
    vf.write_text(json.dumps(vex), encoding="utf-8")
    r = run_cli("policy", "--policy", str(pf), "--findings", str(ff),
                "--vex", str(vf))
    assert r.returncode == 1
    # structurally-invalid VEX fails CLOSED: nothing suppressed, error shown
    vf.write_text(json.dumps({"statements": "not-a-list"}), encoding="utf-8")
    r = run_cli("policy", "--policy", str(pf), "--findings", str(ff),
                "--vex", str(vf))
    assert r.returncode == 1
    ev = json.loads(r.stdout)
    assert "vex_error" in ev["vex"] and ev["vex"]["unmatched"] == 1


def test_vex_evaluate_grouping():
    from bts_sbom._internal.policy import vex_evaluate
    from bts_sbom.vex import build_document, statement
    st = [
        statement("CVE-2026-0001", ["pkg:pypi/a"], "not_affected",
                  justification="component_not_present"),
        statement("CVE-2026-0002", ["pkg:pypi/b"], "fixed",
                  action_statement="upgrade"),
        statement("CVE-2026-0003", ["pkg:pypi/c"], "affected",
                  action_statement="upgrade"),
        statement("CVE-2026-0004", ["pkg:pypi/d"], "under_investigation",
                  impact_statement="pending"),
    ]
    doc = build_document(st, timestamp="2026-01-01T00:00:00Z")
    findings = [{"osv_id": "CVE-2026-%04d" % n, "cve_id": None,
                 "aliases": [], "purl": "pkg:pypi/%s@1.0" % ch,
                 "ecosystem": "PyPI", "name": ch, "version": "1.0"}
                for n, ch in ((1, "a"), (2, "b"), (3, "c"), (4, "d"))]
    findings.append({"osv_id": "CVE-2026-0005", "cve_id": None,
                     "aliases": [], "purl": "pkg:pypi/e@1.0",
                     "ecosystem": "PyPI", "name": "e", "version": "1.0"})
    out = vex_evaluate(findings, doc)
    assert out["not_affected"] == 1 and out["fixed"] == 1
    assert out["affected"] == 1 and out["under_investigation"] == 1
    assert out["unmatched"] == 1
    assert len(out["suppressed"]) == 2                # not_affected + fixed


# ═══ round 2: E1 transitive dependency resolution ═════════════════════════════

def test_npm_lock_nested_transitive_entries(tmp_path):
    """E1 audit lock: package-lock v3 nested node_modules entries ARE the
    transitive closure and must all be returned."""
    from bts_sbom._internal import manifests
    lock = tmp_path / "package-lock.json"
    lock.write_text(json.dumps({
        "name": "root", "lockfileVersion": 3,
        "packages": {
            "": {"dependencies": {"left-pad": "^1.3.0"}},
            "node_modules/left-pad": {"version": "1.3.0"},
            "node_modules/lodash": {"version": "4.17.21"},
            "node_modules/tar/node_modules/minipass": {"version": "3.1.6"},
        }}), encoding="utf-8")
    pkgs = manifests.parse_file(str(lock))
    rel = {p.name: p.relationship for p in pkgs}
    assert rel == {"left-pad": "direct", "lodash": "transitive",
                   "minipass": "transitive"}
    assert pkgs[0].depth == 0 and rel["minipass"] == "transitive"


def test_cargo_lock_direct_transitive_from_sibling_manifest(tmp_path):
    """E1: Cargo.lock is a resolved closure; the direct set comes from the
    sibling Cargo.toml. Without it, relationship is honestly 'unknown'."""
    from bts_sbom._internal import manifests
    lock = tmp_path / "Cargo.lock"
    lock.write_text(
        '[[package]]\nname = "serde"\nversion = "1.0.193"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
        '\n[[package]]\nname = "rand"\nversion = "0.8.5"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n',
        encoding="utf-8")
    toml = tmp_path / "Cargo.toml"
    toml.write_text('[package]\nname = "demo"\nversion = "0.1.1"\n'
                    '\n[dependencies]\nserde = "1.0"\n', encoding="utf-8")
    pkgs = manifests.parse_file(str(lock))
    rel = {p.name: p.relationship for p in pkgs}
    assert rel == {"serde": "direct", "rand": "transitive"}
    assert [p.depth for p in pkgs if p.name == "rand"] == [1]
    # no sibling manifest -> unknown, never a fabricated 'direct'
    toml.unlink()
    pkgs = manifests.parse_file(str(lock))
    rel = {p.name: p.relationship for p in pkgs}
    assert rel == {"serde": "unknown", "rand": "unknown"}


# ═══ round 2: X1 cross-platform hardening ═════════════════════════════════════

def test_utf8_bom_lockfiles_parse_on_every_os(tmp_path):
    """X1 regression: Windows-produced lockfiles (UTF-8 BOM, CRLF, a Latin-1
    byte in a comment) must parse identically on any OS."""
    from bts_sbom._internal import manifests
    lock = tmp_path / "requirements.txt"
    lock.write_bytes(b"\xef\xbb\xbfrequests==2.31.0\r\n"
                     b"# caf\xe9 annotation\r\nurllib3==2.0.3\r\n")
    pkgs = manifests.parse_file(str(lock))
    assert {p.name for p in pkgs} == {"requests", "urllib3"}
    pj = tmp_path / "package-lock.json"
    doc = {"name": "r", "lockfileVersion": 3,
           "packages": {"": {}, "node_modules/left-pad": {"version": "1.3.0"}}}
    pj.write_bytes(b"\xef\xbb\xbf" + json.dumps(doc).encode("utf-8"))
    pkgs = manifests.parse_file(str(pj))
    assert [p.name for p in pkgs] == ["left-pad"]


def test_norm_rel_path_cross_platform():
    from bts_sbom._internal.pathutil import norm_rel_path, rel_suffix_matches
    assert norm_rel_path("var\\lib\\dpkg\\status") == "var/lib/dpkg/status"
    assert norm_rel_path("./var/lib/dpkg//status") == "var/lib/dpkg/status"
    assert rel_suffix_matches("rootfs\\var\\lib\\dpkg\\status",
                              "var/lib/dpkg/status")
    assert rel_suffix_matches("rootfs/var/lib/dpkg/status",
                              "var\\lib\\dpkg\\status")
    assert not rel_suffix_matches("unrelated/status", "var/lib/dpkg/status")
    # parser routing agrees on both spellings (Windows file on Linux CI)
    from bts_sbom._internal import manifests
    assert manifests.parser_for("C:\\rootfs\\var\\lib\\dpkg\\status") \
        is manifests.parser_for("/rootfs/var/lib/dpkg/status")
    assert manifests.parser_for("C:\\rootfs\\var\\lib\\dpkg\\status") \
        is not None
