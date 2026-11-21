"""Stdlib-only secret scanner (tools/secret_scan.py) -- method gap closer.

Closes audit gap advlab-harness:M20 (and the duplicate_merged rows pointing
at it: advlab-harness:M19, advlab-project:M22) plus the related
assignment-guides:AG-020 / practice-prompts:PP-19 rows: the repo had no
rule-based secret detector anywhere, despite the stdlib-only philosophy
fitting one well.

Honesty contract covered here: a scan never prints the secret value it
found (only file:line:rule); a file that cannot be read is reported as an
inconclusive scan, never silently folded into a "clean" result; a bad
root path is a usage error, not a false "clean".

Fixtures are built at test time under a tempfile.TemporaryDirectory() and
are never committed to the repo, so the real secret_scan.py CI step can
never trip over its own test fixtures.
"""
from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SCANNER = REPO / "tools" / "secret_scan.py"

# One fake value per pattern family. Deliberately obviously-fake but shaped
# exactly like the real thing, so the regex families must match on shape
# alone, and this test can assert that shape never leaks to stdout.
#
# Each literal below is deliberately split with "+" (and the header/footer
# text kept out of the fixture dict as plain contiguous text) so that the
# *source line itself* never contains a contiguous secret shape -- this
# test file is itself scanned by the real tools/secret_scan.py CI step
# (bts_sbom_app_ci.yml), and a scanner test must not be its own fixture.
AWS_KEY = "AKIA" + "FAKEEXAMPLE12345"
PEM_BODY = "MIIFAKEPEMBODYCONTENT" + "x" * 55
BEARER_TOKEN = "sk-ant-" + "FAKEh9x7q2m4p8w1z5v3b6n0c3f7j1k5r9t2y6"
AZURE_KEY = "A" * 80 + "FAKE/+=="
URL_PASSWORD = "FakeSup3rSecretPassw0rd"
PEM_HEADER = "-----BEGIN " + "RSA PRIVATE KEY-----"
PEM_FOOTER = "-----END " + "RSA PRIVATE KEY-----"

FIXTURES = {
    "aws_creds.py": f'AWS_ACCESS_KEY_ID = "{AWS_KEY}"\n',
    "server.pem": PEM_HEADER + "\n" + PEM_BODY + "\n" + PEM_FOOTER + "\n",
    "client.py": f'headers = {{"Authorization": "Bearer {BEARER_TOKEN}"}}\n',
    "azure.env": f"AccountKey={AZURE_KEY}\n",
    "db_url.py": 'DATABASE_URL = "postgres://admin:' + URL_PASSWORD + '@dbhost:5432/app"\n',
    "clean_module.py": "def add(a, b):\n    return a + b\n",
}

FAKE_VALUES = (AWS_KEY, PEM_BODY, BEARER_TOKEN, AZURE_KEY, URL_PASSWORD)

EXPECTED_RULES_BY_FILE = {
    "aws_creds.py": "AWS_ACCESS_KEY",
    "server.pem": "PEM_PRIVATE_KEY",
    "client.py": "BEARER_API_TOKEN",
    "azure.env": "AZURE_STORAGE_KEY",
    "db_url.py": "URL_EMBEDDED_PASSWORD",
}


def _write_fixtures(root: Path) -> None:
    for name, content in FIXTURES.items():
        (root / name).write_text(content, encoding="utf-8")


def _run_scanner(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, "-I", str(SCANNER), *args],
        cwd=REPO,
        capture_output=True,
        text=True,
        timeout=30,
    )


def test_scanner_script_exists():
    assert SCANNER.is_file(), "tools/secret_scan.py must exist"


def test_reports_every_fixture_by_file_line_rule_and_exits_nonzero():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_fixtures(root)
        result = _run_scanner(str(root))

    assert result.returncode == 1, (result.stdout, result.stderr)
    for fname, rule in EXPECTED_RULES_BY_FILE.items():
        needle = f"{fname}:1: {rule}"
        assert needle in result.stdout, (
            f"missing {needle!r} in scanner output:\n{result.stdout}"
        )
    # clean_module.py must never be reported.
    assert "clean_module.py" not in result.stdout


def test_never_leaks_the_matched_secret_value():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        _write_fixtures(root)
        result = _run_scanner(str(root))

    combined = result.stdout + result.stderr
    for value in FAKE_VALUES:
        assert value not in combined, (
            f"scanner leaked a matched secret value ({value!r}) into its own output"
        )


def test_clean_tree_exits_zero_and_says_clean():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "clean_module.py").write_text(FIXTURES["clean_module.py"], encoding="utf-8")
        result = _run_scanner(str(root))

    assert result.returncode == 0, (result.stdout, result.stderr)
    assert "clean" in result.stdout.lower()


def test_bad_root_is_a_usage_error_not_a_false_clean():
    result = _run_scanner(str(Path(tempfile.gettempdir()) / "does-not-exist-bts-sbom-xyz"))
    assert result.returncode == 2, (result.stdout, result.stderr)
    assert "clean" not in result.stdout.lower()


def test_binary_files_are_skipped_without_crashing():
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "blob.bin").write_bytes(b"\x00\x01\x02binary\xffdata" + AWS_KEY.encode())
        result = _run_scanner(str(root))

    assert result.returncode == 0, (result.stdout, result.stderr)


def test_unreadable_file_is_reported_as_inconclusive_not_silently_clean(monkeypatch):
    """A file that cannot be read must never be silently treated as clean.

    This is the project's honesty contract applied to the scanner itself:
    absence of evidence (a file we could not inspect) is never reported as
    a pass. Exercised in-process (not via subprocess) so monkeypatch can
    force the read failure deterministically, with no network involved.
    """
    sys.path.insert(0, str(REPO / "tools"))
    try:
        import secret_scan  # noqa: PLC0415 (import after sys.path edit, by design)
    finally:
        sys.path.remove(str(REPO / "tools"))

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        (root / "ok.py").write_text("def f():\n    return 1\n", encoding="utf-8")
        blocked = root / "blocked.py"
        blocked.write_text("def g():\n    return 2\n", encoding="utf-8")

        real_read_bytes = Path.read_bytes

        def fake_read_bytes(self, *a, **kw):
            if self.name == "blocked.py":
                raise OSError("permission denied (simulated)")
            return real_read_bytes(self, *a, **kw)

        monkeypatch.setattr(Path, "read_bytes", fake_read_bytes, raising=True)

        exit_code = secret_scan.main([str(root)])

    assert exit_code == 3

