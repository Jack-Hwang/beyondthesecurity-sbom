"""Tests for the egress allowlist/SSRF guard (bts_sbom_app/net.py, course package C01) and the stdlib secret scanner
(bts_sbom_app/secretscan.py, course package C08).

Every value used below that LOOKS like a credential is a well-known placeholder (AWS's own documented example access
key id, or a string literally spelled "placeholder") - never a real secret - matching the "no secrets or tokens
anywhere in the repo" rule while still exercising the regexes for real.
"""
from __future__ import annotations

import subprocess
import urllib.request

import pytest

from bts_sbom import ossscan
from bts_sbom_app import net, resilience, secretscan

# AWS's own documented example access key id (docs.aws.amazon.com) - 16 chars after "AKIA", a well-known placeholder.
_AWS_EXAMPLE_KEY = "AKIAIOSFODNN7EXAMPLE"


def _no_connect(*_a, **_k):
    raise AssertionError("a blocked request must never reach the opener (no socket may open)")


# --------------------------------------------------------------------------------------------------- C01: net.py


LITERAL_BLOCKED_HOSTS = [
    "127.0.0.1",          # loopback
    "169.254.169.254",    # link-local / cloud metadata
    "10.0.0.5",           # private (RFC1918)
    "192.168.1.1",        # private (RFC1918)
    "::1",                # loopback (IPv6)
    "fe80::1",            # link-local (IPv6)
]


def test_egress_blocks_literal_private_link_local_and_metadata_addresses(monkeypatch):
    """AC: BSA-AC-1130"""
    monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)
    monkeypatch.setattr(net, "TRANSPORT", None)
    monkeypatch.setattr(urllib.request, "urlopen", _no_connect)
    blocked = 0
    for host in LITERAL_BLOCKED_HOSTS:
        url = ("http://[%s]/x" % host) if ":" in host else ("http://%s/x" % host)
        oc = net.fetch_json(url)
        assert oc.state == resilience.ACCESS_FAILURE
        assert oc.reason == "egress_blocked_host"
        blocked += 1
    assert blocked == len(LITERAL_BLOCKED_HOSTS) == 6
    # the legacy wrapper contract (data-or-None) also sees the refusal, not a hang or a crash
    assert net.http_json("http://169.254.169.254/x") is None


def test_egress_refusal_log_never_leaks_userinfo_and_still_counts_toward_stats(monkeypatch, caplog):
    """AC: BSA-AC-1130"""
    monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)
    monkeypatch.setattr(net, "TRANSPORT", None)
    monkeypatch.setattr(urllib.request, "urlopen", _no_connect)
    net.reset_stats()
    with caplog.at_level("WARNING", logger="bts_sbom_app.net"):
        oc = net.fetch_json("http://user:hunter2@10.0.0.5/x")
    assert oc.state == resilience.ACCESS_FAILURE and oc.reason == "egress_blocked_host"
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "hunter2" not in logged and "user:" not in logged     # the embedded Basic-Auth userinfo never leaks
    assert "10.0.0.5" in logged                                  # the host itself is still logged, just not the creds
    # a blocked request is still a counted (failed) request, not invisible to net.STATS
    assert net.STATS["requests"] == 1 and net.STATS["failures"] == 1


def test_egress_refusal_never_raises_on_a_malformed_url(monkeypatch):
    """AC: BSA-AC-1131"""
    monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)
    monkeypatch.setattr(net, "TRANSPORT", None)
    monkeypatch.setattr(urllib.request, "urlopen", _no_connect)
    bad_url = "http://[::1/x"                      # unterminated IPv6 bracket - urlsplit() itself raises ValueError
    assert net._egress_refusal(bad_url) == "egress_blocked_scheme"
    oc = net.fetch_json(bad_url)                    # must return a graceful failure, never propagate the exception
    assert oc.state == resilience.ACCESS_FAILURE and oc.reason == "egress_blocked_scheme"


def test_egress_blocks_non_http_schemes_even_with_the_private_host_opt_out_set(monkeypatch):
    """AC: BSA-AC-1131"""
    monkeypatch.setattr(net, "TRANSPORT", None)
    monkeypatch.setattr(urllib.request, "urlopen", _no_connect)
    blocked = 0
    for url in ("file:///etc/passwd", "ftp://host/x"):
        monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)
        oc = net.fetch_json(url)
        assert oc.state == resilience.ACCESS_FAILURE and oc.reason == "egress_blocked_scheme"
        monkeypatch.setenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", "1")
        oc2 = net.fetch_json(url)                      # the opt-out is for HOSTS, not schemes
        assert oc2.state == resilience.ACCESS_FAILURE and oc2.reason == "egress_blocked_scheme"
        blocked += 1
    assert blocked == 2


def test_egress_blocks_a_hostname_that_resolves_to_a_non_public_address(monkeypatch):
    """AC: BSA-AC-1132"""
    monkeypatch.setattr(net, "TRANSPORT", None)
    monkeypatch.setattr(urllib.request, "urlopen", _no_connect)
    monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)
    cases = [("internal.example.corp", ("10.0.0.9", 0)), ("metadata.google.internal", ("169.254.169.254", 0))]
    blocked = 0
    for host, addr in cases:
        monkeypatch.setattr(ossscan.socket, "getaddrinfo",
                             lambda h, *a, _addr=addr, **k: [(2, 1, 6, "", _addr)])
        oc = net.fetch_json("http://%s/x" % host)
        assert oc.state == resilience.ACCESS_FAILURE and oc.reason == "egress_blocked_host"
        blocked += 1
    assert blocked == len(cases) == 2


def test_egress_opt_out_allows_a_private_host_but_never_bypasses_the_scheme_check(monkeypatch):
    """AC: BSA-AC-1133"""
    monkeypatch.setenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", "1")
    assert net._egress_refusal("http://10.0.0.5/x") is None
    assert net._egress_refusal("file:///etc/passwd") == "egress_blocked_scheme"


# The allowlist itself lives in net.py (net.KNOWN_PUBLIC_HOSTS) so production code and this test can never drift
# apart - see the egress-guard comment block in net.py for why each of these never needs a DNS lookup at all.
PUBLIC_HOSTS_USED_BY_THIS_APP = sorted(net.KNOWN_PUBLIC_HOSTS)


def test_egress_never_blocks_the_apps_own_public_hosts_and_the_transport_stub_path_is_unaffected(monkeypatch):
    """AC: BSA-AC-1134"""
    monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)

    def boom_dns(*_a, **_k):
        raise AssertionError("a known-public host must be classified without any DNS lookup")
    monkeypatch.setattr(ossscan.socket, "getaddrinfo", boom_dns)
    passed = 0
    for host in PUBLIC_HOSTS_USED_BY_THIS_APP:
        assert net._egress_refusal("https://%s/x" % host) is None
        passed += 1
    assert passed == len(PUBLIC_HOSTS_USED_BY_THIS_APP) == 6

    # the TRANSPORT test-hook path never opens a socket, so it must never be made to resolve DNS either - every
    # existing stubbed caller (osv/licenses/compat/arch) keeps working exactly as before the guard was added.
    def boom(*_a, **_k):
        raise AssertionError("a TRANSPORT-stubbed call must never touch DNS")
    monkeypatch.setattr(ossscan.socket, "getaddrinfo", boom)

    calls = []

    def transport(url, _headers, _body):
        calls.append(url)
        return (200, "plain text body") if url.endswith("/t") else (200, {"x": 1})

    monkeypatch.setattr(net, "TRANSPORT", transport)
    oc1 = net.fetch_json("https://totally-fake.example.invalid/j")
    oc2 = net.fetch_text("https://totally-fake.example.invalid/t", limit=1000)
    j3 = net.http_json("https://totally-fake.example.invalid/j2")
    assert oc1.state == resilience.SUCCESS and oc2.state == resilience.SUCCESS and j3 == {"x": 1}
    assert len(calls) == 3


def test_the_package_archive_fetch_path_is_guarded_the_same_as_json_and_text(monkeypatch):
    """AC: BSA-AC-1135"""
    monkeypatch.setattr(net, "TRANSPORT", None)
    monkeypatch.setattr(urllib.request, "urlopen", _no_connect)
    monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)

    blocked = 0
    for url in ("http://127.0.0.1/pkg.tar.gz", "file:///etc/passwd"):
        oc = net.fetch_bytes(url)
        assert oc.state == resilience.ACCESS_FAILURE and oc.data is None
        blocked += 1
    assert blocked == 2

    # a public host still reaches the (mocked) connection attempt - the guard does not block fetch_bytes outright.
    monkeypatch.setattr(ossscan.socket, "getaddrinfo", lambda h, *a, **k: [(2, 1, 6, "", ("93.184.216.34", 0))])

    class _FakeResp:
        status = 200

        def read(self, *_a):
            return b"pkg-bytes"

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda *_a, **_k: _FakeResp())
    oc2 = net.fetch_bytes("https://files.pythonhosted.org/pkg.tar.gz")
    assert oc2.state == resilience.SUCCESS and oc2.data == b"pkg-bytes"


# ----------------------------------------------------------------------------------------------- C08: secretscan.py


_FIXTURES = {
    "aws.txt": (_AWS_EXAMPLE_KEY, "aws-access-key"),
    "key.pem": ("-----BEGIN RSA PRIVATE KEY-----", "private-key-block"),
    "anthropic.txt": ("sk-ant-" + "x" * 25, "anthropic-api-key"),
    "openai.txt": ("sk-" + "x" * 32, "openai-style-key"),
    "azure.txt": ("AccountKey=" + "x" * 32, "azure-storage-account-key"),
    "db.txt": ("postgres://user:placeholderpass@dbhost:5432/app", "password-in-url"),
    "cfg.txt": ('password = "placeholderpass"', "password-assignment"),
}


def test_secretscan_flags_each_of_the_7_rule_categories_as_file_line_rule_only(tmp_path):
    """AC: BSA-AC-1136"""
    secret_values = []
    for name, (line, _rule) in _FIXTURES.items():
        (tmp_path / name).write_text("prefix\n" + line + "\n", encoding="utf-8")
        secret_values.append(line)

    findings, summary = secretscan.scan_tree(str(tmp_path))

    assert len(secretscan.RULE_NAMES) == 7
    found_rules = {f["rule"] for f in findings}
    assert found_rules == set(secretscan.RULE_NAMES) == {rule for _line, rule in _FIXTURES.values()}
    for f in findings:
        assert set(f.keys()) == {"file", "line", "rule"}   # file + line + rule - nothing else
        assert f["line"] == 2
    dumped = repr(findings)
    for secret in secret_values:
        assert secret not in dumped                        # the matched text itself is never carried
    assert summary["findings"] == len(findings) == 7
    assert summary["coverage_limited"] is False


def test_secretscan_skips_binary_and_oversized_files_and_names_the_coverage_limit(tmp_path):
    """AC: BSA-AC-1137"""
    (tmp_path / "blob.bin").write_bytes(b"\x00\x01" + _AWS_EXAMPLE_KEY.encode("ascii") + b"\x02\x03")
    (tmp_path / "huge.txt").write_bytes(
        (_AWS_EXAMPLE_KEY + "\n").encode("ascii") + b"x" * (secretscan.MAX_FILE_BYTES + 10)
    )
    (tmp_path / "clean.txt").write_text("nothing to see here\n", encoding="utf-8")

    findings, summary = secretscan.scan_tree(str(tmp_path))

    assert findings == []                                   # neither skipped file's look-alike was ever read
    assert summary["files_skipped_binary"] == 1
    assert summary["files_skipped_oversized"] == 1
    assert summary["files_skipped_total"] == 2
    assert summary["files_scanned"] == 1                    # only clean.txt
    assert summary["findings"] == 0
    assert summary["coverage_limited"] is True              # 0 findings must NOT be read as "clean" here


def test_secretscan_skips_git_and_node_modules_by_name_and_never_follows_a_symlink_out_of_root(tmp_path):
    """AC: BSA-AC-1138"""
    root = tmp_path / "proj"
    root.mkdir()
    (root / ".git").mkdir()
    (root / ".git" / "looks_like_a_secret.txt").write_text(_AWS_EXAMPLE_KEY + "\n", encoding="utf-8")
    (root / "node_modules" / "pkg").mkdir(parents=True)
    (root / "node_modules" / "pkg" / "looks_like_a_secret.txt").write_text(_AWS_EXAMPLE_KEY + "\n", encoding="utf-8")

    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "leak.txt").write_text(_AWS_EXAMPLE_KEY + "\n", encoding="utf-8")
    try:
        (root / "escape_link").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("this runner cannot create symlinks")

    (root / "app.py").write_text("print('hello')\n", encoding="utf-8")

    findings, summary = secretscan.scan_tree(str(root))

    assert findings == []
    assert summary["files_scanned"] == 1                     # only app.py: .git/, node_modules/ and the symlink
    assert summary["files_skipped_total"] == 0                # target are never even visited, not "skipped"


def test_secretscan_does_not_follow_an_ntfs_directory_junction_out_of_root(tmp_path):
    """AC: BSA-AC-1138"""
    root = tmp_path / "proj_junction"
    root.mkdir()
    (root / "app.py").write_text("print('hello')\n", encoding="utf-8")

    outside = tmp_path / "outside_junction"
    outside.mkdir()
    (outside / "leak.txt").write_text(_AWS_EXAMPLE_KEY + "\n", encoding="utf-8")

    junction = root / "escape_junction"
    try:
        # bytes (not text=True): mklink's own console-codepage output is not guaranteed to be valid UTF-8, and
        # only the return code / junction.exists() below are actually used to decide pass vs. skip.
        created = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True,
        )
    except OSError as exc:
        pytest.skip("this runner cannot invoke mklink: %s" % exc)
    if created.returncode != 0 or not junction.exists():
        detail = (created.stderr or created.stdout).decode("utf-8", errors="replace")
        pytest.skip("this runner cannot create an NTFS junction: %s" % detail)

    findings, summary = secretscan.scan_tree(str(root))

    assert findings == []                                      # the junction target's secret is never read
    assert summary["files_scanned"] == 1                       # only app.py - the junction is never descended into
    assert summary["files_skipped_total"] == 0                 # not visited at all, not "skipped" either


def test_secretscan_does_not_flag_benign_near_miss_lines(tmp_path):
    """AC: BSA-AC-1139"""
    (tmp_path / "benign.txt").write_text(
        "\n".join([
            'password = "ask"',                   # value too short (< 6 chars) for the password-assignment rule
            'password_hint = "longenoughvalue"',  # "password" is a substring but not the whole keyword token -
                                                   # the regex re-anchors on password/passwd/pwd + separator, so a
                                                   # suffixed identifier like this is never treated as an assignment
            "mysql://user@dbhost/mydb",           # no password before the '@' for the password-in-url rule
            "AKIAEXAMPLE",                        # 7 chars after AKIA, not the 16 the aws-access-key rule requires
        ]) + "\n",
        encoding="utf-8",
    )

    findings, summary = secretscan.scan_tree(str(tmp_path))

    assert findings == []
    assert summary["files_scanned"] == 1
    assert summary["findings"] == 0
