"""Regression tests for the defects an adversarial pass REPRODUCED against the public-facing surface (2026-11-27)."""
from __future__ import annotations

import json
import os
import socket
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import access, evals, net, netaddr, promptreg, server, workspace

TOKEN = "t0ken-" + "y" * 30


def _start(tmp_path, monkeypatch, *, token=TOKEN, capped=None, **env):
    if token is None:
        monkeypatch.delenv(access.ENV, raising=False)
    else:
        monkeypatch.setenv(access.ENV, token)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    st = server.State(evals.repo_root(), str(tmp_path), None)
    handler = server.make_handler(st)
    httpd = server.CappedServer(("127.0.0.1", 0), handler, max_connections=capped) if capped else ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return st, httpd, httpd.server_address[1]


def _call(port, path, body=None, headers=None, method=None):
    req = urllib.request.Request("http://127.0.0.1:%d%s" % (port, path), data=json.dumps(body).encode() if body is not None else None, method=method,
                                 headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8"), dict(e.headers)


# ------------------------------------------------------------------ slowloris, connection cap, version disclosure
def test_a_stalled_connection_is_dropped_by_the_read_timeout_and_the_server_header_names_no_version(tmp_path, monkeypatch):
    """AC: BSA-AC-1230"""
    monkeypatch.setattr(server, "HANDLER_TIMEOUT", 1.0)
    st, httpd, port = _start(tmp_path, monkeypatch)
    try:
        s = socket.create_connection(("127.0.0.1", port), timeout=10)
        s.sendall(b"GET /api/engine HTTP/1.1\r\nHost: 127.0.0.1\r\n")                                 # never completed: no blank line
        t0 = time.time()
        data = s.recv(4096)                                                                           # the server gives up and closes (EOF), instead of waiting for ever
        assert data == b"" and time.time() - t0 < 6
        s.close()
        code, body, hdr = _call(port, "/healthz")
        assert code == 200 and hdr["Server"] == "bts-sbom" and "Python" not in json.dumps(hdr) and "BaseHTTP" not in json.dumps(hdr)
        code, body, hdr = _call(port, "/api/health")
        assert code == 401 and hdr["Server"] == "bts-sbom"                                            # the 401 discloses nothing either
    finally:
        httpd.shutdown()


def test_connections_beyond_the_cap_get_503_at_once_and_free_slots_are_reused(tmp_path, monkeypatch):
    """AC: BSA-AC-1231"""
    monkeypatch.setattr(server, "HANDLER_TIMEOUT", 3.0)
    st, httpd, port = _start(tmp_path, monkeypatch, capped=2)
    holders = []
    try:
        for _ in range(2):                                                                            # 2 of 2 slots held by idle connections
            h = socket.create_connection(("127.0.0.1", port), timeout=10)
            h.sendall(b"GET /healthz HTTP/1.1\r\nHost: x\r\n")
            holders.append(h)
        time.sleep(0.5)
        extra = socket.create_connection(("127.0.0.1", port), timeout=10)
        reply = extra.recv(4096)
        assert reply.startswith(b"HTTP/1.0 503") and b"Retry-After" in reply                           # 1 of 1 excess connection refused without a thread
        extra.close()
        for h in holders:
            h.close()
        deadline = time.time() + 8
        code = 0
        while time.time() < deadline and code != 200:                                                  # the timeout / close frees the slots
            code = _call(port, "/healthz")[0]
            time.sleep(0.3)
        assert code == 200
    finally:
        httpd.shutdown()


def test_deeply_nested_json_degrades_like_any_malformed_body(tmp_path, monkeypatch):
    """AC: BSA-AC-1232"""
    st, httpd, port = _start(tmp_path, monkeypatch)
    try:
        body = '{"question": "x", "nested": ' + "[" * 200000 + "1" + "]" * 200000 + "}"
        req = urllib.request.Request("http://127.0.0.1:%d/api/chat" % port, data=body.encode(), headers={"Authorization": "Bearer " + TOKEN, "Content-Type": "application/json"})
        try:
            with urllib.request.urlopen(req, timeout=30) as r:
                code, text = r.status, r.read().decode()
        except urllib.error.HTTPError as e:
            code, text = e.code, e.read().decode()
        assert code == 400 and "question required" in text and "Traceback" not in text and "RecursionError" not in text
        assert _call(port, "/api/health", headers={"Authorization": "Bearer " + TOKEN})[0] == 200      # the service is still answering
    finally:
        httpd.shutdown()


# ------------------------------------------------------------------ forwarded-for trust and the failed-credential throttle
class _H:
    def __init__(self, ip, headers):
        self.client_address = (ip, 1)
        self.headers = headers


def test_x_forwarded_for_is_ignored_unless_the_operator_declares_a_trusted_proxy(monkeypatch):
    """AC: BSA-AC-1233"""
    spoof = _H("127.0.0.1", {"X-Forwarded-For": "203.0.113.77"})
    monkeypatch.delenv(server.TRUST_FORWARDED_ENV, raising=False)
    assert server._caller_id(spoof) == "127.0.0.1" and server._caller_id(_H("10.1.2.3", {"X-Forwarded-For": "9.9.9.9"})) == "10.1.2.3"          # 2 of 2 spoofs ignored
    monkeypatch.setenv(server.TRUST_FORWARDED_ENV, "1")
    assert server._caller_id(spoof) == "203.0.113.77" and server._caller_id(_H("8.8.8.8", {"X-Forwarded-For": "9.9.9.9"})) == "8.8.8.8"            # trusted only behind a private peer
    monkeypatch.setenv(server.TRUST_FORWARDED_ENV, "1")
    ingress = _H("100.100.0.64", {"X-Forwarded-For": "220.118.99.214"})            # what the Container Apps ingress really looks like (measured live): a shared-address-space peer
    assert server._caller_id(ingress) == "220.118.99.214" and server._caller_id(_H("100.100.0.173", {"X-Forwarded-For": "220.118.99.214"})) == "220.118.99.214"     # 2 ingress instances, 1 caller
    assert server._caller_id(_H("::ffff:10.0.0.4", {"X-Forwarded-For": "9.9.9.9"})) == "9.9.9.9" and server._caller_id(_H("169.254.1.1", {"X-Forwarded-For": "9.9.9.9"})) == "9.9.9.9"
    monkeypatch.setenv(server.TRUST_FORWARDED_ENV, "0")
    assert server._caller_id(spoof) == "127.0.0.1"


def test_failed_credentials_are_throttled_per_caller_without_checking_the_token_and_the_right_token_never_fails(tmp_path, monkeypatch):
    """AC: BSA-AC-1234"""
    monkeypatch.setattr(server, "AUTH_FAIL_LIMIT", 3)
    st, httpd, port = _start(tmp_path, monkeypatch, BTS_SBOM_TRUST_FORWARDED="1")
    try:
        a = {"X-Forwarded-For": "203.0.113.5"}
        b = {"X-Forwarded-For": "203.0.113.9"}
        assert _call(port, "/api/health", headers=dict(a, Authorization="Bearer " + TOKEN))[0] == 200                      # a valid token before any failure
        codes = [_call(port, "/api/health", headers=dict(a, Authorization="Bearer wrong-%d" % i))[0] for i in range(3)]
        assert codes == [401, 401, 401]
        code, body, hdr = _call(port, "/api/health", headers=dict(a, Authorization="Bearer wrong-3"))
        assert code == 429 and int(hdr["Retry-After"]) >= 1 and TOKEN not in body                                           # the 4th guess is refused unchecked
        assert _call(port, "/api/health", headers=dict(a, Authorization="Bearer " + TOKEN))[0] == 429                       # even the right token from the locked-out caller waits
        assert _call(port, "/api/health", headers=dict(b, Authorization="Bearer " + TOKEN))[0] == 200                       # 1 of 1 other caller unaffected
        assert _call(port, "/healthz", headers=a)[0] == 200                                                                  # the probes are never throttled
        for i in range(server.MAX_CHAT_RATE_CALLERS + 50):                                                                   # the table is bounded
            st.auth_failed("198.51.100.%d-%d" % (i % 250, i))
        assert len(st._auth_fails) <= server.MAX_CHAT_RATE_CALLERS + 1
    finally:
        httpd.shutdown()


# ------------------------------------------------------------------ the prompt digest is no longer recomputed per chat turn
def test_the_prompt_digest_is_cached_on_the_package_signature_and_changes_when_a_module_changes(tmp_path, monkeypatch):
    """AC: BSA-AC-1235"""
    pkg = tmp_path / "bts_sbom_app"
    pkg.mkdir()
    (pkg / "m.py").write_text('SYSTEM = ("%s")\n' % ("You are a careful reviewer. Use ONLY the evidence JSON and never invent identifiers. " * 2), encoding="utf-8")
    calls = {"n": 0}
    real = promptreg.collect

    def counting(root):
        calls["n"] += 1
        return real(root)

    monkeypatch.setattr(promptreg, "collect", counting)
    promptreg._DIGEST_CACHE.clear()
    d1 = promptreg.digest(str(tmp_path))
    assert promptreg.digest(str(tmp_path)) == d1 and promptreg.digest(str(tmp_path)) == d1 and calls["n"] == 1                 # 3 calls, 1 parse
    (pkg / "m.py").write_text((pkg / "m.py").read_text(encoding="utf-8").replace("careful", "careless"), encoding="utf-8")
    assert promptreg.digest(str(tmp_path)) != d1 and calls["n"] == 2                                                         # an edit invalidates it
    assert promptreg._signature(str(tmp_path / "nowhere")) == ()                                                              # a missing package has no signature, so it is never served from the cache


# ------------------------------------------------------------------ legacy IPv4 spellings, file:// authority, DNS pinning
LEGACY = ("2130706433", "0x7f000001", "017700000001", "0177.0.0.1", "127.1", "0x7f.1", "2852039166", "localhost.", "LOCALHOST", "[::ffff:7f00:1]")


def test_legacy_ipv4_spellings_of_loopback_and_metadata_are_refused_by_both_guards(monkeypatch):
    """AC: BSA-AC-1236"""
    monkeypatch.delenv(workspace.PRIVATE_ENV, raising=False)
    monkeypatch.delenv("BTS_OSS_ALLOW_PRIVATE_HOSTS", raising=False)
    for host in LEGACY:
        with pytest.raises(ValueError, match="not a public host"):
            workspace.normalize_source("https://%s:8443/x/y.git" % host)
        assert net._egress_refusal("http://%s:8443/index.html" % host) == "egress_blocked_host", host                          # 10 of 10 spellings in each guard
    assert net._egress_refusal("http://127.0.0.1:1/") == "egress_blocked_host"                                               # the control
    for ok in ("134744072", "8.8.8.8", "0x08080808"):
        assert netaddr.is_public(netaddr.parse_literal(ok)) and net._egress_refusal("https://%s/" % ok) is None                # 3 of 3 spellings of a PUBLIC address pass
    assert netaddr.parse_literal("github.com") is None and netaddr.parse_literal("1.2.3.4.5") is None and netaddr.parse_literal("") is None
    assert netaddr.normalize_host("[FE80::1%eth0]") == "fe80::1" and netaddr.normalize_host("Example.COM.") == "example.com"


def test_a_file_url_that_names_a_host_is_refused_so_the_checked_path_is_the_executed_one(tmp_path, monkeypatch):
    """AC: BSA-AC-1237"""
    monkeypatch.delenv(workspace.ROOTS_ENV, raising=False)
    for url in ("file://evil-host/srv/x", "file://10.0.0.5/etc", "file://user@host/x"):
        with pytest.raises(ValueError, match="must not name a host"):
            workspace.normalize_source(url)                                                                                    # 3 of 3 with an authority
    assert workspace.normalize_source("file:///srv/x")["kind"] == "git" and workspace.normalize_source("file://localhost/srv/x")["kind"] == "git"      # 2 of 2 without one


def test_the_clone_connects_to_the_address_that_was_checked_so_dns_rebinding_cannot_swap_it(tmp_path, monkeypatch):
    """AC: BSA-AC-1238"""
    monkeypatch.delenv(workspace.PRIVATE_ENV, raising=False)
    answers = iter([[(2, 1, 6, "", ("93.184.216.34", 0))], [(2, 1, 6, "", ("169.254.169.254", 0))]])          # the 2nd answer is the rebinding swap
    monkeypatch.setattr(workspace.socket, "getaddrinfo", lambda host, port: next(answers))
    seen = []
    monkeypatch.setattr(workspace, "run", lambda cmd, **k: seen.append(cmd) or (1, "", "stub clone"))
    res = workspace.prepare("https://git.example.test:8443/o/r.git", str(tmp_path / "work"))
    assert res["ok"] is False and len(seen) == 1
    assert "http.curloptResolve=git.example.test:8443:93.184.216.34" in seen[0] and seen[0].index("http.curloptResolve=git.example.test:8443:93.184.216.34") < seen[0].index("clone")   # the checked address is pinned
    assert workspace._curl_pin("ssh://git@host/o/r.git", "1.2.3.4") == [] and workspace._curl_pin("https://h/o/r.git", "") == []             # only https clones can be pinned
    assert workspace._curl_pin("https://h/o/r.git", "1.2.3.4") == ["-c", "http.curloptResolve=h:443:1.2.3.4"]
    monkeypatch.setattr(workspace.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("10.0.0.9", 0)), (2, 1, 6, "", ("93.184.216.34", 0))])
    assert workspace._resolve_for_clone("https://mixed.example.test/o/r.git") == ("10.0.0.9", "")                                            # any internal answer refuses the clone


def test_the_deployment_template_declares_the_trusted_proxy_and_the_renderer_keeps_it():
    """AC: BSA-AC-1239"""
    root = evals.repo_root()
    text = open(os.path.join(root, "deploy", "azure", "containerapp.yaml"), encoding="utf-8").read()
    assert "BTS_SBOM_TRUST_FORWARDED" in text and 'value: "1"' in text.split("BTS_SBOM_TRUST_FORWARDED", 1)[1].split("\n")[1]
    assert "BTS_SBOM_ALLOWED_ROOTS" in text


def test_the_ingress_peer_in_shared_address_space_is_a_proxy_and_the_caller_diagnosis_header_is_opt_in_and_token_only(tmp_path, monkeypatch):
    """AC: BSA-AC-1240"""
    st, httpd, port = _start(tmp_path, monkeypatch, BTS_SBOM_TRUST_FORWARDED="1")
    try:
        auth = {"Authorization": "Bearer " + TOKEN, "X-Forwarded-For": "203.0.113.50"}
        assert "X-BTS-Caller-Debug" not in _call(port, "/api/health", headers=auth)[2]                                       # off by default
        monkeypatch.setenv("BTS_SBOM_DEBUG_CALLER", "1")
        code, body, hdr = _call(port, "/api/health", headers=auth)
        assert code == 200 and "xff=203.0.113.50" in hdr["X-BTS-Caller-Debug"] and "id=203.0.113.50" in hdr["X-BTS-Caller-Debug"]  # 1 of 1 authenticated response carries it
        code, body, hdr = _call(port, "/api/health", headers={"X-Forwarded-For": "203.0.113.50"})
        assert code == 401 and "X-BTS-Caller-Debug" not in hdr and TOKEN not in json.dumps(hdr)                              # 0 of 1 unauthenticated responses
        code, body, hdr = _call(port, "/healthz")
        assert code == 200 and "X-BTS-Caller-Debug" not in hdr                                                              # the open probes never carry it
    finally:
        httpd.shutdown()
