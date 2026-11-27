"""Source acquisition boundary of a service that is reachable beyond localhost: declared roots and no internal git hosts."""
from __future__ import annotations

import os

import pytest

from bts_sbom_app import chat, evals, server, workspace


def _proj(tmp_path, name):
    p = tmp_path / name
    p.mkdir()
    (p / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8")
    return p


def test_a_local_source_must_live_inside_a_declared_root_when_roots_are_declared(tmp_path, monkeypatch):
    """AC: BSA-AC-1106"""
    inside, other = _proj(tmp_path, "allowed-app"), _proj(tmp_path, "elsewhere")
    monkeypatch.delenv(workspace.ROOTS_ENV, raising=False)
    assert workspace.allowed_roots() == [] and workspace.normalize_source(str(other))["kind"] == "local"          # unset: trusted-operator mode, unchanged
    monkeypatch.setenv(workspace.ROOTS_ENV, str(inside.parent / "allowed-app"))
    assert workspace.normalize_source(str(inside))["path"] == str(inside)
    for bad in (str(other), str(inside / ".." / "elsewhere"), str(tmp_path), os.path.join(str(inside), "..", "..")):
        with pytest.raises(ValueError, match="outside the declared roots"):
            workspace.normalize_source(bad)
    monkeypatch.setenv(workspace.ROOTS_ENV, os.pathsep.join([str(inside), str(other)]))
    assert workspace.normalize_source(str(other / "requirements.txt"))["kind"] == "local"                          # two roots, a file inside one
    link = tmp_path / "link-out"
    try:
        os.symlink(str(other), str(link), target_is_directory=True)
    except (OSError, NotImplementedError, AttributeError):
        link = None
    monkeypatch.setenv(workspace.ROOTS_ENV, str(inside))
    if link is not None:
        with pytest.raises(ValueError, match="outside the declared roots"):                                       # a symlink is judged by its real path
            workspace.normalize_source(str(link))
    for url in ("file://" + str(other).replace("\\", "/"), "file:///" + str(other).replace("\\", "/").lstrip("/")):
        with pytest.raises(ValueError, match="file:// path is outside|must not name a host"):                                          # a file:// clone is the same boundary
            workspace.normalize_source(url)
    monkeypatch.delenv(workspace.ROOTS_ENV, raising=False)
    assert workspace.normalize_source("file:///" + str(other).replace("\\", "/").lstrip("/"))["kind"] == "git"


def test_a_git_url_to_a_non_public_ip_or_a_local_name_is_refused_unless_allowed(monkeypatch):
    """AC: BSA-AC-1107"""
    monkeypatch.delenv(workspace.PRIVATE_ENV, raising=False)
    bad = ("https://127.0.0.1/x.git", "https://169.254.169.254/latest/meta-data", "https://10.0.0.5/x.git", "https://192.168.1.1/x.git", "https://100.64.1.1/x.git",
           "https://[::1]/x.git", "https://[::ffff:10.0.0.5]/x.git", "git@localhost:o/r.git", "ssh://git@foo.internal/o/r.git", "https://metadata.google.internal/x")
    for url in bad:
        with pytest.raises(ValueError, match="is not a public host"):
            workspace.normalize_source(url)
    for url in ("https://github.com/o/r.git", "git@github.com:o/r.git", "https://gitlab.com/o/r", "ssh://git@8.8.8.8/o/r.git"):
        assert workspace.normalize_source(url)["kind"] == "git", url
    assert workspace.normalize_source("psf/requests")["url"] == "https://github.com/psf/requests.git"
    monkeypatch.setenv(workspace.PRIVATE_ENV, "1")
    assert workspace.normalize_source("https://10.0.0.5/x.git")["kind"] == "git"                                  # a private git server on purpose
    assert workspace.public_address("8.8.8.8") is True and workspace.public_address("github.com") is None and workspace.public_address("::ffff:127.0.0.1") is False


def test_a_refused_source_writes_nothing_and_a_name_that_resolves_to_an_internal_address_is_refused_before_git_runs(tmp_path, monkeypatch):
    """AC: BSA-AC-1108"""
    other = _proj(tmp_path, "elsewhere")
    work = tmp_path / "work"
    monkeypatch.setenv(workspace.ROOTS_ENV, str(tmp_path / "nothing-here"))
    res = workspace.prepare(str(other), str(work))
    assert res["ok"] is False and "outside the declared roots" in res["error"] and not work.exists()              # 0 bytes under work_root
    monkeypatch.delenv(workspace.ROOTS_ENV, raising=False)
    monkeypatch.delenv(workspace.PRIVATE_ENV, raising=False)
    calls = []
    monkeypatch.setattr(workspace, "run", lambda *a, **k: calls.append(a) or (1, "", "stub"))
    monkeypatch.setattr(workspace.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("10.1.2.3", 0))])
    res = workspace.prepare("https://git.example.test/o/r.git", str(work))
    assert res["ok"] is False and "resolves to a non-public address (10.1.2.3)" in res["error"] and calls == [] and not work.exists()
    monkeypatch.setattr(workspace.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("93.184.216.34", 0))])
    assert workspace._resolves_privately("https://git.example.test/o/r.git") == ""                               # public: fine
    monkeypatch.setattr(workspace.socket, "getaddrinfo", lambda host, port: (_ for _ in ()).throw(OSError("no dns")))
    assert workspace._resolves_privately("https://git.example.test/o/r.git") == ""                               # undecidable is not a refusal
    assert workspace._resolves_privately("https://10.0.0.5/x.git") == "" and workspace._resolves_privately("file:///x") == ""   # literals were classified earlier, no DNS
    monkeypatch.setenv(workspace.PRIVATE_ENV, "1")
    monkeypatch.setattr(workspace.socket, "getaddrinfo", lambda host, port: [(2, 1, 6, "", ("10.1.2.3", 0))])
    assert workspace._resolves_privately("https://git.example.test/o/r.git") == ""


def test_the_chat_action_and_the_api_report_the_boundary_instead_of_analysing(tmp_path, monkeypatch):
    """AC: BSA-AC-1109"""
    other = _proj(tmp_path, "elsewhere")
    monkeypatch.setenv(workspace.ROOTS_ENV, str(tmp_path / "nothing-here"))
    assert "outside the declared roots" in server._safe_source(str(other))
    assert server._safe_source("https://127.0.0.1/x.git") and "not a public host" in server._safe_source("https://127.0.0.1/x.git")

    class NoActions:                                           # analyze must never be reached
        def analyze(self, src):
            raise AssertionError("the boundary was not enforced before the action ran")

    out = chat.run_tool(evals.synthetic_project(), "analyze_project", {"source": str(other)}, actions=NoActions())
    assert out[0]["source"] == "action:analyze:refused" and "outside the declared roots" in " ".join(out[0]["lines"])
    monkeypatch.delenv(workspace.ROOTS_ENV, raising=False)
    assert server._safe_source(str(other)) is None
