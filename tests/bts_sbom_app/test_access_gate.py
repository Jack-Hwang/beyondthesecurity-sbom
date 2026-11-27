"""Shared-secret gate of a deployed instance: BTS_SBOM_ACCESS_TOKEN closes every route but the two probes."""
from __future__ import annotations

import base64
import json
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import access, cli, evals, server

TOKEN = "t0ken-" + "x" * 30


def _basic(user: str, pw: str) -> str:
    return "Basic " + base64.b64encode(("%s:%s" % (user, pw)).encode("utf-8")).decode("ascii")


def _serve(tmp_path, monkeypatch, token=TOKEN):
    if token is None:
        monkeypatch.delenv(access.ENV, raising=False)
    else:
        monkeypatch.setenv(access.ENV, token)
    st = server.State(evals.repo_root(), str(tmp_path), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _call(url, body=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8"), dict(e.headers)


def test_the_token_comes_from_the_environment_must_be_long_enough_and_can_be_generated():
    """AC: BSA-AC-1100"""
    assert access.configured_token({}) is None and access.configured_token({access.ENV: ""}) is None and access.configured_token({access.ENV: "   "}) is None
    assert access.configured_token({access.ENV: "  " + TOKEN + "\n"}) == TOKEN
    with pytest.raises(ValueError, match="at least 16 characters"):
        access.configured_token({access.ENV: "short-secret"})
    a, b = access.generate(), access.generate()
    assert a != b and len(a) >= 43 and access.configured_token({access.ENV: a}) == a                 # 256 bits, url-safe, accepted by its own validator
    assert access.exempt("/healthz") and access.exempt("/readyz") and not access.exempt("/api/chat") and not access.exempt("/healthz/x") and not access.exempt("/")


def test_the_credential_is_read_from_basic_bearer_or_a_header_and_compared_exactly():
    """AC: BSA-AC-1101"""
    for h in ({"Authorization": _basic("anyone", TOKEN)}, {"Authorization": _basic("", TOKEN)}, {"Authorization": "Bearer " + TOKEN}, {"Authorization": "bearer " + TOKEN},
              {"X-BTS-Token": TOKEN}):
        assert access.authorized(h, TOKEN) is True, h
    for h in ({}, {"Authorization": _basic("anyone", TOKEN + "x")}, {"Authorization": _basic("anyone", TOKEN[:-1])}, {"Authorization": "Bearer "},
              {"Authorization": "Basic !!!not-base64!!!"}, {"Authorization": "Basic " + base64.b64encode(b"\xff\xfe:x").decode()},
              {"Authorization": "Digest " + TOKEN}, {"X-BTS-Token": TOKEN.upper()}, {"Authorization": _basic(TOKEN, "")}):
        assert access.authorized(h, TOKEN) is False, h
    assert access.authorized({}, None) is True and access.authorized({"Authorization": "Bearer nope"}, None) is True            # gate off: nothing is checked
    assert access.challenge() == {"WWW-Authenticate": 'Basic realm="bts-sbom", charset="UTF-8"'}


def test_with_a_token_every_route_but_the_probes_answers_401_with_the_challenge(tmp_path, monkeypatch):
    """AC: BSA-AC-1102"""
    httpd, base = _serve(tmp_path, monkeypatch)
    try:
        for path in ("/", "/static/bts_console.js", "/api/health", "/api/llm", "/api/escalations", "/api/agent-card", "/api/fleet", "/api/nosuch"):
            code, body, hdr = _call(base + path)
            assert code == 401 and "authentication required" in body and hdr["WWW-Authenticate"].startswith("Basic realm=") and TOKEN not in body, path
        for path in ("/healthz", "/readyz"):
            assert _call(base + path)[0] == 200, path
        code, body, _ = _call(base + "/api/health", headers={"Authorization": _basic("u", TOKEN + "x")})
        assert code == 401 and TOKEN not in body
        for h in ({"Authorization": _basic("browser", TOKEN)}, {"Authorization": "Bearer " + TOKEN}, {"X-BTS-Token": TOKEN}):
            assert _call(base + "/api/health", headers=h)[0] == 200, h
        assert _call(base + "/", headers={"Authorization": _basic("browser", TOKEN)})[0] == 200
    finally:
        httpd.shutdown()


def test_a_post_without_the_token_is_refused_before_its_body_is_used_and_the_stream_needs_it_too(tmp_path, monkeypatch):
    """AC: BSA-AC-1103"""
    httpd, base = _serve(tmp_path, monkeypatch)
    try:
        for path in ("/api/chat", "/api/chat/stream", "/api/escalations/E-00000000/resolve", "/api/scan"):
            code, body, hdr = _call(base + path, {"question": "취약점 현황 요약해줘"})
            assert code == 401 and "WWW-Authenticate" in hdr, path
        assert list(tmp_path.iterdir()) == [] or not any(p.name == "escalations.jsonl" for p in tmp_path.iterdir())      # nothing was processed, nothing was logged
        code, body, _ = _call(base + "/api/chat", {"question": "담당자와 이야기하고 싶어요"}, {"Authorization": "Bearer " + TOKEN})
        assert code == 200 and json.loads(body)["answer_source"] == "escalation"
        code, body, _ = _call(base + "/api/chat/stream", {"question": "담당자와 이야기하고 싶어요"}, {"Authorization": _basic("u", TOKEN)})
        assert code == 200 and "event: final" in body
    finally:
        httpd.shutdown()


def test_without_a_token_nothing_changes_and_the_agent_card_states_which_scheme_applies(tmp_path, monkeypatch):
    """AC: BSA-AC-1104"""
    httpd, base = _serve(tmp_path, monkeypatch, token=None)
    try:
        assert _call(base + "/api/health")[0] == 200 and _call(base + "/")[0] == 200
        card = json.loads(_call(base + "/api/agent-card")[1])
        assert list(card["securitySchemes"]) == ["none"]
    finally:
        httpd.shutdown()
    httpd, base = _serve(tmp_path, monkeypatch)
    try:
        card = json.loads(_call(base + "/api/agent-card", headers={"X-BTS-Token": TOKEN})[1])
        assert list(card["securitySchemes"]) == ["accessToken"] and card["securitySchemes"]["accessToken"]["scheme"] == "basic"
        assert TOKEN not in json.dumps(card)
    finally:
        httpd.shutdown()


def test_a_too_short_token_stops_the_service_at_start_and_the_cli_prints_a_usable_one(tmp_path, monkeypatch, capsys):
    """AC: BSA-AC-1105"""
    monkeypatch.setenv(access.ENV, "short")
    with pytest.raises(ValueError, match="at least 16 characters"):
        server.State(evals.repo_root(), str(tmp_path), None)
    monkeypatch.delenv(access.ENV, raising=False)
    assert cli.main(["access-token"]) == 0
    tok = capsys.readouterr().out.strip()
    assert len(tok) >= 43 and access.configured_token({access.ENV: tok}) == tok
    assert cli.main(["access-token", "--json"]) == 0
    obj = json.loads(capsys.readouterr().out)
    assert obj["env"] == "BTS_SBOM_ACCESS_TOKEN" and obj["min_length"] == 16 and obj["token"] != tok
