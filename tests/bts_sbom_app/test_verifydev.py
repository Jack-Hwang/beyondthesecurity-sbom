"""verify-dev contract: NOT RUN without a deployment, honest checks, token never printed (task 22, AC 567-572)."""
from __future__ import annotations

import json
import os

from bts_sbom_app import verifydev

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def _opener(responses):
    def get(path):
        return responses[path]
    return get


def test_no_dev_base_url_prints_not_run_and_exits_two(capsys):
    """AC: BSA-AC-567"""
    os.environ.pop("DEV_BASE_URL", None)
    rc = verifydev.run(base_url="")
    out = capsys.readouterr().out
    assert rc == 2 and "NOT RUN" in out


def test_a_healthy_cloud_deployment_reports_pass(tmp_path, capsys):
    """AC: BSA-AC-568"""
    def get(path):
        if path == "/healthz":
            return 200, '{"ok": true}'
        if path == "/readyz":
            return 200, '{"ok": true, "mode": "active"}'
        if path == "/api/projects":
            return 401, '{"error": "unauthorized"}'
        if path == "/api/engine":
            return 200, '{"cloud": {"enabled": true}}'
        return 404, "{}"
    rc = verifydev.run(base_url="https://dev.example.invalid", token="FAKE-TOKEN-vd-1", opener=get, out_dir=str(tmp_path))
    out = capsys.readouterr().out
    assert rc == 0 and "PASS" in out
    summary = json.load(open(os.path.join(str(tmp_path), "proof-results.json"), encoding="utf-8"))
    assert summary["overall"] == "pass"
    assert "FAKE-TOKEN-vd-1" not in json.dumps(summary) and "FAKE-TOKEN-vd-1" not in out


def test_an_open_api_route_fails_the_authentication_check(tmp_path):
    """AC: BSA-AC-569"""
    def get(path):
        if path == "/healthz":
            return 200, '{"ok": true}'
        if path == "/readyz":
            return 200, '{"ok": true, "mode": "active"}'
        return 200, '{"projects": []}'                                  # unauthenticated API answers 200: FAIL
    rc = verifydev.run(base_url="https://dev.example.invalid", opener=get, out_dir=str(tmp_path))
    summary = json.load(open(os.path.join(str(tmp_path), "proof-results.json"), encoding="utf-8"))
    assert rc == 1 and summary["overall"] == "fail"
    assert any(c["check"] == "unauthenticated_api_is_401" and c["status"] == "FAIL" for c in summary["checks"])


def test_plain_http_to_a_non_local_host_is_refused_before_any_token_request(tmp_path):
    """AC: BSA-AC-570"""
    sent = []

    def get(path):
        sent.append(path)
        return 200, "{}"
    rc = verifydev.run(base_url="http://public.example.invalid", token="FAKE-TOKEN-vd-2", opener=get, out_dir=str(tmp_path))
    assert rc == 2 and sent == [], "0 requests may carry the token over plain http"


def test_the_token_is_never_written_to_output_or_sidecars(tmp_path, capsys):
    """AC: BSA-AC-571"""
    def get(path):
        if path == "/api/engine":
            return 200, '{"cloud": {"enabled": true}}'
        if path == "/readyz":
            return 200, '{"ok": true, "mode": "active"}'
        return (200, '{"ok": true}') if path == "/healthz" else (401, '{"error": "unauthorized"}')
    token = "FAKE-TOKEN-sidecar-check-9999"
    rc = verifydev.run(base_url="https://dev.example.invalid", token=token, opener=get, out_dir=str(tmp_path))
    blob = json.dumps(json.load(open(os.path.join(str(tmp_path), "proof-results.json"), encoding="utf-8")))
    runs = os.listdir(os.path.join(str(tmp_path), "proof-runs"))
    for fn in runs:
        blob += open(os.path.join(str(tmp_path), "proof-runs", fn), encoding="utf-8").read()
    assert rc == 0 and token not in blob and token not in capsys.readouterr().out


def test_the_contract_holds_5_blocks_4_verbs_and_real_modules():
    """AC: BSA-AC-572"""
    contract = json.load(open(os.path.join(REPO, ".agentic-dev", "contract.json"), encoding="utf-8"))
    for block in ("spec", "commands", "artifacts", "integrations", "notes"):
        assert block in contract, block
    for verb in ("build", "proof", "deploy_dev", "verify_dev"):
        assert verb in contract["commands"], verb
    # python commands must resolve to existing modules; deploy_dev is an external CLI (azd) whose absence
    # is honestly recorded in the contract notes as NOT RUN
    for verb, cmd in contract["commands"].items():
        if "-m " in cmd:
            assert _module_exists(cmd.split("-m ")[-1].split(" ")[0]), (verb, cmd)
    assert contract["commands"]["deploy_dev"].startswith("azd ")
    assert any("NOT RUN" in n for n in contract["notes"])
    assert contract["artifacts"]["proof_output"].startswith("evidence/")


def _module_exists(name: str) -> bool:
    from importlib import util
    for base in (os.path.join(REPO), ):
        for candidate in (name.replace(".", os.sep) + ".py", name.replace(".", os.sep), name.replace(".", os.sep) + os.sep + "__init__.py"):
            if os.path.exists(os.path.join(base, candidate)):
                return True
    return util.find_spec(name) is not None


def test_a_standby_deployment_is_incomplete_never_pass():
    def get(path):
        if path == "/readyz":
            return 200, '{"ok": true, "mode": "standby"}'
        return (200, '{"ok": true}') if path == "/healthz" else (401, '{"error": "unauthorized"}')
    rc = verifydev.run(base_url="https://dev.example.invalid", opener=get, out_dir=str(os.path.join(REPO, "evidence", "_vd_test")))
    assert rc == 2                                          # NOT RUN-classified: incomplete, never a pass
