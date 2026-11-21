"""LLM router, outbound preview and the optional Azure OpenAI provider (task 19, AC 541-549)."""
from __future__ import annotations

import json

import pytest

from bts_sbom_app import ai, evals, llm, pipeline, router, server
from conftest import FakeScanner


def _api(tmp_path, make_repo, world, monkeypatch):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(),
                               run_arch=False, run_proposals=False, cache_dir=str(tmp_path / "cache"))
    st = server.State(evals.repo_root(), str(ev), None)
    return st, rec


def test_the_outbound_preview_holds_no_file_contents_no_paths_no_credentials(tmp_path, make_repo, world):
    """AC: BSA-AC-541"""
    st, rec = _api(tmp_path, make_repo, world, None)
    payload = ai.evidence(rec)
    blob = json.dumps(payload)
    assert "content" not in blob and "text" not in blob                   # no file contents, only structured facts
    for part in blob.replace('"', " ").replace(",", " ").split():
        assert not part.startswith("/") and ":\\" not in part, part       # 0 absolute paths
    assert "tok123" not in blob and "@" not in blob                      # 0 credentials


def test_the_preview_sends_zero_llm_requests(tmp_path, make_repo, world, monkeypatch):
    """AC: BSA-AC-542"""
    st, rec = _api(tmp_path, make_repo, world, monkeypatch)
    payload = ai.evidence(rec)
    assert world.llm_calls == 0 and len(payload["vulns"]) >= 1           # looked at, not sent


def test_router_returns_deterministic_when_cloud_llm_is_not_allowed():
    """AC: BSA-AC-543"""
    reasons = []
    for combo in (({"primary": "exaone"}, "public", 0.0, False), ({"primary": "exaone"}, "private", 0.5, True),
                  ({"primary": "exaone", "fallback": "azure-openai"}, "public", 0.0, False),
                  ({"primary": "exaone", "fallback": "azure-openai"}, "public", 0.2, True)):
        providers, data_class, ratio, throttled = combo
        assert router.choose_backend(data_class=data_class, daily_budget_ratio=ratio, throttled=throttled,
                                     cloud_llm_allowed=False, providers=providers, reasons=reasons) == "deterministic"
    assert len(reasons) == 4


def test_private_data_never_goes_to_a_provider():
    """AC: BSA-AC-544"""
    reasons = []
    assert router.choose_backend(data_class="private", daily_budget_ratio=0.0, throttled=False,
                                 cloud_llm_allowed=True, providers={"primary": "exaone"}, reasons=reasons) == "deterministic"
    assert "private" in reasons[0]


def test_a_daily_budget_ratio_of_point_nine_or_more_downgrades():
    """AC: BSA-AC-545"""
    for ratio in (0.9, 1.0):
        reasons = []
        assert router.choose_backend(data_class="public", daily_budget_ratio=ratio, throttled=False,
                                     cloud_llm_allowed=True, providers={"primary": "exaone"}, reasons=reasons) == "deterministic"
        assert "0.9" in reasons[0] or "1.00" in reasons[0]


def test_throttling_falls_back_or_downgrades_honestly():
    """AC: BSA-AC-546"""
    reasons = []
    assert router.choose_backend(data_class="public", daily_budget_ratio=0.0, throttled=True, cloud_llm_allowed=True,
                                 providers={"primary": "exaone", "fallback": "azure-openai"}, reasons=reasons) == "azure-openai"
    reasons2 = []
    assert router.choose_backend(data_class="public", daily_budget_ratio=0.0, throttled=True, cloud_llm_allowed=True,
                                 providers={"primary": "exaone"}, reasons=reasons2) == "deterministic"
    assert "no fallback" in reasons2[0]


def test_the_proposal_records_the_router_reason(world, tmp_path):
    """AC: BSA-AC-547"""
    origin = tmp_path / "proj"
    origin.mkdir()
    (origin / "requirements.txt").write_text("requests==2.19.1\n", encoding="utf-8", newline="\n")
    ana = pipeline.engine.analyze(str(origin), scanner=FakeScanner())
    rec = dict(ana)
    rec["private"] = True                                            # the scan flagged this evidence as private
    out = ai.propose(rec, client=llm.ChatClient.from_config("FAKE-KEY-router-1"), use_llm=True)
    assert out["source"] == "deterministic"
    assert "private" in out["llm_note"] and "router" in out["llm_note"]


def test_the_azure_openai_key_never_leaks_into_logs_errors_or_status(world, monkeypatch):
    """AC: BSA-AC-548"""
    key = "FAKE-AZURE-KEY-0123456789"
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fake-endpoint.invalid")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "dep-1")
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", key)

    def fake(url, headers, body):
        return 502, "upstream error for key=%s" % key              # the provider text embeds the key

    llm.TRANSPORT = fake
    c = llm.ChatClient.from_azure_openai()
    with pytest.raises(llm.LLMError) as ei:
        c.complete("s", "u")
    assert key not in str(ei.value) and key not in "".join(c.errors)
    blob = json.dumps(c.describe())
    assert key not in blob


def test_the_azure_openai_request_carries_deployment_and_api_version(world, monkeypatch):
    """AC: BSA-AC-549"""
    monkeypatch.setenv("AZURE_OPENAI_ENDPOINT", "https://fake-endpoint.invalid")
    monkeypatch.setenv("AZURE_OPENAI_DEPLOYMENT", "dep-1")
    monkeypatch.setenv("AZURE_OPENAI_API_VERSION", "2024-02-01")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "FAKE-AZURE-KEY-0123456789")
    seen = {}

    def fake(url, headers, body):
        seen["url"] = url
        seen["auth"] = headers.get("api-key", "")
        return 200, json.dumps({"choices": [{"message": {"content": "ok"}}], "usage": {"prompt_tokens": 1, "completion_tokens": 1}})

    llm.TRANSPORT = fake
    c = llm.ChatClient.from_azure_openai()
    out = c.complete("s", "u")
    assert out == "ok"
    assert "/openai/deployments/dep-1/chat/completions" in seen["url"] and "api-version=2024-02-01" in seen["url"]
    assert seen["auth"].startswith("FAKE-AZURE-KEY")               # header present, never logged elsewhere
    monkeypatch.delenv("AZURE_OPENAI_API_KEY", raising=False)
