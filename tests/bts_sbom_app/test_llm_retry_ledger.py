"""The LLM retry ledger + degradation flag (course 5-3 D4 §20 / 5-4 D1 §21-22): every transport attempt is recorded
with WHAT happened and WHY it was retried or refused (429_retry_after / 429_day_limit / 5xx_transient / http_4xx /
network_lost), retry_stats() turns the ledger into the health signal a spiking retry rate needs to be visible, and
the chat turn carries an explicit degraded flag so the UI badges a downgrade instead of a reader discovering it in
prose (the degradation signal travels WITH the result; silence is the failure mode)."""
import inspect
import json

from bts_sbom_app import llm as llm_mod
from bts_sbom_app import server as server_mod


def _ok(text="hi"):
    return 200, json.dumps({"choices": [{"message": {"content": text}, "finish_reason": "stop"}],
                            "usage": {"prompt_tokens": 1, "completion_tokens": 1}})


def _client(monkeypatch, transport):
    monkeypatch.setattr(llm_mod, "TRANSPORT", transport)
    monkeypatch.setattr(llm_mod, "SLEEP", lambda s: None)      # instant retries
    return llm_mod.ChatClient("k", daily_budget=10)


# ------------------------------------------------------------------ the ledger: every attempt is recorded with its reason
def test_a_clean_call_logs_one_ok_attempt(monkeypatch):
    """AC: BSA-AC-1266"""
    c = _client(monkeypatch, lambda u, h, b: _ok("hi"))
    assert c.complete("s", "u") == "hi"
    assert [(e["attempt"], e["outcome"], e["reason"]) for e in c.attempt_log] == [(0, "ok", "completed")]
    st = c.retry_stats()
    assert st["completions"] == 1 and st["retry_rate"] == 0.0 and st["failures"] == 0


def test_a_429_with_retry_after_is_retried_and_both_attempts_are_logged(monkeypatch):
    """AC: BSA-AC-1266"""
    sleeps, calls = [], []

    def transport(url, headers, body):
        calls.append(1)
        return (429, "busy", {"Retry-After": "1"}) if len(calls) == 1 else _ok("second")

    c = _client(monkeypatch, transport)
    monkeypatch.setattr(llm_mod, "SLEEP", lambda s: sleeps.append(s))
    assert c.complete("s", "u") == "second"
    assert [(e["outcome"], e["reason"]) for e in c.attempt_log] == [("retried", "429_retry_after"), ("ok", "completed")]
    st = c.retry_stats()
    assert st["attempts"] == 2 and st["retried"] == 1 and st["retry_rate"] == 0.5 and st["by_reason"] == {"429_retry_after": 1}
    assert sleeps == [1.0]                                     # the provider's own Retry-After was honoured (C15)


def test_a_day_limit_429_fails_once_without_a_second_call(monkeypatch):
    """AC: BSA-AC-1266"""
    calls = []

    def transport(url, headers, body):
        calls.append(1)
        return 429, '{"error": "daily request limit exceeded"}'

    c = _client(monkeypatch, transport)
    try:
        c.complete("s", "u")
        raise AssertionError("should have raised LLMUnavailable")
    except llm_mod.LLMUnavailable:
        pass
    assert len(calls) == 1 and [(e["outcome"], e["reason"]) for e in c.attempt_log] == [("failed", "429_day_limit")]


def test_a_transient_5xx_is_retried_a_permanent_4xx_is_not(monkeypatch):
    """AC: BSA-AC-1266"""
    seq = [(503, "overloaded"), _ok("recovered")]
    c = _client(monkeypatch, lambda u, h, b: seq.pop(0))
    assert c.complete("s", "u") == "recovered"
    assert [(e["outcome"], e["reason"]) for e in c.attempt_log] == [("retried", "5xx_transient"), ("ok", "completed")]
    seq2 = [(400, "bad request")]
    c2 = _client(monkeypatch, lambda u, h, b: seq2.pop(0))
    try:
        c2.complete("s", "u")
        raise AssertionError("should have raised LLMError")
    except llm_mod.LLMError:
        pass
    assert [(e["outcome"], e["reason"]) for e in c2.attempt_log] == [("failed", "http_400")]   # 4xx: 0 retries (D1 §19)


def test_a_network_loss_is_recorded_then_raised_and_the_log_is_bounded(monkeypatch):
    """AC: BSA-AC-1266"""
    def boom(url, headers, body):
        raise OSError("connection reset")

    c = _client(monkeypatch, boom)
    try:
        c.complete("s", "u")
        raise AssertionError("should have raised")
    except OSError:                                             # the TRANSPORT hook bypasses _post's LLMUnavailable wrap; in production it is wrapped there
        pass
    assert [(e["outcome"], e["reason"]) for e in c.attempt_log] == [("failed", "network_lost")]
    c.attempt_log = [{"outcome": "ok", "reason": "completed"} for _ in range(250)]
    c._log_attempt(0, "ok", 200, "completed")
    assert len(c.attempt_log) == c._ATTEMPT_CAP                # the ledger is a bounded health signal, not a journal
    empty = llm_mod.ChatClient("k").retry_stats()
    assert empty["attempts"] == 0 and empty["retry_rate"] is None and empty["completions"] == 0   # honest zero shape


# ------------------------------------------------------------------ the surfaces: describe() + the turn's degraded flag
def test_describe_carries_the_retry_health_and_the_turn_carries_the_degraded_flag():
    """AC: BSA-AC-1266"""
    assert "retry" in llm_mod.ChatClient("k").describe()
    assert "degraded" in inspect.getsource(server_mod._annotate_budget_note)
    res = {"llm_note": "EXAONE unavailable -> extractive answer: boom"}
    server_mod._annotate_budget_note(res, llm_mod.ChatClient("k", daily_budget=10))
    assert res["degraded"] is True                              # a turn with a caveat is a degraded turn, by rule
    clean = {"llm_note": ""}
    server_mod._annotate_budget_note(clean, llm_mod.ChatClient("k", daily_budget=10))
    assert clean["degraded"] is False and clean.get("llm_note") == ""    # a clean turn stays clean, no note is invented
    budget = {"llm_note": ""}
    server_mod._annotate_budget_note(budget, type("C", (), {"budget_tier": lambda s: "warn", "calls_today": lambda s: 1, "daily_budget": 2})())
    assert budget["degraded"] is True and "warn" in budget["llm_note"]   # the budget tier also forces the flag
    stream_src = open("bts_sbom_app/chat_stream.py", encoding="utf-8").read()
    assert 'degraded=bool(res.get("degraded"))' in stream_src   # the SSE final event carries the flag
    panel_src = open("bts_sbom_app/web/bts_chat_panel.js", encoding="utf-8").read()
    assert "bts-chat-degraded" in panel_src and "fin.llm_note" in panel_src   # the dock badges the degradation, esc()'d
