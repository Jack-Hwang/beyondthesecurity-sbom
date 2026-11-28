"""ops-server bundle: LLM budget tiers/ledger/Retry-After/truncation (llm.py) and chat concurrency/rate/length
limits (server.py). No network: TRANSPORT is a deterministic stub throughout."""
from __future__ import annotations

import json
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import access, llm, server
from bts_sbom_app.util import read_json, write_json


# ---------------------------------------------------------------------------------------------------------
# shared HTTP harness (same shape as test_access_gate.py's _serve/_call; kept local so this file stands alone)
# ---------------------------------------------------------------------------------------------------------

def _serve(tmp_path, monkeypatch, **env):
    monkeypatch.delenv(access.ENV, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    # root is its own tmp_path subdirectory (never the real checkout's evals.repo_root()): ChatClient.from_env's
    # ledger path is root-scoped, not evidence-scoped, so a shared real root would read/write the live repo's
    # actual evidence/.llm_ledger.json across test runs - exactly the file-level isolation these tests must not break.
    st = server.State(str(tmp_path / "root"), str(tmp_path / "evidence"), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    return st, httpd, "http://127.0.0.1:%d" % httpd.server_address[1]


def _call(url, body=None, headers=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None,
                                 headers=dict({"Content-Type": "application/json"}, **(headers or {})))
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8"), dict(e.headers)


ESCALATE_Q = "담당자와 이야기하고 싶어요"   # routed deterministically (escmod) - no LLM call, same query test_access_gate.py uses


def _mk_transport(seq):
    """A TRANSPORT stub that returns the next entry of ``seq`` (status, text, headers) on each call."""
    state = {"n": 0}

    def transport(url, headers, body):
        i = state["n"]
        state["n"] += 1
        return seq[i]
    return transport


# ---------------------------------------------------------------------------------------------------------
# C33 - budget tiers
# ---------------------------------------------------------------------------------------------------------

def test_budget_tier_reports_ok_warn_critical_and_exhausted_at_measured_thresholds(tmp_path):
    """AC: BSA-AC-1140"""
    ledger = str(tmp_path / "ledger.json")
    c = llm.ChatClient(api_key="k", base_url="http://x.invalid", model="gpt-4o", ledger=ledger, daily_budget=10)
    today = c._today()
    got = {}
    for calls in (0, 4, 5, 7, 8, 9, 10, 11):
        write_json(ledger, {today: calls})
        got[calls] = c.budget_tier()
    assert got == {0: "ok", 4: "ok", 5: "warn", 7: "warn", 8: "critical", 9: "critical", 10: "exhausted", 11: "exhausted"}
    d = c.describe()
    assert d["budget_tier"] == "exhausted" and d["degraded"] is True and d["remaining_calls_today"] == 0
    state = c.budget_state()
    assert state["tier"] == "exhausted" and state["degraded"] is True and state["calls_today"] == 11


def test_chat_llm_note_carries_the_degraded_budget_tier_on_both_chat_endpoints(tmp_path, monkeypatch):
    """AC: BSA-AC-1141"""
    st, httpd, base = _serve(tmp_path, monkeypatch, BTS_SBOM_LLM_DAILY_BUDGET="2")
    try:
        # ok tier: the plain response is untouched
        code, body, _ = _call(base + "/api/chat", {"question": ESCALATE_Q})
        assert code == 200
        note_ok = json.loads(body)["llm_note"]
        assert "LLM daily budget" not in note_ok

        # force the ledger to exhausted (5 calls today against a budget of 2)
        write_json(st.client.ledger, {st.client._today(): 5})

        code, body, _ = _call(base + "/api/chat", {"question": ESCALATE_Q})
        assert code == 200
        res = json.loads(body)
        assert "LLM daily budget exhausted" in res["llm_note"] and "5/2 calls today" in res["llm_note"]

        code, body, _ = _call(base + "/api/chat/stream", {"question": ESCALATE_Q})
        assert code == 200 and "event: final" in body
        assert any("LLM daily budget exhausted" in ln for ln in body.splitlines())
    finally:
        httpd.shutdown()


# ---------------------------------------------------------------------------------------------------------
# C48 - token/cost ledger
# ---------------------------------------------------------------------------------------------------------

def test_ledger_adds_token_counters_and_cost_null_for_unpriced_model_old_ledger_still_parses(tmp_path):
    """AC: BSA-AC-1142"""
    ledger = str(tmp_path / "ledger.json")
    today = time.strftime("%Y-%m-%d", time.gmtime())
    write_json(ledger, {today: 5})                     # pre-C48 ledger shape: a bare int call count
    c = llm.ChatClient(api_key="k", base_url="http://x.invalid", model="gpt-4o", ledger=ledger, daily_budget=100)
    assert c.calls_today() == 5                         # the old int is read as today's call count (format never broken)
    c._record_usage(1000, 500)
    day = read_json(ledger, {})[today]
    assert day["calls"] == 5 and day["prompt_tokens"] == 1000 and day["completion_tokens"] == 500
    assert day["cost_usd"] == round(1000 / 1000.0 * 0.0025 + 500 / 1000.0 * 0.0100, 6) == 0.0075

    ledger2 = str(tmp_path / "ledger2.json")
    c2 = llm.ChatClient(api_key="k", base_url="http://x.invalid", model="k-exaone_v2.5", ledger=ledger2, daily_budget=100)
    c2._record_usage(200, 100)
    day2 = read_json(ledger2, {})[c2._today()]
    assert day2["prompt_tokens"] == 200 and day2["completion_tokens"] == 100 and day2["cost_usd"] is None
    assert llm.estimated_cost_usd(200, 100, "k-exaone_v2.5") is None
    assert llm.estimated_cost_usd(1000, 500, "gpt-4o") == 0.0075
    assert llm.estimated_cost_usd(1000, 500, "gpt-4o-2024-08-06") == 0.0075   # a dated deployment name still prices

    # mixed-model day (bug found + fixed in this bundle): reconnecting later the same day to an unpriced model
    # (State.set_llm builds a brand NEW ChatClient pointed at the same on-disk ledger) must not discard the real
    # dollar figure the priced model above already accumulated today - mirrors _bump()'s own setdefault guard on
    # this same field; _record_usage used to unconditionally overwrite cost_usd with None here.
    c3 = llm.ChatClient(api_key="k", base_url="http://x.invalid", model="k-exaone_v2.5", ledger=ledger, daily_budget=100)
    c3._record_usage(10, 5)
    day_mixed = read_json(ledger, {})[today]
    assert day_mixed["cost_usd"] == 0.0075                         # preserved, not nulled, by the unpriced follow-up call
    assert day_mixed["prompt_tokens"] == 1010 and day_mixed["completion_tokens"] == 505


# ---------------------------------------------------------------------------------------------------------
# C15 - Retry-After
# ---------------------------------------------------------------------------------------------------------

def test_retry_after_header_is_honoured_capped_at_30s_fallback_to_the_fixed_wait(monkeypatch):
    """AC: BSA-AC-1143"""
    ok_body = json.dumps({"choices": [{"message": {"content": "hi"}, "finish_reason": "stop"}],
                          "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    cases = [
        ({"Retry-After": "7"}, 7.0),              # present -> honoured exactly
        ({"Retry-After": "999"}, 30.0),           # capped at 30s
        ({}, 3.0),                                 # absent -> fixed wait
        ({"Retry-After": "not-a-number"}, 3.0),   # unparseable -> fixed wait
    ]
    for headers, want_sleep in cases:
        sleeps = []
        monkeypatch.setattr(llm, "SLEEP", lambda s, sleeps=sleeps: sleeps.append(s))
        llm.TRANSPORT = _mk_transport([(429, "slow down", headers), (200, ok_body, {})])
        try:
            c = llm.ChatClient(api_key="k", base_url="http://x.invalid", model="gpt-4o", daily_budget=1000)
            out = c.complete("s", "u")
            assert out == "hi" and sleeps == [want_sleep], (headers, sleeps)
        finally:
            llm.TRANSPORT = None


# ---------------------------------------------------------------------------------------------------------
# C41 - truncated completion
# ---------------------------------------------------------------------------------------------------------

def test_finish_reason_length_raises_llmtruncated_through_the_existing_llmerror_path():
    """AC: BSA-AC-1144"""
    body = json.dumps({"choices": [{"message": {"content": "cut off..."}, "finish_reason": "length"}],
                       "usage": {"prompt_tokens": 12, "completion_tokens": 2048}})
    llm.TRANSPORT = lambda url, headers, b: (200, body, {})
    try:
        c = llm.ChatClient(api_key="k", base_url="http://x.invalid", model="gpt-4o", daily_budget=1000)
        with pytest.raises(llm.LLMTruncated) as ei:
            c.complete("s", "u", max_tokens=2048)
        assert isinstance(ei.value, llm.LLMError)                     # every existing caller catches LLMError broadly
        assert "truncated by token budget" in str(ei.value)
        assert c.usage == {"prompt_tokens": 12, "completion_tokens": 2048}   # tokens recorded even though truncated
    finally:
        llm.TRANSPORT = None


# ---------------------------------------------------------------------------------------------------------
# C10 - concurrency cap + per-caller rate limit
# ---------------------------------------------------------------------------------------------------------

def test_global_concurrency_cap_refuses_with_429_retry_after_and_recovers_after_release(tmp_path, monkeypatch):
    """AC: BSA-AC-1145"""
    st, httpd, base = _serve(tmp_path, monkeypatch, BTS_SBOM_CHAT_MAX_CONCURRENCY="1", BTS_SBOM_CHAT_RATE_LIMIT="1000")
    calls = {"n": 0}
    orig_bot = st.bot

    def counting_bot(*args, **kwargs):                 # the handler now passes trace_id= (C25) - accept and forward
        calls["n"] += 1
        return orig_bot(*args, **kwargs)
    monkeypatch.setattr(st, "bot", counting_bot)
    try:
        assert st.chat_sem.acquire(blocking=False) is True          # simulate one chat turn already in flight
        code, body, hdr = _call(base + "/api/chat", {"question": ESCALATE_Q})
        assert code == 429 and "Retry-After" in hdr
        assert calls["n"] == 0 and st.client.calls_today() == 0      # the refusal never touched the chatbot or the LLM ledger

        st.chat_sem.release()                                       # the in-flight turn finished
        code, body, hdr = _call(base + "/api/chat", {"question": ESCALATE_Q})
        assert code == 200 and json.loads(body)["answer_source"] == "escalation" and calls["n"] == 1
    finally:
        httpd.shutdown()


def test_per_caller_rate_limit_refuses_only_the_caller_over_limit(tmp_path, monkeypatch):
    """AC: BSA-AC-1146"""
    st, httpd, base = _serve(tmp_path, monkeypatch, BTS_SBOM_CHAT_RATE_LIMIT="1", BTS_SBOM_TRUST_FORWARDED="1",
                              BTS_SBOM_CHAT_RATE_WINDOW_SECONDS="60", BTS_SBOM_CHAT_MAX_CONCURRENCY="1000")
    try:
        caller_a = {"X-Forwarded-For": "203.0.113.5"}      # the TCP peer is loopback (the test harness), so the
        caller_b = {"X-Forwarded-For": "203.0.113.9"}      # last X-Forwarded-For entry is trusted as the caller id (C10)

        code1, body1, _ = _call(base + "/api/chat", {"question": ESCALATE_Q}, caller_a)
        assert code1 == 200 and json.loads(body1)["answer_source"] == "escalation"

        code2, body2, hdr2 = _call(base + "/api/chat", {"question": ESCALATE_Q}, caller_a)   # caller_a's 2nd call this window
        assert code2 == 429 and "Retry-After" in hdr2 and int(hdr2["Retry-After"]) >= 1
        assert st.client.calls_today() == 0                 # the refusal never spent the daily LLM budget

        code3, body3, _ = _call(base + "/api/chat", {"question": ESCALATE_Q}, caller_b)      # a different caller: unaffected
        assert code3 == 200 and json.loads(body3)["answer_source"] == "escalation"
    finally:
        httpd.shutdown()


class _FakeHandler:
    def __init__(self, ip, headers):
        self.client_address = (ip, 12345)
        self.headers = headers


def test_caller_id_trusts_the_last_x_forwarded_for_entry_only_behind_a_private_or_loopback_peer(monkeypatch):
    """AC: BSA-AC-1147"""
    monkeypatch.setenv("BTS_SBOM_TRUST_FORWARDED", "1")                  # the operator declares a trusted proxy in front (Container Apps template)
    # 8.8.8.8/1.1.1.1/9.9.9.9 are real, globally-routable addresses (ipaddress.is_private is False for them);
    # 10.x/127.x are RFC1918/loopback (is_private is True) - picked deliberately so this test cannot pass by
    # accident on Python's broader "not globally reachable" private ranges (which also covers RFC5737 TEST-NETs).
    behind_proxy = _FakeHandler("127.0.0.1", {"X-Forwarded-For": "8.8.8.8, 10.0.0.4"})
    assert server._caller_id(behind_proxy) == "10.0.0.4"            # last entry: the hop the trusted proxy itself appended
    behind_proxy_private_peer = _FakeHandler("10.1.2.3", {"X-Forwarded-For": "9.9.9.9"})
    assert server._caller_id(behind_proxy_private_peer) == "9.9.9.9"
    direct = _FakeHandler("8.8.8.8", {"X-Forwarded-For": "9.9.9.9"})
    assert server._caller_id(direct) == "8.8.8.8"                   # no proxy in front: the header is attacker-controlled, ignored
    direct_no_header = _FakeHandler("1.1.1.1", {})
    assert server._caller_id(direct_no_header) == "1.1.1.1"


# ---------------------------------------------------------------------------------------------------------
# C72 - question length bound
# ---------------------------------------------------------------------------------------------------------

def test_question_over_max_chars_is_400_exactly_the_cap_is_accepted(tmp_path, monkeypatch):
    """AC: BSA-AC-1148"""
    st, httpd, base = _serve(tmp_path, monkeypatch)
    try:
        assert server.MAX_QUESTION_CHARS == 4000
        too_long = "a" * (server.MAX_QUESTION_CHARS + 1)
        exactly = "a" * server.MAX_QUESTION_CHARS
        for path in ("/api/chat", "/api/chat/stream"):
            code, body, _ = _call(base + path, {"question": too_long})
            assert code == 400 and "question too long" in body, (path, code, body)
            code, body, _ = _call(base + path, {"question": exactly})
            assert code == 200, (path, code, body)
    finally:
        httpd.shutdown()


# ---------------------------------------------------------------------------------------------------------
# C10 follow-up - State._chat_hits must not grow without bound (bug found + fixed in this bundle)
# ---------------------------------------------------------------------------------------------------------

def test_prune_chat_hits_drops_already_expired_entries_before_touching_fresh_ones():
    """AC: BSA-AC-1149"""
    hits = {"expired_a": [0.0], "expired_b": [1.0], "fresh_c": [100.0], "fresh_d": [99.9]}
    dropped = server._prune_chat_hits(hits, now=100.0, window=10.0, keep=2)
    assert dropped == 2
    assert set(hits) == {"fresh_c", "fresh_d"}      # the two still-live callers were never touched


def test_prune_chat_hits_falls_back_to_oldest_inserted_when_nothing_has_expired():
    """AC: BSA-AC-1149"""
    hits = {"a": [100.0], "b": [100.0], "c": [100.0]}   # none expired: now == every hit's own timestamp
    dropped = server._prune_chat_hits(hits, now=100.0, window=60.0, keep=1)
    assert dropped == 2
    assert set(hits) == {"c"}                            # the oldest-inserted ("a", then "b") are dropped first


def test_chat_rate_check_bounds_chat_hits_across_many_distinct_one_off_callers(tmp_path, monkeypatch):
    """AC: BSA-AC-1149"""
    st, httpd, base = _serve(tmp_path, monkeypatch)
    httpd.shutdown()                                       # only the State object is needed below
    monkeypatch.setattr(server, "MAX_CHAT_RATE_CALLERS", 10)
    # reproduces the confirmed leak scenario directly: many distinct caller identities (e.g. distinct public
    # client IPs reaching the deployed /api/chat over the life of the process), each calling chat_rate_check
    # once; before the fix len(st._chat_hits) grew to 500 and stayed there forever, even once every entry's
    # history was long out of the sliding window.
    for i in range(500):
        allowed, retry_after = st.chat_rate_check("caller-%d" % i)
        assert allowed is True and retry_after == 0.0
    assert len(st._chat_hits) <= server.MAX_CHAT_RATE_CALLERS
