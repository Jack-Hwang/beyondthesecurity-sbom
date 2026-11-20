"""Circuit breaker + the four-shape "no answer" outcome (course package A, lecture 3-1 p.25,30 / 3-2 p.44).

All fakes here are offline: ``net.TRANSPORT`` stands in for the real network exactly as the rest of the
suite uses it, and the real-urllib retry/backoff path is exercised by monkeypatching ``urllib.request.urlopen``
directly (still 0 real network calls) so the Retry-After/backoff logic itself gets covered, not just the
test-hook shortcut.
"""
from __future__ import annotations

import email.message
import threading
import urllib.error
import urllib.request
from typing import Any, Dict, List

import pytest

from bts_sbom_app import net, resilience

HOST_A = "https://a.example.invalid/path"
HOST_B = "https://b.example.invalid/path"


class ScriptedTransport:
    """net.TRANSPORT fake: one scripted (status, parsed) response per registered host substring."""

    def __init__(self) -> None:
        self.calls: List[str] = []
        self._map: Dict[str, Any] = {}

    def set(self, url_substr: str, value: Any) -> None:
        self._map[url_substr] = value

    def __call__(self, url: str, headers: Dict[str, str], body: Any):
        self.calls.append(url)
        for k, v in self._map.items():
            if k in url:
                return v
        raise AssertionError("no script registered for %s" % url)


class FakeClock:
    def __init__(self, start: float = 1000.0) -> None:
        self.t = start

    def __call__(self) -> float:
        return self.t

    def advance(self, secs: float) -> None:
        self.t += secs


class _FakeResp:
    def __init__(self, data: bytes, status: int = 200) -> None:
        self._data = data
        self.status = status

    def read(self, n: Any = None) -> bytes:
        return self._data if n is None else self._data[:n]

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *exc: Any) -> bool:
        return False


def _http_error(url: str, code: int, retry_after: Any = None) -> urllib.error.HTTPError:
    hdrs = email.message.Message()
    if retry_after is not None:
        hdrs["Retry-After"] = str(retry_after)
    return urllib.error.HTTPError(url, code, "scripted error", hdrs, None)


@pytest.fixture
def clock(monkeypatch) -> FakeClock:
    c = FakeClock()
    monkeypatch.setattr(resilience, "CLOCK", c)
    net.reset_breakers()
    return c


@pytest.fixture
def no_sleep(monkeypatch) -> List[float]:
    sleeps: List[float] = []
    monkeypatch.setattr(net, "SLEEP", lambda s: sleeps.append(s))
    return sleeps


def test_three_consecutive_failures_open_the_breaker(monkeypatch):
    """AC: BSA-AC-301"""
    t = ScriptedTransport()
    t.set("a.example.invalid", (503, None))
    monkeypatch.setattr(net, "TRANSPORT", t)
    for _ in range(3):
        net.fetch_json(HOST_A)
    snap = resilience.get_breaker("a.example.invalid").snapshot()
    assert snap["state"] == resilience.OPEN and snap["opens"] == 1


def test_open_breaker_short_circuits_five_calls_with_zero_transport_attempts(monkeypatch):
    """AC: BSA-AC-302"""
    t = ScriptedTransport()
    t.set("a.example.invalid", (503, None))
    monkeypatch.setattr(net, "TRANSPORT", t)
    for _ in range(3):
        net.fetch_json(HOST_A)
    assert resilience.get_breaker("a.example.invalid").snapshot()["state"] == resilience.OPEN
    before = len(t.calls)
    net.reset_stats()
    outcomes = [net.fetch_json(HOST_A) for _ in range(5)]
    assert len(t.calls) == before                                       # 0 new transport attempts while open
    assert all(o.state == resilience.ACCESS_FAILURE and o.reason == "circuit_open" and o.attempts == 0 for o in outcomes)
    assert net.STATS["short_circuited"] == 5


def test_half_open_lets_exactly_one_of_four_concurrent_probes_through(clock):
    """AC: BSA-AC-303"""
    b = resilience.CircuitBreaker(failure_threshold=3, open_seconds=60.0, clock=clock)
    for _ in range(3):
        b.on_failure()
    assert b.snapshot()["state"] == resilience.OPEN
    clock.advance(61.0)
    results: List[bool] = []
    lock = threading.Lock()

    def worker() -> None:
        ok = b.allow()
        with lock:
            results.append(ok)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    assert sum(results) == 1 and len(results) == 4
    assert b.snapshot()["state"] == resilience.HALF_OPEN


def test_probe_success_closes_probe_failure_reopens_with_new_cooldown(clock):
    """AC: BSA-AC-304"""
    b = resilience.CircuitBreaker(failure_threshold=3, open_seconds=60.0, clock=clock)
    for _ in range(3):
        b.on_failure()
    clock.advance(61.0)
    assert b.allow() is True
    b.on_success()
    snap = b.snapshot()
    assert snap["state"] == resilience.CLOSED and snap["consecutive_failures"] == 0

    for _ in range(3):
        b.on_failure()
    first_opened_at = b.snapshot()["opened_at"]
    clock.advance(61.0)
    assert b.allow() is True                                            # the probe
    clock.advance(5.0)
    b.on_failure()                                                      # probe fails
    snap2 = b.snapshot()
    assert snap2["state"] == resilience.OPEN and snap2["opened_at"] != first_opened_at and snap2["opens"] == 3


def test_two_hosts_are_isolated(monkeypatch):
    """AC: BSA-AC-305"""
    t = ScriptedTransport()
    t.set("a.example.invalid", (503, None))
    t.set("b.example.invalid", (200, {"ok": True}))
    monkeypatch.setattr(net, "TRANSPORT", t)
    for _ in range(3):
        net.fetch_json(HOST_A)
    assert resilience.get_breaker("a.example.invalid").snapshot()["state"] == resilience.OPEN
    oc = net.fetch_json(HOST_B)
    assert oc.state == resilience.SUCCESS
    assert resilience.get_breaker("b.example.invalid").snapshot()["state"] == resilience.CLOSED


def test_404_is_empty_result_neutral_to_breaker_and_stats(monkeypatch):
    """AC: BSA-AC-306"""
    t = ScriptedTransport()
    t.set("a.example.invalid", (404, None))
    monkeypatch.setattr(net, "TRANSPORT", t)
    net.reset_stats()
    for _ in range(5):
        oc = net.fetch_json(HOST_A)
        assert oc.state == resilience.EMPTY_RESULT and oc.data is None and oc.status == 404
    assert net.STATS["failures"] == 0 and net.STATS["empty"] == 5
    snap = resilience.get_breaker("a.example.invalid").snapshot()
    assert snap["state"] == resilience.CLOSED and snap["consecutive_failures"] == 0
    assert net.http_json(HOST_A) is None                                 # unchanged contract


def test_truncated_body_is_partial_result_and_http_text_still_returns_it(monkeypatch):
    """AC: BSA-AC-307"""
    t = ScriptedTransport()
    body = "x" * 50
    t.set("a.example.invalid", (200, body))
    monkeypatch.setattr(net, "TRANSPORT", t)
    oc = net.fetch_text(HOST_A, limit=50)
    assert oc.state == resilience.PARTIAL_RESULT and oc.data == body
    assert net.STATS["partial"] == 1
    assert net.http_text(HOST_A, limit=50) == body                       # old contract: truncated text, not None
    t.set("a.example.invalid", (200, "short"))
    oc2 = net.fetch_text(HOST_A, limit=50)
    assert oc2.state == resilience.SUCCESS


def test_retry_after_seven_sleeps_seven_and_caps_at_thirty(no_sleep, monkeypatch):
    """AC: BSA-AC-308"""
    monkeypatch.setattr(net, "TRANSPORT", None)                          # exercise the real-urllib retry path
    calls = {"n": 0}

    def fake_urlopen(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_error(req.full_url, 503, retry_after=7)
        return _FakeResp(b'{"ok": true}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    oc = net.fetch_json("https://real1.example.invalid/x", retries=2)
    assert oc.state == resilience.SUCCESS and no_sleep == [7.0]

    no_sleep.clear()
    calls["n"] = 0

    def fake_urlopen_big(req, timeout=None):
        calls["n"] += 1
        if calls["n"] == 1:
            raise _http_error(req.full_url, 503, retry_after=99)
        return _FakeResp(b'{"ok": true}')

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen_big)
    oc2 = net.fetch_json("https://real2.example.invalid/x", retries=2)
    assert oc2.state == resilience.SUCCESS and no_sleep == [30.0]


def test_http_json_contract_unchanged_across_four_response_shapes(monkeypatch):
    """AC: BSA-AC-309"""
    t = ScriptedTransport()
    monkeypatch.setattr(net, "TRANSPORT", t)
    t.set("ok.example", (200, {"x": 1}))
    assert net.http_json("https://ok.example/a") == {"x": 1}
    t.set("missing.example", (404, None))
    assert net.http_json("https://missing.example/a") is None
    t.set("broken.example", (500, None))
    assert net.http_json("https://broken.example/a") is None
    t.set("forbidden.example", (403, None))
    assert net.http_json("https://forbidden.example/a") is None


def test_non_retryable_4xx_stops_after_one_attempt_retryable_status_retries(no_sleep, monkeypatch):
    """AC: BSA-AC-310"""
    monkeypatch.setattr(net, "TRANSPORT", None)
    calls = {"n": 0}

    def fake_urlopen_403(req, timeout=None):
        calls["n"] += 1
        raise _http_error(req.full_url, 403)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen_403)
    oc = net.fetch_json("https://host403.example.invalid/a", retries=2)
    assert oc.state == resilience.ACCESS_FAILURE and calls["n"] == 1 and oc.attempts == 1

    calls["n"] = 0

    def fake_urlopen_503(req, timeout=None):
        calls["n"] += 1
        raise _http_error(req.full_url, 503)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen_503)
    oc2 = net.fetch_json("https://host503.example.invalid/a", retries=2)
    assert oc2.state == resilience.ACCESS_FAILURE and calls["n"] == 3 and oc2.attempts == 3


def test_breaker_threshold_zero_disables_it(monkeypatch):
    """AC: BSA-AC-311"""
    monkeypatch.setenv("BTS_SBOM_BREAKER_THRESHOLD", "0")
    net.reset_breakers()
    t = ScriptedTransport()
    t.set("disabled.example", (503, None))
    monkeypatch.setattr(net, "TRANSPORT", t)
    for _ in range(10):
        oc = net.fetch_json("https://disabled.example/a")
        assert oc.state == resilience.ACCESS_FAILURE
    b = resilience.get_breaker("disabled.example")
    assert b.enabled is False and b.snapshot()["state"] == resilience.CLOSED
    assert len(t.calls) == 10


def test_stats_short_circuited_empty_partial_and_reset(monkeypatch):
    """AC: BSA-AC-312"""
    net.reset_stats()
    t = ScriptedTransport()
    monkeypatch.setattr(net, "TRANSPORT", t)
    t.set("statshost1", (404, None))
    net.fetch_json("https://statshost1.example/a")
    t.set("statshost2", (200, "y" * 10))
    net.fetch_text("https://statshost2.example/a", limit=10)
    t.set("statshost3", (503, None))
    for _ in range(3):
        net.fetch_json("https://statshost3.example/a")
    oc = net.fetch_json("https://statshost3.example/a")                  # breaker now open -> short-circuited
    assert oc.reason == "circuit_open"
    assert net.STATS["empty"] == 1 and net.STATS["partial"] == 1 and net.STATS["short_circuited"] == 1
    net.reset_stats()
    assert net.STATS == {"requests": 0, "failures": 0, "last_error": "", "short_circuited": 0, "empty": 0, "partial": 0}


def test_reset_breakers_restores_fresh_closed_state(monkeypatch):
    """AC: BSA-AC-313"""
    t = ScriptedTransport()
    t.set("resetme", (503, None))
    monkeypatch.setattr(net, "TRANSPORT", t)
    for _ in range(3):
        net.fetch_json("https://resetme.example/a")
    assert resilience.get_breaker("resetme.example").snapshot()["state"] == resilience.OPEN
    net.reset_breakers()
    snap = resilience.get_breaker("resetme.example").snapshot()
    assert snap["state"] == resilience.CLOSED and snap["consecutive_failures"] == 0 and snap["opens"] == 0


def test_concurrent_failing_calls_open_breaker_exactly_once(monkeypatch):
    """AC: BSA-AC-314"""
    t = ScriptedTransport()
    t.set("race.example", (503, None))
    monkeypatch.setattr(net, "TRANSPORT", t)

    def worker() -> None:
        net.fetch_json("https://race.example/a")

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for th in threads:
        th.start()
    for th in threads:
        th.join()
    snap = resilience.get_breaker("race.example").snapshot()
    assert snap["state"] == resilience.OPEN and snap["opens"] == 1


def test_breaker_counts_one_failure_per_call_not_per_retry(no_sleep, monkeypatch):
    """AC: BSA-AC-315"""
    monkeypatch.setattr(net, "TRANSPORT", None)

    def always_503(req, timeout=None):
        raise _http_error(req.full_url, 503)

    monkeypatch.setattr(urllib.request, "urlopen", always_503)
    net.fetch_json("https://retrycount.example.invalid/a", retries=2)      # 1 call, 3 internal attempts
    snap = resilience.get_breaker("retrycount.example.invalid").snapshot()
    assert snap["consecutive_failures"] == 1 and snap["failures"] == 1
