"""Circuit breaker + the four honest outcomes of net.fetch_json/fetch_text (task 2, AC 301-313)."""
from __future__ import annotations

import threading
import time
import urllib.error


from bts_sbom_app import net, resilience

URL = "https://unit.test.example/api"
URL2 = "https://other.test.example/api"


class _FakeClock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t

    def advance(self, seconds: float) -> None:
        self.t += seconds




def test_three_consecutive_failures_open_the_circuit():
    """AC: BSA-AC-301"""
    calls = []
    net.TRANSPORT = lambda u, h, b: (calls.append(u) or (503, None))
    for _ in range(3):
        o = net.fetch_json(URL, retries=0)
        assert o.state == "access_failure" and o.reason == "http 503"
    brk = resilience.breaker_for(URL)
    assert brk.snapshot()["state"] == "open"


def test_open_circuit_sends_zero_requests_and_reports_circuit_open(world):
    """AC: BSA-AC-302"""
    calls = []
    net.TRANSPORT = lambda u, h, b: (calls.append(u) or (503, None))
    for _ in range(3):
        net.fetch_json(URL, retries=0)
    sent_before = len(calls)
    outcomes = [net.fetch_json(URL, retries=2) for _ in range(5)]
    assert len(calls) == sent_before, "no request may reach an open circuit"
    assert all(o.state == "access_failure" and o.reason == "circuit_open" for o in outcomes)


def test_after_the_cooldown_exactly_one_of_4_concurrent_calls_probes(world):
    """AC: BSA-AC-303"""
    brk, clock = _seed_breaker()
    net.TRANSPORT = lambda u, h, b: (503, None)
    for _ in range(3):
        net.fetch_json(URL, retries=0)
    assert brk.snapshot()["state"] == "open"
    clock.advance(60.0)
    barrier = threading.Barrier(4)
    hook_calls = []

    def probe_hook(url, headers, body):
        hook_calls.append(url)
        for _ in range(200):                    # up to 10s: wait until the other 3 callers were rejected and recorded
            if len(results) >= 3:
                return 200, {"ok": 1}
            time.sleep(0.05)
        raise AssertionError("the 3 rejected callers never finished")

    net.TRANSPORT = probe_hook
    results = []

    def worker():
        barrier.wait(timeout=10)
        results.append(net.fetch_json(URL, retries=2))

    threads = [threading.Thread(target=worker, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    ok = [r for r in results if r.state == "success"]
    rejected = [r for r in results if r.reason == "circuit_open"]
    assert len(ok) == 1 and len(rejected) == 3, results
    assert len(hook_calls) == 1


def test_probe_success_closes_the_circuit_and_the_next_calls_go_out(world):
    """AC: BSA-AC-304"""
    _seed_breaker()
    seq = [(503, None), (503, None), (503, None), (200, {"ok": 1})]
    calls = []

    def hook(url, headers, body):
        calls.append(url)
        i = len(calls) - 1
        return seq[i] if i < len(seq) else (200, {"ok": 1})

    net.TRANSPORT = hook
    for _ in range(3):
        net.fetch_json(URL, retries=0)
    clock = resilience.breaker_for(URL)
    assert clock.snapshot()["state"] == "open"
    _advance_breaker(URL, 60.0)
    o = net.fetch_json(URL, retries=0)
    assert o.state == "success"
    assert resilience.breaker_for(URL).snapshot()["state"] == "closed"
    before = len(calls)
    for _ in range(3):
        assert net.fetch_json(URL, retries=0).state == "success"
    assert len(calls) == before + 3


def test_probe_failure_reopens_for_a_fresh_cooldown(world):
    """AC: BSA-AC-305"""
    _seed_breaker()
    calls = []
    net.TRANSPORT = lambda u, h, b: (calls.append(u) or (503, None))
    for _ in range(3):
        net.fetch_json(URL, retries=0)
    _advance_breaker(URL, 60.0)
    o = net.fetch_json(URL, retries=0)                       # the one probe fails again
    assert o.state == "access_failure" and o.reason == "http 503"
    assert len(calls) == 4
    assert resilience.breaker_for(URL).snapshot()["state"] == "open"
    sent = len(calls)
    for _ in range(5):
        assert net.fetch_json(URL, retries=2).reason == "circuit_open"
    assert len(calls) == sent, "a fresh cooldown must send 0 requests"


def _seed_breaker() -> tuple:
    """Register a breaker for URL with a test-controlled clock (fetch_json reuses the registered one)."""
    clock = _FakeClock()
    brk = resilience.breaker_for(URL, clock=clock)
    return brk, clock


def _advance_breaker(url, seconds: float) -> None:
    """Advance the fake clock of the registered breaker (tests control the cooldown without sleeping)."""
    brk = resilience.breaker_for(url)
    brk._clock.advance(seconds)


def test_hosts_are_isolated(world):
    """AC: BSA-AC-306"""
    net.TRANSPORT = lambda u, h, b: ((503, None) if "unit.test.example" in u else (200, {"ok": 1}))
    for _ in range(3):
        net.fetch_json(URL, retries=0)
    assert resilience.breaker_for(URL).snapshot()["state"] == "open"
    assert resilience.breaker_for(URL2).snapshot()["state"] == "closed"
    assert net.fetch_json(URL2, retries=0).state == "success"


def test_404_is_empty_result_and_neutral_for_the_breaker():
    """AC: BSA-AC-307"""
    net.TRANSPORT = lambda u, h, b: (404, None)
    net.reset_stats()
    brk = resilience.breaker_for(URL)
    o = net.fetch_json(URL, retries=2)
    assert o.state == "empty_result" and o.status == 404
    assert net.STATS["failures"] == 0
    assert net.STATS["empty"] == 1
    assert brk.snapshot()["consecutive_failures"] == 0


def test_truncated_text_is_a_partial_result_and_still_returned(monkeypatch):
    """AC: BSA-AC-308"""
    monkeypatch.setattr(net, "TRANSPORT", None)

    class _Resp:
        status = 200

        def __init__(self, payload: bytes) -> None:
            self._payload = payload

        def read(self, n: int) -> bytes:
            return self._payload[:n]

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(b"0123456789AB"))
    net.reset_stats()
    o = net.fetch_text(URL, limit=10)
    assert o.state == "partial_result" and o.data == "0123456789" and o.reason.startswith("truncated")
    assert net.STATS["partial"] == 1
    # a body inside the limit is a plain success
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(b"short"))
    o2 = net.fetch_text(URL, limit=10)
    assert o2.state == "success" and o2.data == "short"


def test_retry_after_is_honoured_and_capped(world, monkeypatch):
    """AC: BSA-AC-309"""
    waits = []
    monkeypatch.setattr(net, "SLEEP", waits.append)
    seq = [(429, None, {"Retry-After": "7"}), (200, {"ok": 1}, {})]
    idx = {"i": 0}

    def hook(url, headers, body):
        out = seq[min(idx["i"], len(seq) - 1)]
        idx["i"] += 1
        return out

    net.TRANSPORT = hook
    o = net.fetch_json(URL, retries=2)
    assert o.state == "success" and waits == [7.0]
    # 90 seconds is capped at 30
    waits.clear()
    idx["i"] = 0
    seq2 = [(429, None, {"Retry-After": "90"}), (200, {"ok": 1}, {})]

    def hook2(url, headers, body):
        out = seq2[min(idx["i"], len(seq2) - 1)]
        idx["i"] += 1
        return out

    net.TRANSPORT = hook2
    o2 = net.fetch_json(URL, retries=2)
    assert o2.state == "success" and waits == [30.0]


def test_non_retryable_403_makes_one_attempt_and_zero_retries(world):
    """AC: BSA-AC-310"""
    calls = []
    net.TRANSPORT = lambda u, h, b: (calls.append(u) or (403, None))
    o = net.fetch_json(URL, retries=2)
    assert o.state == "access_failure" and o.reason == "http 403"
    assert len(calls) == 1


def test_wrappers_keep_their_old_return_values(world, monkeypatch):
    """AC: BSA-AC-311"""
    monkeypatch.setattr(net, "SLEEP", lambda s: None)
    cases = {
        200: {"ok": 1},
        404: None,
        500: None,
        429: None,
    }

    def hook(url, headers, body):
        status = int(url.rsplit("/", 1)[-1])
        return status, cases[status]

    net.TRANSPORT = hook
    assert net.http_json(URL + "/200") == {"ok": 1}
    assert net.http_json(URL + "/404") is None
    assert net.http_json(URL + "/500") is None
    assert net.http_json(URL + "/429") is None
    text_cases = {200: "hello", 404: None}

    def hook_text(url, headers, body):
        status = int(url.rsplit("/", 1)[-1])
        return status, text_cases[status]

    net.TRANSPORT = hook_text
    assert net.http_text(URL + "/200") == "hello"
    assert net.http_text(URL + "/404") is None


def test_threshold_zero_disables_the_breaker(world, monkeypatch):
    """AC: BSA-AC-312"""
    monkeypatch.setenv("BTS_SBOM_BREAKER_THRESHOLD", "0")
    net.reset_breakers()
    calls = []
    net.TRANSPORT = lambda u, h, b: (calls.append(u) or (503, None))
    for _ in range(10):
        assert net.fetch_json(URL, retries=0).state == "access_failure"
    assert len(calls) == 10, "every call must still be attempted"
    assert resilience.breaker_for(URL) is None
    assert net.STATS["short_circuited"] == 0


def test_short_circuited_calls_are_counted(world):
    """AC: BSA-AC-313"""
    net.reset_stats()
    net.TRANSPORT = lambda u, h, b: (503, None)
    for _ in range(3):
        net.fetch_json(URL, retries=0)
    for _ in range(5):
        net.fetch_json(URL, retries=2)
    assert net.STATS["short_circuited"] == 5
