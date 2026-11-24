"""Fixes from the independent security review of the merged feature set: path containment and a bounded set of event buses."""
from __future__ import annotations

import os

from bts_sbom_app import doclint, events, portfolio, server


def test_portfolio_skips_links_and_files_outside_the_root(tmp_path):
    """AC: BSA-AC-358"""
    root = tmp_path / "repo"
    outside = tmp_path / "outside"
    (root / "bts_sbom_app").mkdir(parents=True)
    outside.mkdir()
    (root / "bts_sbom_app" / "inside.py").write_text("x = 1\n", encoding="utf-8")
    (outside / "secret.txt").write_text("not part of the project\n", encoding="utf-8")
    # form 1: a '..' pattern that reaches a file next to the repository
    assert portfolio._expand(str(root), "../outside/*.txt") == []
    # form 2: a symbolic link inside the repository that points outside (skipped when the platform forbids creating links)
    try:
        os.symlink(str(outside / "secret.txt"), str(root / "bts_sbom_app" / "linked.py"))
    except (OSError, NotImplementedError, AttributeError):
        links_made = False
    else:
        links_made = True
    found = portfolio._expand(str(root), "bts_sbom_app/*.py")
    names = [os.path.basename(p) for p in found]
    assert names == ["inside.py"], names
    if not links_made:
        print("symlink creation not permitted here: only the '..' form was exercised")


def test_enforcement_map_paths_cannot_leave_the_repository(tmp_path):
    """AC: BSA-AC-359"""
    root = tmp_path / "repo"
    root.mkdir()
    (root / "ok.py").write_text("def real_function():\n    return 1\n", encoding="utf-8")
    (tmp_path / "outside_secret.py").write_text("def totally_real_function():\n    return 2\n", encoding="utf-8")
    absolute = str(tmp_path / "outside_secret.py").replace("\\", "/")
    header = "| 위험 | 강제 수단 | 위치 | 검증 테스트 |\n|---|---|---|---|\n"
    parent_row = "| r | m | `../outside_secret.py:totally_real_function` | `ok.py::real_function` |\n"
    absolute_row = "| r | m | `%s:totally_real_function` | `ok.py::real_function` |\n" % absolute
    for row in (parent_row, absolute_row):
        problems = doclint.check_enforcement_table(header + row, repo_root=str(root))
        assert len(problems) >= 1 and any("leaves the repository" in p or "does not exist" in p or "not a file path" in p for p in problems), problems
        assert not doclint._func_defined(str(root), "../outside_secret.py", "totally_real_function")
    ok_row = "| r | m | `ok.py:real_function` | `ok.py::real_function` |\n"
    assert doclint.check_enforcement_table(header + ok_row, repo_root=str(root)) == []


def test_event_buses_are_bounded_and_open_ones_survive():
    """AC: BSA-AC-360"""
    buses = {}
    for i in range(70):
        b = events.EventBus("%010x" % i)
        b.close()
        buses[b.job_id] = b
    open_ids = []
    for i in range(70, 75):
        b = events.EventBus("%010x" % i)           # still running
        buses[b.job_id] = b
        open_ids.append(b.job_id)
    dropped = server._prune_buses(buses, server.MAX_BUSES - 1)
    assert dropped >= 75 - (server.MAX_BUSES - 1)
    assert len(buses) == server.MAX_BUSES - 1
    assert all(j in buses for j in open_ids), "an open bus (running job) was dropped"
    assert "%010x" % 0 not in buses and "%010x" % 69 in buses, "oldest closed buses go first"


def test_failed_license_lookups_are_never_cached_as_misses(tmp_path, monkeypatch):
    """AC: BSA-AC-441"""
    import json

    from bts_sbom_app import licenses, net, resilience

    net.reset_breakers()
    monkeypatch.setattr(net, "TRANSPORT", lambda url, headers, body: (503, None))      # the host is down for every call
    comps = [{"ecosystem": "npm", "name": "pkg%d" % i, "version": "1.0.0", "files": []} for i in range(20)]
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    stats = licenses.resolve(comps, str(tmp_path), online=True, cache_dir=str(cache_dir), workers=1, sources=("deps.dev",))
    assert stats.get("lookup_unavailable") == 20, stats
    cache_file = cache_dir / licenses.CACHE_FILE
    cached = json.loads(cache_file.read_text(encoding="utf-8")) if cache_file.exists() else {}
    assert cached == {}, "an outage was cached as 'no license'"
    assert resilience.snapshot(), "the breaker saw the outage"
    net.reset_breakers()


def test_late_failure_of_a_call_from_before_the_breaker_opened_cannot_reopen_it():
    """AC: BSA-AC-442"""
    from bts_sbom_app import resilience

    now = [0.0]
    b = resilience.CircuitBreaker(failure_threshold=1, open_seconds=10.0, clock=lambda: now[0])
    ok_x, gen_x = b.begin()                    # call X starts while the breaker is closed and runs long
    ok_z, gen_z = b.begin()                    # call Z starts too and fails first: the breaker opens
    assert ok_x and ok_z
    b.on_failure(gen_z)
    assert b.snapshot()["state"] == "open"
    now[0] = 11.0
    ok_y, gen_y = b.begin()                    # cooldown over: Y is the half-open probe
    assert ok_y and b.snapshot()["state"] == "half_open"
    b.on_failure(gen_x)                        # X finally fails - it is not the probe
    assert b.snapshot()["state"] == "half_open", "a straggler reopened the breaker under the probe"
    b.on_success(gen_y)                        # the real probe succeeds
    assert b.snapshot()["state"] == "closed"
