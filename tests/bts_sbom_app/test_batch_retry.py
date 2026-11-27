"""Batch partial status and retry-only-failed (C13).

Every test stubs ``pipeline.run_project`` (no network, no real clone) and uses ``tmp_path`` for all
run directories, so results are deterministic and the suite is offline.
"""
from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from bts_sbom_app import batch, pipeline


def _metrics(components: int, vulns: int = 1) -> Dict[str, Any]:
    return {
        "components": components, "vulns": vulns, "severity": {"high": vulns},
        "license_resolved": components, "license_total": components, "license_resolved_rate": 1.0,
        "license_sources": {"spdx": components},
        "plans": 0, "plans_upgrade": 0, "plans_verified_clean": 0, "plans_unverified": 0,
        "sbom_ref_rate": 1.0, "cyclonedx_valid": True, "spdx_valid": True,
        "patch_status": "not_requested", "patch_applied_components": 0,
        "patch_rescan_fixed": 0, "patch_estimated_fixed": 0,
        "arch_edges": 0, "arch_cycles": 0, "proposal_source": "deterministic",
        "stage_errors": 0, "elapsed_s": 0.1,
    }


def _ok_record(name: str, components: int) -> Dict[str, Any]:
    return {"name": name, "error": None, "metrics": _metrics(components),
            "patch": {"status": "not_requested"}, "proposals": {"source": "deterministic"}, "stage_errors": {}}


def _err_record(name: str, msg: str = "clone failed") -> Dict[str, Any]:
    return {"name": name, "error": msg, "metrics": {}, "stage_errors": {}}


def _llm_record(name: str, components: int, *, items: int, dropped: Optional[Dict[str, int]] = None,
                 repaired: int = 0) -> Dict[str, Any]:
    """A fake `pipeline.run_project` success record whose `proposals` is exaone-sourced (LLM-backed) with a full
    items/dropped/repaired payload - the real shape `ai.propose()` returns once a response validates
    (`source="exaone"`), which is the normal production path (`use_llm=True` by default). This is the shape that
    `_reinflate()` used to collapse down to `{"source": "exaone"}` only, crashing `_proposal_stats()`."""
    m = _metrics(components)
    m["proposal_source"] = "exaone"
    its = [{"title": "p%d" % i, "action": "upgrade", "risk": "low", "rationale": "r%d" % i} for i in range(items)]
    return {"name": name, "error": None, "metrics": m, "patch": {"status": "not_requested"},
            "proposals": {"source": "exaone", "model": "x", "items": its,
                           "summary": "", "dropped": dropped or {}, "repaired": repaired},
            "stage_errors": {}}


def make_profile_stub(profiles: Dict[str, Dict[str, Any]], calls: List[str]):
    """A fake `pipeline.run_project` driven by a per-name `profiles` map: `{"error": msg}` fails; a `"source":
    "exaone"` entry succeeds via `_llm_record` (full items/dropped/repaired payload); anything else succeeds via
    `_ok_record` (deterministic, no items/dropped)."""
    def fake(src: str, *, work_root: str, out_dir: Optional[str], name: Optional[str] = None,
             client: Any = None, cache_dir: Optional[str] = None, **kw: Any) -> Dict[str, Any]:
        calls.append(src)
        nm = name or src
        prof = profiles[nm]
        if "error" in prof:
            return _err_record(nm, prof["error"])
        if out_dir:                                       # mirror pipeline.persist()'s side effect: run_batch(write=True)
            os.makedirs(os.path.join(out_dir, nm), exist_ok=True)   # writes <run_dir>/<name>/<name>.md for every success
        if prof.get("source") == "exaone":
            return _llm_record(nm, prof["components"], items=prof.get("items", 0),
                                dropped=prof.get("dropped"), repaired=prof.get("repaired", 0))
        return _ok_record(nm, prof["components"])
    return fake


def make_stub(fail_names: Any, calls: List[str], components_by_name: Optional[Dict[str, int]] = None):
    """A deterministic stand-in for pipeline.run_project: fails for `fail_names`, else succeeds with a fixed
    component count. Records every `src` it was called with in `calls` (no network, no real clone)."""
    fail_names = set(fail_names)
    components_by_name = components_by_name or {}

    def fake(src: str, *, work_root: str, out_dir: Optional[str], name: Optional[str] = None,
             client: Any = None, cache_dir: Optional[str] = None, **kw: Any) -> Dict[str, Any]:
        calls.append(src)
        nm = name or src
        if nm in fail_names:
            return _err_record(nm)
        return _ok_record(nm, components_by_name.get(nm, 3))

    return fake


def _sources(names: List[str]) -> List[Dict[str, str]]:
    return [{"name": n, "src": "https://example.test/%s.git" % n} for n in names]


def test_source_id_is_stable_8_hex_and_sensitive_to_src_and_ref():
    """AC: BSA-AC-1195"""
    a1 = batch.source_id("https://example.test/a.git")
    a2 = batch.source_id("https://example.test/a.git")
    b = batch.source_id("https://example.test/b.git")
    as_dict = batch.source_id({"src": "https://example.test/a.git"})
    with_ref = batch.source_id({"src": "https://example.test/a.git", "ref": "v2"})
    checks = 0
    assert a1 == a2                                      # same source -> same id, repeatable
    checks += 1
    assert len(a1) == 8 and all(c in "0123456789abcdef" for c in a1)   # 8 hex chars
    checks += 1
    assert a1 != b                                       # different source -> different id
    checks += 1
    assert a1 == as_dict                                 # bare string and {"src": ...} normalize to the same id
    checks += 1
    assert with_ref != a1                                # a ref is part of the identity
    checks += 1
    assert checks == 5                                   # (5 of 5 id-stability checks passed)


def test_batch_status_and_failed_sources_reflect_the_mix(tmp_path, monkeypatch):
    """AC: BSA-AC-1196"""
    calls: List[str] = []
    names = ["a", "b", "c", "d", "e"]
    fail = {"b", "d"}
    monkeypatch.setattr(pipeline, "run_project", make_stub(fail, calls))

    out = batch.run_batch(_sources(names), str(tmp_path / "mixed"), tag="t", client=None, write=False)
    agg = out["summary"]["summary"]
    assert agg["status"] == "partial_success"
    assert len(agg["failed_sources"]) == 2 == agg["errors"]        # (2 of 2 failed sources captured)
    assert {fs["name"] for fs in agg["failed_sources"]} == {"b", "d"}
    assert agg["projects"] - agg["errors"] == 3                    # (3 of 3 successes preserved)

    all_ok = batch.run_batch(_sources(["x", "y"]), str(tmp_path / "allok"), tag="t", client=None, write=False)
    assert all_ok["summary"]["summary"]["status"] == "success" and all_ok["summary"]["summary"]["failed_sources"] == []

    monkeypatch.setattr(pipeline, "run_project", make_stub({"p", "q"}, calls))
    all_fail = batch.run_batch(_sources(["p", "q"]), str(tmp_path / "allfail"), tag="t", client=None, write=False)
    assert all_fail["summary"]["summary"]["status"] == "failure" and len(all_fail["summary"]["summary"]["failed_sources"]) == 2


def _write_prior_summary(tmp_path, names: List[str], fail: set, components_by_name=None) -> str:
    """Build a prior run's summary.json directly (as batch.run_batch would have written it) without touching
    report.py, so these tests exercise retry_failed's own contract in isolation."""
    components_by_name = components_by_name or {}
    projects = []
    for n in names:
        sid = batch.source_id({"src": "https://example.test/%s.git" % n, "name": n})
        if n in fail:
            projects.append({"name": n, "id": sid, "error": "clone failed", "metrics": {}, "stage_errors": {}})
        else:
            projects.append({"name": n, "id": sid, "error": None, "metrics": _metrics(components_by_name.get(n, 3)),
                             "stage_errors": {}})
    run_dir = tmp_path / "runs" / "20260101T000000Z_t"
    run_dir.mkdir(parents=True)
    agg = batch.aggregate([
        (_err_record(n) if n in fail else _ok_record(n, components_by_name.get(n, 3)))
        for n in names
    ])
    # match ids onto the aggregate's failed_sources too, as run_batch would
    by_name = {p["name"]: p["id"] for p in projects}
    for fs in agg["failed_sources"]:
        fs["id"] = by_name[fs["name"]]
    from bts_sbom_app.util import write_json
    write_json(str(run_dir / "summary.json"), {"schema": "bts-sbom.batch.v1", "tag": "t", "summary": agg, "projects": projects})
    return str(run_dir)


def test_retry_failed_reanalyses_exactly_the_failed_ids(tmp_path, monkeypatch):
    """AC: BSA-AC-1197"""
    names = ["a", "b", "c", "d", "e"]
    fail = {"b", "d"}
    prior_run_dir = _write_prior_summary(tmp_path, names, fail)

    calls: List[str] = []
    monkeypatch.setattr(pipeline, "run_project", make_stub(set(), calls))   # everyone succeeds this time
    out = batch.retry_failed(_sources(names), prior_run_dir, str(tmp_path), tag="retry", client=None, write=False)

    assert len(calls) == 2                                              # (2 of 2 failed sources re-analysed)
    called_names = {os.path.basename(c).split(".")[0] for c in calls}
    assert called_names == {"b", "d"}                                   # exactly the failed ones, 0 of 3 successes re-run
    assert out["summary"]["retried_ids"] and len(out["summary"]["retried_ids"]) == 2


def test_retry_failed_merges_by_id_with_zero_duplicates_and_recomputes_aggregate(tmp_path, monkeypatch):
    """AC: BSA-AC-1198"""
    names = ["a", "b", "c", "d", "e"]
    fail = {"b", "d"}
    components = {"a": 3, "b": 3, "c": 3, "d": 3, "e": 3}
    prior_run_dir = _write_prior_summary(tmp_path, names, fail, components)

    calls: List[str] = []
    monkeypatch.setattr(pipeline, "run_project", make_stub(set(), calls, {"b": 7, "d": 9}))   # b, d now succeed
    out = batch.retry_failed(_sources(names), prior_run_dir, str(tmp_path), tag="retry", client=None, write=False)

    ids = [r.get("id") for r in out["records"]]
    assert len(ids) == 5 == len(set(ids))                               # (5 of 5 merged ids unique, 0 duplicates)
    agg = out["summary"]["summary"]
    assert agg["projects"] == 5 and agg["errors"] == 0
    assert agg["status"] == "success"                                   # both previously-failed sources now ok
    assert agg["components"] == 3 + 7 + 3 + 9 + 3                        # recomputed from 3 rehydrated + 2 fresh records


def test_retry_failed_reports_missing_ids_instead_of_dropping_them(tmp_path, monkeypatch):
    """AC: BSA-AC-1199"""
    names = ["a", "b", "c"]
    fail = {"c"}
    prior_run_dir = _write_prior_summary(tmp_path, names, fail)

    calls: List[str] = []
    monkeypatch.setattr(pipeline, "run_project", make_stub(set(), calls))
    out = batch.retry_failed(_sources(["a", "b"]), prior_run_dir, str(tmp_path), tag="retry", client=None, write=False)
    # "c" is not present in the `sources` passed to retry_failed this time: it cannot be retried

    assert calls == []                                                  # (0 of 0 re-analysed: the one failure is unreachable)
    assert len(out["summary"]["missing_ids"]) == 1                      # (1 of 1 missing id reported)
    names_in_merge = [r.get("name") for r in out["records"]]
    assert "c" in names_in_merge and len(names_in_merge) == 3            # still present, 0 silently dropped
    agg = out["summary"]["summary"]
    assert agg["status"] == "partial_success" and agg["errors"] == 1


def _final_profiles() -> Dict[str, Dict[str, Any]]:
    """Per-name end-state: a, c succeed deterministically; b, d, e succeed via exaone with a full
    items/dropped/repaired payload (the shape that used to crash `_proposal_stats()` on reinflation)."""
    return {
        "a": {"components": 3},
        "b": {"components": 7, "source": "exaone", "items": 2, "dropped": {"invalid_action": 1}, "repaired": 1},
        "c": {"components": 3},
        "d": {"components": 9, "source": "exaone", "items": 3, "dropped": {}, "repaired": 0},
        "e": {"components": 3, "source": "exaone", "items": 4, "dropped": {"no_evidence": 2}, "repaired": 0},
    }


def test_retry_failed_reinflates_exaone_proposal_stats_without_crashing(tmp_path, monkeypatch):
    """AC: BSA-AC-1198"""
    names = ["a", "b", "c", "d", "e"]
    out_root = str(tmp_path / "proj")
    final_profiles = _final_profiles()
    first_pass_profiles = dict(final_profiles)
    first_pass_profiles["b"] = {"error": "clone failed"}
    first_pass_profiles["d"] = {"error": "clone failed"}

    calls: List[str] = []
    # First pass: "e" succeeds with exaone proposals (full items/dropped/repaired); "b"/"d" fail. This writes a real
    # summary.json whose projects[] entry for "e" is the trimmed shape retry_failed will later reinflate.
    monkeypatch.setattr(pipeline, "run_project", make_profile_stub(first_pass_profiles, calls))
    first = batch.run_batch(_sources(names), out_root, tag="t1", client=None, write=True)
    assert first["summary"]["summary"]["status"] == "partial_success"
    run_dir = first["summary"]["run_dir"]

    # Retry: only "b"/"d" are re-analysed; "e" (an exaone-sourced first-pass success) is reinflated from the
    # trimmed projects[] entry - this is exactly the path that used to raise KeyError('items') in `_proposal_stats`.
    calls.clear()
    monkeypatch.setattr(pipeline, "run_project", make_profile_stub(final_profiles, calls))
    retried = batch.retry_failed(_sources(names), run_dir, out_root, tag="retry", client=None, write=False)
    assert {os.path.basename(c).split(".")[0] for c in calls} == {"b", "d"}   # "e" was not re-run
    agg = retried["summary"]["summary"]
    assert agg["status"] == "success" and agg["errors"] == 0

    # The exaone proposal stats survived reinflation instead of being silently zeroed or raising: b, d, e are the
    # three exaone-sourced successes (kept 2+3+4=9, dropped 1+0+2=3, repaired 1+0+0=1).
    props = agg["proposals"]
    assert props["exaone"] == 3 and props["deterministic"] == 2
    assert props["kept"] == 9 and props["dropped"] == 3 and props["repaired"] == 1
    assert props["keep_rate"] == round(9 / 12, 3)


def test_retry_failed_aggregate_equals_a_fresh_full_run_aggregate(tmp_path, monkeypatch):
    """AC: BSA-AC-1198"""
    names = ["a", "b", "c", "d", "e"]
    out_root = str(tmp_path / "proj")
    final_profiles = _final_profiles()
    first_pass_profiles = dict(final_profiles)
    first_pass_profiles["b"] = {"error": "clone failed"}
    first_pass_profiles["d"] = {"error": "clone failed"}

    calls: List[str] = []
    monkeypatch.setattr(pipeline, "run_project", make_profile_stub(first_pass_profiles, calls))
    first = batch.run_batch(_sources(names), out_root, tag="t1", client=None, write=True)
    run_dir = first["summary"]["run_dir"]

    calls.clear()
    monkeypatch.setattr(pipeline, "run_project", make_profile_stub(final_profiles, calls))
    retried = batch.retry_failed(_sources(names), run_dir, out_root, tag="retry", client=None, write=False)

    # A fresh full run (nothing ever failed) over the same end-state profiles must produce the exact same
    # aggregate() output - a retry merge must be indistinguishable from a fresh run, proposal statistics included.
    calls.clear()
    monkeypatch.setattr(pipeline, "run_project", make_profile_stub(final_profiles, calls))
    fresh = batch.run_batch(_sources(names), str(tmp_path / "fresh"), tag="fresh", client=None, write=False)

    assert fresh["summary"]["summary"] == retried["summary"]["summary"]


def test_retry_failed_tolerates_a_legacy_summary_json_missing_the_proposal_count_fields(tmp_path, monkeypatch):
    """AC: BSA-AC-1198"""
    # A summary.json written before proposal_kept/proposal_dropped/proposal_repaired existed on metrics: an
    # exaone-sourced prior success with only "proposal_source" on its metrics, nothing else proposal-related.
    # Old summary.json files must keep loading (and aggregating) without error, just with 0 for the unknown counts.
    sources = _sources(["a", "b"])
    legacy_metrics_a = _metrics(3)
    legacy_metrics_a["proposal_source"] = "exaone"          # no proposal_kept/proposal_dropped/proposal_repaired keys
    projects = [
        {"name": "a", "id": batch.source_id(sources[0]), "error": None, "metrics": legacy_metrics_a, "stage_errors": {}},
        {"name": "b", "id": batch.source_id(sources[1]), "error": "clone failed", "metrics": {}, "stage_errors": {}},
    ]
    run_dir = tmp_path / "runs" / "20250101T000000Z_legacy"
    run_dir.mkdir(parents=True)
    from bts_sbom_app.util import write_json
    write_json(str(run_dir / "summary.json"), {"schema": "bts-sbom.batch.v1", "tag": "legacy", "projects": projects})

    calls: List[str] = []
    monkeypatch.setattr(pipeline, "run_project", make_stub(set(), calls))   # "b" now succeeds on retry
    out = batch.retry_failed(sources, str(run_dir), str(tmp_path), tag="retry", client=None, write=False)
    agg = out["summary"]["summary"]
    assert agg["status"] == "success" and agg["errors"] == 0            # no crash: "b" retried and now succeeds
    assert agg["proposals"]["exaone"] == 1                              # "a" (reinflated) still counted as exaone
    assert agg["proposals"]["kept"] == 0 and agg["proposals"]["dropped"] == 0   # unknown for legacy data -> 0, not a crash
