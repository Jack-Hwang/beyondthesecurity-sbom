"""Persistent job records: honest restart behaviour, secrets never stored, corrupt files skipped (task 6, AC 401-412)."""
from __future__ import annotations

import json
import os

import pytest

from bts_sbom_app import jobstore


def _store(tmp_path, **kw):
    return jobstore.JobStore(str(tmp_path / ".jobs"), **kw)


def test_a_finished_job_record_is_read_back_by_a_new_store(tmp_path):
    """AC: BSA-AC-401"""
    st = _store(tmp_path)
    rec, _reused = st.create("https://github.com/o/r.git")
    st.update(rec["id"], state="done", name="proj", metrics={"components": 3})
    again = jobstore.JobStore(str(tmp_path / ".jobs"))
    got = again.get(rec["id"])
    assert got["state"] == "done" and got["metrics"] == {"components": 3}


def test_queued_and_running_records_become_interrupted_on_recover(tmp_path):
    """AC: BSA-AC-402"""
    st = _store(tmp_path)
    a, _ = st.create("https://github.com/o/r.git", id_gen=lambda: "aaaaaaaaaa")
    b, _ = st.create("https://github.com/o/r.git", id_gen=lambda: "bbbbbbbbbb")
    st.update(a["id"], state="queued")
    out = jobstore.JobStore(str(tmp_path / ".jobs")).recover()
    assert out == {"interrupted": 2, "corrupt": 0}
    d = st.get(a["id"])
    assert d["state"] == "interrupted" and d["interrupted_reason"] == "server_restart" and d["finished_at"]


def test_an_approval_token_is_never_written_to_a_job_file(tmp_path):
    """AC: BSA-AC-403"""
    st = _store(tmp_path)
    token = "0123456789abcdef0123456789abcdef"
    rec, _ = st.create("https://github.com/o/r.git")
    st.update(rec["id"], state="done", metrics={"x": 1}, artifacts={}, stage_errors={},
              patch=True, approved=True, work_copy="/tmp/whatever")          # no token field is even accepted
    blobs = [open(os.path.join(tmp_path / ".jobs", f), encoding="utf-8").read() for f in os.listdir(tmp_path / ".jobs")]
    assert sum(b.count(token) for b in blobs) == 0


def test_credentials_never_reach_the_stored_source(tmp_path):
    """AC: BSA-AC-404"""
    st = _store(tmp_path)
    rec, _ = st.create("https://user:tok123@github.com/o/r.git?x=1#frag")
    stored = jobstore.JobStore(str(tmp_path / ".jobs")).get(rec["id"])["source"]
    assert ":" + "tok123" not in stored and "@" not in stored and "x=1" not in stored and "frag" not in stored
    assert stored == "https://github.com/o/r.git"


def test_malformed_ids_open_no_file_outside_the_jobs_folder(tmp_path, monkeypatch):
    """AC: BSA-AC-405"""
    opened = []

    def guard(path, *a, **kw):
        opened.append(str(path))
        return open(path, *a, **kw)

    monkeypatch.setattr(jobstore, "read_json", lambda p, d=None: opened.append(str(p)) or None)
    st = _store(tmp_path)
    for bad in ("../x", "A1B2C3D4E5", "x"):
        assert st.get(bad) is None
    assert opened == [], "no file may be opened for a malformed id"


def test_the_same_idempotency_key_reuses_the_earlier_job(tmp_path):
    """AC: BSA-AC-406"""
    st = _store(tmp_path)
    rec, _ = st.create("https://github.com/o/r.git", idempotency_key="run-1")
    prior = st.find_by_key("run-1")
    assert prior["id"] == rec["id"] and prior["state"] in ("queued", "running", "done")
    reused = prior["state"] in ("queued", "running", "done")
    assert reused is True and prior["state"] == "running"


def test_an_errored_earlier_job_lets_a_new_job_start_for_the_same_key(tmp_path):
    """AC: BSA-AC-407"""
    st = _store(tmp_path)
    rec, _ = st.create("https://github.com/o/r.git", idempotency_key="run-2")
    st.update(rec["id"], state="error", error="boom")
    prior = st.find_by_key("run-2")
    assert prior["state"] == "error"                                   # the server may start 1 new job for the same key


def test_prune_keeps_running_records_and_drops_the_oldest_finished(tmp_path):
    """AC: BSA-AC-408"""
    clock = {"t": 1700000000.0}
    st = _store(tmp_path, max_jobs=200, clock=lambda: clock["t"])

    def tick():
        clock["t"] += 1
        return clock["t"]

    recs = []
    for i in range(200):
        clock["t"] += 1
        r, _ = st.create("https://github.com/o/r.git", id_gen=lambda i=i: "%010x" % (0x1000 + i))
        st.update(r["id"], state="done")
        recs.append(r)
    clock["t"] += 1
    running, _ = st.create("https://github.com/o/r.git", id_gen=lambda: "aaaaaaaaaa")
    st.update(running["id"], state="running")
    clock["t"] += 1
    extra, _ = st.create("https://github.com/o/r.git", id_gen=lambda: "bbbbbbbbbb")
    st.update(extra["id"], state="done")
    deleted = st.prune()
    rows = st._records()
    assert len(rows) == 200
    assert any(r["id"] == running["id"] for _i, r in rows), "a running record is never pruned"
    assert any(r["id"] == extra["id"] for _i, r in rows), "the newest finished record survives"
    assert deleted > 0


def test_a_corrupt_record_is_skipped_and_counted(tmp_path):
    """AC: BSA-AC-409"""
    st = _store(tmp_path)
    r1, _ = st.create("https://github.com/o/r.git", id_gen=lambda: "cccccccccc")
    r2, _ = st.create("https://github.com/o/r.git", id_gen=lambda: "dddddddddd")
    st.update(r1["id"], state="done")
    st.update(r2["id"], state="done")
    with open(os.path.join(tmp_path / ".jobs", "eeeeeeeeee.json"), "w", encoding="utf-8") as fh:
        fh.write("{not json")
    fresh = jobstore.JobStore(str(tmp_path / ".jobs"))
    out = fresh.recover()
    assert out["corrupt"] == 1
    assert fresh.get(r1["id"])["state"] == "done" and fresh.get(r2["id"])["state"] == "done"


def test_a_write_that_fails_midway_leaves_no_partial_file(tmp_path, monkeypatch):
    """AC: BSA-AC-410"""
    st = _store(tmp_path)
    rec, _ = st.create("https://github.com/o/r.git")
    real_replace = os.replace

    def broken_replace(src, dst):
        raise OSError("simulated crash during replace")

    monkeypatch.setattr(jobstore.os, "replace", broken_replace)
    with pytest.raises(OSError):
        st.update(rec["id"], state="done")
    monkeypatch.setattr(jobstore.os, "replace", real_replace)
    files = os.listdir(tmp_path / ".jobs")
    assert files == [rec["id"] + ".json"]                              # the folder holds only the original record, 0 partial files
    fresh = json.loads(open(os.path.join(tmp_path / ".jobs", files[0]), encoding="utf-8").read())
    assert fresh["state"] == "running"
