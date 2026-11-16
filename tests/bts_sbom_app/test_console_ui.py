"""The open-source security screen: record -> console report, the page and its static files, downloads, triage, approved scans."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import threading
import time
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import cli, console, evals, pipeline, server
from conftest import FakeScanner

FORBIDDEN = ("kev", "epss", "epss_percentile", "priority", "reachability_status", "vex_status")


@pytest.fixture
def ui(tmp_path, make_repo, world):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                               cache_dir=str(tmp_path / "cache"))
    assert rec["error"] is None, rec
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "rec": rec, "ev": ev, "st": st}
    httpd.shutdown()


def _get(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as r:
            return r.status, dict(r.headers), r.read()
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), e.read()


def _post(url, body):
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_record_becomes_a_console_report(ui):
    """AC: BSA-AC-69"""
    rep = console.to_report(ui["rec"])
    assert len(rep["findings"]) == 2 and rep["severity"]["total"] == 2
    assert sum(rep["severity"][k] for k in console.SEVERITIES) == 2
    assert sorted(f["cve"] for f in rep["findings"]) == ["CVE-2020-1111", "CVE-2020-2222"]
    assert sorted(f["fixed"] for f in rep["findings"]) == ["2.20.0", "2.31.0"]
    assert rep["components"] == 1 and len(rep["packages"]) == 1
    assert [(r["component"], r["safe_version"]) for r in rep["remediation"]] == [("requests", "2.31.0")]


def test_fields_bts_sbom_does_not_compute_are_left_out(ui):
    """AC: BSA-AC-70"""
    rep = console.to_report(ui["rec"])
    for f in rep["findings"]:
        assert not [k for k in FORBIDDEN if k in f], f
    assert "deprecated" not in rep["license_verification"]["summary"]
    assert rep["license_verification"]["summary"] == {"ok": 1, "none": 0, "invalid": 0}


def test_page_is_served_with_csp_and_assets_only_from_the_allow_list(ui):
    """AC: BSA-AC-71"""
    base = ui["base"]
    code, hdr, body = _get(base + "/")
    assert code == 200 and b"<title>BTS-SBOM</title>" in body and "script-src 'self'" in hdr["Content-Security-Policy"]
    code, _, js = _get(base + "/static/sca_app.js")
    with open(os.path.join(server.WEB_DIR, "sca_app.js"), "rb") as fh:
        assert code == 200 and js == fh.read()                        # served byte for byte
    probes = ["/static/../server.py", "/static/%2e%2e/server.py", "/static/index.html", "/static/nope.js"]
    assert [_get(base + p)[0] for p in probes] == [404, 404, 404, 404]


def test_view_and_history_list_the_analysed_project(ui):
    """AC: BSA-AC-72"""
    base, name = ui["base"], ui["rec"]["name"]
    code, _, body = _get(base + "/api/view/" + name)
    v = json.loads(body)
    assert code == 200 and len(v["report"]["findings"]) == 2 and v["project"] == name
    rows = json.loads(_get(base + "/api/history")[2])["history"]
    assert [r["vulns"] for r in rows if r["name"] == name] == [2]
    assert _get(base + "/api/view/no-such-project")[0] == 404


def test_sbom_download_is_an_attachment_and_rejects_bad_input(ui):
    """AC: BSA-AC-73"""
    base, name = ui["base"], ui["rec"]["name"]
    code, hdr, body = _get(base + "/api/sbom/%s?format=cdx" % name)
    assert code == 200 and json.loads(body)["bomFormat"] == "CycloneDX" and "attachment" in hdr["Content-Disposition"]
    assert _get(base + "/api/sbom/%s?format=zip" % name)[0] == 400
    assert _get(base + "/api/sbom/no-such-project?format=cdx")[0] == 404


def test_ignore_decision_is_persisted_and_invalid_ones_are_refused(ui):
    """AC: BSA-AC-74"""
    base, name = ui["base"], ui["rec"]["name"]
    code, out = _post(base + "/api/triage", {"check_id": "CVE-2020-1111", "status": "accepted", "note": "tracked in JIRA-1"})
    assert code == 200 and out["triage"]["CVE-2020-1111"]["status"] == "accepted"
    assert os.path.isfile(os.path.join(str(ui["ev"]), ".triage.json"))
    marked = [f for f in json.loads(_get(base + "/api/view/" + name)[2])["report"]["findings"] if f.get("triage_status") == "accepted"]
    assert [f["cve"] for f in marked] == ["CVE-2020-1111"]
    bad = [{"check_id": "X", "status": "maybe"}, {"check_id": "  ", "status": "accepted"}, {"check_id": "X", "status": "accepted", "note": "n" * 501}]
    assert [_post(base + "/api/triage", b)[0] for b in bad] == [400, 400, 400]


def test_copied_platform_files_match_their_recorded_hashes():
    """AC: BSA-AC-75"""
    with open(os.path.join(server.WEB_DIR, "PLATFORM_ASSETS.sha256"), "r", encoding="utf-8") as fh:
        rows = [ln.split("  ", 1) for ln in fh.read().splitlines() if ln.strip()]
    assert len(rows) == 6
    ok = 0
    for digest, rel in rows:
        with open(os.path.join(server.WEB_DIR, *rel.split("/")), "rb") as fh:
            data = fh.read()
        ok += hashlib.sha256(data).hexdigest() == digest
        if rel == "sca_app.js":                                       # an edited copy must be detected
            assert hashlib.sha256(data + b" ").hexdigest() != digest
    assert ok == 6


def test_approved_scan_needs_the_digest_and_work_copies_are_cleaned_up(ui, monkeypatch, tmp_path):
    """AC: BSA-AC-76"""
    base, src = ui["base"], str(tmp_path)
    assert _post(base + "/api/scan", {"source": src, "patch": True, "approved": True})[0] == 400          # no digest
    assert _post(base + "/api/scan", {"source": src, "approved": True, "approval_token": "abc"})[0] == 400   # approval without patch
    seen = {}

    def stub(source, **kw):
        seen.update(kw)
        os.makedirs(os.path.join(kw["work_root"], "copy"))
        return {"name": "stub", "error": None, "metrics": {}, "artifacts": {}, "stage_errors": {},
                "patch": {"status": "applied" if kw.get("approved") else "not_requested"}}

    monkeypatch.setattr(server.pipeline, "run_project", stub)
    real_rmtree = shutil.rmtree

    def slow_rmtree(*a, **k):                                         # a slow clean-up exposes a job that reports "done" before it
        time.sleep(0.4)
        return real_rmtree(*a, **k)

    monkeypatch.setattr(server.shutil, "rmtree", slow_rmtree)

    def run(body):
        code, out = _post(base + "/api/scan", body)
        assert code == 202
        for _ in range(100):
            job = json.loads(_get(base + "/api/jobs/" + out["job"])[2])
            if job["state"] != "running":
                return job
            time.sleep(0.1)
        raise AssertionError("job did not finish")

    job = run({"source": src})
    assert not os.path.exists(seen["work_root"]) and job["work_copy"] is None                              # nothing applied: removed
    job = run({"source": src, "patch": True, "approved": True, "approval_token": "T"})
    assert seen["approval_token"] == "T" and os.path.isdir(job["work_copy"])                              # applied: kept
    shutil.rmtree(job["work_copy"], ignore_errors=True)


def test_patch_diff_reaches_the_page_as_strings():
    """AC: BSA-AC-77"""
    base = {"name": "p", "components": [], "vulns": [], "plans": [], "engine": {}, "license": {}}
    obj = console.build_view(dict(base, patch={"status": "applied", "diff": {"stat": " a | 1 +", "patch": "diff --git a b"}}))
    txt = console.build_view(dict(base, patch={"status": "applied", "diff": "diff --git a b"}))
    assert obj["patch"]["diff"] == {"stat": " a | 1 +", "patch": "diff --git a b"}
    assert txt["patch"]["diff"] == {"stat": "", "patch": "diff --git a b"}


def test_records_written_before_the_identifier_rename_still_load(ui, tmp_path):
    """AC: BSA-AC-78"""
    rec = ui["rec"]
    assert rec["schema"] == "bts-sbom.project.v1"                     # new analyses write the current id
    ev = tmp_path / "mixed"
    for name, schema in (("current", "bts-sbom.project.v1"), ("earlier", "sbomplus.project.v1"), ("foreign", "other.project.v1")):
        d = ev / name
        d.mkdir(parents=True)
        (d / (name + ".json")).write_text(json.dumps(dict(rec, name=name, schema=schema)), encoding="utf-8")
    assert sorted(cli.load_projects(str(ev))) == ["current", "earlier"]    # the unknown id stays out
