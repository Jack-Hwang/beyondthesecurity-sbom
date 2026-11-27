"""Change tracking between analyses (Hub-style alerts) and accountable triage -> OpenVEX (fail-closed)."""
from __future__ import annotations

import copy
import datetime
import json
import os
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import changes, cli, evals, pipeline, sbom, server, triage
from bts_sbom_app.llm import ChatClient
from conftest import FakeScanner

TODAY = datetime.date(2026, 11, 17)


def _v(vid, pkg="requests", ver="2.19.1", sev="HIGH", cvss=7.5, aliases=(), fixed="2.20.0", **kw):
    return dict({"id": vid, "aliases": list(aliases), "osv_ids": [], "package": pkg, "version": ver, "ecosystem": "PyPI", "purl": "pkg:pypi/%s@%s" % (pkg, ver),
                 "severity": sev, "cvss": cvss, "fixed_version": fixed, "summary": "s", "files": ["requirements.txt"], "malicious": False}, **kw)


def _c(name="requests", ver="2.19.1", lic="Apache-2.0", **kw):
    return dict({"name": name, "version": ver, "ecosystem": "PyPI", "license": lic, "vulns": 0, "files": ["requirements.txt"]}, **kw)


def _rec(comps, vulns, name="demo"):
    return {"schema": pipeline.PROJECT_SCHEMA, "name": name, "components": comps, "vulns": vulns}


# ------------------------------------------------------------------ changes
def test_upgrade_that_clears_one_advisory_while_a_new_high_one_and_a_gpl_component_appear():
    """AC: BSA-AC-154"""
    before = _rec([_c()], [_v("CVE-2018-18074")])
    after = _rec([_c(ver="2.20.0"), _c("gplthing", "1.0", "GPL-3.0-only")], [_v("CVE-2024-0001", ver="2.20.0", fixed="")])
    d = changes.diff(before, after)
    s = d["summary"]
    assert (s["vulns_new"], s["vulns_resolved"], s["components_added"], s["components_changed"]) == (1, 1, 1, 1) and d["verdict"] == "mixed"
    assert d["components"]["changed"][0]["direction"] == "upgrade" and d["components"]["changed"][0]["to"] == ["2.20.0"]
    assert sorted(a["kind"] for a in d["alerts"]) == ["copyleft_introduced", "new_at_or_above_threshold"] and "no known fixed version" in d["alerts"][0]["detail"]
    same = changes.diff(before, copy.deepcopy(before))
    assert same["verdict"] == "same" and same["alerts"] == [] and same["vulnerabilities"]["persisting"] == 1


def test_threshold_crossings_up_and_down_and_the_label_floor_for_unscored_findings():
    """AC: BSA-AC-155"""
    before = _rec([_c()], [_v("CVE-1", cvss=6.5, sev="MEDIUM"), _v("CVE-2", cvss=8.0, sev="HIGH"), _v("CVE-3", cvss=None, sev="HIGH", pkg="x", ver="1")])
    after = _rec([_c()], [_v("CVE-1", cvss=7.5, sev="HIGH"), _v("CVE-2", cvss=5.0, sev="MEDIUM"), _v("CVE-3", cvss=None, sev="HIGH", pkg="x", ver="1")])
    d = changes.diff(before, after, threshold=7.0)
    kinds = sorted(a["kind"] for a in d["alerts"])
    assert kinds == ["threshold_crossed_down", "threshold_crossed_up"] and d["summary"]["vulns_rescored"] == 2 and d["summary"]["vulns_new"] == 0
    assert changes.effective_score(_v("X", cvss=None, sev="HIGH")) == (7.0, "label-floor") and changes.effective_score(_v("X", cvss=None, sev="UNKNOWN")) == (None, "none")
    strict = changes.diff(_rec([_c()], []), _rec([_c()], [_v("CVE-9", cvss=None, sev="HIGH")]), threshold=7.0)
    assert [a["kind"] for a in strict["alerts"]] == ["new_at_or_above_threshold"]                           # HIGH proves >= 7.0 even without a score


def test_the_same_advisory_under_another_alias_is_one_persisting_finding():
    """AC: BSA-AC-156"""
    d = changes.diff(_rec([_c()], [_v("GHSA-aaaa-bbbb-cccc", aliases=["CVE-2020-1111"])]),
                     _rec([_c(ver="2.19.2")], [_v("CVE-2020-1111", ver="2.19.2", aliases=["GHSA-aaaa-bbbb-cccc"])]))
    assert (d["summary"]["vulns_new"], d["summary"]["vulns_resolved"], d["vulnerabilities"]["persisting"]) == (0, 0, 1)
    assert d["summary"]["components_changed"] == 1 and d["verdict"] == "same"


def test_cyclonedx_documents_compare_with_their_vulnerabilities_and_spdx_compares_components():
    """AC: BSA-AC-157"""
    comps = [_c(purl="pkg:pypi/requests@2.19.1", relationship="direct"), _c("idna", "2.7", purl="pkg:pypi/idna@2.7", relationship="transitive")]
    a = sbom.cyclonedx("p", comps, [])
    b = sbom.cyclonedx("p", comps, [dict(_v("GHSA-zzzz-zzzz-zzzz", aliases=["CVE-2025-1"]), osv_ids=["GHSA-zzzz-zzzz-zzzz"], references=[], summary="x")])
    d = changes.diff(a, b)
    assert d["summary"]["vulns_new"] == 1 and d["vulnerabilities"]["new"][0]["package"] == "requests" and d["before"]["kind"] == "cyclonedx"
    spdx = {"spdxVersion": "SPDX-2.3", "name": "p", "packages": [{"name": "requests", "versionInfo": "2.19.1", "licenseConcluded": "MIT"}]}
    spdx2 = {"spdxVersion": "SPDX-2.3", "name": "p", "packages": [{"name": "requests", "versionInfo": "2.20.0", "licenseConcluded": "GPL-3.0-only"}]}
    e = changes.diff(spdx, spdx2)
    assert e["summary"]["components_changed"] == 1 and e["before"]["vulns"] == 0 and [x["kind"] for x in e["alerts"]] == ["copyleft_introduced"]
    with pytest.raises(ValueError):
        changes.diff({"hello": 1}, spdx)


def test_brief_accepts_a_grounded_narrative_and_rejects_forged_figures(world):
    """AC: BSA-AC-158"""
    d = changes.diff(_rec([_c()], [_v("CVE-2018-18074")]), _rec([_c(ver="2.20.0")], [_v("CVE-2024-0001", ver="2.20.0", fixed="")]))

    def reply(text):
        world.llm_handler = lambda body: (200, json.dumps({"choices": [{"message": {"content": json.dumps({"text": text})}}],
                                                           "usage": {"prompt_tokens": 5, "completion_tokens": 7}}))

    reply("새 취약점 1건(CVE-2024-0001)이 임계값 7.0을 넘었고 1건은 해결되었습니다.")
    ok = changes.brief(d, client=ChatClient("k"), use_llm=True)
    assert ok["source"] == "exaone" and ok["text"].startswith("새 취약점") and "# Changes" in ok["text"]
    for forged in ("새 취약점 12건이 발생했습니다.", "CVE-2099-9999 가 새로 발견되었습니다."):
        reply(forged)
        r = changes.brief(d, client=ChatClient("k"), use_llm=True)
        assert r["source"] == "deterministic" and "rejected" in r["llm_note"] and r["text"].startswith("# Changes")
    nokey = changes.brief(d, client=None, use_llm=True)
    assert nokey["source"] == "deterministic" and "EXAONE_API_KEY" in nokey["llm_note"] and changes.brief(d)["llm_note"] == ""


def _evidence(tmp_path, make_repo, files):
    origin = make_repo(files)
    ev = tmp_path / "ev"

    def run():
        return pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False,
                                    cache_dir=str(tmp_path / "c"), name="proj")
    return origin, ev, run


def test_second_analysis_of_a_project_carries_what_changed_and_keeps_the_previous_record(tmp_path, make_repo, world):
    """AC: BSA-AC-159"""
    origin, ev, run = _evidence(tmp_path, make_repo, {"requirements.txt": "requests==2.19.1\n"})
    first = run()
    assert first["error"] is None and "changes" not in first and not os.path.exists(str(ev / "proj" / "proj.prev.json"))
    with open(os.path.join(origin, "requirements.txt"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("requests==2.31.0\nflask==0.12\n")
    second = run()
    c = second["changes"]
    assert c["summary"]["vulns_resolved"] == 2 and c["summary"]["vulns_new"] == 1 and c["summary"]["components_added"] == 1 and c["verdict"] == "mixed"
    assert [a["kind"] for a in c["alerts"]] == ["new_at_or_above_threshold"] and c["alerts"][0]["package"] == "flask"
    prev = json.load(open(str(ev / "proj" / "proj.prev.json"), encoding="utf-8"))
    assert prev["metrics"]["vulns"] == 2 and len(cli.project_records(str(ev))) == 1                    # the archive is not listed as a project
    assert cli.main(["diff", "proj", "--evidence", str(ev), "--fail-on-alert"]) == 1


def test_cli_diff_exit_codes(tmp_path, capsys):
    """AC: BSA-AC-174"""
    a, b, c = tmp_path / "a.json", tmp_path / "b.json", tmp_path / "c.json"
    a.write_text(json.dumps(_rec([_c()], [])), encoding="utf-8")
    b.write_text(json.dumps(_rec([_c()], [_v("CVE-2024-1")])), encoding="utf-8")
    c.write_text(json.dumps(_rec([_c(ver="2.20.0")], [])), encoding="utf-8")
    assert cli.main(["diff", str(a), str(b), "--fail-on-alert"]) == 1
    capsys.readouterr()
    assert cli.main(["diff", str(b), str(c), "--fail-on-alert", "--json"]) == 0
    assert json.loads(capsys.readouterr().out)["verdict"] == "better"
    assert cli.main(["diff", "no-such-project", "--evidence", str(tmp_path)]) == 2
    assert cli.main(["diff", str(a), str(tmp_path / "missing.json")]) == 2


# ------------------------------------------------------------------ triage -> OpenVEX
JUST = "vulnerable_code_not_in_execute_path"


def _stmt(store, vulns=None, today=TODAY):
    doc = sbom.openvex("demo", vulns or [_v("CVE-2018-18074", aliases=["GHSA-x84v-xcm2-53pg"])], triage=store, today=today)
    assert len(doc["statements"]) == 1
    return doc["statements"][0]


def test_false_positive_becomes_not_affected_only_with_a_justification_and_a_reason():
    """AC: BSA-AC-160"""
    ok = _stmt({"CVE-2018-18074": {"status": "false-positive", "note": "the redirect handling is never used", "justification": JUST, "by": "sec"}})
    assert ok["status"] == "not_affected" and ok["justification"] == JUST and "never used" in ok["impact_statement"] and "action_statement" not in ok
    for entry in ({"status": "false-positive", "note": "the redirect handling is never used"},                        # no justification
                  {"status": "false-positive", "note": "short", "justification": JUST},                                  # 5-character reason
                  {"status": "false-positive", "note": "the redirect handling is never used", "justification": "because"}):
        st = _stmt({"CVE-2018-18074": entry})
        assert st["status"] == "affected" and "action_statement" in st and "stays affected" in st["status_notes"]
    alias = _stmt({"ghsa-x84v-xcm2-53pg": {"status": "false-positive", "note": "the redirect handling is never used", "justification": JUST}})
    assert alias["status"] == "not_affected"                                                                          # a decision on an alias reaches the finding


def test_expired_decisions_no_longer_apply_but_one_expiring_today_does():
    """AC: BSA-AC-161"""
    e = {"status": "false-positive", "note": "the redirect handling is never used", "justification": JUST}
    assert _stmt({"CVE-2018-18074": dict(e, expires="2026-11-16")})["status"] == "affected"
    assert _stmt({"CVE-2018-18074": dict(e, expires="2026-11-17")})["status"] == "not_affected"
    ev = triage.evaluate([_v("CVE-2018-18074")], {"CVE-2018-18074": dict(e, expires="2026-11-16")}, today=TODAY)
    assert ev["counts"]["expired"] == 1 and ev["expired"][0]["expires"] == "2026-11-16" and "open again" in ev["findings"][0]["triage"]["issue"]


def test_accepted_risk_stays_affected_with_owner_and_date_and_a_fixed_claim_the_scan_contradicts_is_rejected():
    """AC: BSA-AC-162"""
    st = _stmt({"CVE-2018-18074": {"status": "accepted", "note": "waiting for the vendor release", "by": "dev-lead", "expires": "2027-02-01"}})
    assert st["status"] == "affected" and all(x in st["action_statement"] for x in ("waiting for the vendor release", "dev-lead", "2027-02-01"))
    assert "Upgrade requests to 2.20.0" in st["action_statement"]
    bare = triage.evaluate([_v("CVE-2018-18074")], {"CVE-2018-18074": {"status": "accepted", "note": "ok"}}, today=TODAY)
    assert bare["counts"]["rejected"] == 1
    fixed = triage.evaluate([_v("CVE-2018-18074")], {"CVE-2018-18074": {"status": "fixed", "note": "upgraded in branch x"}}, today=TODAY)
    assert fixed["counts"]["rejected"] == 1 and "still reports" in fixed["rejected"][0]["issue"]


def test_scoped_decision_beats_the_global_one_and_unmatched_decisions_are_listed_as_stale():
    """AC: BSA-AC-163"""
    vulns = [_v("CVE-2018-18074"), _v("CVE-2018-18074", pkg="other", ver="1.0", purl="pkg:pypi/other@1.0")]
    store = {"CVE-2018-18074": {"status": "accepted", "note": "global acceptance of the risk", "by": "g"},
             "CVE-2018-18074@requests": {"status": "false-positive", "note": "only requests is unaffected here", "justification": JUST},
             "CVE-1999-0001": {"status": "accepted", "note": "nothing matches this one"}}
    ev = triage.evaluate(vulns, store, today=TODAY)
    assert [f["triage"]["state"] for f in ev["findings"]] == ["not_affected", "accepted"] and ev["stale"] == ["CVE-1999-0001"]
    purl = triage.evaluate(vulns, {"CVE-2018-18074@pkg:pypi/other": {"status": "accepted", "note": "scoped by a purl prefix"}}, today=TODAY)
    assert [("triage" in f) for f in purl["findings"]] == [False, True]


def test_review_candidates_list_weak_matches_and_dev_dependencies_and_never_suggest_a_verdict():
    """AC: BSA-AC-164"""
    rec = _rec([_c(), _c("pytest", "7.0", scope={"dev": True, "optional": False}), _c("solid", "1.0")],
               [_v("CVE-A", affects_confirmed=False), _v("CVE-B", pkg="pytest", ver="7.0", affects_confirmed=True), _v("CVE-C", pkg="solid", ver="1.0", affects_confirmed=True),
                _v("CVE-D", affects_confirmed=False)])
    rows = triage.review_candidates(rec, {"CVE-D": {"status": "false-positive", "note": "decided already, with a reason", "justification": JUST}}, today=TODAY)
    assert sorted((r["id"], tuple(r["reasons"])) for r in rows) == [("CVE-A", ("range_unconfirmed",)), ("CVE-B", ("dev_only",))]
    assert not [r for r in rows if "status" in r or "suggested" in json.dumps(r)]
    assert triage.check_extras("nope") and triage.check_extras(None, "17/11/2026") and triage.check_extras(None, None, "has space") and triage.check_extras(JUST, "2026-12-01", "requests", "me") is None


@pytest.fixture
def svc(tmp_path, make_repo, world):
    origin = make_repo({"requirements.txt": "requests==2.19.1\n"})
    ev = tmp_path / "ev"
    rec = pipeline.run_project(origin, work_root=str(tmp_path / "w"), out_dir=str(ev), use_llm=False, scanner=FakeScanner(), run_arch=False, cache_dir=str(tmp_path / "c"))
    st = server.State(evals.repo_root(), str(ev), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield {"base": "http://127.0.0.1:%d" % httpd.server_address[1], "rec": rec, "st": st, "ev": ev}
    httpd.shutdown()


def _http(url, body=None):
    req = urllib.request.Request(url, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_service_stores_the_decision_fields_and_serves_the_vex_with_them_applied(svc):
    """AC: BSA-AC-165"""
    base, name = svc["base"], svc["rec"]["name"]
    code, out = _http(base + "/api/triage", {"check_id": "CVE-2020-1111", "status": "false-positive", "note": "the vulnerable function is never called",
                                              "justification": JUST, "expires": "2099-01-01", "scope": "requests", "by": "sec-team"})
    assert code == 200 and all(out["triage"]["CVE-2020-1111"][k] for k in ("justification", "expires", "scope", "by"))
    for bad in ({"justification": "because"}, {"expires": "next week"}, {"scope": "has space"}):
        assert _http(base + "/api/triage", dict({"check_id": "CVE-2020-2222", "status": "accepted", "note": "x"}, **bad))[0] == 400
    code, vex = _http(base + "/api/vex/" + name)
    by_id = {s["vulnerability"]["name"]: s for s in vex["statements"]}
    assert code == 200 and len(vex["statements"]) == 2 and by_id["CVE-2020-1111"]["status"] == "not_affected" and by_id["CVE-2020-2222"]["status"] == "affected"
    assert _http(base + "/api/vex/unknown")[0] == 404
    code, conf = _http(base + "/api/conformance/" + name)
    assert code == 200 and len(conf["regimes"]) == 5
    assert _http(base + "/api/changes/" + name)[1].get("note")


def test_a_prepare_exception_is_named_in_the_record_error_not_hidden_behind_a_bare_message(tmp_path, monkeypatch):
    """AC: BSA-AC-338. A stage that raised is recorded in rec["stage_errors"]; for the prepare stage the record's own error now carries the same text
    ("workspace preparation failed: <ExceptionType>: <message>") so a failed analysis says why instead of an intermittent, undiagnosable bare message."""
    from bts_sbom_app import workspace

    def boom(*a, **kw):
        raise RuntimeError("disk said no")

    monkeypatch.setattr(workspace, "prepare", boom)
    rec = pipeline.run_project(str(tmp_path), work_root=str(tmp_path / "w"), use_llm=False, run_arch=False)
    assert rec["error"] == "workspace preparation failed: RuntimeError: disk said no" == "workspace preparation failed: " + rec["stage_errors"]["prepare"]
    monkeypatch.setattr(workspace, "prepare", lambda *a, **kw: {"ok": False, "error": "refused: not a git url"})
    assert pipeline.run_project(str(tmp_path), work_root=str(tmp_path / "w2"), use_llm=False, run_arch=False)["error"] == "refused: not a git url"

