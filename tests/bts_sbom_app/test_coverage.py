"""Decision coverage graph (ARTEX's dual-graph concept, reimplemented from scratch): verdict per advisory, worklist, lineage, chains."""
from __future__ import annotations

import datetime
import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

import pytest

from bts_sbom_app import chat, cli, coverage, evals, server
from bts_sbom_app.util import write_json

TODAY = datetime.date(2026, 11, 20)


def _rec():
    """synthetic demo (1 advisory, verified plan) plus 4 more advisories so every verdict is exercised."""
    rec = evals.synthetic_project()
    rec["schema"] = "bts-sbom.project.v1"
    rec["vulns"] = rec["vulns"] + [
        {"id": "CVE-2020-1111", "package": "requests", "version": "2.19.1", "severity": "MEDIUM", "summary": "x"},
        {"id": "CVE-2021-2222", "package": "leftpad", "version": "1.0.0", "severity": "LOW", "summary": "y"},
        {"id": "CVE-2022-3333", "package": "leftpad", "version": "1.0.0", "severity": "HIGH", "summary": "z"},
        {"id": "CVE-2023-4444", "package": "leftpad", "version": "1.0.0", "severity": "LOW", "summary": "w"},
    ]
    return rec


def _store():
    return {
        "CVE-2020-1111": {"status": "false-positive", "note": "the value is parsed but never reaches the vulnerable path",
                          "justification": "vulnerable_code_not_in_execute_path", "by": "kim", "ts": "2026-11-19T10:00:00+09:00"},
        "CVE-2021-2222": {"status": "false-positive", "note": "short"},                                     # rejected: no justification
        "CVE-2023-4444": {"status": "accepted", "note": "risk accepted for the legacy pin through year end",
                          "expires": "2026-11-01", "by": "lee", "ts": "2026-10-01T09:00:00+09:00"},        # expired on TODAY
    }


def test_verdicts_percent_worklist_and_chains():
    """AC: BSA-AC-219"""
    c = coverage.build(_rec(), _store(), today=TODAY)
    assert c["advisories"] == 5 and c["verdicts"] == {"decided": 1, "planned": 1, "rejected": 1, "expired": 1, "unhandled": 1}
    assert c["handled_pct"] == 40.0 and len(c["lineage"]) == 3 and len(c["chains"]) == 5
    wl = {r["id"]: r["verdict"] for r in c["worklist"]}
    assert wl == {"CVE-2018-18074": "planned", "CVE-2021-2222": "rejected", "CVE-2022-3333": "unhandled", "CVE-2023-4444": "expired"}
    assert c["worklist"][0]["id"] == "CVE-2022-3333"                                                   # nothing recorded sorts first
    ch = {x["id"]: [s["step"] for s in x["chain"]] for x in c["chains"]}
    assert ch["CVE-2018-18074"] == ["finding", "plan", "outcome"] and ch["CVE-2020-1111"] == ["finding", "decision", "outcome"]
    md = coverage.to_md(c)
    assert "Decision coverage of demo" in md and "Decision lineage" in md and "unhandled" in md
    comp = coverage.compact(c)
    assert comp["schema"] == "bts-sbom.coverage.v1" and comp["verdicts"]["decided"] == 1 and "lineage" not in comp


def test_rejected_and_expired_decisions_stay_open_and_are_anchored():
    """AC: BSA-AC-220"""
    c = coverage.build(_rec(), _store(), today=TODAY)
    by = {r["id"]: r for r in c["worklist"]}
    assert by["CVE-2021-2222"]["verdict"] == "rejected" and "justification" in by["CVE-2021-2222"]["issue"]
    assert by["CVE-2023-4444"]["verdict"] == "expired" and "2026-11-01" in by["CVE-2023-4444"]["issue"]
    assert all(r["id"] != "CVE-2020-1111" for r in c["worklist"])                                      # the standing decision handles it
    lin = {l["advisory"]: l for l in c["lineage"]}
    assert lin["CVE-2020-1111"]["state"] == "not_affected" and lin["CVE-2020-1111"]["by"] == "kim"
    assert lin["CVE-2023-4444"]["state"] == "expired" and lin["CVE-2023-4444"]["ts"].startswith("2026-10-01")
    assert len({l["key"] for l in c["lineage"]}) == 3                                                  # one anchor per applied decision


def test_a_scoped_decision_covers_only_its_package():
    """AC: BSA-AC-222"""
    rec = _rec()
    scoped = {"CVE-2020-1111@leftpad": {"status": "false-positive", "note": "parsed input only, never executed on this package",
                                        "justification": "component_not_present"}}
    c = coverage.build(rec, scoped, today=TODAY)
    assert {r["id"]: r["verdict"] for r in c["worklist"]}["CVE-2020-1111"] == "unhandled"              # scoped to another package
    c2 = coverage.build(rec, {"CVE-2020-1111": {"status": "false-positive", "note": "parsed input only, never executed",
                                                "justification": "vulnerable_code_not_in_execute_path"}}, today=TODAY)
    assert c2["verdicts"]["decided"] == 1
    assert all(x["chain"][0]["step"] == "finding" and x["chain"][-1]["step"] == "outcome" for x in c2["chains"])


def test_cli_api_and_chat_answer_from_the_same_graph(tmp_path, capsys):
    """AC: BSA-AC-221"""
    ev = tmp_path / "ev" / "demo"
    ev.mkdir(parents=True)
    rec = _rec()
    write_json(str(ev / "demo.json"), rec)
    write_json(str(tmp_path / "ev" / ".triage.json"), _store())                                       # the store lives in the evidence root
    assert cli.main(["coverage", "demo", "--evidence", str(tmp_path / "ev")]) == 0
    out = capsys.readouterr().out
    assert "Decision coverage of demo" in out and "unhandled" in out and "Decision lineage" in out
    st = server.State(evals.repo_root(), str(tmp_path / "ev"), None)
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    try:
        with urllib.request.urlopen("http://127.0.0.1:%d/api/coverage/demo" % httpd.server_address[1], timeout=10) as r:
            api = json.loads(r.read())
    finally:
        httpd.shutdown()
    assert api["verdicts"] == coverage.build(rec, _store(), today=TODAY)["verdicts"] and api["handled_pct"] == 40.0
    bot = chat.Chatbot(evals.build_index(), {"demo": rec}, None, None, _store())
    ans = bot.ask("커버리지 어때 아직 안 정해진 취약점 있어?", project="demo")
    assert "coverage" in ans["tools"] and "5 unhandled" in ans["answer"] or "1 unhandled" in ans["answer"]
    assert "Coverage counts only what is recorded" in ans["answer"]
