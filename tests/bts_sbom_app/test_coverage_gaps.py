"""Coverage gaps: a partial scan says so in every answer instead of reading "nothing found" as "nothing there"."""
from __future__ import annotations

import copy

from bts_sbom_app import chat, evals, fleet, gaps, handoff

CORE_STATUSES = ("target_missing", "empty_project", "unsupported_manifest", "parse_failed", "query_missing", "network_failure", "stale_db")


def _rec(**engine):
    rec = copy.deepcopy(evals.synthetic_project())
    rec["engine"] = {"core": "0", "sources": [], "unsupported": [], "status": {"mode": "online", "unqueried": 0, "version_unresolved": 0,
                                                                              "network_fallback_offline": 0},
                     "data_status": "complete", "vulnerability_presence": "found", "notes": []}
    for k, v in engine.items():
        if k == "status":
            rec["engine"]["status"].update(v)
        else:
            rec["engine"][k] = v
    return rec


def _ask(rec, q, project="demo"):
    return chat.Chatbot(evals.build_index(), {"demo": rec}).ask(q, project=project)


def test_a_complete_online_scan_has_no_gap():
    """AC: BSA-AC-1000"""
    rec = _rec()
    assert gaps.of(rec) == [] and gaps.status(rec) == "complete" and gaps.lines(rec) == []
    assert gaps.summary(rec) == {"status": "complete", "gaps": [], "note": ""} and gaps.envelope(rec) is None


def test_each_non_complete_core_status_is_one_gap_and_an_unknown_value_is_never_invented():
    """AC: BSA-AC-1001"""
    for ds in CORE_STATUSES:
        g = gaps.of(_rec(data_status=ds))
        assert [x["code"] for x in g] == ["data_status:" + ds] and g[0]["source"] == "engine.data_status", ds
    assert gaps.of(_rec(data_status="something-new")) == [] and gaps.of(_rec(data_status=None)) == []
    unknown = gaps.of(_rec(vulnerability_presence="unknown"))
    assert [x["code"] for x in unknown] == ["presence_unknown"]


def test_every_recorded_limit_of_a_run_becomes_a_named_gap_in_a_fixed_order():
    """AC: BSA-AC-1002"""
    rec = _rec(status={"mode": "offline", "unqueried": 3, "version_unresolved": 1, "network_fallback_offline": 2},
               unsupported=["a.lock", "b.lock"])
    rec["stage_errors"] = {"licenses": "TimeoutError: x"}
    g = gaps.of(rec)
    assert [x["code"] for x in g] == ["mode:offline", "network_fallback_offline", "unqueried", "version_unresolved", "unsupported_files", "stage_errors"]
    assert all(x["source"] and x["detail"] for x in g) and "2 file(s)" in g[4]["detail"] and "licenses" in g[5]["detail"]
    assert gaps.lines(rec)[0].startswith("Coverage of demo is partial") and len(gaps.lines(rec)) == 1 + len(g)


def test_an_older_record_without_engine_facts_has_no_gap():
    """AC: BSA-AC-1003"""
    rec = copy.deepcopy(evals.synthetic_project())
    assert "engine" not in rec and gaps.of(rec) == [] and gaps.status(rec) == "complete"
    rec["engine"] = {"status": None, "unsupported": None}
    assert gaps.of(rec) == []


def test_an_answer_about_a_partial_scan_carries_the_gap_and_a_complete_scan_does_not():
    """AC: BSA-AC-1004"""
    partial = _ask(_rec(status={"mode": "offline"}), "취약점 현황 요약해줘")
    assert partial["found"] and "Coverage of demo is partial" in partial["answer"] and "Coverage gap [mode:offline]" in partial["answer"]
    assert partial["citation_accuracy"] == 1.0 and partial["coverage"]["status"] == "partial" and partial["coverage"]["gaps"][0]["code"] == "mode:offline"
    ok = _ask(_rec(), "취약점 현황 요약해줘")
    assert "Coverage" not in ok["answer"] and ok["coverage"] == {"status": "complete", "gaps": [], "note": ""}


def test_no_finding_is_followed_by_the_gap_and_the_annotation_is_added_once():
    """AC: BSA-AC-1005"""
    rec = _rec(status={"unqueried": 4}, data_status="query_missing")
    rec["vulns"] = []
    r = _ask(rec, "취약점 현황 요약해줘")
    assert "overview" in r["tools"] and "top_vulns" in r["tools"] and "No vulnerabilities were found in demo." in r["answer"]
    assert r["answer"].count("Coverage of demo is partial") == 1 and "Coverage gap [unqueried]" in r["answer"]


def test_an_absent_advisory_id_in_a_partial_scan_is_not_presented_as_clean():
    """AC: BSA-AC-1006"""
    r = _ask(_rec(status={"mode": "offline"}), "CVE-2099-0001 영향 있어")
    assert "is not present in the analysed findings" in r["answer"] and "Coverage gap [mode:offline]" in r["answer"]
    clean = _ask(_rec(), "CVE-2099-0001 영향 있어")
    assert "is not present in the analysed findings" in clean["answer"] and "Coverage" not in clean["answer"]


def test_a_project_without_a_match_is_not_verified_when_its_scan_was_partial():
    """AC: BSA-AC-1007"""
    complete, partial, hit = _rec(), _rec(status={"mode": "offline"}), _rec()
    complete["vulns"], partial["vulns"] = [], []
    projects = {"a-clean": complete, "b-offline": partial, "c-hit": hit}
    res = fleet.affected(projects, vuln_id="CVE-2018-18074")
    assert [p["project"] for p in res["projects"]] == ["c-hit"] and res["not_found_in"] == ["a-clean", "b-offline"]
    assert res["not_verified"] == [{"project": "b-offline", "gaps": ["mode:offline"]}]
    lines = chat._affected(projects, {"id": "CVE-2018-18074"})
    assert any("Not verified for b-offline" in x and "mode:offline" in x for x in lines) and not any("a-clean" in x and "Not verified" in x for x in lines)
    none = chat._affected({"b-offline": partial}, {"id": "CVE-2018-18074"})
    assert "was not found in any of the 1 analysed projects" in none[0] and "Not verified for b-offline" in none[1]


def test_a_partial_record_becomes_a_recoverable_envelope_and_a_complete_one_none():
    """AC: BSA-AC-1008"""
    rec = _rec(status={"unqueried": 2})
    rec["stage_errors"] = {"arch": "OSError: x"}
    rec["timings"] = {"prepare": 0.1, "analyze": 1.2, "arch": 0.3}
    env = gaps.envelope(rec)
    assert env["error_type"] == "coverage_gap" and env["severity"] == "recoverable" and env["completed_steps"] == ["analyze", "prepare"]
    assert "never queried" in env["coverage_gap"] and env["partialResult"] == {"components": 2, "findings": 1}
    assert env["severity"] in handoff.SEVERITIES and gaps.envelope(_rec()) is None


def test_the_annotation_adds_nothing_when_the_scan_was_complete_or_no_vulnerability_tool_ran():
    """AC: BSA-AC-1009"""
    results = [{"tool": "overview", "source": "s", "lines": ["x"], "trust": "tool"}]
    assert chat.annotate_gaps(_rec(), copy.deepcopy(results))[0]["lines"] == ["x"]
    assert chat.annotate_gaps(None, copy.deepcopy(results))[0]["lines"] == ["x"]
    other = [{"tool": "license", "source": "s", "lines": ["y"], "trust": "tool"}]
    assert chat.annotate_gaps(_rec(status={"mode": "offline"}), other)[0]["lines"] == ["y"]
    two = [dict(results[0]), {"tool": "top_vulns", "source": "t", "lines": ["z"], "trust": "tool"}]
    out = chat.annotate_gaps(_rec(status={"mode": "offline"}), two)
    assert len(out[0]["lines"]) == 3 and out[1]["lines"] == ["z"]


def test_the_report_of_a_new_analysis_names_its_gaps():
    """AC: BSA-AC-1010"""
    rec = _rec(status={"mode": "offline"})
    text = "\n".join(chat._analysis_report(rec))
    assert "Coverage gap [mode:offline]" in text
    assert "Coverage" not in "\n".join(chat._analysis_report(_rec()))
