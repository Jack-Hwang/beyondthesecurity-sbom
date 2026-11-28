"""The eval diagnostics round (C61/C62/C74/C75/C47/C04): the answer-correctness grader against reference content,
the 3-way miss classification, the argument-VALUE check for fired tool calls, the stage bottleneck score, Wilson
intervals on the live-lane proportions, and the rolling-baseline drift - each measured from artifacts the suite
already produces, each honest when the data for it does not exist."""
import json

from bts_sbom_app import chat, evals, evalguard, evals_top10


# ------------------------------------------------------------------ C47: the interval says what the point can support
def test_wilson_interval_bounds_and_the_honest_zero_shape():
    """AC: BSA-AC-1268"""
    ci = evalguard.wilson_interval(24, 26)
    assert ci["lo"] <= 24 / 26 <= ci["hi"] and 0.75 < ci["lo"] and ci["hi"] <= 1.0     # 24/26 is a point; the interval is wider
    ci0 = evalguard.wilson_interval(0, 40)
    assert ci0["lo"] < 0.1 and 0.05 <= ci0["hi"] < 0.2                                 # 0/40 does NOT prove the rate is 0
    assert evalguard.wilson_interval(5, 0) == {"lo": None, "hi": None}                 # no items: no measurement, no fake interval


# ------------------------------------------------------------------ C61: the answer-correctness grader
def test_the_reference_grader_scores_whole_answers_not_just_must_lists(tmp_path):
    """AC: BSA-AC-1268"""
    r = evals_top10.reference_eval()
    assert r["cases"] == len(evals_top10.A2_ROWS) and r["rows"]
    for row in r["rows"]:
        assert isinstance(row["correct"], bool) and isinstance(row["missing"], list)
    assert 0.0 <= r["answer_correctness"] <= 1.0
    # the grader's distinct rule: a bare refusal or a forbidden value fails even with the must-list satisfied
    import types
    bot = types.SimpleNamespace(ask=lambda q, project: {"found": True, "answer": "NTIA 요건을 모두 충족한다. 가짜 CVE-9999 도 있다.",
                                                        "tools": ["conformance"], "citation_accuracy": 1.0, "claims": []})
    real_ask = evals_top10._both_projects
    evals_top10._both_projects = lambda root=None: (bot, {})
    try:
        r2 = evals_top10.reference_eval()
    finally:
        evals_top10._both_projects = real_ask
    assert r2["answer_correctness"] < 1.0 or any(row["missing"] or row["forbidden"] for row in r2["rows"])


# ------------------------------------------------------------------ C62: the 3-way miss classification
def _fixture_report(tmp_path, rows):
    p = tmp_path / "report.json"
    p.write_text(json.dumps({"passed": 0, "rounds": len(rows), "results": rows}, ensure_ascii=False), encoding="utf-8")
    return str(p)


def test_failing_suite_rows_are_classified_not_lumped(tmp_path):
    """AC: BSA-AC-1268"""
    rows = [
        {"feature": "f1", "tool": "overview", "fired": False, "found": True, "tools": ["top_vulns"], "issues": ["expected tool did not fire"]},
        {"feature": "f2", "tool": "overview", "fired": True, "found": False, "tools": ["overview"], "issues": ["found=false"]},
        {"feature": "f3", "tool": "vuln_lookup", "fired": True, "found": True, "tools": ["vuln_lookup"],
         "answer_head": "뭔가 답은 했다", "issues": []},                                   # found + golden expect requests missing -> content_miss
        {"feature": "f4", "tool": "overview", "fired": True, "found": True, "tools": ["overview"],
         "answer_head": "counts of components", "issues": ["weird"]},                     # fits none -> unclassified, named
    ]
    (tmp_path / "chat_features.json").write_text(json.dumps(
        [{"feature": "f1", "tool": "overview"}, {"feature": "f2", "tool": "overview"},
         {"feature": "f3", "tool": "vuln_lookup", "expect": ["requests"]}, {"feature": "f4", "tool": "overview"}], ensure_ascii=False), encoding="utf-8")
    mq = evals_top10.miss_quadrant(_fixture_report(tmp_path, rows), str(tmp_path / "chat_features.json"))
    assert mq["available"] and mq["fails"] == 4                       # f3 counted too: the failure the runner itself could not see
    assert mq["classes"]["tool_miss"]["features"] == ["f1"]
    assert mq["classes"]["empty_result"]["features"] == ["f2"]
    assert mq["classes"]["content_miss"]["features"] == ["f3"]
    assert mq["classes"]["unclassified"]["features"] == ["f4"]
    assert sum(c["n"] for c in mq["classes"].values()) == 4


# ------------------------------------------------------------------ C74: the fired call must carry the RIGHT values
def test_tool_args_are_checked_against_the_golden_expectation(tmp_path):
    """AC: BSA-AC-1268"""
    rows = [
        {"feature": "취약점 조회", "tool": "vuln_lookup", "fired": True, "found": True, "tools": ["vuln_lookup"],
         "tool_args": {"vuln_lookup": {"id": "CVE-2018-18074"}}, "issues": []},          # the measured expectation, met
        {"feature": "취약점 조회2", "tool": "vuln_lookup", "fired": True, "found": True, "tools": ["vuln_lookup"],
         "tool_args": {"vuln_lookup": {"id": "CVE-0000-0000"}}, "issues": []},           # right tool, WRONG id: exactly the C74 defect
    ]
    (tmp_path / "golden.json").write_text(json.dumps([
        {"feature": "취약점 조회", "tool": "vuln_lookup", "expect_args": {"vuln_lookup": {"id": "CVE-2018-18074"}}},
        {"feature": "취약점 조회2", "tool": "vuln_lookup", "expect_args": {"vuln_lookup": {"id": "CVE-2018-18074"}}}], ensure_ascii=False), encoding="utf-8")
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"passed": 2, "rounds": 2, "results": rows}, ensure_ascii=False), encoding="utf-8")
    r = evals_top10.tool_arg_eval(str(report), str(tmp_path / "golden.json"))
    assert r["available"] and r["checked"] == 2 and r["correct"] == 1 and r["arg_accuracy"] == 0.5
    assert r["misses"][0]["want"] == "CVE-2018-18074" and r["misses"][0]["got"] == "CVE-0000-0000"
    # the repo's own golden row carries the measured expectation and the live lane can grade it
    golden = {g["feature"]: g for g in json.load(open("evals/chat_features.json", encoding="utf-8"))}
    assert golden["취약점 조회"]["expect_args"]["vuln_lookup"]["id"] == "CVE-2018-18074"


# ------------------------------------------------------------------ C75: the stage bottleneck
def test_the_bottleneck_is_the_median_share_winner(tmp_path):
    """AC: BSA-AC-1268"""
    rows = [{"feature": "a", "stage_ms": {"route": 1, "retrieval": 1, "verify": 6, "generate": 2}, "issues": []},
            {"feature": "b", "stage_ms": {"route": 1, "retrieval": 2, "verify": 5, "generate": 2}, "issues": []}]
    r = evals_top10.stage_bottleneck(_fixture_report(tmp_path, rows))
    assert r["available"] and r["rows"] == 2 and r["bottleneck"] == "verify" and r["median_share"]["verify"] > 0.5
    empty = evals_top10.stage_bottleneck(_fixture_report(tmp_path, [{"feature": "x", "stage_ms": {}, "issues": []}]))
    assert empty["rows"] == 0 and "stage_ms" in empty["note"]


# ------------------------------------------------------------------ C04: the rolling baseline
def test_the_rolling_baseline_names_drift_and_cannot_pass_without_history(tmp_path):
    """AC: BSA-AC-1268"""
    hist = tmp_path / "hist.jsonl"
    with open(hist, "w", encoding="utf-8") as fh:
        for v in (0.95, 0.96, 0.94, 0.95):
            fh.write(json.dumps({"scores": {"grounding_f": v}}) + "\n")
    r = evals_top10.rolling_baseline({"grounding_f": 0.90}, str(hist))
    assert r["history_runs"] == 4 and r["median"]["grounding_f"] == 0.95
    assert r["drift"] and "0.900 is below" in r["drift"][0] and r["pass"] is False
    ok = evals_top10.rolling_baseline({"grounding_f": 0.95}, str(hist))
    assert ok["pass"] is True and ok["drift"] == []
    none = evals_top10.rolling_baseline({"grounding_f": 0.95}, str(tmp_path / "nothing.jsonl"))
    assert none["pass"] is False and none["history_runs"] == 0            # no history is NOT a pass - it is "cannot tell yet"


# ------------------------------------------------------------------ the turn itself carries the diagnostics inputs
def test_the_chat_turn_echoes_stage_timings_and_fired_arguments():
    """AC: BSA-AC-1268"""
    bot = chat.Chatbot(evals.build_index(), {"demo": evals.synthetic_project()}, None)
    r = bot.ask("CVE-2018-18074 취약점 상세 알려줘", project="demo")
    assert isinstance(r.get("stage_ms"), dict) and set(r["stage_ms"]) == {"route", "retrieval", "verify", "generate"}
    assert all(isinstance(v, int) and v >= 0 for v in r["stage_ms"].values())
    assert r["tool_args"]["vuln_lookup"]["id"] == "CVE-2018-18074"        # the echoed value the arg eval grades
