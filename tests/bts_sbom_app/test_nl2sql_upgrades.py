"""NL2SQL upgrades: shape validation, few-shot examples, LLM-lane eval, snapshot freshness (MetaNet 3-2 bundle).

Owns bts_sbom_app/nl2sql.py only - fixtures here are copied/trimmed, not imported, from test_nl2sql.py so this
file never needs to touch that one.
"""
from __future__ import annotations

import json
import sqlite3

import pytest

from bts_sbom_app import llm, nl2sql


VULN_ROWS = [  # (ecosystem, vuln_id, summary) - same shape as test_nl2sql.py's fixture
    ("PyPI", "CVE-2018-18074", "Insecure credential handling on redirect"),
    ("PyPI", "GHSA-x84v-xcm2-53pg", "requests redirect credential leak"),
    ("npm", "GHSA-aaaa-bbbb-cccc", "leftpad prototype pollution"),
    ("npm", "CVE-2021-1", "lodash prototype pollution"),
    ("PyPI", "CVE-2020-9999", "flask open redirect"),
    ("PyPI", "GHSA-zzzz-yyyy-xxxx", "requests cookie exposure"),
]
PKG_ROWS = [
    ("PyPI", "requests", "CVE-2018-18074"), ("PyPI", "requests", "GHSA-x84v-xcm2-53pg"),
    ("PyPI", "requests", "GHSA-zzzz-yyyy-xxxx"), ("npm", "leftpad", "GHSA-aaaa-bbbb-cccc"),
    ("npm", "lodash", "CVE-2021-1"), ("PyPI", "flask", "CVE-2020-9999"),
]
IMPORT_META = [("PyPI", 4, 1732000000.0), ("npm", 2, 1731800000.0)]


def _make_db(path, vuln_rows=VULN_ROWS, pkg_rows=PKG_ROWS, import_meta=None):
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE vulns (ecosystem TEXT, vuln_id TEXT, vuln_json TEXT, PRIMARY KEY (ecosystem, vuln_id))")
    conn.execute("CREATE TABLE pkg_map (ecosystem TEXT, package_name TEXT, vuln_id TEXT, "
                 "PRIMARY KEY (ecosystem, package_name, vuln_id))")
    conn.execute("CREATE TABLE import_meta (ecosystem TEXT PRIMARY KEY, vuln_count INTEGER, imported_at REAL)")
    conn.executemany("INSERT INTO vulns VALUES (?,?,?)",
                     [(e, i, json.dumps({"id": i, "summary": s})) for e, i, s in vuln_rows])
    conn.executemany("INSERT INTO pkg_map VALUES (?,?,?)", pkg_rows)
    if import_meta:
        conn.executemany("INSERT INTO import_meta VALUES (?,?,?)", import_meta)
    conn.commit()
    conn.close()


@pytest.fixture()
def osv_db(tmp_path):
    path = str(tmp_path / "osv.db")
    _make_db(path, import_meta=IMPORT_META)
    return path


def _payload_transport(payload_or_list):
    """A TRANSPORT stub that replies with payload_or_list[call_index] (or the single payload every time)."""
    calls = []

    def transport(url, headers, body):
        calls.append(body["messages"][-1]["content"])
        payload = payload_or_list[len(calls) - 1] if isinstance(payload_or_list, list) else payload_or_list
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(payload, ensure_ascii=False)}}],
                                "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    transport.calls = calls
    return transport


# -- C17: structured-output shape gate feeds the existing capped self-correction loop ------------------

def test_malformed_generation_shapes_self_correct_to_access_failure(osv_db, monkeypatch):
    """AC: BSA-AC-1160"""
    bad_payloads = [
        {"sql": 123, "tables": [], "assumptions": [], "clarification_needed": None},               # sql not str
        {"sql": "SELECT 1", "tables": "vulns", "assumptions": [], "clarification_needed": None},   # tables not list
        {"sql": "SELECT 1", "tables": [], "assumptions": [], "clarification_needed": None,         # unknown key
         "extra_key": 1},
    ]
    uncaught = 0
    for bad in bad_payloads:
        transport = _payload_transport(bad)
        monkeypatch.setattr(llm, "TRANSPORT", transport)
        client = llm.ChatClient("k")
        try:
            res = nl2sql.answer("전체 취약점은 몇 개야?", osv_db, client=client)
        except Exception:
            uncaught += 1
            continue
        assert res["status"] == "access_failure"
        assert res["attempts"] <= 3
        assert res["error"]["errorCategory"] == "validation"
    assert uncaught == 0                           # 3 of 3 malformed-shape regressions end in access_failure


def test_shape_error_self_corrects_to_success_on_retry(osv_db, monkeypatch):
    """AC: BSA-AC-1161"""
    first_bad = {"sql": "SELECT 1", "tables": [], "assumptions": [], "clarification_needed": None, "bogus": True}
    then_good = {"sql": "SELECT COUNT(*) AS vuln_count FROM vulns", "tables": ["vulns"], "assumptions": [],
                 "clarification_needed": None}
    transport = _payload_transport([first_bad, then_good])
    monkeypatch.setattr(llm, "TRANSPORT", transport)
    res = nl2sql.answer("전체 취약점은 몇 개야?", osv_db, client=llm.ChatClient("k"))
    assert res["status"] == "success" and res["rows"] == [(6,)]
    assert res["attempts"] == 2 and len(transport.calls) == 2
    # the concrete shape error (not a crash) rode along in the regeneration prompt
    assert "알 수 없는 키" in transport.calls[1] and "실패" in transport.calls[1]


# -- C57: curated few-shot pool, token-overlap selection, disjoint from the golden set ------------------

def test_select_examples_ranks_by_token_overlap_and_clamps_k():
    """AC: BSA-AC-1162"""
    q = "pyyaml 패키지의 취약점 목록을 보여줘"
    top3 = nl2sql.select_examples(q, k=3)
    assert len(top3) == 3
    assert top3[0]["question"] == "pyyaml 패키지에 걸린 취약점 알려줘"     # highest token overlap (pyyaml+취약점)
    assert len(nl2sql.select_examples(q, k=1)) == 2                     # k clamped up to the 2-4 band
    assert len(nl2sql.select_examples(q, k=99)) == 4                    # k clamped down to the 2-4 band


def test_generate_sql_prompt_folds_in_the_selected_examples(osv_db, monkeypatch):
    """AC: BSA-AC-1163"""
    captured = {}

    def transport(url, headers, body):
        captured["system"] = body["messages"][0]["content"]
        payload = {"sql": "SELECT COUNT(*) AS vuln_count FROM vulns", "tables": ["vulns"],
                   "assumptions": [], "clarification_needed": None}
        return 200, json.dumps({"choices": [{"message": {"content": json.dumps(payload, ensure_ascii=False)}}],
                                "usage": {"prompt_tokens": 1, "completion_tokens": 1}})
    monkeypatch.setattr(llm, "TRANSPORT", transport)
    q = "pyyaml 패키지의 취약점 목록을 보여줘"
    nl2sql.answer(q, osv_db, client=llm.ChatClient("k"))
    selected = nl2sql.select_examples(q)
    assert 2 <= len(selected) <= 4
    for ex in selected:                            # 3 of 3 selected examples found verbatim in the sent prompt
        assert ex["question"] in captured["system"]
        assert ex["sql"] in captured["system"]


def test_nl2sql_examples_disjoint_from_golden_set():
    """AC: BSA-AC-1164"""
    golden_qs = {c["question"] for c in nl2sql._default_golden()}
    examples = nl2sql.NL2SQL_EXAMPLES
    leaks = [ex["question"] for ex in examples if ex["question"] in golden_qs]
    assert leaks == []                              # 0 of 18 example questions leak into the 30-question golden set
    assert 15 <= len(examples) <= 25


# -- C30: nl2sql_eval exercises the LLM lane too, with a deterministic stub client -----------------------

class _EvalStubClient:
    """Deterministic stand-in for an LLM: returns the known-correct reference SQL for most golden questions
    and a deliberately wrong filter for a few (so ex_llm is actually measured, not copied from ex_template) -
    never a real network/LLM call."""

    def __init__(self, sql_by_question, wrong_questions):
        self._by_q = sql_by_question
        self._wrong = set(wrong_questions)

    def complete(self, system, user, max_tokens, json_mode=True):
        q = user.split("\n\n")[0]
        sql = self._by_q.get(q)
        if q in self._wrong or sql is None:
            sql = "SELECT COUNT(*) AS vuln_count FROM vulns WHERE ecosystem = 'nope-ecosystem-xyz'"
        payload = {"sql": sql, "tables": ["vulns"], "assumptions": [], "clarification_needed": None}
        return json.dumps(payload, ensure_ascii=False)


def test_nl2sql_eval_reports_ex_llm_alongside_ex_template(osv_db):
    """AC: BSA-AC-1165"""
    golden = nl2sql._default_golden()
    by_q = {c["question"]: c["reference_sql"] for c in golden}
    wrong = {golden[0]["question"], golden[10]["question"], golden[20]["question"]}
    client = _EvalStubClient(by_q, wrong)
    rep = nl2sql.nl2sql_eval(osv_db, client=client)
    assert rep["cases"] == 30
    assert rep["ex_template"] == 1.0                      # unchanged offline baseline (measured, not assumed)
    assert rep["ex_llm"] == 0.9                           # 27 of 30 LLM-lane hits: 3 deliberately wrong
    assert rep["ex_llm"] != rep["ex_template"]             # distinct metric, not an alias
    assert len(rep["llm_misses"]) == 3
    assert sum(rep["llm_status_breakdown"].values()) == 30
    rep_offline = nl2sql.nl2sql_eval(osv_db)               # client=None: old contract, no stray LLM accounting
    assert "ex_llm" not in rep_offline and "llm_misses" not in rep_offline


def test_eval_does_not_count_both_sides_access_failure_as_a_hit(osv_db):
    """AC: BSA-AC-1165"""
    # a reference_sql that cannot execute on its own (bad column) must never be scored a match just because
    # the candidate also honestly misses (no template, no client) - both land on access_failure/[] but that
    # is NOT evaluable agreement, it is two independent failures.
    golden = [{"question": "존재하지 않는 질문 패턴 xyz123", "reference_sql": "SELECT no_such_col FROM vulns"}]
    rep = nl2sql.nl2sql_eval(osv_db, golden=golden)
    assert rep["cases"] == 1
    assert rep["ex_template"] == 0.0                        # was a false 1.0 before the fix
    assert len(rep["misses"]) == 1
    assert rep["misses"][0]["status"] == "access_failure"
    assert rep["misses"][0]["stage"] == "both_failed"       # _eval_stage names which side(s) actually failed


def test_package_group_by_golden_cases_use_the_real_pkg_map_schema(osv_db):
    """AC: BSA-AC-1165"""
    # pre-existing defect: route()'s '패키지별' template and its golden reference_sql both selected a 'name'
    # column that does not exist in pkg_map (only ecosystem/package_name/vuln_id do), so these 2 golden cases
    # always landed on access_failure on BOTH sides and the (pre-fix) hit logic counted that as a match -
    # this proves they now actually execute and return real grouped rows, honestly.
    golden = [c for c in nl2sql._default_golden() if c["question"].startswith("패키지별")]
    assert len(golden) == 2
    for c in golden:
        assert "package_name" in c["reference_sql"] and ", name" not in c["reference_sql"]
        ref = nl2sql.run_readonly(nl2sql.validate(c["reference_sql"]), osv_db)
        assert ref["status"] == "success" and ref["rows"]           # genuinely executes now, not access_failure
        res = nl2sql.answer(c["question"], osv_db)
        assert res["status"] == "success" and res["source"] == "template" and res["rows"]
    rep = nl2sql.nl2sql_eval(osv_db, golden=golden)
    assert rep["ex_template"] == 1.0 and rep["misses"] == []        # now a genuine 1.0, not a hidden-failure 1.0


# -- C21: import_meta freshness attached per ecosystem referenced, honestly ------------------------------

def test_as_of_single_ecosystem_known_and_never_imported(tmp_path):
    """AC: BSA-AC-1166"""
    db_known = str(tmp_path / "known.db")
    _make_db(db_known, vuln_rows=[("PyPI", "CVE-2018-18074", "x")], pkg_rows=[],
             import_meta=[("PyPI", 1, 1732000000.0)])
    res = nl2sql.answer("생태계 목록을 알려줘", db_known)
    assert res["status"] == "success"
    assert res["as_of"] == {"PyPI": nl2sql._iso_date(1732000000.0)}

    db_missing = str(tmp_path / "missing.db")              # ecosystem present in the data, never in import_meta
    _make_db(db_missing, vuln_rows=[("RubyGems", "CVE-2099-1", "y")], pkg_rows=[], import_meta=[])
    res2 = nl2sql.answer("생태계 목록을 알려줘", db_missing)
    assert res2["status"] == "success"
    assert res2["as_of"] == {"RubyGems": None}              # referenced but never imported -> explicit None


def test_as_of_multi_ecosystem(osv_db):
    """AC: BSA-AC-1167"""
    res = nl2sql.answer("생태계별 취약점 수를 보여줘", osv_db)
    assert res["status"] == "success"
    assert res["as_of"] == {"PyPI": nl2sql._iso_date(1732000000.0), "npm": nl2sql._iso_date(1731800000.0)}
    assert len(res["as_of"]) == 2                           # 2 of 2 referenced ecosystems dated


def test_as_of_unknown_ecosystem_stated_explicitly(osv_db):
    """AC: BSA-AC-1168"""
    res = nl2sql.answer("전체 취약점은 몇 개야?", osv_db)              # COUNT(*) exposes no ecosystem column
    assert res["status"] == "success"
    assert "as_of" in res                                   # always present, never silently dropped
    assert res["as_of"] == {"unknown": None}                # stated explicitly, not omitted


def test_ecosystems_in_result_column_detection():
    """AC: BSA-AC-1169"""
    assert nl2sql._ecosystems_in_result(["ecosystem", "cnt"], [("PyPI", 3), ("npm", 1)]) == ["PyPI", "npm"]
    assert nl2sql._ecosystems_in_result(["vuln_count"], [(6,)]) is None             # no ecosystem column -> unknown
    assert nl2sql._ecosystems_in_result(["ecosystem"], []) == []                    # column present, 0 rows -> known-empty
