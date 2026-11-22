"""NL2SQL safe lane: validator gates, 4-state executor, error-attached self-correction, EX eval (MetaNet 3-2)."""
from __future__ import annotations

import json
import sqlite3

import pytest

from bts_sbom_app import llm, nl2sql


VULN_ROWS = [  # (ecosystem, vuln_id, summary)
    ("PyPI", "CVE-2018-18074", "Insecure credential handling on redirect"),
    ("PyPI", "GHSA-x84v-xcm2-53pg", "requests redirect credential leak"),
    ("npm", "GHSA-aaaa-bbbb-cccc", "leftpad prototype pollution"),
    ("npm", "CVE-2021-1", "lodash prototype pollution"),
    ("PyPI", "CVE-2020-9999", "flask open redirect"),
    ("PyPI", "GHSA-zzzz-yyyy-xxxx", "requests cookie exposure"),
]
PKG_ROWS = [  # (ecosystem, name, vuln_id)
    ("PyPI", "requests", "CVE-2018-18074"), ("PyPI", "requests", "GHSA-x84v-xcm2-53pg"),
    ("PyPI", "requests", "GHSA-zzzz-yyyy-xxxx"), ("npm", "leftpad", "GHSA-aaaa-bbbb-cccc"),
    ("npm", "lodash", "CVE-2021-1"), ("PyPI", "flask", "CVE-2020-9999"),
]


@pytest.fixture()
def osv_db(tmp_path):
    path = str(tmp_path / "osv.db")
    conn = sqlite3.connect(path)
    conn.execute("CREATE TABLE vulns (ecosystem TEXT, vuln_id TEXT, vuln_json TEXT, PRIMARY KEY (ecosystem, vuln_id))")
    conn.execute("CREATE TABLE pkg_map (ecosystem TEXT, name TEXT, vuln_id TEXT, PRIMARY KEY (ecosystem, name, vuln_id))")
    conn.executemany("INSERT INTO vulns VALUES (?,?,?)",
                     [(e, i, json.dumps({"id": i, "summary": s})) for e, i, s in VULN_ROWS])
    conn.executemany("INSERT INTO pkg_map VALUES (?,?,?)", PKG_ROWS)
    conn.commit()
    conn.close()
    return path


def test_validator_blocks_writes_and_enforces_limit():
    """AC: BSA-AC-510"""
    for bad in ["DELETE FROM vulns", "insert into vulns values (1)",
                "SELECT 1; DROP TABLE vulns", "WITH x AS (DELETE FROM vulns) SELECT 1",
                "PRAGMA journal_mode", "ATTACH DATABASE 'x' AS y"]:
        with pytest.raises(nl2sql.SqlError) as ei:
            nl2sql.validate(bad)
        assert ei.value.category in ("business", "validation")
    assert nl2sql.validate("SELECT * FROM vulns").endswith("LIMIT 200")          # missing -> appended
    assert nl2sql.validate("SELECT * FROM vulns LIMIT 999", max_rows=200).endswith("LIMIT 200")  # over -> reduced
    assert nl2sql.validate("SELECT * FROM vulns LIMIT 5") == "SELECT * FROM vulns LIMIT 5"       # kept


def test_executor_four_states(osv_db):
    """AC: BSA-AC-511"""
    ok = nl2sql.run_readonly("SELECT COUNT(*) FROM vulns", osv_db)
    assert ok["status"] == "success" and ok["rows"] == [(6,)]
    empty = nl2sql.run_readonly("SELECT * FROM pkg_map WHERE name = 'nope'", osv_db)
    assert empty == {"status": "empty_result", "rows": []}                        # 0 rows is never an error
    part = nl2sql.run_readonly("SELECT * FROM vulns ORDER BY vuln_id", osv_db, max_rows=2)
    assert part["status"] == "partial_result" and part["truncated"] is True and len(part["rows"]) == 2
    bad = nl2sql.run_readonly("SELECT * FROM table_that_does_not_exist", osv_db)
    assert bad["status"] == "access_failure" and bad["error"]["isRetryable"] is True
    write = nl2sql.run_readonly("UPDATE vulns SET vuln_id = 'x'", osv_db)         # DB itself refuses (query_only+ro URI)
    assert write["status"] == "access_failure"


def test_self_correction_attaches_error_then_stops_on_repeat(osv_db, monkeypatch):
    """AC: BSA-AC-512"""
    calls = []

    def transport(url, headers, body):
        calls.append(body["messages"][-1]["content"])
        sql = "SELECT nope FROM vulns" if len(calls) == 1 else "SELECT COUNT(*) AS vuln_count FROM vulns"
        payload = json.dumps({"sql": sql, "tables": ["vulns"], "assumptions": [], "clarification_needed": None},
                             ensure_ascii=False)
        return 200, json.dumps({"choices": [{"message": {"content": payload}}],
                                "usage": {"prompt_tokens": 4, "completion_tokens": 6}})

    monkeypatch.setattr(llm, "TRANSPORT", transport)
    c = llm.ChatClient("k")
    res = nl2sql.answer("전체 취약점은 몇 개야?", osv_db, client=c)
    assert res["status"] == "success" and res["rows"] == [(6,)] and res["source"] == "llm" and res["attempts"] == 2
    assert len(calls) == 2 and "nope" in calls[1] and "실패" in calls[1]           # the concrete error rode along
    # same error twice -> immediate stop (2 attempts), reported as access_failure with the reason
    calls.clear()

    def transport2(url, headers, body):
        calls.append(body["messages"][-1]["content"])
        payload = json.dumps({"sql": "SELECT nope FROM vulns", "tables": ["vulns"], "assumptions": [],
                              "clarification_needed": None}, ensure_ascii=False)
        return 200, json.dumps({"choices": [{"message": {"content": payload}}],
                                "usage": {"prompt_tokens": 4, "completion_tokens": 6}})

    monkeypatch.setattr(llm, "TRANSPORT", transport2)
    res2 = nl2sql.answer("전체 취약점은 몇 개야?", osv_db, client=llm.ChatClient("k"))
    assert res2["status"] == "access_failure" and res2["attempts"] == 2 and len(calls) == 2
    assert res2["error"]["errorCategory"] == "transient"


def test_ex_eval_30_golden_above_gate(osv_db):
    """AC: BSA-AC-513"""
    rep = nl2sql.nl2sql_eval(osv_db)
    assert rep["cases"] == 30
    assert rep["ex"] >= 0.8
    assert rep["misses"] == [] or rep["ex"] >= 0.8
    template_miss = [m for m in rep["misses"]]
    assert template_miss == []                                                     # template lane should be exact here


def test_offline_lane_without_client_answers_by_template(osv_db):
    """AC: BSA-AC-513"""
    r = nl2sql.answer("requests 패키지의 취약점 목록을 보여줘", osv_db)
    assert r["status"] == "success" and r["source"] == "template" and len(r["rows"]) == 3
    miss = nl2sql.answer("오늘 저녁 메뉴 추천해줘", osv_db)                         # out of scope -> honest miss
    assert miss["status"] == "access_failure" and miss["error"]["message"]
