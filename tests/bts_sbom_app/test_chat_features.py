"""The chat-driven feature suite: one conversational question per chat-runnable feature, run against the live
service by scripts/chat_features_run.py (evidence/chat_features/report.json). These tests pin the suite itself:
coverage (every read tool + the knowledge lane has a question), runner hygiene, and the Korean advisory-id
extraction that the fleet/proposal questions depend on."""
from __future__ import annotations

import json
import os

from bts_sbom_app.chat import _ID
from bts_sbom_app import chat as chatmod
from bts_sbom_app import server as server_mod

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))
SUITE = os.path.join(ROOT, "evals", "chat_features.json")


def _suite() -> list:
    with open(SUITE, encoding="utf-8") as fh:
        return json.load(fh)


def test_every_read_tool_has_a_question():
    """AC: BSA-AC-558."""
    from bts_sbom_app.chat import TOOL_CATALOG, WRITE_TOOLS
    suite = _suite()
    tools = {r["tool"] for r in suite if r.get("tool")}
    read_tools = {t for t in TOOL_CATALOG if t not in WRITE_TOOLS} - {"record_decision"}
    missing = read_tools - tools
    assert not missing, "chat questions missing for read tools: %s" % sorted(missing)
    nl_rows = [r for r in suite if r.get("tool") == "nl2sql"]
    assert len(nl_rows) >= 3, "the nl2sql lane needs its own conversational questions"


def test_rows_carry_project_or_explicitly_target_the_knowledge_lane():
    """AC: BSA-AC-558."""
    for r in _suite():
        # nl2sql/latest_arch/book_search/affected_projects are project-independent lanes
        assert (r.get("project") or r.get("tool") in (None, "latest_arch", "book_search", "affected_projects", "nl2sql", "draw_diagram", "decide")), r["feature"]


def test_korean_particle_glued_to_an_id_still_extracts():
    """AC: BSA-AC-558. A Hangul particle directly after the id ("CVE-2018-18074에") used to break the \\b word
    boundary and silently killed fleet/vuln routing for every Korean sentence - measured 2026-11-22."""
    from bts_sbom_app.chat import _ID as advisory_id
    assert advisory_id.findall("CVE-2018-18074에 영향받는 프로젝트") == ["CVE-2018-18074"]
    assert advisory_id.findall("GHSA-x84v-xcm2-53pg은 requests 이슈") == ["GHSA-x84v-xcm2-53pg"]
    assert advisory_id.findall("CVE-2018-18074 is affected") == ["CVE-2018-18074"]


def test_runner_writes_a_report(tmp_path, capsys):
    """AC: BSA-AC-558."""
    import scripts.chat_features_run as runner
    base = "http://127.0.0.1:65530"                    # nothing listens: the runner records the failure, never aborts
    rows = [{"feature": "x", "tool": None, "q": "질문"}]
    results = runner.run(base, rows)
    assert results[0]["issues"] and "request failed" in results[0]["issues"][0]


def test_nl2sql_tool_answers_from_the_real_db_shape(tmp_path):
    """AC: BSA-AC-602. The chat tool runs a read-only SELECT over the resolved DB and returns the 4-state
    result with SQL - project-independent (book_search precedent)."""
    import json as _json
    import sqlite3
    dbp = str(tmp_path / "osv.db")
    conn = sqlite3.connect(dbp)
    conn.execute("CREATE TABLE vulns (ecosystem TEXT, vuln_id TEXT, vuln_json TEXT, PRIMARY KEY (ecosystem, vuln_id))")
    conn.execute("CREATE TABLE pkg_map (ecosystem TEXT, package_name TEXT, vuln_id TEXT, PRIMARY KEY (ecosystem, package_name, vuln_id))")
    conn.execute("INSERT INTO vulns VALUES ('PyPI', 'CVE-2024-0001', '{\"summary\": \"bad\"}')")
    conn.execute("INSERT INTO pkg_map VALUES ('PyPI', 'django', 'CVE-2024-0001')")
    conn.commit(); conn.close()
    out = chatmod.run_tool(None, "nl2sql", {"q": "django 패키지의 취약점 목록 보여줘"}, db_path=dbp)[0]
    assert out["tool"] == "nl2sql" and out["trust"] == "tool"
    lines = "\n".join(out["lines"])
    assert "status: success" in lines and "django" in lines and "CVE-2024-0001" in lines


def test_nl2sql_tool_answers_honestly_when_the_db_is_absent():
    """AC: BSA-AC-603."""
    out = chatmod.run_tool(None, "nl2sql", {"q": "생태계별 취약점 수"}, db_path=None)[0]
    assert "OSV database is not present" in "\n".join(out["lines"])

def test_db_routes_schema_and_query_validation(tmp_path):
    """AC: BSA-AC-604."""
    import json as _json
    import sqlite3
    import threading
    import urllib.error
    import urllib.request
    from http.server import ThreadingHTTPServer
    dbp = tmp_path / "osv.db"
    conn = sqlite3.connect(str(dbp))
    conn.execute("CREATE TABLE vulns (ecosystem TEXT, vuln_id TEXT, vuln_json TEXT)")
    conn.execute("INSERT INTO vulns VALUES ('PyPI', 'CVE-2024-0001', '{}')")
    conn.commit(); conn.close()
    st = server_mod.State(str(tmp_path), str(tmp_path / "ev"), None)
    dbp = st.db_path()
    os.makedirs(os.path.dirname(dbp), exist_ok=True)
    conn = sqlite3.connect(dbp)
    conn.execute("CREATE TABLE vulns (ecosystem TEXT, vuln_id TEXT, vuln_json TEXT)")
    conn.execute("INSERT INTO vulns VALUES ('PyPI', 'CVE-2024-0001', '{}')")
    conn.commit(); conn.close()
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), server_mod.make_handler(st))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    base = "http://127.0.0.1:%d" % httpd.server_address[1]
    try:
        with urllib.request.urlopen(base + "/api/db/schema", timeout=10) as r:
            d = _json.loads(r.read())
        assert "vulns" in d["tables"] and d["tables"]["vulns"] == 1
        body = _json.dumps({"q": ""}).encode()
        req = urllib.request.Request(base + "/api/db/query", data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            urllib.request.urlopen(req, timeout=10)
            raise AssertionError("empty q must 400")
        except urllib.error.HTTPError as e:
            assert e.code == 400
    finally:
        httpd.shutdown()
