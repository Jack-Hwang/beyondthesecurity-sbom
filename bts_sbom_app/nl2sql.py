"""Offline Text-to-SQL lane over the local OSV SQLite mirror (MetaNet 3-2차시 NL2SQL, stdlib only).

Safety is layered - the validator is the first gate, the database is the real one:
1. ``validate`` - single statement, SELECT/WITH only (write keywords rejected wherever they appear, CTEs included),
   LIMIT enforced (missing -> appended, over-cap -> reduced).
2. ``run_readonly`` - the connection is opened with a read-only URI and ``PRAGMA query_only``; even a bypassed
   validator cannot write, and any failure comes back as the ``access_failure`` state, never as empty rows.

States follow the course 4-state enum: success / empty_result / partial_result (LIMIT truncation) /
access_failure - a valid 0-row answer is a success, never an error. Generation has two lanes: a deterministic
template router (offline default, this is what the EX eval measures) and an optional LLM lane whose
self-correction loop attaches the concrete error to the regeneration prompt, caps attempts at 3 and stops
immediately on a repeated identical error.
"""
from __future__ import annotations

import re
import sqlite3
from typing import Any, Dict, List, Optional, Sequence, Tuple

#: tokens that must never appear anywhere in a lane query (CTE bodies included)
WRITE_TOKENS = frozenset({"insert", "update", "delete", "drop", "alter", "create", "attach", "detach",
                          "pragma", "vacuum", "replace", "grant", "revoke", "reindex", "analyze"})
STATE_SUCCESS, STATE_EMPTY, STATE_PARTIAL, STATE_ACCESS = "success", "empty_result", "partial_result", "access_failure"


class SqlError(Exception):
    """A lane failure carrying the course errorCategory + isRetryable contract."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category                       # validation | business | transient
        self.retryable = category == "validation"      # business rules refuse retry; validation -> fix and retry

    def to_dict(self) -> Dict[str, Any]:
        return {"errorCategory": self.category, "isRetryable": self.retryable, "message": str(self)}


def _strip_strings(sql: str) -> str:
    return re.sub(r"'(?:[^']|'')*'", "''", sql)


def _tokens(sql: str) -> List[str]:
    return re.findall(r"[A-Za-z_]+", _strip_strings(sql).lower())


def validate(sql: str, max_rows: int = 200) -> str:
    """Return the executable SQL or raise SqlError - single statement, read-only shape, LIMIT enforced."""
    s = (sql or "").strip()
    while s.endswith(";"):
        s = s[:-1].rstrip()
    if not s:
        raise SqlError("validation", "빈 SQL")
    if ";" in s:
        raise SqlError("validation", "1문장만 허용")
    toks = _tokens(s)
    if not toks:
        raise SqlError("validation", "토큰 없음")
    hits = sorted(WRITE_TOKENS & set(toks))
    if hits:
        raise SqlError("business", "SELECT만 허용 (차단 토큰: %s)" % ", ".join(hits))
    if toks[0] == "explain" and len(toks) > 1:
        toks = toks[1:]
    if toks[0] not in ("select", "with"):
        raise SqlError("business", "SELECT만 허용")
    m = re.search(r"\blimit\s+(\d+)\b", s.lower())
    if m:
        n = int(m.group(1))
        if n > max_rows:
            s = s[:m.start()] + "LIMIT %d" % max_rows + s[m.end():]
    elif not re.search(r"\bcount\s*\(\s*\*\s*\)", s.lower()):
        s += " LIMIT %d" % max_rows                                   # non-aggregate reads get a hard cap too
    return s


def run_readonly(sql: str, db_path: str, max_rows: int = 200, timeout: float = 5.0) -> Dict[str, Any]:
    """The 4-state executor: never turns a valid 0-row answer into an error, or an error into empty rows."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"), uri=True, timeout=timeout)
    except sqlite3.Error as exc:
        return {"status": STATE_ACCESS, "rows": [], "error": {"errorCategory": "transient", "isRetryable": True,
                                                              "message": type(exc).__name__}}
    try:
        conn.execute("PRAGMA query_only = ON")
        cur = conn.execute(sql)
        rows = cur.fetchall()[:max_rows + 1]
    except sqlite3.Error as exc:
        return {"status": STATE_ACCESS, "rows": [], "error": {"errorCategory": "transient", "isRetryable": True,
                                                              "message": "%s: %s" % (type(exc).__name__, exc)}}
    finally:
        conn.close()
    if len(rows) > max_rows:
        return {"status": STATE_PARTIAL, "rows": rows[:max_rows], "truncated": True}
    if not rows:
        return {"status": STATE_EMPTY, "rows": []}
    return {"status": STATE_SUCCESS, "rows": rows}


# -- catalog: what the tables mean, for the LLM lane and for humans -------------------------------

CATALOG: Dict[str, Any] = {
    "tables": {
        "vulns": {"desc": "OSV 권고문 원문 1건당 1행", "columns": {
            "ecosystem": "생태계 (PyPI, npm, ...)", "vuln_id": "OSV/CVE 식별자",
            "vuln_json": "OSV 원문 JSON - 요약은 json_extract(vuln_json,'$.summary')"}},
        "pkg_map": {"desc": "패키지-취약점 연결(1행 = 패키지 1개가 걸린 권고문 1건)", "columns": {
            "ecosystem": "생태계", "package_name": "패키지 이름(소문자)", "vuln_id": "권고문 식별자"}},
    },
    "metrics": {
        "취약점 수": "SELECT COUNT(*) FROM vulns - 중복 없이 권고문 건수",
        "패키지별 취약점": "pkg_map 를 package_name 으로 GROUP BY - 건수는 걸린 권고문 수",
    },
}

def _id_summary(q: str) -> str:
    mid = re.search(r"(CVE|GHSA|PYSEC)[-_]?[0-9]{4}[-_]?[0-9]+|(CVE|GHSA|PYSEC)[-0-9A-Za-z]+", q, re.I)
    ident = mid.group(0).upper().replace("_", "-") if mid else ""
    return ("SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns WHERE vuln_id LIKE '%%%s%%' ORDER BY vuln_id LIMIT 20" % ident)


def route(question: str) -> Optional[str]:
    """Deterministic template router - the offline lane and the EX-eval reference. Order matters: the id and
    eco-list patterns must win over the package and count patterns that would otherwise swallow them."""
    q = question.strip()
    if re.search(r"(CVE|GHSA|PYSEC)", q, re.I):
        return _id_summary(q)
    if re.search(r"생태계별", q):
        return "SELECT ecosystem, COUNT(*) AS cnt FROM vulns GROUP BY ecosystem ORDER BY cnt DESC, ecosystem"
    if re.search(r"생태계", q) and re.search(r"목록|리스트|종류|어떤|무슨", q):
        return "SELECT DISTINCT ecosystem FROM vulns ORDER BY ecosystem"
    if re.search(r"패키지별", q):
        return "SELECT name, COUNT(*) AS cnt FROM pkg_map GROUP BY package_name ORDER BY cnt DESC, name LIMIT 20"
    pkg = re.search(r"([A-Za-z][A-Za-z0-9_.-]{1,40})\s*(패키지|라이브러리|모듈)?의?\s*(취약점|권고문)\s*(목록|리스트)?", q)
    if pkg and pkg.group(1).lower() not in ("취약점", "보안", "이", "그"):
        name = pkg.group(1).lower()
        return ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
                "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
                "WHERE p.package_name = '%s' ORDER BY p.vuln_id LIMIT 20" % name.replace("'", "''"))
    if re.search(r"(취약점|보안|권고문).*?(요약|설명)", q):
        return "SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns ORDER BY vuln_id LIMIT 20"
    if re.search(r"(전체|총|몇\s*개|수)", q) and re.search(r"취약", q):
        return "SELECT COUNT(*) AS vuln_count FROM vulns"
    return None


GEN_SYSTEM = ("You convert one question into exactly ONE read-only SQLite SELECT over the given catalog. "
              "Never write INSERT/UPDATE/DELETE/DDL. Reply ONLY JSON "
              '{"sql": string|null, "tables": [string], "assumptions": [string], "clarification_needed": string|null}.')


def generate_sql(question: str, client: Any, catalog_text: str, error: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """LLM lane via the existing OpenAI-compatible client (json_mode) - schema-linked, nullable clarification,
    and the previous attempt's concrete error attached when regenerating (course ④ self-correction)."""
    import json as _json
    ask = question
    if error:
        ask = "%s\n\n이전 시도가 실패했다 - 원인(%s): %s. 다른 SQL로 다시 생성하라." % (
            question, error.get("errorCategory"), error.get("message"))
    raw = client.complete(GEN_SYSTEM + "\nCATALOG:\n" + catalog_text, ask, 900, json_mode=True)
    obj = _json.loads(raw)
    if not isinstance(obj, dict):
        raise SqlError("validation", "생성 응답이 JSON 객체가 아님")
    return obj


def answer(question: str, db_path: str, client: Any = None, max_attempts: int = 3,
           max_rows: int = 200) -> Dict[str, Any]:
    """Route -> (LLM lane) generate -> validate -> run, attaching the concrete error to each regeneration."""
    catalog_text = repr(CATALOG)[:1200]
    attempts = 0
    last_err: Optional[Dict[str, Any]] = None
    prev_err: Optional[str] = None
    while attempts < max_attempts:
        attempts += 1
        sql = route(question) if attempts == 1 and client is None else None
        if sql is None:
            if client is None:
                break                                     # no template, no model: honest miss
            try:
                gen = generate_sql(question, client, catalog_text, error=last_err)
            except Exception as exc:                      # LLM error -> structured failure, not empty rows
                return {"question": question, "status": STATE_ACCESS, "rows": [], "sql": None, "source": "llm",
                        "attempts": attempts, "error": {"errorCategory": "transient", "isRetryable": True,
                                                        "message": str(exc)[:160]}}
            if gen.get("clarification_needed") and not gen.get("sql"):
                return {"question": question, "status": STATE_ACCESS, "rows": [], "sql": None, "source": "llm",
                        "attempts": attempts, "clarification_needed": gen["clarification_needed"]}
            sql = gen.get("sql")
            if not sql:
                break
        try:
            sql = validate(sql, max_rows=max_rows)
            res = run_readonly(sql, db_path, max_rows=max_rows)
        except SqlError as exc:
            last_err = exc.to_dict()
            if prev_err == str(exc) or not exc.retryable or client is None:
                break                                     # same error twice, or a business refusal: stop
            prev_err = str(exc)
            continue                                      # regenerate with the error attached
        if res["status"] == STATE_ACCESS:
            last_err = res["error"]
            if prev_err == res["error"]["message"] or client is None:
                break
            prev_err = res["error"]["message"]
            continue
        return {"question": question, "status": res["status"], "rows": res["rows"], "sql": sql,
                "source": "template" if attempts == 1 and route(question) == sql else "llm",
                "attempts": attempts, **({"truncated": True} if res.get("truncated") else {})}
    if last_err is None:                                  # no template matched and no model lane: an honest miss
        last_err = {"errorCategory": "validation", "isRetryable": False,
                    "message": "no template route and no LLM client - not answered"}
    return {"question": question, "status": STATE_ACCESS, "rows": [], "sql": sql,
            "source": "template" if sql else "llm", "attempts": attempts, "error": last_err}


# -- EX evaluation: candidate result set vs an authored reference query on the same database -------

def nl2sql_eval(db_path: str, golden: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    """EX over the golden set (question + authored reference_sql): hit = same non-empty status + equal result rows."""
    cases = golden if golden is not None else _default_golden()
    ex = 0
    misses: List[Dict[str, Any]] = []
    for c in cases:
        ref = run_readonly(validate(c["reference_sql"]), db_path)
        cand = answer(c["question"], db_path)
        hit = cand["status"] == ref["status"] and _norm(cand["rows"]) == _norm(ref["rows"])
        ex += 1 if hit else 0
        if not hit:
            misses.append({"q": c["question"], "status": cand["status"],
                           "rows": cand["rows"][:2], "expected": _norm(ref["rows"])[:2]})
    return {"cases": len(cases), "ex": round(ex / len(cases), 4) if cases else 0.0, "misses": misses}


def _norm(rows: List[Sequence[Any]]) -> List[List[Any]]:
    return sorted([list(map(_scalar, r)) for r in rows])


def _scalar(v: Any) -> Any:
    return v if isinstance(v, (int, float, str, type(None))) else str(v)


def _default_golden() -> List[Dict[str, str]]:
    """30 questions across the template families; each with an authored (not router-derived) reference query."""
    g: List[Dict[str, str]] = []
    for q, s in [
        ("전체 취약점은 몇 개야?", "SELECT COUNT(*) AS vuln_count FROM vulns"),
        ("총 취약점 수를 알려줘", "SELECT COUNT(*) AS vuln_count FROM vulns"),
        ("취약점이 총 몇 개나 돼?", "SELECT COUNT(*) AS vuln_count FROM vulns"),
        ("생태계별 취약점 수를 보여줘", "SELECT ecosystem, COUNT(*) AS cnt FROM vulns GROUP BY ecosystem ORDER BY cnt DESC, ecosystem"),
        ("생태계별로 몇 건씩 있어?", "SELECT ecosystem, COUNT(*) AS cnt FROM vulns GROUP BY ecosystem ORDER BY cnt DESC, ecosystem"),
        ("패키지별 취약점 건수는?", "SELECT name, COUNT(*) AS cnt FROM pkg_map GROUP BY package_name ORDER BY cnt DESC, name LIMIT 20"),
        ("패키지별로 취약점이 몇 건이야?", "SELECT name, COUNT(*) AS cnt FROM pkg_map GROUP BY package_name ORDER BY cnt DESC, name LIMIT 20"),
        ("생태계 목록을 알려줘", "SELECT DISTINCT ecosystem FROM vulns ORDER BY ecosystem"),
        ("이 DB에 어떤 생태계가 있어?", "SELECT DISTINCT ecosystem FROM vulns ORDER BY ecosystem"),
        ("등록된 생태계 종류는?", "SELECT DISTINCT ecosystem FROM vulns ORDER BY ecosystem"),
    ]:
        g.append({"question": q, "reference_sql": s})
    for pkg in ("requests", "leftpad", "flask", "lodash"):
        g.append({"question": "%s 패키지의 취약점 목록을 보여줘" % pkg,
                  "reference_sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary "
                                    "FROM pkg_map p JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
                                    "WHERE p.package_name = '%s' ORDER BY p.vuln_id LIMIT 20" % pkg)})
    for vid in ("CVE-2018-18074", "GHSA-x84v-xcm2-53pg", "CVE-2021-1", "GHSA-aaaa-bbbb-cccc"):
        g.append({"question": "%s 취약점이 뭐야?" % vid,
                  "reference_sql": ("SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns "
                                    "WHERE vuln_id LIKE '%%%s%%' ORDER BY vuln_id LIMIT 20" % vid)})
    for q, s in [
        ("취약점 요약 몇 개 보여줘", "SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns ORDER BY vuln_id LIMIT 20"),
        ("권고문 설명 목록을 보여줘", "SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns ORDER BY vuln_id LIMIT 20"),
        ("요즘 뜨는 보안 이슈 요약해줘", "SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns ORDER BY vuln_id LIMIT 20"),
    ]:
        g.append({"question": q, "reference_sql": s})
    for pkg in ("mocha", "express", "django", "numpy", "urllib3"):
        g.append({"question": "%s 패키지의 취약점 목록을 보여줘" % pkg,
                  "reference_sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary "
                                    "FROM pkg_map p JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
                                    "WHERE p.package_name = '%s' ORDER BY p.vuln_id LIMIT 20" % pkg)})
    for vid in ("CVE-2019-1234", "GHSA-pqrs-tuvw-xyz"):
        g.append({"question": "%s 취약점이 뭐야?" % vid,
                  "reference_sql": ("SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns "
                                    "WHERE vuln_id LIKE '%%%s%%' ORDER BY vuln_id LIMIT 20" % vid)})
    for q, s in [
        ("현재 알려진 취약점 개수는?", "SELECT COUNT(*) AS vuln_count FROM vulns"),
        ("지금까지 수집된 취약점은 몇 건이야?", "SELECT COUNT(*) AS vuln_count FROM vulns"),
    ]:
        g.append({"question": q, "reference_sql": s})
    return g
