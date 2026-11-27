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

The LLM lane's raw JSON is shape-validated before it is trusted (``_validate_gen_shape``) and grounded with a
curated few-shot pool (``NL2SQL_EXAMPLES`` / ``select_examples``); ``nl2sql_eval`` can additionally exercise
that lane end to end (``ex_llm``) with a caller-supplied client; and every answer states which ecosystem(s) its
rows came from and how fresh the local OSV snapshot is for each (``answer()``'s ``as_of`` field, import_meta
backed) - explicitly "unknown" rather than silently omitted when the result does not expose an ecosystem.
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


def _execute_readonly(sql: str, db_path: str, max_rows: int = 200,
                       timeout: float = 5.0) -> Tuple[Dict[str, Any], List[str]]:
    """Same 4-state contract as ``run_readonly`` plus the result's column names (``cursor.description``) - the
    column names are what lets ``answer()`` tell which ecosystem(s) a result actually drew from (see
    ``_ecosystems_in_result``) without guessing from the SQL text."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"), uri=True, timeout=timeout)
    except sqlite3.Error as exc:
        return ({"status": STATE_ACCESS, "rows": [], "error": {"errorCategory": "transient", "isRetryable": True,
                                                                "message": type(exc).__name__}}, [])
    try:
        conn.execute("PRAGMA query_only = ON")
        cur = conn.execute(sql)
        cols = [d[0] for d in (cur.description or [])]
        rows = cur.fetchall()[:max_rows + 1]
    except sqlite3.Error as exc:
        return ({"status": STATE_ACCESS, "rows": [], "error": {"errorCategory": "transient", "isRetryable": True,
                                                                "message": "%s: %s" % (type(exc).__name__, exc)}}, [])
    finally:
        conn.close()
    if len(rows) > max_rows:
        return ({"status": STATE_PARTIAL, "rows": rows[:max_rows], "truncated": True}, cols)
    if not rows:
        return ({"status": STATE_EMPTY, "rows": []}, cols)
    return ({"status": STATE_SUCCESS, "rows": rows}, cols)


def run_readonly(sql: str, db_path: str, max_rows: int = 200, timeout: float = 5.0) -> Dict[str, Any]:
    """The 4-state executor: never turns a valid 0-row answer into an error, or an error into empty rows."""
    res, _cols = _execute_readonly(sql, db_path, max_rows=max_rows, timeout=timeout)
    return res


def _import_meta(db_path: str) -> Dict[str, float]:
    """ecosystem -> import_meta.imported_at (epoch seconds); {} when the table is absent or unreadable - an
    honest "freshness unknown" rather than a crash (RM-15 <=26h snapshot-freshness gate, read-only access)."""
    try:
        conn = sqlite3.connect("file:%s?mode=ro" % db_path.replace("\\", "/"), uri=True, timeout=5.0)
    except sqlite3.Error:
        return {}
    try:
        conn.execute("PRAGMA query_only = ON")
        rows = conn.execute("SELECT ecosystem, imported_at FROM import_meta").fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    return {str(e): a for e, a in rows if a is not None}


def _iso_date(ts: float) -> str:
    import datetime as _dt
    return _dt.datetime.fromtimestamp(ts, tz=_dt.timezone.utc).strftime("%Y-%m-%d")


def _ecosystems_in_result(cols: List[str], rows: List[Sequence[Any]]) -> Optional[List[str]]:
    """Distinct ecosystem values actually present in the result rows, or None when the result has no
    ``ecosystem`` column at all - the caller then states "unknown" explicitly instead of guessing one."""
    lower = [c.lower() for c in cols]
    if "ecosystem" not in lower:
        return None
    idx = lower.index("ecosystem")
    return sorted({str(r[idx]) for r in rows if idx < len(r) and r[idx] is not None})


def _as_of(db_path: str, ecosystems: Optional[List[str]]) -> Dict[str, Any]:
    """import_meta.imported_at per ecosystem the answer referenced (RM-15 snapshot-freshness disclosure) -
    {"unknown": None} when the result doesn't expose which ecosystem(s) it drew from, stated explicitly rather
    than omitted; an ecosystem referenced but never imported maps to None too (same honesty, not silence)."""
    if ecosystems is None:
        return {"unknown": None}
    meta = _import_meta(db_path)
    return {eco: (_iso_date(meta[eco]) if eco in meta else None) for eco in ecosystems}


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
        return "SELECT package_name, COUNT(*) AS cnt FROM pkg_map GROUP BY package_name ORDER BY cnt DESC, package_name LIMIT 20"
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

#: curated few-shot pool (course 3-2 S3): 15-25 {question, sql, rationale} entries, kept disjoint from the
#: golden set in _default_golden() (test_nl2sql_upgrades.py asserts the leak check) - covers packages/ids the
#: golden set never uses so the deterministic-overlap scorer below cannot accidentally reward a golden match.
NL2SQL_EXAMPLES: List[Dict[str, str]] = [
    {"question": "pyyaml 패키지에 걸린 취약점 알려줘",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'pyyaml' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "패키지명으로 pkg_map과 vulns를 ecosystem+vuln_id로 조인해 요약을 가져온다"},
    {"question": "jinja2 라이브러리 보안 권고문 목록",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'jinja2' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "같은 패키지-취약점 조인 패턴, 다른 패키지명"},
    {"question": "axios 모듈의 취약점 리스트",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'axios' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "npm 생태계 패키지에도 동일 패턴이 적용된다"},
    {"question": "pillow 패키지 취약점 몇 건 있어?",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'pillow' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "건수를 묻더라도 실제로는 행 목록을 돌려주는 편이 안전하다 (COUNT가 아니라 권고문 자체가 중요)"},
    {"question": "CVE-2022-4567은 어떤 취약점이야?",
     "sql": ("SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns "
             "WHERE vuln_id LIKE '%CVE-2022-4567%' ORDER BY vuln_id LIMIT 20"),
     "rationale": "식별자 패턴(CVE/GHSA)은 LIKE로 부분 일치해야 하이픈/언더스코어 표기 차이를 흡수한다"},
    {"question": "GHSA-wxyz-1234-5678 상세 설명해줘",
     "sql": ("SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns "
             "WHERE vuln_id LIKE '%GHSA-wxyz-1234-5678%' ORDER BY vuln_id LIMIT 20"),
     "rationale": "GHSA 식별자도 동일한 LIKE 조회 패턴"},
    {"question": "npm 생태계에 취약점이 몇 개나 있어?",
     "sql": "SELECT COUNT(*) AS vuln_count FROM vulns WHERE ecosystem = 'npm'",
     "rationale": "특정 ecosystem 값으로 COUNT를 필터링하는 패턴 (라우터에는 없는 형태, LLM만 커버)"},
    {"question": "PyPI 쪽 권고문은 총 몇 건이야?",
     "sql": "SELECT COUNT(*) AS vuln_count FROM vulns WHERE ecosystem = 'PyPI'",
     "rationale": "ecosystem 리터럴로 COUNT를 필터링하는 또 다른 생태계 예시"},
    {"question": "가장 최근에 등록된 취약점 10개 보여줘",
     "sql": "SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns ORDER BY vuln_id DESC LIMIT 10",
     "rationale": "정렬 방향(DESC)과 LIMIT을 조절해 '최근' 같은 상대적 시간 표현을 처리한다"},
    {"question": "npm 패키지 중 취약점이 제일 많은 것 5개",
     "sql": "SELECT package_name, COUNT(*) AS cnt FROM pkg_map WHERE ecosystem = 'npm' GROUP BY package_name ORDER BY cnt DESC LIMIT 5",
     "rationale": "ecosystem 필터 + GROUP BY + LIMIT로 '상위 N개' 질문을 다루는 예시"},
    {"question": "werkzeug에 영향을 주는 보안 권고문 알려줘",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'werkzeug' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "패키지 조인 패턴의 또 다른 표현(영향을 주는)"},
    {"question": "click 패키지는 안전해? 취약점 있어?",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'click' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "예/아니오 질문형태도 같은 패키지-취약점 조회로 해석된다"},
    {"question": "aiohttp 관련 CVE 목록 보여줘",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'aiohttp' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "'CVE 목록' 표현도 패키지별 취약점 조회로 매핑된다"},
    {"question": "pandas 패키지 보안 이슈 요약해줘",
     "sql": ("SELECT p.package_name, p.vuln_id, json_extract(v.vuln_json,'$.summary') AS summary FROM pkg_map p "
             "JOIN vulns v ON v.ecosystem = p.ecosystem AND v.vuln_id = p.vuln_id "
             "WHERE p.package_name = 'pandas' ORDER BY p.vuln_id LIMIT 20"),
     "rationale": "'요약해줘'도 패키지별 조회로 해석된다 (별도 요약 엔드포인트 없음)"},
    {"question": "CVE-2023-9999 설명 부탁해",
     "sql": ("SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns "
             "WHERE vuln_id LIKE '%CVE-2023-9999%' ORDER BY vuln_id LIMIT 20"),
     "rationale": "짧은 구어체 질문도 식별자 LIKE 조회로 해석된다"},
    {"question": "GHSA-ijkl-7890-mnop 이게 뭔지 알려줘",
     "sql": ("SELECT vuln_id, json_extract(vuln_json,'$.summary') AS summary FROM vulns "
             "WHERE vuln_id LIKE '%GHSA-ijkl-7890-mnop%' ORDER BY vuln_id LIMIT 20"),
     "rationale": "GHSA 식별자의 또 다른 구어체 표현"},
    {"question": "생태계마다 등록된 패키지 종류가 몇 개야?",
     "sql": "SELECT ecosystem, COUNT(DISTINCT package_name) AS pkg_count FROM pkg_map GROUP BY ecosystem ORDER BY pkg_count DESC, ecosystem",
     "rationale": "COUNT(DISTINCT ...) + GROUP BY ecosystem로 '종류 수' 질문을 다루는 예시"},
    {"question": "전체 데이터베이스에 등록된 패키지는 몇 개야?",
     "sql": "SELECT COUNT(DISTINCT package_name) AS pkg_count FROM pkg_map",
     "rationale": "COUNT(DISTINCT ...)만으로 전체 집계를 내는 가장 단순한 형태"},
]


def _qtokens(text: str) -> set:
    """Lowercased alnum/Hangul token set for a crude token-overlap similarity (no external NLP deps, stdlib only)."""
    return set(re.findall(r"[A-Za-z0-9가-힣_]+", (text or "").lower()))


def select_examples(question: str, k: int = 3, pool: Optional[List[Dict[str, str]]] = None) -> List[Dict[str, str]]:
    """Rank NL2SQL_EXAMPLES by token overlap with ``question`` (ties keep pool order) and return the top-k,
    clamped to 2-4: grounds the LLM lane with concrete examples without needing a retrieval index."""
    examples = NL2SQL_EXAMPLES if pool is None else pool
    qtok = _qtokens(question)
    k = max(2, min(4, k))
    order = sorted(range(len(examples)), key=lambda i: (-len(qtok & _qtokens(examples[i]["question"])), i))
    return [examples[i] for i in order[:k]]


def _examples_block(examples: List[Dict[str, str]]) -> str:
    lines = ["FEW-SHOT EXAMPLES (grounding only - adapt to the actual question, do not copy blindly):"]
    for ex in examples:
        lines.append("Q: %s\nSQL: %s\n근거: %s" % (ex["question"], ex["sql"], ex.get("rationale", "")))
    return "\n".join(lines)


#: the 4 generate_sql reply keys the course③ structured-output contract allows - anything else is a shape error
GEN_KEYS = frozenset({"sql", "tables", "assumptions", "clarification_needed"})


def _validate_gen_shape(obj: Dict[str, Any]) -> Dict[str, Any]:
    """Course③ structured-output gate: sql str|None, tables/assumptions list[str], clarification_needed
    str|None, no unknown keys - any violation raises SqlError('validation', ...) so answer()'s capped
    self-correction loop can regenerate instead of trusting (or crashing on) a malformed shape."""
    unknown = sorted(set(obj.keys()) - GEN_KEYS)
    if unknown:
        raise SqlError("validation", "알 수 없는 키: %s" % ", ".join(unknown))
    sql = obj.get("sql")
    if sql is not None and not isinstance(sql, str):
        raise SqlError("validation", "sql은 string 또는 null이어야 함 (받음: %s)" % type(sql).__name__)
    for key in ("tables", "assumptions"):
        val = obj.get(key, [])
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise SqlError("validation", "%s는 string의 list여야 함" % key)
    clarification = obj.get("clarification_needed")
    if clarification is not None and not isinstance(clarification, str):
        raise SqlError("validation", "clarification_needed은 string 또는 null이어야 함")
    return {"sql": sql, "tables": obj.get("tables", []), "assumptions": obj.get("assumptions", []),
            "clarification_needed": clarification}


def generate_sql(question: str, client: Any, catalog_text: str, error: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """LLM lane via the existing OpenAI-compatible client (json_mode) - schema-linked, few-shot grounded
    (NL2SQL_EXAMPLES via select_examples), nullable clarification, and the previous attempt's concrete error
    attached when regenerating (course ④ self-correction). The raw reply is shape-validated
    (_validate_gen_shape) before it is trusted; a malformed shape raises SqlError('validation', ...) into the
    capped self-correction loop in answer() instead of crashing or being trusted blindly."""
    import json as _json
    ask = question
    if error:
        ask = "%s\n\n이전 시도가 실패했다 - 원인(%s): %s. 다른 SQL로 다시 생성하라." % (
            question, error.get("errorCategory"), error.get("message"))
    raw = client.complete(
        GEN_SYSTEM + "\nCATALOG:\n" + catalog_text + "\n" + _examples_block(select_examples(question)),
        ask, 900, json_mode=True)
    try:
        obj = _json.loads(raw)
    except ValueError as exc:
        raise SqlError("validation", "생성 응답이 JSON이 아님: %s" % exc)
    if not isinstance(obj, dict):
        raise SqlError("validation", "생성 응답이 JSON 객체가 아님")
    return _validate_gen_shape(obj)


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
            except SqlError as exc:                       # malformed generation shape: self-correct, don't crash
                last_err = exc.to_dict()
                if prev_err == str(exc) or not exc.retryable:
                    return {"question": question, "status": STATE_ACCESS, "rows": [], "sql": None, "source": "llm",
                            "attempts": attempts, "error": last_err}
                prev_err = str(exc)
                continue                                   # regenerate with the concrete shape error attached
            except Exception as exc:                      # genuine LLM/transport error -> structured failure
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
            res, cols = _execute_readonly(sql, db_path, max_rows=max_rows)
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
                "attempts": attempts, "as_of": _as_of(db_path, _ecosystems_in_result(cols, res["rows"])),
                **({"truncated": True} if res.get("truncated") else {})}
    if last_err is None:                                  # no template matched and no model lane: an honest miss
        last_err = {"errorCategory": "validation", "isRetryable": False,
                    "message": "no template route and no LLM client - not answered"}
    return {"question": question, "status": STATE_ACCESS, "rows": [], "sql": sql,
            "source": "template" if sql else "llm", "attempts": attempts, "error": last_err}


# -- EX evaluation: candidate result set vs an authored reference query on the same database -------

def _eval_stage(cand_status: str, ref_status: str) -> str:
    """Classify an nl2sql_eval miss by which side failed to execute - a reference_sql that cannot run on its
    own (e.g. a schema typo) must never be hidden behind a false 'both sides returned access_failure' hit."""
    cand_failed = cand_status == STATE_ACCESS
    ref_failed = ref_status == STATE_ACCESS
    if cand_failed and ref_failed:
        return "both_failed"
    if ref_failed:
        return "reference_failed"
    if cand_failed:
        return "candidate_failed"
    return "mismatch"


def nl2sql_eval(db_path: str, golden: Optional[List[Dict[str, str]]] = None, client: Any = None) -> Dict[str, Any]:
    """EX over the golden set (question + authored reference_sql): hit = same status + equal result rows, AND
    that status is not access_failure (a reference_sql that itself cannot run is never an evaluable match, so
    'both sides failed' is always reported as a miss, never a hit). ``ex_template`` (the offline template
    lane) is always measured; when ``client`` is given, every golden question is ALSO run through the LLM
    lane (answer(..., client=client)) and reported as ``ex_llm`` with its own miss list and per-status
    breakdown - the eval no longer silently skips the lane production actually uses just because it needs a
    client to exercise. Every miss (template or LLM) carries a ``stage`` (_eval_stage) saying which side
    failed access, so a broken reference query cannot hide behind a vacuous status match."""
    cases = golden if golden is not None else _default_golden()
    ex = 0
    misses: List[Dict[str, Any]] = []
    llm_hits = 0
    llm_misses: List[Dict[str, Any]] = []
    llm_status_breakdown: Dict[str, int] = {}
    for c in cases:
        ref = run_readonly(validate(c["reference_sql"]), db_path)
        cand = answer(c["question"], db_path)
        hit = (cand["status"] == ref["status"] and cand["status"] != STATE_ACCESS
               and _norm(cand["rows"]) == _norm(ref["rows"]))
        ex += 1 if hit else 0
        if not hit:
            misses.append({"q": c["question"], "status": cand["status"],
                           "rows": cand["rows"][:2], "expected": _norm(ref["rows"])[:2],
                           "stage": _eval_stage(cand["status"], ref["status"])})
        if client is not None:
            cand_llm = answer(c["question"], db_path, client=client)
            hit_llm = (cand_llm["status"] == ref["status"] and cand_llm["status"] != STATE_ACCESS
                       and _norm(cand_llm["rows"]) == _norm(ref["rows"]))
            llm_hits += 1 if hit_llm else 0
            llm_status_breakdown[cand_llm["status"]] = llm_status_breakdown.get(cand_llm["status"], 0) + 1
            if not hit_llm:
                llm_misses.append({"q": c["question"], "status": cand_llm["status"],
                                   "rows": cand_llm["rows"][:2], "expected": _norm(ref["rows"])[:2],
                                   "stage": _eval_stage(cand_llm["status"], ref["status"])})
    out = {"cases": len(cases), "ex": round(ex / len(cases), 4) if cases else 0.0,
           "ex_template": round(ex / len(cases), 4) if cases else 0.0, "misses": misses}
    if client is not None:
        out["ex_llm"] = round(llm_hits / len(cases), 4) if cases else 0.0
        out["llm_misses"] = llm_misses
        out["llm_status_breakdown"] = llm_status_breakdown
    return out


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
        ("패키지별 취약점 건수는?", "SELECT package_name, COUNT(*) AS cnt FROM pkg_map GROUP BY package_name ORDER BY cnt DESC, package_name LIMIT 20"),
        ("패키지별로 취약점이 몇 건이야?", "SELECT package_name, COUNT(*) AS cnt FROM pkg_map GROUP BY package_name ORDER BY cnt DESC, package_name LIMIT 20"),
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
