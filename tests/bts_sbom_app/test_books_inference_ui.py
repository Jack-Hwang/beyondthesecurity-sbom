"""Book KB = service-upgrade inference source, not a book/keyword database (사용자 지정 2026-11-22).

The distilled notes (knowledge_books/, "이 프로젝트 적용") and the improvement map (docs/BOOK_IMPROVEMENT_MAP.md)
are the inference OUTPUT the screen exists for; ingest / search / library stay as its source infrastructure.
Covers the two parsers (books.read_notes / books.read_improvement_map), the two API reads
(/api/books/notes, /api/books/map) and the static structure of web/bts_books.js.
"""
from __future__ import annotations

import os
import re
import types

from bts_sbom_app import books, books_api, rag

HOST = {"Host": "127.0.0.1:8800"}
BIND = ("127.0.0.1", 8800)

WEB = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "bts_sbom_app", "web")

NOTE = """# circuit breakers for agents

출처: Building Agentic AI Systems (Biswas, Talukdar) (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 도구 호출은 실패를 전제로 설계한다.
- 재시도는 지수 백오프로 제한한다.

## 이 프로젝트 적용

- chat.run_tool 실패에 서킷브레이커를 붙인다 (AC-301~).
- 프로브는 1회만 허용한다.
"""

MAP = """# BOOK IMPROVEMENT MAP

intro text that is not a table

## 1. 에이전트 신뢰성 (Building Agentic AI Systems)

| 기법 | 상태 | 근거 |
|---|---|---|
| 서킷브레이커 | **구현 (AC-301)** | net.py:fetch_json |
| 무한 재시도 | **기각** | 비용 폭주 |

## 9. 측정 (verification)

| 지표 | 이전 | 이후 |
|---|---|---|
| dev recall | 0.933 | 0.940 |
"""


def test_read_notes_parses_title_book_principles_and_applied(tmp_path):
    """AC: BSA-AC-572"""
    kb = tmp_path / "knowledge_books"
    kb.mkdir()
    (kb / "circuit-breakers.md").write_text(NOTE, encoding="utf-8")
    (kb / "readme.txt").write_text("not a note", encoding="utf-8")             # non-md files are ignored
    res = books.read_notes(str(tmp_path))
    assert res["total"] == 1 and res["notes"][0]["file"] == "knowledge_books/circuit-breakers.md"
    n = res["notes"][0]
    assert n["title"] == "circuit breakers for agents"
    assert "Biswas, Talukdar" in n["book"]
    assert n["principles"] == ["도구 호출은 실패를 전제로 설계한다.", "재시도는 지수 백오프로 제한한다."]
    assert n["applied"] == ["chat.run_tool 실패에 서킷브레이커를 붙인다 (AC-301~).", "프로브는 1회만 허용한다."]


def test_read_notes_on_a_missing_folder_is_honest(tmp_path):
    """AC: BSA-AC-572"""
    res = books.read_notes(str(tmp_path))
    assert res == {"notes": [], "total": 0, "hint": "no knowledge_books/ folder - nothing distilled yet"}


def test_read_improvement_map_parses_areas_statuses_and_strips_bold(tmp_path):
    """AC: BSA-AC-572"""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "BOOK_IMPROVEMENT_MAP.md").write_text(MAP, encoding="utf-8")
    res = books.read_improvement_map(str(tmp_path))
    assert res["source"] == books.MAP_DOC and len(res["sections"]) == 2
    s1 = res["sections"][0]
    assert s1["area"].startswith("1. 에이전트 신뢰성")
    assert s1["headers"] == ["기법", "상태", "근거"]
    assert s1["rows"][0] == ["서킷브레이커", "구현 (AC-301)", "net.py:fetch_json"]      # ** stripped
    assert s1["rows"][1][1] == "기각"
    assert res["sections"][1]["headers"] == ["지표", "이전", "이후"]                    # a non-기법 table survives as-is


def test_api_serves_notes_and_map_and_answers_an_empty_root_honestly(tmp_path):
    """AC: BSA-AC-572"""
    kb = tmp_path / "knowledge_books"
    kb.mkdir()
    (kb / "n.md").write_text(NOTE, encoding="utf-8")
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "BOOK_IMPROVEMENT_MAP.md").write_text(MAP, encoding="utf-8")
    st = types.SimpleNamespace(root=str(tmp_path), evidence=str(tmp_path / "ev"), jobs={}, buses={},
                               books_index=lambda: rag.Index(()))
    code, obj, _, _ = books_api.route("GET", "/api/books/notes", {}, {}, HOST, st, BIND)
    assert code == 200 and obj["total"] == 1 and obj["notes"][0]["applied"]
    code, obj, _, _ = books_api.route("GET", "/api/books/map", {}, {}, HOST, st, BIND)
    assert code == 200 and obj["sections"][0]["rows"][0][1] == "구현 (AC-301)"
    empty = types.SimpleNamespace(evidence=str(tmp_path), jobs={}, buses={}, books_index=lambda: rag.Index(()))
    code, obj, _, _ = books_api.route("GET", "/api/books/notes", {}, {}, HOST, empty, BIND)
    assert code == 200 and obj == {"notes": [], "total": 0, "hint": "no knowledge_books/ folder - nothing distilled yet"}
    code, obj, _, _ = books_api.route("GET", "/api/books/map", {}, {}, HOST, empty, BIND)
    assert code == 200 and obj["sections"] == [] and obj["hint"]


def test_the_book_tab_leads_with_the_inference_output_not_the_library():
    """AC: BSA-AC-572"""
    js = open(os.path.join(WEB, "bts_books.js"), encoding="utf-8").read()
    map_at = js.index("booksMap")
    notes_at = js.index("booksNotes")
    ingest_at = js.index("booksIngestPath")
    assert map_at < notes_at < ingest_at                     # the inference output is built (and shown) first
    assert "우리 서비스 고도화 추론" in js and "책 DB(키워드 DB)를 만들려는 게 아니다" in js
    assert "이 프로젝트 적용" in js and "개선 지도" in js
    assert "/api/books/notes" in js and "/api/books/map" in js
    assert re.search(r"loadMap\(\);\s*\n\s*loadNotes\(\);\s*\n\s*loadRegistry\(\);", js)   # inference loads first
    assert "the raw source the notes and the map above are inferred from" in js   # ingest reframed as source infra
    assert "check an inference against the book text itself" in js               # search reframed as evidence check
