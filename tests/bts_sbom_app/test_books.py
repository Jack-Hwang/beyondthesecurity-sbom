"""Book knowledge base (books.py + books_api.py + the chat book_search tool)."""
from __future__ import annotations

import json
import os
import time
import types
import zipfile
from typing import Any, Dict, List

import pytest

from bts_sbom_app import books, books_api, chat, evals, rag

HOST = {"Host": "127.0.0.1:8800"}
BIND = ("127.0.0.1", 8800)


# --------------------------------------------------------------------------- fixtures (synthetic, no real books)
def _mini_pdf(path: str, lines: List[str]) -> str:
    """A hand-assembled one-page PDF with an uncompressed content stream - just enough for pdftotext."""
    content = "BT /F1 12 Tf 72 720 Td 14 TL\n" + "".join("(%s) Tj T*\n" % ln for ln in lines) + "ET"
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        ("<< /Length %d >>\nstream\n%s\nendstream" % (len(content), content)).encode("latin-1"),
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    out = "%PDF-1.4\n"
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out.encode("latin-1")))
        out += "%d 0 obj\n%s\nendobj\n" % (i, body.decode("latin-1"))
    xref_at = len(out.encode("latin-1"))
    out += "xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += "%010d 00000 n \n" % off
    out += "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref_at)
    with open(path, "w", encoding="latin-1", newline="\n") as fh:
        fh.write(out)
    return path


def _mini_epub(path: str, title: str = "Test Architecture Book") -> str:
    """A minimal but structurally honest EPUB: container.xml -> OPF (title, manifest, spine) -> 3 xhtml chapters.
    The chapter bodies share no vocabulary so a long query over one chapter clears the retrieval confidence gate
    (the absolute BM25 gate is tuned on real corpora; a 3-4 chunk synthetic one needs many matching rare terms)."""
    def xhtml(heading: str, body: str) -> bytes:
        return ("<?xml version=\"1.0\" encoding=\"utf-8\"?><html xmlns=\"http://www.w3.org/1999/xhtml\"><head>"
                "<title>%s</title></head><body><h1>%s</h1><p>%s</p></body></html>" % (heading, heading, body)).encode("utf-8")

    chapters = [("Chapter One Fitness", "Fitness functions validate architectural characteristics. Architects measure "
                                        "complexity, cohesion, coupling, modularity and evolvability with automated checks."),
                ("Chapter Two Circuit", "A circuit breaker protects a caller from a failing dependency through counted "
                                        "failures and a recovery probe."),
                ("Chapter Three Hexagonal", "The hexagonal style separates the domain core from adapters through ports "
                                            "and explicit edges.")]
    opf = ("<?xml version=\"1.0\"?><package xmlns=\"http://www.idpf.org/2007/opf\" version=\"3.0\" unique-identifier=\"id\">"
           "<metadata xmlns:dc=\"http://purl.org/dc/elements/1.1/\"><dc:title>%s</dc:title>"
           "<dc:identifier id=\"id\">urn:uuid:1234</dc:identifier></metadata><manifest>"
           + "".join("<item id=\"c%d\" href=\"c%d.xhtml\" media-type=\"application/xhtml+xml\"/>" % (i, i) for i in range(3))
           + "</manifest><spine>" + "".join("<itemref idref=\"c%d\"/>" % i for i in range(3)) + "</spine></package>") % title
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("mimetype", "application/epub+zip")
        zf.writestr("META-INF/container.xml",
                    "<?xml version=\"1.0\"?><container version=\"1.0\" xmlns=\"urn:oasis:names:tc:opendocument:xmlns:container\">"
                    "<rootfiles><rootfile full-path=\"OEBPS/content.opf\" media-type=\"application/oebps-package+xml\"/></rootfiles></container>")
        zf.writestr("OEBPS/content.opf", opf)
        for i, (h, b) in enumerate(chapters):
            zf.writestr("OEBPS/c%d.xhtml" % i, xhtml(h, b))
    return path


# many rare terms of chapter one: clears the absolute BM25 confidence gate even on a 3-4 chunk corpus
FITNESS_Q = "fitness functions validate architectural characteristics architects measure complexity cohesion coupling modularity evolvability automated"


@pytest.fixture()
def kb(tmp_path):
    """A built knowledge base over one synthetic EPUB and one synthetic PDF (when pdftotext exists)."""
    src = tmp_path / "src"
    src.mkdir()
    _mini_epub(str(src / "Test Architecture Book (Someone) (z-library.sk).epub"))
    pdftotext = books.find_pdftotext()
    if pdftotext:
        _mini_pdf(str(src / "Tiny Standard 2024.pdf"), ["The standard defines the language.", "Clause 6 covers declarations."])
    out = str(tmp_path / "evidence" / "books")
    reg = books.build(str(src), out)
    return types.SimpleNamespace(src=str(src), out=out, reg=reg, pdftotext=pdftotext)


def _fake_st(kb, with_index: bool = True) -> Any:
    return types.SimpleNamespace(evidence=os.path.dirname(kb.out), jobs={}, buses={},
                                 books_index=lambda: rag.Index(books.load_chunks(kb.out)) if with_index else rag.Index(()),
                                 reset_books_cache=lambda: None)


# ----------------------------------------------------------------------------------------------- extraction
def test_epub_extracts_spine_sections_with_title_and_honest_stats(tmp_path):
    """AC: BSA-AC-523. AC: BSA-AC-525."""
    p = _mini_epub(str(tmp_path / "book.epub"))
    res = books._epub_sections(p)
    assert res["title"] == "Test Architecture Book"
    assert res["spine_fallback"] is False
    assert [s["heading"] for s in res["sections"]] == ["Chapter One Fitness", "Chapter Two Circuit", "Chapter Three Hexagonal"]
    assert "fitness function" in res["sections"][0]["text"].lower()


def test_build_registry_records_every_file_with_explicit_status(kb):
    """AC: BSA-AC-523."""
    rows = kb.reg["books"]
    assert len(rows) == (2 if kb.pdftotext else 1)
    ok = [b for b in rows if b["status"] == "ok"]
    assert all(b["status"] == "ok" for b in rows)                    # the tiny pdf has a text layer when pdftotext exists
    assert {b["format"] for b in ok} <= {"pdf", "epub"}
    for b in ok:
        assert b["chars"] > 0 and b["sections"] >= 1 and 0.0 <= b["junk_ratio"] < 0.2
        assert os.path.exists(os.path.join(kb.out, b["slug"], "book.md"))
    assert kb.reg["totals"]["ok"] == len(ok)


def test_pdf_via_pdftotext_and_honest_skip_without_extractor(tmp_path, monkeypatch):
    """AC: BSA-AC-526."""
    src = tmp_path / "src"; src.mkdir()
    _mini_pdf(str(src / "Tiny Standard 2024.pdf"), ["Clause 6 covers declarations.", "A semicolon terminates a statement."])
    if books.find_pdftotext():
        reg = books.build(str(src), str(tmp_path / "out1"))
        assert reg["books"][0]["status"] == "ok"
        with open(os.path.join(str(tmp_path / "out1"), reg["books"][0]["slug"], "sections.jsonl"), encoding="utf-8") as fh:
            sec = json.loads(fh.readline())
        assert "declarations" in sec["text"]
    monkeypatch.setattr(books, "find_pdftotext", lambda: None)
    reg = books.build(str(src), str(tmp_path / "out2"), pdftotext=None)
    b = reg["books"][0]
    assert b["status"] == "skipped" and "pdftotext" in b["reason"]
    assert reg["totals"]["skipped"] == 1 and reg["totals"]["ok"] == 0


def test_pdf_with_non_ascii_filename_extracts_via_temp_copy(tmp_path):
    """AC: BSA-AC-526. The mingw64 poppler opens non-ASCII names through a non-Unicode argv (em-dash -> '?'),
    so extract_pdf routes such paths through a temporary ASCII-named copy."""
    if not books.find_pdftotext():
        pytest.skip("pdftotext not on PATH")
    src = tmp_path / "src"; src.mkdir()
    _mini_pdf(str(src / "표준 — 문서 2024.pdf"), ["Clause 6 covers declarations."])
    res = books.extract_pdf(str(src / "표준 — 문서 2024.pdf"))
    assert res["status"] == "ok" and "declarations" in res["text"]
    reg = books.build(str(src), str(tmp_path / "out"))
    assert reg["books"][0]["status"] == "ok" and reg["totals"]["ok"] == 1


def test_identical_content_is_indexed_once_and_recorded_as_duplicate(tmp_path):
    """AC: BSA-AC-524."""
    import shutil
    src = tmp_path / "src"; src.mkdir()
    _mini_epub(str(src / "Same Book.epub"))
    shutil.copyfile(str(src / "Same Book.epub"), str(src / "Same Book (copy).epub"))   # byte-identical
    reg = books.build(str(src), str(tmp_path / "out"))
    statuses = sorted(b["status"] for b in reg["books"])
    assert statuses == ["duplicate", "ok"]
    dup = next(b for b in reg["books"] if b["status"] == "duplicate")
    assert dup["duplicate_of"]


def test_load_chunks_carry_book_meta_and_kind(tmp_path):
    """AC: BSA-AC-529."""
    src = tmp_path / "src"; src.mkdir()
    _mini_epub(str(src / "b.epub"))
    out = tmp_path / "out"
    books.build(str(src), str(out))
    chunks = books.load_chunks(str(out))
    assert chunks and all(c["meta"]["kind"] == "books" for c in chunks)
    assert all(c["source"].startswith("books/") for c in chunks)
    assert any("fitness function" in c["text"].lower() for c in chunks)


def test_outline_returns_headings_and_sizes_only(tmp_path):
    """AC: BSA-AC-527."""
    src = tmp_path / "src"; src.mkdir()
    _mini_epub(str(src / "Outline Book.epub"))
    out = str(tmp_path / "out")
    reg = books.build(str(src), out)
    slug = next(b["slug"] for b in reg["books"] if b["status"] == "ok")
    doc = books.outline(out, slug)
    assert doc["slug"] == slug and len(doc["outline"]) == 3
    assert all(set(s) == {"heading", "chars"} for s in doc["outline"])
    assert books.outline(out, "no-such-slug") is None


def test_books_and_notes_stay_out_of_the_evaluation_corpus(tmp_path):
    """AC: BSA-AC-529."""
    root = tmp_path / "repo"; (root / "knowledge").mkdir(parents=True)
    (root / "knowledge" / "a.md").write_text("# A\n\nthe curated corpus only\n", encoding="utf-8")
    src = root / "src"; src.mkdir()
    _mini_epub(str(src / "b.epub"))
    books.build(str(src), str(root / "evidence" / "books"))
    (root / "knowledge_books").mkdir()
    (root / "knowledge_books" / "note.md").write_text("# A book note\n\n## 이 프로젝트 적용\n\nserves, never evaluates\n", encoding="utf-8")
    idx = evals.build_index(str(root))
    kinds = {c["meta"]["kind"] for c in idx.chunks}
    assert "books" not in kinds
    assert not any(c["source"].startswith(("books/", "knowledge_books/")) for c in idx.chunks)
    notes = books.load_notes(str(root))
    assert notes and all(c["meta"]["kind"] == "knowledge" and c["source"].startswith("knowledge_books/") for c in notes)


# ----------------------------------------------------------------------------------------------- books_api
def test_api_registry_search_and_outline(kb):
    """AC: BSA-AC-527."""
    st = _fake_st(kb)
    code, obj, _, _ = books_api.route("GET", "/api/books", {}, {}, HOST, st, BIND)
    assert code == 200 and obj["built"] is True and obj["totals"]["ok"] >= 1
    code, obj, _, _ = books_api.route("GET", "/api/books/search", {"q": [FITNESS_Q]}, {}, HOST, st, BIND)
    assert code == 200 and obj["found"] is True and obj["results"]
    row = obj["results"][0]
    assert row["book"] and row["source"].startswith("books/") and len(row["snippet"]) <= 241 and "took_ms" in obj
    slug = next(b["slug"] for b in kb.reg["books"] if b["status"] == "ok")
    code, obj, _, _ = books_api.route("GET", "/api/books/%s" % slug, {}, {}, HOST, st, BIND)
    assert code == 200 and len(obj["outline"]) == 3
    code, obj, _, _ = books_api.route("GET", "/api/books/nope", {}, {}, HOST, st, BIND)
    assert code == 404
    code, obj, _, _ = books_api.route("GET", "/api/books/search", {"q": [""]}, {}, HOST, st, BIND)
    assert code == 400
    code, obj, _, _ = books_api.route("GET", "/api/books/search", {"q": ["x" * 400]}, {}, HOST, st, BIND)
    assert code == 400


def test_api_search_on_empty_library_is_honest(tmp_path):
    """AC: BSA-AC-527."""
    st = types.SimpleNamespace(evidence=str(tmp_path), jobs={}, buses={}, books_index=lambda: rag.Index(()))
    code, obj, _, _ = books_api.route("GET", "/api/books", {}, {}, HOST, st, BIND)
    assert code == 200 and obj["built"] is False and obj["hint"]
    code, obj, _, _ = books_api.route("GET", "/api/books/search", {"q": ["anything"]}, {}, HOST, st, BIND)
    assert code == 200 and obj["found"] is False and "ingest" in obj["reason"]


def test_ingest_job_runs_and_refuses_concurrent_and_bad_src(tmp_path):
    """AC: BSA-AC-531."""
    src = tmp_path / "src"; src.mkdir()
    _mini_epub(str(src / "Job Book.epub"))
    ev = tmp_path / "evidence"; ev.mkdir()
    st = types.SimpleNamespace(evidence=str(ev), jobs={}, buses={}, books_index=lambda: rag.Index(()),
                               reset_books_cache=lambda: None)
    code, obj, _, _ = books_api.route("POST", "/api/books/ingest", {}, {"src": str(src)}, HOST, st, BIND)
    assert code == 202 and obj["job"]
    jid = obj["job"]
    for _ in range(200):
        if st.jobs[jid].get("state") != "running":
            break
        time.sleep(0.05)
    assert st.jobs[jid]["state"] == "done" and st.jobs[jid]["totals"]["ok"] == 1
    assert books.load_registry(os.path.join(str(ev), "books")) is not None
    # a src that is not an existing local folder -> 400 (books are read, never fetched)
    for bad in ("", "x" * 1001, str(tmp_path / "missing")):
        code, obj, _, _ = books_api.route("POST", "/api/books/ingest", {}, {"src": bad}, HOST, st, BIND)
        assert code == 400
    # a second ingest while one runs -> 429
    st.jobs["runningjob"] = {"kind": "books", "state": "running"}
    code, obj, _, _ = books_api.route("POST", "/api/books/ingest", {}, {"src": str(src)}, HOST, st, BIND)
    assert code == 429


def test_cross_origin_post_is_refused(tmp_path):
    """AC: BSA-AC-531."""
    st = types.SimpleNamespace(evidence=str(tmp_path), jobs={}, buses={})
    bad = dict(HOST, Origin="http://evil.example", **{"Sec-Fetch-Site": "cross-site"})
    code, obj, _, _ = books_api.route("POST", "/api/books/ingest", {}, {"src": str(tmp_path)}, bad, st, BIND)
    assert code == 403


# ----------------------------------------------------------------------------------------------- chat tool
def test_book_search_lines_honest_when_library_empty():
    """AC: BSA-AC-528."""
    lines = chat.run_tool(None, "book_search", {"q": "fitness"}, books=None)[0]["lines"]
    assert "No book knowledge base is loaded" in lines[0]


def test_book_search_lines_cite_book_and_section(kb):
    """AC: BSA-AC-532."""
    idx = rag.Index(books.load_chunks(kb.out))
    out = chat.run_tool(None, "book_search", {"q": FITNESS_Q}, books=idx)[0]
    assert out["trust"] == "book"
    hits = [ln for ln in out["lines"] if ln.startswith("[book]")]
    assert hits and "Test Architecture Book" in hits[0]
    assert out["lines"][-1].startswith("Quoted from the local book library")


def test_validate_calls_accepts_book_search_without_project():
    """AC: BSA-AC-528."""
    ok, dropped = chat.validate_calls([{"tool": "book_search", "args": {"q": "circuit breaker"}}], None)
    assert ok and not any(dropped.values())
    assert chat.run_tool(None, "book_search", ok[0]["args"], books=rag.Index(()))[0]["lines"][0].startswith("No book")


def test_fleet_question_routes_to_book_search(kb):
    """AC: BSA-AC-528."""
    idx = rag.Index(books.load_chunks(kb.out))
    bot = chat.Chatbot(rag.Index([{"id": "k#0", "source": "knowledge/a.md", "heading": "A", "text": "the curated corpus", "meta": {"kind": "knowledge"}}]),
                       books=idx)
    res = bot.ask("책에서 %s 알려줘" % FITNESS_Q)
    assert res["found"] is True and "book_search" in res["tools"]
    assert "[book]" in res["answer"] and res["answer_source"] == "tools"


def test_english_book_question_routes_too(kb):
    """AC: BSA-AC-528."""
    idx = rag.Index(books.load_chunks(kb.out))
    bot = chat.Chatbot(rag.Index([]), books=idx)
    res = bot.ask("what do the books say about the hexagonal style?")
    assert "book_search" in res["tools"] and res["found"] is True


# ----------------------------------------------------------------------------------------------- distilled notes
def test_distilled_notes_carry_the_apply_section():
    """AC: BSA-AC-530."""
    root = evals.repo_root()
    folder = os.path.join(root, books.NOTES_DIR)
    notes = [fn for fn in os.listdir(folder) if fn.endswith(".md")] if os.path.isdir(folder) else []
    assert len(notes) >= 25, "the distilled notes of the ingested book library must exist"
    for fn in notes:
        with open(os.path.join(folder, fn), "r", encoding="utf-8") as fh:
            txt = fh.read()
        assert "## 이 프로젝트 적용" in txt, "%s lacks the apply-to-project section" % fn
        assert max((len(line) for line in txt.splitlines()), default=0) <= 400      # notes, not pasted book text
    reg = books.load_registry(books.books_dir(os.path.join(root, "evidence")))
    if reg:
        ok = {b["slug"] for b in reg.get("books", []) if b.get("status") == "ok"}
        stems = {fn[:-3] for fn in notes}
        assert ok <= stems, "indexed books without a distilled note: %s" % sorted(ok - stems)
