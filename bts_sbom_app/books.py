"""Book knowledge base: extract the text of a local folder of PDF/EPUB architecture books into a deterministic,
LLM-free store under ``<evidence>/books/`` and hand it to the retrieval layer as ``kind="books"`` chunks.

Per book the builder writes ``sections.jsonl`` (heading/text), ``book.md`` (heading-structured markdown the
retriever chunks) and ``stats.json`` (pages, chars, chars/page, junk ratio); ``registry.json`` records every
attempted file with an explicit status - ``ok``, ``skipped`` (with a reason, e.g. no PDF text extractor on PATH)
or ``duplicate`` (same SHA-256 as an already-indexed file). Nothing is silently dropped.

Extraction discipline (ADR-0021): EPUB is parsed with the standard library only (zipfile + html.parser +
xml.etree, so ADR-0007's zero-dependency rule holds); PDF text comes from an external ``pdftotext`` binary when
one is on PATH - absent, PDFs are reported skipped rather than half-parsed. The extracted book text is the
user's own local copy and stays inside the gitignored ``evidence/books/`` folder; only code and our own
distilled notes (``knowledge/books/``, kind="knowledge") are tracked.
"""
from __future__ import annotations

import hashlib
import html.parser
import json
import os
import posixpath
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
import zipfile
from typing import Any, Callable, Dict, List, Optional

from . import rag
from .util import now_iso, read_json, write_json

SCHEMA = "bts-sbom.books.v1"
REGISTRY = "registry.json"
_CHUNK_SIZE = 1600          # book text is less dense per heading than the curated knowledge notes
_CHUNK_OVERLAP = 120
_PDFTOTEXT_TIMEOUT = 600    # seconds per book; ISO standards run to thousands of pages
_BLOCK_TAGS = {"p", "div", "br", "li", "ul", "ol", "tr", "table", "blockquote", "section", "article",
               "h1", "h2", "h3", "h4", "h5", "h6", "pre", "figcaption"}
_SKIP_TAGS = {"script", "style", "head", "svg"}
_HEADING_TAGS = {"h1", "h2", "h3", "h4", "h5", "h6"}


# ----------------------------------------------------------------------------------------------- extraction
class _HTMLText(html.parser.HTMLParser):
    """Collect visible text of one XHTML spine document, remembering its first heading as the section title."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title: Optional[str] = None
        self.parts: List[str] = []
        self._skip = 0
        self._capture = False

    def handle_starttag(self, tag: str, attrs: Any) -> None:
        if tag in _SKIP_TAGS:
            self._skip += 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if self.title is None and tag in _HEADING_TAGS:
            self._capture = True
        else:
            self._capture = False

    def handle_startendtag(self, tag: str, attrs: Any) -> None:
        if tag in _BLOCK_TAGS:
            self.parts.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIP_TAGS and self._skip:
            self._skip -= 1
        elif tag in _BLOCK_TAGS:
            self.parts.append("\n")
        if tag in _HEADING_TAGS:
            self._capture = False

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        if self._capture and self.title is None and data.strip():
            self.title = data.strip()[:200]
        self.parts.append(data)

    def text(self) -> str:
        raw = "".join(self.parts)
        lines = [re.sub(r"[ \t\r\f\v]+", " ", ln).strip() for ln in raw.split("\n")]
        return "\n".join(ln for ln in lines if ln)


def _epub_sections(path: str) -> Dict[str, Any]:
    """Spine-ordered sections of one EPUB. Falls back to the sorted .xhtml/.html members (recorded as
    ``spine_fallback``) when the container/OPF cannot be honoured - the fallback is reported, never silent."""
    with zipfile.ZipFile(path) as zf:
        names = set(zf.namelist())
        rootfile = None
        if "META-INF/container.xml" in names:
            root = ET.fromstring(zf.read("META-INF/container.xml"))
            for rf in root.iter():
                if rf.tag.split("}")[-1] == "rootfile" and rf.get("full-path"):
                    rootfile = rf.get("full-path")
                    break
        title, href_by_id, spine = None, {}, None
        if rootfile and rootfile in names:
            opf = ET.fromstring(zf.read(rootfile))
            opf_dir = posixpath.dirname(rootfile)
            for el in opf.iter():
                tag = el.tag.split("}")[-1]
                if tag == "title" and title is None and el.text:
                    title = el.text.strip()[:300]
                elif tag == "item" and el.get("id") and el.get("href"):
                    href_by_id[el.get("id")] = el.get("href")
                elif tag == "itemref" and el.get("idref"):
                    spine = [] if spine is None else spine
                    spine.append(el.get("idref"))
            ids = spine if spine is not None else list(href_by_id)
            docs = [posixpath.join(opf_dir, href_by_id[i]) for i in ids if i in href_by_id]
        else:
            docs = []
        if not docs:                                        # degraded but honest: index what is actually there
            docs = sorted(n for n in names if n.lower().endswith((".xhtml", ".html", ".htm"))
                          and not n.startswith("META-INF/"))
            fallback = True
        else:
            fallback = False
        sections: List[Dict[str, str]] = []
        for i, href in enumerate(docs):
            href = urllib.parse.unquote(href.split("#")[0])
            if href not in names:
                continue
            parser = _HTMLText()
            try:
                parser.feed(zf.read(href).decode("utf-8", "replace"))
            except Exception:                                 # noqa: BLE001 - one broken spine page must not kill the book
                continue
            text = parser.text().strip()
            if text:
                sections.append({"heading": parser.title or "%s #%d" % (os.path.basename(href), i + 1), "text": text})
    return {"title": title, "sections": sections, "spine_fallback": fallback}


def find_pdftotext() -> Optional[str]:
    return shutil.which("pdftotext")


def extract_pdf(path: str, pdftotext: Optional[str] = None) -> Dict[str, Any]:
    """Text of one PDF via an external ``pdftotext`` (poppler). No extractor or a failing/empty run is an explicit
    ``skipped`` result with a reason - the builder never invents text and never half-indexes a PDF. A path with
    non-ASCII characters is first copied to a temporary ASCII-named file: the mingw64 poppler build receives argv
    through a non-Unicode CRT, so an em-dash or Cyrillic character in the file name arrives as '?' and the file
    cannot be opened (measured on the real library, 2026-11-22)."""
    tool = pdftotext or find_pdftotext()
    if not tool:
        return {"status": "skipped", "reason": "no pdf text extractor on PATH (pdftotext not found)"}
    tmp = None
    try:
        run_path = path
        if not path.isascii():
            fd, tmp = tempfile.mkstemp(suffix=".pdf")
            os.close(fd)
            shutil.copyfile(path, tmp)
            run_path = tmp
        try:
            proc = subprocess.run([tool, "-enc", "UTF-8", run_path, "-"], capture_output=True, timeout=_PDFTOTEXT_TIMEOUT)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "skipped", "reason": "pdftotext failed: %s" % (str(exc)[:200])}
        if proc.returncode != 0:
            return {"status": "skipped", "reason": "pdftotext exit %s: %s" % (
                proc.returncode, proc.stderr.decode("utf-8", "replace").strip()[:200] or "no error message")}
        text = proc.stdout.decode("utf-8", "replace").replace("\x00", "")
        if not text.strip():
            return {"status": "skipped", "reason": "no text layer (likely a scanned image-only PDF)"}
        return {"status": "ok", "text": text, "pages": text.count("\f") + (1 if text.strip() else 0)}
    finally:
        if tmp:
            try:
                os.remove(tmp)
            except OSError:
                pass


# -------------------------------------------------------------------------------------------------- modelling
def _clean_title(stem: str) -> str:
    t = re.sub(r"\s*\((?:z[- ]?lib|1lib)[^)]*\)", "", stem, flags=re.I)
    return re.sub(r"\s{2,}", " ", t).strip(" -")


def _slug(title: str) -> str:
    s = re.sub(r"[^a-z0-9]+", "-", title.lower()).strip("-")
    return (s or "book")[:80]


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


def _junk_ratio(text: str) -> float:
    if not text:
        return 0.0
    bad = sum(1 for ch in text if (not ch.isprintable() and ch not in "\n\t") or ch == "\ufffd")
    return round(bad / len(text), 4)


def build(src: str, out_dir: str, *, pdftotext: Optional[str] = None,
          progress: Optional[Callable[[Dict[str, Any]], None]] = None) -> Dict[str, Any]:
    """Index every .pdf/.epub under ``src`` (recursively, sorted for determinism) into ``out_dir``. Every file gets
    a registry entry with an explicit status; identical content (SHA-256) is indexed once and the rest are recorded
    as duplicates. Returns the written registry."""
    def emit(ev: Dict[str, Any]) -> None:
        if progress:
            try:
                progress(ev)
            except Exception:                                 # noqa: BLE001 - telemetry must never kill the run
                pass

    files: List[str] = []
    for dp, _, fns in os.walk(src):
        for fn in sorted(fns):
            if fn.lower().endswith((".pdf", ".epub")):
                files.append(os.path.join(dp, fn))
    files.sort()
    os.makedirs(out_dir, exist_ok=True)
    tool = pdftotext if pdftotext is not None else find_pdftotext()
    seen: Dict[str, str] = {}
    used_slugs: Dict[str, int] = {}
    books: List[Dict[str, Any]] = []
    for path in files:
        emit({"step": "file", "book": os.path.basename(path)})
        base = {"file": os.path.basename(path), "path": path, "format": "pdf" if path.lower().endswith(".pdf") else "epub"}
        try:
            sha = _sha256(path)
        except OSError as exc:
            books.append({**base, "slug": "", "title": _clean_title(os.path.splitext(base["file"])[0]),
                          "status": "skipped", "reason": "unreadable: %s" % str(exc)[:160]})
            continue
        if sha in seen:
            books.append({**base, "slug": "", "title": _clean_title(os.path.splitext(base["file"])[0]),
                          "status": "duplicate", "sha256": sha, "duplicate_of": seen[sha]})
            continue
        seen[sha] = path
        title = _clean_title(os.path.splitext(base["file"])[0])
        if base["format"] == "epub":
            try:
                res = _epub_sections(path)
            except (OSError, zipfile.BadZipFile, ET.ParseError) as exc:
                books.append({**base, "slug": "", "title": title, "sha256": sha, "status": "skipped",
                              "reason": "epub parse failed: %s" % str(exc)[:160]})
                continue
            status, sections = "ok", res["sections"]
            text_all = "\n".join(s["text"] for s in sections)
            entry = {**base, "sha256": sha, "title": res["title"] or title, "spine_fallback": res["spine_fallback"]}
        else:
            res = extract_pdf(path, tool)
            if res.get("status") != "ok":
                books.append({**base, "slug": "", "title": title, "sha256": sha, "status": "skipped",
                              "reason": res.get("reason", res.get("status", "unknown"))})
                continue
            status = "ok"
            sections = [{"heading": title, "text": res["text"].replace("\r\n", "\n").replace("\r", "\n")}]
            text_all = res["text"]
            entry = {**base, "sha256": sha, "title": title}
        slug = _slug(entry["title"])
        n = used_slugs.get(slug, 0)
        used_slugs[slug] = n + 1
        if n:
            slug = "%s-%d" % (slug, n + 1)
        stats = {"sections": len(sections), "chars": len(text_all), "junk_ratio": _junk_ratio(text_all),
                 "pages": res.get("pages")}
        if stats["chars"]:
            stats["chars_per_page"] = round(stats["chars"] / max(1, stats["pages"] or stats["sections"]), 0)
        slug_dir = os.path.join(out_dir, slug)
        os.makedirs(slug_dir, exist_ok=True)
        with open(os.path.join(slug_dir, "sections.jsonl"), "w", encoding="utf-8") as fh:
            for s in sections:
                fh.write(json.dumps({"heading": s["heading"], "text": s["text"]}, ensure_ascii=False) + "\n")
        with open(os.path.join(slug_dir, "book.md"), "w", encoding="utf-8") as fh:
            fh.write("# %s\n\n" % entry["title"])
            for s in sections:
                fh.write("## %s\n\n%s\n\n" % (s["heading"], s["text"]))
        write_json(os.path.join(slug_dir, "stats.json"), stats)
        books.append({**entry, "slug": slug, "status": status, **stats})
    ok = [b for b in books if b.get("status") == "ok"]
    registry = {"schema": SCHEMA, "built_at": now_iso(), "src": os.path.abspath(src), "pdftotext": tool,
                "totals": {"files": len(files), "ok": len(ok), "skipped": len(books) - len(ok) - sum(1 for b in books if b.get("status") == "duplicate"),
                           "duplicates": sum(1 for b in books if b.get("status") == "duplicate"),
                           "sections": sum(b.get("sections", 0) for b in ok), "chars": sum(b.get("chars", 0) for b in ok)},
                "books": books}
    write_json(os.path.join(out_dir, REGISTRY), registry)
    return registry


# --------------------------------------------------------------------------------------------------- retrieval
def books_dir(evidence: str) -> str:
    return os.path.join(evidence, "books")


def load_registry(out_dir: str) -> Optional[Dict[str, Any]]:
    reg = read_json(os.path.join(out_dir, REGISTRY), None)
    return reg if isinstance(reg, dict) and reg.get("schema") == SCHEMA else None


def outline(out_dir: str, slug: str) -> Optional[Dict[str, Any]]:
    """Chapter/section outline of one indexed book (headings + sizes only - never the full text over the wire)."""
    reg = load_registry(out_dir)
    entry = next((b for b in (reg or {}).get("books", []) if b.get("slug") == slug and b.get("status") == "ok"), None)
    if entry is None:
        return None
    secs: List[Dict[str, Any]] = []
    try:
        with open(os.path.join(out_dir, slug, "sections.jsonl"), "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                s = json.loads(line)
                secs.append({"heading": s["heading"], "chars": len(s["text"])})
    except OSError:
        return None
    return {k: entry.get(k) for k in ("slug", "title", "format", "sections", "chars", "pages")} | {"outline": secs}


def load_chunks(out_dir: str) -> List[Dict[str, Any]]:
    """``kind="books"`` retrieval chunks over every indexed book. This corpus is serve-time only - it never enters
    ``evals.build_index`` (the RAG golden/dev/test metric baselines measure the curated corpus, ADR-0021)."""
    reg = load_registry(out_dir)
    if not reg:
        return []
    chunks: List[Dict[str, Any]] = []
    for b in reg.get("books", []):
        if b.get("status") != "ok":
            continue
        path = os.path.join(out_dir, b["slug"], "book.md")
        try:
            with open(path, "r", encoding="utf-8") as fh:
                md = fh.read()
        except OSError:
            continue
        chunks.extend(rag.chunk_markdown(md, "books/%s.md" % b["slug"], size=_CHUNK_SIZE, overlap=_CHUNK_OVERLAP,
                                         meta={"kind": "books", "book": b.get("title") or b["slug"], "format": b.get("format")}))
    return chunks


NOTES_DIR = "knowledge_books"


def load_notes(root: str) -> List[Dict[str, Any]]:
    """The distilled notes (our own synthesis of the books, kind="knowledge") as serve-time-only chunks. They live
    outside ``knowledge/`` on purpose: when the notes sat inside the eval corpus they measurably regressed the
    RAG golden/dev/test baselines (dev recall 0.933 -> 0.867, beyond the 0.02 gate tolerance - ADR-0021), so they
    load into the chat index next to the raw book chunks and never into ``evals.build_index``."""
    d = os.path.join(root, NOTES_DIR)
    if not os.path.isdir(d):
        return []
    chunks = rag.load_dir(d, kind="knowledge")
    for c in chunks:
        c["source"] = NOTES_DIR + "/" + c["source"]
    return chunks


MAP_DOC = os.path.join("docs", "BOOK_IMPROVEMENT_MAP.md")


def _split_md_sections(text: str) -> List[tuple]:
    """The "## <heading>" sections of a note as (heading, body-lines) pairs, in file order."""
    sections: List[tuple] = []
    head, lines = None, []
    for ln in text.splitlines():
        if ln.startswith("## "):
            if head is not None:
                sections.append((head, lines))
            head, lines = ln[3:].strip(), []
        elif head is not None:
            lines.append(ln)
    if head is not None:
        sections.append((head, lines))
    return sections


def _bullet_lines(lines: List[str]) -> List[str]:
    """The non-empty bullet text of a section body ("- x" -> "x"), in order."""
    out = []
    for ln in lines:
        s = ln.strip()
        if s.startswith("- "):
            out.append(s[2:].strip())
    return out


def read_notes(root: str) -> Dict[str, Any]:
    """The distilled notes (knowledge_books/*.md) in their authored shape - title, the 출처 line naming the book
    they synthesize, the 핵심 원칙 and the 이 프로젝트 적용 bullets. This is the INFERENCE OUTPUT the Book KB
    screen exists for: the books are read-only raw material, these notes are what our service took from them
    (사용자 지정 2026-11-22: the book KB is not a database to build, it is material for reasoning about how to
    upgrade this service). Read-only; a missing folder is an honest empty list, never an error."""
    if not root:                                       # no root -> never fall back to the CWD (a test double or a
        return {"notes": [], "total": 0, "hint": "no knowledge_books/ folder - nothing distilled yet"}
    d = os.path.join(root, NOTES_DIR)
    if not os.path.isdir(d):
        return {"notes": [], "total": 0, "hint": "no knowledge_books/ folder - nothing distilled yet"}
    notes = []
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".md"):
            continue
        try:
            with open(os.path.join(d, fn), "r", encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        title, source = "", ""
        for ln in text.splitlines():
            if ln.startswith("# ") and not title:
                title = ln[2:].strip()
            if ln.startswith("출처:"):
                source = ln[len("출처:"):].strip()
        secs = {h: _bullet_lines(ls) for h, ls in _split_md_sections(text)}
        principles = next((v for k, v in secs.items() if k.startswith("핵심 원칙")), [])
        applied = next((v for k, v in secs.items() if k.startswith("이 프로젝트 적용")), [])
        notes.append({"file": NOTES_DIR + "/" + fn, "title": title or fn[:-3], "book": source,
                      "principles": principles, "applied": applied})
    return {"notes": notes, "total": len(notes)}


def read_improvement_map(root: str) -> Dict[str, Any]:
    """docs/BOOK_IMPROVEMENT_MAP.md parsed into its "## <area>" tables: every book technique with its status
    (구현 / 신규 구현 / 부분 / 기각·비적용, AC cited) and its evidence - the machine-readable answer to
    "which book techniques did this service actually adopt". A missing doc is an honest empty map."""
    if not root:                                       # no root -> never fall back to the CWD (see read_notes)
        return {"sections": [], "source": MAP_DOC, "hint": "no improvement-map doc"}
    path = os.path.join(root, MAP_DOC)
    if not os.path.isfile(path):
        return {"sections": [], "source": MAP_DOC, "hint": "no improvement-map doc"}
    sections: List[Dict[str, Any]] = []
    area: Optional[str] = None
    for ln in open(path, "r", encoding="utf-8").read().splitlines():
        if ln.startswith("## "):
            area = ln[3:].strip()
            sections.append({"area": area, "headers": [], "rows": []})
            continue
        if area is None or not ln.strip().startswith("|"):
            continue
        cells = [c.strip().replace("**", "") for c in ln.strip().strip("|").split("|")]
        if all(set(c) <= set("-: ") and c for c in cells):      # the |---|---| separator row
            continue
        sec = sections[-1]
        if not sec["rows"] and not sec["headers"] and len(sec["headers"]) == 0:
            sec["headers"] = cells                              # the first table row of the section is its header
        else:
            sec["rows"].append(cells)
    return {"sections": [s for s in sections if s["rows"]], "source": MAP_DOC}
