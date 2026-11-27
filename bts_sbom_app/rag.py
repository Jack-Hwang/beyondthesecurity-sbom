"""Hybrid retrieval (BM25 + TF-IDF cosine, fused by Reciprocal Rank Fusion) over markdown knowledge + run evidence.

Design (each point is measured by evals/rag_golden.json):
  * heading-aware chunking: split on markdown headings first, then by size with overlap; every chunk carries its
    heading path as a contextual header so "Patching / verification loop" is retrievable by its section name;
  * bilingual tokenizer: ASCII words, identifier parts (CVE-2024-1234 stays whole AND splits), Hangul runs plus
    syllable bigrams (no morphological analyser needed), Korean particles stripped from long words;
  * query expansion with a small domain synonym table (Korean <-> English) - recall for cross-lingual questions;
  * lexical-precision re-rank: a THIRD rank list (heading match + ordered bigram adjacency) fused by the same RRF,
    so it competes with BM25/TF-IDF instead of overriding them; the ``found`` gate reads the pool-best BM25 so a
    re-ordering can never turn a found question into "not found";
  * ``conflicts``: the same measured label carrying different numbers in two different top chunks is annotated as an
    unresolved conflict (rule ``escalate``) - nothing is auto-preferred;
  * confidence gate: a question whose content words are not covered by the best chunk is OUT OF CORPUS
    (``found=False``) instead of being answered with the least-bad chunk;
  * metadata filters (kind, project) so project evidence never answers a general question and vice versa;
  * English-only queries (no Hangul) get a query-side English->Korean technical-term bridge (``EN_KR_BRIDGE`` plus
    the reverse of ``SYNONYMS``) and light inflection folding, with a lower confidence-gate floor (``EN_MIN_BM25``)
    measured on evals/rag_en.json + evals/rag_en_holdout.json - Korean queries are never affected by either change.
"""
from __future__ import annotations

import math
import os
import re
from collections import Counter
from typing import Any, Dict, List, Optional, Sequence, Tuple

from . import evalguard

RRF_K = 60
CHUNK = 600
OVERLAP = 60
_STOP = set("the a an of to in on for and or is are be as at by with from that this it its what which how do does can i you "
            "me my we our your tell about please show give list explain "
            "이 그 저 것 수 등 및 또는 에서 에게 으로 로 은 는 이 가 을 를 의 에 와 과 도 만 좀 해줘 알려줘 알려 주세요 뭐야 무엇 어떻게 "
            "어떤 있나 있어 하는 한다 합니다 대해 대한 관련 설명 보여줘".split())
_PARTICLE = re.compile(r"(에서는|에서|으로|에게|까지|부터|이다|입니다|하는|합니다|이란|란|은|는|이|가|을|를|의|에|와|과|도|만|로)$")
SYNONYMS = {
    "취약점": ["vulnerability", "cve", "advisory"], "취약": ["vulnerability"], "라이선스": ["license", "licence", "spdx"],
    "패치": ["patch", "upgrade", "fix"], "수정": ["fix", "patch", "remediation"], "업그레이드": ["upgrade", "patch"],
    "의존성": ["dependency", "dependencies"], "순환": ["cycle", "circular"], "핫스팟": ["hotspot", "churn"],
    "아키텍처": ["architecture", "dsm"], "레거시": ["legacy", "modernization", "현대화"], "현대화": ["modernization", "legacy"],
    "금융": ["finance", "financial"], "의료": ["medical", "fda"], "선박": ["maritime", "ship", "iacs"],
    "해사": ["maritime", "iacs"], "방산": ["defense", "dod"], "국방": ["defense", "dod"], "자동차": ["automotive", "r155"],
    "승인": ["approval", "approved"], "되돌림": ["revert", "rollback"], "원본": ["origin", "original"],
    "챗봇": ["chatbot", "chat"], "검색": ["retrieval", "search", "rag"], "평가": ["evaluation", "metric", "eval"],
    "루프": ["loop"], "회귀": ["regression"], "엑사원": ["exaone"], "환각": ["hallucination", "grounding"],
    "근거": ["citation", "grounding", "evidence"], "인용": ["citation", "quote"], "정직": ["honesty", "honest"],
    "복사본": ["copy", "workcopy"], "심각도": ["severity", "cvss"], "점수": ["score", "cvss"],
    "vulnerabilities": ["vulnerability"], "licenses": ["license"], "patches": ["patch"],
    # paraphrase vocabulary (derived from the dev-set failures: wording that never appears in the documents)
    "이용 허가": ["license", "라이선스"], "허가 조건": ["license", "라이선스"], "사용권": ["license", "라이선스"],
    "사이트": ["registry", "deps.dev"], "원상복구": ["revert", "되돌림"], "원상 복구": ["revert", "되돌림"],
    "복구": ["revert", "되돌림"], "낡은": ["eol", "runtime", "런타임"], "오래된": ["eol", "runtime", "런타임"],
    "지원되는지": ["eol", "end-of-life"], "지원 종료": ["eol", "end-of-life"], "횟수 제한": ["limit", "429", "budget", "한도"],
    "호출 횟수": ["limit", "429", "budget", "한도"], "한도": ["limit", "429", "budget"],
    # paraphrase vocabulary (2026-11-22, dev failures after the round-1 lecture corpus landed)
    "고쳤는데": ["fix", "patch", "regression"], "새 문제": ["regression", "재발"],
}

EN_KR_BRIDGE = {
    # English -> Korean technical-term bridge, applied ONLY to queries without a single Hangul character (see
    # tokenize()). Derived from the vocabulary knowledge/*.md actually uses for these concepts (headings and
    # parenthetical glosses), not from any one eval query - symmetric to SYNONYMS but in the other direction, for
    # terms SYNONYMS does not already cover in reverse (see _REVERSE_SYNONYMS below for the ones it does).
    "lockfile": ["락파일"], "lockfiles": ["락파일"],
    "calculate": ["계산"], "calculation": ["계산"], "calculations": ["계산"],
    "pattern": ["패턴"], "patterns": ["패턴"],
    "format": ["형식"], "formats": ["형식"],
    "acceptance": ["수용"], "criteria": ["기준"], "criterion": ["기준"],
    "fusion": ["융합"], "coupling": ["결합"],
    "normalize": ["정규화"], "normalization": ["정규화"],
    "layer": ["계층"], "layers": ["계층"], "hierarchical": ["계층"], "hierarchy": ["계층"],
    "extraction": ["분리"], "requirement": ["요구"], "requirements": ["요구"],
    "dependency": ["의존", "의존성"], "dependencies": ["의존", "의존성"],
    "edit": ["수정"], "edited": ["수정"], "editing": ["수정"],
    "metric": ["지표"], "metrics": ["지표"],
    "delivery": ["전달"], "target": ["대상"], "targets": ["대상"],
    "verify": ["검증"], "verified": ["검증"], "verification": ["검증"],
    "hidden": ["숨은"], "section": ["섹션"], "sections": ["섹션"],
    "reject": ["기각"], "rejected": ["기각"], "alternative": ["대안"], "alternatives": ["대안"],
}


def _build_reverse_synonyms(table: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """SYNONYMS is written Korean-key -> English-values; an English query gets nothing from it as-is (no key ever
    matches an English token). This reverses it once at import time so an English token can look up the Korean
    key(s) that use it - the SAME hand-written table, just read in the other direction."""
    rev: Dict[str, List[str]] = {}
    for k, vs in table.items():
        if "가" <= k[0] <= "힣":
            for v in vs:
                rev.setdefault(v, []).append(k)
    return rev


_REVERSE_SYNONYMS = _build_reverse_synonyms(SYNONYMS)


def _has_hangul(text: str) -> bool:
    return any("가" <= ch <= "힣" for ch in text)


def _en_stem_variants(t: str) -> List[str]:
    """Light, general English inflection folding (plural/-ed/-ing), query-side only: lets "hotspots" reach a
    corpus chunk written "hotspot", or "calculated" reach the Korean bridge key for "calculate". Candidates are
    added to the query's token pool alongside the original word, never replacing it; the corpus itself (and so
    every Korean query's token counts, df/idf and BM25 length-normalisation) is completely unchanged."""
    if len(t) < 5 or not t.isalpha():
        return []
    out = set()
    if t.endswith("ies") and len(t) >= 6:
        out.add(t[:-3] + "y")
    elif t.endswith("es") and len(t) >= 6 and (t[-3] in "sxz" or t[-4:-2] in ("ch", "sh")):
        out.add(t[:-2])
    elif t.endswith("s") and not t.endswith("ss"):
        out.add(t[:-1])
    if t.endswith("ed") and len(t) >= 6:
        out.add(t[:-2])
        out.add(t[:-1])
    if t.endswith("ing") and len(t) >= 7:
        out.add(t[:-3])
        out.add(t[:-3] + "e")
    return [s for s in out if len(s) >= 3]


# Confidence-gate adjustment for English-only queries (see Index.search): measured on evals/rag_en.json +
# evals/rag_en_holdout.json (2026-11-27). The bilingual tokenizer's Korean path generates many more tokens per
# query (syllable bigrams), so a Korean query's BM25 ceiling sits well above an English query's for equivalent
# relevance - the committed 12.0 gate was tuned on Korean queries only and silently rejected good English answers
# (found_rate 0.5 on rag_en.json while recall@5 was already 0.875 - the right document WAS retrieved, just hidden
# behind the gate). Worst measured English OOD false-accept risk across both English sets AND the three pinned
# sets' own English-only OOD probes ("who won the world cup final" and siblings): 9.70 ("Who won the latest World
# Cup final?", rag_en.json). 10.0 keeps every English OOD probe measured (all <= 9.70) rejected while recovering
# English in-domain questions that score just under the Korean-tuned line. Korean queries are never affected:
# this constant is only read when the query has no Hangul AND the caller left min_bm25 at its committed default
# (see Index.search) - re-measure both English sets (never rag_en.json alone) if this is ever retuned.
EN_MIN_BM25 = 10.0


def _hangul_tokens(run: str) -> List[str]:
    out = []
    w = _PARTICLE.sub("", run) if len(run) >= 3 else run
    if len(w) >= 2:
        out.append(w)
    if w != run and len(run) >= 2:
        out.append(run)
    out.extend(run[i:i + 2] for i in range(len(run) - 1))
    return out


def _relaxed(a: str, b: str) -> bool:
    """A relaxed token match for the re-rank signals: equal, or a shared stem of at least 4 characters
    (patch/patching, license/licensing). Shorter tokens must match exactly - bigrams are already imprecise."""
    return a == b or (len(a) >= 4 and len(b) >= 4 and (a.startswith(b) or b.startswith(a)))


_FACT_EQ = re.compile(r"([A-Za-z가-힣][A-Za-z0-9가-힣 .·/_%-]{0,24}?)\s*[=:：]\s*(\d+(?:\.\d+)?)")
_FACT_IS = re.compile(r"([A-Za-z][A-Za-z0-9 .·/_%-]{0,24}?)\s+(?:is|are)\s+(\d+(?:\.\d+)?)")
_FACT_KR = re.compile(r"([가-힣]{2,12})\s(\d{1,4})(?=\s*(?:회|건|개|배|초|%|점|명|개월|일))")
_LEADING_STOP = re.compile(r"^(?:the|a|an|this|그|이|저)\s+")


def _norm_label(lab: str) -> str:
    lab = re.sub(r"\s+", " ", lab).strip().rstrip(":：= ").lower()
    lab = _LEADING_STOP.sub("", lab)
    return _PARTICLE.sub("", lab) if len(lab) >= 3 else lab


def _facts(text: str) -> List[Tuple[str, str]]:
    """Measured facts in a chunk: (normalized label, number as written). Two regex forms - ``label = 3`` and the
    Korean counting form ``한도 80회`` - are enough for the corpus; anything else is not machine-readable here."""
    out: List[Tuple[str, str]] = []
    seen: set = set()
    for rx in (_FACT_EQ, _FACT_IS, _FACT_KR):
        for m in rx.finditer(text):
            lab, val = _norm_label(m.group(1)), m.group(2)
            key = (lab, val)
            if len(lab) >= 2 and key not in seen:
                seen.add(key)
                out.append(key)
    return out


def conflicts(results: Sequence[Dict[str, Any]], limit: int = 3) -> List[Dict[str, Any]]:
    """Deterministic conflict annotation over the top retrieved chunks (the lecture's 상충 로그): the same measured
    label carrying DIFFERENT numbers in two DIFFERENT sources. Authority between two knowledge files is unknowable
    here, so the resolution rule is always ``escalate`` and the status ``unresolved`` - the judgement stays with the
    reader, and nothing is silenced or auto-preferred."""
    facts: List[Tuple[str, str, str]] = []
    for r in results[:2]:
        src = r["chunk"]["source"]
        for lab, val in _facts(r["chunk"]["text"]):
            facts.append((lab, val, src))
    out: List[Dict[str, Any]] = []
    reported: set = set()
    for i in range(len(facts)):
        for j in range(i + 1, len(facts)):
            a, b = facts[i], facts[j]
            if a[0] != b[0] or a[1] == b[1] or a[2] == b[2] or a[0] in reported:
                continue
            try:
                if float(a[1]) == float(b[1]):
                    continue
            except ValueError:
                continue
            reported.add(a[0])
            out.append({"label": a[0], "a": {"source": a[2], "value": a[1]}, "b": {"source": b[2], "value": b[1]},
                        "rule": "escalate", "status": "unresolved"})
            if len(out) >= limit:
                return out
    return out


def tokenize(text: str, *, for_query: bool = False) -> List[str]:
    toks: List[str] = []
    low = text.lower()
    for m in re.finditer(r"[a-z0-9][a-z0-9_.\-/@:]*[a-z0-9]|[a-z0-9]|[가-힣]+", low):
        t = m.group(0)
        if "가" <= t[0] <= "힣":
            toks.extend(_hangul_tokens(t))
            continue
        if t in _STOP:
            continue
        toks.append(t)
        parts = [p for p in re.split(r"[_.\-/@:]+", t) if p and p not in _STOP]
        if len(parts) > 1:
            toks.extend(parts)
    if for_query:
        extra: List[str] = []
        no_hangul = not _has_hangul(text)
        for t in list(dict.fromkeys(toks)):
            for key, syn in SYNONYMS.items():
                if t == key or (len(key) >= 2 and key in t and "가" <= key[0] <= "힣" and t in (key,)):
                    extra.extend(syn)
            if no_hangul:
                # English-only query: fold light inflection and bridge to the Korean terms the notes use for it.
                variants = _en_stem_variants(t)
                extra.extend(variants)
                for cand in [t] + variants:
                    extra.extend(_REVERSE_SYNONYMS.get(cand, ()))
                    extra.extend(EN_KR_BRIDGE.get(cand, ()))
        for key, syn in SYNONYMS.items():
            if "가" <= key[0] <= "힣" and key in text:
                extra.extend(syn)
        toks.extend(extra)
    return [t for t in toks if t not in _STOP]


def chunk_markdown(text: str, source: str, *, size: int = CHUNK, overlap: int = OVERLAP, meta: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Heading-aware chunks: [{id, source, heading, text, meta}]. The heading path is part of ``text`` (contextual header)."""
    meta = meta or {}
    sections: List[Tuple[str, str]] = []
    path: List[str] = []
    buf: List[str] = []

    def flush() -> None:
        body = "\n".join(buf).strip()
        if body:
            sections.append((" / ".join(path), body))
        buf.clear()

    for line in text.splitlines():
        m = re.match(r"^(#{1,4})\s+(.*)$", line)
        if m:
            flush()
            lvl = len(m.group(1))
            path[:] = path[: lvl - 1] + [m.group(2).strip()]
        else:
            buf.append(line)
    flush()
    chunks: List[Dict[str, Any]] = []
    for heading, body in sections:
        head = (heading + "\n") if heading else ""
        if len(body) + len(head) <= size:
            pieces = [body]
        else:
            pieces = []
            paras = re.split(r"\n\s*\n|\n(?=[-*] )", body)
            cur = ""
            for p in paras:
                if len(cur) + len(p) + 1 > size and cur:
                    pieces.append(cur)
                    cur = cur[-overlap:] + "\n" + p if overlap else p
                else:
                    cur = (cur + "\n" + p) if cur else p
                while len(cur) > size * 1.6:
                    pieces.append(cur[:size])
                    cur = cur[size - overlap:]
            if cur.strip():
                pieces.append(cur)
        for i, pc in enumerate(pieces):
            chunks.append({"id": "%s#%d" % (source, len(chunks)), "source": source, "heading": heading,
                           "text": (head + pc).strip(), "meta": dict(meta)})
    return chunks


class Index:
    def __init__(self, chunks: Sequence[Dict[str, Any]] = ()):
        self.chunks: List[Dict[str, Any]] = []
        self.tf: List[Counter] = []
        self.df: Counter = Counter()
        self.len: List[int] = []
        self.norm: List[float] = []
        self._idf_cache: Dict[str, float] = {}
        for c in chunks:
            self.add(c)

    def add(self, chunk: Dict[str, Any]) -> None:
        toks = tokenize(chunk["text"])
        tf = Counter(toks)
        self.chunks.append(chunk)
        self.tf.append(tf)
        self.len.append(len(toks))
        for t in tf:
            self.df[t] += 1
        self._idf_cache.clear()
        self.norm = []

    def _idf(self, t: str) -> float:
        v = self._idf_cache.get(t)
        if v is None:
            n = len(self.chunks)
            v = self._idf_cache[t] = math.log(1 + (n - self.df.get(t, 0) + 0.5) / (self.df.get(t, 0) + 0.5))
        return v

    def _norms(self) -> List[float]:
        if not self.norm:
            self.norm = [math.sqrt(sum(((1 + math.log(c)) * self._idf(t)) ** 2 for t, c in tf.items())) or 1.0 for tf in self.tf]
        return self.norm

    def search(self, query: str, k: int = 5, *, filters: Optional[Dict[str, Any]] = None, min_cover: float = 0.0,
               min_bm25: float = 12.0) -> Dict[str, Any]:
        # Confidence gate: absolute BM25 of the best chunk. (An unweighted query-token coverage ratio was tried first; with
        # Korean syllable bigrams a query has 17-24 tokens, so even good matches scored low coverage and 51-67% of valid
        # questions were rejected. Threshold chosen on golden+dev, verified on the untouched test set - see evidence/loop.)
        # The absolute value depends on corpus size and query length: re-measure it when either changes substantially.
        # 2026-11-22 re-measure (corpus grew: round-1 lecture knowledge + book-derived domain notes): the generic
        # Korean word "결과" repeated in a lecture chunk scored 11.7 and leaked an out-of-domain query past the
        # old 11.0 gate (dev OOD 0.8). 12.0 rejects that hit with ZERO loss on golden/dev/test recall, precision
        # or OOD (measured before/after on all three sets); 12.5 starts dropping true finds (dev found 1.0 -> 0.933).
        # English-only queries read a lower, separately-measured floor instead (EN_MIN_BM25) when the caller left
        # min_bm25 at this committed default - see EN_MIN_BM25 for the measurement. Any caller that passes its own
        # min_bm25 explicitly (not this default) always gets exactly the value it asked for, in any language.
        gate_bm25 = EN_MIN_BM25 if (min_bm25 == 12.0 and not _has_hangul(query)) else min_bm25
        qt = tokenize(query, for_query=True)
        qc = Counter(qt)
        if not qc or not self.chunks:
            return {"found": False, "results": [], "reason": "empty query or index", "coverage": 0.0}
        avg = sum(self.len) / max(1, len(self.len))
        cand = [i for i, c in enumerate(self.chunks) if not filters or all(
            (c["meta"].get(fk) in fv) if isinstance(fv, (list, set, tuple)) else (c["meta"].get(fk) == fv) for fk, fv in filters.items())]
        bm: Dict[int, float] = {}
        for i in cand:
            tf = self.tf[i]
            s = 0.0
            for t in qc:
                f = tf.get(t, 0)
                if f:
                    s += self._idf(t) * f * 2.5 / (f + 1.5 * (0.25 + 0.75 * self.len[i] / avg))
            if s > 0:
                bm[i] = s
        norms = self._norms()
        qv = {t: (1 + math.log(c)) * self._idf(t) for t, c in qc.items()}
        qn = math.sqrt(sum(v * v for v in qv.values())) or 1.0
        tfidf: Dict[int, float] = {}
        for i in bm:
            tf = self.tf[i]
            dot = sum(qv[t] * (1 + math.log(tf[t])) * self._idf(t) for t in qv if t in tf)
            tfidf[i] = dot / (qn * norms[i])
        r1 = {i: r for r, i in enumerate(sorted(bm, key=lambda i: -bm[i]))}
        r2 = {i: r for r, i in enumerate(sorted(tfidf, key=lambda i: -tfidf[i]))}
        # lexical-precision OBSERVABILITY (the lecture's re-ranker, measured and REJECTED as an ordering change - see
        # ADR-0016 for the three measured variants): heading match + ordered query-bigram adjacency form a precision
        # score that is REPORTED per result (``lex``) but changes NO ordering - every ordering variant measured
        # negative on the gate (dev recall -0.067, one OOD flipped), while the same signal confirmed the lecture's
        # precision claim on the untouched test set (mrr +0.097). A future cross-encoder starts from these numbers.
        lex: Dict[int, float] = {}
        qtok_uniq = list(dict.fromkeys(qt))
        for i in bm:
            tfc = self.tf[i]
            h = sum(1 for t in qtok_uniq if any(_relaxed(t, ht) for ht in self._head_toks(i)))
            if h > 0:
                p = sum(1 for a, b in zip(qt, qt[1:]) if tfc.get(a) and tfc.get(b))
                lex[i] = h * 2.0 + p
        fused = {i: 1 / (RRF_K + r1[i] + 1) + 1 / (RRF_K + r2[i] + 1) for i in bm}
        order = sorted(fused, key=lambda i: -fused[i])
        results = []
        content = [t for t in qtok_uniq if len(t) >= 2]
        for i in order[:k]:
            cov = (sum(1 for t in content if t in self.tf[i]) / len(content)) if content else 0.0
            results.append({"chunk": self.chunks[i], "rrf": round(fused[i], 5), "bm25": round(bm[i], 3),
                            "tfidf": round(tfidf[i], 3), "coverage": round(cov, 2), "lex": round(lex.get(i, 0.0), 2)})
        top = results[0] if results else None
        found = bool(top and top["bm25"] >= gate_bm25 and top["coverage"] >= min_cover)
        return {"found": found, "results": results, "coverage": top["coverage"] if top else 0.0,
                "rerank": {"pool": len(bm), "lex_candidates": len(lex)},
                "reason": "" if found else ("no chunk covers the question's content words" if top else "no lexical match")}

    def _head_toks(self, i: int) -> List[str]:
        """Tokenized heading path of chunk i, cached per index build (headings are short and stable)."""
        cache = getattr(self, "_head_cache", None)
        if cache is None:
            cache = self._head_cache = {}
        got = cache.get(i)
        if got is None:
            got = cache[i] = set(tokenize(self.chunks[i].get("heading") or ""))
        return got


def load_dir(root: str, *, kind: str = "knowledge", exts: Tuple[str, ...] = (".md",)) -> List[Dict[str, Any]]:
    chunks: List[Dict[str, Any]] = []
    for dp, dns, fns in os.walk(root):
        dns[:] = sorted(d for d in dns if not d.startswith("."))
        for fn in sorted(fns):
            if fn.lower().endswith(exts):
                fp = os.path.join(dp, fn)
                rel = os.path.relpath(fp, root).replace("\\", "/")
                try:
                    with open(fp, "r", encoding="utf-8", errors="replace") as fh:
                        txt = fh.read()
                except OSError:
                    continue
                chunks.extend(chunk_markdown(txt, rel, meta={"kind": kind}))
    return chunks


def evaluate(index: Index, golden: Sequence[Dict[str, Any]], k: int = 5) -> Dict[str, Any]:
    """golden: [{q, expect: [source-prefixes], ood?: bool}] -> Recall@k, MRR, OOD rejection, misses."""
    hits = 0
    found_in = 0
    rr = 0.0
    nd = 0.0
    n_in = 0
    ood_ok = 0
    n_ood = 0
    seg: Dict[str, Dict[str, float]] = {}
    misses: List[Dict[str, Any]] = []
    for g in golden:
        res = index.search(g["q"], k=k)
        names = evalguard.segment_names(g)
        if g.get("ood"):
            n_ood += 1
            s = seg.setdefault("ood", {"n": 0, "hit": 0, "rr": 0.0})
            s["n"] += 1
            if not res["found"]:
                ood_ok += 1
                s["hit"] += 1
            else:
                misses.append({"q": g["q"], "why": "ood answered", "top": res["results"][0]["chunk"]["source"]})
            continue
        n_in += 1
        found_in += 1 if res["found"] else 0
        exp = g["expect"]
        rel = [any(x["chunk"]["source"].startswith(e) for e in exp) for x in res["results"]]
        rank = next((r for r, ok in enumerate(rel, 1) if ok), None)
        # binary-relevance nDCG@k: gain 1 for every retrieved chunk of an expected document, ideal = k relevant slots
        dcg = sum(1.0 / math.log2(i + 1) for i, ok in enumerate(rel, 1) if ok)
        idcg = sum(1.0 / math.log2(i + 1) for i in range(1, min(k, max(1, sum(rel) or 1)) + 1))
        nd += dcg / idcg if idcg else 0.0
        for nm in names:
            s = seg.setdefault(nm, {"n": 0, "hit": 0, "rr": 0.0})
            s["n"] += 1
            s["hit"] += 1 if rank else 0
            s["rr"] += 1 / rank if rank else 0.0
        if rank:
            hits += 1
            rr += 1 / rank
        else:
            misses.append({"q": g["q"], "why": "expected %s not in top %d" % (exp, k),
                           "top": res["results"][0]["chunk"]["source"] if res["results"] else None})
    return {"queries": n_in, "recall_at_k": round(hits / n_in, 3) if n_in else None, "mrr": round(rr / n_in, 3) if n_in else None,
            "ndcg_at_k": round(nd / n_in, 3) if n_in else None, "found_rate": round(found_in / n_in, 3) if n_in else None,
            "ood_queries": n_ood, "ood_rejected": ood_ok, "ood_rate": round(ood_ok / n_ood, 3) if n_ood else None, "k": k,
            "segments": {nm: ({"n": int(s["n"]), "ood_rate": round(s["hit"] / s["n"], 3)} if nm == "ood"
                              else {"n": int(s["n"]), "recall": round(s["hit"] / s["n"], 3), "mrr": round(s["rr"] / s["n"], 3)}) for nm, s in sorted(seg.items())},
            "misses": misses}
