# ADR-0016: Retrieval re-ranker — measured and rejected as an ordering change; ships as annotation only

## Status

Accepted (lecture round 1, Metanet advanced week 2, "VectorDB 기반 Hybrid Search 고급 RAG"). Scope:
`bts_sbom_app/rag.py` (`Index.search` observability fields). The lecture lists re-ranking as the fourth retrieval
method; `docs/LECTURE_MAPPING.md` had it as 미구현 with "stdlib 전용 제약" as the reason. This ADR replaces that
reason with a measured one.

## 근거 (Context)

The lecture's re-ranker (a cross-encoder over the top candidates) claims a precision win on the final ordering. The
repo already fuses BM25 and TF-IDF cosine by RRF (k=60) at golden 1.0 recall / 0.975 MRR / 0.950 nDCG (current
corpus), so the question was not "does a re-ranker exist" but "does a stdlib lexical precision signal beat the
tuned 2-list fusion on the measured sets". Three variants were built and measured on the golden/dev/test retrieval
sets (gate: no metric below baseline − 0.02):

1. **Third RRF list, entry = heading match OR query-bigram adjacency** — test MRR +0.104, but dev recall −0.067
   (one query lost its expected document), and with a pool-best `found` gate one out-of-corpus dev question flipped
   to answered (OOD 1.0 → 0.8).
2. **Third RRF list, entry = heading match only** — regression everywhere (golden MRR −0.108, dev recall −0.133):
   English section titles matching incidental query tokens jumped over the correct Korean-matched chunks.
3. **Capped adjacent-swap bonus (≤ one rank gap ≈ 0.002)** — dev recall −0.067 persisted: the measured sets are
   knife-edge (the expected document sits at the top-5 boundary), so even a one-rank swap costs a case.
4. **Pool-best `found` gate (independent of ordering)** — strictly more permissive than the measured top-based
   gate and let an out-of-corpus question through. Rejected on its own.

## 결정 (Decision)

- The fused score stays exactly the 2-list RRF (BM25 + TF-IDF cosine, k=60). No ordering term is added.
- `Index.search` REPORTS the lexical precision signal per result: `lex` (heading matches × 2 + ordered
  query-bigram adjacencies, relaxed stem match for ASCII tokens ≥ 4 chars) and a `rerank` block
  (`{pool, lex_candidates}`). This is observability, not behavior change — measured identical to HEAD on all
  golden/dev/test metrics, enforced by BSA-AC-486..488 (annotation never reorders).
- The `found` gate keeps its measured semantics: the top result's absolute BM25 against the threshold.
- Revisit condition: the same trigger as hierarchical chunking — the corpus grows past a few hundred chunks or the
  golden sets stop being knife-edge. A future cross-encoder starts from the recorded numbers, not from zero.

## 기각 대안 (Rejected alternatives)

- Shipping variant 1 or 3 because the untouched test set improved (MRR +0.097..+0.104) — rejected: the gate covers
  every measured set, and a variable that buys test MRR by spending dev recall is exactly the "one variable,
  measured, accept or roll back" failure the loop discipline exists to catch.
- External cross-encoder / embedding re-ranker — rejected: stdlib-only (ADR-0007) and offline; the same constraint
  LECTURE_MAPPING already recorded, now backed by measurements instead of assumption.
- Silencing the signal entirely until a real re-ranker ships — rejected: the precision signal is free to compute,
  visible in the UI evidence chips, and gives the next attempt a measured baseline.

## 결과 (Consequences)

- `docs/LECTURE_MAPPING.md` 리랭킹 row moves from 미구현 to "측정 후 기각(관측만 유지)" with the numbers inline.
- Search results carry `lex` and `rerank`; consumers that don't read them are unaffected (verified: the full app
  suite and evalrag/evalchat are unchanged).
- The rejection itself is a measured result of the lecture's own loop discipline: change one variable, gate it,
  roll it back with the numbers recorded.
