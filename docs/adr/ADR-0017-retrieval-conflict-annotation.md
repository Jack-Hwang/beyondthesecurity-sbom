# ADR-0017: Retrieval conflict annotation — same label, different numbers, escalate to the reader

## Status

Accepted (lecture round 1, Metanet advanced week 2, "VectorDB 기반 Hybrid Search 고급 RAG" 상충 주석).
`docs/LECTURE_MAPPING.md` had 정보원 상충 로그 as 미구현 ("다음 개선 후보"); this ADR closes it.

## 근거 (Context)

The lecture's conflict pipeline (detect → judge entailment → resolve by recency/authority → log → expose to the
reader) assumes a semantic judge. This repo runs stdlib-only, offline, and its knowledge base is a small
versioned markdown corpus where the realistic failure is a STALE COPY: two files answering the same measured label
("retry budget", "호출 한도") with different numbers, both retrieved for one question. Two constraints shape the
decision:

1. Authority between two knowledge files is unknowable here — there is no per-file recency or rank to prefer, so
   any auto-resolution would be a guess wearing a rule's clothes.
2. A conflict note must never become a claim of its own: it is an annotation ABOUT two passages, so it must not
   enter the claim/quote/verification pipeline (it has no single source to verify against).

## 결정 (Decision)

- `rag.conflicts(results)` scans the top-2 retrieved chunks for measured facts (`label = 3`, English copula
  "budget is 3", Korean counting "한도 80회"), normalizes labels (articles and particles stripped), and returns one
  entry per cross-source label disagreement: `{label, a: {source, value}, b: {source, value}, rule: "escalate",
  status: "unresolved"}`. Same value, same source, or a set the baseline never measured → 0 entries.
- `chat.ask` attaches the list as `conflicts` (empty unless the retrieval passed the confidence gate) and appends
  one plain-text `[conflict]` line per entry AFTER the answer body — for the extractive and the LLM answer alike,
  so the annotation cannot be dropped by a model that dislikes it.
- The resolution rule is always `escalate` and the status always `unresolved`: the annotation shows both values
  with their sources and says the judgement stays with the reader. The renderer draws one warning note per
  conflict (BSA-AC-491..495).

## 기각 대안 (Rejected alternatives)

- Auto-resolving by file mtime (최신 우선) — rejected: mtime is checkout noise, not editorial recency; a fresh
  clone inverts every decision.
- Auto-resolving by source authority (권위 우선) — rejected: the corpus has no authority ranking, and inventing
  one (README beats knowledge/domain) would be a policy without a measurement.
- LLM entailment judging (모순 판정) — rejected: non-deterministic, costs the daily call budget, and the failure
  mode (a missed contradiction reads as no conflict) is worse than an honest escalate.
- License-source conflict probing (querying the second registry source after a hit) — rejected for now: it doubles
  the network calls per component against the call-budget discipline; the council/deterministic conflict report in
  `evals.license_eval` already covers the license-interpretation conflict surface.

## 결과 (Consequences)

- Stale duplicate documents surface instead of silently answering with whichever chunk ranked first.
- The annotation is deterministic, offline and free; false positives cost one visible note that names both sides,
  never a wrong answer (the answer body is untouched).
- `docs/LECTURE_MAPPING.md` 상충 로그 row moves to 구현 with the chat surface named.
