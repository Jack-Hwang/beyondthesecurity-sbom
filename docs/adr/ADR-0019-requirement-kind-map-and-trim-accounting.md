# ADR-0019: Requirement-kind map (SFR/DAR/PER/SIR/SECR/CONR) and prompt trim accounting

## Status

Accepted (lecture round 1, Metanet advanced weeks 1-2: 요구사항 6분류 from week 1 session 3, 툴 출력 트림 trim
로그 from week 2 session 2). `docs/LECTURE_MAPPING.md` had both as 미구현 / 부분.

## 근거 (Context)

The lecture splits a requirement set into six kinds (SFR functional, DAR data, PER performance, SIR interface, SECR
security, CONR constraint) so the spec's SHAPE is visible: a spec that is 95% functional and carries 0 explicit
security or performance requirements is missing kinds, not sentences. The repo's 359 ACs were grouped by module
only. Separately, `ai.evidence` caps every list it hands to the model (12 vulns, 12 plans, …) — the lecture's
trim-log point is that an over-trimmed context silently loses evidence, so the DROPPED count must travel with the
prompt instead of disappearing at the slice.

## 결정 (Decision)

- `speclint.reqmap(spec)` tags every AC with exactly one kind using ordered deterministic keyword rules — SECR
  beats PER ("the approval token shall arrive within 2s" is a security requirement with a deadline), SFR is the
  DEFAULT so nothing is silently dropped; the result reports per-kind counts, the id partition and the
  `defaults` count, and prints as a `REQ-KINDS` line in `python -m bts_sbom_app.speclint`. Informational only: it
  shows the spec's shape, it gates nothing (BSA-AC-501..504).
- `ai.evidence` computes every list in full, slices to the cap, and reports the exact number of dropped rows per
  list in a `trimmed` block carried inside the evidence JSON itself (BSA-AC-505..506). The prompt therefore shows
  the model its own truncation, and the response cache invalidates naturally through the prompt hash.
- Known rule limits, stated in code: keyword rules are a heuristic shape-reader, not semantics; an AC can argue
  for two kinds and gets the first match.

## 기각 대안 (Rejected alternatives)

- Adding the kind as a required EARS field (`- BSA-AC-n [Pattern] [Kind] …`) — rejected: it would force a manual
  retag of 359 existing ACs and turn every future AC into two lint decisions for an informational signal; the
  deterministic keyword map reads the existing spec without touching it.
- Manual kind tags with lint enforcement — rejected for the same cost, plus drift: an untagged AC would be a lint
  failure forever arguing with the default anyway.
- Putting trim counts in a side channel (log file, return tuple) — rejected: the lecture's point is that the
  context the model sees must self-describe what was cut; a side channel the model never sees defeats it, and a
  tuple breaks every caller of `evidence()`.

## 결과 (Consequences)

- `python -m bts_sbom_app.speclint` now prints the spec's kind shape (SFR=185 DAR=58 PER=3 SIR=75 SECR=32 CONR=6
  at adoption time) — a spec-shape smell (e.g. PER=3) is visible at a glance and can drive which ACs to write next.
- LLM prompts carry their own trim accounting; a future "evidence too small" hypothesis is checkable against
  measured `trimmed` numbers instead of guesswork.
- `docs/LECTURE_MAPPING.md` 요구 6분류 and trim-log rows move to 구현.
