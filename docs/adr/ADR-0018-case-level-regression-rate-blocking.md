# ADR-0018: Case-level regression rate — a query that passed at baseline and fails now blocks the pass

## Status

Accepted (lecture round 1, Metanet advanced week 2, "DataOps & MLOps 응용/심화" 회귀율 정의). Scope:
`bts_sbom_app/loop.py` (`case_regressions`, `run_rag_pass`).

## 근거 (Context)

The lecture defines 회귀율 as the share of previously PASSING cases that now fail, and regression testing as
protecting what used to work — not only catching what the change targeted. `loop.run_rag_pass` gated five
AGGREGATE metrics per eval set (recall/MRR/nDCG/OOD/found against the accepted baseline, delta 0.02) and stored
per-query misses, but never compared them case by case. The gap is real: aggregates can stay flat while a single
query regresses, because another query improved enough to compensate — the average hides the loss. Conversely, a
query that failed before and passes now is an improvement and must never read as a regression.

## 결정 (Decision)

- `loop.case_regressions(base_misses, cand_misses)` returns `{set, q}` for every query that is missing in the
  candidate but was NOT missing at the accepted baseline. A set the baseline never measured is skipped (it is the
  vanished-set case, already handled as `undecidable`).
- `run_rag_pass` computes the list against the accepted baseline and treats it as a blocking failure: the gate
  carries a `case regression: N query(ies) ...` line naming up to 3 queries, the entry records `case_regressions`,
  and the decision is `rollback`. The first pass of a fresh loop stays `baseline` with an empty list.
- Improvements are explicitly not regressions (a query that only left the miss list never appears).

## 기각 대안 (Rejected alternatives)

- Reporting regressions as an informational metric only — rejected: an advisory number nobody gates is how a
  known regression ships anyway; the whole point of the lecture's definition is that a pass→fail case is a failure
  even when the average held.
- Adding the count to the `HIGHER`/`LOWER` delta machinery — rejected: it is a count, not a rate with a tolerable
  delta; "0 tolerated, any count blocks" is the honest rule and is clearer as its own failure line.
- Extending case-level comparison to `run_pass` (the batch project loop) — deferred: its per-case outcome lives in
  failure clusters, not a stable per-query pass/fail; revisit when a per-case verdict is recorded there.

## 결과 (Consequences)

- The retrieval loop now matches the lecture's definition: previously passing queries are protected individually,
  not only through five averages (BSA-AC-496..500).
- Existing `evidence/loop/rag_history.json` records already carry per-set `misses`, so old baselines compare
  without a format migration.
- Tuning that trades one query for another now requires an explicit human acceptance instead of passing silently
  on averages.
