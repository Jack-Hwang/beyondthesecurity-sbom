# Loop engineering log

One variable per pass. `accept` = no blocking metric regressed by more than 0.02 against the previous accepted pass.
Code fingerprints identify the exact tool version that produced each pass.

## End-to-end passes (10 real GitHub sources)

| # | tag | decision | variable changed | metrics that moved vs previous accepted pass | note |
|---|---|---|---|---|---|
| 1 | p01_baseline | baseline | baseline: bts-sbom 0.1.0 core + deps.dev/registry licenses + OSV-verified plans + manifest patcher | baseline |  |
| 2 | p02_verify_key | accept | plan verification keyed by plan identity (was package+candidate: two plans sharing a candidate left one unverified) | plan_verified_rate 0.956 -> 0.975 |  |
| 3 | p03_license_norm | accept | license normalization: structure-preserving SPDX parser (keeps parentheses) + well-formed unknown SPDX ids accepted + PSFL alias | spdx_valid_rate 0.8 -> 1.0 | license_resolved_rate did not move because a stale cache had stored normalised misses: the effect was realised only in pass 4 (measurement defect, not a normaliser failure) |
| 4 | p04_raw_cache | accept | measurement fix: license cache stores RAW source evidence (was normalised outcome incl. cached misses); extra registry fallbacks OFF | license_resolved_rate 0.962 -> 0.964 |  |
| 5 | p05_extra_registries | accept | knob license_extra_registries: OFF -> ON (npm legacy licenses[] array, Maven Central POM with parent inheritance) | license_resolved_rate 0.964 -> 0.978 |  |
| 6 | p06_dedupe | accept | engine dedupe: same advisory+package+version from several manifests -> ONE finding (ruby merge and go.sum filter held OFF) | vulns 1959 -> 1438 | found by the first real e2e: 521 of 1959 findings were duplicates across manifests |
| 7 | p07_ruby_merge | accept | engine ruby platform merge: ffi 1.17.3-arm64-darwin etc. -> one package version (go.sum filter held OFF) | components 2529 -> 2499; vulns 1438 -> 1294; license_resolved_rate 0.978 -> 0.99; plan_verified_rate 0.975 -> 0.974 |  |
| 8 | p08_go_mvs | accept | engine go_mvs: ignore go.sum-only module versions (never selected by the build) | components 2499 -> 2478; vulns 1294 -> 1292 |  |
| 9 | p09_ruby_arch | accept | arch: Ruby require/require_relative import graph (Rails autoload stays unresolved, marked partial) | arch_coverage 0.9 -> 1.0 |  |
| 10 | p10_classification | accept | classification honesty (bundled: two changes that cannot move a gated metric): transitive-only deps -> manual (was blocked); MAL- advisories -> CRITICAL (was UNKNOWN) | no gated/tracked metric moved | deviation from one-variable-per-pass: two classification-only changes bundled because neither can move a gated metric |
| 11 | p11_exaone | accept | EXAONE lane ON (K-EXAONE 2.5 proposals with 4-layer validation + loop hypotheses); everything else frozen | no gated/tracked metric moved | EXAONE produced 0/10 accepted proposals: timeout, empty completion (reasoning used the token cap), truncated JSON, busy 429 |
| 12 | p12_exaone_repair | accept | EXAONE lane repair (one variable family: reasoning-model budget): max_tokens 3000->8192, timeout 120->300s, one request in flight, ledger counts failed attempts, only validated answers cached | exaone_rate - -> 0.8 | audit of the answers: about half of the semantic drops were version/section refs, not invented entities - the validator was too strict |
| 13 | p13_ai_validator | accept | ai validator: version/section/license refs accepted as evidence anchors + refs repaired from the title when it names exactly one evidence package (cached EXAONE answers re-validated, no new LLM calls except uncached projects) | exaone_rate 0.8 -> 1.0; ai_keep_rate - -> 0.919 | ai_keep_rate is IN-SAMPLE: the validator was changed after reading these 10 responses |
| 14 | p14_patch_scope | accept | patch regression judged on findings of the EDITED files only (untouched lockfile no longer blamed; was reverting a 134-package npm patch for 1 new advisory) | no gated/tracked metric moved | nodejs-goof regression_reverted was a false regression (untouched lockfile); regression is now judged on the edited files |
| 15 | p15_final_verify | accept | none (final verification of the shipped tree: chat pointer normalisation and CLI changes landed after pass 14 and cannot move a batch metric) | no gated/tracked metric moved | no variable: final tree reproduces pass 14 exactly (0 LLM calls, EXAONE answers served from the validated cache) |

## Retrieval passes (golden = regression set, dev = tuned on, test = written before tuning)

| # | tag | decision | variable changed | metrics that moved |
|---|---|---|---|---|
| 1 | r1_baseline | baseline | baseline: lexical BM25+TF-IDF RRF, unweighted coverage gate (0.34) | baseline |
| 2 | r2_paraphrase_synonyms | accept | rag synonyms: Korean paraphrase vocabulary derived from dev failures (license wording, revert, EOL, call limits) | dev_recall 0.733 -> 1.0 |
| 3 | r3_measure_found | accept | measurement: add in-domain found_rate (false-rejection) to the RAG gate metrics; retrieval unchanged | golden_found - -> 0.7; dev_found - -> 0.333; test_found - -> 0.333 |
| 4 | r4_bm25_gate | accept | rag confidence gate: absolute BM25 >= 11 replaces unweighted coverage >= 0.34 (false rejections of valid questions) | golden_found 0.7 -> 0.85; dev_found 0.333 -> 0.933; dev_ood 0.8 -> 1.0; test_found 0.333 -> 0.833 |

