# ADR-0010: No fine-tuning — EXAONE called only as an API, behind 4-layer validation and a deterministic downgrade

## Status

Accepted. Post-hoc record: `bts_sbom_app/ai.py`, `llm.py`, `council.py` and `loop.py` already implement this; this
document records why. Current as of 2026-11-20.

## 근거 (Context)

`bts_sbom_app/llm.py`'s module docstring describes `ChatClient` as an "LG EXAONE (K-EXAONE, OpenAI-compatible chat
completions) client - stdlib only", configured by an API key / base URL / model triple, with a per-day call ledger
("Cost/limit protection: a per-day call ledger (`daily_budget`, default 80 < the 100/day free tier) stops calls
BEFORE the provider does"). Nothing in this codebase trains or adjusts model weights; every AI-backed feature —
`ai.propose` (upgrade/replace/license/architecture proposals), `chat`'s tool-call planning, `council`'s independent
license votes, `loop.propose_variables` (next loop-engineering variable to try) — calls this same stateless
request/response client.

`ai.py`'s module docstring spells out the second half of the design: a proposal must pass 4 independent validation
layers (schema, rule, semantic grounding against the evidence handed to the model, cross-field consistency with the
deterministic plan) "otherwise it is dropped and counted in `dropped`", and "When EXAONE is unavailable (no key,
local budget, provider day limit, network, invalid output) the lane falls back to DETERMINISTIC proposals and says
so (`source="deterministic"` + the cause in `llm_note`) - it never reports an LLM success it did not have."  This is
measured directly:

- `BSA-AC-33` — an HTTP 429 day-limit response downgrades to deterministic after exactly 1 call, 0 retries (test:
  `tests/bts_sbom_app/test_ai_rag_loop.py::test_http_429_day_limit_downgrades_after_one_call`).
- `BSA-AC-34` — of 4 proposed items (1 bad action, 1 unknown-id citation, 1 wrong target version, 1 clean), exactly 1
  survives validation (test: `tests/bts_sbom_app/test_ai_rag_loop.py::test_four_layer_validation_keeps_exactly_one`).

`docs/LECTURE_MAPPING.md` records the two paths this ADR declines explicitly as "적용 불가" (not applicable): "Batches
API (50% 비용) | 적용 불가 | EXAONE 은 동기 OpenAI 호환 API 뿐" and "LoRA 파인튜닝 | 적용 불가 | API 호출만 가능".

## 결정 (Decision)

BTS-SBOM never trains or fine-tunes a model, and never self-hosts one. The only interaction with LG EXAONE (or any
other OpenAI-compatible endpoint, including a locally run one, per `llm.ChatClient.from_config`'s localhost
exception) is a synchronous chat-completion API call, rate-limited by a local daily budget. Every structured output
from that call must pass 4 independent validation layers before any of it is used anywhere downstream (manifest
patch plans, chat tool calls, license council votes, loop-engineering hypotheses); anything that does not pass is
dropped and counted, and when nothing passes — or the API itself is unavailable or over budget — the caller receives
a deterministic, rule-based answer instead, explicitly labeled as such (`source="deterministic"`, `llm_note`
explaining why), never silently presented as if it were a verified model answer.

## 기각 대안 (Rejected alternatives)

- **Fine-tune (LoRA or full) a model on this project's SBOM/vulnerability/license history.** Rejected: there is no
  training infrastructure in a stdlib-only, zero-dependency package (ADR-0007), and `docs/LECTURE_MAPPING.md` already
  records this path as "적용 불가 / API 호출만 가능". A fine-tuned model would also need its own ongoing governance
  (its own model card, drift monitoring, retraining triggers) that this project is not staffed to run.
- **Self-host an open model (vLLM / Triton / ONNX runtime).** Rejected for the same reason recorded in
  `LECTURE_MAPPING.md` ("해당 없음: 모델을 직접 서빙하지 않음(EXAONE API)"): it would add a hard runtime dependency and an
  operational burden (GPU provisioning, serving infra) incompatible with ADR-0007's stdlib-only, localhost-tool
  shape.
- **Trust the model's structured output directly, skip the 4-layer validator.** Rejected because a hallucinated
  advisory id, an invented target version, or a correct-sounding action applied to the wrong component would be
  indistinguishable from a grounded answer without re-checking every field against the evidence that was actually
  sent to the model — precisely the failure mode `ai.validate()` exists to catch, and the reason `BSA-AC-34` measures
  that exactly the surviving proposal (not all 4) is kept.

## 결과 (Consequences)

- The AI lane can never report a success it did not have: a 429/day-limit/network failure, or a validator rejection
  of every candidate, degrades to the deterministic lane that was already correct before any AI code existed
  (`BSA-AC-33`). Removing the EXAONE key entirely still leaves a working, if less thorough, product.
- Deterministic proposals are measurably more templated than a working EXAONE call (`ai.deterministic()` produces a
  fixed shape per plan/license/EOL/cycle/cluster finding, with no free-form rationale beyond a format string).
- The validator's semantic layer is necessarily reactive, not exhaustive: `ai._repair_refs`'s own comment records
  that roughly half of early "semantic" drops were refs like `['4.0.5']` or `['vulns']` — not invented entities, just
  phrasings the validator had not yet been taught to recognise as legitimate — so the validator is tuned against
  observed real EXAONE answers, not a closed-form specification of every correct phrasing.
