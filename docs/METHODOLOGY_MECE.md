# 개발 방법론 MECE 맵과 적용 현황 (BTS-SBOM)

- 작성일: 2026-11-17 / 출처: 강의자료 폴더(PDF 8개 + zip 4개)의 **전량 판독** / 대상: BTS-SBOM(코어 `bts_sbom`, 앱 계층 `bts_sbom_app`)

- 이 문서는 강의 내용을 **자기 말로 요약한 방법론 목록**이며 슬라이드 원문을 옮기지 않았습니다. 레포 공개 전에 수강 약관/출처 표기 정책을 확인하세요.

- 숫자는 모두 `docs/methodology/matrix.json`(방법 600개 × 차원 × 상태 × 증거 경로)에서 생성했습니다. 손으로 고친 값은 없습니다.


## 1. 한눈에

12명의 독립 판독자가 강의자료를 전량 읽고(모두 전 페이지 판독 완료 보고) 방법론 항목 **600개**를 뽑았습니다. 같은 내용이 여러 자료에 반복되어 그중 83개는 하나로 통합했고, 나머지 **517개**를 12개 차원으로 분류해 레포에 적용됐는지 증거로 점검했습니다.

| 상태 | 개수 | 뜻 |
|---|---:|---|
| 적용 | 101 | 코드와 테스트(또는 측정 증거 파일)로 구현됨 |
| 부분 | 156 | 일부만 구현됨 (빠진 부분은 각 표의 비고) |
| 문서만 | 15 | 문서에만 있고 코드가 강제하지 않음 |
| 빈틈 | 153 | 적용 대상인데 아직 없음 |
| 해당 없음 | 92 | 우리 서비스에 맞지 않음 (이유는 비고: stdlib 전용, API 전용 LLM, 학습 파이프라인 없음 등) |
| 중복(통합) | 83 | 다른 방법과 중복, 대표 항목에서 판정 |

적용 대상(해당 없음·중복 제외) 425개 중 **적용 101개(24%) + 부분 156개(37%)**, 문서만 15개, 빈틈 153개입니다. 이번 릴리스에서 빈틈을 줄이는 작업을 했고(아래 5절), 남은 것은 근거와 함께 로드맵으로 둡니다. "전부 적용"이라고 주장하지 않습니다.


## 2. 왜 MECE인가 (검증 방법)

**상호 배타(ME)**: 모든 방법은 아래 *결정 트리*의 위에서부터 첫 번째 "예"에 해당하는 **하나의 차원에만** 들어갑니다. 한 방법이 두 차원에 걸쳐 보이면 *동률 규칙*으로 한쪽에 둡니다. 이름과 본문(essence)만으로 답할 수 있는 질문이며 독자가 붙인 단계 태그는 쓰지 않습니다.

**전체 포괄(CE)**: 방법 600개가 빠짐없이 한 번씩 배정되어 있습니다(배정 누락 0, 중복 배정 0).

**검증**: 규칙을 쓴 쪽과 무관한 두 분류기(A, B)가 규칙과 정의만 보고 600개를 각각 **맹검 분류**했습니다 - 두 분류기끼리 일치율 **93.2%**. 초안 배정과 어긋난 159개는 중재 에이전트가 결정 트리를 직접 따라가 재판정했고, 최종 분류는 A와 97.0%, B와 96.2% 일치합니다. 1차 초안에서는 비판 에이전트가 id 1건 누락, 겹침 10건, "규칙이 함수가 아님", MLOps 차원 부재를 찾았고 모두 고쳤습니다.

정직한 한계: 규칙은 판단이 필요한 질문이라 **순수 함수가 아닙니다**. 독립 분류기도 약 7%에서 서로 다르게 분류했고, 중재 후에도 "여전히 논쟁 가능"으로 남은 방법이 22개 있습니다(중재자 표기).


### 결정 트리 (위에서부터 첫 번째 "예")

1. Is this purely a classroom-delivery/teaching technique (class-session flow, in-class quiz, Socratic opening question) with no technical system content? -> **D12**
2. Is this a stage of a TRAINED model's own ML lifecycle: the fine-tune-vs-RAG decision gate, training-data pipeline, loss/overfitting monitoring, registration gate, champion/challenger promotion, model registry/lineage, drift-monitoring->retrain trigger, or an MLOps maturity/Ops-framework comparison? -> **D11**
3. Is the method's core action a technical permission/tool-access control (whitelist, allowed/disallowed-tools, PreToolUse hook), a secrets/credential-hygiene rule, a red-team/threat-model workflow, a code-level/pipeline verification that a claim or citation is actually grounded, or an AI impact-assessment/regulatory-compliance analysis? -> **D6**
4. Does the method measure, score, or report whether an already-produced model/agent output or a test-suite run was correct (a quality metric, regression/impact scope such as the direct/upstream/downstream/shared quadrant, a pass/fail aggregation-integrity rule, LLM-judge calibration, or benchmark/experiment-ladder design)? -> **D7**
5. Is the method about collecting, cleaning, governing, or contractually defining the data that feeds the system (preprocessing/chunking, provenance, storage architecture, or a data contract/quality gate)? -> **D8**
6. Is the method about getting the right knowledge/facts in front of the model: a retrieval/search strategy, query transformation, vector-store/index design, or preserving/budgeting specific factual content (case-facts, context budget) across turns? -> **D4**
7. Does the method control how the model acts or produces output at runtime: agentic-loop/termination mechanics, orchestration hand-off/topology execution, tool-interface/routing design, a prompt-engineering technique, or an output-schema/format design? -> **D5**
8. Is the method about shipping or running the application live: a deployment procedure, runbook, rollback, blue/green or canary release, capacity plan, infrastructure-as-code, or cost/observability operations? -> **D10**
9. Does the method define or verify what the system must do: acceptance-criteria phrasing, requirement classification, ambiguity-to-measurable-criteria conversion, or AC<->test traceability? -> **D1**
10. Is the method about deciding whether/when to build something or how to scope it before requirements exist: topic/feature selection, value x feasibility, MoSCoW, a project charter, or an AI-suitability/system-selection decision rule? -> **D2**
11. Does the method decide or explain how the system/components are technically structured for one specific decision: a reference architecture, hosting/cost trade-off, model routing, multi-agent topology choice, or a foundational LLM/agent architecture concept? -> **D3**
12. [Catch-all] None of the above -- is this about how the team/harness documents, governs, lints, or organizes its own work (or does it simply not match any earlier question)? -> **D9**

### 동률 규칙

- ADR template & Well-Architected review: a generic, reusable TEMPLATE/checklist/lint for how to write or review decision records (ADR structure, Well-Architected pillars as a review lens) -> D9 Process & Governance. A SPECIFIC technical decision recorded with those tools (hosting choice, FT-vs-RAG, topology) -> D3 Architecture.
- 'process/governance' stage tag: documentation/navigation conventions, harness self-verification of its own governance config, and enforcement-tiering POLICY principles are D9 even when adjacent to safety or architecture content; a technical permission/tool-access CONTROL (whitelist, allow/disallow-tools, PreToolUse hook) is D6 even when its stage tag says 'governance'.
- 'security/agent-governance' stage tag: resolves to D6 when the method IS the technical control; resolves to D9 when the method is about documenting/auditing governance policy (model cards, ARB review, impact assessments).
- 'verification' stage tag: result/aggregation REPORTING (verify.md blocks, a SKIP!=PASS rule, regression-impact scoping) is D7, never D9 or D10, regardless of a 'verification' or 'operations' stage tag.
- 'planning' stage tag: topic/feature/system SELECTION and scoping (before requirements exist) is D2; tracking execution of an ALREADY-SCOPED plan (todos<->AC linkage) is D9 even if a reader tagged it 'planning'.
- Requirement-vs-evaluation for system-selection checklists: an ex-ante 'should/which AI system to build' decision rule is D2 (or D1 if phrased as a gate on an already-chosen system's spec), never D7, which is reserved for post-hoc measurement of a produced output.
- Claim/citation/not-found pattern: designing the OUTPUT SCHEMA/format carrying claim+quote+source+date fields is D5; code-level or pipeline VERIFICATION that a claim/citation is actually grounded (substring check, Citation Verifier, regulatory linkage) is D6; a numeric groundedness/citation-accuracy METRIC is D7.
- Runbook: always D10 (it is the record of how a system IS deployed/rolled back/monitored), even when a reader tagged it 'architecture' or it sits inside an architecture document.
- Data contract: always D8 (schema.yaml, producer-consumer contract, quality gate), even when a reader tagged it 'process' or it is checked by the same doc-lint dispatcher that also checks ADRs/runbooks.
- Context-window/case-facts: preserving or budgeting specific factual content across turns (case-facts block, context-budget layers) is D4; the agent's perceive-reason-act-observe LOOP mechanics, even when framed around 'the context window', is D5.
- MLOps blue-green/reproducibility language: generic-sounding deployment or reproducibility-test wording is still D11 when it is explicitly part of the curated train->evaluate->register->promote->monitor->retrain pipeline (adjacent, same session, to champion/challenger registration); the same wording used for a non-model-specific application release is D10, and a bare reproducibility metric outside that pipeline is D7.

### 중재 과정에서 나온 규칙 보강 제안 (아직 문구에 반영하지 않은 것)

- `D6 scope ('AI impact assessment...com...`: D6 scope names AI impact assessment as D6, but tie-break assigns impact assessments to D9. -> "Clarify: D6's 'AI impact assessment' scope covers only cases where the method itself is the automated compliance/safety control; a methodology, obligation-mapping, or documentation/export of impact..."
- `D2 scope 'non-overlapping task/work-s...`: Phrase in D2 scope overlaps with D9's todos/AC execution-tracking tie-break, causing conflicting calls. -> "Limit D2's 'non-overlapping task/work-split assignment' to pre-requirements scope splitting; a todos/plan template that also tracks acceptance criteria and verification status is D9 even if it also..."
- `D3/D7/D9/D10 boundary for CI eval-inf...`: Sync-vs-batch eval API tiering and CI-gate wiring for regression evals aren't clearly assigned among D3/D7/D9/D10. -> "Clarify: choosing sync-vs-batch API routing for evals by cost/latency is D3 (model/compute routing); wiring eval results into a CI merge-blocking gate is D10 (CI/CD infrastructure); only the pass/f..."
- `D5 scope / D8 not_in_scope (output-sc...`: Field-level schema design (nullable/enum, field description, engine limits) misread as data or architecture content. -> "Add to D5 scope: field-level output-schema decisions -- nullable/placeholder defaults, enum+other patterns, field-description elements, engine hard-limits, format-vs-tool-call choice -- are D5 even..."
- `D3 scope / tie-break (cost-hosting tr...`: Cost/latency tradeoff fact tables and sync-vs-batch decision criteria get stage-tagged operations and misread as D10. -> "Add tie-break: a fact table or decision matrix comparing API modes/hosting options by cost, latency, or SLA (e.g. sync vs batch) is D3 even when stage-tagged operations; D10 covers only executing a..."
- `D7 scope (experiment-ladder wording)`: 'Refine on a small sample before scaling up' pattern is read as prompt-engineering (D5) or catch-all (D9). -> "Clarify D7's experiment-ladder design explicitly covers validating prompt/schema on a small sample set and gating large-scale/batch execution on hitting a target metric, not only formal benchmark d..."
- `D3.scope & D5.scope ('multi-agent top...`: Same phrase in both D3 and D5 scope text causes topology-choice methods to 3-way split -> "D3 = choosing/cataloging topology options pre-runtime. D5 = only the coordinator's runtime hand-off/execution mechanics of an already-chosen topology (dynamic selection, spawning, redelegation)."
- `D6.scope vs D7.primary_question (metr...`: A metric pass/fail threshold that also blocks execution reads as D6 instead of D7 -> "A differential pass/fail threshold on a quality metric (e.g. TCA) stays D7 even when breaching it blocks the action; D6 covers only the blocking mechanism's own implementation."
- `D7.scope 'latency/cost-per-eval' vs D...`: Both scopes list cost/latency metrics, blurring eval-run metrics vs live production monitoring -> "D7's cost/latency metrics cover only evaluation-run or test-suite measurement. Recurring production monitoring of live traffic (TTFT, error rate, cost-per-conversation, drift) with no pass/fail gat..."
- `D3/D5 boundary: decision_tree order 7...`: Foundational LLM/RL/agent concepts (softmax, Q-learning, discounted return) wrongly pulled into D5 by tree order -> "In decision_tree order 7 (D5), add: excludes foundational explanations of model-internal mechanisms (decoding math, RL value/update rules, agent theory) even when phrased around generation/agent be..."
- `D4 scope vs D8 scope for embedding/ve...`: Embedding-model choice and vector-DB storage get misread as D8 data-pipeline steps via stage tag -> "Add to D4 scope: embedding-model selection and vector-database storage/indexing are D4 vector-store/index design, not D8, even when tagged stage=data; D8 covers only pre-embedding cleaning/chunking..."
- `D9 catch-all vs D6/D7/D10 for governa...`: Model cards, tracking tables, control maps, meta-tests split inconsistently across D6/D7/D9/D10 -> "Add tie-break: an artifact that documents, maps, tracks, or self-tests the team's own governance/config/process (model cards, control-to-enforcement maps, service/session tracking tables, build-com..."
- `D6 not_in_scope vs D9 governance-arti...`: D6 scope lists impact-assessment/compliance docs but tie-breaks route governance artifacts to D9 -> "Add to D6 not_in_scope: authoring or linting governance artifacts themselves (model cards, AI impact assessments, control-mapping tables) is D9; D6 is reserved for enforcing an actual technical con..."
- `D5 scope vs D3 scope on cost/fit-rule...`: Multi-agent cost/fit rules and tool build-vs-buy decisions sit in both D5 and D3 scope text -> "Clarify: a quantified cost-tier or fit-rule used to decide agent/tool structure (1x/4x/15x, build-vs-buy) is D5 orchestration/tooling design; only the resulting hosting or vendor choice recorded vi..."
- `D6 scope 'hallucination-control techn...`: Scope lists hallucination-control under D6 but tree's order-3 question only asks about code-level verification -> "Reword decision-tree order 3 to add: 'or a generation-time abstention/not-found rule for insufficient evidence', so hallucination-control techniques route to D6 before D5's conflict-handling clause..."

## 3. 12개 차원과 적용 현황

| 차원 | 이름 | 방법 | 적용 | 부분 | 문서만 | 빈틈 | 해당 없음 | 중복 |
|---|---|---:|---:|---:|---:|---:|---:|---:|
| [D1](methodology/D1.md) | Requirements & Specification | 26 | 6 | 5 | 2 | 3 | 0 | 10 |
| [D2](methodology/D2.md) | Planning & Scoping | 18 | 2 | 5 | 0 | 8 | 1 | 2 |
| [D3](methodology/D3.md) | Architecture & Technical Decisions | 33 | 2 | 11 | 0 | 2 | 18 | 0 |
| [D4](methodology/D4.md) | Knowledge, Retrieval & Context Management | 44 | 12 | 7 | 6 | 8 | 7 | 4 |
| [D5](methodology/D5.md) | Generation & Agent Orchestration Control | 103 | 22 | 34 | 0 | 29 | 7 | 11 |
| [D6](methodology/D6.md) | Validation, Safety & Security | 59 | 14 | 14 | 1 | 9 | 9 | 12 |
| [D7](methodology/D7.md) | Evaluation & Quality Metrics | 107 | 21 | 27 | 1 | 32 | 16 | 10 |
| [D8](methodology/D8.md) | Data Engineering & Pipeline Ops | 30 | 4 | 10 | 0 | 11 | 2 | 3 |
| [D9](methodology/D9.md) | Dev Process, Governance & Documentation Harness | 120 | 14 | 29 | 1 | 42 | 12 | 22 |
| [D10](methodology/D10.md) | Delivery, Release & Operations | 37 | 2 | 11 | 0 | 5 | 11 | 8 |
| [D11](methodology/D11.md) | ML Model Lifecycle Management | 18 | 2 | 3 | 4 | 4 | 4 | 1 |
| [D12](methodology/D12.md) | Pedagogy & Course Delivery (out of product scope) | 5 | 0 | 0 | 0 | 0 | 5 | 0 |

각 차원 문서에 방법 한 줄씩(상태, 증거 경로 또는 해당 없음 이유)이 있습니다. 질문과 범위:

- **D1 Requirements & Specification** - Does the method capture or verify WHAT the system must do -- acceptance-criteria phrasing, requirement classification, or AC<->test traceability? (범위 밖: Deciding WHETHER/WHEN to build something or an ex-ante system-selection checklist (D2), HOW the system is structured (D3), or whether an AC actually passed at runtime (D7).)
- **D2 Planning & Scoping** - Is the method about deciding WHETHER/WHEN to build something or how to scope it, before requirements are frozen -- topic/feature selection, AI-suitability/system-selection rules, value x feasibility, MoSCoW, charters? (범위 밖: Writing the acceptance criteria themselves (D1), sizing runtime infrastructure/capacity (D10), or tracking day-to-day execution of an already-scoped plan such as todos<->AC linkage (D9).)
- **D3 Architecture & Technical Decisions** - Does the method decide or explain HOW the system/components are technically structured for a SPECIFIC decision -- reference architecture, hosting/cost trade-off, model routing, multi-agent topology, or foundational LLM/agent architecture concept? (범위 밖: The generic ADR/Well-Architected review TEMPLATE, checklist or lint itself (D9), the runtime control flow of an agent (D5), the data pipeline itself (D8), how a decision is executed/rolled out (D10), or a trained model's train->register->promote lifecycle (D11).)
- **D4 Knowledge, Retrieval & Context Management** - Is the method about getting the right KNOWLEDGE/FACTS in front of the model -- search/retrieval strategy, query transformation, vector-store design, or preserving/budgeting context and case-facts across turns? (범위 밖: How retrieved/preserved content is produced into a final answer, or the agent's perceive-reason-act-observe LOOP mechanics even when framed around 'the context window' (D5); how the underlying corpus is collected/cleaned (D8).)
- **D5 Generation & Agent Orchestration Control** - Does the method control HOW the model acts/produces output at runtime -- agentic-loop/termination mechanics, orchestration hand-offs/topology execution, tool-interface/routing design, prompt-engineering, or output-schema/format design? (범위 밖: Sourcing or preserving the knowledge acted on (D4); measuring whether the output/behavior was correct (D7); verifying or auditing whether a specific claim/citation is actually true, or a technical permission/secrets control (D6).)
- **D6 Validation, Safety & Security** - Does the method guard against an unsafe, insecure, or ungrounded ACTION or CLAIM -- a technical permission/tool-access control, secrets hygiene, red-teaming, code-level citation/claim verification, or regulatory/impact-assessment compliance? (범위 밖: Measuring/reporting a quality METRIC after the fact (D7); documenting governance POLICY about a control rather than being the technical control itself (D9); designing the OUTPUT FORMAT a claim/citation is expressed in (D5).)
- **D7 Evaluation & Quality Metrics** - Does the method measure, score, or report whether an already-produced model/agent OUTPUT or a TEST-SUITE RUN was correct -- a quality metric, regression/impact scope, verification-result reporting or aggregation-integrity rule, LLM-as-judge, or benchmark/experiment-ladder design? (범위 밖: An ex-ante decision about whether to build/select an approach at all (D2); designing the generation output schema itself (D5); a technical safety/security control or compliance assessment (D6); monitoring a deployed MODEL's drift or triggering its retraining (D11), even when phrased as a 'regression/reproducibility' check inside that pipeline.)
- **D8 Data Engineering & Pipeline Ops** - Is the method about collecting, cleaning, governing, or contractually defining the DATA that feeds the system -- preprocessing/chunking, provenance, storage architecture, or data contracts/quality gates? (범위 밖: Training/evaluating/registering a MODEL on that data (D11); retrieval-time use of data (D4); a generic process/governance document-lint dispatcher that happens to also check a 'datacontract' doc type among 8 others (D9).)
- **D9 Dev Process, Governance & Documentation Harness** - [Catch-all] Is the method about how the team/harness documents, governs, lints, or organizes its own work -- doc placement/template rules, the generic ADR/Well-Architected review process, governance checklists/gates, harness self-verification of its own config, cost/tag governance policy, or todo/traceability tracking -- or does it fail to match any question above? (범위 밖: Making a SPECIFIC architecture decision (D3); a technical permission/security CONTROL itself such as a tool whitelist or PreToolUse hook (D6); a data-contract ARTIFACT (D8); measuring verification RESULTS (D7).)
- **D10 Delivery, Release & Operations** - Is the method about shipping/running the application in a live environment -- deployment procedure, runbooks, rollback, capacity, CI/CD infrastructure, or cost/observability operations -- for the application in general rather than a trained model's own lifecycle? (범위 밖: A model-specific train->register->promote->drift->retrain lifecycle step, even when phrased with generic deployment/reproducibility language, when it is part of the curated MLOps pipeline (D11); a generic ADR/process template (D9); a verification RESULT's content (D7).)
- **D11 ML Model Lifecycle Management** - Is the method a stage of a TRAINED MODEL's own lifecycle -- the fine-tune-vs-RAG decision gate, training-data pipeline, loss/overfitting monitoring, registration gate, champion/challenger promotion, model-registry/lineage, drift-monitoring->retrain trigger, or MLOps maturity/Ops-framework comparison -- regardless of this course's own hosted-model-only applicability? (범위 밖: General application deployment/runbook/ops with no trained-model promotion involved (D10); generic data contracts/pipelines not about model training (D8); foundational LLM/PEFT architecture CONCEPTS discussed without lifecycle framing (D3). Catalogued for completeness per each method's reader-assigned applicability field, which is mostly low/na since this course's services only consume hosted models.)
- **D12 Pedagogy & Course Delivery (out of product scope)** - Is the method purely a classroom-delivery/teaching technique (class-session flow, in-class formative quiz, Socratic opening question) with no technical system content, rather than something with real applicability to any of the five target product/platform lines? (범위 밖: Anything with real low/medium/high applicability to a target system goes into D1-D11 by content, even if it was taught inside a classroom session.)

## 4. 방법론을 우리 서비스에 적용한 방식 (요약)

| 영역 | 적용한 방법 | 위치 |
|---|---|---|
| 요구사항·SDD | EARS 수용기준 + 측정값 + AC<->테스트 양방향 추적 린트 | `specs/`, `bts_sbom_app/speclint.py`, `tests/bts_sbom_app/test_specs.py` |
| 검색·RAG | BM25+TF-IDF -> RRF(k=60), 메타데이터 필터, 증거 하한, claim-quote-source 검증 | `bts_sbom_app/rag.py`, `chat.py`, `evals/` |
| 에이전트 제어 | stop_reason 루프, 공회전 탐지, 승인 게이트(다이제스트), 결정적 폴백 | `ai.py`, `loop.py`, `patch.py`, `pipeline.py` |
| 검증·안전 | 4계층 응답 검증, 작업 복사본 격리, 경로·심볼릭 링크 차단, 서버 CSP/허용 목록 | `ai.py`, `workspace.py`, `server.py` |
| 평가 | Recall@5/MRR/nDCG, 인용 정확도, 음성 거절, 회귀 게이트(Δ0.02, 붕괴 탐지) | `evals.py`, `loop.py`, `evidence/loop/` |
| 증거·재현 | 증거 사이드카(latest + runs), 코드 지문, 한 번에 변수 하나 | `evidence/`, `docs/LOOP_LOG.md` |
| 배포 | 3개 OS × 2개 파이썬 CI, 린터 버전 고정, 두 번의 독립 감사와 e2e 레인, 태그 전 브랜치 CI | `.github/workflows/`, `docs/WORK_LOG_*` |

## 5. 이번 릴리스(0.2.0)에서 닫은 빈틈

| 항목 | 닫은 방법(id) | 증거 |
|---|---|---|
| `ci_minimal_permissions` | w2s1:m33 | .github/workflows/ci.yml:15-21 (top-level `permissions: contents: read` block added); tests/test_method_ci_minimal_pe... |
| `module_owners_map` | advlab-project:M16, practice-prompts:PP-20, w1s3:w1s3-35 | C:/firebaseprojects/_meth/module_owners_map/MODULE_OWNERS.md (one row per top-level path, no overlapping rows); test_... |
| `adr_dangling_refs` | advlab-harness:M33, advlab-project:M14, assignment-guides:AG-001 | docs/adr/ADR-0005-css-load-order.md and docs/adr/ADR-0006-evidence-latest-history.md (each with Decision/Rationale/Re... |
| `spinning_stopped_regression_test` | w1s2:spinning-detection-code-pattern, w1s2:agentic-loop-canonical | tests/bts_sbom_app/test_method_spinning_stopped.py::test_identical_plan_set_twice_stops_the_loop (identical-call/iden... |
| `llm_finish_reason_guard` | w1s2:termination-signal-mapping, w2s2:w2s2-22 | bts_sbom_app/llm.py:_complete() now reads choices[0].finish_reason and raises LLMError on 'length' before the content... |
| `sector_verified_by_role` | w1s3:w1s3-11, w2s3:w2s3-45 | bts_sbom/sectors.py VERIFIED_BY map (26 entries, one per SECTOR_PROFILES id across all 6 sectors) threaded into every... |
| `ai_call_site_registry` | w1s3:w1s3-13 | bts_sbom_app/ai.py (AI_CALL_SITES dict + check_registry()/_call_sites() at lines ~154-230, before propose()); docs/AI... |
| `ears_spec_coverage` | advlab-harness:M27, advlab-project:M19, w1s3:w1s3-06, w1s3:w1s3-07 | bts_sbom_app/speclint.py:all_patterns_covered() + __main__ gate; tests/bts_sbom_app/test_method_ears_spec_coverage.py... |
| `doc_naming_final_only_fix` | advlab-harness:M06, advlab-project:M06 | docs/BTS_SBOM_ANALYSIS.md (renamed from docs/ANALYSIS_2026-11-17.md) + tests/test_method_doc_naming_final_only_fix.py... |
| `dev_safety_hooks` | advlab-harness:M16, advlab-harness:M18, advlab-project:M33 | C:/firebaseprojects/_meth/dev_safety_hooks/.claude/settings.json (permissions.allow/ask/deny tiers + disableBypassPer... |
| `license_source_conflicts` | practice-prompts:PP-56, assignment-guides:AG-034 | bts_sbom_app/licenses.py look()/resolve() now appends {component, value_a, source_a, value_b, source_b} to stats['con... |
| `rag_source_diversity_cap` | annex-arch:M18, practice-prompts:PP-51 | bts_sbom_app/rag.py Index.search() now walks the full RRF-fused order and caps results at SOURCE_CAP=2 per chunk sour... |
| `secret_scanner` | advlab-harness:M20, advlab-harness:M19, advlab-project:M22, assignment-guides:AG-020, practice-prompts:PP-19 | tools/secret_scan.py; tests/test_method_secret_scanner.py; .github/workflows/bts_sbom_app_ci.yml (new 'Secret scan' s... |
| `chat_redteam_injection` | annex-eval:M27, annex-eval:M28, annex-eval:M29, annex-eval:M30 | tests/bts_sbom_app/test_method_chat_redteam_injection.py: ASR = successful_bypasses/total is computed and asserted ==... |

## 6. 로드맵: 닫지 않은 빈틈

기획 에이전트가 이번 라운드에서 보류한 항목 98개입니다. 이유는 대부분 "같은 파일을 다른 항목이 이미 수정" 또는 "라운드당 슬롯 한도"입니다. 가치 높은 순으로 다음 릴리스 후보입니다.

- Add requirement classification-code tagging (SFR/DAR/PER/SIR/SECR/CONR) - 보류 이유: File conflict: needs speclint.py + specs/bts_sbom_app_features.md, already claimed by selected ears_spec_coverage; retrofitting ~27 secti...
- Add a numeric-density (NFR) gate for non-AC limitation/capacity text - 보류 이유: File conflict: needs bts_sbom_app/speclint.py, claimed by ears_spec_coverage.
- Add a measured AC + test for the /api/health contract - 보류 이유: File conflict on specs/bts_sbom_app_features.md (claimed by ears_spec_coverage); the endpoint itself lives in forbidden bts_sbom_app/serv...
- CI check that a changed AC also touches its test in the same PR - 보류 이유: Needs .github/workflows/bts_sbom_app_ci.yml, claimed by secret_scanner's CI slot; good fast-follow in the same PR.
- Require a structured interview log before adding a new regulated sector/feature section - 보류 이유: File conflict on speclint.py/specs.md (claimed by ears_spec_coverage); the method itself flags it as a soft, bypassable guard.
- License/PII pre-check ledger for new package ecosystems - 보류 이유: No file conflict, but slot budget reached this round (14 selected); CONTRIBUTING.md + new docs file, medium value vs selected items.
- PROJECT_CHARTER.md with Must/Should/Could/Won't scope and measurable success metrics - 보류 이유: Process-document only with weaker measurability than selected items; defer.
- Value x feasibility x data-availability x regulatory-risk roadmap decision log - 보류 이유: Process-document only; lower priority than selected items this round.
- 6-question AI-system-selection checklist in the PR template - 보류 이유: Rated low value by its own auditor; process-only addition.
- Per-call LLM latency log for honest observability - 보류 이유: File conflict: bts_sbom_app/llm.py claimed by llm_finish_reason_guard; good same-module fast-follow.
- LLM-limits-to-countermeasure traceability table - 보류 이유: No hard file conflict (docs/ARCHITECTURE.md free) but slot budget reached; good next-batch pairing with adr_dangling_refs.
- Sensitivity/difficulty pre-routing before calling EXAONE - 보류 이유: File conflict: bts_sbom_app/ai.py claimed by ai_call_site_registry.
- Monthly LLM budget utilization report - 보류 이유: File conflict: bts_sbom_app/llm.py claimed by llm_finish_reason_guard.
- ADR + guard test for the agentic-search-vs-RAG boundary - 보류 이유: Touches docs/ARCHITECTURE.md; slot budget reached and overlaps the traceability-table idea above.
- Freshness/date metadata in RAG citations - 보류 이유: Touches forbidden bts_sbom_app/chat.py.
- SSE streaming for /api/chat - 보류 이유: Touches forbidden bts_sbom_app/server.py and bts_sbom_app/chat.py.
- Persisted chat session store across restarts - 보류 이유: Touches forbidden bts_sbom_app/chat.py and bts_sbom_app/server.py.
- Trim audit log for tool/RAG context inputs - 보류 이유: Touches forbidden bts_sbom_app/chat.py.
- Ablation harness proving hybrid beats solo BM25/TF-IDF - 보류 이유: Touches forbidden bts_sbom_app/evals.py.
- Sector-aware metadata filter for knowledge chunks - 보류 이유: Touches forbidden bts_sbom_app/chat.py.
- Deterministic multi-query retrieval (no LLM call) - 보류 이유: Touches forbidden bts_sbom_app/evals.py.
- Context-budget overflow counter - 보류 이유: Touches forbidden bts_sbom_app/chat.py.
- Expose dependency-graph multi-hop impact queries in chat - 보류 이유: Touches forbidden bts_sbom_app/chat.py and bts_sbom_app/evals.py.
- Decoding-parameter profile for EXAONE calls - 보류 이유: File conflict: llm.py and ai.py both already claimed (llm_finish_reason_guard, ai_call_site_registry).
- Record why each EXAONE proposal was dropped - 보류 이유: File conflict: bts_sbom_app/ai.py claimed by ai_call_site_registry.
- Skip the EXAONE call when there is nothing to propose - 보류 이유: File conflict: bts_sbom_app/ai.py claimed by ai_call_site_registry; strong same-module fast-follow for budget protection.
- Log which evidence fields ai.evidence() trimmed - 보류 이유: File conflict: bts_sbom_app/ai.py claimed by ai_call_site_registry.
- Surface the HITL approval wait as an explicit job state - 보류 이유: Touches forbidden bts_sbom_app/server.py.
- Retry EXAONE proposal generation once with the concrete validation error attached - 보류 이유: File conflict: bts_sbom_app/ai.py claimed; also doubles worst-case EXAONE calls against the daily budget, needs its own dedicated review.
- Add a non-interactive timebox test for the CLI/CI entry point - 보류 이유: Runs bts_sbom_app.cli as a subprocess; slot budget reached, pairs well with a future 'doctor' subcommand batch.
- Surface numeric conflicts across retrieved passages instead of always citing the first match - 보류 이유: Touches forbidden bts_sbom_app/chat.py.
- Add discriminating (confusable-tool) cases to the chatbot routing eval - 보류 이유: Touches forbidden bts_sbom_app/evals.py.
- Document an explicit scope (Won't/assumptions) block per feature area and lint it - 보류 이유: File conflict: speclint.py/specs.md claimed by ears_spec_coverage; good fold-in fast-follow.
- Add an opt-in 'new findings only' rescan report using the existing triage store - 보류 이유: Touches forbidden bts_sbom_app/console.py and bts_sbom_app/server.py.
- Harden bts_sbom_app/server.py against CSRF-style cross-origin POST - 보류 이유: Touches forbidden bts_sbom_app/server.py.
- AI Impact Assessment document for the EXAONE proposal lane and RAG chatbot - 보류 이유: Overlaps docs/AI_SUITABILITY.md (ai_call_site_registry) and the Model Card/AI Usage Card proposals below; avoid 3 overlapping governance ...
- Declare minimal GitHub Actions permissions in both workflows (bts_sbom_app_ci.yml half) - 보류 이유: Split: ci.yml half selected as ci_minimal_permissions; the bts_sbom_app_ci.yml half conflicts with secret_scanner's CI slot - fast-follow...
- Human-approval gate before 6-sector regulatory report export - 보류 이유: Touches forbidden bts_sbom/cli.py.
- Structured isError/errorCategory/isRetryable envelope on the JSON API - 보류 이유: Touches forbidden bts_sbom_app/server.py.
- Per-field confidence tag + review routing on EXAONE proposal refs - 보류 이유: File conflict: bts_sbom_app/ai.py claimed by ai_call_site_registry.
