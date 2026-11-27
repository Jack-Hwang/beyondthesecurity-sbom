# 메타넷 과정 폴더 전체 재분석 -> BTS-SBOM 고도화 + Azure 재배포 (2026-11-27)

1~2주차는 `docs/METANET_ADVANCED_MAPPING.md`, 5~6주차 첫 적용은 `docs/METANET_WEEK56_MAPPING.md`, 그 밖의 기법은 `docs/LECTURE_MAPPING.md` 에 있다.
이 문서는 **폴더 안의 모든 자료**(PDF 23 · pptx 7 · xlsx 1 · zip 6: 실습 프롬프트 · 과제 가이드 · 참조 프로젝트 · 산출물)를 다시 처음부터 읽고, 이미 있는 것과
대조해 **남은 갭만** 구현한 뒤 Azure에 올린 기록이다. "구현"은 테스트와 측정값이 있는 것만 뜻한다 (BSA-AC-1100~1240).
자격증명 파일(`애저실습키.txt`)은 일부러 읽지 않았다.

## 1. 방법

1. 자료를 텍스트로 추출하고 문서 그룹 27개로 나눴다. 그룹마다 에이전트 1명이 전문을 읽고, 가르치는 기법·요구마다 **저장소를 두 가지 이상 검색어로 검색해** 이미
   있는지 확인한 뒤 남은 것만 제안과 EARS 수락 기준으로 보고했다(저장소 검색 없이 빈 목록을 낸 그룹 2개는 더 엄격한 조건으로 다시 돌렸다).
2. 갭 116건을 87개 묶음으로 합치고, 3개 관점(제품 사용자 가치 · 과정/포트폴리오 적합 · 오프라인 구현 가능성/위험)이 1~5점으로 독립 채점했다.
3. 상위 후보를 10개 묶음으로 나눠 **파일 소유권이 겹치지 않게** 병렬 구현했고, 묶음마다 독립 검토 2명(정확성 / 보안·회귀)이 결함을 찾고 반박 검증 에이전트가
   재현을 시도해 **재현된 24건만** 확정해 고쳤다. 인젝션 방어와 영어 검색은 홀드아웃을 먼저 쓰고 측정한 뒤 개선했다.

| 문서 그룹 | 기법·요구 | 이미 있던 것(검증) | 남은 갭 |
|---|---|---|---|
| 1주차 (통합 아키텍처·컨테이너 챗봇·요구사항) | 52 | 15 | 4 |
| 2주차 (DataOps/MLOps·학습데이터·Hybrid RAG) | 55 | 15 | 5 |
| 3주차 (데이터엔지니어링·NL2SQL·DB 최적화) | 43 | 7 | 3 |
| 4주차 (모델 서빙·스케일링·멀티에이전트 UI) | 62 | 14 | 5 |
| 5주차 1~2차시 (Prompt Flow·Fine-tuning+RAG) | 38 | 7 | 5 |
| 5주차 3~4차시 (ML 파이프라인·운영 거버넌스) | 30 | 13 | 4 |
| 6주차 (최종 아키텍처·프로젝트 설계) | 24 | 10 | 3 |
| 별첨 TOP10 평가지표 | 10 | 10 | 5 |
| 별첨 LLM·RAG·에이전트 아키텍처 해설 | 46 | 12 | 5 |
| CCD RFC pptx: API 명세·생애주기 | 24 | - | - |
| CCD RFC pptx: 디자인·AI 패턴·챗봇 설계 | 22 | 12 | 6 |
| pptx: SDD AI-Native·보안 하네스·플랫폼 에이전트 | 90 | 12 | 5 |
| 요구사항명세서 xlsx | 42 | 14 | 3 |
| 실습 프롬프트 0~1주차 | 48 | 9 | 4 |
| 실습 프롬프트 2주차 | 30 | 18 | 6 |
| 실습 프롬프트 3주차 | 38 | 10 | 5 |
| 실습 프롬프트 4주차 | 27 | 9 | 4 |
| 실습 프롬프트 5주차 | 48 | 14 | 5 |
| 실습 프롬프트 6주차+README | 24 | 15 | 2 |
| 과제 가이드 1~3 | 48 | 10 | 4 |
| 과제 가이드 4~5+포트폴리오 | 58 | 14 | 5 |
| adv-lab: README·lab.sh·참조 프로젝트 | 46 | 11 | 6 |
| adv-lab: w1~w3 스캐폴드 | 48 | 17 | 3 |
| adv-lab: w4~w6 스캐폴드 | 42 | 12 | 5 |
| 산출물: 03_architecture | 90 | - | - |
| 산출물: 01_planning 나머지+00/02/03 | 380 | 10 | 7 |
| 산출물: 04_verify·05_operate·99_toolchain 외 | 30 | 11 | 7 |

(요구 수는 에이전트가 센 값이라 그룹 간 비교 기준이 아니다. 표의 "-" 는 첫 시도가 비어 있어 재분석으로 대체된 그룹이다.)

## 2. 실측으로 드러난 약점 (이번에 고친 것)

| 발견 | 측정 | 조치 |
|---|---|---|
| 프롬프트 인젝션 방어가 영어 문장 리터럴뿐 | dev 50개 재현율 **0.48**, 한국어 공격 **0/8** | 동사+목적어 형태·한국어 활용/존댓말·제로폭/자간 난독화 정규화로 일반화. 홀드아웃(46개, 사전 작성) 재현율 0.182 -> **1.0**, 오탐 **0.0**; dev 0.48 -> 1.0 (남은 오탐 1건은 한계로 명시) |
| 영어 질문은 검색은 되는데 신뢰도 게이트가 절반을 거절 | `rag_en` recall@5 0.875 / found **0.50** | 영어->한국어 용어 다리 + 영어 전용 게이트 바닥: recall 1.0, MRR 0.906, found **0.812**, 홀드아웃 found 0.875, 영어 OOD 거절 1.0. **한국어 6개 지표 한 자리도 불변** (golden 1.0/0.95, dev 1.0/0.836, test 0.917/0.75) |
| NL2SQL `패키지별` 템플릿이 존재하지 않는 컬럼을 조회 | 골든 2건이 항상 접근 실패인데 평가가 양쪽 실패를 일치로 세어 EX 1.0 | 템플릿·참조 SQL 수정, `nl2sql_eval` 이 양쪽 실패를 실패로 보고 |
| 숫자 인용 검사가 `7.5` 의 `5` 를 인용된 것으로 통과 | 재현 후 확정 | 토큰 단위 일치로 교체 |
| 모순 게이트가 "not vulnerable" 을 affected 로 분류 | 재현 후 확정 | 부정형 우선 분류(한국어 포함) |
| 에스컬레이션 id 가 가림 처리된 질문으로 계산돼 서로 다른 질문이 하나로 합쳐짐 | 재현 후 확정 | 원문 해시로 id, 저장/반환은 가림 유지 |
| SSRF 가드 로그에 `user:password@` 가 평문 | 재현 후 확정 | 호스트명만 기록 |
| 비밀값 스캐너가 Windows 정션을 따라 루트 밖을 훑음 | 재현 후 확정 | reparse point 검출 + 실경로 포함 검사 |
| 예산 스크립트가 실제 az 가 받지 않는 옵션을 출력 | 설치된 az 2.93.0 `--help` 로 확인 | 검증된 7개 옵션만 실행 줄에, 임계값·태그는 비실행 안내로 |
| 배치 재시도 후 합산 집계가 새 실행과 다름 | 재현 후 확정 | 프로젝트별 제안 통계를 summary 에 보존, 두 집계가 같음을 테스트 |
| RAG 게이트 min_bm25 가 손으로 정한 값 | 61문항 5구간: 구간 검사는 "안전 아님"(0.25), **정확한 항목별 검사는 안전**(OOD 오수락 0/14) | `evalrag --calibrate` 가 둘을 나란히 보고 (종료 코드는 정확한 검사) |

## 3. 구현한 묶음 (점수 순위 · 묶음 · 평균 점수 · AC)

| 순위 | 묶음 | 평균 | 제목 | AC |
|---|---|---|---|---|
| 1 | C20 | 4.67 | Redeploy template (containerapp.yaml) has regressed behind the proven live probe config | 1190~1191 |
| 2 | C03 | 4.33 | No numeric-token citation completeness check over the free-text chat answer | 1111 |
| 3 | C02 | 4.00 | One failing tool call aborts the whole chat turn instead of being isolated | 1110 |
| 4 | C18 | 4.00 | License resolution has no stratified confidence audit across resolution sources | 1180~1181 |
| 5 | C23 | 4.00 | Conversation memory's 3-turn window discards case identifiers (CVE/component/license ids) needed later | 1120~1121 |
| 6 | C40 | 4.00 | MCP chat_ask always holds its own server-side LLM key instead of an operator-gated/sampling design | 1150~1151 |
| 7 | C54 | 4.00 | Prompt-injection guard is regex-only with no labeled attack/benign corpus or measured precision/recall | 1172 |
| 8 | C01 | 3.67 | No egress host/SSRF allowlist at the shared outbound gateway (net.py) | 1130~1135 |
| 9 | C05 | 3.67 | No stratified confidence x impact audit sampling for closed triage/VEX decisions | 1182 |
| 10 | C08 | 3.67 | No secret/credential scan over the source trees BTS-SBOM analyses | 1136~1139 |
| 11 | C17 | 3.67 | NL2SQL generation output isn't shape-validated before use | 1160~1161 |
| 12 | C19 | 3.67 | Escalation handoff payload omits the root-cause/coverage evidence it already computes | 1122 |
| 13 | C29 | 3.67 | The RAG confidence-gate threshold (min_bm25) is hand-tuned, not calibrated | 1170~1171 |
| 14 | C33 | 3.67 | No graduated 'nearing daily LLM budget' warning tier before the hard stop | 1140~1141 |
| 15 | C36 | 3.67 | Operator/user-authored free text (escalation notes, VEX decisions) persists PII with no redaction | 1124 |
| 16 | C37 | 3.67 | Azure Container Apps descriptor declares no governance tags or cost-budget alerts | 1192 |
| 17 | C44 | 3.67 | No answer-level consistency gate (self-contradiction check across claims) | 1125 |
| 18 | C48 | 3.67 | No token/cost ($) ledger extending the daily call-budget | 1142 |
| 19 | C56 | 3.67 | No standalone smoke-test script for a live/redeployed base URL | 1193~1194 |
| 20 | C57 | 3.67 | No few-shot examples ground the live LLM NL2SQL prompt (the lane production actually uses) | 1162~1164 |
| 21 | C73 | 3.67 | No consolidated 6-governance-gate audit checklist named per the course taxonomy | 1183~1184 |
| 22 | C81 | 3.67 | NL2SQL schema/catalog isn't exposed as an MCP resource, and nl2sql isn't a direct MCP tool | 1153~1154 |
| 23 | C13 | 3.33 | Bulk/fleet project scans have no way to retry only the failed subset | 1195~1199 |
| 24 | C21 | 3.33 | Vulnerability answers never disclose how stale the local OSV snapshot is | 1166~1169 |
| 27 | C30 | 3.33 | EX evaluation never exercises the LLM-generation NL2SQL lane that production actually uses | 1165 |
| 29 | C34 | 3.33 | MCP initialize response hides the resources capability the server already serves | 1152 |
| 30 | C38 | 3.33 | Chat answers carry no spec/prompt/model/build version stamp for later audit | 1114 |
| 34 | C60 | 3.33 | MCP server has no long-running tool and never emits progress/log notifications | 1158~1159 |
| 42 | C11 | 3.00 | No deterministic secret-pattern masking on chat answers, escalation payloads or reports | 1123 |
| 43 | C16 | 3.00 | Chat recommends clean-room reimplementation for copyleft components without checking the deployment can verify it | 1113 |
| 48 | C46 | 3.00 | No MCP 'prompts' primitive for the product's own canned questions | 1155~1157 |
| 58 | C77 | 3.00 | Prompt re-pin (`prompts --update`) requires only a reason string, not a verified fresh eval result | 1185~1186 |
| 59 | C79 | 3.00 | license_risks silently defaults the distribution mode to 'binary' without flagging it as an assumption | 1112 |
| 62 | C84 | 3.00 | RAG eval sets measure zero English in-domain queries | 1173 |
| 67 | C10 | 2.67 | No concurrency cap or per-consumer rate limit on /api/chat and /api/chat/stream | 1145~1147 |
| 70 | C15 | 2.67 | LLM client's 429 backoff ignores the provider's Retry-After header | 1143 |
| 79 | C41 | 2.33 | Truncated (finish_reason=length) completions are logged the same as any malformed JSON | 1144 |
| 84 | C72 | 2.33 | No chat question length bound (boundary-condition input guard) | 1148 |

그 밖에 재분석(산출물 03_architecture)에서 나온 **소스 경계**(`BTS_SBOM_ALLOWED_ROOTS`, AC-1106~1109)와, 배포에 필수라 직접 만든 **액세스 토큰 게이트**(AC-1100~1105),
빌드 컨텍스트 허용 목록(AC-1200), CLI 연결(AC-1201~1206), 콘솔 인계/부분 커버리지 배지(AC-1220~1223), 렌더링 스크립트(AC-1224~1225)가 있다.

## 4. 구현하지 않은 후보 (후속)

아래는 재분석에서 점수가 매겨졌지만 이번에 만들지 않은 49개다. 이유는 "중복·저가치"가 아니라 **이번 범위 밖**이다 (상위 순서대로 읽으면 다음 작업 목록이 된다).

| 순위 | 묶음 | 평균 | 제목 |
|---|---|---|---|
| 25 | C22 | 3.33 | Chat answer UI never shows the escalation handoff or partial-scan coverage gaps it already computes |
| 26 | C26 | 3.33 | Patch-apply approval has a digest but no actor-attributed, append-only audit trail |
| 28 | C31 | 3.33 | Patch-review convergence is untracked; the same reviewer finding can recur without escalating |
| 31 | C50 | 3.33 | The remediation decision table is hardcoded with no org-overridable config |
| 32 | C52 | 3.33 | No escalation trigger-rate rollup report |
| 33 | C55 | 3.33 | No coverage gate linking security-classified AC ids to the Enforcement Map |
| 35 | C64 | 3.33 | Human triage corrections never feed back into the regression/golden eval sets |
| 36 | C66 | 3.33 | No stratified human-review sampling queue for non-escalated chat answers |
| 37 | C67 | 3.33 | A heuristic quality score can be promoted to a release gate without human-label calibration |
| 38 | C71 | 3.33 | Resolved escalations are never read back as an eval-candidate feed |
| 39 | C85 | 3.33 | AI Impact Assessment document has no staleness check |
| 40 | C87 | 3.33 | verify_claims() is binary (supported/not) instead of the material's 3-way classification including contradiction |
| 41 | C06 | 3.00 | No retry of only the unqueried packages from a prior scan |
| 44 | C28 | 3.00 | No Datasheet-for-Datasets doc or content-addressed chunk lineage for the knowledge/ corpus |
| 45 | C42 | 3.00 | Loop regression pass records have no latency or cost-per-case metric |
| 46 | C43 | 3.00 | No queue-depth or oldest-wait-time metrics for open escalations |
| 47 | C45 | 3.00 | Eval sets have no source/adversarial coverage tagging |
| 49 | C58 | 3.00 | MCP server has no per-call timeout, audit log or per-tool error rate |
| 50 | C59 | 3.00 | Supply-chain bench history is recorded but never gated for regression |
| 51 | C61 | 3.00 | No distinct Answer Correctness grader against a reference answer |
| 52 | C63 | 3.00 | No reverse traceability gate: CLI/API surfaces can exist with zero mention in any spec AC |
| 53 | C65 | 3.00 | No coarse-grained phase checkpoint persisted for scan jobs (crash/SIGTERM leaves no resume trace) |
| 54 | C70 | 3.00 | No MLOps maturity (Level 0/1/2) self-diagnostic as a measured command |
| 55 | C74 | 3.00 | Tool-call accuracy eval checks only that a tool fired, never whether the argument value was correct |
| 56 | C75 | 3.00 | No weighted stage-bottleneck score in the TOP10 quality report |
| 57 | C76 | 3.00 | No end-user feedback (thumbs up/down) capture on chat answers |
| 60 | C80 | 3.00 | No decision-criteria table exists for human reviewers at approval-gated checkpoints |
| 61 | C82 | 3.00 | Rollback triggers are documented but not machine-evaluated |
| 63 | C86 | 3.00 | Chat-stream latency (TTFT), which capacity.md itself names as the right metric, has never been measured |
| 64 | C04 | 2.67 | No standing operational quality/degradation-drift monitor with rolling-baseline alerting |
| 65 | C07 | 2.67 | Circuit-breaker 'we never asked' reason collapsed to plain None in license/vuln lookups |
| 66 | C09 | 2.67 | CI never runs the product's own scanner on its own dependencies (no dogfood gate) |
| 68 | C12 | 2.67 | No scheduled (nightly) drift-check workflow decoupled from PR/push triggers |
| 69 | C14 | 2.67 | No reproducibility/determinism regression test for the eval or scan pipeline |
| 71 | C35 | 2.67 | Dockerfile/deploy image references are pinned by tag only, not an immutable digest |
| 72 | C51 | 2.67 | HITL approval controls in the web console carry no accessible label |
| 73 | C53 | 2.67 | Chat/MCP tool descriptions lack a worked example and a stated boundary against confusable tools |
| 74 | C68 | 2.67 | Outbound LLM/registry calls have no proactive rate limiter, only reactive retry-after-429 |
| 75 | C24 | 2.33 | No diagnose-and-propose index advisor for the growing local OSV SQLite mirror behind nl2sql |
| 76 | C25 | 2.33 | No correlation/trace id links a request's job record, SSE stream and escalation entry |
| 77 | C32 | 2.33 | A chat turn has no cancellation; disconnect doesn't stop in-flight LLM/tool work |
| 78 | C39 | 2.33 | No repo-wide checker that relative Markdown links actually resolve |
| 80 | C47 | 2.33 | Golden/dev/test proportions are reported as point estimates with no confidence interval |
| 81 | C49 | 2.33 | No low decoding temperature enforced for structured/extraction LLM calls |
| 82 | C62 | 2.33 | No retrieval-vs-groundedness diagnostic quadrant or 3-way miss classification |
| 83 | C69 | 2.33 | /api/chat/stream has no keep-alive heartbeat during long silent gaps |
| 85 | C78 | 2.33 | No near-duplicate/stale doc detector for docs/ |
| 86 | C27 | 2.00 | No generic Mermaid structural well-formedness lint across all diagram kinds |
| 87 | C83 | 2.00 | No conflicting-instruction lint across registered prompt blocks |

의도적으로 하지 않은 것: 파인튜닝(이 앱의 결핍은 지식이고 RAG 가 푼다), Azure ML / Prompt Flow 서비스 종속(표준 라이브러리 전용·오프라인 우선), 다른 제품(Claude Code
Desktop)의 데스크톱·SSH·플러그인 요구, MCP 샘플링(연결 가능한 클라이언트가 아직 지원하지 않음 — 서버 보유 키를 운영자 게이트로 막는 쪽을 택함).

## 5. Azure 배포 (2026-11-27)

주소 https://bts-sbom.wittyforest-2c8fae00.koreacentral.azurecontainerapps.io (리소스 그룹 `bts-sbom-rg`, koreacentral, 구독 "Azure in Open"). 자세한 절차·함정은 `deploy/azure/README.md` §12, 상태 기록은 `docs/RUNBOOK.md` Delivery State.

| 항목 | 내용 |
|---|---|
| 구성 | ACR `btsbomacr1126`(Basic) · Log Analytics `btsbom-logs` · 환경 `bts-sbom-env` · Storage `btsbomstg1127`(Azure Files `evidence` 2Gi) · 앱 `bts-sbom`, 모든 리소스에 태그 team/week/owner |
| 이미지 | `bts-sbom-app:0.5.0-final1127f` (현재 리비전 `bts-sbom--0000006`), 클라우드 빌드, **빌드 컨텍스트 1.925 MiB** (허용 목록 `.dockerignore`; 없으면 저장된 LLM 키가 든 `evidence/` 와 4 GB `_attic/` 까지 올라간다) |
| 선언 | `scripts/azure_render_app.py` 가 템플릿을 환경변수로 렌더(ASCII 전용, 비밀값은 출력 안 함), 스케일 0->1, 0.5 vCPU / 1 Gi, 프로브 3종 |
| 인증 | 액세스 토큰 게이트 ON: `/` 토큰 없이 401, `/healthz`·`/readyz` 200. 토큰은 로컬 파일과 ACA secret 에만 있다 |
| 소스 경계 | `BTS_SBOM_ALLOWED_ROOTS=/srv/bts-sources` — 라이브 5/5 거부(`/etc`, `C:/Windows`, `file:///etc`, 메타데이터 주소, 127.0.0.1 git URL) |
| 스모크 | `scripts/smoke_deployed.py` 4/4 PASS (healthz 125 ms, readyz 93 ms, 인증 401/200, SSE 첫 바이트 281 ms) |
| 기능 | LLM 채팅(`gpt-5-mini`, 한국어, 인용 1.0, 12.2 s) · NL2SQL(LLM 레인, 수정한 `패키지별` 질의 포함) · 에스컬레이션 로그 · 시드 프로젝트 3개 + OSV DB |
| 원격 스캔 | sampleproject 8 s · dvpwa 24 s(20 컴포넌트, 라이선스 100 %) · **NodeGoat 1,091 컴포넌트 / 311 취약점 / 라이선스 98.5 %** |

**배포가 잡은 결함 1건**: OSV DB 를 Azure Files(SMB)에 두자 스캐너 캐시 쓰기가 `database is locked` 로 건마다 5 s 를 기다려 NodeGoat 스캔이 **780 s**(이전 배포 355 s)였다.
시작 시 읽기 전용 시드를 로컬 디스크로 한 번 복사하도록 고쳐(AC-1226~1227) 같은 스캔이 **96 s**, 락 오류 0, 결과 동일.
**셸 함정**: Git Bash 가 `az` 의 `/tmp/...` 인자를 Windows 경로로 바꿔 보낸다(`MSYS_NO_PATHCONV=1` 필요).
**하지 않은 것**: Easy Auth(AAD) — 앱 등록이 필요하고 서비스에 사용자 계정이 없다 / 예산 경보 — 설치된 `az consumption budget create` 가 알림 임계값을 표현하지 못한다 / 최소 레플리카 1 고정 — 데모 비용 상한 때문에 0 으로 둠.

**배포 후 적대적 점검(레드팀, 로컬 인스턴스)**: 에이전트 3명이 공격 48가지를 시도해 11건을 재현했고 반박 검증을 모두 통과했다. 전부 고쳤다(AC-1230~1240).

| 재현된 결함 | 조치 |
|---|---|
| 요청을 다 보내지 않고 멈춘 연결이 스레드를 붙잡음 — 게이트 **아래**에서 일어나 토큰이 소용없음 | 읽기 타임아웃 15 s + 동시 연결 상한 128(초과 즉시 503) |
| 채팅 한 턴마다 프롬프트 digest 로 패키지 85개 재파싱(약 1 CPU 초) | 파일 서명 기준 캐시 + 시작 시 예열 |
| 레거시 IPv4 표기(`2130706433`, `0x7f000001`, `0177.0.0.1`, `127.1`, `localhost.`)가 git/fetch SSRF 가드를 통과 | 두 가드가 하나의 파서(`netaddr.py`) 공유 |
| `file://호스트/경로` 의 검사 경로와 실행 경로가 다름 | authority 가 있으면 거부 |
| DNS 리바인딩: 검사 후 git 이 다시 해석 | 검사한 공개 주소를 `http.curloptResolve` 로 https 클론에 고정 |
| 실패한 자격증명에 속도 제한 없음 | 호출자별 20회/분 초과 시 토큰 검사 없이 429 |
| X-Forwarded-For 위조로 호출자별 제한 우회 | 운영자가 `BTS_SBOM_TRUST_FORWARDED=1` 선언 시에만 신뢰 |
| 중첩 200,000단 JSON 이 RecursionError | 400 으로 처리 |
| Server 헤더가 Python 버전 노출 | `bts-sbom` |

**라이브에서만 보인 결함**: 인그레스는 `100.100.0.x`(공유 주소 공간)에서 접속하는데 `ipaddress.is_private` 가 이를 False 로 봐 X-Forwarded-For 를 신뢰하지 않았고, 호출자별 제한이 라이브에서 한 번도 걸리지 않았다(36회 전부 200).
옵트인 진단 헤더로 `peer=100.100.0.64 xff=<실제 IP>` 를 확인해 판정을 "공개 라우팅이 아닌 주소"로 넓힌 뒤 라이브 재측정: 채팅 36회 중 200 x30 / 429 x6, 잘못된 토큰 25회 중 401 x20 / 429 x5.


## 6. 한계

- 에이전트가 채점한 점수와 "이미 있다"는 판정은 검색 기반이다. 두 가지 이상 검색어로 확인했지만 누락 가능성이 0은 아니다.
- 인젝션 방어는 정규식이다. 부정문("무시하지 마")과 소프트웨어 동작 설명("라이브러리는 이전 지시를 무시한다")을 구분하지 못한다. 홀드아웃 46개 기준 수치이며 새 공격 표현은 새 샘플로 다시 재야 한다.
- 영어 검색은 영어->한국어 용어 다리다. 32개 영어 질의로 잰 챗 `found` 는 27/32(0.84), OOD 11/11 거절이고, 임의의 영어 질문은 여전히 놓칠 수 있다.
- 프롬프트 레지스트리는 템플릿 문구의 지문이다. NL2SQL 예시 목록처럼 상수가 아닌 값은 지문에 들어 있지 않다.
- 대화 메모리는 프로세스 전역 한 개다(기존 단일 테넌트 설계). CaseFacts 는 상한(500)과 LRU 만 두었고 호출자별 분리는 하지 않았다.
- 서비스는 단일 레플리카·단일 공유 토큰이다. 사용자 계정·권한 분리는 없다(Easy Auth/AAD 는 앱 등록이 필요해 이번엔 하지 않았다).
