# 구현 브리프 5 — 메타넷 심화과정 3~4주차 · 별첨 → BTS-SBOM 적용

출처 자료(8종, 2026-11-22 분석):
- `3주차_1차시_데이터엔지니어링_AI.pdf` — 메달리온(Bronze/Silver/Gold)·수집 패턴·회복력·멱등·MCP 스코프·컨텍스트 관리
- `3주차_2차시_NL2SQL.pdf` — NL2SQL 파이프라인(링크→예시→생성→검증→실행→답변)·카탈로그·자기교정·결정적 안전장치·EX 평가
- `3주차_3차시_DB자동최적화.pdf` — AI DBA(툴 5종·tool_choice·PreToolUse 차단·독립 리뷰·회귀 4분면)
- `4주차_1차시_모델서빙컨테이너.pdf` — 서빙 지표·이미지(멀티스테이지·비루트)·프로브·공급망(Trivy·SBOM·서명)·벤치
- `4주차_2차시_Inference배포_스케일링.pdf` — SLO·용량 산정·HPA/KEDA/CA·카나리·롤백·런북 4블록·CI/CD OIDC
- `4주차_3차시_멀티에이전트_스트리밍UI.pdf` — 워크플로 5패턴·토폴로지·coordinator-subagent·오류 봉투·SSE 이벤트·HITL
- `별첨_AI에이전트_답변품질_평가지표·방법론_TOP10.pdf` — 지표 ①~⑦ + 방법론 ⑧~⑩, 게이트 기준표, Selection 가이드
- `별첨_LLM·RAG·파인튜닝·AI에이전트_아키텍처_종합해설.pdf` — RAG/GraphRAG/Agentic RAG·PEFT·에이전트 9요소·기업 도입 3단계

이전 브리프(1~4)와 ac6082d에서 이미 적용된 것과의 중복은 "구현" 판정으로 정리했다.
정직 판 상세 표는 이 문서 §3, 구현 계획은 §4, 게이트는 §5.

---

## 1. 판단 요약 — 자료가 SBOM 프로젝트에 주는 것

1. **품질은 지표 게이트로** (별첨1): 근거성≥0.90·Recall@5≥0.85·읽기툴≥0.95/쓰기툴 1.0·치명 0·회귀 Δ≥−δ.
   프로젝트는 이미 `loop.gate`(Δ≥−0.02)·`chat.verify_claims`(AC-40/41)·`evals.rag_eval`이 있으므로
   **지표를 TOP10 체계로 통합·채점기 결합 규칙·회귀 게이트 정식화**가 남은 일.
2. **NL2SQL은 안전장치가 코드다** (3-2): 로컬 evidence SQLite 위 읽기전용 질의 레인 — sqlglot 검증기·
   4상태 executor(success/empty_result/partial_result/access_failure)·자기교정(오류 첨부·상한 3)·EX≥0.8.
3. **에이전트 실패는 숨기지 않는다** (4-3): 오류 봉투(severity·retry_budget·completed_steps·partial)·
   부분 결과+갭 주석·SSE 단계 이벤트(step_start/tool_call/tool_result/handoff/final/error)·발행 전 승인(HITL).
   `events.py`(AC-336~357)가 job 레벨이라면, **chat/council 레벨 단계 이벤트와 오류 봉투가 신규**.
4. **산출물은 자기 증명** (4-1): SBOM 도구가 **자기 이미지의 SBOM을 내보는** 공급망 게이트(Trivy CRITICAL 0 +
   CycloneDX 산출)는 이 프로젝트의 정체성과 직결. Dockerfile은 이미 비루트·pinned·healthcheck이므로
   미달은 "빌드·스캔·SBOM 게이트 미실행" 한 가지.
5. **운영 기록은 4블록** (4-2): docs/RUNBOOK.md가 있으므로 Delivery State·Rollback trigger·Monitoring
   Baseline 3블록 보강 + `docs/capacity.md`(SLO·용량 근거 수식) 신설.

## 2. 적용 안 함 — 정직 기각 (근거 필수)

| 자료 항목 | 판정 | 근거 |
|---|---|---|
| AI DBA 에이전트(3-3) | 적용 안 함 | 로컬 SQLite 단일 파일 DB — EXPLAIN·인덱스 제안·마이그레이션 파이프라인이 필요한 운영 DB가 없음. 필요 시점: evidence를 PostgreSQL로 이전할 때 |
| KEDA/AKS 배포(4-2) | 보류 | 단일 콘솔/웹앱, SLO 요구가 120 RPS급이 아님. kind 매니페스트는 G-단계에서 산출만 |
| PEFT/LoRA(별첨2) | 적용 불가 | EXAONE/Azure API 호출만 가능, 가중치 접근 없음 (LECTURE_MAPPING 기존 판정 유지) |
| GraphRAG(별첨2) | 로드맵 | CVE→CPE→패키지 관계 그래프는 유망하나 골든 Recall@5가 이미 높아 측정된 필요 없음 (계층 청킹과 동일 판단) |

## 3. 정직 매핑 표 (자료 → 현재 구현 상태 → 남은 일)

| 기법 (자료 출처) | 상태 | 어디에 / 남은 일 |
|---|---|---|
| 재시도 3회→서킷→빈 결과+구조화 사유 (3-1, CC16) | **구현** | `net.py` 서킷브레이커, `osv.py` 격상 — 부분 성공 목록(succeeded/failed)만 신규 |
| 자연키 멱등 upsert·재실행 중복 0 (3-1) | **구현** | 레코드 스키마 `bts-sbom.project.v1` 자연키=name, `write_json` 덮어쓰기 — 재처리 멱등 테스트로 명시만 |
| data.go.kr 함정 3종(콤마 만원·해제거래·트래픽) (3-1) | 해당 없음 | 실거래가 도메인 자료. 함정 유형(단위·플래그·한도) 판별은 OSV/ licenses 수집에 일반화 적용 중 |
| MCP 설정 스코프·${ENV}·읽기전용 (3-1) | **부분** | 프로젝트 키는 env/`.llm_config.json`(gitignored) — MCP 서버 노출 자체는 G-단계(별도 브리프) |
| 툴=행동·리소스=카탈로그 (3-1) | **미구현** | G-단계: bts_sbom 툴을 MCP로 노출 시 적용 (스키마·데이터 사전을 리소스로) |
| 스크래치패드·탐색 위임 (3-1, D5) | 해당 없음(자동화됨) | ZCode 하네스가 대행. 제품 코드엔 불필요 |
| NL2SQL 파이프라인 6단계 (3-2) | **미구현** | 신규 `nl2sql.py` — evidence SQLite 읽기전용 질의 레인 (§4 B) |
| 메타데이터 카탈로그·지표 정의 고정 (3-2) | **미구현** | B와 함께: 용어사전(예: "취약점 수"=정의) + `is_canceled`류 공통 필터 규약 |
| sqlglot SELECT-only·LIMIT 강제 (3-2) | **미구현** | B: 검증기 `validate()` — 신규 의존성 `sqlglot` 승인 필요(단일·경량·Apache-2.0) |
| 4상태 executor(0건≠오류) (3-2, D5§9) | **부분** | chat은 빈 결과를 passages 없이 처리 — 4상태 enum으로 통일이 B의 산출 |
| 자기교정 루프(오류 첨부·상한 3·동일오류 중단) (3-2) | **미구현** | B: `propose→validate→실행 오류 첨부→재생성`, 동일 오류 반복 시 중단 |
| EX≥0.8 평가셋 30문항 (3-2) | **미구현** | B: 로컬 DB 골든 30문항 + `evals.nl2sql_eval` |
| 툴 5종·tool_choice 첫행동 강제·폴백 (3-3) | **부분** | chat 툴 게이트 존재 — tool_choice 강제/폴백 개념은 EXAONE/Azure tool_use 옵션으로만 가능, 채택 여부 B에서 판단 |
| PreToolUse exit 2 차단·deny 우선 (3-3) | **구현(등가)** | `chat.py` actions 화이트리스트(읽기전용 세션)·검증 4계층 — 원격 차단 훅과 동등한 결정적 강제 |
| 회귀 4분면 direct/upstream/downstream/shared (3-3) | **구현** | `impact.py` AC-316~335 (ac6082d) |
| 독립 리뷰 인스턴스 (3-3) | **구현** | `review.py` 별도 세션 리뷰 (ac6082d) |
| 서빙 이미지 멀티스테이지·비루트·pinned (4-1) | **부분** | `Dockerfile.bts-sbom-app` 비루트(10001)·pinned·healthcheck 완료 — 멀티스테이지는 stdlib-only라 이득 미미(기각 가능하나 apt 층 분리 검토) |
| **Trivy CRITICAL 0 게이트 + CycloneDX SBOM 산출 (4-1)** | **미구현** | C: `docker build` 자체가 미실행 — 빌드→스캔→**자기 SBOM 산출**→bench_latest.json 증빙까지 게이트화 (§4 C) |
| 프로브 3종·graceful shutdown (4-1) | **부분** | `/readyz`+HEALTHCHECK 있음 — startup/readiness 분리·SIGTERM 진행 요청 정리 보강 (C) |
| 벤치·Evidence Sidecar(고정경로+timestamp/) (4-1) | **미구현** | C: CLI 부하 스모크(k6 대신 표준 라이브러리) → `evidence/bench/bench_latest.json` |
| SLO·용량 산정 근거 수식 (4-2) | **미구현** | F: `docs/capacity.md` — 콘솔 p95·동시 스캔 처리량 실측 기반 |
| 카나리·롤백 trigger·런북 4블록 (4-2) | **부분** | `docs/RUNBOOK.md` 존재 — Delivery State·Rollback trigger(예: /readyz 실패 5분)·Monitoring Baseline 보강 (F) |
| OIDC·환경 보호 규칙 CI/CD (4-2) | **미구현** | GitHub Actions 미구축 — G-단계(Pages 릴리스 파이프라인에 통합 검토) |
| 워크플로 5패턴·토폴로지 ADR (4-3) | **구현(등가)** | 단일 ReAct chat + council(members+chair) = 허브앤스포크. P2P 기각 근거는 코드 구조가 이미 coordinator 중심 |
| 서브에이전트 findings 명시 전달·비상속 (4-3) | **부분** | council 합의 프롬프트에 요약만 전달 — **핸드오프 스키마(schema_version·task·context·constraints·not_passed) 신규** (D) |
| 오류 봉투(severity·retry_budget·completed_steps·partial) (4-3) | **미구현** | D: council 멤버 실패 시 부분 결과 유지 + 구조화 봉투 + 갭 주석 |
| SSE 단계 이벤트 7종·HITL 발행 전 승인 (4-3) | **부분** | `events.py` job 레벨(AC-336~357) — chat 레벨 step_start/tool_call/tool_result/final/error + 승인 대기 상태가 신규 (D) |
| 지표① 정답도 EM/F1·채점기 결합 (별첨1) | **부분** | `evals.chat_eval` 근거성 위주 — 정답 참조 정규화(숫자·날짜) 후 EM/코드 채점 결합이 신규 (A) |
| 지표② 근거성·환각 ≥0.90 (별첨1) | **구현(부분)** | `chat.verify_claims` AC-40/41 — claim 단위 지지율 F 스코어·기준값 게이트가 신규 (A) |
| 지표③ 관련성·완결성 (별첨1) | **미구현** | A: 역생성 질문 cos 평균 + 필수요소 충족률 |
| 지표④ Recall@5≥0.85 (별첨1) | **구현** | `evals.rag_eval` 골든 — 기준값 문서화만 |
| 지표⑤ 툴 호출 정확도(읽기≥0.95·쓰기 1.0) (별첨1) | **미구현** | A: chat 툴 게이트 기록 기반 채점 — 쓰기 계열은 차단 테스트가 1.0 증명 |
| 지표⑦ 치명 0·과잉 거절 ≤5% (별첨1) | **부분** | 범위 밖 거절 5/5 테스트 존재 — 정상 질의 과잉 거절률 측정이 신규 (A) |
| ⑩ 회귀 게이트 Δ≥−δ·골든셋 스모크 (별첨1) | **구현** | `loop.gate` Δ≥−0.02 — TOP10 기준표와 수치·지표 대응 문서화 (A) |
| ⑧ LLM-as-a-Judge κ 보정 (별첨1) | 해당 없음 | 판정 모델 미사용(근거성은 코드 계산) — 기존 판정 유지 |

## 4. 구현 계획 — 4단계 (우선순위 순)

### A. 품질 평가 TOP10 게이트화 — `evals.py`·`evals_chat.py`·`chat.py` 확장
- A1 근거성 F 스코어: 답변을 claim으로 분해 → 컨텍스트 지지율 ≥ **0.90** 게이트 (`evals_chat`)
- A2 관련성(역생성 질문 cos) ≥ 0.80 + 완결성(필수요소 충족) — 절차·정책형 질문 골든에 한정
- A3 툴 호출 정확도: 게이트 로그에서 이름·인자·순서 비교, 읽기 ≥ 0.95 / 쓰기 = 1.0 (차단 테스트로 증명)
- A4 과잉 거절률 ≤ 5%: 정상 질의 세트 50건에서 범위 밖 거절 비율
- A5 TOP10 스코어카드 리포트(`evals/top10_report.md`) + 회귀 게이트 수치 문서화(Δ≥−0.02 기존 gate와 통합)
- AC: 스펙에 신규 AC 추가 후 테스트 마커 연결 (speclint 통과 필수)

### B. NL2SQL 안전 레인 — 신규 `nl2sql.py` + 챗 툴 연결
- B1 카탈로그(`nl2sql/catalog.json`): evidence 스키마·용어사전·지표 정의(예: 심각도=CVSS 기준 필터)
- B2 생성 툴 스키마: {sql, tables, assumptions, clarification_needed} nullable 규약
- B3 검증기: sqlglot 파싱 → 단일문·SELECT만(CTE 속 DML 포함)·LIMIT 강제 → 실패는 errorCategory 담은 구조화 에러
- B4 executor 4상태: success/empty_result/partial_result/access_failure (절단=partial)
- B5 자기교정: 원 질문+실패 SQL+DB 오류 첨부 재생성, 상한 3회, 동일 오류 반복 즉시 중단
- B6 EX 평가셋 30문항(EX≥0.8) + 차단 테스트(DROP/DELETE 100% 거절)
- 의존성: `sqlglot` — 프로젝트 stdlib 전용 원칙 위반 여부 승인 필요(개발 의존성으로 한정하는 대안 포함)

### C. 서빙 공급망 게이트 + 자기 SBOM — `Dockerfile.bts-sbom-app`·`scripts/`
- C1 첫 `docker build` 실측 완료 → Trivy `--severity CRITICAL --exit-code 1` 게이트
- C2 **bts-sbom이 자기 이미지의 CycloneDX SBOM을 산출**(trivy --format cyclonedx → `evidence/sbom/`) — "SBOM 도구의 자기 적용" 데모
- C3 프로브 분리(/health 프로세스, /readyz 증거폴더)·SIGTERM graceful shutdown 확인
- C4 벤치 스모크(동시 요청 n·p95) → `evidence/bench/bench_latest.json` + timestamp/ 누적

### D. 멀티에이전트 통제·스트리밍 UI 고도화 — `chat.py`·`council.py`·`events.py`·`server.py`·`web/`
- D1 오류 봉투: {error_type, severity(warning/recoverable/fatal), retry_budget, completed_steps, partialResult, coverageGap}
- D2 핸드오프 스키마: council→chair 전달에 schema_version·task·context·constraints·not_passed 명시
- D3 chat 레벨 SSE 단계 이벤트 7종(step_start/tool_call/tool_result/handoff/final/error) + `web/bts_console.js` 진행 표시·갭 배너
- D4 발행 전 HITL 승인: 효과 있는 작업 최종 제안 직전 승인 대기 상태 UI(기존 게이트 위에 승인 이벤트 추가)
- D5 부분 실패 시 보고서에 커버리지 갭 주석(실패 영역 명시, 실패 숨김 금지)

### E. 운영 문서·규약 (문서만)
- E1 `docs/capacity.md`: SLO(콘솔 p95·스캔 처리량) 실측 근거 수식
- E2 `docs/RUNBOOK.md` 4블록 보강: Delivery State·Deployment·Rollback trigger(/readyz 실패 5분)·Monitoring Baseline
- E3 LECTURE_MAPPING.md에 §3 표 병합

### G. 로드맵 (구현 보류, 승인 필요 시 착수)
- G1 kind 매니페스트 + GitHub Actions(OIDC) 릴리스 파이프라인
- G2 bts_sbom MCP 서버(툴=행동, 스키마·사전=리소스)
- G3 CVE-CPE 관계 GraphRAG, evidence PostgreSQL 이전 시 AI DBA 재검토

## 5. 게이트 (완료 판정)

| 단계 | 게이트 |
|---|---|
| A | top10_report.md 생성, 근거성 ≥0.90·과잉거절 ≤5%·툴(읽기) ≥0.95 달성, speclint/doclint 0, 전체 테스트 green |
| B | DROP/DELETE 100% 차단, 30문항 EX ≥ 0.8, 4상태 단위테스트, 스펙 AC 등록 |
| C | docker build 성공 + Trivy CRITICAL 0 + 자기 CycloneDX SBOM 존재 + bench_latest.json |
| D | 장애 주입 시 부분 결과+갭 주석 반환, SSE 이벤트 순서 테스트, 승인 대기 상태 테스트 |
| E | 문서 3종 병합·링크 확인 |

## 6. 스펙 등록 규칙 (기존 프로젝트 컨벤션)

- 신규 AC는 `specs/bts_sbom_app_features.md`에 먼저 추가 → 테스트 docstring의 "AC: BSA-AC-###"는 **실제 등록된 번호만** 인용 (임의 번호는 speclint 실패)
- 단계별 커밋: A / B / C / D 각각 독립 커밋(테스트 green 상태에서)
