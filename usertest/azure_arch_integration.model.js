// azure_arch_integration.model.js — the Azure operations architecture squeezed from 34 slides into 10 for the
// course assignment deck (docs/BTS-SBOM_1-6주차_종합_과제.pptx). Content comes from the architect deck model
// (single source); only the frame is denser (content area y 178..660, no verdict bar — verdicts go to notes).
"use strict";
const A = require("./azure_arch_deck.model.js");
const { M, I, G } = A;
const by = (t) => { const s = A.S.find((x) => x.title.startsWith(t)); if (!s) throw new Error("no slide " + t); return s; };
const S = [];

S.push({ id: "ctx", ...by("시스템 컨텍스트 (C4-1)"), dy: 50 });
S.push({
  id: "inv_state", kind: "table", then: "table2", split: 188,
  t1: { title: "inventory", fs: 9, cols: [{ t: "리소스 (측정)", w: 3.0 }, { t: "규모 · 이중화", w: 3.2 }, { t: "아키텍트가 본 점", w: 5.8 }], rows: [
    ["ACA 환경 bts-sbom-env", "Consumption · 영역 중복 아님", I("VNet 통합·영역 중복은 환경 재창출이 필요 — 프로덕션 전환의 전제")],
    ["앱 bts-sbom · 리비전 0000016", "0.5 vCPU · 1Gi · 2Gi · 0→1", M("리비전 17개 보존(전부 Healthy) · ACR 태그 15 · 롤백 = 트래픽 전환(훈련 0회)")],
    ["ACR btsbomacr1126", "Basic · 공용 엔드포인트", G("서명·신뢰 정책·소프트 삭제 모두 OFF — 공급망 증명 없음")],
    ["Storage btsbomstg1127 · evidence", "Standard_LRS 단일 리전 · 2GB", G("백업 0 · 프라이빗 엔드포인트 0 — 사용 5.4MB")],
    ["Log Analytics btsbom-logs", "보존 30일 · 한도 없음", G("HTTP 요청 로그 꺼짐 · 앱 메트릭 미수집")],
    ["Azure OpenAI (별도 RG)", "gpt-5-mini · GlobalStandard", M("일일 호출 예산 80회 — 장부는 컨테이너 로컬(아래)")],
  ] },
  t2: { title: "state", fs: 9, cols: [{ t: "상태 — 무엇이 살아남나", w: 2.6 }, { t: "내구성", w: 2.4 }, { t: "재시작 · 스케일 0에서", w: 3.6 }, { t: "RPO — 판단", w: 3.4 }], rows: [
    [M("Azure Files 'evidence' — 유일한 영속 계층"), M("단일 리전 · 백업 0"), M("보존"), I("지역 장애·삭제 시 전체 유실 가능 — 백업은 선택이 아니라 전제")],
    [M("로컬 디스크 — OSV DB·격리 복사본·LLM 장부"), M("휘발성"), M("매 기동 재생성 — 'OSV snapshot: copied' 로그 확인"), I("LLM 일일 예산이 기동마다 0으로 — '일일 상한'이 사실상 '기동당 상한'")],
    [M("프로세스 메모리 — 잡·SSE 버스·속도 제한 표"), M("휘발성"), M("실행 중 스캔은 중단, 재요청"), I("단일 레플리카라 허용 — 레플리카 ≥ 2면 큐·외부 저장으로")],
    [M("외부 — OSV·deps.dev·Git 호스트"), M("외부"), M("회로차단기 3회 실패 → 60초 개방 · 결과는 gap 공시"), I("RPO 개념 없음 — '오프라인 폴백 시 갭 공시'가 가용성 전략")],
  ] },
  verdict: I("영속 계층이 '폴더 하나'인 것은 의도된 단순함이다 — 그렇다면 그 폴더의 백업은 전제다."),
  notes: "출처: az resource list(5개), az containerapp show·env show, az acr show, az storage share-rm show --expand stats, REST /revisions(17개), 진단 설정(HTTPLogs off), Dockerfile 주석(LLM 장부 경로 /app/evidence), 콜드 스타트 콘솔 로그. 2026-11-28 실측.",
});
S.push({ id: "cred", ...by("자격 증명·비밀·네트워크 경계"), dy: 50 });
S.push({ id: "modules", ...by("모듈 지도 (C4-3)") });
S.push({
  id: "adr", kind: "table", fs: 9.5,
  cols: [{ t: "판단", w: 1.7 }, { t: "채택", w: 3.6 }, { t: "버린 대안", w: 3.0 }, { t: "되돌리는 조건", w: 3.7 }],
  rows: [
    ["의존성 0", M("표준 라이브러리 전용"), "requests · FastAPI · numpy", I("바이너리 분석·임베딩이 핵심일 때")],
    ["프로세스", M("단일 프로세스 3차선(동기·SSE·잡)"), "web-queue-worker · Dapr", I("스캔 대기가 사용자 경험을 해칠 때")],
    ["스트리밍", M("SSE + heartbeat 15초"), "WebSocket · long-poll", I("클라이언트 푸시 요구")],
    ["영속 저장소", M("파일 — JSON 레코드 + JSONL 대장"), "PostgreSQL · Cosmos DB", I("질의·트랜잭션·다중 레플리카 쓰기")],
    ["스케일", M("최소 0 → 최대 1 레플리카"), "상시 1대", G("첫 요청 35초의 일 허용치 미정의")],
    ["SQLite 위치", M("쓰기 DB는 로컬, 시드만 공유"), "공유 위 SQLite", I("로컬 재생성 비용이 커질 때")],
    ["자격 증명", M("시스템 할당 MI + AcrPull 1건"), "관리자 계정 · Workload Identity", I("Key Vault 연계 시 연합 자격 증명")],
    ["인증", M("공유 토큰 1개(최소 16자)"), "Easy Auth 사용자 인증", G("사용자 ≥ 2 또는 '누가' 필요 — 현재 미설정")],
    ["LLM", M("외부 gpt-5-mini · 예산 80회/일"), "자체 호스팅 오픈모델", I("예산 초과·데이터 반출 우려")],
    ["승인", M("승인 토큰 = 계획 다이제스트"), "세션 기반 · 역할 승인", I("다단계 승인·역할 분리")],
    ["이미지", M("python:3.12-slim · 비루트 · 86MB"), "디스트로리스 · 멀티스테이지", I("이미지 크기가 콜드 스타트 병목일 때")],
    ["배포 단위", M("리비전 불변 · Single · 최신 100%"), "Blue/Green · 카나리아", I("트래픽이 1 레플리카를 넘을 때")],
  ],
  facts: [
    ["얻은 것", M("유휴 비용 0(72h 중 5.7h 가동) · 공급망 표면 최소(선언 의존성 []) · 마이그레이션 0 · 롤백 = 트래픽 전환")],
    ["잃은 것", M("첫 요청 35.4초 · 경고·백업 없는 단일 리전 LRS · 질의·트랜잭션 불가 · 토큰 1개 = 모두 같은 신원")],
  ],
  verdict: I("여섯 판단 중 인증만 '의도한 미완'이다 — 사용자가 생기면 끝나는 임시값이며, 임시값에 만료일이 없는 것이 리스크다."),
  notes: A.S.find((x) => x.title.startsWith("핵심 설계 판단 12건 (ADR 요약) ①")).notes + " / " + A.S.find((x) => x.title.startsWith("핵심 설계 판단 12건 (ADR 요약) ②")).notes,
});
S.push({
  id: "coldcap", kind: "coldcap", total: 35.38,
  segs: by("런타임 뷰 — 콜드 스타트").segs, bars: by("용량·성능 모델").bars,
  notes: [
    M("첫 요청 TTFB 35.38초(레플리카 0) → 기동 후 /healthz 56ms · /readyz 113ms · 토큰 없는 /api 401 55ms. 로그: 04:05:15.907 스케줄 → 04:05:35.782 풀 완료(3.72초·86MB) → 04:05:36.001 리스닝."),
    I("35.4초 중 앱이 바꿀 수 있는 것은 마지막 0.2초뿐 — 99%가 플랫폼 활성화·이미지 풀. 완화: 최소 레플리카 1(상시 과금·미실측) 또는 예열 ping(스케일 0을 깨는 위험)."),
    I("병목은 자원이 아니라 직렬 큐(잡 1)와 콜드 스타트 — 다음 실험은 잡 동시성 2(env BTS_SBOM_MAX_JOBS)."),
  ],
  verdict: I("콜드 스타트는 버그가 아니라 가격이다 — '첫 요청'을 하루 몇 번 겪는지가 최소 레플리카를 올릴지의 유일한 기준."),
});
S.push({ id: "slo", ...by("SLO 제안"), fs: 9.5 });
S.push({ id: "fmea", ...by("장애 모드 분석 (FMEA)"), fs: 8.5 });
S.push({ id: "sr", kind: "strideRisk", stride: { title: "stride", fs: 8.5, cols: by("위협 모델 (STRIDE)").cols, rows: by("위협 모델 (STRIDE)").rows }, risks: by("리스크 레지스터").risks,
  verdict: by("위협 모델 (STRIDE)").verdict, notes: by("위협 모델 (STRIDE)").notes + " / " + by("리스크 레지스터").notes });
S.push({ id: "tobe", ...by("목표 아키텍처 (To-Be)"), dy: 50 });
S.push({
  id: "lanes", kind: "table", fs: 9,
  cols: [{ t: "레인 (모듈)", w: 3.2 }, { t: "역할 — spec AC 문장 요약", w: 7.0 }, { t: "AC · 근거", w: 2.8 }],
  rows: [
    ["AI 영향성 평가 (ai_impact.py)", "지금 존재하는 산출물에서만 증거를 해석 — 행 수·구성·버전 스탬프. 유령 경로는 수집할 수 없다", "AC-1264 · docs/AI_IMPACT_ASSESSMENT.md"],
    ["평가 코퍼스 인벤토리·데이터시트 (datasheet.py)", "전형·경계·적대를 보이는 규칙으로 집계 — 미지 태그는 그대로 보고한다", "AC-1265 · docs/DATASET_DATASHEET.md"],
    ["LLM 호출 장부·페이싱 (llm.py)", "모든 전송 시도와 결과를 기록(429_retry_after 등) · 구조화 호출은 temperature 0.2, 추론 모델엔 미전송 · 최소 호출 간격", "AC-1266 · AC-1269"],
    ["사용자 피드백 (feedback.py)", "dock의 위/아래 투표를 trace_id로 append-only 기록 — 같은 판정 재클릭은 1회, 뒤집힘은 별도 이벤트", "AC-1267"],
    ["TOP-10 점수카드 엄격화", "found + 모든 참조 요소 + 금지값 없음 + 맨손 거절 아님 → correct (C61)", "AC-1268"],
    ["카나리아 판단 (canary.py)", "promote/rollback/hold을 기록된 숫자 상한으로 — 어떤 지표가 어떤 수치로 깨졌는지 이름", "AC-1270 · docs/AZURE_CANARY_RUNBOOK.md"],
    ["프롬프트 충돌 린트 (prompt_lint.py)", "중복 내용·혼합 출력 계약·모순 숫자 범위를 프롬프트 id로 — 이 저장소는 3/3 규칙 clean", "AC-1271 (C83)"],
    ["벤치 게이트·성숙도·FT 결정 (bench_gate·maturity·ft_decision)", "벤치 이력 회귀 게이트 · MLOps 성숙도 자가 진단 · 파인튜닝 판정표를 이 저장소 산출물로 측정", "d6c702c (AC-1267~1271 레인)"],
    ["GitOps 배포 레인 (scripts/gitops_deploy.py)", "상태 변화마다 대장 1행 — record·deploy_failed·auto_rolled_back·promoted·rolled_back_to·drift (Azure에서 실측)", "AC-1272 · evidence/deploy_ledger.jsonl"],
    ["CI 이미지 레인 (.github/workflows/ci-image.yml)", "Azure 로그인 = OIDC 워크로드 아이덴티티 연합, 저장 시크릿 0 (azure/login@v2)", "AC-1273 · 5c7484b"],
    ["조회 차단 사유·평가 후보 피드", "라이선스 조회가 막히면 그 사유를 meta에 기록 · 해소된 에스컬레이션을 평가 후보 행으로(노트 ≥10자)", "AC-1259 · AC-1260"],
  ],
  verdict: I("이 표는 spec AC 문장과 커밋 메시지를 옮긴 것이다 — 이번 점검에서 각 구현 코드를 열어 보지는 않았다. 테스트 연결은 speclint(테스트 없는 AC 0·미등록 참조 0)가 보증한다."),
  notes: "출처: specs/bts_sbom_app_features.md AC-1259~1273, 커밋 d6c702c(AC-1267..1271)·69beae6(GitOps, AC-1272/1273)·5c7484b(ci-image 수정), 각 모듈 docstring(2026-11-28).",
});

const SEC5 = "5 · 아키텍처 설계", SEC6 = "6 · 적용 기술", SEC7 = "7 · MECE 종합";
const SRCDESIGN = "출처: 메타넷AI앱개발과정/ Claude_Code_Desktop_SDD_AI_Native_설계(41장)·Claude_보안_하네스_아키텍처(35장)·요구사항명세서(요구 123개) · 제목·요지만 발췌";
// ---- AI native SDLC · harness · guardrails, from the course design deliverables. Each slide pairs the source's
// analogy with where the same pattern already lives in BTS-SBOM (the product side is tagged measured/inference/gap).
const SD = "출처: SDD 설계 덱 ";
S.push({
  id: "sdlc", kind: "flow",
  steps: [
    { t: "① 원문 모으기", d: "00 sources\n공식 문서 · 관찰 · 강의\n근거 등급 D·R·L·O·I\n게이트: 질문·답변 10쌍" },
    { t: "② 명세 쓰기", d: "01 planning\n요구 123개를 시험 가능한\nEARS 문장으로 (수치 필수)\n게이트: EARS·ADR·NFR lint" },
    { t: "③ 쪼개고 만들기", d: "02 plan → 03 build\n겹치지 않게 작업을 쪼개고\nAI·서브에이전트에 위임\n게이트: AC 시험 (proof)" },
    { t: "④ 증명하기", d: "04 verify\n검증 보고 · 추적성 매트릭스\n'맞다'를 기계가 판정\n게이트: 회귀 게이트" },
    { t: "⑤ 운영하기", d: "05 operate\n런북 · 드리프트 감시\ndrift는 버그가 아니라\n명세를 고칠 신호" },
  ],
  factsTitle: "사람 · AI · 기계의 역할 분담 — 그리고 BTS-SBOM에서는",
  facts: [
    ["AI · 사람 · 기계", "AI는 초안과 반복(구현 금지, 질문 10개로 빈칸 찾기) · 사람은 답변과 승인(모르면 '가정'으로 표시) · 기계 게이트는 판정(질문·답변 10쌍, lint, AC 시험, 회귀 게이트)"],
    ["정본을 지키는 4가지 규칙", "Placement(정본은 sdd/ 안에만, 사본 금지) · Final-Only(날짜·버전 사본 대신 덮어쓰기) · INDEX 진입점 · drift = 명세 갱신 신호"],
    ["BTS-SBOM · 명세 → 시험 → 코드", M("수용 기준 677개 전부 EARS 패턴 + shall + 숫자 · speclint로 명세-테스트 양방향 추적(테스트 없는 AC 0 · 미등록 참조 0)")],
    ["BTS-SBOM · 사람은 승인, 기계는 판정", M("패치는 승인 토큰(=계획 다이제스트)이 맞아야 적용 · 게이트는 pytest · speclint · doclint · 도그푸드 · 야간 드리프트가 맡는다")],
  ],
  verdict: I("AI가 코드를 쓰는 시대 — 병목은 '생성'이 아니라 '검증'으로 옮겨 갔다. 두 산출물이 같은 결론이다."),
  notes: SD + "7~12·36~41장. BTS-SBOM 쪽: specs/bts_sbom_app_features.md(AC 677)·python -m bts_sbom_app.speclint·actions.py·.github/workflows/nightly-drift.yml (2026-11-28).",
});
S.push({
  id: "guard", kind: "pipeline",
  steps: [
    { t: "도구 호출", d: "에이전트가 어떤\n도구를 쓰려 함" },
    { t: "① 금지 규칙", d: "deny 목록 — 먼저\n걸린 것이 결과" },
    { t: "② 훅 검사", d: "종료 코드 2 = 차단\n사람이 쓴 스크립트" },
    { t: "③ 권한 모드", d: "Plan · Manual ·\nAccept edits · Auto" },
    { t: "④ 사람 승인", d: "필요할 때만 묻는다\n되돌릴 수 없는 일" },
    { t: "⑤ 분류기", d: "외부 웹 쓰기만\n기계가 분류" },
    { t: "실행", d: "한 곳이라도 막히면\n실행되지 않는다" },
  ],
  lanes: [
    { title: "검문은 공항 검색대처럼 · 권한 모드는 자율성 다이얼", tone: "info", lines: [
      "검사 순서는 금지 → 확인 → 허용, 막히면 거부. allow 목록은 덮어쓰지 않고 더해진다. deny는 어느 층이든 allow를 이긴다.",
      "권한 모드 5: Plan(읽기·계획만, 파일 변경 0건) · Manual(매번 묻기, 기본값) · Accept edits(작업 폴더 편집 자동) · Auto(분류기가 판단) · Bypass(묻지 않음, 격리 환경만). 왼쪽일수록 안전하고 느리다.",
    ] },
    { title: "강제 5층 — 프롬프트는 안내, 코드는 강제", tone: "info", lines: [
      "① 프롬프트(가장 쌈 · 무시될 수 있음) → ② 실행 전 검증(스키마 · 권한 · 금지 규칙 · 훅: 실행 자체를 막음) → ③ 실행 후 검증(출력 · 업무 규칙 · 인용 확인: 잘못된 결과를 거름)",
      "→ ④ 런타임 감시(예산 · 공회전 · 범위 이탈: 폭주를 끊음) → ⑤ 사람 이관(되돌릴 수 없는 고위험 · 재시도 소진). 코드로 강제할 곳 = 금전 한도 · 개인정보 · 데이터 삭제 · 외부 배포",
    ] },
    { title: "BTS-SBOM 대응 — 같은 층 구조", tone: "ok", lines: [
      M("② 실행 전: 소스 경계 ALLOWED_ROOTS · 승인 토큰 없으면 변경 0건 → ③ 실행 후: 재스캔 회귀 시 자동 복구 · 인용 검증(이번 질문의 문서에 없는 출처는 거절)"),
      M("④ 런타임: 소켓 128 · 잡 1 · 채팅 4 · 실패 20회/분 → 429 · 회로차단기 3회→60초 · LLM 일일 예산 80회 → ⑤ 사람 이관: 승인 토큰 · 에스컬레이션 → 감사: approvals.jsonl"),
    ] },
  ],
  verdict: I("프롬프트는 안내이고 코드는 강제다 — 실패 비용이 큰 곳일수록 바깥(코드) 층에서 막는다. 어느 한 층도 혼자서는 부족하다."),
  notes: SD + "25·27~29장, 보안 하네스 덱 13·17장. BTS-SBOM 한도는 server.py·access.py·workspace.py·actions.py·resilience.py·llm.py 코드 실측(2026-11-28).",
});
S.push({
  id: "harness6", kind: "table", fs: 9,
  cols: [{ t: "부품", w: 1.9 }, { t: "역할 (설계 산출물)", w: 3.6 }, { t: "성격", w: 1.3 }, { t: "BTS-SBOM에서는", w: 5.2 }],
  rows: [
    ["H1 거버넌스 파일", "CLAUDE.md · rules/ — 모델이 읽는 팀 규칙", "권유", I("CLAUDE.md 없음 — 안내는 readme.txt·RUNBOOK이 맡는다(가이드 층이 약함 → 보강 후보)")],
    ["H2 트리거 · 스킬", "skills/ · /smoke · /grounded-answer — 반복 작업의 순서 고정", "절차 고정", M("슬래시 명령 /help · /ir · /report — 자주 하는 절차를 한 단어로 고정")],
    ["H3 역할 에이전트", "agents/ 11종 — 역할마다 도구 허용목록", "역할 분담", M("도구 3계층(읽기 · 승인 필요 · 쓰기) — 역할별 에이전트는 아직 없음(단일 에이전트)")],
    ["H4 경계 루프", "settings.json 권한 · 훅 — 허용 · 확인 · 금지", "결정적 강제", M("도구 호출 최대 4회 · 속도 제한 · 승인 토큰 = 계획 다이제스트(틀리면 변경 0건)")],
    ["H5 외부 연결 · 격리", ".mcp.json · 샌드박스 · 관리 정책 — 닿는 범위 통제", "범위 통제", M("소스 경계 ALLOWED_ROOTS · SSRF 가드 · 호스트 허용목록 · 격리 워크카피 · 비루트 UID 10001")],
    ["H6 증거 규약", "contract · proof · lint · eval — '됐다'의 증거", "기계 판정", M("evidence/*.json · approvals.jsonl · speclint · pytest · 도그푸드 — 주장마다 증거 파일")],
  ],
  facts: [
    ["설정은 5층 — 위가 이긴다", "관리형(Managed) → CLI --settings → settings.local.json(개인 · 이 프로젝트) → settings.json(팀 공유) → ~/.claude/settings.json(개인 · 전체). 회사 규칙이 팀 규칙보다, 팀 규칙이 개인 취향보다 위"],
    ["로컬 vs 리모트 제어면", "PC(로컬)는 즉시 · 오프라인에서도 강제하지만 바꿀 수 있고, 서버(리모트)는 바꿀 수 없지만 로그인 후에만 강제한다 — 약점이 서로 반대라 함께 쓴다. BTS-SBOM은 환경변수 한 층(운영자가 바꿈) — 계층 구조는 아님"],
  ],
  verdict: I("왼쪽(H1~H3)은 잘하게 돕는 가이드, 오른쪽(H4~H6)은 넘지 못하게 하는 강제 — BTS-SBOM은 오른쪽이 강하고 왼쪽(H1)이 비어 있다."),
  notes: SD + "24~25장, 보안 하네스 덱 5~7·13장. BTS-SBOM 실측: 저장소 루트에 CLAUDE.md·AGENTS.md 없음(ls), server.py·access.py·net.py·Dockerfile.bts-sbom-app (2026-11-28).",
});
S.push({
  id: "ladder", kind: "table", fs: 9,
  cols: [{ t: "단", w: 0.6 }, { t: "이름", w: 2.7 }, { t: "언제 쓰나", w: 5.3 }, { t: "BTS-SBOM에서는", w: 3.4 }],
  rows: [
    ["L0", "단일 에이전트", "기본 · 대부분의 일 — 비용 1×", M("여기에 있음 — 도구 호출 루프 최대 4회")],
    ["L1", "서브에이전트", "탐색 · 리뷰를 격리된 기억 공간에 맡김 — ~4×", "없음"],
    ["L2", "포크 · 백그라운드", "같은 맥락을 이어받아 다른 시도를 병렬로", "없음"],
    ["L3", "Workflow 스크립트", "사용자 요청으로 대규모 팬아웃", I("유사: 배치 재구현 스크립트(64패키지) — 에이전트 병렬은 아님")],
    ["L4", "에이전트 팀", "서로 토론 · 실험 (기능)", "없음"],
    ["L5", "세션 간 브랜치 · PR", "브랜치 · PR 단위로 일", "없음"],
    ["L6", "원격 · 예약", "앱을 닫아도 계속", I("유사: 야간 드리프트 · 백그라운드 잡 — 예약 실행이지 원격 에이전트는 아님")],
    ["L7", "외부 오케스트레이터", "SDK · CI · A2A 브리지", I("MCP 서버(stdio)로 외부가 도구를 호출 — 오케스트레이터는 아님")],
  ],
  facts: [
    ["한도는 런타임이 강제 · 비용은 1× · ~4× · ~15×", "중첩 깊이 3 · 동시 실행 20 · 예산 상한 maxBudgetUsd — 에이전트를 늘릴수록 능력과 비용이 함께 커지므로 가장 낮은 단에서 시작해 깨지는 곳만 올린다(증분 복잡성)"],
    ["위임 봉투 4요소 · 도구 규격 4가지", "봉투: ① 작업(무엇을 · 왜) ② 컨텍스트(경로 · 이미 아는 것) ③ 출력 형식(표 · 500자 이내) ④ 제약(읽기 전용 · 추측 금지) — 결과 1건만 돌아온다. 규격: MCP(에이전트→도구) · Messages API(런타임→모델) · SDK·claude -p(외부→Claude Code) · A2A(에이전트↔에이전트, 브리지 필요)"],
  ],
  verdict: I("BTS-SBOM은 사다리의 L0에 머물며 '검증'에 투자했다 — 에이전트를 늘리기 전에 답을 검사하는 쪽이다."),
  notes: SD + "30~32장. BTS-SBOM 쪽: chat.py(MAX_CALLS 4)·batch_reimpl.py·.github/workflows/nightly-drift.yml·mcp_server.py (2026-11-28).",
});
S.push({
  id: "halluc", kind: "table", fs: 8.5,
  cols: [{ t: "곳", w: 0.9 }, { t: "원인", w: 2.1 }, { t: "증상", w: 1.9 }, { t: "처방 (설계 산출물)", w: 3.2 }, { t: "BTS-SBOM 대응", w: 4.3 }],
  rows: [
    ["1 지식", "모르는 사내 · 최신 지식", "그럴듯한 지어낸 값", "RAG · 문서 MCP · 웹으로 근거 주입", M("Book KB 15권 9,179 청크 · 로컬 OSV DB NL2SQL — 근거를 주입")],
    ["2 검색", "필요한 근거를 못 찾음", "부분 정답 · 다른 문서 내용", "하이브리드 검색 · 재순위 · 그래프 확장", M("BM25+TF-IDF → RRF 재순위 · 골든 Recall@5 1.0") + " · GraphRAG는 없음"],
    ["3 조립", "근거가 잘리거나 섞임", "출처 없는 문장", "근거마다 ID · 경로 유지, 인용 강제", M("인용 검증 — 이번 질문의 문서에 없는 출처는 거절")],
    ["4 생성", "근거를 무시하거나 과장", "근거와 모순", "별도 검증 에이전트 · 근거성 점수 · 기권", M("4계층 검증(스키마 · 규칙 · 의미 · 교차필드) 실패 시 결정적 강등") + " · 별도 검증 에이전트는 없음"],
    ["5 외부 입력", "문서 · 웹 속 숨은 지시", "목표 이탈 · 정보 유출", "결과 = 데이터 원칙 · 읽기 전용 검색", M("인젝션 가드(홀드아웃 재현율 1.0) · 도구 출력의 지시문은 인용하되 명령으로 취급하지 않음")],
  ],
  facts: [
    ["검색 길 — 라우터 5유형 (ADR-007)", "① 코드(에이전틱 검색, 벡터 없음) ② 문서 사실(하이브리드 RAG → 상위 5) ③ 관계 · 영향(GraphRAG) ④ 다단계 조사(Agentic RAG, 3회 이내) ⑤ 최신 외부 문서(MCP · 웹) — 가장 싼 길부터. BTS-SBOM은 규칙 + LLM JSON 플랜으로 도구를 고른다(5유형 분류까지는 아님)"],
    ["검증자 — 다른 AI가 확인한다", "① 주장 쪼개기 ② 근거와 대조 ③ 판정(지지 · 미지지 · 모순) ④ 근거성 점수 = 지지 ÷ 전체, 0.9 이상만 확정 → 아니오면 다시 검색(최대 3회) → 끝내 없으면 '근거 없음 + 확인 방법'으로 기권. 근거 계약: 사실 주장마다 출처 1개 이상 · 숫자는 근거에 있는 것만 · 자료 속 지시는 따르지 않음"],
  ],
  verdict: I("환각은 한 곳의 잘못이 아니라 다섯 길의 잘못이다 — 어디서 틀렸는지에 따라 처방이 다르다."),
  notes: SD + "33~35장. BTS-SBOM 쪽: rag.py(BM25+TF-IDF→RRF)·conversation.py 인용 검증·chat.py 4계층 검증·pii_guard.py·evals/injection (이전 세션 실측).",
});
S.push({
  id: "dpatterns", kind: "table", fs: 8.5,
  cols: [{ t: "#", w: 0.4 }, { t: "설계 패턴", w: 2.6 }, { t: "쉬운 설명", w: 3.9 }, { t: "적용 위치 · 근거", w: 2.5 }, { t: "BTS-SBOM에서는", w: 4.6 }],
  rows: [
    ["1", "로컬 우선 · 동일 엔진", "엔진 하나를 여러 장소에서 실행", "Agent Runtime (ADR-001)", M("같은 코드, 네 곳: 로컬 서버 · Azure 컨테이너 · CLI 39명령 · MCP 서버")],
    ["2", "작업 공간 격리", "세션마다 별도 작업 폴더(git worktree)", "Session Manager (ADR-002)", M("격리 작업 복사본 — 원본 트리 해시 불변(AC-1) · 소스 경계")],
    ["3", "자격증명 브로커(프록시)", "비밀은 밖에 두고 통로에서 주입", "GitHub · 보안 프록시 (ADR-003)", M("이미지 풀 = 시스템 할당 MI · 비밀번호 0 · 시크릿은 플랫폼에")],
    ["4", "심층 방어(계층적 강제)", "여러 겹의 검문 — 한 겹이 뚫려도 다음이 막음", "Permission Engine (ADR-004)", M("토큰 게이트 → 속도 제한 → 소스 경계 → 승인 토큰 → 회귀 복구")],
    ["5", "설정 계층 · 구성 공유", "같은 설정 파일, 위 계층이 아래를 덮음", "Extension Host (ADR-005)", I("환경변수 BTS_SBOM_* + 코드 기본값 — 단일 층(위 · 아래 없음)")],
    ["6", "게이트웨이", "바깥 호출을 한 통로로 모아 통제", "추론 API · 커넥터 프록시 (D7)", M("net.py SSRF 가드 · 호스트 허용목록 — 바깥 호출이 한 통로")],
    ["7", "허브앤스포크 오케스트레이터", "지휘자 1 + 전문가 N, 결과만 모음", "Subagent Runtime (ADR-006)", "없음 — 단일 에이전트(L0)"],
    ["8", "라우터(전략 선택)", "질문 유형마다 다른 검색 경로", "Query Router (ADR-007)", M("규칙 + LLM JSON 플랜 라우터 — 도구 호출 최대 4회")],
    ["9", "확장 포인트(플러그인)", "표준 규격으로 기능을 꽂음", "MCP · 스킬 · 플러그인 (D10 · D18)", M("MCP 서버(stdio) · CLI 확장 · A2UI 카드 19/27")],
    ["10", "이벤트 주입(옵저버)", "바깥 변화가 생기면 에이전트를 깨움", "PR 감시 · CI 이벤트 (관찰 O)", M("야간 드리프트(예약) · SSE 이벤트 · 깃 푸시 → CI 이미지 레인")],
  ],
  facts: [
    ["읽는 법", "각 패턴은 ADR · 근거 문서로 이어진다(설계 산출물: ADR 7건 · 4섹션). BTS-SBOM 대응 열은 이 덱의 다른 장에서 실측한 값이다 — 없는 것은 '없음'으로 적었다"],
  ],
  verdict: I("10개 중 8개는 BTS-SBOM에 같은 역할의 것이 있다 — 이름은 달라도 구조는 같다. 없는 2개(허브앤스포크 · 다층 설정)는 단일 에이전트 · 단일 레플리카라는 선택의 결과다."),
  notes: SD + "18~21장. BTS-SBOM 쪽: Dockerfile.bts-sbom-app·cli.py(39명령)·mcp_server.py·workspace.py·net.py·AZURE_IDENTITY.md (2026-11-28).",
});
S.push({
  id: "devpat", kind: "table", fs: 8.5,
  cols: [{ t: "#", w: 0.4 }, { t: "개발 패턴", w: 2.5 }, { t: "쉬운 설명", w: 3.7 }, { t: "BTS-SBOM에서는", w: 5.4 }],
  rows: [
    ["1", "Spec-anchored SDD", "명세를 먼저 갱신하고 코드가 따라감", M("수용 기준 677개 · 정본 specs/ · speclint 양방향 추적")],
    ["2", "EARS 수용기준", "5패턴 + shall + 수치 = 시험 가능", M("모든 AC에 숫자 — 모호어는 린트에서 걸림")],
    ["3", "인터뷰 패턴", "구현 전에 AI가 질문 10개로 빈칸 찾기", I("에스컬레이션 · 핸드오프로 일부 — '질문 10개' 절차는 없음")],
    ["4", "ADR", "결정 · 근거 · 기각 대안 · 결과 4섹션", M("docs/adr — 결정마다 대안 · 근거 기록")],
    ["5", "Plan mode 우선", "큰 설계는 읽기 전용 계획부터", I("설계는 계획부터 — 실행 기록은 덱 밖(작업 로그)")],
    ["6", "증분 복잡성", "가장 단순한 구조로 시작, 깨지는 곳만 올림", M("단일 레플리카 · 큐 없음 · 파일 저장소 — 트리거 기반 로드맵")],
    ["7", "계약 우선", "contract.json — build · proof · deploy · verify", M("BtsOss 계약(AC-533) — 단계별 계약 파일까지는 아님")],
    ["8", "proof + verify_dev", "로직 시험과 배포 환경 확인 둘 다", M("pytest + scripts/smoke_deployed.py(healthz · readyz · 401/200)")],
    ["9", "골든셋 회귀", "정답 세트로 매 변경마다 품질 비교", M("loop.py 골든셋 게이트 · evalrag · TOP-10 품질 게이트")],
    ["10", "Docs · Diagrams as Code", "Markdown + Mermaid로 리뷰 · 버전 관리", M("docs/*.md · diagrams.py 37종 + mermaid lint")],
    ["11", "Final-Only", "사본 대신 덮어쓰기 · 생성물은 재생성", M("덱 2종이 모델 1개에서 재생성(빌드 스크립트) · 사본 없음")],
    ["12", "추적성 자동 생성", "요구 ↔ 설계 매트릭스를 스크립트로", M("speclint: 테스트 docstring ↔ AC · 표면 역추적")],
  ],
  facts: [
    ["게이트 — 기계가 판정 (설계 산출물 8개)", "EARS lint(요구 123개 · 5패턴) · ADR lint(결정 7건) · NFR lint(19개 수치화) · 추적성(고아 0 · 미정의 참조 0) · 도식 구조(Mermaid 문법) · 도식 렌더링(실제 브라우저) · 링크(깨진 링크 0) · 배치 규칙(사본 0) — 처음 FAIL도 숨기지 않고 기록했다"],
    ["추적성 — ID가 모든 문서를 꿰는 실", "원문 → 요구 → 구성요소 → 인터페이스 → 시퀀스 → 통제 · 결정 → 시험: 요구의 100%가 설계 문서에, 96.7%가 구성요소에 할당 — 거꾸로도 따라갈 수 있다"],
  ],
  verdict: I("12개 중 10개는 BTS-SBOM에 이미 있다 — 빠진 2개(인터뷰 10문 · 계약 파일)는 다음 보강 후보다."),
  notes: SD + "22·37~38장. BTS-SBOM 쪽: specs/·docs/adr·loop.py·scripts/smoke_deployed.py·diagrams.py·speclint.py·usertest/build_azure_arch_deck.js (2026-11-28).",
});
S.push({
  id: "sec9", kind: "table", fs: 8.5,
  cols: [{ t: "계층", w: 0.6 }, { t: "이름", w: 1.8 }, { t: "건물 비유", w: 1.5 }, { t: "대표 항목", w: 3.1 }, { t: "강제", w: 0.9 }, { t: "BTS-SBOM 대응", w: 4.1 }],
  rows: [
    ["H0", "거버넌스 · 계약", "건물 사용 계약", "요금제 · ZDR · BAA · 보존 기간", "리모트", I("Azure 구독 · LLM 일일 예산 80회 — 계약 문서는 없음")],
    ["H1", "신원 · 인증", "출입증", "SSO · 도메인 검증 · SCIM · 조직 고정", "둘 다", M("액세스 토큰 게이트 1개 — Easy Auth 미설정")],
    ["H2", "인가 · 역할", "층별 권한", "Owner · Admin · Member · 좌석", "리모트", M("역할 구분 없음 — 토큰 하나가 전부(한계)")],
    ["H3", "정책 배포", "규정이 내려옴", "server-managed · MDM · managed 파일", "둘 다", M("환경변수 15개 · 배포 yaml — 라이브가 진실")],
    ["H4", "실행 통제", "방마다 잠금", "모드 · deny→ask→allow · 훅 · 분류기", "로컬", M("소스 경계 · 승인 토큰 · 속도 제한")],
    ["H5", "격리", "출입 통제된 작업실", "샌드박스 · dev container · VM · 프록시", "둘 다", M("격리 워크카피 · 비루트 UID 10001 컨테이너")],
    ["H6", "데이터", "문서 보관함", "학습 정책 · 보존 · 텔레메트리", "둘 다", M("evidence 영속 · PII 마스킹 · 백업 0(갭)")],
    ["H7", "확장", "외부 업체 출입", "managed MCP · 마켓플레이스 · .mcpb", "둘 다", M("MCP 서버 · A2UI 카드 — 허용목록 없음(갭)")],
    ["H8", "감사", "CCTV · 출입 기록", "OTel · Compliance API · 지출 한도", "둘 다", M("approvals.jsonl · 에스컬레이션 로그 · LA 로그")],
  ],
  facts: [
    ["어디서 강제하나 — 로컬 vs 리모트", "같은 9계층을 두 곳에서 나눠 지킨다: 로컬(PC)은 매 실행 · MDM 30분 재확인으로 즉시 강제하지만 로컬 관리자가 고칠 수 있고, 리모트(서버)는 시작 시 1회 + 1시간마다 폴링, 사용자는 못 바꾼다 — 약점이 서로 반대라 함께 쓴다. 규칙은 위에서 내려오고(H0→H5), 기록은 아래에서 올라간다(H8이 H3을 고친다)"],
    ["정책은 코드처럼", "병합은 위가 이긴다: managed(안쪽 4단) → CLI 인수 → local → project → user. 단 deny는 어느 층이든 allow를 이긴다 · 기준선 B1 표준 · B2 강화 · B3 규제 · 링 배포(오탐 한 번에 전사가 멈추지 않게) · 검증 명세 HV-01~20 · 잔여 위험은 숨기지 않는다"],
  ],
  verdict: I("BTS-SBOM은 9계층 중 H1·H3~H8의 역할을 갖추고, H0(계약)·H2(역할)가 비어 있다 — 둘 다 '사용자가 한 명'인 현재 규모의 결과다."),
  notes: "출처: 보안 하네스 덱 2·5~7·13·30~34장. BTS-SBOM 대응은 이 덱의 실측값(access.py·AZURE_IDENTITY.md·az containerapp show·actions.py, 2026-11-28).",
});
S.push({
  id: "journey", kind: "pipeline",
  steps: [
    { t: "① 창구", d: "'이 버그 고쳐줘'\n한 문장을 입력" },
    { t: "② 셸 · 세션", d: "세션과 워크트리를\n고름" },
    { t: "③ 엔진", d: "규칙과 대화로\n문맥을 조립" },
    { t: "④ 두뇌", d: "추론 API가\n'먼저 파일을 읽자'" },
    { t: "⑤ 관문", d: "deny → 훅 →\n권한 모드 · 승인" },
    { t: "⑥ 손", d: "도구가 워크트리\n파일을 읽고 고침" },
    { t: "⑦ 결과", d: "diff · 할 일 ·\n다음 단계를 보고" },
  ],
  lanes: [
    { title: "위에서 아래로 — 건물의 층처럼", tone: "info", lines: [
      "위층(사람 · 화면)은 아래층(엔진 · 모델 · 인프라)에 일을 시키고, 아래층은 위층을 몰라도 된다.",
      "요청은 L1 창구 → L2 셸 · 세션 → L3 엔진 → L5 두뇌 → L3 관문 → L4 도구 → L6 파일로 내려가고, 결과는 다시 L1으로 올라온다.",
    ] },
    { title: "엔진 하나, 창구 여럿", tone: "info", lines: [
      "Claude Code는 '엔진(하네스)' 하나 — 터미널 · 데스크톱 · IDE · 웹 · 모바일 · Slack · CI는 그 엔진을 부르는 창구다.",
      "두뇌는 모델 공급자(Anthropic API · Bedrock · Foundry · 게이트웨이) — 엔진과 두뇌가 분리돼 바꿔 낄 수 있다.",
    ] },
    { title: "BTS-SBOM에서 같은 길", tone: "ok", lines: [
      M("① dock에 '스캔 결과가 비어 있으면 안전?' → ② /api/chat/stream 라우팅 → ③ 챗 봇이 프로젝트 기록 · 부분 스캔 공시로 문맥 조립 → ④ gpt-5-mini가 tool_use(top_vulns) 결정"),
      M("⑤ 관문: 토큰 게이트 · 호출자 30회/분 · 동시 4 → ⑥ 도구가 evidence · OSV DB를 읽음 → ⑦ SSE 이벤트 · 인용 칩 · 답변으로 보고"),
    ] },
  ],
  verdict: I("에이전트를 처음 보는 사람은 이 한 장만 기억해도 된다 — 문장이 창구 → 엔진 → 두뇌 → 관문 → 도구 → 파일로 내려갔다가 보고로 돌아온다."),
  notes: "출처: 플랫폼 에이전트 덱 2·6~7장. BTS-SBOM 쪽은 과제 덱 24~25장의 E2E 실측(도구 호출 → 결과 5줄 → 답변, 인젝션 질문에 정직한 '아니요').",
});
S.push({
  id: "layers7", kind: "table", fs: 9,
  cols: [{ t: "층", w: 0.6 }, { t: "이름", w: 2.1 }, { t: "쉬운 질문", w: 3.0 }, { t: "구성 요소", w: 3.4 }, { t: "BTS-SBOM에서는", w: 3.7 }],
  rows: [
    ["L0", "사람 · 조직", "누가 시키고 누가 정책을 정하나", "개발자 · 지식 노동자 · 조직 관리자", M("사용자 · 운영자(az CLI) — 역할 구분 없음")],
    ["L1", "표면(창구)", "어디서 대화하나", "Desktop · CLI · IDE · Web · Mobile · Slack · CI", M("웹 콘솔 5섹션 + dock · CLI 39명령 · MCP 서버")],
    ["L2", "앱 셸 · 제어면", "창 · 세션 · 알림을 누가 관리하나", "셸 · 세션 · 제어면 · Git · 미리보기 · 정책", M("bts_console.js · server.py 라우터(/api 38) · 잡 상태")],
    ["L3", "에이전트 런타임", "생각 → 행동 → 확인을 어떻게 반복하나", "루프 · 권한 · 훅 · 확장 · 위임", M("chat.py 루프(최대 4회) · 토큰 게이트 · 4계층 검증 · 강등")],
    ["L4", "확장 · 도구", "무엇으로 일하나", "내장 도구 ~46 · MCP · 커넥터 · 스킬 · 플러그인 · SDK", M("도구 3계층(읽기 · 승인 필요 · 쓰기) · MCP · A2UI 19/27")],
    ["L5", "모델 · 플랫폼", "두뇌와 출입문은 어디 있나", "추론 · 인증 · 세션 · VM · 제3자 공급자", M("Azure OpenAI gpt-5-mini(별도 RG) · 시크릿 5종 · ACA")],
    ["L6", "인프라 · 외부", "결과가 실제로 어디 남나", "내 PC · 파일 · GitHub · 웹 · 사내 시스템", M("Azure Files evidence · ACR · OSV · deps.dev · Git 호스트")],
  ],
  facts: [
    ["근거 등급 — 무엇이 확인된 사실인가", "D 공식 문서 · O 직접 관찰 · I 추론(가정 번호로 추적) · X 제3자 — 내부 구현은 공개되지 않았으므로 구분해 표시하고, 공개 문서에 없는 것은 쓰지 않았다. BTS-SBOM 덱도 같은 규칙(측정 · 추론 · 갭)을 쓴다"],
    ["같은 엔진, 네 곳에서 실행 (ADR-001)", "Local(내 PC 프로젝트 폴더) · Worktree(세션마다 별도 작업 폴더 · 브랜치) · SSH(끊겨도 최대 30일) · Cloud(새 VM, 앱을 닫아도 계속) — 앱은 그대로, 엔진이 '어디서' 도는지만 바뀐다"],
  ],
  verdict: I("BTS-SBOM을 같은 7층으로 읽으면 빈 곳이 보인다 — L0 역할 구분, L1 사용자 인증, L3 권한 · 훅의 계층 구조. To-Be 구성도가 그 빈 곳을 채운다."),
  notes: "출처: 플랫폼 에이전트 덱 2·5~8·30장. BTS-SBOM 대응은 이 덱의 실측값(코드 grep · az CLI, 2026-11-28).",
});
const SRC = "실측 2026-11-28 · az CLI·REST·Azure Monitor·코드 · 동적 버전: docs/AZURE_OPERATIONS_OVERVIEW.html";
const PLAN = [
  { id: "ctx", action: "replace", target: "아키텍처 ④", sec: SEC5, title: "아키텍처 ④: Azure 운영 아키텍처 전체 구성도\n(공식 Azure 아이콘 · 화살표마다 프로토콜·보호 수단)", sources: SRC },
  { id: "inv_state", action: "replace", target: "아키텍처 ⑤", sec: SEC5, title: "아키텍처 ⑤: 운영 리소스·상태 — 있고·없고·살아남는 것", sources: SRC },
  { id: "cred", action: "insert_after", target: "아키텍처 ⑤", sec: SEC5, title: "아키텍처 ⑥: 자격 증명·비밀·네트워크 경계 — 한 문과 열린 창", sources: SRC },
  { id: "modules", action: "insert_after", target: "아키텍처 ⑥", sec: SEC5, title: "아키텍처 ⑦: 모듈 지도 — {mods}개 모듈을 5개 계층으로", sources: "git ls-files bts_sbom_app/*.py = {mods}개(__init__ 포함) · 빌드가 계층 구분과 전수 대조 · 계층 구분은 아키텍트 판단" },
  { id: "adr", action: "insert_after", target: "아키텍처 ⑦", sec: SEC5, title: "아키텍처 ⑧: 핵심 설계 판단 12건 — 채택·버린 대안·되돌리는 조건", sources: SRC },
  { id: "coldcap", action: "insert_after", target: "⑯ Azure 운영", sec: SEC6, title: "⑯-1 런타임 뷰: 콜드 스타트 35.4초와 자원의 여유", sources: "curl 타이밍 · ContainerAppSystemLogs · Azure Monitor 앱 메트릭(72h) · 2026-11-28" },
  { id: "slo", action: "insert_before", target: "성과와 한계", sec: SEC7, title: "SLO 제안 — 목표는 제안값, 현재 값은 측정, 빈 칸은 갭", sources: SRC },
  { id: "fmea", action: "insert_before", target: "성과와 한계", sec: SEC7, title: "장애 모드 분석(FMEA) 10건 — 탐지는 프로브 하나", sources: SRC },
  { id: "sr", action: "insert_before", target: "성과와 한계", sec: SEC7, title: "위협 모델(STRIDE) 6건 · 운영 리스크 레지스터 10건", sources: SRC },
  { id: "tobe", action: "insert_after", target: "성과와 한계", sec: SEC7, title: "목표 아키텍처(To-Be) — 바뀌는 것은 상태의 위치다", sources: "제안안(존재하지 않는 구성요소) · Azure 아키텍처 센터 지침 · 비용·난이도 미평가 · 공식 Azure 아이콘" },
  { id: "lanes", action: "insert_after", target: "⑱ 콘솔 구조", sec: SEC6, title: "⑲ 병행 레인: AI 영향성 평가 · 백로그 잔여 · GitOps 배포\n(AC-1259~1273 — 이 덱의 마지막 갱신 분)", sources: "specs AC-1259~1273 · 커밋 d6c702c·69beae6·5c7484b · 역할 열은 AC 문장 요약(코드는 이번 점검에서 열지 않음) · 2026-11-28" },
  { id: "sdlc", action: "replace", target: "⑳ AI 네이티브 SDLC", sec: SEC6, title: "⑳ AI 네이티브 SDLC — 명세로 합의하고, 하네스로 다루고, 게이트로 증명한다", sources: "출처: SDD 설계 덱 7~12·36~41장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "guard", action: "replace", target: "㉑ 가드레일", sec: SEC6, title: "㉑ 가드레일 — 행동 하나의 검문 흐름: 프롬프트는 안내, 코드는 강제", sources: "출처: SDD 설계 덱 25·27~29장 · 보안 하네스 덱 13·17장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "harness6", action: "replace", target: "㉒ 에이전트를 안전하게", sec: SEC6, title: "㉒ 하네스 = 모델 + 6가지 부품\n왼쪽은 잘하게 돕고, 오른쪽은 넘지 못하게 한다", sources: "출처: SDD 설계 덱 24~25장 · 보안 하네스 덱 5~7·13장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "ladder", action: "insert_after", target: "㉒ 하네스 = 모델", sec: SEC6, title: "㉓ 멀티에이전트 — 8단 사다리 · 위임 봉투 4요소 · 도구 규격 4가지", sources: "출처: SDD 설계 덱 30~32장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "halluc", action: "insert_after", target: "㉓ 멀티에이전트", sec: SEC6, title: "㉔ 환각은 어디서 생기나 — 5곳의 원인 · 증상 · 처방", sources: "출처: SDD 설계 덱 33~35장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "dpatterns", action: "insert_after", target: "㉔ 환각은", sec: SEC6, title: "㉕ 설계 패턴 10가지 — 구조를 어떻게 나누고 연결했나", sources: "출처: SDD 설계 덱 18~21장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "devpat", action: "insert_after", target: "㉕ 설계 패턴", sec: SEC6, title: "㉖ 개발 패턴 12가지 — 어떻게 만들고 확인했나", sources: "출처: SDD 설계 덱 22·37~38장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "sec9", action: "insert_after", target: "㉖ 개발 패턴", sec: SEC6, title: "㉗ 보안 하네스 9계층 H0~H8 — 건물 보안처럼 9겹", sources: "출처: 보안 하네스 덱 2·5~7·13·30~34장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "journey", action: "insert_after", target: "㉗ 보안 하네스", sec: SEC6, title: "㉘ 요청 하나가 내려가는 길\n'이 버그 고쳐줘'가 파일까지 내려갔다가 돌아온다", sources: "출처: 플랫폼 에이전트 덱 2·6~7장 · BTS-SBOM 대응은 과제 덱 24~25장의 E2E 실측" },
  { id: "layers7", action: "insert_after", target: "㉘ 요청 하나가", sec: SEC6, title: "㉙ 계층 아키텍처 L0~L6 — 엔진 하나, 창구 여럿", sources: "출처: 플랫폼 에이전트 덱 2·5~8·30장 · BTS-SBOM 대응은 이 덱의 실측값 · 2026-11-28" },
  { id: "retire", action: "remove", target: "㉓ 설계·개발 패턴과 보안 하네스" },
];

module.exports = { S, PLAN, LAYERS: A.LAYERS, M, I, G };
