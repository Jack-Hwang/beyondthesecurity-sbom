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
// ---- AI native SDLC · harness · guardrails, explained for a first-time reader and mapped onto BTS-SBOM ----
S.push({
  id: "sdlc", kind: "flow",
  steps: [
    { t: "① 원문 → 요구", d: "공식 문서·관찰·강의를 모은다\n흐릿한 요구('안전하고 빠르게')는\nAI의 추측을 부른다\n요구 123개 → 시험 가능한 문장" },
    { t: "② 명세가 먼저", d: "EARS: 패턴 키워드 + shall + 측정 수치\n수치가 없으면 아직 요구가 아니다\n한 문장이 곧 시험 1개" },
    { t: "③ AI 초안 · 사람 결정", d: "AI는 초안과 반복\n사람은 결정과 승인\n기계 게이트는 판정\n명세를 갱신하고 코드가 따라간다" },
    { t: "④ 하네스로 다루고", d: "에이전트 = 모델 + 하네스\n모델이 '맞게' 일하도록\n둘러싼 장치(가드레일·권한·감시)" },
    { t: "⑤ 게이트로 증명", d: "정본 게이트 8개 · 회귀 게이트\n'맞다'를 사람 느낌이 아니라\n기계 판정으로 — 실패도 기록" },
  ],
  factsTitle: "같은 방식, BTS-SBOM에서는",
  facts: [
    ["명세 → 시험 → 코드가 한 줄로", M("수용 기준 677개 전부 EARS 패턴 + shall + 숫자 — speclint: 테스트 없는 AC 0 · 미등록 참조 0")],
    ["사람은 승인, 기계는 판정", M("패치는 승인 토큰(=계획 다이제스트)이 맞아야 적용 · 게이트는 pytest·speclint·도그푸드·야간 드리프트가 맡는다")],
    ["실패도 숨기지 않는다", M("클린룸 재구현은 호환성 실패를 compatibility_failed로 그대로 기록 · 야간 드리프트는 퇴화를 잡는 게이트")],
  ],
  verdict: I("병목은 '생성'이 아니라 '검증'으로 옮겨 간다 — 두 산출물 모두 같은 결론이다."),
  notes: "출처: Claude_Code_Desktop_SDD_AI_Native_설계.pptx 7~12·36~41장. BTS-SBOM 쪽은 specs/bts_sbom_app_features.md(AC 677)·python -m bts_sbom_app.speclint(2026-11-28)·actions.py·nightly-drift.yml.",
});
S.push({
  id: "guard", kind: "pipeline",
  steps: [
    { t: "① 프롬프트", d: "안내 — 가장 안쪽 층\n모델에게 지시" },
    { t: "② 실행 전 검증", d: "금지 규칙(deny) 먼저\n허용 규칙 · 권한 모드 확인" },
    { t: "③ 실행 후 검증", d: "나온 결과를\n근거와 대조" },
    { t: "④ 런타임 감시", d: "도는 동안 감시\n한도·회로차단" },
    { t: "⑤ 사람 이관", d: "위험한 일은\n사람이 승인" },
    { t: "감사 기록", d: "막힌 것도 실행된 것도\n한 줄씩 남긴다" },
  ],
  lanes: [
    { title: "검문은 공항 검색대처럼", tone: "info", lines: ["행동 하나가 순서대로 통과해야 실행된다 — 한 곳이라도 막히면 실행되지 않는다.", "deny는 어느 층이든 allow를 이긴다 · 설정은 위가 이긴다(managed → CLI → local → project → user)"] },
    { title: "권한 모드 = 자율성 다이얼", tone: "info", lines: ["왼쪽(Plan: 읽기·계획만)일수록 안전하고 느리다, 오른쪽일수록 빠르고 위험하다 — 일의 위험도에 맞춘다.", "실패 비용이 큰 곳일수록 바깥(코드) 층에서 막는다 — 어느 한 층도 혼자서는 부족하다"] },
    { title: "BTS-SBOM 대응 (같은 층 구조)", tone: "ok", lines: ["실행 전: 소스 경계 ALLOWED_ROOTS · 승인 토큰 없으면 변경 0건 · 실패 후: 재스캔 회귀 시 자동 복구", "런타임: 소켓 128 · 잡 1 · 채팅 4 · 실패 20회/분 → 429 · 회로차단기 3회→60초 · 감사: approvals.jsonl"] },
  ],
  verdict: I("프롬프트는 안내이고 코드는 강제다 — 두 산출물이 같은 층 구조를 쓴다."),
  notes: "출처: SDD 설계 덱 25·27~29장, 보안 하네스 덱 13장(정책 병합). BTS-SBOM 한도는 server.py·access.py·workspace.py·actions.py 코드 실측(2026-11-28).",
});
S.push({
  id: "agents", kind: "cards", cols: 3,
  cards: [
    { title: "멀티에이전트 — 8단 사다리", tone: "info", lines: [
      "에이전트를 늘릴수록 능력과 비용이 함께 커진다 — 가장 낮은 단에서 시작해 깨지는 곳만 올린다.",
      "L0 단일 에이전트(기본 · 대부분의 일) → L1 서브에이전트(탐색 · 리뷰 격리) → … L7",
      "서브에이전트는 내 대화를 모른다 — 봉투에 4가지를 꼭 넣고 결과 한 장만 돌려받는다.",
    ] },
    { title: "환각은 어디서 생기나 — 5곳", tone: "warn", lines: [
      "지식 → 검색 → 조립 → 생성 → 외부 입력. 다섯 곳 중 어디서 틀렸는지에 따라 처방이 다르다.",
      "질문마다 다른 검색 길: 라우터가 질문 유형을 보고 가장 싼 길부터 고른다 (ADR-007).",
      "검증자는 다른 AI — 답을 쓴 AI가 자기 답을 검사하면 같은 실수를 반복한다. 생성과 검증을 분리한다.",
    ] },
    { title: "BTS-SBOM에 이미 있는 것", tone: "ok", lines: [
      M("도구 호출 루프 최대 4회 · 4계층 검증(스키마·규칙·의미·교차필드) 실패 시 결정적 강등 — 단일 에이전트(L0)로 멈춰 있다."),
      M("인용 검증: 이번 질문의 문서에 없는 출처는 거절 · Book KB 15권 9,179 청크 · 인젝션 가드 · PII 마스킹."),
      I("서브에이전트 사다리는 아직 오르지 않았다 — 멀티에이전트는 '깨지는 곳'이 생기면 올리는 다음 카드(32장 To-Be)."),
    ] },
  ],
  strip: [
    "도구를 꽂는 규격 4가지 — 누가 누구에게 말하는가에 따라 다르다 (에이전트 → 도구·데이터: MCP / 로컬 stdio · 원격 HTTP). BTS-SBOM은 MCP 서버(stdio)와 A2UI 카드 19/27 도구를 이미 갖췄다.",
  ],
  verdict: I("BTS-SBOM은 사다리의 L0에서 '검증'에 투자했다 — 에이전트를 늘리기 전에 답을 검사하는 쪽이다."),
  notes: "출처: SDD 설계 덱 30~35장. BTS-SBOM 쪽: chat.py(MAX_CALLS 4·4계층 검증)·conversation.py 인용 검증·pii_guard.py·mcp_server.py·ui_cards.py(코드 실측 2026-11-28). 8단 사다리의 L2~L7 명칭은 이번 발췌에서 확인하지 않았다 — 원본 30장 참조.",
});
S.push({
  id: "patterns", kind: "table", fs: 9.5,
  cols: [{ t: "패턴 (설계 산출물)", w: 2.9 }, { t: "쉬운 뜻", w: 4.3 }, { t: "BTS-SBOM에서는", w: 4.6 }],
  rows: [
    ["로컬 우선 + 작업 공간 격리 (설계)", "여러 AI 세션이 한 저장소에서 동시에 일해도 서로의 파일을 덮지 않는다 — 세션마다 작업 공간을 따로 둔다", M("격리 작업 복사본에서만 분석·수정 — 원본 트리 해시 불변(AC-1) · 소스 경계 ALLOWED_ROOTS")],
    ["비밀은 밖에, 통로에서 주입 (설계)", "AI가 코드를 실행하는 VM 안에는 훔칠 비밀이 없게 — 통로(프록시·플랫폼)가 대신 열쇠를 꽂는다", M("이미지 풀 = 시스템 할당 MI · 레지스트리 비밀번호 0 · 시크릿은 플랫폼 시크릿 · 코드에 비밀 없음")],
    ["Spec-anchored SDD (개발)", "명세를 먼저 갱신하고 코드가 따라간다 — 명세가 흔들리면 AI도 흔들린다", M("수용 기준 677개 · 명세-테스트 양방향 추적(speclint) · 정본은 specs/ 한 곳")],
    ["EARS 수용기준 (개발)", "패턴 키워드 + shall + 측정 수치 — 수치가 없으면 아직 요구가 아니다", M("모든 AC에 숫자('0건', '2건') — '빠르게' 같은 모호어는 린트에서 걸림")],
    ["보안 하네스 9계층 H0~H8", "출입증(인증) → 층별 권한(인가) → 규정(정책) → 방마다 잠금(실행 통제) → 기록(감사). 조직 계약 H0에서 도구 호출 한 건(H4·H5)까지 내려오고, 감사 H8이 정책 H3을 고친다", I("BTS-SBOM 대응: 토큰 게이트(인증) → 공유 토큰 1개(인가는 아직 미분리) → 속도 제한·소스 경계(실행 통제) → approvals.jsonl(감사)")],
  ],
  factsTitle: "읽는 법",
  facts: [
    ["설계 패턴 10 · 개발 패턴 12 중 위에 실은 것", I("이번 5분 점검에서 원본 덱의 제목·요지만 발췌했다 — 나머지 목록은 원본 19·22장, 9계층의 H1·H2·H6·H7 명칭은 보안 하네스 덱 5장에 있다.")],
    ["로컬 vs 리모트 제어면", "PC(로컬)는 즉시 · 오프라인에서도 강제하지만 바꿀 수 있고, 서버(리모트)는 바꿀 수 없지만 로그인 후에만 강제한다 — 약점이 서로 반대라 함께 쓴다"],
  ],
  verdict: I("두 산출물의 패턴은 이름은 달라도 층 구조가 같다 — 격리·비밀 분리·명세 우선·감시·감사."),
  notes: "출처: SDD 설계 덱 12·19~22장, 보안 하네스 덱 2·5~7장. BTS-SBOM 대응은 이 덱의 실측값(AC-1, access.py, AZURE_IDENTITY.md, server.py).",
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
  { id: "sdlc", action: "insert_after", target: "⑲ 병행 레인", sec: SEC6, title: "⑳ AI 네이티브 SDLC — 명세로 합의하고, 하네스로 다루고, 게이트로 증명한다", sources: SRCDESIGN },
  { id: "guard", action: "insert_after", target: "⑳ AI 네이티브 SDLC", sec: SEC6, title: "㉑ 가드레일 — 행동 하나의 검문 흐름: 프롬프트는 안내, 코드는 강제", sources: SRCDESIGN },
  { id: "agents", action: "insert_after", target: "㉑ 가드레일", sec: SEC6, title: "㉒ 에이전트를 안전하게 — 8단 사다리 · 환각 5곳 · 검증자 분리", sources: SRCDESIGN },
  { id: "patterns", action: "insert_after", target: "㉒ 에이전트를 안전하게", sec: SEC6, title: "㉓ 설계·개발 패턴과 보안 하네스 9계층 — 그리고 BTS-SBOM에 이미 있는 것", sources: SRCDESIGN },
];

module.exports = { S, PLAN, LAYERS: A.LAYERS, M, I, G };
