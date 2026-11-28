// azure_arch_deck.model.js — the SINGLE SOURCE of the architect deck (v2).
// Both docs/AZURE_OPERATIONS_OVERVIEW.pptx and .html are rendered from this file by
// usertest/build_azure_arch_deck.js. Coordinates are px on a 1280x720 stage.
//
// Honesty tags at the start of a line (rendered as a coloured chip in both media):
//   [M] 측정   — measured on 2026-11-28 (az CLI / REST / Azure Monitor / Log Analytics / code), source in notes
//   [I] 추론   — the architect's inference or judgement (derived from measurements; not itself measured)
//   [G] 갭     — unmeasured, unverified, or absent: stated as a gap, never as zero/passed
const M = (s) => "[M] " + s;
const I = (s) => "[I] " + s;
const G = (s) => "[G] " + s;

// ---- 93 modules of bts_sbom_app partitioned into layers (the partition is an architect judgement; the build
// asserts against the real directory that every .py file lands in exactly one layer) ----
const LAYERS = [
  { n: "진입·표현", why: "요청을 받고 답을 그린다", mods: ["server", "access", "__main__", "__init__", "cli", "cli_ext", "console", "mcp_server", "ui_cards"] },
  { n: "의존성·취약성", why: "SBOM → 취약점 → 라이선스", mods: ["pipeline", "workspace", "engine", "cparse", "sbom", "osv", "licenses", "cvss", "cvss4", "cvss4_data", "versions", "gaps", "changes", "net", "netaddr", "secretscan", "batch", "util"] },
  { n: "소스·바이너리·아키텍처 지능", why: "코드를 읽어 구조와 호환성을 잰다", mods: ["srcscan", "binscan", "binary_rea", "compat", "compat_c", "compat_runtime", "arch", "arch_api", "arch_flow", "arch_intel", "arch_map", "code_intel", "diagrams", "decision"] },
  { n: "AI·에이전트·지식", why: "도구를 부르고 답을 검증한다", mods: ["ai", "ai_impact", "chat", "chat_stream", "conversation", "contextpack", "council", "llm", "promptreg", "pii_guard", "rag", "books", "books_api", "nl2sql", "feedback", "datasheet", "ft_decision", "prompt_lint", "calibrate", "evals", "evals_chat", "evals_top10", "evalguard", "quality", "loop", "looplog"] },
  { n: "거버넌스·조치·운영", why: "판정·승인·규제 증거·런타임 보호", mods: ["actions", "audit", "conformance", "coverage", "cra", "cra_api", "deliver", "escalation", "escalation_report", "events", "fleet", "govgate", "handoff", "incidents", "impact", "oss_api", "patch", "portfolio", "reimpl", "reimpl_c", "remediate", "report", "resilience", "review", "sectors", "selfcheck", "speclint", "doclint", "triage", "traceability", "bench_gate", "canary", "maturity"] },
];

const S = [];  // slides
const add = (s) => S.push(s);

/* ---------- 0. 표지·요약·지도 ---------- */
add({
  kind: "cover",
  title: "BTS-SBOM × Azure 운영 아키텍처",
  big: "아키텍트 에디션 v2",
  sub: "운영 리소스 · 전체 구성도 · UI 구성요소 기능 · 설계 판단 · 장애·위협 분석 · 리스크 · 진화 로드맵",
  meta: [
    "2026-11-28 라이브 실측 — az CLI · REST · Azure Monitor · Log Analytics · 코드 계측",
    "리비전 bts-sbom--0000016 · 이미지 ir-20261128b · Korea Central · 리소스 5개 · 코드 기준 커밋 {commit}",
    "→ 키 또는 클릭으로 진행 · 구성도는 단계별로 등장 · N 키로 출처(HTML)",
  ],
  icons: ["container_apps", "acr", "storage", "openai"],
  notes: "모든 수치는 2026-11-28 실측이다. 측정 도구: az containerapp/ac/storage/monitor, az rest(리비전·역할 할당), Azure Monitor 메트릭 저장소(72h), Log Analytics 쿼리, 코드 grep. 측정하지 않은 것은 [G] 갭으로, 판단은 [I] 추론으로 표기했다.",
});

add({
  sec: "0 요약", title: "아키텍트의 결론을 먼저: 한 문장, 잘 된 것 4, 리스크 5, 다음 판단 3",
  kind: "cards", cols: 2,
  cards: [
    { title: "한 문장 정의", tone: "info", lines: [
      I("표준 라이브러리만 쓰는 단일 컨테이너가 공유 토큰 하나 뒤에서 스캔→판단→조치→증빙을 수행하고, 증거는 Azure Files 한 폴더에 쌓는다 — '데모·파일럿' 성숙도의 정직한 단일 레플리카 시스템."),
      M("스케일 0이 실제로 작동: 72시간 중 레플리카 가동 약 5.7시간(메트릭 합산 339분)."),
    ] },
    { title: "지금 잘 된 것 (측정)", tone: "ok", lines: [
      M("롤백 가능 — 리비전 17개 전부 보존·Healthy, 0000016이 트래픽 100%(REST)."),
      M("이미지 풀 = 시스템 할당 MI·AcrPull 1건 — 레지스트리 비밀번호 0, 관리자 계정 OFF."),
      M("자원 여유 — 최대 워킹셋 121MiB/1Gi(12%), 최대 CPU 0.135/0.5코어(27%) · 72시간."),
    ] },
    { title: "가장 큰 리스크 (측정 + 추론)", tone: "gap", lines: [
      M("첫 요청마다 콜드 스타트 35.4초(기동 후 56ms) — 스케일 0의 가격."),
      M("안전망 0 — 경고 규칙 0 · 백업 0 · 단일 리전 LRS · HTTP 요청 로그 꺼짐."),
      M("인증은 공유 토큰 1개 — Easy Auth 미설정(auth show = {})."),
      I("LLM 일일 호출 예산(80회)의 장부가 컨테이너 로컬 디스크 → 기동마다 0으로 리셋(코드·Dockerfile 주석 근거, 런타임 미확인)."),
    ] },
    { title: "다음 판단 3 — 트리거로 쓴다 (추론)", tone: "warn", lines: [
      I("사용자가 2명 이상이 되는 순간 → Easy Auth(Entra ID) 사용자 인증."),
      I("하루 첫 요청을 10회 넘게 겪는 순간 → 최소 레플리카 1(콜드 스타트 0) 또는 예열."),
      I("증거가 '감사 증거'로 쓰이는 순간 → Files 백업 + 경고 규칙 + HTTP 로그. 셋 다 비용은 거의 0이다."),
    ] },
  ],
  verdict: I("이 시스템의 정체성은 '완전함'이 아니라 '정직한 단순함'이다. 단순함을 유지한 채 안전망(경고·백업·인증·예산)부터 보강하는 순서가 옳다 — 증설은 그다음."),
  notes: "리비전·롤백: GET <app>/revisions?api-version=2024-03-01 → 17개. MI: ACR 범위 역할 할당 ServicePrincipal 1건 = AcrPull(2026-11-27T16:35:29Z 생성). 자원: Azure Monitor 메트릭 저장소 WorkingSetBytes/UsageNanoCores 최대(72h, 시간별). 콜드 스타트: 레플리카 0에서 /healthz 첫 요청 TTFB 35.38s. 경고/백업: bts-sbom-rg 리소스 인벤토리 5개 + metric alert 0. Easy Auth: az containerapp auth show = {}. LLM 장부: Dockerfile.bts-sbom-app 주석 + server.py State.__init__(ledger=<root>/evidence/.llm_ledger.json, root=/app).",
});

add({
  sec: "0 요약", title: "읽는 법 — 모든 문장은 측정·추론·갭 중 하나다",
  kind: "legend",
  legend: [
    { tag: "M", t: "측정", d: "2026-11-28에 도구로 읽은 값. az CLI·REST·Azure Monitor·Log Analytics·코드. 출처는 발표자 노트(HTML은 N 키)." },
    { tag: "I", t: "추론", d: "아키텍트의 판단·유도. 측정값에서 논리로 이어간 것이지 그 자체가 측정은 아니다. 반박 가능해야 한다." },
    { tag: "G", t: "갭", d: "측정하지 않음·확인 못 함·없음. 0이나 '통과'로 적지 않는다 — 이 프로젝트의 원칙(근거 없이 통과시키지 않는다)." },
  ],
  map: [
    ["1", "운영 환경 리소스·설정", "4 – 8", "인벤토리 · 리비전 이력 · 설정 스택 · 자격 증명·경계 · 상태/데이터 지도"],
    ["2", "전체 아키텍처 구성도", "9 – 12", "컨텍스트(C4-1) · 컨테이너(C4-2) · 데이터 흐름 · 콜드 스타트 해부"],
    ["3", "UI 서비스 구성요소 기능", "13 – 17", "콘솔 5섹션 · 기능 ①②③ · {mods} 모듈 지도(C4-3)"],
    ["4", "설계 판단", "18 – 23", "품질 속성 · SLO 제안 · 핵심 판단 12건(ADR) · 트레이드오프 · 구성 드리프트"],
    ["5", "장애·위협·용량·관측 분석", "24 – 28", "FMEA 10건 · STRIDE · 용량 여유 · 관측 맹점 · 비용 모델"],
    ["6", "리스크·부채·진화", "29 – 33", "리스크 레지스터 · 부채 · Well-Architected · 트리거 로드맵 · To-Be 구성도"],
  ],
  verdict: I("v1(13장)이 '무엇이 있는가'를 답했다면 v2(34장)는 '왜 그렇게 했고 언제 바꿔야 하는가'를 답한다. 추가된 21장은 전부 판단과 분석이다."),
  notes: "측정/추론/갭 구분은 이 프로젝트의 정직 계약(specs의 'skip-is-not-pass', 'never-invent')을 덱에 그대로 적용한 것이다.",
});

/* ---------- 1. 운영 환경 리소스·설정 ---------- */
add({
  sec: "1 리소스·설정", title: "Azure 운영 환경 리소스 인벤토리 — 있고, 없고, 한 것",
  sub: "az CLI·REST 실측 (2026-11-28) · 리소스 그룹 bts-sbom-rg · Korea Central",
  kind: "table", fs: 10,
  kpi: [
    { v: "5", u: "개", label: "bts-sbom-rg 리소스", note: "환경·앱·ACR·Storage·LA" },
    { v: "17", u: "개", label: "보존된 리비전", note: "전부 Healthy · 트래픽 100%는 0000016" },
    { v: "15", u: "개", label: "보존된 이미지 태그", note: "ACR btsbomacr1126" },
    { v: "0", u: "건", label: "경고 · 백업 · 사설망", note: "경고 규칙·백업 자격증명·프라이빗 엔드포인트 — 인벤토리에 없음", tone: "gap" },
  ],
  cols: [{ t: "리소스", w: 3.1 }, { t: "SKU · 규모 · 이중화", w: 3.4 }, { t: "역할", w: 2.1 }, { t: "아키텍트가 본 점", w: 4.4 }],
  rows: [
    ["[icon:container_apps_env] Container Apps 환경 bts-sbom-env", "Consumption 전용 · 영역 중복 아님 · KEDA 2.20", "요청 라우팅·스케일·로그 목적지", I("소비형 전용이라 VNet 통합·영역 중복은 이 환경에서 불가 — 프로덕션 전환은 환경 재창출이다")],
    ["[icon:container_apps] 앱 bts-sbom · 리비전 0000016", "0.5 vCPU · 1Gi · 임시 디스크 2Gi · 레플리카 0→1", "서비스 런타임(단일 레플리카)", M("이미지 ir-20261128b · 리비전 모드 Single · 비활성 보존 한도 100")],
    ["[icon:acr] 컨테이너 레지스트리 btsbomacr1126", "Basic · 공용 엔드포인트 허용 · 관리자 계정 OFF", "이미지 저장 · 클라우드 빌드", G("이미지 서명·신뢰 정책·소프트 삭제·검역 모두 OFF — 공급망 증명 없음")],
    ["[icon:storage] 스토리지 btsbomstg1127 · 공유 evidence", "Standard_LRS 단일 리전 · 2GB 할당 · 5.4MB 사용", "스캔 기록·트리아지·감사 대장 영속", G("백업 0 · 프라이빗 엔드포인트 0 · 공용 네트워크 허용(HTTPS 강제·TLS 1.2)")],
    ["[icon:log_analytics] Log Analytics btsbom-logs", "PerGB2018 · 보존 30일 · 일일 한도 없음", "콘솔·시스템 로그 + 인그레스 메트릭", G("HTTP 요청 로그 꺼짐 · 앱 메트릭 미수집 — 요청 단위 이력이 없다")],
    ["[icon:openai] Azure OpenAI (별도 RG rg-bts-openai)", "gpt-5-mini 2025-08-07 · GlobalStandard · 용량 단위 10", "답변 생성", M("일일 호출 예산 80회(환경변수) · 경고 50%·위험 80%·소진 100%")],
  ],
  verdict: I("인벤토리는 5개로 작고 명료하다. 그러나 이 시스템의 설계는 '있는 것'만큼 '없는 것'이 말해준다: 경고, 백업, 프라이빗 네트워크, 사용자 인증 — 각각 의도적 생략인지 이 덱이 묻는다."),
  notes: "인벤토리: az resource list -g bts-sbom-rg (5개). 환경: az containerapp env show (zoneRedundant false, workloadProfiles [Consumption], keda 2.20.2). ACR: az acr show (Basic, adminUserEnabled false, publicNetworkAccess Enabled, anonymousPullEnabled false, policies: trust/softDelete/retention/quarantine disabled). Storage: az storage account show + az storage share-rm show --expand stats (quota 2GB, shareUsageBytes 5,659,062). LA: workspace retentionInDays 30, dailyQuotaGb -1. OpenAI: az cognitiveservices account deployment list. LLM 예산: llm.py daily_budget 기본 80, 임계 50/80/100%. 없는 것: metric alert 0, bts-sbom-rg에 Microsoft.Insights/actionGroups·Microsoft.RecoveryServices/vaults·Microsoft.Insights/components 없음.",
});

add({
  sec: "1 리소스·설정", title: "리비전 이력이 말해주는 것 — 38시간, 리비전 16번",
  sub: "리비전 생성 시각(REST) × 이미지 태그 생성 시각(ACR) 대응 · 시각은 UTC",
  kind: "table", fs: 10.5, then: "cards", thenCols: 3,
  kpi: [
    { v: "16", u: "회", label: "38시간 만든 리비전", note: "11-26 18:08 → 11-28 02:14 UTC" },
    { v: "26", u: "분", label: "최근 배포 간격", note: "ir-20261128 → ir-20261128b" },
    { v: "6", u: "회", label: "첫날 연속 재배포", note: "11-26 final1127 b~f, 약 56분" },
  ],
  cols: [{ t: "시각 (UTC)", w: 2.4 }, { t: "리비전", w: 1.5 }, { t: "이미지 태그", w: 3.0 }, { t: "무엇을 바꿨나", w: 6.1 }],
  rows: [
    ["11-26 18:08 – 19:04", "1 – 6", "0.5.0-final1127 b ~ f", I("첫 배포 후 6회 연속 재배포 — 안정화 루프. 태그 접미사가 곧 재시도 횟수")],
    ["11-27 16:17", "7", "0.5.0-cra1", "EU CRA 컴플라이언스 레인(AC-1241~1246)"],
    ["11-27 16:36", "8", "(이미지 동일)", I("설정 변경으로 만들어진 리비전 — 시각이 MI 전환(역할 할당 16:35:29Z)과 일치")],
    ["11-27 16:54 – 17:33", "9 – 10", "0.5.0-a2ui1128 · loop2", "A2UI 카드 · 기능 루프 2"],
    ["11-28 00:17 – 01:16", "11 – 14", "loop3 · a2ui1130 · loop4 · a2ui1130b", "기능 루프 3·4 · A2UI 카드 고도화"],
    ["11-28 01:48 – 02:14", "15 – 16", "ir-20261128 · ir-20261128b", "침해사고 대응 레인(AC-1261~1263)·QA 수선"],
  ],
  cards: [
    { title: "롤백 경로 ① 리비전 전환", tone: "ok", lines: [
      M("17개 전부 보존·Healthy(비활성 16) — 트래픽을 이전 리비전으로 100% 돌리면 끝."),
      G("롤백을 실제로 실행해 본 기록 0회 — 메커니즘과 능력은 다르다."),
    ] },
    { title: "롤백 경로 ② 이미지 태그", tone: "info", lines: [
      M("ACR 태그 15개 잔존 — 리비전을 정리해도 구 이미지를 새 리비전으로 재배포 가능."),
      I("리비전 전환이 빠르다(빌드 없음), 태그 재배포는 ACR 빌드 46~50초 + 기동."),
    ] },
    { title: "도구 함정 (기록)", tone: "warn", lines: [
      M("az containerapp revision list는 활성 리비전 1건만 돌려준다."),
      M("전수는 REST /revisions — 17건. 'CLI가 1개를 보였다'는 '1개만 있다'가 아니다."),
    ] },
  ],
  verdict: I("하루 6회 배포는 운영이 아니라 개발의 연장이다. 리비전 17개는 롤백의 '재료'일 뿐 — 롤백 훈련 1회(10분)가 안전망의 시작이다."),
  notes: "리비전 생성 시각: GET /revisions?api-version=2024-03-01 (createdTime). 태그 시각: az acr repository show-tags --detail. 리비전↔태그 대응은 시각 차(태그 뒤 약 30초)에 의한 추론이다. 롤백 훈련 기록: docs·RUNBOOK·evidence에서 롤백 실행 기록을 찾지 못함(확인 범위: 이번 세션 검색) → 갭으로 표기.",
});

add({
  sec: "1 리소스·설정", title: "설정 스택 — 라이브 값 그대로 (코드 없이 바꿀 수 있는 것들)",
  sub: "az containerapp show (configuration·template) · 2026-11-28",
  kind: "cards", cols: 3,
  cards: [
    { icon: "container_apps", title: "컴퓨트·스케일", lines: [
      M("0.5 vCPU · 메모리 1Gi · 임시 디스크 2Gi"),
      M("최소 0 · 최대 1 레플리카 · HTTP 기본 스케일 규칙"),
      G("스케일 쿨다운·폴링은 API가 미반환 — 기본값 300초/30초로 추정, 재확인 필요"),
      I("최대 1은 의도(단일 레플리카 = 잡 상태를 메모리에 두어도 안전)"),
    ] },
    { icon: "monitor", title: "프로브 3종", lines: [
      M("Startup /readyz 5초 간격 ×24회 — 기동 예산 최대 125초"),
      M("Liveness /healthz · Readiness /readyz 10초 대기 · 30초 간격 · 3회 실패"),
      I("실패 감지 예산: 기동 125초, 실행 중 장애는 최대 약 93초 뒤"),
      I("healthz=프로세스, readyz=의존성·증거 폴더 쓰기 — 의미가 분리돼 있다"),
    ] },
    { icon: "container_apps_env", title: "인그레스", lines: [
      M("외부 공개 · HTTPS 강제(allowInsecure=false) · 대상 포트 8800 · 전송 Auto"),
      M("트래픽 100% 최신 리비전 · 리비전 모드 Single · 사용자 지정 도메인 0"),
      I("인그레스는 열려 있고 '문'은 앱 계층(access.py)의 토큰 게이트 — 플랫폼이 아니다"),
    ] },
    { icon: "key_vault", title: "시크릿·환경변수", lines: [
      M("시크릿 5종(이름만): access-token · azure-api-key · azure-api-version · azure-base-url · azure-deployment"),
      M("Key Vault 참조 0 · 환경변수 15개(평문 10 · 시크릿 참조 5)"),
      I("로테이션 절차가 문서화돼 있지 않다 — 토큰·API 키 교체는 수동 재배포"),
    ] },
    { icon: "managed_identity", title: "자격 증명", lines: [
      M("시스템 할당 관리 ID 1개 · 역할 AcrPull 1건(ACR 범위) · 레지스트리 identity: system"),
      M("ACR 관리자 계정 OFF · 익명 풀 OFF · ARM은 AAD 인증"),
      I("앱이 가진 Azure 권한은 '이미지 풀' 하나 — 최소 권한이 설정에 그대로 보인다"),
    ] },
    { icon: "files", title: "볼륨·경로", lines: [
      M("AzureFile 'evidence' → /tmp/evidence(subPath evidence)"),
      M("OSV DB /tmp/osvdb(로컬) ← 시드 /tmp/evidence · 소스 루트 /srv/bts-sources"),
      I("LLM 호출 장부는 /app/evidence(로컬) — Dockerfile 주석이 '볼륨과 무관'이라고 못 박음 → 8장·30장"),
    ] },
  ],
  verdict: I("설정의 90%는 코드 한 줄 없이 환경변수·yaml로 바뀐다 — 좋은 설계다. 남은 10%(인증·네트워크·백업)는 플랫폼 설정인데 비어 있다."),
  notes: "모든 값: az containerapp show -n bts-sbom -g bts-sbom-rg (configuration.secrets 이름, configuration.ingress, template.scale/containers[0].resources/probes/env). 스케일 규칙: 라이브 template.scale에 rules·cooldown 없음(기본 HTTP 규칙); 11-23 스냅샷 deploy/azure/containerapp.applied.yaml은 cooldownPeriod 300 / pollingInterval 30. 프로브 실패 감지 시간 = initialDelay + failureThreshold × period 로 산술했다(실행 시점 오차 있음). 장부 경로: Dockerfile.bts-sbom-app 23-27행 주석.",
});

add({
  sec: "1 리소스·설정", title: "자격 증명·비밀·네트워크 경계 — 한 문과 열린 창",
  sub: "신뢰 경계 3개 · 화살표마다 근거·보호 수단을 적었다",
  kind: "diagram",
  zones: [
    { x: 36, y: 120, w: 236, h: 392, label: "인터넷 (신뢰 없음)", tone: "outer" },
    { x: 284, y: 120, w: 562, h: 392, label: "Azure 테넌트 — 공용 엔드포인트 (IP 제한 없음)", tone: "tenant" },
    { x: 858, y: 120, w: 386, h: 392, label: "컨테이너 내부 (UID 10001)", tone: "inner" },
  ],
  nodes: [
    { id: "user", x: 56, y: 158, w: 196, h: 84, icon: "browser", title: "사용자", sub: ["브라우저·스크립트", "HTTPS + 공유 토큰 1개"], b: 1 },
    { id: "ops", x: 56, y: 268, w: 196, h: 84, icon: "resource_group", title: "운영자 (az CLI)", sub: ["AAD 계정 · 구독 쓰기 권한", "배포·롤백·리비전 전환"], b: 2 },
    { id: "ing", x: 332, y: 158, w: 222, h: 84, icon: "container_apps_env", title: "ACA 인그레스", sub: ["HTTPS 강제 · 프로브 2경로 개방", "IP 제한 미설정"], b: 1 },
    { id: "acr", x: 304, y: 286, w: 250, h: 100, icon: "acr", title: "ACR btsbomacr1126", sub: ["공용 엔드포인트 허용", "관리자 OFF · 익명 풀 OFF", "신뢰 정책(서명) OFF"], b: 3 },
    { id: "stg", x: 304, y: 406, w: 250, h: 88, icon: "storage", title: "Storage btsbomstg1127", sub: ["HTTPS · TLS 1.2 · 공용 허용", "프라이빗 엔드포인트 0"], b: 3 },
    { id: "gate", x: 878, y: 158, w: 346, h: 84, icon: "managed_identity", title: "토큰 게이트 (access.py)", sub: ["최소 16자 · 실패 20회/분 → 429", "통과해야 /api 진입"], b: 1, tone: "hi" },
    { id: "app", x: 878, y: 268, w: 346, h: 84, title: "앱 bts-sbom (리비전 0000016)", sub: ["비루트 UID 10001 · 시크릿은 플랫폼 암호화", "가진 Azure 권한: AcrPull 1건"], b: 2 },
    { id: "mi", x: 878, y: 376, w: 346, h: 122, icon: "key_vault", title: "시크릿 5종 — Key Vault 참조 0", sub: ["access-token · azure-api-key", "azure-api-version · azure-base-url", "azure-deployment", "로테이션 절차 없음 → 수동 재배포"], b: 3, tone: "gap" },
  ],
  edges: [
    { from: "user", to: "ing", label: "HTTPS·토큰", b: 1, lx: 262, ly: 183 },
    { from: "ing", to: "gate", label: "8800", b: 1, lx: 700, ly: 183 },
    { from: "gate", to: "app", label: "통과 시", b: 2, fromSide: "b", toSide: "t", lx: 1062, ly: 248 },
    { from: "ops", to: "acr", b: 2 },
    { from: "ops", to: "stg", label: "배포·공유 관리", b: 2, dash: true, via: [120, 352, 120, 450, 304, 450], lx: 150, ly: 432 },
    { from: "app", to: "mi", label: "env(secretRef)", b: 3, fromSide: "b", toSide: "t", dash: true, lx: 1062, ly: 359 },
    { from: "app", to: "acr", label: "이미지 풀 · MI(AcrPull)", b: 3, via: [878, 300, 690, 300, 690, 336, 554, 336], lx: 700, ly: 283 },
    { from: "app", to: "stg", label: "SMB 마운트 evidence", b: 3, via: [878, 334, 740, 334, 740, 450, 554, 450], lx: 750, ly: 317 },
  ],
  facts: [
    ["있는 것 (측정)", M("HTTPS 강제 · Storage TLS 1.2 최소 · ACR 관리자 OFF·익명 풀 OFF·ARM AAD 인증 · 시크릿 값은 플랫폼 암호화 · 토큰 최소 16자 · 실패 20회/분 → 429")],
    ["없는 것 (갭)", G("Easy Auth 미설정 · ACR·Storage 공용 네트워크 허용(프라이빗 엔드포인트 0) · IP 제한 없음 · 방화벽/WAF 없음 · 비밀 로테이션 절차 없음")],
  ],
  verdict: I("현재 보안 모델 = 한 문(토큰) + 열린 창(공용 PaaS 엔드포인트). 문은 튼튼하다(게이트·속도 제한). 창은 열려 있다 — 데모에선 합리적, 테넌트 분리가 필요해지는 순간 첫 번째 보강 대상."),
  notes: "인그레스: external true, allowInsecure false, ipSecurityRestrictions 미설정. 토큰 게이트: access.py MIN_LENGTH=16, server.py AUTH_FAIL_LIMIT=20 / AUTH_FAIL_WINDOW=60초. 시크릿 이름 5종·keyVaultRefs 0: az containerapp show. ACR/Storage 공용 접근: az acr show publicNetworkAccess Enabled, networkRuleSet 없음; az storage account show networkRuleSet.defaultAction Allow, privateEndpointConnections []. MI: 시스템 할당 + ACR 범위 AcrPull(REST roleAssignments). 경계와 화살표의 '의미' 해석은 추론.",
  builds: { 1: "사용자·인그레스·토큰 게이트 — 누가 어떻게 들어오나", 2: "운영자 경로와 앱 — 사람의 권한은 앱과 분리", 3: "비밀·이미지·증거 — 앱과 PaaS 사이의 연결" },
});

add({
  sec: "1 리소스·설정", title: "상태·데이터 지도 — 무엇이 어디에 살아남는가",
  sub: "영속은 Azure Files 한 곳 · 나머지는 기동마다 다시 만들어진다",
  kind: "table", fs: 10,
  kpi: [
    { v: "5.4", u: "MB", label: "공유 evidence 사용량", note: "/ 2GB 할당 (0.26%) · TransactionOptimized" },
    { v: "1", u: "개", label: "영속 볼륨", note: "AzureFile 'evidence'" },
    { v: "3", u: "층", label: "휘발성 계층", note: "로컬 디스크 · 프로세스 메모리 · 외부 캐시", tone: "warn" },
  ],
  cols: [{ t: "저장소", w: 2.5 }, { t: "위치 · 내용", w: 3.9 }, { t: "내구성 (측정)", w: 2.5 }, { t: "재시작·스케일 0에서", w: 2.9 }, { t: "RPO — 판단", w: 2.2 }],
  rows: [
    [M("Azure Files 'evidence'"), "공유 /tmp/evidence — 스캔 기록·트리아지·에스컬레이션·승인 대장(approvals.jsonl)·채팅 턴·OSV 시드 DB", M("Standard_LRS 단일 리전 · 백업 0 · 스냅샷 0"), M("보존 — 유일한 영속 계층"), I("지역 장애·삭제 시 전체 유실 가능")],
    [M("컨테이너 로컬 디스크 2Gi"), "/tmp/osvdb(OSV DB 사본)·/srv/bts-sources(격리 복사본)·/app/evidence(LLM 호출 장부)", M("휘발성 — 이미지 레이어 위 쓰기 계층"), M("매 기동 재생성 — 'OSV snapshot: copied' 로그 확인"), I("LLM 일일 예산이 기동마다 0으로 — '일일 상한'이 사실상 '기동당 상한'")],
    [M("프로세스 메모리"), "백그라운드 잡 상태·SSE 버스·호출자별 속도 제한 표·실패 카운터", M("휘발성 — 프로세스 수명"), M("유실 — 실행 중 스캔은 중단, 재요청 필요"), I("단일 레플리카라 허용. 레플리카 2 이상이면 큐·외부 저장으로 반드시 이동")],
    [M("외부 데이터 원천"), "OSV.dev · deps.dev · 레지스트리 · 공개 Git 호스트 → 로컬 캐시(휘발성)", M("외부 — 통제 불가"), M("회로차단기 3회 실패 → 60초 개방 · 결과는 gap으로 공시"), I("RPO 개념 없음 — 대신 '오프라인 폴백 시 갭 공시'가 가용성 전략")],
    [M("Azure Monitor"), "LA(콘솔·시스템 로그 30일) · 메트릭 저장소(인그레스 4종, 앱 메트릭은 93일)", M("플랫폼 보존"), M("보존"), G("HTTP 요청 로그·앱 메트릭의 LA 수집 없음 — 요청 단위 이력이 없다")],
  ],
  verdict: I("영속 계층이 '폴더 하나'인 것은 의도된 단순함이다. 조건은 하나 — 그 폴더가 유일한 진실의 원천이라는 것. 그렇다면 그 폴더의 백업은 선택이 아니라 전제다."),
  notes: "공유 사용량: az storage share-rm show --expand stats (5,659,062 bytes). evidence에 쓰는 파일: 코드 grep(runs, *.triage.json, escalations.jsonl, approvals.jsonl, .pending_decisions.json, sections.jsonl, chat_turns.jsonl, chat_feedback.jsonl, bts_sbom_osv_local.db). LLM 장부: <root>/evidence/.llm_ledger.json, root=/app(Dockerfile CMD) → 로컬. 메모리 상태: server.py State.__init__(jobs, buses, _chat_hits, _auth_fails). 회로차단기: resilience.py DEFAULT_FAILURE_THRESHOLD=3, DEFAULT_OPEN_SECONDS=60. OSV 시드 복사: 콜드 스타트 콘솔 로그 'OSV snapshot: copied'. LA 진단 설정: 환경 'to-btsbom-logs' — ConsoleLogs·SystemLogs·AllMetrics 켬, HTTPLogs 끔; 앱 리소스에는 진단 설정 없음. 메트릭 저장소 보존 기간(93일)은 Azure Monitor 기본값에 대한 일반 지식 — 이 구독에서 별도 확인하지 않았다.",
});

/* ---------- 2. 전체 아키텍처 구성도 ---------- */
add({
  sec: "2 구성도", title: "시스템 컨텍스트 (C4-1) — 누가, 무엇을 통해, 어디에 닿는가",
  sub: "공식 Azure 아키텍처 아이콘(V25) · 화살표마다 프로토콜·보호 수단",
  kind: "diagram",
  zones: [
    { x: 36, y: 120, w: 230, h: 410, label: "사람", tone: "outer" },
    { x: 290, y: 120, w: 644, h: 410, label: "Azure — bts-sbom-rg (Korea Central)", tone: "tenant", labelBottom: true },
    { x: 946, y: 120, w: 298, h: 410, label: "외부 · 별도 리소스 그룹", tone: "outer" },
  ],
  nodes: [
    { id: "user", x: 56, y: 276, w: 190, h: 96, icon: "browser", title: "사용자", sub: ["웹 콘솔 · CLI · MCP 서버", "HTTPS + 공유 토큰"], b: 1 },
    { id: "ops", x: 56, y: 396, w: 190, h: 96, icon: "resource_group", title: "운영자 (az CLI)", sub: ["AAD 계정 · 빌드·배포", "리비전 전환"], b: 1 },
    { id: "ing", x: 330, y: 276, w: 180, h: 84, icon: "container_apps_env", title: "ACA 인그레스", sub: ["HTTPS 강제 · 프로브 개방", "KEDA 2.20 · 스케일 0→1"], b: 2 },
    { id: "app", x: 560, y: 240, w: 190, h: 200, icon: "container_apps", title: "앱 bts-sbom", sub: ["리비전 0000016", "이미지 ir-20261128b", "0.5 vCPU · 1Gi · 2Gi", "단일 프로세스 · 8800", "/api 라우트 38 · UI 46", "SSE · HITL 승인", "백그라운드 잡", "UID 10001 · 의존성 0"], b: 2, tone: "hi" },
    { id: "acr", x: 560, y: 140, w: 190, h: 84, icon: "acr", title: "ACR", sub: ["Basic · 태그 15", "MI AcrPull 풀"], b: 3 },
    { id: "files", x: 790, y: 240, w: 140, h: 90, icon: "files", title: "Azure Files", sub: ["evidence 2GB", "5.4MB · 영속"], b: 3 },
    { id: "la", x: 790, y: 360, w: 140, h: 90, icon: "log_analytics", title: "Log Analytics", sub: ["콘솔·시스템 로그", "보존 30일"], b: 3 },
    { id: "oai", x: 964, y: 140, w: 200, h: 84, icon: "openai", title: "Azure OpenAI", sub: ["gpt-5-mini · 별도 RG", "예산 80회/일"], b: 4 },
    { id: "ext", x: 964, y: 340, w: 200, h: 150, title: "외부 데이터 원천", sub: ["OSV.dev · deps.dev", "패키지 레지스트리", "공개 Git 호스트", "SSRF 가드", "회로차단기 3회→60초"], b: 4, tone: "outer" },
  ],
  edges: [
    { from: "user", to: "ing", label: "HTTPS·토큰", b: 1, lx: 252, ly: 306 },
    { from: "ops", to: "app", label: "빌드·배포·리비전 전환", b: 1, dash: true, toOff: 76, lx: 300, ly: 422 },
    { from: "ops", to: "acr", label: "az acr build", b: 1, via: [246, 476, 278, 476, 278, 126, 655, 126, 655, 140], lx: 380, ly: 109 },
    { from: "ing", to: "app", label: "8800", b: 2, lx: 512, ly: 297 },
    { from: "app", to: "acr", label: "이미지 풀 (MI)", b: 3, fromSide: "t", toSide: "b", lx: 664, ly: 224 },
    { from: "app", to: "files", label: "SMB", b: 3, lx: 752, ly: 266 },
    { from: "app", to: "la", label: "진단", b: 3, dash: true, lx: 754, ly: 386 },
    { from: "app", to: "oai", label: "HTTPS REST", b: 4, via: [750, 262, 770, 262, 770, 178, 964, 178], lx: 800, ly: 160 },
    { from: "app", to: "ext", label: "HTTPS (아웃바운드 공용 IP)", b: 4, via: [655, 440, 655, 508, 946, 508, 946, 470, 964, 470], lx: 700, ly: 489 },
  ],
  legend: [M("측정: 리소스·구성·경로 전부 2026-11-28 값"), I("추론: 외부 의존 5개 중 3개(OSV·deps.dev·Git 호스트)는 요청 시점에 필요 — '오프라인 폴백 시 갭 공시'가 가용성 전략"),
    I("CI/야간 드리프트는 서비스를 호출하지 않는다(오프라인 배터리) — 그래서 구성도에 없다")],
  verdict: I("아웃바운드가 공용 인터넷이라 데이터 유출 경로는 방화벽이 아니라 코드의 SSRF 가드·호출 허용목록이 막는다 — 네트워크 경계가 아니라 앱 경계가 실질적 경계다."),
  notes: "구성도의 모든 노드는 존재가 실측된 리소스다(az resource list). 앱 능력: /api 라우트 리터럴 38개(server.py grep), UI가 참조하는 경로 46종(web JS grep). 아웃바운드: 소비형 환경의 공용 아웃바운드 IP(환경 outboundIpAddresses 다수) — 고정 IP 아님. SSRF 가드·호스트 허용목록: net.py, BTS_OSS_ALLOWED_HOSTS. CI가 서비스를 호출하지 않는다는 것은 nightly-drift.yml의 작업 내용에 근거(이번 세션에서 워크플로 파일을 열어 확인하지는 않음 → 부분 추론).",
  builds: { 1: "사람 — 사용자와 운영자", 2: "진입 경로와 앱", 3: "상태 3곳 — ACR·Files·LA", 4: "아웃바운드 — OpenAI와 외부 데이터" },
});

add({
  sec: "2 구성도", title: "컨테이너 내부 (C4-2) — 요청이 거치는 7단계와 3개의 차선",
  sub: "하나의 프로세스, 세 개의 세마포어 — 큐·워커 없이 자원 고갈을 막는 구조",
  kind: "pipeline",
  steps: [
    { t: "소켓 128 상한", d: "초과는 즉시 503", b: 1 },
    { t: "토큰 게이트", d: "access.py · 실패 20회/분 → 429", b: 1 },
    { t: "라우터", d: "/api 38 라우트 리터럴 + 프로브", b: 2 },
    { t: "핸들러", d: "동기 JSON · SSE · 잡 시작", b: 2 },
    { t: "서비스 93 모듈", d: "스캔·판단·조치·증빙", b: 3 },
    { t: "저장소", d: "Files · 로컬 · 외부(가드)", b: 3 },
  ],
  lanes: [
    { title: "동기 요청", tone: "info", lines: [M("소켓 128 · 질문 4,000자 · 500은 상관 ID만(트레이스백 없음)"), I("요청-응답은 짧게 — 긴 작업은 잡 차선으로")] },
    { title: "SSE 스트림", tone: "info", lines: [M("동시 4 · 호출자 30회/분 · heartbeat 15초(최소 5)"), M("리더 퇴장 → 남은 도구 호출을 cancelled 행으로 기록")] },
    { title: "백그라운드 잡", tone: "warn", lines: [M("동시 1 — 초과는 429 + Retry-After"), M("SIGTERM 드레인 20초 — 신규 503, 진행 잡 완료 대기")] },
  ],
  verdict: I("한도의 근거는 '0.5 vCPU 단일 레플리카'다. 잡을 1개로 묶어 둔 것이 스캔과 채팅이 서로를 굶기지 않는 이유이자, 처리량의 천장이기도 하다(26장)."),
  notes: "한도 전부 코드 실측: server.py MAX_CONNECTIONS=128, MAX_QUESTION_CHARS=4000, BTS_SBOM_MAX_JOBS=1, BTS_SBOM_CHAT_MAX_CONCURRENCY=4, BTS_SBOM_CHAT_RATE_LIMIT=30 / WINDOW 60초, HEARTBEAT_SECONDS=15(최소 5), begin_drain(timeout=20.0); access.py MIN_LENGTH=16; server.py AUTH_FAIL_LIMIT=20. 모듈 수 93: ls bts_sbom_app/*.py.",
});

add({
  sec: "2 구성도", title: "데이터 흐름 — 스캔에서 증거까지 한 방향, 쓰기 경로는 둘",
  sub: "읽기 원본은 건드리지 않는다 · 쓰는 DB는 로컬 · 남는 증거는 공유",
  kind: "flow",
  steps: [
    { t: "스캔 입력", d: "git URL · 잠금파일·폴더\n원본 무변경 · 격리 복사본\n소스 경계 ALLOWED_ROOTS" },
    { t: "분석 엔진", d: "SBOM → OSV 취약점 → deps.dev 라이선스\n아키텍처·코드 지능\n오프라인 폴백 시 갭 공시" },
    { t: "evidence 기록", d: "프로젝트 레코드 · CycloneDX/SPDX/VEX\n감사 대장 5종 · approvals.jsonl\n→ Azure Files 공유" },
    { t: "판단·조치", d: "트리아지 · VEX · Fix Plan\n승인 토큰 = 계획 다이제스트\n회귀 시 자동 복구" },
    { t: "관측", d: "Log Analytics · 상관 ID\nLLM 비용 장부\n→ LA·메트릭 저장소" },
  ],
  cards: [
    { title: "측정된 결함과 수선 (AC-1226~1227)", tone: "ok", lines: [
      M("OSV DB를 SMB(Azure Files)에 두면 캐시 쓰기가 잠금 대기 — NodeGoat 스캔 780초."),
      M("시작 시 시드→로컬 복사(seed→local)로 96초, 락 오류 0. 현재 구성(OSV_DB_PATH=/tmp/osvdb)이 그 결과."),
      I("콜드 스타트 콘솔 로그의 'OSV snapshot: copied'가 이 복사가 기동 경로에 있음을 확인해 준다(컨테이너 기동 후 0.2초 내)."),
    ] },
    { title: "아키텍처 교훈", tone: "info", lines: [
      I("SQLite는 네트워크 공유 위 동시 쓰기를 견디지 못한다 — 읽기전용 시드는 공유, 쓰는 DB는 로컬."),
      I("영속 데이터(레코드·대장)는 공유에 append(JSONL) — 쓰기 경로를 '공유의 append'와 '로컬의 트랜잭션'으로 분리한 것이 핵심."),
      M("라이브 환경변수: OSV_DB_PATH=/tmp/osvdb/… · OSV_SEED_DB=/tmp/evidence/… — 시드는 공유, 쓰는 DB는 로컬."),
    ] },
  ],
  verdict: I("이 경계가 흐려지는 순간(공유 위 DB) 780초 사건이 재현된다. 구성 값 하나(OSV_DB_PATH)가 아키텍처 결정인 이유다."),
  notes: "780초→96초·락 오류 0: specs AC-1226~1227 및 docs/AZURE_DEPLOYMENT.md의 기록(이전 세션 실측). 현재 경로: 라이브 환경변수 BTS_SBOM_OSV_DB_PATH=/tmp/osvdb/bts_sbom_osv_local.db, BTS_SBOM_OSV_SEED_DB=/tmp/evidence/bts_sbom_osv_local.db. 승인 토큰=다이제스트: actions.py. 감사 대장 5종: cra.py ledgers, approvals: actions._audit.",
});

add({
  sec: "2 구성도", title: "런타임 뷰 — 콜드 스타트 35.4초 해부",
  sub: "레플리카 0 상태에서 /healthz 첫 요청 · curl 타이밍 × ContainerAppSystemLogs 이벤트",
  kind: "coldstart",
  total: 35.38,
  segs: [
    { t: "요청 유지 → 레플리카 스케줄", s: 15.3, tone: "a", tag: "I", note: "활성화·KEDA 스케일 결정 (플랫폼)" },
    { t: "노드 준비 → 이미지 풀 시작", s: 16.1, tone: "b", tag: "I", note: "할당·볼륨 마운트 (플랫폼)" },
    { t: "이미지 풀", s: 3.72, tone: "c", tag: "M", note: "86MB · ACR 공용 엔드포인트" },
    { t: "앱 기동 → 리스닝", s: 0.22, tone: "d", tag: "M", note: "OSV 시드 복사 + 서버 기동" },
  ],
  cards: [
    { title: "측정값", tone: "ok", lines: [
      M("첫 요청 TTFB 35.38초 → 기동 후 /healthz 56ms · /readyz 113ms · 토큰 없는 /api 401 55ms."),
      M("로그: 04:05:15.907 레플리카 스케줄 → 04:05:35.782 풀 완료(3.72초)·컨테이너 기동 → 04:05:36.001 리스닝."),
    ] },
    { title: "유도 (추론)", tone: "info", lines: [
      I("구간 분할은 curl 총시간과 로그 시각의 차이 — 요청 시작 시각은 뺄셈으로 유도."),
      I("35.4초 중 앱이 바꿀 수 있는 것은 마지막 0.2초뿐 — 99%가 플랫폼 활성화·이미지 풀."),
      I("구간을 15초 + 16초로 나눈 근거는 로그의 첫 이벤트(스케줄)와 풀 완료 시각 — 요청 시작 시각은 뺄셈이라 약 ±1초의 오차가 있다."),
    ] },
    { title: "완화 옵션과 대가", tone: "warn", lines: [
      I("최소 레플리카 1 — 콜드 스타트 0, 상시 과금(금액 미실측)."),
      I("예열 ping — 첫 사용 전에 깨운다. 단 주기 ping은 스케일 0을 무력화한다."),
      I("이미지 경량화 — 풀 3.7초만 해당(11%). 효과 작음."),
      G("아직 측정하지 않은 것: 콜드 스타트의 분포(표본 1회) · 예열 ping이 스케일 0을 깨는지 · 상시 1대의 실제 청구액."),
    ] },
  ],
  verdict: I("콜드 스타트는 버그가 아니라 가격이다: 월 몇 달러의 대가가 첫 요청 35초다. '첫 요청'을 하루 몇 번 겪는지가 최소 레플리카를 올릴지의 유일한 기준이어야 한다."),
  notes: "측정: replicas 0 확인(az containerapp replica list) 직후 curl -w time_starttransfer /healthz 3회 + readyz + /api/projects(토큰 없음). 로그: ContainerAppSystemLogs_CL (Reason_s AssigningReplica·PullingImage·PulledImage·ContainerCreated·ContainerStarted, Image size 90177536 bytes), ContainerAppConsoleLogs_CL ('OSV snapshot: copied', 'BTS-SBOM serving on http://0.0.0.0:8800'). 구간 경계 중 '노드 준비→풀 시작'은 PullingImage 시각에서 풀 소요 3.72초를 뺀 값이다.",
});

/* ---------- 3. UI 서비스 구성요소 기능 ---------- */
add({
  sec: "3 구성요소", title: "UI 서비스 개요 — 콘솔 5섹션 · 하단 대화 dock",
  sub: "bts_console.js GROUPS 실측 · 모든 판은 JSON API 위의 렌더러",
  kind: "cards", cols: 3,
  kpi: [
    { v: "5", u: "섹션", label: "콘솔 내비그룹", note: "bts_console.js GROUPS" },
    { v: "38", u: "개", label: "/api 라우트 리터럴", note: "server.py · UI가 호출하는 경로는 46종" },
    { v: "16", u: "개", label: "웹 자산(JS·CSS)", note: "vendor 폴더 제외" },
  ],
  cards: [
    { title: "🔎 분석 스캔", lines: ["Scan(Git·잠금파일) · OSS 결과 · Lockfile · Container — BtsOss 계약 단일 폼"] },
    { title: "📊 결과와 우선순위", lines: ["Findings · What changed · SSVC · EPSS · Exploit Matrix — 측정 안 한 지표는 공란"] },
    { title: "🗄 리포트와 구조", lines: ["Report · Arch Intel · Diagrams(37종) · Dep Graph · Code Intel · DB 질의 · Supply Chain"] },
    { title: "📚 지식·컴플라이언스", lines: ["Book KB · SBOM checks · Conformance · CRA · VEX · License Risk · Industry · 사고 대응"] },
    { title: "🔧 수정과 운영", lines: ["Fix Plan · Patch(승인 토큰) · Clean-Room 재구현 · CI/CD · History · Fleet"] },
    { title: "💬 하단 대화 dock", tone: "hi", lines: ["모든 탭 상주 · SSE 7종 활동 카드(tool_call/result · awaiting_approval · handoff · final · error)", "A2UI 카드(카탈로그 19/27 도구, esc-only 렌더) · 승인은 인라인 버튼 = 사용자 행위", "질문 → 도구 → 인용 검증 → 카드/다이어그램 단발 턴"] },
  ],
  factsTitle: "이 화면이 API를 어떻게 쓰는가 — 판에는 비즈니스 로직이 아니라 렌더러만 있다",
  facts: [
    ["콘솔 → API", [M("/api 라우트 리터럴 38개 · UI가 참조하는 경로 46종 · 웹 자산 16개(JS·CSS) — 코드 grep"), I("46 = 38 + 동적 접두어(예: /api/jobs/<id>/events) — 판을 바꿔도 계약이 늘지 않는다(코드 grep 기반 판단)")]],
    ["SSE 활동 카드 7종 · 승인", [M("tool_call/result · awaiting_approval · handoff · final · error 등 — dock이 스트림 이벤트를 그대로 활동 카드로 렌더"), M("인라인 승인 버튼 = 사용자 행위 — 토큰은 계획 다이제스트, 시도 전부 approvals.jsonl에 기록")]],
    ["A2UI 카드", M("카탈로그 19/27 도구 · esc-only 렌더 — 위젯이 아니라 이스케이프된 텍스트·목록·표만 그린다(병행 레인 실측)")],
  ],
  verdict: I("UI는 상태를 갖지 않는다 — 판이 아니라 렌더러다. 그래서 화면의 수(5+1)와 API의 수(38)를 따로 셀 수 있고, UI를 바꿔도 계약이 흔들리지 않는다."),
  notes: "GROUPS: bts_sbom_app/web/bts_console.js. 라우트: server.py '/api/...' 리터럴 distinct 38개, web/*.js가 참조하는 '/api/' 경로 distinct 46개(동적 접두어 포함). 웹 자산: bts_sbom_app/web 직속 js/css 16개. A2UI 카드: docs/A2UI_INTEGRATION.md, AC-645/646(병행 레인 실측).",
});

add({
  sec: "3 구성요소", title: "구성요소 기능 ① — 분석 스캔 · 결과와 우선순위",
  sub: "정직 계약: 측정하지 않은 것은 0이 아니라 '없음'으로 답한다",
  kind: "cards", cols: 4,
  cards: [
    { title: "Scan (Git·Lockfile·폴더)", lines: ["의존성 추출 → 라이선스/취약점 매칭 → CycloneDX·SPDX·OpenVEX 생성.", "소스 경계·SSRF 가드 내장. 부분 스캔은 갭 공시."] },
    { title: "Findings · What changed", lines: ["두 분석/SBOM diff로 신규·해소 취약점·버전 이동 감지, 임계 알림.", "배치 재시도 후 합산 집계 일치 보장."] },
    { title: "Prioritize (SSVC·EPSS·Exploit)", lines: ["SSVC 의사결정 트리 · EPSS · 익스플로잇 성숙도.", "피드 미연동 지표는 배지로 '미측정' 공시 — 과잉 표시 없음."] },
    { title: "Dep Graph · Health", lines: ["의존성 그래프 · EOL · 유지관리 신호.", "Fleet으로 포트폴리오 롤업·영향 프로젝트 역조회."] },
  ],
  strip: [
    M("백그라운드 잡은 벌크헤드(동시 1) — 2번째 요청은 429 + Retry-After"),
    M("상관 ID가 잡 기록·SSE·에스컬레이션을 관통 (AC-1256)"),
    G("KEV·EUVD 피드 미연동 — '악용 중 여부'는 not-assessed로 답한다"),
  ],
  factsTitle: "이 그룹의 실측치 — 이전 세션·evidence/runs 기록",
  facts: [
    ["NodeGoat 원격 스캔", M("컴포넌트 1,091 · 취약점 311(CRITICAL 32 · HIGH 168) · 라이브 96초")],
    ["u-boot v2026.10", M("컴포넌트 68 · 취약점 43 · 라이선스 해석 65/68(96%) — deps.dev 44 · 레지스트리 21")],
    ["Fleet 롤업", M("저장 기록 5개 프로젝트 · 컴포넌트 5,358 · 취약점 401건 · 수정 없음 11 — '마지막 분석 기준의 하한값'으로 표시")],
    ["What changed", I("두 분석의 diff로 신규·해소·버전 이동을 감지 — 집계 일치는 배치 재시도 후 합산으로 보장(AC 기록)")],
  ],
  verdict: I("이 그룹의 제품적 차별화는 '많이 찾는 것'이 아니라 '못 찾은 것을 못 찾았다고 쓰는 것'이다 — gap·unverified·미측정이 1급 시민이다."),
  notes: "v1 덱(13장) 8번 슬라이드 내용을 계승·갱신. KEV/EUVD 미연동: CRA 레인 설계(cra.py — 악용 여부 not-assessed).",
});

add({
  sec: "3 구성요소", title: "구성요소 기능 ② — 리포트·구조 · 지식·컴플라이언스",
  sub: "CRA 레인(AC-1241~1246)과 사고 대응 판이 이 그룹의 최신 라인",
  kind: "cards", cols: 4,
  cards: [
    { title: "Arch Intel · Code Intel", lines: ["EA 스타일 다이어그램(37종 카탈로그) · DMN 추론엔진 · 콜그래프 · 순환복잡도 · 클론 — SciTools Understand 핵심을 표준 라이브러리로 재구현."] },
    { title: "Book KB · NL2SQL", lines: ["로컬 도서 15권(9,179 청크) + 정제 노트를 추론 소스로 — 클린룸 패턴 2단 추론(책→모델 폴백).", "스캔 증거 OSV DB에 한국어 NL2SQL."] },
    { title: "SBOM Conformance · CRA", lines: ["NTIA·CISA·EU CRA·BSI TR-03183-2 요소별 매트릭스.", "CRA 판: security.txt(RFC 9116) · 지원기간 5년 검증 · Article 14 시계 · 부록 J 대장 5종 · readiness 8체크."] },
    { title: "VEX · 라이선스 리스크 · 사고 대응", lines: ["처분 결정은 VEX 근거 fail-closed(not_affected는 근거 필수). 강한 카피레프트는 클린룸 경로 안내.", "KISA 매핑 사고 SLA · 보고서 · IoC 조회 판."] },
  ],
  strip: [
    M("security.txt는 /.well-known/에서 자동 서빙 — 주소를 추측하지 않으면 404 + 해결책으로 정직히 답한다"),
    M("u-boot 실측: CRA readiness 37.5% → 75.0% (지원기간 선언 후) · 부록 J 대장 14/45/70/3/2행"),
  ],
  factsTitle: "이 그룹의 실측치 — 이전 세션 기록",
  facts: [
    ["Book KB · RAG", M("로컬 도서 15권 · 9,179 청크 — 골든 Recall@5 1.0 · MRR 0.95 · 보류 test Recall@5 0.917")],
    ["Diagrams(37종)", M("mermaid lint가 실제 결함(라벨 잘림으로 괄호 불균형)을 잡아 수선한 기록(AC-1249)")],
    ["CRA(u-boot)", M("readiness 37.5% → 75.0%(지원기간 선언 후) · 부록 J 대장 14/45/70/3/2행 · test_cra 8 passed")],
    ["NL2SQL", M("'패키지별 취약점 상위 5' → success · attempts 1(django 74) — 읽기 전용·4상태 응답")],
  ],
  verdict: I("리포트는 '문서'가 아니라 '증거 묶음'이다 — 근거가 없으면 not_evidence로 적는 규칙이 리포트의 신뢰도를 만든다."),
  notes: "v1 덱 9번 슬라이드 계승. u-boot CRA 실측: specs AC-1241~1246, evidence/cra_e2e, test_cra.py.",
});

add({
  sec: "3 구성요소", title: "구성요소 기능 ③ — 수정 · 운영 · HITL 승인 체인",
  sub: "라이브 HITL 실측: 오래된 토큰 거부 · 격리 적용 80.7초 · 소스 경계 거부",
  kind: "flow",
  steps: [
    { t: "1. Fix Plan", d: "업그레이드 계획 생성\nDMN 처분 정책이 우선순위 결정\n(조직 오버라이드 가능, AC-1258)" },
    { t: "2. Patch 승인", d: "승인 토큰 = 보여준 계획의 다이제스트\n계획이 바뀌면 토큰 무효\n시도 전부 감사 대장 기록(AC-1257)" },
    { t: "3. 적용·재검증", d: "워크카피 1라운드 적용 → 재스캔\n회귀 시 자동 복구\n라이브 실측 80.7초" },
    { t: "4. VEX 결정", d: "not_affected는 VEX 근거 5종 중 하나\n+ 10자 이상 사유 없으면 affected 유지\n(fail-closed)" },
    { t: "5. Clean-Room", d: "GPL/AGPL은 패치 불가\n명세 채널에 책→AI 2단 패턴 주입\n카피 게이트 4행 shingle 0.05" },
  ],
  factsTitle: "이 체인의 실측치",
  facts: [
    ["라이브 HITL 체인", M("오래된 승인 토큰 거부 · 격리 적용 80.7초 · 소스 경계 거부 — Azure 리비전에서 실측(AC-645/646)")],
    ["감사 대장", M("approvals.jsonl — patch_apply·decision_commit 시도 전부 기록(actor·시각·digest_mismatch 포함, AC-1257)")],
    ["처분 정책 오버라이드", M("remediation_policy() — 무효 항목이 1건이라도 있으면 오버라이드 전체를 기각하고 기본값 유지(AC-1258)")],
    ["클린룸", M("concurrencytest 0.1.12(GPL) — 카피 게이트 겹침 0.0(기준 0.05) · 계약 테스트 2 실행/0 실패 · 판정 ok")],
  ],
  strip: [
    M("전 과정은 취약점 처리 요건의 증거로 기록 — Article 14 시계(24h/72h/14일)와 감사 대장이 같은 evidence 폴더를 공유한다"),
  ],
  verdict: I("승인 토큰을 '세션'이 아니라 '계획의 해시'로 만든 것이 이 체인의 핵심이다 — 누가·언제 승인했는지와 무관하게 '무엇을 승인했는가'가 증거로 남는다."),
  notes: "v1 덱 10번 슬라이드 계승. 라이브 HITL 실측: docs/A2UI_INTEGRATION.md·memory(a2ui-cards-live-round) — 오래된 토큰 거부, 격리 적용 80.7초, 소스 경계 거부. 처분 정책 오버라이드: decision.remediation_policy() (AC-1258). 감사 대장: actions._audit (AC-1257).",
});

add({
  sec: "3 구성요소", title: "모듈 지도 (C4-3) — {mods}개 모듈을 5개 계층으로",
  sub: "모듈 수는 실측(git 추적 파일 {mods}개, __init__ 포함) · 계층 구분은 아키텍트 판단 — 빌드가 '추적되는 모든 파일이 정확히 한 계층'인지 검증",
  kind: "layers", layers: LAYERS,
  facts: [
    I("100개 중 AI·에이전트·지식(26)과 소스·바이너리·아키텍처 지능(14)이 40% — 차별화는 '스캔'이 아니라 '스캔을 검증하는 층'(evals·evalguard·quality·loop)에 있다."),
    I("거버넌스·조치·운영(33)이 가장 두껍다 — 이 제품의 본질이 '분석 도구'가 아니라 '판정·승인·증거'라는 뜻."),
    I("데이터 계층이 파일(JSON/JSONL) 하나라 질의·트랜잭션 요구가 커지면 가장 먼저 갈라지는 지점이다."),
    M("계수 검증 — 이 덱의 빌드가 git 추적 파일 전수와 계층 구분을 대조한다. 만드는 동안 병행 레인이 모듈 7개를 커밋해 93→100이 되었고, 빌드가 그 변경을 잡아냈다."),
    I("계층 간 호출 방향·순환은 아직 측정하지 않았다 — arch_map으로 측정 가능(다음 과제)."),
    M("단, server.py는 1,331줄(wc -l) — 라우팅·게이팅·SSE·잡 상태를 한 파일이 담는다. 진입 계층의 '얇음'은 파일 수 기준이지 코드량 기준이 아니다."),
    I("다음으로 큰 파일과 계층별 코드량은 측정하지 않았다 — '파일 수 = 복잡도'라는 오독을 막으려면 줄 수 분포를 함께 봐야 한다."),
  ],
  verdict: I("계층 간 의존 방향은 '진입 → 서비스 → 저장' 한 방향이고, 지능·AI 계층은 거버넌스 계층이 호출하는 형태다 — 순환은 아직 측정하지 않았다(arch_map으로 측정 가능, 다음 과제)."),
  notes: "모듈 수: git ls-files bts_sbom_app/*.py = 100개(2026-11-28, 커밋 d6c702c 이후, __init__ 포함). 이 덱을 만드는 동안 병행 레인이 모듈 7개(bench_gate·canary·datasheet·feedback·ft_decision·maturity·prompt_lint)를 커밋해 93→100이 되었고, 빌드의 계층 검증이 그 변경을 잡아냈다 — 커밋된 모듈만 센다. 계층 구분은 파일명·역할에 따른 아키텍트 판단이며, build 스크립트가 디렉터리 실측과 대조해 누락·중복이 없음을 확인한다. 순환 복잡도·순환 의존 측정은 arch_intel(code_intel)로 가능하지만 이번 세션에서 실행하지 않았다 → 추론으로 표기.",
});

/* ---------- 4. 설계 판단 ---------- */
add({
  sec: "4 설계 판단", title: "아키텍처 드라이버 — 품질 속성 1위는 '정직성'이다",
  sub: "유틸리티 트리: 품질 속성 → 시나리오 → 측정 응답 → 상태",
  kind: "table", fs: 10,
  cols: [{ t: "품질 속성", w: 2.3 }, { t: "시나리오 (자극 → 환경)", w: 4.2 }, { t: "측정 응답 목표", w: 4.3 }, { t: "상태", w: 2.2 }],
  rows: [
    ["정직성 (최우선)", "조회 실패·미지원 매니페스트가 0건으로 보이지 않아야", "못 찾음은 gap·unverified로 표기 — 테스트 없는 AC 0건(speclint)", M("충족")],
    ["근거 기반 AI", "근거 없는 답변·프롬프트 인젝션", "인용 정확도 1.0 · 인젝션 홀드아웃 재현율 0.18 → 1.0", M("충족(이전 실측)")],
    ["승인 후에만 변경", "토큰이 틀린 패치 요청", "변경 0건 (AC-14·15)", M("충족")],
    ["유휴 비용", "아무도 쓰지 않는 시간", "스케일 0 — 72시간 중 가동 약 5.7시간", M("충족")],
    ["첫 요청 응답성", "스케일 0 상태에서 첫 요청", "측정 35.4초 — 목표치 없음", G("SLO 미정의")],
    ["복구", "잘못된 배포", "이전 리비전 트래픽 전환 — 리비전 17개 보존", M("메커니즘 존재 · G 실행 훈련 0회")],
    ["데이터 보존", "지역 장애·삭제·랜섬", "백업 0 · 단일 리전", G("미충족")],
    ["최소 권한", "앱이 가진 Azure 권한", "시스템 할당 MI · AcrPull 1건 · 레지스트리 비밀번호 0", M("충족")],
    ["탐지 (관측)", "장애를 사용자보다 먼저 알아야", "경고 규칙 0 · HTTP 요청 로그 꺼짐", G("미충족 — 27장")],
  ],
  verdict: I("'정직성'을 기능이 아니라 품질 속성 1위로 둔 설계다 — 그래서 다른 속성(응답성·복구)을 희생하는 선택이 반복됐다. 문제는 희생이 명시되지 않았다는 것. SLO를 숫자로 못 박으면 논쟁이 끝난다."),
  notes: "테스트 없는 AC 0건: python -m bts_sbom_app.speclint (2026-11-28). 인용 정확도·홀드아웃: 과제 덱·evals 기록(이전 실측). 가동 시간: Replicas 메트릭 72h 합산 339 → 약 5.7 replica-hour. 콜드 스타트: 12장. 백업: bts-sbom-rg 인벤토리.",
});

add({
  sec: "4 설계 판단", title: "SLO 제안 — 숫자를 못 박으면 논쟁이 끝난다",
  sub: "목표는 아키텍트의 제안값(추론) · 현재 값은 측정 · 비어 있는 칸은 갭으로 둔다",
  kind: "table", fs: 10.5,
  cols: [{ t: "지표", w: 2.4 }, { t: "제안 목표 (추론)", w: 3.4 }, { t: "현재 값 (측정)", w: 4.6 }, { t: "갭", w: 3.2 }],
  rows: [
    ["첫 응답 · 워밍", I("P95 ≤ 3초"), M("/healthz 56ms · /readyz 113ms · 토큰 없는 /api 401 55ms — 부하 없는 상태 3회"), G("부하 중 P95 미측정 — HTTP 요청 로그가 꺼져 있다")],
    ["첫 응답 · 콜드", I("≤ 40초 + '기동 중' 안내"), M("35.4초 — 레플리카 0에서 1회 실측"), G("표본 1회 — 분포·재현성 미측정")],
    ["가용성", I("데모 99% · 파일럿 99.5%"), G("측정 불가 — 가동률 기록·경고가 없다"), G("SLO 정의 자체가 없음")],
    ["복구 시간 RTO", I("롤백 ≤ 10분 · 재배포 ≤ 60분"), M("리비전 17개 보존 — 전환 메커니즘은 존재"), G("전환 실측 훈련 0회")],
    ["데이터 손실 RPO", I("≤ 24시간 (백업 도입 후)"), M("백업 0 · 단일 리전 LRS · 공유 5.4MB"), G("백업 없음 — 현재는 유실 시 전체")],
    ["LLM 비용 상한", I("일일 80회 × 30일 = 2,400회/월"), M("예산 80회/일(환경변수) · 장부는 컨테이너 로컬"), I("장부가 기동마다 리셋 — 상한이 사실상 없음(코드 유도)")],
    ["처리량 (스캔)", I("NodeGoat 규모 시간당 ≥ 30건"), I("직렬 잡 1 → 이론 상한 약 37건/시간(3600초 ÷ 96초, 유도)"), G("부하 테스트 0회 — 실측 처리량 없음")],
    ["배포 안전성", I("배포 1회당 롤백률 < 5%"), M("리비전 16회 / 38시간 · 롤백 실행 0회"), G("롤백률·배포 성공률 기록 없음 — 측정 불가")],
  ],
  factsTitle: "왜 지금 숫자인가",
  facts: [
    ["SLO가 없으면 보강 논쟁이 취향 싸움이 된다", I("'경고가 필요하다'는 의견이고, 'P95 3초를 지키려면 HTTP 로그가 필요하다'는 논리다 — 이 덱의 모든 갭은 이 표의 어느 칸에서 왔는지 추적된다.")],
    ["측정 가능한 것부터", I("첫 응답·복구·RPO는 오늘도 측정할 수 있다(측정 3회 + 훈련 1회). 가용성은 경고·로그가 들어와야 측정된다 — 순서가 정해진다.")],
  ],
  verdict: I("목표는 제안값이므로 조직의 허용치로 덮어쓰면 된다. 지켜야 할 것은 '현재 값' 칸이다 — 측정이 비어 있으면 비워 두고 갭이라고 쓴다. 그것이 이 표의 유일한 규칙이다."),
  notes: "현재 값 출처: 콜드/워밍 응답은 2026-11-28 curl 타이밍(레플리카 0 상태에서 1회 + 기동 후 3회). 리비전: REST /revisions. 백업: bts-sbom-rg 인벤토리. LLM 장부: Dockerfile 주석 + server.py ledger 경로. 제안 목표는 아키텍트 판단이며 측정값이 아니다.",
});

add({
  sec: "4 설계 판단", title: "핵심 설계 판단 12건 (ADR 요약) ① — 런타임·데이터",
  sub: "판단 → 버린 대안 → 근거 → 되돌리는 조건",
  kind: "table", fs: 10,
  cols: [{ t: "판단", w: 2.1 }, { t: "채택", w: 3.0 }, { t: "버린 대안", w: 2.5 }, { t: "근거", w: 3.4 }, { t: "되돌리는 조건 (추론)", w: 2.4 }],
  rows: [
    ["의존성", M("표준 라이브러리 전용 — 선언 의존성 []"), "requests · FastAPI · numpy", I("공급망 표면 최소화 — 자기 SBOM가 의존성 없이 완결(도그푸드)"), "바이너리 분석·임베딩이 핵심이 될 때"],
    ["프로세스", M("단일 프로세스 3차선 — 동기·SSE·잡"), "web-queue-worker · Dapr", I("큐 비용·복잡도 > 단일 레플리카에서의 이득; 세마포어 벌크헤드로 대체"), "스캔 대기열이 사용자 경험을 해치는 시점"],
    ["스트리밍", M("SSE + heartbeat 15초"), "WebSocket · long-poll", I("표준 라이브러리로 충분 — 클라이언트→서버 푸시 불필요; 프록시 절단 방지"), "클라이언트 푸시 요구 발생"],
    ["영속 저장소", M("파일 — JSON 레코드 + JSONL 대장"), "PostgreSQL · Cosmos DB", I("사람이 읽는 증거·append-only 감사 대장·마이그레이션 0"), "질의·트랜잭션·다중 레플리카 쓰기 요구"],
    ["스케일", M("최소 0 → 최대 1 레플리카"), "상시 1대", I("유휴 비용 0 — 72h 중 5.7h 가동. 콜드 스타트 35.4초를 대가로 받아들임"), G("첫 요청 35초의 일 허용치 미정의")],
    ["SQLite 위치", M("쓰기 DB는 로컬, 시드만 공유"), "공유 위 SQLite", M("SMB 잠금 대기 780초 → 96초, 락 오류 0 (AC-1226~1227)"), "로컬 재생성 비용이 커지는 시점(미측정)"],
  ],
  verdict: I("여섯 판단 모두 '지금 규모에서' 옳다. 아키텍트의 일은 결정을 옹호하는 것이 아니라 결정이 틀려지는 조건을 미리 써두는 것이다 — 마지막 열이 그것이다."),
  notes: "선언 의존성 []: scripts/dogfood_gate.py의 pyproject 파싱(도그푸드 AC-1251). 큐·Dapr: 라이브 dapr 미설정. heartbeat 15초: server.py HEARTBEAT_SECONDS. SMB 잠금: AC-1226~1227. '되돌리는 조건' 열은 전부 추론이다.",
});

add({
  sec: "4 설계 판단", title: "핵심 설계 판단 12건 (ADR 요약) ② — 자격 증명·인증·운영",
  sub: "판단 → 버린 대안 → 근거 → 되돌리는 조건",
  kind: "table", fs: 10,
  cols: [{ t: "판단", w: 2.1 }, { t: "채택", w: 3.0 }, { t: "버린 대안", w: 2.5 }, { t: "근거", w: 3.4 }, { t: "되돌리는 조건 (추론)", w: 2.4 }],
  rows: [
    ["자격 증명", M("시스템 할당 MI + AcrPull 1건"), "관리자 계정 · 사용자 할당 MI · Workload Identity", M("레지스트리 비밀번호 0 · 관리자 OFF — 앱이 가진 권한은 풀 하나"), "Key Vault 연계 시 사용자 할당 + 연합 자격증명(AZURE_IDENTITY.md 방향)"],
    ["인증", M("공유 액세스 토큰 1개(최소 16자) · 실패 20회/분 → 429"), "Easy Auth 사용자 인증", I("사용자 1명의 과제·데모 — 계정 관리 비용 > 이득"), G("사용자 2명 이상 또는 감사에 '누가'가 필요할 때 — 현재 미설정")],
    ["LLM", M("외부 Azure OpenAI gpt-5-mini · 예산 80회/일 · 회로차단기 3회→60초"), "자체 호스팅 오픈모델", I("운영 비용·스펙 — 결정적 강등으로 LLM 없이도 스캔은 동작"), "예산을 상회하거나 데이터 반출이 문제 될 때(장부 리셋 결함 먼저 — 30장)"],
    ["승인", M("승인 토큰 = 계획 다이제스트"), "세션 기반 승인 · 역할 승인", I("계획이 바뀌면 토큰 무효 — 시간·사람과 무관하게 증거로 남는다"), "다단계 승인·역할 분리 요구"],
    ["이미지", M("python:3.12-slim + git · 비루트 UID 10001 · 86MB"), "디스트로리스 · 멀티스테이지", I("풀 3.7초 — 콜드 스타트의 11%. 단순 빌드·비루트"), "이미지 크기가 콜드 스타트 병목이 될 때"],
    ["배포 단위", M("리비전 = 불변 · Single 모드 · 트래픽 100% 최신"), "Blue/Green · 카나리아", I("롤백 = 트래픽 전환. 카나리아는 단일 레플리카에서 무의미"), "트래픽이 1 레플리카를 넘을 때"],
  ],
  verdict: I("여섯 판단 중 인증만 '의도한 미완'이다. 나머지는 다 대안을 이긴 선택이고, 인증은 사용자가 생기면 끝나는 임시값이다 — 임시값에 만료일이 없는 것이 리스크다."),
  notes: "MI·AcrPull: REST roleAssignments(ACR 범위, ServicePrincipal, 2026-11-27T16:35:29Z). 토큰: access.py MIN_LENGTH=16, server.py AUTH_FAIL_LIMIT=20. LLM: llm.py daily_budget 기본 80, resilience.py 3회/60초. 승인 토큰: actions.py. 이미지: Dockerfile.bts-sbom-app, 풀 로그(3.72초, 90,177,536 bytes). 리비전 모드: activeRevisionsMode Single.",
});

add({
  sec: "4 설계 판단", title: "트레이드오프 심층 — 스케일 0 · 의존성 0 · 단일 레플리카",
  sub: "얻은 것 · 잃은 것 · 지금 정당한 이유 · 재평가 트리거",
  kind: "cards", cols: 3,
  cards: [
    { title: "스케일 0 (0→1 레플리카)", tone: "info", lines: [
      I("얻은 것: ") + M("유휴 비용 0 — 72시간 중 약 5.7시간만 가동."),
      I("잃은 것: 첫 요청 35.4초 · 실행 중 작업은 종료 시 유실 · 상시 관측 불가."),
      I("지금 정당: 사용자 1명, 하루 몇 번의 요청 — 35초는 '가격'."),
      I("재평가: 첫 요청 35초를 하루 10회 넘게 겪을 때 → 최소 1 레플리카."),
    ] },
    { title: "의존성 0 (표준 라이브러리)", tone: "info", lines: [
      I("얻은 것: ") + M("공급망 표면 최소 — 자기 SBOM가 의존성 없이 완결(선언 의존성 [])."),
      I("잃은 것: 모든 기능을 직접 구현 — 개발 속도·검증된 구현의 이점."),
      I("지금 정당: 제품이 '공급망 검증'이므로 자기 자신이 첫 번째 증거다."),
      I("재평가: 바이너리 분석·임베딩처럼 stdlib로 부적절한 영역이 핵심이 될 때."),
    ] },
    { title: "단일 레플리카 · 파일 저장소", tone: "info", lines: [
      I("얻은 것: ") + M("잡 상태를 메모리에 둬도 안전 · 마이그레이션 0 · 사람이 읽는 증거."),
      I("잃은 것: 가용성 = 단일 지점 · 백업 없는 단일 리전 LRS · 질의·트랜잭션 불가."),
      I("지금 정당: 레플리카 1개가 구성의 전제(max 1)."),
      I("재평가: 레플리카 ≥ 2가 필요할 때 → 잡은 큐, 기록은 DB, 증거는 Blob."),
    ] },
  ],
  factsTitle: "대안 시나리오 비교 — 측정하지 않은 칸은 숫자를 붙이지 않고 갭으로 둔다",
  facts: [
    ["A · 지금: 스케일 0 · 레플리카 1 · 파일 저장소", [M("비용: v1 모델 ≈ $3/월(하루 1시간 가정) · 확정 청구 미확인"), M("첫 응답: 콜드 35.4초 · 워밍 56ms"), I("복구: 리비전 전환 가능(17개 보존) — 훈련 0회 · 상태: Files 1곳 + 메모리·로컬(휘발성)")]],
    ["B · 상시 1대 (최소 레플리카 1)", [G("비용: 미실측 — 공개 단가 산정 필요"), I("첫 응답: 콜드 스타트 0 · 복구·상태: A와 동일(레플리카 1)")]],
    ["C · 큐 + DB + Blob + 레플리카 ≥ 2 (33장)", [G("비용·구성 난이도: 미평가 — 트리거 도달 시 산정"), I("첫 응답: 콜드 스타트 0 + 수평 확장 · 복구: 영역 중복 가능 — 설계·훈련 필요 · 상태: 큐·DB·Blob")]],
  ],
  verdict: I("세 결정은 독립이 아니라 묶여 있다 — '단일 레플리카'가 무너지면 나머지 둘도 함께 재검토해야 한다. 그래서 진화 로드맵의 분기점은 하나다: 레플리카 수."),
  notes: "세 트레이드오프의 '얻은 것' 중 측정 가능한 것만 측정 태그를 붙였다. 나머지는 추론이다.",
});

add({
  sec: "4 설계 판단", title: "구성의 진실은 어디에 있나 — 저장소가 말하는 것과 라이브가 말하는 것",
  sub: "deploy/azure/containerapp.applied.yaml (11-23 스냅샷) 대 라이브 (11-28 REST)",
  kind: "table", fs: 10.5, then: "cards", thenCols: 2,
  cols: [{ t: "항목", w: 2.2 }, { t: "저장소의 applied.yaml", w: 4.6 }, { t: "라이브 (REST·az show)", w: 6.2 }],
  rows: [
    ["리비전·이미지", "latestReady = bts-sbom--0000002 · 0.5.0-uboot2", M("bts-sbom--0000016 · ir-20261128b · 트래픽 100%")],
    ["레지스트리", "btsbomacr1123 · acr-password 시크릿 · 사용자 이름 포함", M("btsbomacr1126 · identity: system · 비밀번호 시크릿 없음")],
    ["자격 증명", "identity: None", M("시스템 할당 MI · AcrPull 1건")],
    ["OSV DB 경로", "/tmp/evidence/… (공유 위 DB)", M("/tmp/osvdb/… (로컬) + 시드 /tmp/evidence/…")],
    ["환경 도메인", "…yellowdesert-…", M("…wittyforest-… (환경이 11-26 재창출됨)")],
  ],
  cards: [
    { title: "왜 위험한가 (추론)", tone: "gap", lines: [
      I("재배포 절차가 이 파일을 믿으면 옛 결함이 부활한다 — 비밀번호 풀(acr-password)과 공유 위 DB(780초 사건)."),
      I("라이브가 유일한 진실의 원천 → 변경 이력이 git이 아니라 활동 로그에만 남는다."),
    ] },
    { title: "권장 수순", tone: "ok", lines: [
      I("① 라이브에서 export → 마스킹 → PR (구성 드리프트 게이트): 적용값이 문서와 다르면 빌드 실패."),
      M("② 위생: 현재 파일에 구독 ID·작성자 이메일이 그대로 있다 — 공개 저장소이므로 마스킹 대상."),
    ] },
  ],
  verdict: I("라이브가 진실이면 저장소는 거짓말을 하고 있다. '적용됨'이라는 이름의 파일이 가장 오래된 거짓말이다 — 배포 파이프라인에 드리프트 게이트를 넣는 것이 정답이다."),
  notes: "저장소 파일: deploy/azure/containerapp.applied.yaml (systemData createdAt 2026-11-23, latestReady 0000002, registries btsbomacr1123 + passwordSecretRef acr-password, identity None). 라이브: az containerapp show (registry identity system, identity SystemAssigned, env BTS_SBOM_OSV_DB_PATH/SEED_DB). 환경 생성: az containerapp env show systemData.createdAt 2026-11-26T17:43Z. 구독 ID·이메일 포함 여부는 파일을 직접 읽어 확인했다.",
});

/* ---------- 5. 분석 ---------- */
add({
  sec: "5 분석", title: "장애 모드 분석 (FMEA) — 10개 시나리오, 탐지는 프로브 하나",
  sub: "현재 동작은 코드·플랫폼 설정에서 읽었다 · RTO는 판단",
  kind: "table", fs: 9.5,
  cols: [{ t: "장애", w: 2.6 }, { t: "영향", w: 2.5 }, { t: "현재 동작 (근거)", w: 4.7 }, { t: "탐지", w: 2.2 }, { t: "격차", w: 3.0 }],
  rows: [
    ["Azure Files 마운트 실패·지역 장애", "기동 실패 또는 증거 전체 유실", M("스타트업 프로브 예산 125초 후 실패 · 백업 0"), "프로브·활동 로그", G("백업·스냅샷 0 — RTO 미실측")],
    ["잘못된 배포", "오류 버전 서빙", M("프로브 실패 시 트래픽 미전환 · 이전 리비전 16개 보존"), "스모크 스크립트", G("롤백 훈련 0회 — RTO 분 단위(판단)")],
    ["Azure OpenAI 429·지연", "답변 지연·실패", M("회로차단기 3회→60초 · 일일 예산 80회 · 결정적 강등"), "클라이언트·장부", I("장부가 기동마다 리셋(코드 유도)")],
    ["OSV·deps.dev·Git 호스트 불통", "취약점·라이선스 미조회", M("회로차단기 + 갭 공시 — 0건으로 위장하지 않음"), "결과의 갭 표시", "없음(설계대로)"],
    ["대형 저장소로 메모리 초과", "컨테이너 재시작·스캔 중단", M("1Gi 한도 · 72h 최대 워킹셋 121MiB"), G("RestartCount LA 미수집"), G("OOM 원인 귀속 불가")],
    ["콜드 스타트", "첫 요청 35.4초 대기", M("요청을 35초 유지 후 응답"), "없음", G("SLO·예열 없음")],
    ["토큰·API 키 유출", "전체 데이터 노출·비용 발생", M("토큰 1개 · 실패 20회/분 → 429 · HTTPS 강제"), "없음", G("로테이션 절차 없음 — 수동 재발급")],
    ["환경변수 오타·시크릿 유실", "기동 실패", M("스타트업 프로브가 트래픽 전에 차단"), "프로브", "없음(설계대로)"],
    ["실행 중 SIGTERM", "스캔 중단", M("드레인 20초 — 신규 503, 진행 잡 완료 대기"), "없음", G("플랫폼 유예(미지정)와 대조 필요")],
    ["환경 재창출로 진단 설정 유실", "로그 없이 동작(맹목)", I("진단 설정은 환경 리소스에만 있고 IaC에 없음 — 23장"), "인벤토리 비교", G("IaC 미반영")],
  ],
  verdict: I("10개 중 7개의 '탐지'가 프로브·수동에 의존한다. 알림이 없는 탐지는 탐지가 아니라 발견이다 — 장애를 사용자가 먼저 알게 된다."),
  notes: "전 항목의 '현재 동작'은 이 덱의 측정값을 재인용한다(프로브: az containerapp show; 회로차단기: resilience.py; 워킹셋: Azure Monitor; 드레인: server.py begin_drain(20.0); 진단 설정: az rest diagnosticSettings — 환경에만 존재). '탐지' 열: 경고 규칙 0건이므로 자동 알림 경로가 없다.",
});

add({
  sec: "5 분석", title: "위협 모델 (STRIDE) — 여섯 범주, 완화와 잔여 리스크",
  sub: "완화는 코드·플랫폼 설정에서 읽었다 · 잔여 리스크는 판단",
  kind: "table", fs: 10,
  cols: [{ t: "위협", w: 2.2 }, { t: "진입점·자산", w: 2.9 }, { t: "완화 (근거)", w: 4.6 }, { t: "잔여 리스크 (추론)", w: 5.1 }],
  rows: [
    ["Spoofing 스푸핑", "공용 인그레스", M("공유 토큰(최소 16자) · HTTPS 강제 · 실패 20회/분 → 429"), I("토큰이 1개라 모든 사용자가 같은 신원 — 유출 시 전체 노출")],
    ["Tampering 변조", "증거 폴더 · 이미지", M("append-only JSONL 대장 · 승인 토큰=다이제스트 · 레지스트리 MI 전용 풀 · 비루트 UID"), G("증거 무결성 서명 없음 · 이미지 서명 없음(ACR 신뢰 정책 OFF)")],
    ["Repudiation 부인", "승인·적용 행위", M("approvals.jsonl — 시도 전부 기록(actor·시각·digest_mismatch 포함)"), I("actor가 호출자 id일 뿐 — 공유 토큰이라 사람 구분 불가")],
    ["Info Disclosure 노출", "스캔 소스·API 키·로그", M("PII 마스킹 · 시크릿 스캔 · 키는 플랫폼 시크릿 · 500 응답에 트레이스백 없음"), I("토큰 획득자가 전체 프로젝트 열람 · ACR·Storage 공용 엔드포인트")],
    ["DoS 서비스 거부", "모든 진입점", M("소켓 128 · 잡 1 · 채팅 4 · 호출자 30회/분 · 질문 4,000자 · git 600초 타임아웃"), I("단일 레플리카 — 한도 초과 시 503/429로 전환(가용성 희생은 설계)")],
    ["Elevation 권한 상승", "도구 호출·패치 적용", M("승인 체인(사람의 클릭) · 소스 경계 ALLOWED_ROOTS · 격리 워크카피 · 회귀 시 자동 복구"), I("챗 도구가 쓰기 가능(CHAT_ACTIONS=1) — 승인 우회 경로 점검은 계속 필요")],
  ],
  factsTitle: "보강 우선순위 — 잔여 리스크 열에서 나온다",
  facts: [
    ["① ID — 사용자 구분 (Easy Auth)", [I("트리거: 사용자 ≥ 2 또는 감사에 '누가'가 필요할 때"), M("현재 미설정 — az containerapp auth show = {} · 토큰 1개")]],
    ["② 서명 — 이미지·증거 무결성", [M("ACR 신뢰 정책 OFF(Notary) · 증거 무결성 서명 없음"), I("제안: cosign 서명 + ACR 신뢰 정책, 증거는 불변성 정책 또는 해시 체인 — 비용·난이도 미평가")]],
    ["③ 네트워크 — 프라이빗 엔드포인트", [M("ACR·Storage 공용 네트워크 허용 · IP 제한 없음"), I("소비형 환경은 VNet 통합이 불가 — 워크로드 프로필 환경(33장)이 전제")]],
  ],
  verdict: I("완화 목록은 '코드가 하는 일'이다. 잔여 리스크 열은 '플랫폼이 안 하는 일'이다 — 보강 우선순위는 후자에서 나온다: ID(사용자 구분) → 서명(이미지·증거) → 네트워크(프라이빗 엔드포인트)."),
  notes: "완화 항목 근거: access.py·server.py(토큰·속도 제한·한도), actions.py(감사 대장·승인 토큰), Dockerfile(비루트), ACR 설정(az acr show — trustPolicy disabled), PII/시크릿 스캔(pii_guard.py·secretscan.py), 소스 경계(환경변수 BTS_SBOM_ALLOWED_ROOTS), CHAT_ACTIONS=1(라이브 환경변수).",
});

add({
  sec: "5 분석", title: "용량·성능 모델 — 자원의 73~88%가 비어 있다",
  sub: "Azure Monitor 앱 메트릭 · 최근 72시간 · 시간별 최대값",
  kind: "bars",
  bars: [
    { label: "메모리 (최대 워킹셋)", value: 120.7, max: 1024, display: "120.7MiB / 1,024MiB", note: "12% — 8배 여유", tone: "ok" },
    { label: "CPU (최대 사용)", value: 0.135, max: 0.5, display: "0.135 / 0.5 코어", note: "27% — 3.7배 여유", tone: "ok" },
    { label: "공유 evidence 용량", value: 5.4, max: 2048, display: "5.4MB / 2,048MB", note: "0.26% — 사실상 비어 있음", tone: "ok" },
    { label: "트래픽 (72시간 요청)", value: 518, max: 10000, display: "518건 (시간당 최대 36)", note: "순수 데모 부하 — 한도 검증 안 됨", tone: "info" },
    { label: "임시 디스크 2Gi", value: 1, max: 2048, display: "미측정", note: "체크아웃·OSV DB·장부가 여기 산다", tone: "gap" },
  ],
  cards: [
    { title: "측정된 부하", tone: "info", lines: [
      M("NodeGoat 원격 스캔 96초 — 컴포넌트 1,091 · 취약점 311 (라이브)."),
      M("u-boot v2026.10 — 68 컴포넌트 · 43 취약점 · 라이선스 96% 해석."),
      M("72h 최대 워킹셋 121MiB · 재시작 4회(원인 미귀속)."),
      G("임시 디스크 사용량은 플랫폼 메트릭에 없다 — 미측정."),
    ] },
    { title: "한계 해석 (추론)", tone: "warn", lines: [
      I("천장은 CPU·메모리가 아니라 '직렬 큐(잡 1)' — 처리량 ≈ 1/스캔시간 = NodeGoat 규모 시간당 약 37건(이론 상한)."),
      I("임시 디스크 2Gi가 두 번째 천장 — 대형 저장소 체크아웃은 거부·갭으로 이어진다."),
      I("그래서 첫 실험은 '잡 동시성 2' — 메모리 여유(8배)를 쓰고 처리량 2배를 노린다. 환경변수 하나(BTS_SBOM_MAX_JOBS)로 측정 후 되돌릴 수 있다."),
    ] },
  ],
  verdict: I("지금 병목은 자원이 아니라 대기(직렬 큐)와 콜드 스타트다. 증설은 순서가 아니다 — 잡 동시성을 2로 올리는 실험이 증설보다 앞선다."),
  notes: "메트릭: az monitor metrics list --resource <app> --offset 72h --interval PT1H (WorkingSetBytes max 126,574,592; UsageNanoCores max 135,463,876; Requests total 518 / max 36; RestartCount total 4). 공유 사용량: share-rm stats. NodeGoat·u-boot: 과제 덱·evidence/runs 기록. 처리량 상한은 산술 유도(3600/96). 임시 디스크 사용량은 플랫폼 메트릭에 없어 미측정.",
});

add({
  sec: "5 분석", title: "관측 가능성 — 보이는 것과 안 보이는 것",
  sub: "이 시스템은 '증거'를 파는 제품이면서 자기 증거는 남기지 않는다",
  kind: "cards", cols: 2,
  cards: [
    { title: "보이는 것 (측정)", icon: "monitor", tone: "ok", lines: [
      M("healthz / readyz 의미 분리 — 프로세스 vs 의존성·증거 폴더 쓰기."),
      M("LA 콘솔·시스템 로그 — 보존 30일, 3일치 수집량 사실상 0GB."),
      M("상관 ID — X-Correlation-ID = final.trace_id = 잡 레코드 trace = 에스컬레이션 payload."),
      M("메트릭 저장소 — 앱 메트릭(요청·워킹셋·재시작)은 93일간 조회 가능(이번 분석도 여기서 읽었다)."),
      M("LLM 비용 장부 — 호출 수·비용을 호출자별로 기록."),
    ] },
    { title: "안 보이는 것 (갭)", icon: "app_insights", tone: "gap", lines: [
      G("경고 규칙 0 · 액션 그룹 0 — 장애를 사용자가 먼저 알게 된다."),
      G("HTTP 요청 로그 꺼짐(ContainerAppHTTPLogs) — 상태코드·지연 이력 없음."),
      G("앱 메트릭의 LA 수집 없음 — 차트·경고 쿼리 불가(메트릭 저장소에만 있음)."),
      G("분산 추적 없음(App Insights 0) · SLO 정의 없음 · 재시작 4회 원인 미귀속."),
    ] },
  ],
  factsTitle: "고치는 데 드는 것 — 플랫폼 설정이 대부분, 앱 코드 변경은 거의 0",
  facts: [
    ["경고 규칙 3개 + 액션 그룹 1개", [I("5xx 비율 · 재시작 > 0 · readyz 실패 → 이메일 — az monitor 리소스 4개, 30분 작업(판단)"), I("비용 거의 0(경고 건당 소액) — 미실측")]],
    ["HTTP 요청 로그 켜기", [I("환경 진단 설정에 ContainerAppHTTPLogs 추가 — 설정 1줄"), G("수집량 미측정 — 트래픽 518건/72h라 무시할 수준(판단)")]],
    ["앱 진단 설정(AllMetrics)", [I("앱 리소스에 진단 설정 추가 → 워킹셋·재시작·요청이 LA로 — 차트·경고 쿼리 가능"), G("수집량 미측정")]],
    ["Files 백업", [I("공유 스냅샷 또는 Backup Vault(일 1회) + 복원 훈련 1회"), G("비용·복원 시간 미측정")]],
    ["LLM 장부 위치", [I("ledger 경로를 공유 볼륨으로 — 코드 1줄 + 쓰기 빈도 확인(SMB 부담)"), I("비용 0 — 쓰기 빈도가 높으면 공유에 부담(코드 유도)")]],
  ],
  verdict: I("가장 값싼 수정이 가장 어색한 결함이다 — 요청 로그와 앱 메트릭을 켜는 것은 설정 몇 개이고, 그것만으로 FMEA의 '탐지' 열 7칸이 채워진다."),
  notes: "진단 설정: az rest .../diagnosticSettings (환경 'to-btsbom-logs': ConsoleLogs·SystemLogs·AllMetrics on, HTTPLogs off; 앱 리소스: 없음). 경고: az monitor metrics alert list = 0. App Insights: bts-sbom-rg 리소스 목록에 없음. 상관 ID: server.py(A C-1256). 재시작 4회: RestartCount 합산(72h). 메트릭 저장소 보존 93일은 Azure Monitor 기본값(이 구독에서 별도 확인 안 함).",
});

add({
  sec: "5 분석", title: "비용 모델 — 월 몇 달러는 설계가 아니라 부재의 결과다",
  sub: "공개 단가 기반(v1 측정 모델) + 이번 실측 · 확정 청구액은 미확인",
  kind: "table", fs: 10.5,
  cols: [{ t: "구성요소", w: 2.6 }, { t: "과금 단위", w: 2.8 }, { t: "측정·추정", w: 4.2 }, { t: "드라이버", w: 3.2 }],
  rows: [
    ["[icon:container_apps] Container Apps", "사용 시간(vCPU·메모리·초)", M("72h 중 약 5.7시간 가동 · v1 모델 약 $3/월(하루 1시간 가정, 공개 단가)"), I("첫 요청 빈도 — 사람이 쓰는 만큼만")],
    ["[icon:acr] ACR Basic", "일일 요금", M("약 $5/월 — Basic 고정(v1 모델)"), "상시 고정"],
    ["[icon:files] Azure Files 2Gi", "용량·트랜잭션", M("약 $0.4/월(Standard_LRS·v1 모델) · 실사용 5.4MB"), "증거 증가량"],
    ["[icon:log_analytics] Log Analytics", "수집 GB", M("지난 7일 0.004GB — 사실상 0"), G("HTTP 로그·앱 메트릭을 켜면 증가(미측정)")],
    ["[icon:openai] Azure OpenAI", "토큰", M("일일 호출 예산 80회 · 장부는 기동마다 리셋(코드 유도)"), I("챗 사용량 · 장부 수정이 선행 조건")],
    { row: ["확정 청구액", "—", G("az consumption usage list가 Web Direct 구독에서 빈 결과 — 포털 Cost Management 확인 필요"), "—"], gapRow: true },
  ],
  factsTitle: "아직 측정하지 않은 비용 질문 — 숫자를 붙이지 않고 적는다",
  facts: [
    ["하루 30분 쓰는 파일럿", I("가동 ≈ 15시간/월 → 컴퓨트는 v1 모델(하루 1시간 ≈ $3)의 절반가량 — 추정, 미실측")],
    ["상시 1대(콜드 스타트 0)", G("공개 단가 산정 필요 — 이 덱은 숫자를 붙이지 않는다")],
    ["스케일 0의 숨은 조건", I("무응답 쿨다운(라이브 API 미반환 · 기본 300초 추정) 뒤 축소 — 주기 ping·헬스체크를 붙이는 순간 상시 기동이 된다")],
    ["LLM 상한", I("일일 80회 × 30일 = 2,400회/월 상한 — 장부가 기동마다 리셋되면 상한이 아니다(코드 유도)")],
  ],
  verdict: I("진짜 비용 질문은 '월 $3이냐'가 아니라 '하루 30분 쓰는 파일럿의 월 비용은 얼마냐'다 — 아직 측정하지 않았다. 스케일 0을 유지하려면 주기 ping(예열·모니터링)이 상시 기동을 만든다는 함정도 함께 설계해야 한다."),
  notes: "v1 비용 모델: AZURE_OPERATIONS_OVERVIEW v1 12장(공개 단가 × 가정 — 견적이 아닌 모델). 가동 시간: Replicas 메트릭 합산 339분/72h. LA 수집: Usage 테이블 7일(AzureMetrics 0.004GB, 로그 ≈0). 청구: az consumption usage list → Web Direct 오류/빈 결과. 쿨다운 300초는 API 미반환(기본값 추정) → 주기 ping이 스케일 0을 깨는지는 실측 필요(갭).",
});

/* ---------- 6. 리스크·부채·진화 ---------- */
add({
  sec: "6 리스크·진화", title: "리스크 레지스터 — 중요도 × 가능도, 10건",
  sub: "위치는 아키텍트 판단 · 각 리스크의 '지금 상태'는 이 덱의 측정값",
  kind: "matrix",
  risks: [
    { id: "R1", sev: 3, lik: 2, t: "공유 토큰 유출 → 전체 데이터 노출", mit: "Easy Auth 도입 + 토큰 폐기", trig: "사용자 2명 이상" },
    { id: "R2", sev: 3, lik: 2, t: "증거 저장소 유실 — 백업 0 · 단일 리전 LRS", mit: "Files 백업(또는 스냅샷) + 복원 훈련 1회", trig: "지금" },
    { id: "R3", sev: 3, lik: 2, t: "장애 인지 지연 — 경고 규칙 0", mit: "경고 규칙 3개 + 액션 그룹 1개", trig: "지금" },
    { id: "R4", sev: 2, lik: 3, t: "콜드 스타트 35초가 첫인상", mit: "최소 레플리카 1 또는 예열 ping", trig: "일 첫 요청 10회" },
    { id: "R5", sev: 2, lik: 3, t: "LLM 예산 장부가 기동마다 리셋 — 비용 상한 무력화", mit: "장부를 공유 볼륨으로 이동(쓰기 빈도 고려)", trig: "지금" },
    { id: "R6", sev: 2, lik: 2, t: "IaC 드리프트 — 재배포 시 비밀번호 풀·공유 위 DB 부활", mit: "라이브 export 자동화 + 드리프트 게이트", trig: "다음 배포 전" },
    { id: "R7", sev: 2, lik: 2, t: "의존성 0 유지 비용 — 직접 구현의 결함", mit: "계층별 테스트 밀도 유지·외부 구현과 비교 평가", trig: "결함 재현율 상승" },
    { id: "R8", sev: 1, lik: 3, t: "스케일 0·메모리 상태 → 종료 시 실행 중 스캔 유실", mit: "잡 체크포인트 또는 큐", trig: "레플리카 2 이상" },
    { id: "R9", sev: 2, lik: 1, t: "공용 PaaS 엔드포인트(ACR·Storage) 노출", mit: "프라이빗 엔드포인트 · IP 제한", trig: "테넌트 분리 필요" },
    { id: "R10", sev: 1, lik: 3, t: "공개 저장소 구성 파일에 구독 ID·이메일", mit: "마스킹 후 재커밋", trig: "지금" },
  ],
  verdict: I("중요도 3인 리스크는 셋(R1·R2·R3)이고 셋 다 '할 일이 명확하고 비용이 거의 0'이다 — 방치할 이유가 없다. R1은 사용자가 늘어나야 현실화되지만, R2·R3은 오늘도 이자가 붙는다."),
  notes: "리스크의 사실관계는 이 덱의 측정값: 토큰 1개(auth show = {}·secrets 이름), 백업 0(인벤토리), 경고 0(az monitor metrics alert list), 콜드 스타트 35.4초(curl), LLM 장부 로컬(Dockerfile 주석), applied.yaml 나이(파일 생성 시각 11-23), 공용 PaaS(az acr show·az storage account show), 구독 ID·이메일(applied.yaml을 직접 읽음). 중요도·가능도·완화·트리거는 아키텍트 판단이다.",
});

add({
  sec: "6 리스크·진화", title: "기술 부채 — 양이 아니라 이자율이 문제다",
  sub: "부채 · 증거 · 지금 내는 이자 · 상환 방향",
  kind: "table", fs: 10,
  cols: [{ t: "부채", w: 2.9 }, { t: "증거", w: 3.2 }, { t: "이자 (지금 내는 대가)", w: 3.3 }, { t: "상환 방향 (추론)", w: 3.4 }],
  rows: [
    ["LLM 장부가 휘발성 디스크", M("Dockerfile 주석 · server.py ledger=<root>/evidence"), I("일일 상한이 기동당 상한으로 — 비용 보호 무력화"), "장부를 공유 볼륨(evidence)으로 — 쓰기 빈도·SMB 비용 먼저 측정"],
    ["경고 0 · 백업 0", M("bts-sbom-rg 인벤토리 5개"), "무경보·무복구 — R2·R3", "경고 3개·액션 그룹·Files 백업"],
    ["HTTP 로그·앱 메트릭 미수집", M("진단 설정 — HTTPLogs off · 앱 설정 없음"), "문제 재구성 불가 — 재시작 4회 원인 미귀속", "진단 설정 추가(코드 변경 0)"],
    ["applied.yaml 나이(11-23)", M("latestReady 0000002 · acr-password"), "재배포 시 옛 결함 부활", "라이브 export 자동화·드리프트 게이트"],
    ["인젝션 가드 정규식 기반", M("개발셋 오탐 1건·부정문 취약(과제 덱 기록)"), "프롬프트 인젝션 변형에 취약", "의미 기반 2차 판정·홀드아웃 확대"],
    ["기록이 파일(JSON·JSONL)", M("evidence 폴더 구조 — 코드 grep"), "질의·트랜잭션·다중 레플리카 쓰기 불가", "트리거 도달 시 DB — 32장"],
    ["재분석 후보 49개 미구현", M("docs/METANET_FULL_REANALYSIS.md §4"), "기능 갭", "점수순 구현"],
  ],
  factsTitle: "상환 계획 — 복리 부채부터, 한 세션 안에",
  facts: [
    ["① LLM 장부 위치", I("ledger를 공유 볼륨으로 옮기고 테스트 1개 추가 — 코드 1줄, 리스크 R5")],
    ["② 경고·백업", I("경고 규칙 3개·액션 그룹·Files 백업·복원 훈련 — 플랫폼 설정, 리스크 R2·R3")],
    ["③ 관측", I("HTTP 요청 로그·앱 메트릭 수집 — 재시작 4회의 원인을 귀속할 수 있게 된다")],
    ["④ 나머지", I("무이자 부채(파일 저장소·재분석 후보 49개)는 트리거가 올 때까지 갚지 않는다 — 서둘러 갚으면 단순함을 잃는다")],
  ],
  verdict: I("이 목록에서 이자가 매일 복리로 붙는 것은 '장부 리셋'과 '경보 부재' 둘뿐이다. 나머지는 거의 무이자다 — 그래서 먼저 갚을 것은 이 둘이다."),
  notes: "인젝션 가드: 과제 덱(성과·한계 장) 기록. 미등록 AC: 2026-11-28 첫 측정에서 2건(BSA-AC-1264·1265)이었으나 같은 날 병행 레인이 명세 등록을 마감해 재측정 0건(총 675) — 해소된 부채는 목록에서 뺐다. 재분석 후보: METANET_FULL_REANALYSIS.md §4 후속 49목록(이전 세션 집계). 나머지 증거는 이 덱의 측정값.",
});

add({
  sec: "6 리스크·진화", title: "Well-Architected 자체 평가 — 기준은 '증거가 있는가'",
  sub: "다섯 기둥 · 상태 · 근거 · 다음 보강 · 판단은 아키텍트 자체 평가",
  kind: "table", fs: 10,
  cols: [{ t: "기둥", w: 2.2 }, { t: "상태", w: 2.6 }, { t: "근거", w: 4.6 }, { t: "다음 보강", w: 3.4 }],
  rows: [
    ["안정성 Reliability", I("데모 적합 · 파일럿 미흡"), M("리비전 17 보존 · 프로브 3종 · SIGTERM 드레인 20초 / 단일 지역 · 백업 0 · 경고 0"), "백업·경고·롤백 훈련 1회"],
    ["보안 Security", I("데모 적합"), M("MI·HTTPS 강제·토큰 게이트·속도 제한·비루트 / 공유 토큰 1개·공용 PaaS·서명 없음"), "Easy Auth·프라이빗 엔드포인트·이미지 서명"],
    ["비용 Cost", I("우수 · 청구 미확인"), M("스케일 0 — 72h 중 5.7h 가동 / 확정 청구액 CLI 조회 불가(Web Direct)"), "예산 경보·청구액 월 1회 대조"],
    ["운영 우수성 OpsEx", I("우수 · 드리프트 있음"), M("리비전 불변·스모크 스크립트·도그푸드·야간 드리프트 / applied.yaml 나이·롤백 훈련 0회"), "라이브 export 자동화·게임데이(복구 훈련)"],
    ["성능 효율 P+E", I("여유"), M("워킹셋 12% · CPU 27% / 콜드 스타트 35.4초"), "최소 레플리카 1 또는 예열(트리거 기준)"],
  ],
  factsTitle: "교차 검증 — 제품 안의 자가 진단 도구와 비교한다",
  facts: [
    ["병행 레인의 도구 (d6c702c)", M("maturity.py(MLOps 성숙도 자가 진단) · bench_gate.py(벤치 회귀 게이트) · canary.py(카나리아 판단·롤백 트리거) — 커밋된 모듈, docstring으로 역할 확인")],
    ["실행 여부", G("이번 세션에서 실행하지 않았다 — 이 자체 평가와의 교차 검증은 다음 과제. '판단 능력이 있다'와 '훈련했다'는 다르다")],
    ["롤백", [M("canary.py는 롤백 트리거를 숫자로 판정하는 결정 함수(az 호출 없음) — 문서화된 기준이 생겼다"), G("리비전 전환 실측 훈련은 여전히 0회")]],
  ],
  verdict: I("자체 평가라 관대할 유혹이 있다. 기준은 하나로 삼았다: '증거가 있는가'. 없는 칸은 비워두지 않고 갭으로 적었다 — 이 표에서 갭이 가장 많은 기둥이 안정성이다."),
  notes: "자체 평가: 각 기둥의 상태·다음 보강은 아키텍트 판단, 근거 열은 이 덱의 측정값(리비전·프로브·드레인·인벤토리·MI·메트릭·콜드 스타트). Well-Architected 5기둥 구분은 Microsoft Azure Well-Architected Framework의 일반 구조를 참고했으며 공식 평가 도구로 채점하지 않았다.",
});

add({
  sec: "6 리스크·진화", title: "진화 로드맵 — 날짜가 아니라 트리거로 쓴다",
  sub: "세 단계 · 각 단계의 입구는 측정 가능한 조건이다",
  kind: "phases",
  phases: [
    { n: "지금", t: "데모 — 유지 + 즉시 보강", tone: "info", trig: "입구: 지금", items: [
      M("유지: 리비전 롤백 · MI 풀 · 스케일 0 · 단일 레플리카"),
      I("경고 3개(5xx·재시작·readyz) + 액션 그룹 1개 — 비용 거의 0"),
      I("HTTP 로그·앱 메트릭 수집 켜기 — 코드 변경 0"),
      I("Files 백업(또는 스냅샷) + 복원 훈련 1회"),
      I("LLM 장부 위치 수정 · applied.yaml 재 export"),
      I("canary.py의 롤백 트리거를 RUNBOOK 숫자로 채택 — 병행 레인 d6c702c"),
      I("공개 저장소 구성 파일 마스킹(구독 ID·이메일)"),
    ] },
    { n: "다음", t: "파일럿 — 사용자가 생긴다", tone: "warn", trig: I("입구: 사용자 ≥ 2 또는 일 첫 요청 ≥ 10회"), items: [
      I("Easy Auth(Entra ID) 사용자 인증 + 토큰 폐기"),
      I("Key Vault + Workload Identity — 시크릿 5종 이관"),
      I("최소 레플리카 1 또는 예열 — 콜드 스타트 0"),
      I("LLM 장부 공유 볼륨 · 일일 비용 상한 경보"),
      I("롤백·복구 절차를 RUNBOOK에 '실행 기록'으로"),
      I("스케일 규칙 명시(쿨다운·동시 요청)와 예열 ping — 상시 기동 여부를 데이터로 결정"),
      I("역할 기반 토큰(운영자·감사자) — 승인 대장에 '누가'가 기록되게"),
      I("앱 메트릭 기반 SLO 대시보드·오차 예산"),
    ] },
    { n: "그다음", t: "프로덕션 — 증거가 감사 증거가 된다", tone: "gap", trig: I("입구: 감사 증거 사용 또는 레플리카 ≥ 2"), items: [
      I("잡 상태 → 큐(Service Bus) · 기록 → DB(PostgreSQL)"),
      I("증거 → Blob 보관 + Backup Vault · 영역 중복·지역 복제"),
      I("워크로드 프로필 환경 — VNet 통합·프라이빗 엔드포인트"),
      I("Front Door + WAF · 이미지 서명(cosign/ACR 신뢰 정책)"),
      I("SLO 정의(가용성·첫 응답·복구 시간)와 오차 예산"),
      I("재해 복구 훈련(연 1회)·지역 페일오버 절차"),
      I("이미지 SBOM·출처 증명(SLSA)·서명 검증을 배포 파이프라인에"),
      I("비용 모델 재산정 — 상시·다중 리전"),
    ] },
  ],
  verdict: I("로드맵에 날짜가 없다 — 트리거가 있다. 날짜는 희망이고 트리거는 측정이다. 분기점은 하나: 레플리카 수. 레플리카가 2가 되는 순간 큐·DB·ID가 동시에 필요해진다."),
  notes: "트리거 수치(사용자 2명, 일 첫 요청 10회)는 아키텍트가 제안하는 임계값이며 측정값이 아니다 — 조직의 허용치로 조정해야 한다. 기술 선택(Service Bus·PostgreSQL·Blob·Front Door·WAF)은 Azure 아키텍처 센터의 일반적 지침에 따른 제안이고, 프로젝트에서 채택·검증한 것은 아니다(AZURE_ARCHITECTURE_CENTER_APPLIED.md는 As-Is 적용분만 다룬다).",
});

add({
  sec: "6 리스크·진화", title: "목표 아키텍처 (To-Be) — 바뀌는 것은 상태의 위치다",
  sub: "제안안 · 점선 = 아직 없는 구성요소 · 공식 Azure 아이콘",
  kind: "diagram", proposal: true,
  zones: [
    { x: 36, y: 120, w: 220, h: 420, label: "사용자", tone: "outer" },
    { x: 268, y: 120, w: 700, h: 420, label: "Azure — 가상 네트워크 안 (제안)", tone: "vnet" },
    { x: 500, y: 254, w: 464, h: 148, label: "상태의 새 위치 — 잡 enqueue · 기록 · 증거", tone: "inner", b: 3 },
    { x: 980, y: 120, w: 264, h: 420, label: "외부·별도", tone: "outer" },
  ],
  nodes: [
    { id: "user", x: 44, y: 150, w: 170, h: 88, icon: "browser", title: "사용자", sub: ["여러 명 · Entra ID 계정", "역할별 접근"], b: 1 },
    { id: "fd", x: 288, y: 150, w: 200, h: 88, icon: "front_door", title: "Front Door + WAF", sub: ["글로벌 진입 · WAF 정책", "Entra ID(Easy Auth)"], b: 1 },
    { id: "kv", x: 512, y: 150, w: 170, h: 88, icon: "key_vault", title: "Key Vault", sub: ["시크릿·토큰", "WI 연합 자격 증명"], b: 2 },
    { id: "mon", x: 706, y: 150, w: 148, h: 88, icon: "monitor", title: "Monitor", sub: ["경고 규칙 · 액션 그룹", "SLO · App Insights"], b: 4 },
    { id: "aca", x: 288, y: 262, w: 200, h: 132, icon: "container_apps_env", title: "ACA 환경", sub: ["워크로드 프로필 · VNet 통합", "영역 중복 · 앱 ≥ 2 레플리카", "워커 레플리카(잡 전담)", "App Insights 추적"], b: 2, tone: "hi" },
    { id: "sb", x: 512, y: 284, w: 170, h: 110, icon: "service_bus", title: "Service Bus", sub: ["잡 큐 · 상태 외부화", "스캔·배치·야간"], b: 3 },
    { id: "pg", x: 706, y: 284, w: 148, h: 110, icon: "sql", title: "PostgreSQL", sub: ["프로젝트·판정 기록", "트랜잭션·질의"], b: 3 },
    { id: "blob", x: 874, y: 284, w: 80, h: 110, icon: "blob", title: "Blob", sub: ["증거 보관"], b: 3 },
    { id: "acr", x: 512, y: 414, w: 170, h: 88, icon: "acr", title: "ACR (Premium)", sub: ["프라이빗 엔드포인트", "지역 복제 · 이미지 서명"], b: 2 },
    { id: "bk", x: 706, y: 414, w: 148, h: 88, icon: "backup", title: "Backup", sub: ["Vault · 일 1회 백업", "복원 훈련"], b: 4 },
    { id: "oai", x: 1000, y: 150, w: 224, h: 88, icon: "openai", title: "Azure OpenAI", sub: ["gpt-5-mini · 프라이빗 연결", "일일 비용 상한(장부 영속)"], b: 4, tone: "outer" },
    { id: "ext", x: 1000, y: 262, w: 224, h: 132, title: "외부 데이터 원천", sub: ["OSV.dev · deps.dev", "패키지 레지스트리 · Git 호스트", "아웃바운드는 방화벽·프록시 경유"], b: 4, tone: "outer" },
    { id: "ext2", x: 1000, y: 414, w: 224, h: 88, title: "감사자·CI", sub: ["증거 내보내기 · 서명 검증", "SLSA 증명(제안)"], b: 4, tone: "outer" },
  ],
  edges: [
    { from: "user", to: "fd", label: "HTTPS", b: 1, lx: 220, ly: 177 },
    { from: "fd", to: "aca", b: 1, fromSide: "b", toSide: "t" },
    { from: "aca", to: "kv", b: 2, via: [470, 262, 470, 250, 560, 250, 560, 238] },
    { from: "aca", to: "acr", label: "MI 풀", b: 2, via: [388, 394, 388, 458, 512, 458], lx: 420, ly: 440 },
    { from: "aca", to: "sb", b: 3 },
    { from: "pg", to: "bk", label: "백업", b: 4, fromSide: "b", toSide: "t", dash: true, lx: 788, ly: 397 },
    { from: "aca", to: "oai", label: "HTTPS", b: 4, dash: true, via: [470, 394, 470, 526, 976, 526, 976, 194, 1000, 194], lx: 560, ly: 528 },
    { from: "aca", to: "ext", label: "HTTPS", b: 4, dash: true, via: [440, 394, 440, 514, 990, 514, 990, 328, 1000, 328], lx: 880, ly: 496 },
  ],
  legend: [I("제안안 — 존재하지 않는 구성요소다. As-Is(9장)와 비교해 '추가된 것'과 '옮겨진 것'을 읽는다: 메모리→큐, 파일→DB+Blob, 시크릿→KV, 토큰→ID. Monitor는 모든 구성요소의 원격 측정을 받는다(선 생략).")],
  verdict: I("As-Is에서 To-Be로 바뀌는 것은 서비스 목록이 아니라 '상태의 위치'다. 셋 중 하나라도 안 옮기면 멀티 레플리카는 시작되지 않는다 — 순서: ID → 큐 → DB."),
  notes: "제안 구성도. 아이콘은 공식 Azure 아키텍처 아이콘(V25). Front Door/WAF, 워크로드 프로필 환경(VNet 통합), Service Bus, PostgreSQL, Blob, Key Vault+Workload Identity, Backup Vault, App Insights, ACR Premium(프라이빗 엔드포인트·지역 복제), 이미지 서명은 Microsoft Azure 아키텍처 센터의 클라우드 디자인 패턴·Well-Architected 지침에 따른 제안이며, 비용·구성 난이도는 평가하지 않았다(갭).",
  builds: { 1: "진입 — 사용자와 글로벌 진입점", 2: "앱과 자격 증명·이미지", 3: "상태의 새 위치 — 큐·DB·Blob", 4: "관측·백업·외부" },
});

add({
  kind: "end",
  title: "아키텍트의 한 줄",
  lines: [
    "표준 라이브러리 전용 단일 컨테이너가",
    "ACA 인그레스·토큰 게이트·MI 풀·Files 영속·LA 관측 위에서",
    "정직한 단순함으로 동작한다 — 이제 안전망(경고·백업·인증·예산)을 얹을 차례다.",
  ],
  blocks: [
    { t: "지킨다", tone: "ok", items: ["리비전 불변·롤백 경로", "MI 최소 권한", "갭을 갭으로 쓰는 계약", "스케일 0 비용 모델"] },
    { t: "고친다 (비용 ≈ 0)", tone: "warn", items: ["경고 3개·액션 그룹", "HTTP 로그·앱 메트릭", "Files 백업·복원 훈련", "LLM 장부 위치·applied.yaml"] },
    { t: "트리거를 기다린다", tone: "info", items: ["사용자 ≥ 2 → Easy Auth", "첫 요청 하루 10회 → 상시 1대", "레플리카 ≥ 2 → 큐·DB·Blob"] },
  ],
  todo: { title: "지금 당장 10분 — 안전망의 시작", items: [
    "경고 규칙 1개 + 액션 그룹(이메일) — '사용자가 먼저 알게 되는 일'을 끝낸다",
    "환경 진단 설정에 HTTP 요청 로그·앱 메트릭 추가 — 코드 변경 0",
    "이전 리비전으로 트래픽을 돌렸다가 되돌리기 — 롤백 훈련 1회",
  ] },
  docs: "문서: AZURE_DEPLOYMENT.md · AZURE_IDENTITY.md · GIT_STRATEGY.md · CRA_COMPLIANCE.md · RUNBOOK.md · specs/bts_sbom_app_features.md · ADR(docs/adr) · 동적 HTML: docs/AZURE_OPERATIONS_OVERVIEW.html",
  notes: "요약 장. 모든 수치의 출처는 각 장의 발표자 노트에 있다.",
});

module.exports = { S, LAYERS, M, I, G };
