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

const SEC5 = "5 · 아키텍처 설계", SEC6 = "6 · 적용 기술", SEC7 = "7 · MECE 종합";
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
];

module.exports = { S, PLAN, LAYERS: A.LAYERS, M, I, G };
