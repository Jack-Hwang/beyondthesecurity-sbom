// build_azure_ops_deck.js — BTS-SBOM × Azure 운영 개요 덱 (docs/AZURE_OPERATIONS_OVERVIEW.pptx)
// Run: NODE_PATH="C:\Users\Administrator\.npm-global\node_modules" node usertest/build_azure_ops_deck.js
// Slide transitions are added afterwards by usertest/add_ppt_transitions.py (PowerPoint COM), since pptxgenjs
// does not author OOXML transitions. Every number in the deck is a measured/live value or names its source.
const pptxgen = require("pptxgenjs");
const path = require("path");
const fs = require("fs");

const ICONS = path.join(__dirname, "azure_icons");
const ic = (n) => path.join(ICONS, n.replace(/^ic_/, "") + ".png");
const W = 13.333, H = 7.5;
const AZ = "#0078D4", DARK = "#1A1A2E", INK = "#24243A", SUB = "#5A5A72", LINE = "#D8DEE9";
const OK = "#107C41", WARN = "#B36A00";

const p = new pptxgen();
p.defineLayout({ name: "W", width: W, height: H });
p.layout = "W";
p.author = "bts-sbom";
p.title = "BTS-SBOM × Azure 운영 아키텍처 개요";

function header(s, num, title, sub) {
  s.background = { color: "FFFFFF" };
  s.addShape("rect", { x: 0, y: 0, w: W, h: 0.16, fill: { color: AZ } });
  s.addText([{ text: title, options: { fontSize: 26, bold: true, color: INK } }], { x: 0.6, y: 0.34, w: 10.2, h: 0.6 });
  if (sub) s.addText(sub, { x: 0.62, y: 0.95, w: 11.6, h: 0.4, fontSize: 12.5, color: SUB });
  s.addText(String(num), { x: W - 0.9, y: H - 0.55, w: 0.5, h: 0.35, fontSize: 12, color: LINE, align: "right" });
  s.addText("BTS-SBOM · Azure 운영 개요 · 2026-11-28 실측", { x: 0.6, y: H - 0.55, w: 6.5, h: 0.35, fontSize: 9, color: LINE });
}
const chip = (s, x, y, w, txt, color) => {
  s.addShape("roundRect", { x, y, w, h: 0.34, rectRadius: 0.17, fill: { color } });
  s.addText(txt, { x, y, w, h: 0.34, fontSize: 10.5, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
};

/* ---- 1. 표지 ---- */
{
  const s = p.addSlide();
  s.background = { color: DARK };
  s.addImage({ path: ic("sbom"), x: 0.9, y: 1.15, w: 1.6, h: 1.6 });
  s.addImage({ path: ic("container_apps"), x: 10.9, y: 1.15, w: 1.6, h: 1.6 });
  s.addText("BTS-SBOM × Azure", { x: 0, y: 2.95, w: W, h: 1.0, fontSize: 48, bold: true, color: "FFFFFF", align: "center" });
  s.addText("운영 환경 리소스 · 전체 아키텍처 · UI 서비스 구성요소 개요", {
    x: 0, y: 4.05, w: W, h: 0.6, fontSize: 20, color: "#9CC7E8", align: "center" });
  s.addText("2026-11-28 라이브 실측 기준 · Korea Central · 리비전 bts-sbom--0000016 · 이 덱의 모든 수치는 az CLI 실측값",
    { x: 0, y: 5.6, w: W, h: 0.5, fontSize: 13, color: "#8A8FA8", align: "center" });
}

/* ---- 2. 리소스 인벤토리 ---- */
{
  const s = p.addSlide();
  header(s, 2, "Azure 운영 환경 리소스 인벤토리", "az CLI 실측 (2026-11-28) · 리소스 그룹 bts-sbom-rg · 위치 Korea Central");
  const rows = [
    ["", "리소스", "SKU/규모", "역할"],
    ["ic_container_apps", "Container Apps 환경 bts-sbom-env + 앱 bts-sbom", "Consumption · 0.5 vCPU / 1Gi", "SBOM 서비스 런타임 (단일 레플리카)"],
    ["ic_container_apps", "리비전 bts-sbom--0000016", "이미지 ir-20261128b", "현재 라이브 (트래픽 100%)"],
    ["ic_registry", "컨테이너 레지스트리 btsbomacr1126", "Basic", "이미지 저장 · 클라우드 빌드 46~50s"],
    ["ic_storage", "스토리지 계정 btsbomstg1127", "Standard_LRS · Files 공유 evidence", "분석 기록·트리아지·감사 대장 영속"],
    ["ic_logs", "Log Analytics btsbom-logs", "워크스페이스", "콘솔/시스템 로그·메트릭 수집처"],
    ["ic_identity", "시스템 할당 관리 ID (principal a597a9ae…)", "AcrPull 1건", "이미지 풀 — ACR 관리자 계정 OFF"],
    ["ic_security", "액세스 토큰 게이트", "ACA secret 5종", "프로브 외 전 요청 Basic 인증"],
  ];
  let y = 1.5;
  rows.forEach((r, i) => {
    if (i === 0) {
      s.addShape("rect", { x: 0.6, y, w: 12.1, h: 0.42, fill: { color: AZ } });
      ["", "리소스", "SKU/규모", "역할"].forEach((t, j) =>
        s.addText(t, { x: [0.7, 1.9, 5.9, 8.6][j], y, w: [1.1, 4.0, 2.6, 4.0][j], h: 0.42, fontSize: 11.5, bold: true, color: "FFFFFF", valign: "middle" }));
    } else {
      s.addImage({ path: ic(r[0]), x: 0.72, y: y + 0.06, w: 0.4, h: 0.4 });
      [[1.9, 4.0], [5.9, 2.6], [8.6, 4.0]].forEach(([x, w], j) =>
        s.addText(r[j + 1], { x, y, w, h: 0.52, fontSize: 11, color: INK, valign: "middle" }));
      s.addShape("line", { x: 0.6, y: y + 0.54, w: 12.1, h: 0, line: { color: LINE, width: 0.75 } });
    }
    y += 0.56;
  });
  s.addText("스케일 0→1 (호출 시 기동, 최대 1 레플리카) · 종료 절차: az group delete (rg-bts-openai LLM 엔드포인트는 별도 생존)",
    { x: 0.6, y: y + 0.08, w: 12.1, h: 0.4, fontSize: 11, italic: true, color: WARN });
}

/* ---- 3. 전체 아키텍처 구성도 ---- */
{
  const s = p.addSlide();
  header(s, 3, "전체 아키텍처 구성도", "호출 → 인그레스(토큰 게이트) → 컨테이너(8800) → 상태 3곳 + 아웃바운드 2곳");
  // caller
  s.addShape("roundRect", { x: 0.5, y: 2.6, w: 1.9, h: 1.5, rectRadius: 0.1, fill: { color: "F3F6FB" }, line: { color: AZ, width: 1.5 } });
  s.addText("사용자 / CI\n(브라우저·스크립트)", { x: 0.5, y: 2.6, w: 1.9, h: 1.5, fontSize: 11.5, align: "center", valign: "middle", color: INK });
  s.addShape("line", { x: 2.45, y: 3.3, w: 1.15, h: 0, line: { color: AZ, width: 2.5, endArrowType: "triangle" } });
  s.addText("HTTPS · Basic 토큰", { x: 2.3, y: 2.9, w: 1.6, h: 0.3, fontSize: 9.5, color: SUB, align: "center" });
  // ingress
  s.addShape("roundRect", { x: 3.65, y: 2.45, w: 2.2, h: 1.8, rectRadius: 0.1, fill: { color: AZ } });
  s.addText([{ text: "ACA 인그레스\n", options: { fontSize: 13, bold: true, color: "FFFFFF" } },
             { text: "FQDN bts-sbom.wittyforest-…\n토큰 게이트·속도제한\n프로브(healthz/readyz) 우회", options: { fontSize: 9.5, color: "DCEFFB" } }],
    { x: 3.7, y: 2.5, w: 2.1, h: 1.7, valign: "middle" });
  s.addShape("line", { x: 5.9, y: 3.3, w: 1.0, h: 0, line: { color: AZ, width: 2.5, endArrowType: "triangle" } });
  // app box
  s.addShape("roundRect", { x: 6.95, y: 1.7, w: 3.6, h: 3.2, rectRadius: 0.1, fill: { color: "EAF4FC" }, line: { color: AZ, width: 2 } });
  s.addImage({ path: ic("container_apps"), x: 8.4, y: 1.85, w: 0.65, h: 0.65 });
  s.addText("bts-sbom-app 컨테이너 (포트 8800)", { x: 7.0, y: 2.55, w: 3.5, h: 0.35, fontSize: 12.5, bold: true, color: INK, align: "center" });
  s.addText("표준 라이브러리 전용 Python · 단일 프로세스\n콘솔 UI(5섹션) + JSON API 40+ 라우트\n챗 SSE(heartbeat·취소) · HITL 승인 체인\n백그라운드 잡(벌크헤드 429) · SIGTERM 드레인", {
    x: 7.0, y: 2.95, w: 3.5, h: 1.6, fontSize: 10, color: SUB, align: "center", valign: "top" });
  chip(s, 7.2, 4.45, 3.1, "리비전 0000016 · ir-20261128b", AZ);
  // right column: state stores
  const right = [
    ["ic_storage", "Azure Files evidence", "기록·감사 대장·트리아지 영속"],
    ["ic_registry", "ACR btsbomacr1126", "MI(AcrPull)로 풀 · 빌드 50s"],
    ["ic_logs", "Log Analytics", "콘솔·시스템 로그·메트릭"],
    ["ic_openai", "Azure OpenAI (rg-bts-openai)", "gpt-5-mini · 일일 예산 게이트"],
  ];
  let ry = 1.55;
  right.forEach(([icn, t, d]) => {
    s.addImage({ path: ic(icn), x: 10.85, y: ry, w: 0.42, h: 0.42 });
    s.addText([{ text: t + "\n", options: { fontSize: 11, bold: true, color: INK } }, { text: d, options: { fontSize: 9.5, color: SUB } }],
      { x: 11.35, y: ry - 0.06, w: 1.95, h: 0.85, valign: "top" });
    s.addShape("line", { x: 10.55, y: ry + 0.2, w: 0.28, h: 0, line: { color: AZ, width: 1.5 } });
    ry += 0.92;
  });
  s.addShape("line", { x: 10.55, y: ry + 0.2 - 0.92 * 4 + 0.92, w: 0, h: 0.001, line: { color: AZ, width: 0.1 } });
  s.addShape("line", { x: 10.55, y: 1.95, w: 0, h: 3.0, line: { color: AZ, width: 1.5 } });
  s.addShape("line", { x: 10.55, y: 3.3, w: 0, h: 0, line: { color: AZ, width: 0.1 } });
  s.addShape("line", { x: 10.55, y: 1.95, w: 0.3, h: 0, line: { color: AZ, width: 1.5 } });
  s.addShape("line", { x: 10.55, y: 3.3, w: 0.3, h: 0, line: { color: AZ, width: 1.5 } });
  s.addShape("line", { x: 10.55, y: 2.87, w: 0.3, h: 0, line: { color: AZ, width: 1.5 } });
  s.addShape("line", { x: 10.55, y: 4.12, w: 0.3, h: 0, line: { color: AZ, width: 1.5 } });
  // bottom guard band
  s.addShape("rect", { x: 0.6, y: 5.35, w: 12.1, h: 1.35, fill: { color: "F3F6FB" }, line: { color: LINE, width: 1 } });
  s.addImage({ path: ic("security"), x: 0.85, y: 5.6, w: 0.5, h: 0.5 });
  s.addText([{ text: "경계 방어 (레드팀 48공격 → 11건 재현 → 전부 수선, AC-1230~1240)\n", options: { fontSize: 11.5, bold: true, color: INK } },
             { text: "읽기 타임아웃 15s·동시 128 상한 · 레거시 IPv4 SSRF 차단(netaddr.py) · DNS 리바인딩 고정 · 호출자별 429 · X-Forwarded-For는 신뢰 프록시 선언 시에만 · Server 헤더 최소화", options: { fontSize: 10, color: SUB } }],
    { x: 1.5, y: 5.5, w: 11.0, h: 1.1, valign: "middle" });
}

/* ---- 4. 상태·데이터 흐름 ---- */
{
  const s = p.addSlide();
  header(s, 4, "상태와 데이터 흐름", "영속은 Azure Files 한 곳 — 컨테이너 임시 디스크는 버퍼일 뿐");
  const flow = [
    ["ic_network", "스캔 입력", "git URL / 잠금파일 / 폴더\n소스 경계 BTS_SBOM_ALLOWED_ROOTS"],
    ["ic_container_apps", "분석 엔진", "라이선스·취약점·아키텍처·코드\n오프라인 폴백 시 갭 공시(거짓 ‘없음’ 금지)"],
    ["ic_storage", "evidence 기록", "프로젝트 레코드·CycloneDX/SPDX/VEX\nCRA 감사 대장 5종·approvals.jsonl"],
    ["ic_logs", "관측", "Log Analytics + 진단\n응답 상관 ID(X-Correlation-ID)"],
  ];
  flow.forEach((f, i) => {
    const x = 0.55 + i * 3.22;
    s.addShape("roundRect", { x, y: 1.8, w: 2.9, h: 2.5, rectRadius: 0.1, fill: { color: i === 2 ? "EAF4FC" : "F7F9FC" }, line: { color: i === 2 ? AZ : LINE, width: i === 2 ? 2 : 1 } });
    s.addImage({ path: ic(f[0]), x: x + 1.2, y: 1.95, w: 0.5, h: 0.5 });
    s.addText(f[1], { x, y: 2.55, w: 2.9, h: 0.35, fontSize: 13, bold: true, color: INK, align: "center" });
    s.addText(f[2], { x: x + 0.15, y: 2.95, w: 2.6, h: 1.2, fontSize: 10, color: SUB, align: "center" });
    if (i < 3) s.addShape("line", { x: x + 2.92, y: 3.05, w: 0.3, h: 0, line: { color: AZ, width: 2, endArrowType: "triangle" } });
  });
  s.addShape("rect", { x: 0.6, y: 4.6, w: 12.1, h: 2.0, fill: { color: "FFF7E6" }, line: { color: WARN, width: 1 } });
  s.addText([{ text: "측정된 결함과 수선: OSV DB를 SMB(Azure Files)에 두면 scanner 캐시 쓰기가 잠금 대기로 NodeGoat 스캔 780s → ", options: { fontSize: 11.5, color: INK } },
             { text: "시작 시 시드→로컬 복사(seed→local)로 96s, 락 오류 0 (AC-1226~1227)\n", options: { fontSize: 11.5, bold: true, color: OK } },
             { text: "SQLite는 네트워크 공유 위 동시 쓰기를 견디지 못한다 — 읽기전용 시크릿은 공유, 쓰는 DB는 로컬 디스크. evidence 볼륨의 영속 데이터(레코드·대장)는 공유 유지.", options: { fontSize: 10.5, color: SUB } }],
    { x: 0.85, y: 4.75, w: 11.6, h: 1.7, valign: "middle" });
}

/* ---- 5. CI/CD + Git 전략 ---- */
{
  const s = p.addSlide();
  header(s, 5, "빌드·배포 파이프라인과 Git 브랜치 전략", "강의 화이트보드 전략 채택 (docs/GIT_STRATEGY.md) · 태그 YYYYMMDDHHmm");
  const chain = [["feature/*", "aiagent·mcp\n lanes"], ["dev", "통합"], ["release/stg", "QA 게이트\n전체 pytest"], ["master", "PROD\nAzure 태그"]];
  chain.forEach((c, i) => {
    const x = 0.7 + i * 3.15;
    s.addShape("roundRect", { x, y: 1.75, w: 2.6, h: 1.1, rectRadius: 0.1, fill: { color: i === 3 ? AZ : "EAF4FC" }, line: { color: AZ, width: 1.25 } });
    s.addText([{ text: c[0] + "\n", options: { fontSize: 14, bold: true, color: i === 3 ? "FFFFFF" : INK } }, { text: c[1], options: { fontSize: 9.5, color: i === 3 ? "DCEFFB" : SUB } }],
      { x, y: 1.75, w: 2.6, h: 1.1, align: "center", valign: "middle" });
    if (i < 3) s.addText("PR", { x: x + 2.62, y: 2.1, w: 0.5, h: 0.3, fontSize: 11, bold: true, color: AZ, align: "center" });
    if (i < 3) s.addShape("line", { x: x + 2.62, y: 2.5, w: 0.5, h: 0, line: { color: AZ, width: 2, endArrowType: "triangle" } });
  });
  s.addText("hotfix/* → master 직행 후 release·dev 역병합 · QA 통과 시 release/stg에서 태그(예: 20261128121200)", { x: 0.7, y: 3.0, w: 12, h: 0.35, fontSize: 11, color: SUB });
  const steps = [
    "1. git push (번들 커밋 1건 · GitHub Actions는 main 전용·ubuntu·동시성 취소 — 비공개 한도 2,000분/월 규율)",
    "2. az acr build — 클라우드 빌드 ~50s (빌드 컨텍스트 허용목록 .dockerignore로 1.9MiB만 전송)",
    "3. az containerapp update --image — 신규 리비전, 프로브 통과 시 트래픽 100%",
    "4. 라이브 스모크 — healthz/readyz, 인증 401/200, CRA·챗 SSE 실측 (scripts/smoke_deployed.py)",
  ];
  s.addText(steps.join("\n"), { x: 0.7, y: 3.6, w: 12, h: 1.6, fontSize: 12, color: INK, lineSpacing: 20 });
  s.addText("롤백 = az containerapp revision → 이전 리비전 트래픽 100% (리비전 불변성 내장)", { x: 0.7, y: 5.5, w: 12, h: 0.4, fontSize: 11.5, italic: true, color: SUB });
}

/* ---- 6. Identity ---- */
{
  const s = p.addSlide();
  header(s, 6, "Identity: Managed Identity 적용 · Workload Identity 방향", "docs/AZURE_IDENTITY.md · 2026-11-28 적용 실측");
  s.addImage({ path: ic("identity"), x: 0.8, y: 1.7, w: 0.85, h: 0.85 });
  s.addText([
    { text: "적용 완료 — ACR 풀 = 시스템 할당 MI (리비전 0000008부터 라이브)\n", options: { fontSize: 14, bold: true, color: INK } },
    { text: "MI principal a597a9ae-… → AcrPull 1건 → 레지스트리 항목 identity: system → acr-password 시크릿 삭제 + ACR 관리자 계정 OFF.\n앱 설정·시크릿·빌드 문서 어디에도 ACR 비밀번호가 남지 않는다. 리비전 내보내기에서 registry 항목은 identity 한 줄.", options: { fontSize: 12, color: SUB } },
  ], { x: 1.9, y: 1.7, w: 10.6, h: 1.5, valign: "top", lineSpacing: 18 });
  s.addText([
    { text: "방향 — Workload Identity(연합 자격증명)은 Key Vault 연계 시점에\n", options: { fontSize: 14, bold: true, color: INK } },
    { text: "대상: LLM 키 4종·액세스 토큰의 KV 이관. 사용자 할당 MI + 연합 자격증명(issuer *.azurecontainerapps.io) + KV RBAC Secrets User.\n지금 안 하는 이유: stdlib 전용 런타임에 Azure SDK가 없고(REST 핸드셰이크 필요) ACA 참조 방식은 앱 단위 활성화 확인이 필요 — 다음 배포 창에 적용.\n대안: ACA secret은 플랫폼 암호화·내보내기 마스킹 검증됨 — KV 이관의 실익은 사람이 KV에서 로테이션할 때 생긴다.", options: { fontSize: 12, color: SUB } },
  ], { x: 0.8, y: 3.5, w: 11.7, h: 2.2, valign: "top", lineSpacing: 17 });
  s.addShape("rect", { x: 0.6, y: 6.1, w: 12.1, h: 0.75, fill: { color: "EAF4FC" }, line: { color: AZ, width: 1 } });
  s.addText("런타임 최소 권한: 앱이 가진 Azure 권한은 ACR pull 하나. 배포·롤백·리비전 작업은 사람의 az 세션이 수행.", { x: 0.85, y: 6.1, w: 11.6, h: 0.75, fontSize: 12, color: INK, valign: "middle" });
}

/* ---- 7. UI 개요 (5섹션) ---- */
{
  const s = p.addSlide();
  header(s, 7, "UI 서비스 개요 — 콘솔 5섹션 · 하단 대화 dock", "bts_console.js GROUPS 실측 · 모든 판은 JSON API 위의 렌더러");
  const secs = [
    ["🔎", "분석 스캔", "Scan(Git·잠금파일)·OSS 결과·Lockfile·Container — BtsOss 계약 단일 폼"],
    ["📊", "결과와 우선순위", "Findings·What changed·SSVC·EPSS·Exploit Matrix — 측정 안 한 지표는 공란"],
    ["🗄", "리포트와 구조", "Report·Arch Intel·Diagrams(37종)·Dep Graph·Code Intel·DB 질의·Supply Chain"],
    ["📚", "지식·컴플라이언스", "Book KB·SBOM checks·Conformance·CRA·VEX·License Risk·Industry·사고 대응"],
    ["🔧", "수정과 운영", "Fix Plan·Patch(승인 토큰)·Clean-Room 재구현·CI/CD·History·Fleet"],
  ];
  secs.forEach((sec, i) => {
    const y = 1.6 + i * 1.02;
    s.addShape("roundRect", { x: 0.6, y, w: 7.3, h: 0.9, rectRadius: 0.08, fill: { color: i % 2 ? "F7F9FC" : "EAF4FC" }, line: { color: LINE, width: 0.75 } });
    s.addText(sec[0], { x: 0.75, y: y + 0.14, w: 0.6, h: 0.6, fontSize: 22, align: "center" });
    s.addText([{ text: sec[1] + "   ", options: { fontSize: 13.5, bold: true, color: INK } }, { text: sec[2], options: { fontSize: 10.5, color: SUB } }],
      { x: 1.45, y, w: 6.3, h: 0.9, valign: "middle" });
  });
  s.addShape("roundRect", { x: 8.25, y: 1.6, w: 4.5, h: 5.1, rectRadius: 0.1, fill: { color: DARK } });
  s.addImage({ path: ic("chat"), x: 10.1, y: 1.85, w: 0.8, h: 0.8 });
  s.addText("하단 대화 dock", { x: 8.25, y: 2.75, w: 4.5, h: 0.4, fontSize: 15, bold: true, color: "FFFFFF", align: "center" });
  s.addText("모든 탭 상주 · SSE 7종 활동 카드(tool_call/result·awaiting_approval·handoff·final·error)\nA2UI 카드(카탈로그 19/27 도구, esc-only 렌더)\n승인은 인라인 버튼 = 사용자 행위\n질문→도구→인용 검증→카드/다이어그램 단발 턴", {
    x: 8.5, y: 3.25, w: 4.0, h: 3.2, fontSize: 10.5, color: "C9D4E4", valign: "top", lineSpacing: 16 });
}

/* ---- 8. 구성요소: 분석/결과 ---- */
{
  const s = p.addSlide();
  header(s, 8, "구성요소 기능 ① — 분석 스캔 · 결과와 우선순위", "정직 계약: 측정하지 않은 것은 0이 아니라 ‘없음’으로 답한다");
  const cards = [
    ["Scan (Git·Lockfile·폴더)", "의존성 추출→라이선스/취약점 매칭→CycloneDX·SPDX·OpenVEX 생성. 소스 경계·SSRF 가드 내장. 부분 스캔은 갭 공시."],
    ["Findings · What changed", "두 분석/SBOM diff로 신규·해소 취약점·버전 이동 감지, 임계 알림. 배치 재시도 후 합산 집계 일치 보장."],
    ["Prioritize (SSVC·EPSS·Exploit)", "SSVC 의사결정 트리·EPSS·익스플로잇 성숙도. 피드 미연동 지표는 배지로 ‘미측정’ 공시 — 과잉 표시 없음."],
    ["Dep Graph · Health", "의존성 그래프·EOL·유지관리 신호. Fleet으로 포트폴리오 롤업·영향 프로젝트 역조회."],
  ];
  cards.forEach((c, i) => {
    const x = 0.6 + (i % 2) * 6.25, y = 1.7 + Math.floor(i / 2) * 1.85;
    s.addShape("roundRect", { x, y, w: 5.9, h: 1.6, rectRadius: 0.08, fill: { color: "F7F9FC" }, line: { color: LINE, width: 1 } });
    s.addText([{ text: c[0] + "\n", options: { fontSize: 13, bold: true, color: AZ } }, { text: c[1], options: { fontSize: 10.5, color: SUB } }],
      { x: x + 0.2, y: y + 0.1, w: 5.5, h: 1.4, valign: "top", lineSpacing: 15 });
  });
  s.addText("백그라운드 잡은 벌크헤드(동시 1) — 2번째 요청은 429+Retry-After · 작업 상관 ID가 잡 기록·SSE·에스컬레이션을 관통 (AC-1256)",
    { x: 0.6, y: 5.7, w: 12.1, h: 0.4, fontSize: 11, italic: true, color: WARN });
}

/* ---- 9. 구성요소: 구조/지식 ---- */
{
  const s = p.addSlide();
  header(s, 9, "구성요소 기능 ② — 리포트·구조 · 지식·컴플라이언스", "CRA 레인(AC-1241~1246)과 사고 대응 판이 이 그룹의 최신 라인");
  const cards = [
    ["Arch Intel · Code Intel", "EA 스타일 다이어그램(37종 카탈로그)·DMN 추론엔진·콜그래프·순환복잡도·클론 — SciTools Understand 핵심을 표준 라이브러리로 재구현."],
    ["Book KB · NL2SQL", "로컬 도서 15권(9,179 청크)+정제 노트를 추론 소스로 — 클린룸 패턴 2단 추론(책→모델 폴백). 스캔 증거 OSV DB에 한국어 NL2SQL."],
    ["SBOM Conformance · CRA", "NTIA·CISA·EU CRA·BSI TR-03183-2 요소별 매트릭스. CRA 판: security.txt(RFC 9116)·지원기간 5년 검증·Article 14 시계·부록 J 대장 5종·readiness 8체크."],
    ["VEX·Decisions · License Risk · 사고 대응", "처분 결정은 VEX 근거 fail-closed(not_affected는 근거 필수). 강한 카피레프트는 클린룸 경로 안내. KISA 매핑 사고 SLA·보고서·IoC 조회 판."],
  ];
  cards.forEach((c, i) => {
    const x = 0.6 + (i % 2) * 6.25, y = 1.7 + Math.floor(i / 2) * 1.85;
    s.addShape("roundRect", { x, y, w: 5.9, h: 1.6, rectRadius: 0.08, fill: { color: i % 3 ? "F7F9FC" : "EAF4FC" }, line: { color: LINE, width: 1 } });
    s.addText([{ text: c[0] + "\n", options: { fontSize: 13, bold: true, color: AZ } }, { text: c[1], options: { fontSize: 10.5, color: SUB } }],
      { x: x + 0.2, y: y + 0.1, w: 5.5, h: 1.4, valign: "top", lineSpacing: 15 });
  });
  s.addText("security.txt는 /.well-known/에서 자동 서빙 — 주소를 추측하지 않으면 404+해결책으로 정직히 답한다", { x: 0.6, y: 5.7, w: 12.1, h: 0.4, fontSize: 11, italic: true, color: WARN });
}

/* ---- 10. 구성요소: 수정/운영 + HITL ---- */
{
  const s = p.addSlide();
  header(s, 10, "구성요소 기능 ③ — 수정 · 운영 · HITL 승인 체인", "라이브 HITL 실측: 오래된 토큰 거부·격리 적용 80.7s·소스 경계 거부");
  const steps = [
    ["1. Fix Plan", "업그레이드 계획 생성 — DMN 처분 정책(조직 오버라이드 가능, AC-1258)이 우선순위 결정"],
    ["2. Patch 승인", "승인 토큰 = 보여준 계획의 digest 그 자체 — 계획이 바뀌면 토큰 무효. 시도 전부 감사 대장 기록(AC-1257)"],
    ["3. 적용·재검증", "워크카피 1라운드 적용→재스캔→회귀 시 자동 복구. 라이브 실측 80.7s"],
    ["4. VEX 결정", "not_affected는 VEX 근거 5종 중 하나+10자 이상 사유 없으면 affected 유지(fail-closed)"],
    ["5. Clean-Room", "GPL/AGPL은 패치 불가 — 명세 채널에 책→AI 2단 패턴 주입, 카피 게이트 4행 shingle 0.05"],
  ];
  steps.forEach((st, i) => {
    const y = 1.7 + i * 0.92;
    s.addShape("ellipse", { x: 0.7, y: y + 0.08, w: 0.55, h: 0.55, fill: { color: AZ } });
    s.addText(String(i + 1), { x: 0.7, y: y + 0.08, w: 0.55, h: 0.55, fontSize: 16, bold: true, color: "FFFFFF", align: "center", valign: "middle" });
    s.addText([{ text: st[0] + "   ", options: { fontSize: 13, bold: true, color: INK } }, { text: st[1], options: { fontSize: 11, color: SUB } }],
      { x: 1.45, y, w: 11.2, h: 0.75, valign: "middle" });
  });
  s.addText("전 과정은 취약점 처리 요건의 증거로 기록 — Article 14 시계(24h/72h/14일)와 감사 대장이 같은 evidence 폴더를 공유한다.",
    { x: 0.7, y: 6.45, w: 12, h: 0.4, fontSize: 11, italic: true, color: WARN });
}

/* ---- 11. 운영 신뢰성 ---- */
{
  const s = p.addSlide();
  header(s, 11, "운영 신뢰성 — 회복·한도·관측", "Azure 아키텍처 센터 전수 채점의 적용분 (AC-617/618) + 루프3 운영 계약");
  const items = [
    ["최상위 예외 가드", "미처리 예외 → correlation_id를 실은 500 JSON(트레이스백 노출 없음). 라이브 KeyError 사고에서 유래."],
    ["벌크헤드·스로틀", "백그라운드 잡 상한 1 — 초과 429+Retry-After. 채팅 동시성 4·호출자별 30/분."],
    ["SIGTERM 드레인", "신규 잡 503+Retry-After, 진행 잡은 플랫폼 유예 안에 완료 후 종료."],
    ["SSE heartbeat·취소", "15s 무음 간격에 코멘트 라인(프록시 절단 방지)·리더 퇴장 시 남은 도구 취소(AC-1254/1256)."],
    ["자체 도그푸드", "제품이 자기 소스를 오프라인 스캔→자기 SBOM 유효성 게이트(AC-1251) + 야간 드리프트 워크플로(AC-1252)."],
    ["TOP-10 품질 게이트", "근거성·완결성·툴 정확도·과잉거절·회귀 — 라이브/플로어 2레인, 스위트 26/26."],
  ];
  items.forEach((it, i) => {
    const x = 0.6 + (i % 2) * 6.25, y = 1.65 + Math.floor(i / 2) * 1.62;
    s.addShape("roundRect", { x, y, w: 5.9, h: 1.4, rectRadius: 0.08, fill: { color: "F7F9FC" }, line: { color: LINE, width: 1 } });
    s.addText([{ text: it[0] + "\n", options: { fontSize: 12.5, bold: true, color: AZ } }, { text: it[1], options: { fontSize: 10.5, color: SUB } }],
      { x: x + 0.2, y: y + 0.08, w: 5.5, h: 1.25, valign: "top", lineSpacing: 14 });
  });
  s.addText("전 스위트 940 passed · speclint/doclint 정합 · LLM 일일 예산 게이트(경고단계+하드스톱+달러 장부)", { x: 0.6, y: 6.5, w: 12.1, h: 0.4, fontSize: 11.5, bold: true, color: OK });
}

/* ---- 12. 비용·정리 ---- */
{
  const s = p.addSlide();
  header(s, 12, "비용 한도와 철수 절차", "공개 단가 × 실측 사용량 — 견적 아님");
  const rows = [
    ["Container Apps (스케일 0→1)", "사용 시간만 과금 — 하루 1시간 가정 약 $3/월"],
    ["ACR Basic", "약 $5/월"],
    ["Azure Files 2Gi (Standard_LRS)", "약 $0.4/월"],
    ["Log Analytics", "소량(수집 볼륨 의존)"],
    ["Azure OpenAI gpt-5-mini", "토큰별 별도 — 일일 예산 게이트로 상한"],
  ];
  let y = 1.7;
  rows.forEach((r) => {
    s.addText(r[0], { x: 0.8, y, w: 4.6, h: 0.42, fontSize: 12, color: INK, valign: "middle" });
    s.addText(r[1], { x: 5.5, y, w: 3.2, h: 0.42, fontSize: 12, bold: true, color: OK, valign: "middle" });
    s.addShape("line", { x: 0.8, y: y + 0.44, w: 7.9, h: 0, line: { color: LINE, width: 0.75 } });
    y += 0.52;
  });
  s.addShape("rect", { x: 0.6, y: 4.6, w: 12.1, h: 2.0, fill: { color: "F3F6FB" }, line: { color: LINE, width: 1 } });
  s.addText([
    { text: "철수 절차 (문서화됨)\n", options: { fontSize: 13, bold: true, color: INK } },
    { text: "az group delete --name bts-sbom-rg --yes → ResourceGroupNotFound로 검증. NodeGoat 등 라이브 기록은 사전 로컬 보존.\nrg-bts-openai(LLM 엔드포인트)는 별도 리소스 그룹으로 생존. 재배포: deploy/azure/README.md 절차 + applied yaml + evidence 시딩.\n무료 대안 조사 완료: ACA 월 100h 무료 공제(재배포 $0 가능)·Cloud Run 한도·Oracle 춘천 ARM 제약·Cloudflare Tunnel.", options: { fontSize: 11, color: SUB } },
  ], { x: 0.85, y: 4.72, w: 11.6, h: 1.75, valign: "top", lineSpacing: 16 });
}

/* ---- 13. 마무리 ---- */
{
  const s = p.addSlide();
  s.background = { color: DARK };
  s.addImage({ path: ic("sbom"), x: W / 2 - 0.7, y: 1.0, w: 1.4, h: 1.4 });
  s.addText("한 줄 요약", { x: 0, y: 2.6, w: W, h: 0.5, fontSize: 20, color: "#9CC7E8", align: "center" });
  s.addText("표준 라이브러리 전용 단일 컨테이너가\nACA 인그레스·토큰 게이트·MI 풀·Files 영속·LA 관측 위에서\n20개 CRA/운영 AC와 940개 테스트의 증거를 이미 라이브로 서빙한다.",
    { x: 0, y: 3.2, w: W, h: 1.8, fontSize: 22, bold: true, color: "FFFFFF", align: "center", lineSpacing: 34 });
  s.addText("문서: docs/AZURE_DEPLOYMENT.md · AZURE_IDENTITY.md · CRA_COMPLIANCE.md · GIT_STRATEGY.md\n동적 HTML 덱: docs/AZURE_OPERATIONS_OVERVIEW.html (전환·애니메이션·키 내비)", {
    x: 0, y: 5.9, w: W, h: 0.8, fontSize: 12, color: "#8A8FA8", align: "center", lineSpacing: 18 });
}

p.writeFile({ fileName: path.join(__dirname, "..", "docs", "AZURE_OPERATIONS_OVERVIEW.pptx") })
  .then((f) => console.log("written:", f));
