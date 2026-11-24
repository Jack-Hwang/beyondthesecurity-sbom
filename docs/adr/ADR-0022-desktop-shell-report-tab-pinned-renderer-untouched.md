# ADR-0022: Desktop-app shell, the dedicated Report tab, and the pinned renderer discipline

## Status

Accepted (2026-11-22, 사용자 지시: "클로드 클라이언트 데스크탑 형태처럼 만들어 그럼 별도 탭으로 할 수 있잖아" + 카드에 "모두다" 포함)

## 근거 (Context)

SCA 리포트(복제 플랫폼 렌더러 sca_app.js의 산출)가 Git 스캔 판 안(#scaReportOut)에 파묻혀 있어 좁은 폭에
길게 늘어져 있었다. 사용자는 이것을 별도 화면으로 승격하되, 콘솔 전체를 **클로드 데스크탑 클라이언트 같은
좌측 사이드바 + 콘텐츠 열** 구조로 바꾸고, 리포트 화면에 헤더·다운로드·거버넌스 카드까지 모두 담기를
원했다. 제약: sca_app.js와 플랫폼 css 6파일은 NOTICE.md·PLATFORM_ASSETS.sha256으로 **바이트 고정**되어
(test_console_ui가 강제) 수정할 수 없고, 렌더러의 상태는 mount 스코프 closure(모든 querySelector/addEvent
Listener가 mount 한정, `mount.__scaAppBound` 1회 바인딩 가드)라는 점을 실측으로 확인했다.

## 결정 (Decision)

1. **데스크탑 셸**: `#view-scan`을 `.bts-shell`(좌측 `<nav id="sideNav">` + 우측 `.bts-content`)로 개편.
   사이드버튼은 기존 상단 탭 바와 **동일한 `.rtab[data-sv]` 계약**을 유지해 activate()/subnav()/GROUPS/
   LABELS와 위임 클릭 핸들러를 무변경으로 둔다 — CSS(bts_console.css)만 세로 사이드바로 재정의한다
   (고정 app.css의 가로 `.rtab` 규칙은 #sideNav 스코프에서만 덮어쓴다).
2. **Report 별도 탭**: 리포트는 Git 판에서 이사해 자기 판을 갖는다 — `#reportHead`(순수 빌더
   bts_report.js: 이름·출처·시각·심각도 칩 5·다운로드 4) + `#reportOut`(ScaApp 마운트, 페이지에 **1개뿐**)
   + `#govCards`(수정 계획 요약은 /api/view, VEX 커버리지·규제 적합도는 프로젝트당 1회 lazy fetch, 실패는
   "Not loaded:" 뒤에 실패 사유를 붙이는 정직 표기). 탭 진입마다 renderConsole() 재렌더(단일 활성 인스턴스 규율 — 마운트가
   하나이므로 closure 상태 충돌이 원천 불가능). 분석 완료 시 activate('report')로 자동 전환.
3. **Chat 탭**: 채팅 2박스(#chatBox·#streamBox)를 `.rpane[data-sv="chat"]`으로 이동해 별도 탭으로.
4. **렌더러 무수정**: sca_app.js·플랫폼 css는 한 바이트도 고치지 않고, 주변을 우리 파일
   (index.html·bts_console.js/.css·신규 bts_report.js)로만 감싼다. bts_report.js는 bts_ui.js와 같은 UMD
   패턴으로 Node 렌더 하니스에서 순수 함수 테스트가 가능하다. (BSA-AC-538..542)

## 기각 대안 (Rejected alternatives)

- **sca_app.js를 고쳐 레이아웃 자체를 개선** — 플랫폼 복제물 무수정 계약(NOTICE.md, 해시 고정 테스트) 위반.
  렌더러를 감싸는 셸로만 개선한다.
- **독립 URL 페이지(/report/프로젝트)** — 별도 탭으로 충분하다는 사용자 결정("차라리 별도 탭으로")과 콘솔 단일
  페이지 구조(프로젝트 선택이 전역 상태)를 유지하는 쪽이 일치. URL 딥링크가 필요해지면 그때 새 ADR.
- **ScaApp 인스턴스 2개(Git 판+Report 탭 동시 마운트)** — 렌더러의 closure 상태(mount/activeTab/R)가
  전역 1세트라 두 마운트가 서로의 탭 상태를 덮어쓴다. 마운트 1개 + 진입 시 재렌더 규율로 해결.
- **BTS 자체 리포트 UI 신규 작성** — 기존 렌더러의 탭·필터·트리·트리아지 기능을 재작성하는 비용 대비,
  고정 렌더러 재사용 + 주변(header/카드) 강화가 요구("개선")를 충족.

## 결과 (Consequences)

긍정: 30+ 판이 상단 탭 한 줄에 눌려 있던 것을 사이드바로 상시 탐색 가능, 리포트가 전체 폭 전용 화면이 됨,
거버넌스 3카드로 수정 계획·결정 커버리지·규제 적합성이 리포트 한 화면에서 요약됨, 렌더러 무수정으로 플랫폼
동기화 비용 0. 부담: 사이드바는 좁은 뷰포트에서 가로 칩 행으로 폴백(media query), ScaApp은 마운트 1개
규율을 지켜야 하고(새 마운트 추가 금지 — ADR 위반 방지를 BSA-AC-542 테스트가 #reportOut 1개를 검문),
거버넌스 카드 2종은 탭 렌더 시 프로젝트당 2회 소규모 GET이 추가된다(localhost, 측정 생략 — 용량 문서
SLO 경로 아님).
