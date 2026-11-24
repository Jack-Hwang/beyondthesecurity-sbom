# ADR-0024: EA 17.2 다이어그램 카탈로그 + DMN식 추론 엔진의 네이티브 재현

날짜: 2026-11-22
관련: ADR-0023 (Code Intel/Understand 재현 — 같은 "설치본 REA → 자체 재현" 계열의 선행 사례)

## Status

채택 — 구현·테스트 완료(커밋 전). 스펙 AC-573~578.

## 근거 (Context)

사용자가 `C:\firebaseprojects\REA\scitools\easetup_x64.msi`를 REA로 분석하고, (1) 그 제품의 아키텍처와 추론
엔진을 이해하고, (2) 그것이 실제로 지원하는 모든 다이어그램을 우리 도구가 그리게 하며, (3) 대화 중에 직접
그릴 수 있게 통합하라고 했다. REA 결과 설치본은 SciTools가 아니라 **Sparx Systems Enterprise Architect
Trial 17.2.1721.15**였다 (docs/EA_REA_FINDINGS.md — MSI Property 테이블, 3,744파일 전수 추출 대조, EA.exe
내장 New-Diagram 레지스트리 XML이 1차 증거). EA는 요청의 목적(아키텍처·다이어그램·추론)에 정확히 부합하므로
관찰된 대상 그대로 진행한다.

## 결정 (Decision)

1. **카탈로그 = REA 레지스트리의 재현**: `diagrams.py`의 CATALOG는 EA.exe 내장 기술 XML에서 확인된 그룹명
   (UML Structural / UML Behavioral / Extended)과 MDG 기술 파일로 확인된 계열(BPMN, ArchiMate, DFD,
   MindMapping, Kanban, Executable State Machine, Wireframing)을 우리 이름으로 옮긴 것. **2차 재검증에서
   SysML 존재가 확정되어**(1차 "0건"은 UTF-16 추출 누락 오류 — EA_REA_FINDINGS.md 정정 단락) SysML 그룹
   (BDD/IBD/Parametric)과 Robustness(ICONIX)를 추가했고 timing에 Timeline/Roadmap을 병기했다. 총 37종 중
   36종은 실측 데이터 빌더, 1종(ui/와이어프레이밍)은 측정 불가로 정직 노트만 내보낸다.
2. **Mermaid 텍스트 단일 출력**: 이미 벤더딩된 mermaid.min.js(v12)를 재사용하고, 실패 시 소스 텍스트 폴백 —
   arch_intel 다이어그램의 기존 계약과 동일. SVG를 우리가 직접 그리는 길은 열어두되(출력이 텍스트라 어느
   렌더러든 교체 가능) 지금은 새 의존을 만들지 않는다.
3. **추론 엔진은 DMN식 결정 테이블**: `decision.py` — 순수 평가기(테이블 in, verdict+trace out, 결정론).
   severity는 CVSS 밴드 순위 비교, `true/false` 셀은 리터럴(빈 셀/`*`/`-`만 "always"), 결측 입력은 미발화.
   기본 테이블 remediation-policy는 이 도구의 자체 정책(악성→검역, critical+fix→즉시 패치, copyleft+binary→
   라이선스 리뷰 병행 등 8규칙, F 정책)으로, 팩트는 기록의 측정값에서 온다. 테이블이 정책이고 팩트가 데이터라는
   분리를 문서·노트에 명시한다.
4. **대화 중 그리기**: 챗 도구 `draw_diagram`(kind/target/spec)과 `decide`(facts) — LLM 플래너와 정규식 라우터
   양쪽에서 같은 검증기를 통과한다(기존 게이트 재사용). 화살표 문장("A -> B -> C")은 custom 종류로 즉석 그리기.
   다이어그램은 응답 JSON과 SSE final 이벤트 양쪽에 `diagrams`로 실려 가고, 채팅 독과 🖼 Diagrams 탭이 같은
   `.arc-dwrap` 마크업 계약으로 렌더한다.
5. **arch 기록에 실측 엣지 추가**: 패키지/컴포넌트/DFD/레이어 다이어그램의 원천으로 `arch.analyze`가 import
   엣지를 cap 3,000으로 저장("edges"). 기록에 없으면 빌더가 그 이유를 노트로 말한다(재분석 필요).

## 기각 대안 (Rejected alternatives)

- **EA 스타일 SVG 렌더러 직접 구현**: 셰이프·라우팅·배치를 전부 자체 구현하는 길 — 범위 대비 위험과 유지보수가
  크고, mermaid 폴백 계약이 이미 검증돼 있어 기각. 필요하면 나중에 렌더러만 교체한다.
- **EA .qea/.eap 파일 읽기/상호호환**: 설치본엔 런타임이 없고(실행 금지 원칙) 파일 포맷 역공은 이번 목적(종류
  카탈로그+추론)에 불필요 — 기각.
- **다이어그램을 LLM이 그리게 함**: 근거 없는 도식 생성은 정직 계약 위반 — 측정값 빌더만 그리고, custom만
  사용자가 타이핑한 문장을 그대로 옮긴다. 기각(부분 채택: custom 화살표 문장).
- **카탈로그를 EA 마케팅 문서 기준으로 채우기(SysML 등)**: 이 설치본에서 확인 안 된 종류는 클레임하지 않는다 —
  기각하고 REA 레지스트리 기준으로 고정.

## 결과 (Consequences)

- 스펙: AC-573~578. 테스트: `tests/bts_sbom_app/test_diagrams.py`(26)·`test_decision.py`(10)·게이트 레지스트리 핀 갱신.
- 정직 커버리지: 데이터 없는 종류는 이유를 말한다(33 of 33 draw-or-explain), 같은 기록은 같은 그림(결정론),
  레이아웃 품질은 mermaid에 위임했음을 문서에 명시.
