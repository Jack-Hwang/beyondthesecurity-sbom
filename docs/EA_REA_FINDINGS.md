# EA_REA_FINDINGS — `C:\firebaseprojects\REA\scitools` REA 결과 (2026-11-22)

요청: "scitools 폴더를 REA 해줘 — 아키텍처와 추론 엔진, 그리고 여기서 실제로 지원하는 모든 다이어그램".
대상은 설치 MSI 한 파일이었다: `easetup_x64.msi` (346,419,200 bytes). REA 워크플로우는 MSI를 직접 열지
못하므로(unsupported binary format), 다음 순서로 정적 전수 분석했다: WindowsInstaller COM으로 File/Component/
Directory/Media 테이블 덤프(3,744파일) → 내장 캐비닛 4개(#simple/#common/#nonlite/#commonx64)를 expand.exe로
추출(멤버 수 25+79+624+3,016 = 정확히 3,744) → 테이블 조인으로 원래 트리 복원 → EA.exe 문자열·내장 XML·기술
파일 정밀 독해. 추출물은 실행하지 않았고 검증 가능한 바이트로만 다뤘다.

## 1. 제품 신원 (관찰, not 추정)

| 항목 | 값 | 근거 |
|---|---|---|
| 제품 | **Sparx Systems Enterprise Architect Trial** | MSI Property 테이블 `ProductName` |
| 버전 | **17.2.1721.15** | `ProductVersion` |
| Manufacturer | Sparx Systems | `Manufacturer` |
| 주 바이너리 | EA.exe 152,550,496 bytes (네이티브) | 추출 트리 |
| 폴더명과의 불일치 | 폴더 이름은 "scitools"이나 SciTools/Understand 계열 파일 0건(`scitools|understand|.und` 전수 grep) | 트리 전수 grep |

빌드 경로 누출(`C:\EA\EAStable\TimingDiagramManager.cpp` 등)과 내장 리본 XML, 스키마 DDL이 EA임을 교차 확인한다.

## 2. 아키텍처 (관찰된 구성 요소)

1. **단일 네이티브 앱 + 모델 저장소**: EA.exe가 UI·분석·렌더를 모두 품고, 모델은 SQLite 계열 DDL(t_diagram,
   t_diagramtypes, t_object, t_connector, t_diagramobjects, t_diagramlinks, t_attribute, t_operation, t_xref …)
   의 저장소에 기록된다. `Diagram_Type TEXT NOT NULL COLLATE NOCASE PRIMARY KEY` — 다이어그램 종류가 문자열
   키로 저장소 스키마에 박혀 있다. 기업 DB 어댑터: Firebird 임베디드(fbembed.dll), Oracle(74MB oci dll),
   MariaDB, SQL Server, SQLite3 디렉터리가 함께 온다.
2. **스크립팅/자동화**: SpiderMonkey **mozjs-70.dll**(JS 엔진) + VBScript/JScript 템플릿(NormalTemplate/
   DiagramTemplate/SearchTemplate/WorkflowTemplate .js/.vbs) + Scriptlet 엔진. EA의 도식 자동 생성은 이 JS/
   스크립트 계층을 통해서도 노출된다.
3. **MDG 기술 확장**: `MDGTechnologies` 아래 XML 기술 파일들 — UML 코어는 EA.exe 안에 내장(`<Documentation
   name="UML Structural|UML Behavioral|Extended">` + 다이어그램별 `<Stereotype>` 정의), 나머지는 파일로:
   BPMN 1.0/1.1/2.0, **ArchiMate 3.1/2**, **DFD**, **MindMapping**, Kanban, Whiteboard, Wireframing,
   **Executable State Machines**, Executable Business States, strategic, GoF, IFML, NIEM, SPEM, AML, ODM,
   SOMF, UBL, DataWarehouse, ErikssonPenker, ICONIX, CyberSecurityModeling, AUTOSAR(LieberLieber), DataMiner,
   UPDM 2.0 템플릿 묶음(2,274개 XML의 nknezi5v 폴더) 등 50여 개.
4. **렌더/레이아웃**: 다이어그램 저장은 t_diagramobjects(RectTop/Left/Right/Bottom) — 좌표가 모델의 일급 데이터.
   GDI 기반 렌더러는 EA.exe 내부(단일 DLL 아님, 152MB 모놀리스).

## 3. 추론·시뮬레이션 엔진 (관찰)

- **DMN (의사결정 모델)**: DMN-Sim 워크스페이스 2종, `dmn.iml`, DMNTagActionTool.xml, "bpmn-integrate-with-dmn"
  예저 모델들. DMN 결정 테이블(입력열/출력열/규칙 행 + hit policy)을 평가하는 규칙 추론 — EA 17에서 "추론 엔진"
  에 가장 가까운 실체. → 우리 재현: `bts_sbom_app/decision.py` (DMN-lite 평가기 + remediation-policy 테이블).
- **BPSim/LSim**: `BPSIM/lib/l-sim.jar`(LSim 시뮬레이션 코어) + LSimLauncher.jar + antlr-3.4(식 평가 파서) +
  Rhino js.jar — BPMN 프로세스의 이산사건 시뮬레이션.
- **Executable State Machines**: 상태 머신을 실행 가능한 형태로 시뮬레이션하는 기술 파일 + 워크스페이스.
- **Solver 시뮬레이션 패턴**(simulation.xml, Octave 매핑).
- SpiderMonkey는 표현식/스크립트 평가의 공통 하부.

## 4. 다이어그램 레지스트리 전수 (EA.exe 내장 기술 XML — 1차 증거)

**UML Structural** (Documentation id=43A1A33E-0): Package, Class, Object, Composite Structure, Component, Deployment — 6종.
**UML Behavioral** (id=EB14259D-C): Use Case, Activity, State Machine, Communication, Sequence, Timing, Interaction Overview — 7종.
**Extended / Core Extensions** (id=DB937C25-5): Custom, Requirements(diagramID req), Maintenance(main), Analysis,
Construction(construct), User Interface(ui), Data Modeling(dm), ModelDocument/Documentation(doc), Business
Modeling(Logical+class), Business Interaction(Sequence+sd), Test Domain(td), Dashboard(dash), WSDL(wsdl),
XSD Schema(schema), XML Transform(xslt) — 15종.
**기술별 추가** (MDG 파일에서 확인): BPMN Process/Conversation/Choreography(BPMN 2.0), ArchiMate 3.1/2 뷰,
Data Flow Diagram(DFD 기술), Mind Mapping, Kanban/Whiteboard, Executable State Machine, Wireframing, Strategy 등.

**[2차 재검증 정정 — 2026-11-22]** 1차 스캔의 "SysML 0건"은 **오답**이었다. 문자열 추출기가 UTF-16LE 인코딩을
일부 누락해 생긴 오차로, 원본 바이트 재검사에서는 SysML이 명확히 존재한다: ASCII 24건 + **UTF-16LE 250건**,
`MDG Technology for SysML`(Trial), `MDGDgm=SysML`, 그리고 다이어그램명 그 자체 — **"SysML Block Definition
Diagram", "SysML Internal Block Diagram", "SysML Parametric Diagram"**(SysML1.1~1.4::BlockDefinition/
InternalBlock/Parametric 스테레오타입), UML 종류의 SysML 재라벨(Activity/UseCase/Sequence/StateMachine/Package),
requirement 서브타입(functional/performance/interface/physical/extended), ConstraintBlock/InterfaceBlock,
그리고 **SysMLSim**(Modelica 솔버 시뮬레이션). 또한 이 재검증에서 **Robustness Diagram**(ICONIX — "Robustness
Diagram.View by class" + ControlFlow 검증 규칙)과 **Timeline/Roadmap**("Timeline Properties", "Roadmap Title",
"IsTimeline")도 코어 기능으로 확인했다. 제품 카탈로그는 이 정정을 반영해 SysML 그룹(BDD/IBD/Parametric)과
Robustness를 추가했다(총 37종).

커버리지 한계: 리본 XML의 일부 `<Apply>`만 추출돼 EA가 UI에서 분류하는 세부 라벨 전체와 1:1이 아닐 수 있고,
EA의 전 종류 중 "우리 데이터로 그릴 수 있는 것"만 골랐다. 둘 다 카탈로그와 docs에 명시했다. 1차 판정이 인코딩
휴리스틱에 how 영향받는지 보여준 사례라, "0건" 클레임은 항상 원본 바이트 재검증을 거치도록 절차를 고친다.

## 5. 우리 도구로의 재현 (구현 결정 — ADR-0024)

- **카탈로그**: `bts_sbom_app/diagrams.py` — 33종(위 레지스트리 + Code Intel lane). 각 종류는 EA 그룹/이름과
  실측 데이터원을 함께 선언. Mermaid 텍스트로 출력(이미 벤더딩된 mermaid로 렌더, 실패 시 소스 텍스트 폴백).
- **추론 엔진**: `bts_sbom_app/decision.py` — DMN식 결정 테이블 평가기(hit policy F/U/A/P, 밴드 순위 비교,
  결측 입력은 미발화+트레이스). 기본 테이블은 이 도구의 remediation-policy(악성→검역 등 8규칙, F 정책).
- **대화 중 그리기**: 챗 도구 `draw_diagram`(kind/target/spec; kind=catalog는 목록, 화살표 문장은 custom으로
  즉석 그리기) + `decide`(측정 팩트 위 추론). 응답과 SSE final 이벤트 모두 `diagrams` 페이로드를 실어 보내고,
  채팅 독(bts_chat_panel.js)과 Diagrams 탭(bts_console.js)이 같은 마크업 계약(.arc-dwrap)으로 렌더한다.
- **탭**: 🖼 Diagrams (`/api/diagrams` 카탈로그 + `/api/diagrams/<kind>?project&target&spec`).
- **arch 기록 확장**: `arch.analyze`가 실측 import 엣지를 cap 3,000으로 기록("edges") — 패키지/컴포넌트/DFD/
  레이어 다이어그램의 데이터원. 기존 레코드엔 없고, 없으면 그 이유를 노트에 쓴다.

## 6. 한계 (정직 계약)

- 정적 분석만 했다(설치본 미실행). EA의 렌더링·레이아웃 알고리즘은 리버스하지 않았고 우리 레이아웃은 Mermaid에
  위임한다 — "EA와 똑같이 생긴 그림"이 아니라 "EA의 다이어그램 **종류**를 우리 측정값으로 그린 그림"이다.
- MSI 내 일부 파일명은 8.3 단축명으로 복원됐다(장명은 File 테이블로 회복).
- EA.exe 문자열 추출은 ASCII/UTF-16LE 휴리스틱이라, 리소스 전체(아이콘·압축 리소스)의 정보는 미포함.
- 추출물은 `C:\firebaseprojects\REA\scitools\extract\` 에 그대로 두었다(실행 금지, 각자 새 디렉터리 원칙).
