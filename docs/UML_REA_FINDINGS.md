# UML_REA_FINDINGS — Sparx EA 17.2 "지하 500층" 재하강 (2026-11-28)

요청: "ea tool 지하 500층까지 쥐어짜듯이 REA해서, 우리 도구에 실제 레거시 코드를 구현하기 위해 UML 다이어그램을
보여주면서 설계하는 기능을 추가하라." 대상은 `C:\firebaseprojects\REA\scitools` (EA 17.2.1721.15 Trial MSI 추출
트리, docs/EA_REA_FINDINGS.md 1차 조사 이후). 이번 2차 하강은 **EA.exe 단일 152MB 모놀리스에서 EA가 자기 다이어그램을
정의하는 1차 자원을 통째로 회수**하는 것이었다 — 내장 UMLProfile XML 34개 전체, 요소 어휘 테이블, 저장소 DDL.

## 1. 다이어그램 레지스트리 전체 (EA.exe 내장 `<UMLProfile>` XML 34블록 — 1차 증거)

EA가 자기 툴박스/다이어그램을 정의하는 방식은 자기 서술 XML이다: `<UMLProfile profiletype="uml2">` 블록 34개가
바이너리에 통째로 내장돼 있다. 레지스트리 전수:

UML Structural · UML Behavioral · Extended · Extended::Analysis · **UML::UseCase · UML::Class · UML::Package ·
UML::Object · UML::Composite · UML::Communication · UML::Interaction · UML::Timing · UML::State · UML::Activity ·
UML::InteractionOverview · UML::Component · UML::Deployment · UML::Profile · UML::Metamodel** · Extended::Construction ·
Extended::Custom · Extended::XMLSchema · Extended::WSDL · Extended::Requirements · Extended::Maintenance ·
Extended::UserInterface · Common · DatabaseEngineering::DataModeling · Extended::Documentation · Extended::Business ·
Extended::Testdomain · Extended::Dashboard · Extended::XMLTransform

각 블록의 구조: `<Documentation id name version notes>` + `<Content><Stereotypes><Stereotype name notes alias>` +
`<AppliesTo><Apply type="Diagram_X|ToolboxPage">` + `<TaggedValues><Tag name="UML::X" default="툴박스 표시명">`.
이것이 EA 다이어그램 카탈로그의 1차 증거다 — 우리가 1차 조사에서 따로 모았던 37종 카탈로그의 원천이 여기 있다.

## 2. 다이어그램별 툴박스 어휘 (우리 설계 팩이 따라야 할 노테이션 계약)

- **UML::Class (id 5AC79957-8, v7.0)**: ClassElements 툴박스 = Class · Interface · Data Type · Enumeration ·
  Primitive · Signal · AssociationElement. → 클래스 다이어그램이 담을 수 있는 요소의 EA 공식 집합.
- **UML::State (id A7FEB956-B, v7.0)**: State · StateMachine · **Initial · Final · History · Synch · Choice ·
  Junction · EntryPoint · ExitPoint**(+ Deep/Terminate 등). → 상태머신 다이어그램의 의사상태 어휘.
- **UML::Interaction (id 3180369F-0, v7.0)**: Actor · **Lifeline** · Boundary · Control · Entity(ICONIX 3분할) ·
  **InteractionFragment(Fragment)** · MessageEndPoint · Gate · State/Continuation. fragment 토큰 실측:
  alt/opt/par/loop/critical/neg/region — 시퀀스 결합 조각 어휘.
- **UML Structural/Behavioral 블록**: 다이어그램 정의 자체가 EA의 공식 문장으로 내장 — 예: Sequence =
  "specify element behavior as a sequential series of messages passing back and forth, against a vertical time
  scale", State Machine = "model the internal behavior of an element as a graph of states and transitions".
  → 우리 설계 팩의 각 다이어그램 설명 문장은 이 원문을 인용한다(지어내지 않는다).

## 3. 요소·연결자 어휘 (Object_Type / Connector_Type 실측)

EA의 Object_Type 어휘 클러스터(EA.exe 내부 테이블 데이터)에서 측정: State · Signal · Slot · StartClassifierBehaviorAction ·
StateInvariant · Substitution · TimeEvent · TimeObservation · Trigger · UnmarshallAction · Usage · UseCase · ValuePin ·
**ActivityFinal · ActivityInitial · Assembly · AssociationEx · EA_Requirement · Choice · CollaborationOccurrence ·
Composition · Decision · DeepHistoryState · Delegate · EntryPoint/ExitPoint(+Embedded) · HistoryState · InitialState ·
InterruptFlow · Junction · Note · PackagingComponent · Part · Receive · Send · Synchronization(_H/_V) · Terminate ·
ProvidedInterface · RequiredInterface · EA_Attribute · EA_Operation**.

연결자 레지스트리: `t_connectortypes (Connector_Type TEXT NOT NULL COLLATE NOCASE PRIMARY KEY, Description TEXT)` —
다이어그램 종류와 연결자 종류가 **문자열 키로 저장소 스키마에 박혀 있다**. 존재 실측: Association · Aggregation ·
Composition · Dependency · Generalisation/Generalization(양 철자 공존) · Realisation/Realization · Delegate ·
Assembly · Usage · Association Class. 가시성 어휘: Public · Private · Protected · Package.

## 4. 저장소 메타모델 (DDL 실측)

EA.exe 내장 DDL은 `CREATE TABLE t_*_original / t_*_replica` 쌍 188+개 — 기업 DB 복제 스키마. 핵심 테이블:
t_diagram(Diagram_Type이 NOCASE PK) · t_diagramobjects(Rect 좌표가 일급 데이터) · t_object · t_connector ·
t_attribute · t_operation · t_connectortypes · t_diagramtypes. → **EA의 노테이션은 스키마가 계약이다**: 클래스 다이어그램
의미의 attribute/operation/connectortype이 전부 독립 테이블로 정규화돼 있다. 우리 설계 팩도 측정값을 같은 정규형
(요소/속성/연산/연결)으로 뽑고 나서 머메이드로 투영한다.

## 5. 우리 도구에의 채택 (구현 = bts_sbom_app/uml_design.py)

EA가 다이어그램을 "요소 어휘 + 연결자 레지스트리 + 정규형 계약"으로 정의하는 것을 그대로 따른다:

| EA 1차 증거 | 우리 설계 팩 매핑 (Mermaid) |
|---|---|
| 가시성 Public/Private/Protected/Package | `+` / `-` / `#` / `~` |
| Generalisation / Association / Aggregation / Composition / Dependency | `--|>` / `-->` / `o--` / `*--` / `..>` |
| UML::Interaction Lifeline · InteractionFragment · 활성 | `participant` · `alt/opt/loop` · `activate/deactivate` |
| UML::State Initial/Final/Choice/Junction/History | `[*]` · `state choice` · `note` |
| UML::Class 툴박스의 Enumeration/Interface | mermaid `class` + `<<enumeration>>` / `<<interface>>` |

설계 팩은 레거시 소스를 ast로 정규형 계약(요소/속성/연산/연결)으로 측정하고, 그 측정값만 머메이드로 투영한다 —
클린룸 벽 1의 명세 채널(구조는 명세, 본문은 아님)과 정확히 같은 규칙이다.
