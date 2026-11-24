# VS 2026 REA FINDINGS — 실제 아티팩트 역분석 기록 (2026-11-22)

방법: 블라인드 ISO 다운로드 대신 **채널 → 제품 매니페스트 → 표적 페이로드** 방식. aka.ms/vs/18/release/*
별칭은 미등록(Bing 리다이렉트)이었고, 공식 downloads 페이지에서 **LTSC 18.11 채널 별칭**을 발견해 진입했다.
모든 다운로드 산출물은 downloads/vs2026/에 보관(재분석 가능), 실행은 한 번도 하지 않았다(정적 REA만).

## 1. 취득 경로와 정품성

| 아티팩트 | sha256 | 정품성 (REA) |
|---|---|---|
| `vs_Enterprise_ltsc.exe` (5.69 MB) | 1f8f7c27d46c…78683f | Authenticode PKCS#7: 서명자 **Microsoft Corporation** (Microsoft Code Signing PCA 2024 체인, 타임스탬프 속성 1.3.6.1.4.1.311.3.3.1 존재) — REA `inspect_pe_certificates` |
| `VisualStudio.18.Release.LTSC.18.11.chman` (117 KB) | 채널 매니페스트 | channelItems 11건: 제품별 Product/Bootstrapper 엔트리 |
| `VisualStudio.vsman` (18.7 MB) | 제품 매니페스트 | **패키지 21,065개** 카탈로그 |
| `Microsoft.VisualStudio.GraphModel.vsix` (255 KB) | GraphModel.dll: f5836fa6…ce8f8a45 | 18.0.0.0 · Microsoft 강력서명 b03f5f7f11d50a3a · .NET FW 4.7.2 · il-only |
| `Microsoft.VisualStudio.Layer.vsix` (673 KB) | LayerDesigner.Dsl.dll: 4a4fc48e…3380f4cc | 18.0.0.0 · 동일 강력서명 · 8개 DLL (DSL/DSLPackage/DslProvider/Common…) |

증거 ID: ev_2d5b1460(부트스트래퍼 인증서), ev_99ada107(GraphModel 아티팩트), ev_64ac1e8f(LayerDesigner 멤버).

## 2. REA로 추출한 실제 레이어 검증 모델 (LayerDesigner.Dsl 18.0.0.0)

검증 규칙 인벤토리 (ValidationMethod 어트리뷰트 클로저·메서드명에서 추출):

- **ForbiddenNamespace / ForbiddenNamespaceDependencies** — 레이어 노드가 거부 네임스페이스 규칙을 속성으로
  갖는다(자체 저장소 PropertyHandler 포함). 우리 `forbidden` 거부리스트가 이 의미론과 동일하다.
- **ValidateLayerHasNoOrObsoleteArtifacts** — 매칭되는 아티팩트가 없거나 폐기된 레이어를 찾는 규칙. 우리
  `obsolete_layers`가 채택한 바로 그 의미다.
- **ValidateMonikerAmbiguity** — 모니커(참조 해석 키) 중복·모호 검사. 우리는 모니커 체계가 없어 **미채택**
  (도입 시점: 프로젝트 간 참조 별칭을 도입할 때).
- **ValidateReferenceBaseMultiplicity** — 참조 다중성 검사. 도메인 모델 DSL 고유 — **비적용**.
- **LayerNamesMustBeUnique** — 표시명(trim) 기준 유니크. 채택.
- **SupportsValidation** — 아티팩트별 검증 참여 플래그. 관측점으로 기록, 세밀화 후보.

우리 layer_validate는 이제 forbidden 카테고리·obsolete 판정·이름 유니크를 VS와 같은 의미로 수행하고,
`vs_alignment`에 출처(Microsoft.VisualStudio.Layer 18.11.12306.13)를 기록한다 (AC-579).

## 3. DGML 어휘 확인 (GraphModel.dll)

- `DgmlCommonSchema`가 DGML 공용 어휘를 등록한다. "Contains" 카테고리의 실제 정의: *"Whether the source of
  the link contains the target object"* — 우리 지도의 Contains(IsValidContainment)와 동일 의미 확인.
- 스타일 속성(Background/Stroke/StrokeDashArray), GraphDirection/Layout, Paths 별칭은 DGML 레퍼런스 문서와
  일치 — 우리 출력은 문서 표준 안에 있다.

## 4. 채택 / 미채택 요약

- 채택: forbidden 거부리스트, obsolete 레이어, 이름 유니크, Contains 의미 확인 (모두 AC-579로 등록).
- 미채택(기록): MonikerAmbiguity·ReferenceMultiplicity(도메인 모델 전용), SupportsValidation 세밀 제어,
  .layerdiag 저장 형식(비공개 스키마) — 문서화된 DGML을 유지한다.

채굴 도구: `scripts/vs_mine.py`(자체 REA 레인 재사용 — binscan strings), 증거: `downloads/vs2026/rea_findings.json`.
