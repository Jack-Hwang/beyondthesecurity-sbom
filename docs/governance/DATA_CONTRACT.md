# DATA CONTRACT — 프로젝트 기록 스키마

## Schema

- 현재 스키마: **`bts-sbom.project.v1`** (`bts_sbom_app/pipeline.py:PROJECT_SCHEMA`).
- 수용하는 이전 스키마: **`sbomplus.project.v1`** (`PROJECT_SCHEMAS_ACCEPTED` — 같은 레이아웃, 식별자만 다름. 읽기 전용 호환).
- 최상위 필드(코드에서 확인): `schema`, `name`, `source`, `ref`, `components[]`, `vulns[]`, `plans[]`, `license{}`,
  `arch{}`, `sectors{}`, `patch{}`, `proposals{}`, `sbom_check{}`, `engine{}`, `error`, 그리고 산출 단계가 채우는
  `timings`, `stage_errors`, `metrics`, `artifacts`, `origin_unchanged`, `elapsed_s`, `changes`(이전 분석이 있을 때).
- 선택 필드(구현돼 있을 때만 나타난다 — 소비자는 키 부재에 관대해야 한다):
  - `vulns[*].conflicts[]`(작업 7: 출처 상충 — 값·출처·날짜)와 엔진 `adjustments.advisory_conflicts`.
  - `patch.impact{}`(4분면)·`patch.review{}`(독립 리뷰, 작업 1).
  - `patch.approved_by`(클라우드 승인자 신원, 작업 10).
  - `obligations`(사용 형태별 소스 공개 의무, `bts-sbom.obligations.v1`) · `legacy`(EOL·수명주기 위험, `bts-sbom.legacy.v1`) ·
    `alternatives`(대체 후보, `bts-sbom.alternatives.v1`) · `migration`(이관 물결, `bts-sbom.migration.v1`) — **옛 기록에 키가
    없으면 API·CLI 가 읽을 때 증거(`components` 등)로 계산한다**(`computed_on_read: true`, 네트워크 0건). 각 키의 직렬화
    크기는 잘랐을 때 `truncated: true` 와 원래 개수를 기록한다(ADR-0020~0023).

## Invariants (불변식)

1. **근거가 없으면 통과가 아니다**: 검증 실패는 `verification.clean = null`(unverified)으로 남는다 — 절대 true 로
   승격되지 않는다(AC-7, OSV 실패 → unverified).
2. **원본 무변경**: `origin_unchanged` 가 true 로 기록되려면 원본 트리 해시가 같아야 한다(AC-1).
3. **`verification: null` 의 의미**: "확인하지 못했다" — 안전하다는 뜻이 아니다. 소비자는 null 을 실패처럼 취급해야 한다.
4. **SKIP/NOT RUN 은 PASS 로 세지 않는다**: `stage_errors` 는 숨겨지지 않고, 부분 결과는 항상 보인다.
5. 임의의 새 필드 추가는 호환이다(읽는 쪽이 모르는 키를 버린다); 키 제거·의미 변경은 스키마 버전을 올려야 한다.

## Files (증거 폴더 배치)

```
evidence/                                  # the configured --evidence folder
  project-name/project-name.json   프로젝트 기록(이 계약의 주제; 이름은 safe_name 규칙)
  project-name/project-name.prev.json   이전 분석(변경 비교용 — 인스턴스 잠금으로 동시 교체 방지, ADR-0019)
  project-name/codeprop/proposal-id.diff       코드 수정 제안 diff(제안 전용 — 적용은 CLI 다이제스트 토큰, ADR-0024)
  .jobs/job-id.json                스캔 작업 기록(bts-sbom.job.v1, 작업 6)
  .llm_config.json                콘솔 저장 키(평문, gitignore·0600 — 클라우드에서는 생성 거부, AC-465)
  .llm_ledger.json                일일 호출 장부
  audit.jsonl                    감사 해시 체인(작업 10)
  loop/                          루프 패스 기록
  cache/                         원본 증거 캐시(ADR-0009)
```

## Versioning

- 스키마 식별자는 `bts-sbom.project.v<N>` 형태다. 현재 v1.
- 버전을 올리는 기준: 필드 제거, 의미 변경, 구조(리스트→맵 등) 변경. 필드 추가는 v1 유지.

## Compatibility

- 읽는 쪽: `PROJECT_SCHEMAS_ACCEPTED` 에 있는 스키마만 받는다(현재 v1 + sbomplus.project.v1).
- 쓰는 쪽: 새 필드는 항상 추가형 — 이전 소비자가 알 수 없는 키를 만나도 동작해야 한다(위 Invariants 5).
- 작업 기록(`bts-sbom.job.v1`)과 이벤트(`bts-sbom.events.v1`)는 별도 계약이며 같은 규칙(추가형 변경만)을 따른다.
