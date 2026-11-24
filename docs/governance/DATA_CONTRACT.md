# 데이터 계약 (Data Contract) — `bts-sbom.project.v1`

`bts_sbom_app/pipeline.py` 의 `PROJECT_SCHEMA`/`PROJECT_SCHEMAS_ACCEPTED`, `run_project()`, `persist()` 를 읽고 실제
필드만 적는다.

## 스키마 (Schema)

프로젝트 분석 기록의 스키마 식별자는 `"bts-sbom.project.v1"`(`pipeline.PROJECT_SCHEMA`)이다. `run_project()` 가 만드는
기록은 최소한 다음 최상위 키를 갖는다(코드의 초기화 딕셔너리와 이후 단계에서 채워지는 키를 합한 것):

| 키 | 채우는 단계 | 내용 |
|---|---|---|
| `schema` | 초기화 | 항상 `"bts-sbom.project.v1"` |
| `name`, `source`, `ref` | 초기화 | 프로젝트명, 원본 소스 문자열, 참조(브랜치/태그) |
| `components`, `vulns` | `analyze` | SBOM 컴포넌트 목록, OSV 발견 목록 |
| `plans`, `plan_summary` | `plan`/`verify` | 재검증된 업그레이드 계획과 요약 |
| `license` | `licenses`/`license_tree` | `stats`, `project_license`, `project_license_source`, `tree`, `policy` |
| `arch` | `arch` | 핫스팟, import 순환, 런타임 EOL, 클러스터 |
| `sectors`, `conformance` | `sbom`(내부 `build_sboms`) | 산업별 리포트, SBOM 적합도 |
| `sbom_check` | `sbom` | CycloneDX/SPDX 유효성 요약 |
| `patch` | (옵션) `patch` | 승인 게이트를 통과한 패치 결과(ADR-0008) |
| `proposals` | (옵션) `proposals` | AI 제안(ADR-0010 이 다루는 검증·강등을 거친 결과) |
| `engine` | 전체 | 코어 버전, 소스 목록, `data_status`, `vulnerability_presence` |
| `timings`, `stage_errors` | 전체 | 각 단계 소요 시간과, 실패했지만 숨기지 않은 단계별 오류 |
| `elapsed_s`, `metrics` | 완료 | 전체 소요 시간, 집계 지표 |
| `origin_unchanged` | 완료(옵션) | `deliver_target != "inplace"` 일 때만 원본 트리 해시 비교 결과 |
| `changes` | (옵션) `changes_diff` | 이전 분석과의 Hub 스타일 변경 알림 |
| `error` | 초기화 | 분석 자체가 실패한 경우의 최상위 오류 메시지 |

**구 스키마 수용**: 이름이 바뀌기 전에 기록된 문서는 `"sbomplus.project.v1"` 식별자를 가지고 있을 수 있다 — 레이아웃은
동일하므로 그대로 읽을 수 있어야 한다(`pipeline.PROJECT_SCHEMAS_ACCEPTED = (PROJECT_SCHEMA, "sbomplus.project.v1")`).
새로 쓰는 기록은 더 이상 구 식별자를 쓰지 않는다.

## 불변식 (Invariants)

1. **근거 없으면 통과 아님** — `engine.analyze` 가 완전히 조회하지 못한 범위는 `data_status`/`vulnerability_presence`
   로 정직하게 남고, 빈 발견 목록이 "취약점 없음"으로 조용히 치환되지 않는다(README 정직 규율).
2. **원본 트리 불변** — `deliver_target != "inplace"` 인 모든 실행에서 `origin_unchanged` 는 분석·패치 전후 원본 디렉터리의
   트리 해시가 같을 때만 참이다(`tree_hash(origin)` 비교, `BSA-AC-1`).
3. **승인 없이 쓰기 없음** — `rec["patch"]` 는 `approved=True` 와 플랜 다이제스트 일치 토큰이 모두 있어야 `applied`류
   상태로 바뀐다. 그 외에는 `not_requested`/`not_approved`/`digest_mismatch` 중 하나이며 파일 변경이 0건이다
   (`BSA-AC-14`, `BSA-AC-15`).
4. **회귀는 되돌림** — 패치 적용 후 재스캔이 편집한 파일 범위에서 발견을 늘렸다면 `status == "regression_reverted"` 이고
   작업 사본은 패치 전 커밋으로 되돌아가 있다(`BSA-AC-18`).
5. **실패한 단계는 숨기지 않는다** — 어떤 단계가 예외를 던지면 `stage_errors` 딕셔너리에 그 단계 이름을 키로, 예외
   타입과 메시지를 담은 문자열("타입: 메시지" 형태)을 값으로 기록하고, 그 단계는 기본값으로 계속 진행된다
   (`pipeline._Stages.run`) — 예외를 삼켜서 나머지 기록이 마치 그 단계도 성공한 것처럼 보이게 하지 않는다.
6. **캐시는 원본을, 해석은 읽을 때** — 디스크에 캐시되는 제3자 응답은 원본 그대로이며 정규화는 읽을 때마다 다시
   계산된다(ADR-0009) — 이 계약은 `license` 필드가 과거의 정규화 버그를 영구히 동결하지 않음을 보장한다.

## 버전·호환 (Versioning)

- 스키마 식별자는 레이아웃이 **호환되지 않게** 바뀔 때만 올린다(`v1` → `v2`). 필드를 추가하는 것은 스키마 버전을 올리는
  이유가 되지 않는다 — 기존 필드·반환값·상태 코드는 유지한 채 새 필드만 추가한다(이 브리프와 저장소 전체 규칙).
  예: `arch`/`conformance`/`changes` 는 전부 기존 `bts-sbom.project.v1` 기록에 **추가된** 필드이며, 스키마 식별자는
  바뀌지 않았다.
- 읽는 쪽(이 패키지 자신, 추적성/포트폴리오 도구 등)은 `schema` 값이 `PROJECT_SCHEMAS_ACCEPTED` 안에 있는지 확인하고,
  그 밖의 값은 알 수 없는 스키마로 취급해야 한다(새로 추가되는 호환 식별자가 생기면 이 집합에 추가한다).
- 쓰는 쪽은 항상 현재 식별자(`PROJECT_SCHEMA`)만 쓴다 — 구 식별자로 새로 쓰는 경로는 없다.

## 호환 (Compatibility)

- 구 식별자(`sbomplus.project.v1`)로 저장된 기록은 레이아웃이 동일하므로 추가 변환 없이 읽을 수 있어야 한다(위 수용
  규칙). 필드가 없는 경우(그 기록이 만들어질 당시엔 없던 키)는 "없음"으로 취급하고 지어내지 않는다 — 예:
  구 기록에는 `conformance`/`changes` 가 없을 수 있고, 읽는 쪽은 `rec.get("conformance") or {}` 식으로 부재를
  정직하게 다뤄야 한다.
- 증거 폴더의 파일 배치는 `pipeline.persist()` 가 고정한다: 증거 출력 디렉터리 밑에 안전화된 프로젝트명으로 된
  하위 폴더를 만들고, 그 안에 프로젝트명 + `.json`(기록 자체), 이전 실행이 있었다면 그 백업(프로젝트명 +
  `.prev.json`, 덮어쓰기 전에 복사), SBOM 산출물이 있으면 프로젝트명 + `.cdx.json`(CycloneDX) / `.spdx.json`(SPDX) /
  `.vex.json`(OpenVEX)이 나란히 쓰인다. 이 배치가
  바뀌면(파일명 규칙, 디렉터리 깊이) 호환성 문제이므로 스키마 버전을 올려야 한다.
- 이 계약을 참조하는 도구(`portfolio`/`traceability`/`proof` 등, 다른 패키지가 구현)는 `schema` 필드를 먼저 확인하고
  모르는 값이면 "확인 필요"로 보고해야지, 알려진 레이아웃인 것처럼 읽어서는 안 된다.
