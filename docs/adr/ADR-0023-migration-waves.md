# ADR-0023: 업그레이드 영향을 물결(A/B/C)로 계획하고 사이트 0건을 영향 없음이라 하지 않는다

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/migration.py`(신규), `bts_sbom_app/pipeline.py`(migration 단계), `bts_sbom_app/server.py`(/api/migration/(by project)), `bts_sbom_app/cli_ext.py`(migration --source), `bts_sbom_app/report.py`(Migration plan 절). AC: BSA-AC-646~657, 테스트 `tests/bts_sbom_app/test_migration.py`.

## 근거 (Context)
주제 선언 2번의 "코드 수정이 매우 어렵다". `breaking_risk` 는 주 버전 점프만 보고, "내 코드의 몇 군데를 건드리는가"는 알 수 없었다. `contextpack.build` 가 경계 있는 읽기 전용 import 사이트 수집을 이미 제공한다.

## 결정 (Decision)
계획 행마다 jump(patch/minor/major/unknown, versions 파서)와 코드 사이트(available/files/sites/bounded — direct 컴포넌트이고 소스가 주어졌을 때만; 전이 의존성은 "no direct import", 소스 미제공은 "source not provided")를 계산하고 물결을 결정적으로 정한다: A=minor·patch 업그레이드(사이트 ≤ SITE_THRESHOLD 10 또는 전이), B=major·unknown jump 또는 사이트 > 10, C=no_fix 또는 legacy 위험 high(옵션 replace/accept_risk/pin/monitor, accept_risk 는 VEX+만료일 안내). 사이트 0건은 note 로 "import 이름이 패키지 이름과 다를 수 있다 — 영향 없음의 증거가 아니다"를 남긴다. 모든 항목 needs_human, 분석 대상 트리에 쓰기 0건(AC-652). 결정적 출력 — 같은 입력은 바이트 동일.

## 기각 대안 (Rejected alternatives)
- 변경 내역을 자동으로 내려받아 API 변경을 판정: 네트워크 의존 + 이 환경에서 확인 불가 — 릴리스 노트 확인은 체크리스트로 남긴다.
- 사이트 0건이면 "영향 없음" 처리: import 이름이 패키지 이름과 다르면(PyYAML→yaml) 거짓 안심이 된다.
- 물결을 LLM 에게 정하게 함: 비결정적 — 규칙은 코드로 강제한다.

## 결과 (Consequences)
기록에 `migration` 키 추가(축가형). 사이트 계산은 contextpack 의 경계 있는 읽기를 재사용하므로 바이너리·초대형 파일·링크는 이미 제외된다. 사이트 상한은 `SITE_THRESHOLD`(10)와 max_sites 인자로 조정 가능.
