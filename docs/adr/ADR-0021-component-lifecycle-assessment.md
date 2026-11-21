# ADR-0021: 컴포넌트 수명주기(EOL·업스트림 수정 부재)를 결정적 신호로 평가한다

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/legacy.py`(신규), `bts_sbom_app/pipeline.py`(legacy 단계), `bts_sbom_app/server.py`(/api/legacy/(by project)), `bts_sbom_app/cli_ext.py`(legacy), `bts_sbom_app/report.py`(Legacy 절). AC: BSA-AC-616~628, 테스트 `tests/bts_sbom_app/test_legacy.py`.

## 근거 (Context)
주제 선언 2번 — "EOL 이 지난 소프트웨어 패키지 때문에 코드 수정이 어렵다". 기존 `arch.runtime_eol` 은 **런타임**(파이썬·노드)만 판정하고 컴포넌트(프레임워크 등)의 지원 종료는 보지 못한다. `remediate.plan` 의 `status: "no_fix"` 는 이미 "OSV 에 수정 버전이 없음"의 측정 신호다.

## 결정 (Decision)
두 신호만으로 위험을 계산한다: ① EOL(endoflife.date, 오프라인이면 내장 표 — 출처에 UNVERIFIED 를 그대로 남긴다; 매핑·버전 파싱 실패는 unknown 이고 절대 supported 가 아니다), ② no_upstream_fix(계획 행이 no_fix 이고 권고 ≥1 — "버려진 패키지"라고 단정하지 않고 "OSV 에 수정 버전이 없음"이라고만 쓴다). 위험 등급은 결정적(high/medium/low/unknown; EOL unknown 은 low 가 아니다). 제품 매핑은 **시드 5개**(django/angular/spring-boot/rails/laravel)로 한정하고 누락·형태 오류 항목은 로더가 거부한다. 행은 위험→이름 정렬로 바이트 동일 출력.

## 기각 대안 (Rejected alternatives)
- 이름만 보고 "오래된 것 같은" 휴리스릭: 근거 없는 단정 — 정직 계약 위반.
- 임의 패키지의 마지막 릴리스 날짜로 abandonment 판정: 이 환경에서 확인 불가(실제 응답 없음) + 패키지마다 다른 브랜칭 관행 때문에 오류율이 높다.
- 매핑을 기억으로 확장: 부록 B-1("확인 필요") 위반 — endoflife.date 의 실제 슬러그를 확인하기 전엔 시드 5개만.

## 결과 (Consequences)
파이프라인 기록에 `legacy` 키 추가(추가형). `eol_tolerance` 정책(작업 28)이 findings 목록을 채운다. endoflife.date 의 실제 슬러그·주기 표기와 응답 행 형태는 확인 필요(부록 B-1) — 다르게 나오면 unknown 이 되도록 구현돼 있다.
