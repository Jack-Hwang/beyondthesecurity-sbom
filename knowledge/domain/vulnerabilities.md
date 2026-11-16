# 취약점 분석 (Vulnerability analysis)

## 데이터 출처

취약점은 OSV.dev(api.osv.dev)에서 조회한다. 패키지 좌표(ecosystem, name, version)만 외부로 나가며 소스 코드는 나가지 않는다.
같은 취약점의 GHSA, CVE, PYSEC 레코드는 별칭(alias)으로 묶어 하나의 finding 으로 합친다. 대표 ID 는 CVE 를 우선한다.

## 심각도 (severity)

CVSS v3.x 벡터에서 기본 점수(base score)를 직접 계산한다: 0.1-3.9 LOW, 4.0-6.9 MEDIUM, 7.0-8.9 HIGH, 9.0 이상 CRITICAL.
CVSS v4 벡터는 점수 계산을 하지 않고 권고문의 심각도 라벨을 사용하며, `score_source` 에 그 사실을 남긴다. 둘 다 없으면 UNKNOWN 이다. 추측하지 않는다.

## 수정 버전 (fixed version)

OSV 범위 이벤트 중 ECOSYSTEM 과 SEMVER 타입만 사용하고, 현재 설치 버전이 [introduced, fixed) 구간에 속한 범위의 fixed 이벤트를 고른다.
GIT 타입 범위(커밋 해시)는 버전이 아니므로 무시한다. bts_sbom v0.1.0 의 guided remediation 은 커밋 해시를 safe_version 으로 내놓는 결함이 측정되어 사용하지 않는다.
알려진 수정 버전이 없는 취약점은 `no_fix` 로 보고하고 대체 라이브러리 검토나 위험 수용 승인을 권고한다.

## 데이터 완결성 (honesty)

"데이터 없음"은 "취약점 없음"이 아니다. OSV 조회가 실패하면 그 컴포넌트는 깨끗하다고 보고하지 않고 미검증으로 남긴다.
스캐너가 지원하지 않는 매니페스트(unsupported manifest)가 있으면 빈 프로젝트로 숨기지 않고 목록에 노출한다.

## 우선순위

CRITICAL 과 HIGH 를 먼저, 같은 심각도 안에서는 CVSS 점수와 영향 컴포넌트 수 순으로 정렬한다. KEV(Known Exploited Vulnerabilities) 같은 악용 정보는 별도 데이터가 있을 때만 반영한다.
