# ADR-0011: Host-level circuit breaker and four-state fetch outcomes

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/resilience.py`(신규), `bts_sbom_app/net.py:fetch_json/fetch_text`. AC: BSA-AC-301~313 (`specs/bts_sbom_app_features.md`), 테스트 `tests/bts_sbom_app/test_resilience.py`.

## 근거 (Context)
`net.py`의 `http_json`/`http_text`는 재시도·백오프는 있었지만 404(근거 없음)와 접속 실패(확인 못 함)가 둘 다 `None`이라 호출자가 구분할 수 없었고(net.py 구 `http_json` 404 분기와 `_count(False, ...)` 비교), 한 호스트가 죽어 있어도 컴포넌트 수천 개에 대해 호출마다 재시도했으며(`bts_sbom_app/licenses.py:349` 이하 호출처), 서버가 준 `Retry-After`는 무시됐다. 이 도구의 정직 계약("없음 ≠ 안전", AC-7: OSV 질의 실패 → 검증은 unverified)은 "확인하지 못함"을 "찾지 못함"과 구분할 것을 요구한다.

## 결정 (Decision)
호스트(`urlsplit(url).netloc`) 단위 서킷브레이커(연속 실패 3 → Open 60초 → Half-Open 탐침 1회)와 네 상태 `Outcome`(success / empty_result / partial_result / access_failure)을 도입한다. 기존 `http_json`/`http_text`는 얇은 래퍼로 유지해 반환값(데이터 또는 None)을 바꾸지 않는다. 404는 브레이커에 중립(연속 실패를 늘리지도 지우지도 않음), 잘린 본문은 partial_result, 재시도 소진·서킷 열림은 access_failure("확인하지 못함"). 재시도 가능: 타임아웃·429·5xx·URLError. `Retry-After`(정수 초)는 백오프에 반영하되 상한 30초. `BTS_SBOM_BREAKER_THRESHOLD=0`이면 비활성.

## 기각 대안 (Rejected alternatives)
- 호출마다 재시도만 유지: 죽은 호스트에 컴포넌트 수천 개만큼 계속 요청 → 스캔이 수 분 지연되고 429로 이웃 서비스까지 피해.
- 전역 단일 브레이커: 한 호스트의 장애가 전체 외부 조회를 막는다(호스트 격리 상실).
- 예외 기반 API로 교체: 호출처(licenses/osv/arch) 전부 수정 필요 → 회귀 위험이 크고 정직 계약과 무관한 변경.

## 결과 (Consequences)
브레이커가 열려 건너뛴 호출은 항상 `access_failure`(reason `circuit_open`)이며 어떤 경로에서도 통과/없음으로 바뀌지 않는다. 통계에 `short_circuited`/`empty`/`partial`이 생겨 런북의 모니터링 지표(작업 17)로 쓸 수 있다. 단위 테스트는 가짜 시계·가짜 `net.SLEEP`·TRANSPORT 훅(3-튜플 확장, 하위 호환)으로 오프라인에서 측정한다.
