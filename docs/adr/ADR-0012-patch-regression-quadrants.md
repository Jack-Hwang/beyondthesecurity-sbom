# ADR-0012: Patch regression in four quadrants; review is advice over artefacts only

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/impact.py`(신규), `bts_sbom_app/review.py`(신규), `bts_sbom_app/pipeline.py:_patch_loop` 연동. AC: BSA-AC-316~333, 테스트 `tests/bts_sbom_app/test_impact_review.py`.

## 근거 (Context)
`pipeline._patch_loop`의 회귀 판정은 "수정한 파일에 속한 발견 건수"(scoped_before/after)만 비교했다 — 손대지 않은 락파일이 판정에서 제외되고(코드 주석), 같은 컴포넌트를 선언한 다른 매니페스트·다른 프로젝트는 아예 보지 못했다. 강의 3주차 3차시(AI DBA)는 변경을 direct/upstream/downstream/shared 4분면으로 검증하고(shared = "가장 자주 누락됨"), 만든 쪽이 아닌 독립 리뷰를 요구한다. 승인 토큰·재스캔·되돌림은 이미 있었고(AC-14/15/18), 4분면과 독립 리뷰는 없었다.

## 결정 (Decision)
4분면을 SBOM 의미로 번역한다: direct = 업그레이드한 컴포넌트의 발견(해소/잔존/신규 도입), upstream = 편집된 매니페스트의 미수정 형제 컴포넌트 신규 발견(+blocked는 회귀 아님), downstream = 전이 의존성 신규 발견 + 업그레이드된 컴포넌트를 여전히 고정하는 미편집 락파일(unverified — 다시 만들기 전엔 알 수 없음), shared = 같은 컴포넌트가 선언된 미수정 (락이 아닌) 매니페스트 + fleet 기록이 주어지면 같은 구버전을 쓰는 다른 프로젝트 수(정보 제공). 자료가 없는 분면은 unverified(ok 아님). 종합: regression > incomplete > clean. 리뷰어(`review.review`)는 산출물(계획 매니페스트, 변경 파일, diff 크기, impact, 업그레이드 목록)만 받고 조언 전용 — 승인은 기존 16자리 다이제스트 토큰 그대로.

## 기각 대안 (Rejected alternatives)
- 수정한 파일만 계속 판정: shared 분면 누락 — 부분 수정(같은 컴포넌트의 다른 매니페스트)을 회귀로 보지 못함.
- LLM 리뷰어: 비결정적, 키 필요, AI 호출 지점 레지스트리(AC-207 계열) 요구 — 규칙 기반으로 충분.
- 리뷰어가 승인을 대신함: 승인 게이트 약화 — 사람 승인 토큰(AC-14/15)과 이중 게이트를 유지.

## 결과 (Consequences)
패치 결과에 `impact`(4분면+verdict)와 `review`(규칙 R1~R6 판정)가 추가된다(추가형만; 기존 status 값 불변). 락파일이 재생성되지 않으면 downstream이 unverified가 되어 verdict가 incomplete가 되고, 리뷰가 R5로 changes_requested를 권한다. impact 계산 실패는 `impact.error`로 기록되고 패치 상태는 그대로다(AC-333).
