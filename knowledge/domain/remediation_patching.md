# 수정과 패치 (Remediation and patching)

## 안전 버전 계획

컴포넌트마다 모든 취약점을 해소하는 가장 낮은 버전을 고른다: 취약점별 fixed 버전 중 최댓값이다. 메이저 버전이 바뀌면 `major_bump` 와 `breaking_risk=high` 로 표시해 호환성 검토를 요구한다.

## OSV 재조회 검증 (verification)

후보 버전(package, safe_version) 자체를 OSV 에 다시 조회한다. 후보에 남은 취약점이 있으면 다음 fixed 버전으로 올리고 최대 3회 반복한다.
결과는 `clean=true`(OSV 가 후보에 알려진 취약점 없음으로 답함), `clean=false`(잔여 취약점 있음, ID 목록 포함), `clean=null`(OSV 에 닿지 못함, 깨끗함으로 취급하지 않음)이다.

## 승인 게이트 (approval)

승인 없이는 파일을 하나도 바꾸지 않고 계획만 돌려준다(status `not_approved`). 승인 시 계획의 해시(digest)를 토큰으로 대조해, 검토 후 계획이 바뀌었다면 `digest_mismatch` 로 거부한다.

## 무엇을 고치는가

락파일(package-lock.json, poetry.lock, Cargo.lock, go.sum, Gemfile.lock 등)은 무결성 해시를 오프라인으로 다시 계산할 수 없으므로 직접 수정하지 않는다.
대신 그 의존성을 선언한 매니페스트를 수정한다: requirements.txt, package.json(직접 의존은 범위 갱신, 전이 의존은 overrides/resolutions), go.mod, Cargo.toml, pom.xml(버전 속성 포함), composer.json, Gemfile.
그리고 실행할 재생성 명령(`npm install --package-lock-only`, `go mod tidy`, `cargo update -p`, `bundle update`)을 알려준다.
상한 제약이 후보를 막거나(`<1.0`), Go 메이저 2 이상이 모듈 경로 변경을 요구하면 강제로 올리지 않고 `blocked` 로 보고한다.

## 재스캔 검증과 되돌림 (loop)

패치 후 같은 스캔을 다시 돌려 취약점이 실제로 줄었는지 확인한다. 늘었으면 작업 복사본을 패치 이전 커밋으로 되돌리고 `regression_reverted` 를 보고한다.
계획이 두 번 같으면 공회전(spinning)으로 멈춘다. 스캐너가 읽는 락파일이 그대로면 재스캔 수치는 변하지 않으므로, `estimated_fixed`(계획 기준 추정)와 `rescan_fixed`(재스캔 확인)를 구분해 보고한다.

## 전달 대상 (delivery)

- branch: 작업 복사본의 fix 브랜치에 커밋하고 diff 를 돌려준다(기본).
- folder: 변경 파일, fix.patch, PATCH_REPORT.md 를 지정한 폴더로 내보낸다.
- inplace: 원본 로컬 폴더에 git apply 로 적용한다. `allow_origin_write` 가 있어야 한다.
- github: fix 브랜치를 지정한 원격 저장소로 push 한다. `allow_push` 가 있어야 하고, PR 은 `open_pr` 가 추가로 있어야 만든다.
원본 폴더와 원격 저장소는 명시 플래그 없이는 절대 변경되지 않는다.

## 패치 후 새로운 문제가 생기면 원상복구

패치를 적용했는데 새로운 문제(회귀, regression)가 생기면 자동으로 원상복구(revert)한다 — 편집 파일 범위의 재스캔에서 발견이 늘어나면 패치 전 커밋으로 되돌린다. 고쳤는데 새 문제가 더 생기면 원상복구 하나가 원칙이며, 사용자가 승인한 계획의 digest와 다르면 적용하지 않는다.
