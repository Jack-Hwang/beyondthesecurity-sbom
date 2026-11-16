# nodegoat

- source: `https://github.com/OWASP/NodeGoat.git` (commit `c5cb68a708`)
- components: 1091 - vulnerabilities: 441 {'LOW': 31, 'MEDIUM': 128, 'HIGH': 241, 'CRITICAL': 40, 'UNKNOWN': 1}
- license resolved: 1056 of 1091 (0.968) from {'lockfile': 384, 'deps.dev': 667, 'registry:npm': 5}
- project license: Apache-2.0 (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2020-7610 | bson | 1.0.9 | CRITICAL | 9.8 | 1.1.4 |
| CVE-2021-44906 | minimist | 1.2.0 | CRITICAL | 9.8 | 1.2.6 |
| CVE-2021-44906 | minimist | 1.2.0 | CRITICAL | 9.8 | 1.2.6 |
| CVE-2023-45311 | fsevents | 1.2.9 | CRITICAL | 9.8 | 1.2.11 |
| CVE-2021-44906 | minimist | 0.0.8 | CRITICAL | 9.8 | 0.2.4 |
| CVE-2021-44906 | minimist | 1.2.0 | CRITICAL | 9.8 | 1.2.6 |
| CVE-2020-28282 | getobject | 0.1.0 | CRITICAL | 9.8 | 1.0.0 |
| CVE-2017-16042 | growl | 1.9.2 | CRITICAL | 9.8 | 1.10.0 |
| CVE-2021-3918 | json-schema | 0.2.3 | CRITICAL | 9.8 | 0.4.0 |
| CVE-2021-44906 | minimist | 1.2.0 | CRITICAL | 9.8 | 1.2.6 |
| CVE-2021-44906 | minimist | 0.0.10 | CRITICAL | 9.8 | 0.2.4 |
| CVE-2019-10746 | mixin-deep | 1.3.1 | CRITICAL | 9.8 | 1.3.2 |
| CVE-2021-44906 | minimist | 0.0.8 | CRITICAL | 9.8 | 0.2.4 |
| CVE-2021-44906 | minimist | 0.0.8 | CRITICAL | 9.8 | 0.2.4 |
| CVE-2021-3918 | json-schema | 0.2.3 | CRITICAL | 9.8 | 0.4.0 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| handlebars | 4.0.5 | 4.7.10 | 20 | False | True |
| minimist | 1.2.0 | 1.2.6 | 2 | False | True |
| lodash | 4.13.1 | 4.18.0 | 9 | False | None |
| minimist | 0.0.8 | 0.2.4 | 2 | False | True |
| lodash | 4.17.11 | 4.18.0 | 6 | False | None |
| lodash | 2.4.2 | 4.18.1 | 4 | True | None |
| bson | 1.0.9 | 1.1.4 | 2 | False | True |
| form-data | 2.3.3 | 2.5.6 | 2 | False | True |
| form-data | 2.1.4 | 2.5.6 | 2 | False | True |
| form-data | 1.0.1 | 2.5.6 | 2 | True | True |
| form-data | 2.0.0 | 2.5.6 | 2 | False | True |
| form-data | 0.1.4 | 2.5.6 | 2 | True | True |
| fsevents | 1.2.9 | 1.2.11 | 2 | False | True |
| json-schema | 0.2.3 | 0.4.0 | 1 | False | True |
| minimist | 0.0.10 | 0.2.4 | 2 | False | True |

## Patch

- status: **applied** (approved=True), applied components: 125, rescan fixed: 0

- note: manifest edits applied; the scanner reads lockfiles that still pin the old versions - regenerate them (see regenerate) to complete the fix

- regenerate lockfiles: `package.json: npm install --package-lock-only --ignore-scripts  (or yarn/pnpm equivalent)`

## Architecture

- 44 files, 3128 LOC, 34 import edges, 0 cycles (tangle 0.0)
- hotspot `app/routes/session.js`: 20 commits, 278 LOC, score 95.3
- hotspot `server.js`: 20 commits, 158 LOC, score 86.5
- hotspot `app/routes/profile.js`: 18 commits, 112 LOC, score 80.2
- hotspot `app/data/allocations-dao.js`: 13 commits, 115 LOC, score 75.9
- hotspot `Gruntfile.js`: 15 commits, 195 LOC, score 74.0
- runtime nodejs 12: eol (embedded-table (UNVERIFIED))
- note: shallow clone: hotspots/coupling use only the last 295 commits

## Industry reports

| industry | verdict | pass | gap | not_evidence | draft |
|---|---|---|---|---|---|
| defense | gaps | 2 | 2 | 0 | False |
| automotive | gaps | 2 | 2 | 0 | False |
| medical | gaps | 2 | 2 | 1 | False |
| finance | gaps | 2 | 2 | 0 | False |
| maritime | gaps | 3 | 3 | 1 | True |
| cra | gaps | 2 | 2 | 1 | False |
| robot | gaps | 2 | 1 | 1 | False |

## Proposals (deterministic - use_llm=false)

- [upgrade/low] handlebars 4.0.5 -> 4.7.10 - OSV 재조회 결과 후보 버전 깨끗함: 20개 취약점 해소
- [upgrade/low] minimist 1.2.0 -> 1.2.6 - OSV 재조회 결과 후보 버전 깨끗함: 2개 취약점 해소
- [upgrade/low] lodash 4.13.1 -> 4.18.0 - OSV 재조회 결과 후보 미검증: 9개 취약점 해소
- [upgrade/low] minimist 0.0.8 -> 0.2.4 - OSV 재조회 결과 후보 버전 깨끗함: 2개 취약점 해소
- [upgrade/low] lodash 4.17.11 -> 4.18.0 - OSV 재조회 결과 후보 미검증: 6개 취약점 해소
- [upgrade/high] lodash 2.4.2 -> 4.18.1 - OSV 재조회 결과 후보 미검증: 4개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/low] bson 1.0.9 -> 1.1.4 - OSV 재조회 결과 후보 버전 깨끗함: 2개 취약점 해소
- [upgrade/low] form-data 2.3.3 -> 2.5.6 - OSV 재조회 결과 후보 버전 깨끗함: 2개 취약점 해소
- [review_license/medium] 라이선스 미식별 35개 확인 - 라이선스가 식별되지 않으면 의무 이행 여부를 판단할 수 없다
- [upgrade_runtime/medium] nodejs 12 런타임 업그레이드 - 지원 종료(2022-04-30) - 보안 수정이 더 이상 나오지 않는다
