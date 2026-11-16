# nodejs-goof

- source: `https://github.com/snyk-labs/nodejs-goof.git` (commit `add14ba59e`)
- components: 980 - vulnerabilities: 315 {'MEDIUM': 109, 'HIGH': 139, 'LOW': 20, 'CRITICAL': 47}
- license resolved: 978 of 980 (0.998) from {'deps.dev': 710, 'lockfile': 250, 'registry:npm': 18}
- project license: Apache-2.0 (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2023-3696 | mongoose | 4.2.4 | CRITICAL | 10.0 | 5.13.20 |
| CVE-2020-7610 | bson | 0.4.23 | CRITICAL | 9.8 | 1.1.4 |
| CVE-2017-1000228 | ejs | 1.0.0 | CRITICAL | 9.8 | 2.5.5 |
| CVE-2022-29078 | ejs | 1.0.0 | CRITICAL | 9.8 | 3.1.7 |
| CVE-2017-1000228 | ejs | 0.8.8 | CRITICAL | 9.8 | 2.5.5 |
| CVE-2022-29078 | ejs | 0.8.8 | CRITICAL | 9.8 | 3.1.7 |
| CVE-2020-7699 | express-fileupload | 0.0.5 | CRITICAL | 9.8 | 1.1.9 |
| CVE-2026-33937 | handlebars | 4.0.14 | CRITICAL | 9.8 | 4.7.9 |
| CVE-2021-23383 | handlebars | 4.0.14 | CRITICAL | 9.8 | 4.7.7 |
| CVE-2026-106446 | handlebars | 4.0.14 | CRITICAL | 9.8 | 4.7.10 |
| CVE-2021-23369 | handlebars | 4.0.14 | CRITICAL | 9.8 | 4.7.7 |
| CVE-2019-19919 | handlebars | 4.0.14 | CRITICAL | 9.8 | 4.3.0 |
| CVE-2021-3918 | json-schema | 0.2.3 | CRITICAL | 9.8 | 0.4.0 |
| CVE-2021-44906 | minimist | 1.2.0 | CRITICAL | 9.8 | 1.2.6 |
| CVE-2022-24304 | mongoose | 4.2.4 | CRITICAL | 9.8 | 5.13.15 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| handlebars | 4.0.11 | 4.7.10 | 20 | False | True |
| handlebars | 4.0.14 | 4.7.10 | 19 | False | True |
| mongoose | 4.2.4 | 6.13.12 | 13 | True | True |
| elliptic | 6.4.1 | 6.6.1 | 8 | False | False |
| lodash | 4.17.4 | 4.18.1 | 9 | False | True |
| lodash | 4.17.10 | 4.18.1 | 8 | False | True |
| parse-url | 5.0.1 | 8.1.0 | 6 | True | True |
| ejs | 1.0.0 | 3.1.10 | 5 | True | True |
| ejs | 0.8.8 | 3.1.10 | 5 | True | True |
| typeorm | 0.2.24 | 0.3.31 | 5 | False | True |
| express-fileupload | 0.0.5 | 1.1.9 | 2 | True | False |
| pbkdf2 | 3.0.17 | 3.1.7 | 3 | False | True |
| bson | 0.4.23 | 1.1.4 | 2 | True | True |
| form-data | 2.3.3 | 2.5.6 | 2 | False | True |
| minimist | 1.2.0 | 1.2.6 | 2 | False | True |

## Patch

- status: **regression_reverted** (approved=True), applied components: 134, rescan fixed: None

- regenerate lockfiles: `package.json: npm install --package-lock-only --ignore-scripts  (or yarn/pnpm equivalent)`

## Architecture

- 10 files, 743 LOC, 6 import edges, 0 cycles (tangle 0.0)
- hotspot `routes/index.js`: 20 commits, 381 LOC, score 100.0
- hotspot `tests/authentication.component.spec.js`: 2 commits, 59 LOC, score 60.5
- hotspot `app.js`: 14 commits, 89 LOC, score 59.3
- hotspot `routes/users.js`: 1 commits, 45 LOC, score 18.5
- hotspot `typeorm-db.js`: 1 commits, 46 LOC, score 14.8
- runtime nodejs 18: eol (embedded-table (UNVERIFIED))

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

## Proposals (deterministic - EXAONE unavailable -> deterministic proposals: provider rate/day limit (HTTP 429): {"error":{"message":"service is busy, too many concurrent requests(600)","type":"rate_limit_error","param":null,"code":"rate_limit_exceeded"}})

- [upgrade/low] handlebars 4.0.11 -> 4.7.10 - OSV 재조회 결과 후보 버전 깨끗함: 20개 취약점 해소
- [upgrade/low] handlebars 4.0.14 -> 4.7.10 - OSV 재조회 결과 후보 버전 깨끗함: 19개 취약점 해소
- [upgrade/high] mongoose 4.2.4 -> 6.13.12 - OSV 재조회 결과 후보 버전 깨끗함: 13개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/low] elliptic 6.4.1 -> 6.6.1 - OSV 재조회 결과 후보 버전에 잔여 취약점: 8개 취약점 해소
- [upgrade/low] lodash 4.17.4 -> 4.18.1 - OSV 재조회 결과 후보 버전 깨끗함: 9개 취약점 해소
- [upgrade/low] lodash 4.17.10 -> 4.18.1 - OSV 재조회 결과 후보 버전 깨끗함: 8개 취약점 해소
- [upgrade/high] parse-url 5.0.1 -> 8.1.0 - OSV 재조회 결과 후보 버전 깨끗함: 6개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/high] ejs 1.0.0 -> 3.1.10 - OSV 재조회 결과 후보 버전 깨끗함: 5개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [review_license/medium] 라이선스 미식별 2개 확인 - 라이선스가 식별되지 않으면 의무 이행 여부를 판단할 수 없다
- [upgrade_runtime/medium] nodejs 18 런타임 업그레이드 - 지원 종료(2025-04-30) - 보안 수정이 더 이상 나오지 않는다
