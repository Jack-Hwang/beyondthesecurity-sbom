# nodegoat

- source: `https://github.com/OWASP/NodeGoat.git` (commit `c5cb68a708`)
- components: 1091 - vulnerabilities: 311 {'LOW': 19, 'MEDIUM': 92, 'HIGH': 168, 'CRITICAL': 32}
- license resolved: 1075 of 1091 (0.985) from {'deps.dev': 668, 'lockfile': 384, 'registry:npm': 23}
- project license: Apache-2.0 (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2020-7610 | bson | 1.0.9 | CRITICAL | 9.8 | 1.1.4 |
| CVE-2021-44906 | minimist | 1.2.0 | CRITICAL | 9.8 | 1.2.6 |
| CVE-2023-45311 | fsevents | 1.2.9 | CRITICAL | 9.8 | 1.2.11 |
| CVE-2021-44906 | minimist | 0.0.8 | CRITICAL | 9.8 | 0.2.4 |
| CVE-2020-28282 | getobject | 0.1.0 | CRITICAL | 9.8 | 1.0.0 |
| CVE-2017-16042 | growl | 1.9.2 | CRITICAL | 9.8 | 1.10.0 |
| CVE-2021-3918 | json-schema | 0.2.3 | CRITICAL | 9.8 | 0.4.0 |
| CVE-2021-44906 | minimist | 0.0.10 | CRITICAL | 9.8 | 0.2.4 |
| CVE-2019-10746 | mixin-deep | 1.3.1 | CRITICAL | 9.8 | 1.3.2 |
| CVE-2026-33937 | handlebars | 4.0.5 | CRITICAL | 9.8 | 4.7.9 |
| CVE-2021-23383 | handlebars | 4.0.5 | CRITICAL | 9.8 | 4.7.7 |
| CVE-2026-106446 | handlebars | 4.0.5 | CRITICAL | 9.8 | 4.7.10 |
| CVE-2021-23369 | handlebars | 4.0.5 | CRITICAL | 9.8 | 4.7.7 |
| CVE-2019-19919 | handlebars | 4.0.5 | CRITICAL | 9.8 | 4.3.0 |
| CVE-2021-44906 | minimist | 1.2.5 | CRITICAL | 9.8 | 1.2.6 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| handlebars | 4.0.5 | 4.7.10 | 20 | False | True |
| lodash | 4.13.1 | 4.18.1 | 9 | False | True |
| lodash | 4.17.11 | 4.18.1 | 6 | False | True |
| lodash | 2.4.2 | 4.18.1 | 4 | True | True |
| bson | 1.0.9 | 1.1.4 | 2 | False | True |
| form-data | 2.3.3 | 2.5.6 | 2 | False | True |
| form-data | 2.1.4 | 2.5.6 | 2 | False | True |
| form-data | 1.0.1 | 2.5.6 | 2 | True | True |
| form-data | 2.0.0 | 2.5.6 | 2 | False | True |
| form-data | 0.1.4 | 2.5.6 | 2 | True | True |
| fsevents | 1.2.9 | 1.2.11 | 2 | False | True |
| minimist | 1.2.0 | 1.2.6 | 2 | False | True |
| minimist | 0.0.8 | 0.2.4 | 2 | False | True |
| minimist | 0.0.10 | 0.2.4 | 2 | False | True |
| set-value | 2.0.0 | 2.0.1 | 2 | False | True |

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

## Proposals (exaone - cached EXAONE response for identical evidence (no new call))

핵심 위험은 nodejs 12 런타임 EOL, handlebars·bson·fsevents·minimist 등의 치명적 CVE, 일부 컴포넌트의 라이선스 불명입니다. 증거된 업그레이드 계획과 고정 버전이 있으므로 우선순위에 따른 제거·업그레이드가 필요합니다. 총 1091개 컴포넌트와 311개 취약점이 보고되었고, hotspots 및 라이선스 목록은 추가 검토가 필요합니다.

- [upgrade/high] handlebars 치명적 CVE 대응 업그레이드 - handlebars 4.0.5에 CRITICAL CVE 다수가 있고 계획상 4.7.10으로 업그레이드가 검증됨.
- [upgrade/high] bson 치명적 CVE 대응 업그레이드 - bson 1.0.9에 CVSS 9.8 CRITICAL CVE가 있고 계획상 1.1.4로 업그레이드가 검증됨.
- [upgrade/high] fsevents 치명적 CVE 대응 업그레이드 - fsevents 1.2.9에 CVSS 9.8 CRITICAL CVE가 있고 계획상 1.2.11로 업그레이드가 검증됨.
- [upgrade/high] minimist 치명적 CVE 대응 업그레이드 - minimist 1.2.0에 CVSS 9.8 CRITICAL CVE가 있고 계획상 1.2.6으로 업그레이드가 검증됨.
- [upgrade_runtime/high] nodejs 12 런타임 EOL 대응 - 런타임_eol에 nodejs 12가 명시되어 지원 종료 위험이 있으나 증거상 목표 버전은 없음.
- [review_license/medium] 라이선스 불명 컴포넌트 검토 - license.policy에서 category unknown·verdict review이고 unresolved 목록이 존재함.
- [refactor/medium] hotspots 구조 개선 검토 - hotspots로 명시되어 있으나 cycles와 extraction_candidates는 비어 있어 추가 분석이 필요함.
- [upgrade/medium] lodash 업그레이드 계획 반영 - 계획에 lodash 4.13.1·4.17.11·2.4.2에서 4.18.1로의 업그레이드가 verified_clean로 제시됨.
