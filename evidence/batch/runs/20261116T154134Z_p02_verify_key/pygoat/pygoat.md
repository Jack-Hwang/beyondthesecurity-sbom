# pygoat

- source: `https://github.com/adeyosemanputra/pygoat.git` (commit `2aa4cc14f2`)
- components: 58 - vulnerabilities: 587 {'HIGH': 238, 'CRITICAL': 35, 'LOW': 30, 'MEDIUM': 272, 'UNKNOWN': 12}
- license resolved: 56 of 58 (0.966) from {'deps.dev': 45, 'registry:pypi': 11}
- project license: MIT (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=False, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2026-31900 | black | 26.1.0 | CRITICAL | 9.8 | 26.3.0 |
| CVE-2025-59681 | django | 4.2 | CRITICAL | 9.8 | 4.2.25 |
| CVE-2024-53908 | django | 4.2 | CRITICAL | 9.8 | 4.2.17 |
| CVE-2026-4277 | django | 4.2 | CRITICAL | 9.8 | 4.2.30 |
| CVE-2023-31047 | django | 4.2 | CRITICAL | 9.8 | 4.2.1 |
| CVE-2026-112398 | pillow | 12.1.0 | CRITICAL | 9.8 | 13.0.0 |
| CVE-2026-112403 | pillow | 12.1.0 | CRITICAL | 9.8 | 13.0.0 |
| CVE-2026-96639 | pillow | 12.1.0 | CRITICAL | 9.8 | 13.0.0 |
| CVE-2019-20477 | pyyaml | 5.1 | CRITICAL | 9.8 | 5.2 |
| CVE-2020-1747 | pyyaml | 5.1 | CRITICAL | 9.8 | 5.3.1 |
| CVE-2020-14343 | pyyaml | 5.1 | CRITICAL | 9.8 | 5.4 |
| CVE-2019-20477 | pyyaml | 5.1 | CRITICAL | 9.8 | 5.2 |
| CVE-2020-1747 | pyyaml | 5.1 | CRITICAL | 9.8 | 5.3.1 |
| CVE-2020-14343 | pyyaml | 5.1 | CRITICAL | 9.8 | 5.4 |
| CVE-2021-25289 | pillow | 8.0.0 | CRITICAL | 9.8 | 8.1.1 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| pillow | 8.0.0 | 13.0.0 | 72 | True | True |
| pillow | 12.1.0 | 13.0.0 | 62 | True | True |
| django | 4.2 | 5.2.17 | 51 | True | True |
| django | 3.2.18 | 5.2.17 | 20 | True | True |
| pyjwt | 2.8.0 | 2.15.0 | 14 | False | True |
| pyjwt | 2.4.0 | 2.15.0 | 13 | False | True |
| pyyaml | 5.1 | 5.4 | 3 | False | True |
| black | 26.1.0 | 26.10.1 | 3 | False | True |
| certifi | 2022.12.7 | 2026.10.18 | 3 | True | True |
| werkzeug | 2.0.1 | 3.1.9 | 11 | True | True |
| werkzeug | 2.3.7 | 3.1.9 | 8 | True | True |
| jinja2 | 3.1.2 | 3.1.6 | 5 | False | True |
| jinja2 | 3.0.1 | 3.1.6 | 5 | False | True |
| werkzeug | 2.2.2 | 3.1.9 | 10 | True | True |
| flask | 2.0.1 | 3.1.3 | 2 | True | True |

## Patch

- status: **applied** (approved=True), applied components: 44, rescan fixed: 336

## Architecture

- 118 files, 8876 LOC, 42 import edges, 0 cycles (tangle 0.0)
- hotspot `introduction/views.py`: 18 commits, 336 LOC, score 98.2
- hotspot `challenge/views.py`: 11 commits, 677 LOC, score 97.4
- hotspot `uninstaller.py`: 6 commits, 197 LOC, score 93.1
- hotspot `dockerized_labs/sensitive_data_exposure/dataexposure/views.py`: 3 commits, 166 LOC, score 76.5
- hotspot `dockerized_labs/sec_misconfig/app.py`: 5 commits, 136 LOC, score 74.1
- runtime python 3.11: supported (embedded-table (UNVERIFIED))
- runtime python 3.7: eol (embedded-table (UNVERIFIED))
- runtime python 3.9: eol (embedded-table (UNVERIFIED))
- runtime python 3.9: eol (embedded-table (UNVERIFIED))
- note: shallow clone: hotspots/coupling use only the last 215 commits

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

- [upgrade/high] pillow 8.0.0 -> 13.0.0 - OSV 재조회 결과 후보 버전 깨끗함: 72개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/high] pillow 12.1.0 -> 13.0.0 - OSV 재조회 결과 후보 버전 깨끗함: 62개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/high] django 4.2 -> 5.2.17 - OSV 재조회 결과 후보 버전 깨끗함: 51개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/high] django 3.2.18 -> 5.2.17 - OSV 재조회 결과 후보 버전 깨끗함: 20개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/low] pyjwt 2.8.0 -> 2.15.0 - OSV 재조회 결과 후보 버전 깨끗함: 14개 취약점 해소
- [upgrade/low] pyjwt 2.4.0 -> 2.15.0 - OSV 재조회 결과 후보 버전 깨끗함: 13개 취약점 해소
- [upgrade/low] pyyaml 5.1 -> 5.4 - OSV 재조회 결과 후보 버전 깨끗함: 3개 취약점 해소
- [upgrade/low] black 26.1.0 -> 26.10.1 - OSV 재조회 결과 후보 버전 깨끗함: 3개 취약점 해소
- [review_license/medium] 라이선스 미식별 2개 확인 - 라이선스가 식별되지 않으면 의무 이행 여부를 판단할 수 없다
- [upgrade_runtime/medium] python 3.7 런타임 업그레이드 - 지원 종료(2023-06-27) - 보안 수정이 더 이상 나오지 않는다
- [upgrade_runtime/medium] python 3.9 런타임 업그레이드 - 지원 종료(2025-10-31) - 보안 수정이 더 이상 나오지 않는다
- [upgrade_runtime/medium] python 3.9 런타임 업그레이드 - 지원 종료(2025-10-31) - 보안 수정이 더 이상 나오지 않는다
- [upgrade_runtime/medium] python 3.9 런타임 업그레이드 - 지원 종료(2025-10-31) - 보안 수정이 더 이상 나오지 않는다
- [upgrade_runtime/medium] python 3.8 런타임 업그레이드 - 지원 종료(2024-10-07) - 보안 수정이 더 이상 나오지 않는다
