# pygoat

- source: `https://github.com/adeyosemanputra/pygoat.git` (commit `2aa4cc14f2`)
- components: 58 - vulnerabilities: 369 {'HIGH': 159, 'CRITICAL': 32, 'LOW': 23, 'MEDIUM': 149, 'UNKNOWN': 6}
- license resolved: 58 of 58 (1.0) from {'deps.dev': 46, 'registry:pypi': 12}
- project license: MIT (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

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
| CVE-2021-25289 | pillow | 8.0.0 | CRITICAL | 9.8 | 8.1.1 |
| CVE-2026-112398 | pillow | 8.0.0 | CRITICAL | 9.8 | 13.0.0 |
| CVE-2021-34552 | pillow | 8.0.0 | CRITICAL | 9.8 | 8.3.0 |
| CVE-2026-112403 | pillow | 8.0.0 | CRITICAL | 9.8 | 13.0.0 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| pillow | 8.0.0 | 13.0.0 | 72 | True | True |
| pillow | 12.1.0 | 13.0.0 | 62 | True | True |
| django | 4.2 | 5.2.17 | 51 | True | True |
| django | 3.2.18 | 5.2.17 | 20 | True | True |
| pyjwt | 2.8.0 | 2.15.0 | 14 | False | True |
| pyjwt | 2.4.0 | 2.15.0 | 13 | False | True |
| black | 26.1.0 | 26.10.1 | 3 | False | True |
| certifi | 2022.12.7 | 2026.10.18 | 3 | True | True |
| pyyaml | 5.1 | 5.4 | 3 | False | True |
| cryptography | 39.0.1 | 50.0.0 | 13 | True | True |
| werkzeug | 2.0.1 | 3.1.9 | 11 | True | True |
| werkzeug | 2.0.3 | 3.1.9 | 11 | True | True |
| urllib3 | 1.26.9 | 2.8.0 | 10 | True | True |
| werkzeug | 2.1.2 | 3.1.9 | 10 | True | True |
| werkzeug | 2.2.2 | 3.1.9 | 10 | True | True |

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
| finance | gaps | 3 | 1 | 0 | False |
| maritime | gaps | 4 | 2 | 1 | True |
| cra | gaps | 2 | 2 | 1 | False |
| robot | gaps | 2 | 1 | 1 | False |

## Proposals (exaone)

pygoat 프로젝트는 58개 컴포넌트와 369개 취약점이 보고된 가운데, Django 4.2/3.2.18, Pillow 8.0.0/12.1.0, Black 26.1.0에 CVSS 9.8 임계 취약점이 존재한다. 또한 Python 3.7/3.9 런타임 EOL, dockerized_labs/sensitive_data_exposure 추출 후보, certifi@2022.12.7의 약-카피레프트 라이선스 검토 필요가 확인된다. 검증 완료된 업그레이드 계획을 우선 적용해 임계 취약점과 유지보수 위험을 줄여야 한다.

- [monitor/high] Python 3.7/3.9 런타임 EOL 상태 모니터링 - 아키텍처 증거에 Python 3.7과 3.9 런타임 EOL이 표시되어 있으나, 실행 가능한 업그레이드 목표 버전은 증거에 없다.
- [extract_module/medium] sensitive_data_exposure 컴포넌트 모듈 추출 검토 - 민감 데이터 노출 랩이 추출 후보로 표시되어 있고 관련 hotspot view가 존재하므로, 격리와 책임 경계 명확화를 위한 모듈 추출을 검토한다.
