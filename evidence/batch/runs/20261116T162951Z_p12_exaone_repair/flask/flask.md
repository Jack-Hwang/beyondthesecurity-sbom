# flask

- source: `https://github.com/pallets/flask.git` (commit `49943b5a94`)
- components: 20 - vulnerabilities: 14 {'MEDIUM': 9, 'HIGH': 5}
- license resolved: 20 of 20 (1.0) from {'registry:pypi': 4, 'deps.dev': 16}
- project license: BSD-3-Clause (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2024-56201 | jinja2 | 3.1.2 | HIGH | 8.8 | 3.1.5 |
| CVE-2024-56326 | jinja2 | 3.1.2 | HIGH | 7.8 | 3.1.5 |
| CVE-2024-34069 | werkzeug | 2.3.3 | HIGH | 7.5 | 3.0.3 |
| CVE-2023-46136 | werkzeug | 2.3.3 | HIGH | 7.5 | 2.3.8 |
| CVE-2024-49767 | werkzeug | 2.3.3 | HIGH | 7.5 | 3.0.6 |
| CVE-2024-22195 | jinja2 | 3.1.2 | MEDIUM | 5.4 | 3.1.3 |
| CVE-2024-34064 | jinja2 | 3.1.2 | MEDIUM | 5.4 | 3.1.4 |
| CVE-2026-27199 | werkzeug | 2.3.3 | MEDIUM | 5.3 | 3.1.6 |
| CVE-2026-21860 | werkzeug | 2.3.3 | MEDIUM | 5.3 | 3.1.5 |
| CVE-2026-27205 | flask | 2.3.2 | MEDIUM | 4.3 | 3.1.3 |
| CVE-2025-27516 | jinja2 | 3.1.2 | MEDIUM | - | 3.1.6 |
| CVE-2024-49766 | werkzeug | 2.3.3 | MEDIUM | - | 3.0.6 |
| CVE-2026-102598 | werkzeug | 2.3.3 | MEDIUM | - | 3.1.9 |
| CVE-2025-66221 | werkzeug | 2.3.3 | MEDIUM | - | 3.1.4 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| werkzeug | 2.3.3 | 3.1.9 | 8 | True | True |
| jinja2 | 3.1.2 | 3.1.6 | 5 | False | True |
| flask | 2.3.2 | 3.1.3 | 1 | True | True |

## Patch

- status: **applied** (approved=True), applied components: 3, rescan fixed: 14

## Architecture

- 83 files, 18475 LOC, 175 import edges, 3 cycles (tangle 0.375)
- hotspot `src/flask/app.py`: 27 commits, 1687 LOC, score 100.0
- hotspot `src/flask/sansio/app.py`: 17 commits, 1015 LOC, score 95.0
- hotspot `src/flask/helpers.py`: 17 commits, 680 LOC, score 92.5
- hotspot `tests/test_basic.py`: 16 commits, 1975 LOC, score 92.5
- hotspot `src/flask/cli.py`: 12 commits, 1127 LOC, score 92.5
- runtime python 3.11: supported (embedded-table (UNVERIFIED))
- note: shallow clone: hotspots/coupling use only the last 167 commits

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

- [upgrade/high] Werkzeug 2.3.3을 3.1.9로 업그레이드 - 플랜에 from 2.3.3, to 3.1.9, major_bump true, verified_clean true로 기록되어 있으며, 매핑된 다수 HIGH/MEDIUM CVE의 fixed_version을 포함한 대상이다.
- [upgrade/medium] Jinja2 3.1.2를 3.1.6으로 업그레이드 - 플랜에 from 3.1.2, to 3.1.6, major_bump false, verified_clean true로 기록되어 있으며, HIGH 등급을 포함한 매핑 CVE를 해소하는 대상이다.
- [upgrade/high] Flask 2.3.2를 3.1.3으로 업그레이드 - 플랜에 from 2.3.2, to 3.1.3, major_bump true, verified_clean true로 기록되어 있으며, Flask 패키지에 매핑된 CVE의 fixed_version과 일치한다.
- [extract_module/medium] 예제 앱 추출 후보 분리 검토 - architecture.extraction_candidates에 명시되어 핵심 라이브러리와 예제/사이클을 분리해 관리 범위를 조정할 수 있다.
- [refactor/medium] 핫스팟 파일 변경 영향 검토 - architecture.hotspots에 명시된 파일들로, 업그레이드 이후 회귀 위험과 변경 집중도를 낮추기 위한 리팩터링 검토 대상이다.
