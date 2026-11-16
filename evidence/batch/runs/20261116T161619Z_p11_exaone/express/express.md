# express

- source: `https://github.com/expressjs/express.git` (commit `43fca52d28`)
- components: 8 - vulnerabilities: 1 {'MEDIUM': 1}
- license resolved: 8 of 8 (1.0) from {'deps.dev': 8}
- project license: not detected (-)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2021-32822 | hbs | 4.4.0 | MEDIUM | 4.0 | - |

## Patch

- status: **nothing_applied** (approved=True), applied components: 0, rescan fixed: None

## Architecture

- 142 files, 22188 LOC, 58 import edges, 0 cycles (tangle 0.0)
- hotspot `lib/response.js`: 10 commits, 1051 LOC, score 100.0
- hotspot `lib/application.js`: 4 commits, 632 LOC, score 97.2
- hotspot `lib/request.js`: 6 commits, 528 LOC, score 95.8
- hotspot `test/express.static.js`: 3 commits, 816 LOC, score 91.0
- hotspot `test/res.send.js`: 4 commits, 636 LOC, score 89.5
- runtime nodejs 18: eol (embedded-table (UNVERIFIED))
- note: shallow clone: hotspots/coupling use only the last 100 commits

## Industry reports

| industry | verdict | pass | gap | not_evidence | draft |
|---|---|---|---|---|---|
| defense | gaps | 2 | 2 | 0 | False |
| automotive | gaps | 2 | 2 | 0 | False |
| medical | gaps | 2 | 2 | 1 | False |
| finance | gaps | 3 | 1 | 0 | False |
| maritime | gaps | 5 | 1 | 1 | True |
| cra | gaps | 2 | 2 | 1 | False |
| robot | gaps | 2 | 1 | 1 | False |

## Proposals (deterministic - EXAONE unavailable -> deterministic proposals: network error: TimeoutError)

- [replace/high] hbs: 수정 버전 없음 - 알려진 수정 버전이 없다 - 대체 라이브러리 검토 또는 위험 수용 승인이 필요하다
- [upgrade_runtime/medium] nodejs 18 런타임 업그레이드 - 지원 종료(2025-04-30) - 보안 수정이 더 이상 나오지 않는다
- [extract_module/low] examples/mvc 도메인 분리 후보 - 응집도 0.8, 유입 의존 1개로 점진적 분리(strangler) 후보
