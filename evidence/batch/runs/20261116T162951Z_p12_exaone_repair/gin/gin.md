# gin

- source: `https://github.com/gin-gonic/gin.git` (commit `0f09c3a9b4`)
- components: 32 - vulnerabilities: 8 {'UNKNOWN': 8}
- license resolved: 32 of 32 (1.0) from {'deps.dev': 32}
- project license: MIT (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2026-78659 | golang.org/x/net | v0.57.0 | UNKNOWN | - | 0.60.0 |
| CVE-2026-78660 | golang.org/x/net | v0.57.0 | UNKNOWN | - | 0.60.0 |
| CVE-2026-78669 | golang.org/x/net | v0.57.0 | UNKNOWN | - | 0.60.0 |
| CVE-2026-78663 | golang.org/x/net | v0.57.0 | UNKNOWN | - | 0.60.0 |
| CVE-2026-97032 | golang.org/x/net | v0.57.0 | UNKNOWN | - | 0.60.0 |
| CVE-2026-78661 | golang.org/x/net | v0.57.0 | UNKNOWN | - | 0.62.0 |
| CVE-2026-97045 | golang.org/x/net | v0.57.0 | UNKNOWN | - | 0.62.0 |
| GO-2026-5932 | golang.org/x/crypto | v0.56.0 | UNKNOWN | - | 0.58.1-0.20261009181718-2f1f834330b2 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| golang.org/x/net | v0.57.0 | 0.62.0 | 7 | False | True |
| golang.org/x/crypto | v0.56.0 | 0.58.1-0.20261009181718-2f1f834330b2 | 1 | False | True |

## Patch

- status: **applied** (approved=True), applied components: 2, rescan fixed: 8

- regenerate lockfiles: `go.mod: go mod tidy`

## Architecture

- 99 files, 24655 LOC, 15 import edges, 0 cycles (tangle 0.0)
- hotspot `context.go`: 18 commits, 1544 LOC, score 99.0
- hotspot `context_test.go`: 16 commits, 4058 LOC, score 99.0
- hotspot `tree.go`: 7 commits, 958 LOC, score 94.0
- hotspot `gin_test.go`: 8 commits, 1198 LOC, score 90.0
- hotspot `gin.go`: 5 commits, 862 LOC, score 86.1
- runtime go 1.26: unknown (none)
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

## Proposals (deterministic - no proposal survived validation (dropped={'schema': 0, 'rule': 0, 'semantic': 2, 'cross_field': 0}) -> deterministic)

- [upgrade/low] golang.org/x/net v0.57.0 -> 0.62.0 - OSV 재조회 결과 후보 버전 깨끗함: 7개 취약점 해소
- [upgrade/low] golang.org/x/crypto v0.56.0 -> 0.58.1-0.20261009181718-2f1f834330b2 - OSV 재조회 결과 후보 버전 깨끗함: 1개 취약점 해소
