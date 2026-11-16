# ripgrep

- source: `https://github.com/BurntSushi/ripgrep.git` (commit `178cc027e2`)
- components: 69 - vulnerabilities: 0 {}
- license resolved: 69 of 69 (1.0) from {'deps.dev': 69}
- project license: MIT (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=False, affects refs resolved=1.0

## Patch

- status: **nothing_applied** (approved=True), applied components: 0, rescan fixed: None

## Architecture

- 103 files, 55638 LOC, 70 import edges, 0 cycles (tangle 0.0)
- hotspot `crates/ignore/src/walk.rs`: 9 commits, 2811 LOC, score 97.1
- hotspot `crates/core/flags/defs.rs`: 6 commits, 7780 LOC, score 96.1
- hotspot `crates/ignore/src/dir.rs`: 11 commits, 1701 LOC, score 94.1
- hotspot `crates/core/flags/hiargs.rs`: 5 commits, 1481 LOC, score 90.4
- hotspot `crates/globset/src/lib.rs`: 6 commits, 1425 LOC, score 88.6
- note: shallow clone: hotspots/coupling use only the last 100 commits

## Industry reports

| industry | verdict | pass | gap | not_evidence | draft |
|---|---|---|---|---|---|
| defense | gaps | 1 | 3 | 0 | False |
| automotive | gaps | 1 | 3 | 0 | False |
| medical | gaps | 1 | 3 | 1 | False |
| finance | gaps | 2 | 2 | 0 | False |
| maritime | gaps | 4 | 2 | 1 | True |
| cra | gaps | 1 | 3 | 1 | False |
| robot | gaps | 1 | 2 | 1 | False |

## Proposals (deterministic - use_llm=false)

- [extract_module/low] crates/core 도메인 분리 후보 - 응집도 1.0, 유입 의존 0개로 점진적 분리(strangler) 후보
