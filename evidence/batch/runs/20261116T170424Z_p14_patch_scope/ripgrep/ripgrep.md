# ripgrep

- source: `https://github.com/BurntSushi/ripgrep.git` (commit `178cc027e2`)
- components: 69 - vulnerabilities: 0 {}
- license resolved: 69 of 69 (1.0) from {'deps.dev': 69}
- project license: MIT (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

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
- note: ruby: only require/require_relative edges are resolved; Rails autoloaded constants are not (graph is partial)

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

## Proposals (exaone - cached EXAONE response for identical evidence (no new call))

확인된 취약점과 런타임 EOL은 없지만, 추출 후보와 핫스팟이 모듈 경계·복잡도 관리 필요성을 보여줌. 프로젝트 라이선스는 MIT로 표시되나 라이선스 정책과 미해결 항목이 비어 있어 정책 검토가 필요함. 업그레이드 계획이 비어 있어 버전 기반 제고안은 불가하고 구조 개선·모니터링 중심 대응이 적절함.

- [refactor/medium] 핫스팟 리팩터링 우선순위 지정 - 아키텍처 핫스팟으로 식별된 파일들이 변경 영향과 복잡도 관리의 주요 검토 대상임.
- [extract_module/medium] 추출 후보 기반 모듈 경계 정립 - 추출 후보로 명시된 크레이트 단위의 경계와 의존성 구조를 검토해 모듈화 방향을 정할 수 있음.
- [monitor/low] 공급망·런타임 리스크 모니터링 유지 - 현재 취약점과 런타임 EOL 보고가 없으므로 지속 모니터링으로 상태 변화를 확인할 필요가 있음.
