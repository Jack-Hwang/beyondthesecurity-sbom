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

## Proposals (exaone - cached EXAONE response for identical evidence (no new call))

express 저장소의 주요 위험은 Node.js 18 런타임 EOL과 hbs 4.4.0의 CVE-2021-32822(MEDIUM, 수정 버전 없음, no_fix)이다. 라이선스 정책/프로젝트 라이선스는 비어 있거나 null이나 unresolved는 없어 즉각적인 라이선스 차단 이슈는 확인되지 않는다. 아키텍처 추출 후보와 핫스팟은 존재하지만 사이클은 보고되지 않았다.

- [upgrade_runtime/high] Node.js 18 런타임 EOL 대응 - Node.js 18이 runtime_eol 목록에 있어 지원 종료에 따른 보안·유지보수 위험을 낮추기 위해 상위 런타임으로 전환 검토가 필요하다.
- [monitor/medium] hbs CVE-2021-32822 모니터링 - hbs 4.4.0에 MEDIUM CVE가 있고 fixed_version이 없으며 plan status가 no_fix, to가 null이므로 수정 가능성과 완화책을 계속 추적해야 한다.
- [replace/medium] hbs 대체 경로 검토 - 수정 버전과 업그레이드 계획 대상이 확인되지 않아 취약 의존성을 대체하거나 격리하는 방안을 검토할 필요가 있다.
- [accept_risk/medium] hbs 취약점 수용 여부 결정 - no_fix 및 빈 fixed_version 상황에서는 실제 노출도와 비즈니스 영향에 따라 잔여 위험 수용 여부를 명시적으로 결정해야 한다.
- [extract_module/low] 예제 모듈 추출 후보 구조화 - extraction_candidates로 제시된 예제들을 모듈 경계로 정리하면 변경 영향과 재사용성을 관리하기 쉽다.
- [refactor/low] 핵심 핫스팟 리팩터링 검토 - hotspots로 표시된 핵심 파일들의 복잡도와 변경 집중도를 낮추기 위한 리팩터링 검토가 필요하다.
