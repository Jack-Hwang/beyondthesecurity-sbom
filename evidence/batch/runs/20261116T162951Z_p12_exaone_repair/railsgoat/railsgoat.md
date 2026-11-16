# railsgoat

- source: `https://github.com/OWASP/railsgoat.git` (commit `f5951f1308`)
- components: 167 - vulnerabilities: 114 {'LOW': 26, 'MEDIUM': 64, 'HIGH': 21, 'CRITICAL': 3}
- license resolved: 166 of 167 (0.994) from {'deps.dev': 166}
- project license: MIT (root license file)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2026-122006 | activestorage | 8.0.4 | CRITICAL | 9.8 | 8.0.5.2 |
| CVE-2026-66066 | activestorage | 8.0.4 | CRITICAL | - | 8.0.5.1 |
| CVE-2026-39324 | rack-session | 2.1.1 | CRITICAL | - | 2.1.2 |
| CVE-2026-126186 | activestorage | 8.0.4 | HIGH | 8.8 | 8.0.5.2 |
| CVE-2026-41316 | erb | 6.0.1 | HIGH | 8.1 | 6.0.1.1 |
| CVE-2026-126081 | actionpack | 8.0.4 | HIGH | 7.5 | 8.0.5.2 |
| CVE-2026-126080 | activesupport | 8.0.4 | HIGH | 7.5 | 8.0.5.2 |
| CVE-2026-35611 | addressable | 2.8.8 | HIGH | 7.5 | 2.9.0 |
| CVE-2026-54904 | concurrent-ruby | 1.3.6 | HIGH | 7.5 | 1.3.7 |
| CVE-2026-79770 | nokogiri | 1.19.0 | HIGH | 7.5 | 1.19.3 |
| CVE-2026-47737 | puma | 6.6.1 | HIGH | 7.5 | 7.2.1 |
| CVE-2026-47736 | puma | 6.6.1 | HIGH | 7.5 | 7.2.1 |
| CVE-2026-125111 | rack | 3.1.19 | HIGH | 7.5 | 3.1.23 |
| CVE-2026-34829 | rack | 3.1.19 | HIGH | 7.5 | 3.1.21 |
| CVE-2026-34785 | rack | 3.1.19 | HIGH | 7.5 | 3.1.21 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| activestorage | 8.0.4 | 8.0.5.2 | 13 | False | True |
| rack-session | 2.1.1 | 2.1.2 | 1 | False | True |
| rack | 3.1.19 | 3.1.23 | 18 | False | True |
| nokogiri | 1.19.0 | 1.19.5 | 14 | False | True |
| net-imap | 0.6.2 | 0.6.4.1 | 8 | False | True |
| addressable | 2.8.8 | 2.9.1 | 7 | False | True |
| actionpack | 8.0.4 | 8.0.5.2 | 6 | False | True |
| crass | 1.0.6 | 1.0.8 | 5 | False | True |
| activesupport | 8.0.4 | 8.0.5.2 | 4 | False | True |
| websocket-driver | 0.8.0 | 0.8.2 | 4 | False | True |
| concurrent-ruby | 1.3.6 | 1.3.7 | 3 | False | True |
| json | 2.18.0 | 2.19.9 | 2 | False | True |
| puma | 6.6.1 | 7.2.1 | 2 | True | True |
| erb | 6.0.1 | 6.0.1.1 | 1 | False | True |
| rubyzip | 3.2.2 | 3.4.0 | 1 | False | True |

## Patch

- status: **applied** (approved=True), applied components: 3, rescan fixed: 0

- note: manifest edits applied; the scanner reads lockfiles that still pin the old versions - regenerate them (see regenerate) to complete the fix

- regenerate lockfiles: `Gemfile: bundle update <pkg>`

## Architecture

- 143 files, 10719 LOC, 25 import edges, 0 cycles (tangle 0.0)
- hotspot `app/controllers/admin_controller.rb`: 4 commits, 79 LOC, score 82.5
- hotspot `app/controllers/tutorials_controller.rb`: 3 commits, 193 LOC, score 80.3
- hotspot `app/assets/javascripts/bootstrap-timepicker.js`: 2 commits, 804 LOC, score 79.2
- hotspot `app/controllers/benefit_forms_controller.rb`: 4 commits, 81 LOC, score 75.7
- hotspot `spec/support/capybara_shared.rb`: 4 commits, 59 LOC, score 75.4
- runtime ruby 2.6: unknown (none)
- note: shallow clone: hotspots/coupling use only the last 400 commits
- note: ruby: only require/require_relative edges are resolved; Rails autoloaded constants are not (graph is partial)

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

## Proposals (exaone)

railsgoat는 114개 취약점과 5개 hotspot이 보고된 프로젝트로, 핵심 런타임·의존성 취약점과 라이선스 충돌/미해결이 주요 위험이다. activestorage, rack-session, actionpack, activesupport, nokogiri, addressable, concurrent-ruby 등은 검증된 업그레이드 계획이 있으나 erb와 puma 고위험 취약점은 계획이 없다. 또한 bundler-audit@0.9.3의 라이선스 충돌과 jquery-fileupload-rails@1.0.0의 미해결 라이선스를 검토해야 한다.

- [upgrade/high] activestorage 업그레이드 - Critical 취약점 2건과 High 취약점 1건이 8.0.4에 보고되어 있고, 8.0.5.2로 업그레이드하는 검증된 계획이 있다.
- [upgrade/high] rack-session 업그레이드 - rack-session 2.1.1에 Critical 취약점이 있어 검증된 계획에 따라 2.1.2로 올려야 한다.
- [upgrade/high] actionpack·activesupport 업그레이드 - 두 패키지 모두 8.0.4 기준 High 취약점이 있으며 동일한 검증된 업그레이드 계획이 8.0.5.2를 제시한다.
- [upgrade/medium] nokogiri 업그레이드 - nokogiri 1.19.0에 High 취약점이 있고 검증된 계획이 1.19.5를 목표로 한다.
- [upgrade/medium] addressable 업그레이드 - addressable 2.8.8에 High 취약점이 있어 검증된 계획의 2.9.1로 업그레이드한다.
- [upgrade/medium] concurrent-ruby 업그레이드 - concurrent-ruby 1.3.6에 High 취약점이 있고 검증된 계획이 1.3.7을 제시한다.
- [monitor/high] 계획 없는 고위험 취약점 모니터링 - erb와 puma의 High 취약점은 보고되어 있으나 검증된 업그레이드 계획이 제공되지 않아 추적과 대응 계획 수립이 필요하다.
- [review_license/medium] 라이선스 정책 검토 - bundler-audit@0.9.3은 strong-copyleft 검토 및 conflict 판정이 있고 jquery-fileupload-rails@1.0.0은 unknown으로 미해결이므로 라이선스 검토가 필요하다.
