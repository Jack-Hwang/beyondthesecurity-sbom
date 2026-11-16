# railsgoat

- source: `https://github.com/OWASP/railsgoat.git` (commit `f5951f1308`)
- components: 197 - vulnerabilities: 258 {'LOW': 122, 'MEDIUM': 104, 'HIGH': 29, 'CRITICAL': 3}
- license resolved: 166 of 197 (0.843) from {'deps.dev': 166}
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
| CVE-2026-79770 | nokogiri | 1.19.0-aarch64-linux-gnu | HIGH | 7.5 | 1.19.3 |
| CVE-2026-79770 | nokogiri | 1.19.0-aarch64-linux-musl | HIGH | 7.5 | 1.19.3 |
| CVE-2026-79770 | nokogiri | 1.19.0-arm-linux-gnu | HIGH | 7.5 | 1.19.3 |
| CVE-2026-79770 | nokogiri | 1.19.0-arm-linux-musl | HIGH | 7.5 | 1.19.3 |
| CVE-2026-79770 | nokogiri | 1.19.0-arm64-darwin | HIGH | 7.5 | 1.19.3 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| activestorage | 8.0.4 | 8.0.5.2 | 13 | False | True |
| rack-session | 2.1.1 | 2.1.2 | 1 | False | True |
| rack | 3.1.19 | 3.1.23 | 18 | False | True |
| nokogiri | 1.19.0 | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-aarch64-linux-gnu | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-aarch64-linux-musl | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-arm-linux-gnu | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-arm-linux-musl | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-arm64-darwin | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-x86_64-darwin | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-x86_64-linux-gnu | 1.19.5 | 14 | False | True |
| nokogiri | 1.19.0-x86_64-linux-musl | 1.19.5 | 14 | False | True |
| net-imap | 0.6.2 | 0.6.4.1 | 8 | False | True |
| addressable | 2.8.8 | 2.9.1 | 7 | False | True |
| actionpack | 8.0.4 | 8.0.5.2 | 6 | False | True |

## Patch

- status: **applied** (approved=True), applied components: 11, rescan fixed: 0

- note: manifest edits applied; the scanner reads lockfiles that still pin the old versions - regenerate them (see regenerate) to complete the fix

- regenerate lockfiles: `Gemfile: bundle update <pkg>`

## Architecture

- 143 files, 10719 LOC, 0 import edges, None cycles (tangle None)
- hotspot `app/controllers/admin_controller.rb`: 4 commits, 79 LOC, score 82.5
- hotspot `app/controllers/tutorials_controller.rb`: 3 commits, 193 LOC, score 80.3
- hotspot `app/assets/javascripts/bootstrap-timepicker.js`: 2 commits, 804 LOC, score 79.2
- hotspot `app/controllers/benefit_forms_controller.rb`: 4 commits, 81 LOC, score 75.7
- hotspot `spec/support/capybara_shared.rb`: 4 commits, 59 LOC, score 75.4
- runtime ruby 2.6: unknown (none)
- note: shallow clone: hotspots/coupling use only the last 400 commits
- note: no internal import edges resolved (unsupported language or flat layout) - graph metrics are empty, not zero-risk

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

- [upgrade/low] activestorage 8.0.4 -> 8.0.5.2 - OSV 재조회 결과 후보 버전 깨끗함: 13개 취약점 해소
- [upgrade/low] rack-session 2.1.1 -> 2.1.2 - OSV 재조회 결과 후보 버전 깨끗함: 1개 취약점 해소
- [upgrade/low] rack 3.1.19 -> 3.1.23 - OSV 재조회 결과 후보 버전 깨끗함: 18개 취약점 해소
- [upgrade/low] nokogiri 1.19.0 -> 1.19.5 - OSV 재조회 결과 후보 버전 깨끗함: 14개 취약점 해소
- [upgrade/low] nokogiri 1.19.0-aarch64-linux-gnu -> 1.19.5 - OSV 재조회 결과 후보 버전 깨끗함: 14개 취약점 해소
- [upgrade/low] nokogiri 1.19.0-aarch64-linux-musl -> 1.19.5 - OSV 재조회 결과 후보 버전 깨끗함: 14개 취약점 해소
- [upgrade/low] nokogiri 1.19.0-arm-linux-gnu -> 1.19.5 - OSV 재조회 결과 후보 버전 깨끗함: 14개 취약점 해소
- [upgrade/low] nokogiri 1.19.0-arm-linux-musl -> 1.19.5 - OSV 재조회 결과 후보 버전 깨끗함: 14개 취약점 해소
- [review_license/medium] 라이선스 미식별 31개 확인 - 라이선스가 식별되지 않으면 의무 이행 여부를 판단할 수 없다
