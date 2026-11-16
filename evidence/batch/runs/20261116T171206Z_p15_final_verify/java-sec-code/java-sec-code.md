# java-sec-code

- source: `https://github.com/JoyChou93/java-sec-code.git` (commit `4711f4e186`)
- components: 53 - vulnerabilities: 160 {'HIGH': 75, 'MEDIUM': 47, 'CRITICAL': 33, 'LOW': 5}
- license resolved: 46 of 53 (0.868) from {'deps.dev': 42, 'registry:maven': 4}
- project license: not detected (-)
- SBOM: CycloneDX valid=True, SPDX valid=True, affects refs resolved=1.0

## Top vulnerabilities

| id | package | version | severity | CVSS | fixed in |
|---|---|---|---|---|---|
| CVE-2025-70974 | com.alibaba:fastjson | 1.2.24 | CRITICAL | 10.0 | 1.2.48 |
| CVE-2021-44228 | org.apache.logging.log4j:log4j-core | 2.9.1 | CRITICAL | 10.0 | 2.12.2 |
| CVE-2024-1597 | org.postgresql:postgresql | 42.3.1 | CRITICAL | 10.0 | 42.3.9 |
| CVE-2017-18349 | com.alibaba:fastjson | 1.2.24 | CRITICAL | 9.8 | 1.2.31 |
| CVE-2020-10683 | org.dom4j:dom4j | 2.1.0 | CRITICAL | 9.8 | 2.1.3 |
| CVE-2015-7501 | commons-collections:commons-collections | 3.1 | CRITICAL | 9.8 | 3.2.2 |
| CVE-2022-22978 | org.springframework.security:spring-security-web | 4.2.12.RELEASE | CRITICAL | 9.8 | 5.4.11 |
| CVE-2022-23640 | com.monitorjbl:xlsx-streamer | 2.0.0 | CRITICAL | 9.8 | 2.1.0 |
| CVE-2019-17495 | io.springfox:springfox-swagger-ui | 2.9.2 | CRITICAL | 9.8 | 2.10.0 |
| CVE-2023-24163 | cn.hutool:hutool-all | 5.8.10 | CRITICAL | 9.8 | 5.8.21 |
| CVE-2023-24162 | cn.hutool:hutool-all | 5.8.10 | CRITICAL | 9.8 | - |
| CVE-2020-1957 | org.apache.shiro:shiro-core | 1.2.4 | CRITICAL | 9.8 | 1.5.2 |
| CVE-2022-40664 | org.apache.shiro:shiro-core | 1.2.4 | CRITICAL | 9.8 | 1.10.0 |
| CVE-2022-32532 | org.apache.shiro:shiro-core | 1.2.4 | CRITICAL | 9.8 | 1.9.1 |
| CVE-2020-11989 | org.apache.shiro:shiro-core | 1.2.4 | CRITICAL | 9.8 | 1.5.3 |

## Remediation plan (verified against OSV)

| component | from | to | clears | major | verified clean |
|---|---|---|---|---|---|
| com.fasterxml.jackson.core:jackson-databind | 2.9.8 | 2.18.11 | 60 | False | True |
| org.apache.shiro:shiro-core | 1.2.4 | 3.0.0 | 13 | True | True |
| org.apache.logging.log4j:log4j-core | 2.9.1 | 2.25.4 | 8 | False | True |
| org.postgresql:postgresql | 42.3.1 | 42.7.12 | 6 | False | True |
| org.springframework.security:spring-security-web | 4.2.12.RELEASE | 6.5.11 | 5 | True | True |
| com.h2database:h2 | 1.4.199 | 2.2.220 | 4 | True | True |
| cn.hutool:hutool-all | 5.8.10 | 5.8.21 | 1 | False | True |
| com.alibaba:fastjson | 1.2.24 | 1.2.83 | 2 | False | False |
| commons-collections:commons-collections | 3.1 | 3.2.2 | 2 | False | True |
| org.dom4j:dom4j | 2.1.0 | 2.1.3 | 2 | False | True |
| com.monitorjbl:xlsx-streamer | 2.0.0 | 2.1.0 | 1 | False | True |
| io.springfox:springfox-swagger-ui | 2.9.2 | 2.10.0 | 1 | False | True |
| org.springframework:spring-expression | 4.3.16.RELEASE | 6.2.19 | 7 | True | True |
| org.yaml:snakeyaml | 1.21 | 2.0 | 8 | True | True |
| org.apache.poi:poi | 3.10-FINAL | 4.1.1 | 6 | True | True |

## Patch

- status: **nothing_applied** (approved=True), applied components: 28, rescan fixed: 157

- regenerate lockfiles: `pom.xml: mvn -q versions:display-dependency-updates`

## Architecture

- 80 files, 6430 LOC, 46 import edges, 1 cycles (tangle 0.049)
- hotspot `src/main/java/org/joychou/controller/SSRF.java`: 20 commits, 319 LOC, score 98.7
- hotspot `src/main/java/org/joychou/security/SecurityUtil.java`: 19 commits, 253 LOC, score 92.3
- hotspot `src/main/java/org/joychou/controller/XXE.java`: 16 commits, 443 LOC, score 92.3
- hotspot `src/main/java/org/joychou/controller/SQLI.java`: 12 commits, 246 LOC, score 91.1
- hotspot `src/main/java/org/joychou/controller/URLWhiteList.java`: 15 commits, 172 LOC, score 88.6
- note: shallow clone: hotspots/coupling use only the last 104 commits

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

## Proposals (exaone - cached EXAONE response for identical evidence (no new call))

총 53개 컴포넌트와 160개 취약점이 보고되었고, fastjson·log4j·postgresql·hutool·jackson 등에 CRITICAL 취약점이 있다. 일부 업그레이드 계획은 verified_clean=true이나 fastjson은 false이고, 라이선스 정책상 unknown/review 및 미해결 컴포넌트가 있다. SecurityUtil.java와 SSRFChecker.java 간 순환 및 src/main 추출 후보/컨트롤러 hotspot도 존재한다.

- [upgrade/high] log4j-core 긴급 업그레이드 - CVSS 10.0 CRITICAL인 CVE-2021-44228이 2.9.1에 영향을 주며, 계획상 2.25.4로 업그레이드하고 verified_clean=true이다.
- [upgrade/high] fastjson 업그레이드 및 검증 필요 - fastjson 1.2.24에 CRITICAL 취약점들이 있고 계획은 1.2.83으로 업그레이드하지만 verified_clean=false라 추가 검증이 필요하다.
- [upgrade/high] jackson-databind 업그레이드 - 2.9.8에 다수 CRITICAL CVE가 있고 계획상 2.18.11로 업그레이드하며 verified_clean=true이다.
- [upgrade/high] postgresql 업그레이드 - 42.3.1에 CVSS 10.0 CRITICAL인 CVE-2024-1597이 있으며 계획은 42.7.12 업그레이드이고 verified_clean=true이다.
- [upgrade/high] hutool-all 업그레이드 - 5.8.10에 CRITICAL CVE-2023-24163과 CVE-2023-24162가 있으며, 계획은 5.8.21 업그레이드이고 CVE-2023-24163 fixed_version은 5.8.21, CVE-2023-24162 fixed_version은 비어 있다.
- [upgrade/medium] h2 major 업그레이드 - 계획상 major_bump=true인 1.4.199→2.2.220 업그레이드이며 verified_clean=true이고, 라이선스 정책 unknown 및 unresolved 목록에 h2가 포함되어 있다.
- [review_license/medium] 라이선스 unknown/review 대상 검토 - 라이선스 정책 category가 unknown, verdict가 review이며 여러 컴포넌트와 org.jdom:jdom2가 unresolved로 남아 있다.
- [extract_module/medium] SecurityUtil/SSRFChecker 순환 분리 검토 - 두 파일 간 cycle이 있고 src/main이 extraction_candidates로 표시되어 있으며 SecurityUtil.java와 SSRF.java 등이 hotspots로 표시되어 있다.
