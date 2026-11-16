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

## Proposals (deterministic - use_llm=false)

- [upgrade/low] com.fasterxml.jackson.core:jackson-databind 2.9.8 -> 2.18.11 - OSV 재조회 결과 후보 버전 깨끗함: 60개 취약점 해소
- [upgrade/high] org.apache.shiro:shiro-core 1.2.4 -> 3.0.0 - OSV 재조회 결과 후보 버전 깨끗함: 13개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/low] org.apache.logging.log4j:log4j-core 2.9.1 -> 2.25.4 - OSV 재조회 결과 후보 버전 깨끗함: 8개 취약점 해소
- [upgrade/low] org.postgresql:postgresql 42.3.1 -> 42.7.12 - OSV 재조회 결과 후보 버전 깨끗함: 6개 취약점 해소
- [upgrade/high] org.springframework.security:spring-security-web 4.2.12.RELEASE -> 6.5.11 - OSV 재조회 결과 후보 버전 깨끗함: 5개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/high] com.h2database:h2 1.4.199 -> 2.2.220 - OSV 재조회 결과 후보 버전 깨끗함: 4개 취약점 해소 (메이저 업그레이드 - 호환성 검토 필요)
- [upgrade/low] cn.hutool:hutool-all 5.8.10 -> 5.8.21 - OSV 재조회 결과 후보 버전 깨끗함: 1개 취약점 해소
- [upgrade/low] com.alibaba:fastjson 1.2.24 -> 1.2.83 - OSV 재조회 결과 후보 버전에 잔여 취약점: 2개 취약점 해소
- [review_license/medium] 라이선스 미식별 7개 확인 - 라이선스가 식별되지 않으면 의무 이행 여부를 판단할 수 없다
- [refactor/medium] 순환 의존 분리 - 모듈 순환은 변경 영향 분석과 점진적 교체를 막는다
- [extract_module/low] src/main 도메인 분리 후보 - 응집도 1.0, 유입 의존 0개로 점진적 분리(strangler) 후보
