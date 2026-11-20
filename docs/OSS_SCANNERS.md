# OSS 스캐너 통합과 고지문(OSS Notice) 자동화

FOSSLight 스캐너 계열(Scanner, Source, Dependency, Binary, Yocto, Android, Prechecker, Scanner GUI)이 하는 일을 BTS-SBOM 안에
**표준 라이브러리만으로** 다시 구현하고, 그 결과로 OSS 고지문을 자동 생성하는 기능입니다. FOSSLight의 코드를 가져온 것이 아니라
공개 사용자 가이드에 적힌 동작과 입출력 형식을 보고 새로 만들었습니다(아래 "라이선스 위생" 참고).

## 1. 한눈에 보기

```bash
# 폴더 / 압축 파일(zip tar tgz bz2 jar whl rpm src.rpm) / git URL / 압축 파일 URL 을 소스+의존성+바이너리로 분석
bts-sbom oss scan ./my-product -f xlsx -f yaml -o out
bts-sbom oss scan https://github.com/org/repo.git --branch v1.2 -m source,dependency -e "node_modules" -e "test/*"
bts-sbom oss scan product-src.rpm --notice html --contact oss@example.com --license-dir ./licenses

# 고지문: 보고서에서 html / text / simple-html / simple-text
bts-sbom notice out/bts_report_20261117_101500.xlsx -f html --product "My Product" --lang ko --audit notice_audit.json --strict

# 두 스캔의 차이, REUSE 방식 점검, Yocto / Android 빌드 산출물
bts-sbom oss compare before.xlsx after.xlsx
bts-sbom oss precheck lint ./my-product
bts-sbom oss yocto ./build/tmp --license-manifest tmp/deploy/licenses/image/license.manifest
```

웹 콘솔(`bts-sbom-app serve`)에는 **OSS Scanner** 탭이 추가되어 같은 기능을 화면으로 제공합니다(7절).

## 2. FOSSLight 구성요소와 대응

| FOSSLight | 라이선스 | BTS-SBOM 구현 | 방식 | 같은 점 / 다른 점 |
|---|---|---|---|---|
| FOSSLight Scanner (통합) | Apache-2.0 | `bts-sbom oss scan` (`ossscan.py`) | 소스+의존성+바이너리 실행 후 병합, sbom-info.yaml 보정 1회 적용 | 같은 점: `-m`(모드), `-e`(제외), `--branch`, 형식 선택, compare, 보정 `--no-correction`/`--correct-file`. 다른 점: 설정 JSON(`-s`), Docker 모드, Hub 업로드 없음 |
| Source Scanner | Apache-2.0 | `oss_source.py` | 파일별 SPDX 태그, 라이선스 문구, LICENSE 파일, 저작권 문구를 정적 검출 | ScanCode 수준의 검출은 아님. `--engine scancode`는 **명시했을 때만** 설치된 `scancode`를 실행. SCANOSS 지문 전송(외부 전송)과 LGE 전용 KB는 구현하지 않음 |
| Dependency Scanner | Apache-2.0 | `oss_dependency.py`, `oss_manifests_extra.py` | 매니페스트/락파일 **정적 파싱** | npm/yarn/pnpm, pip(requirements, setup.py, pyproject, uv.lock), maven/gradle, cocoapods, carthage, swift, pub, go, nuget, helm, unity, cargo. **패키지 매니저 명령은 실행하지 않음**(분석 대상을 실행하지 않는 원칙). 그래서 로컬 메타데이터에 없는 라이선스는 비워 두고, `--online`을 줄 때만 공개 레지스트리에서 조회 |
| Binary Scanner | Apache-2.0 | `oss_binary.py` | 매직 바이트 판별, 해시, JAR/pom 분석, 버전 배너, 임베디드 SBOM(Go/Rust/.NET/ELF 패키지 메타) | **TLSH 유사도 매칭과 Binary DB는 없음**(DB가 없고 참조 구현과 해시가 일치해야 비교 가능). 대신 로컬 KB 파일(JSON/CSV: 해시 -> OSS)의 정확 일치. 배너 식별은 `needs_check`로 표시 |
| Yocto Scanner | Apache-2.0 | `oss_yocto.py` | bom.json, buildhistory, installed-package 목록, license.manifest, create-spdx JSON 파싱 | bitbake는 실행하지 않음(문서와 동일). `&`/`\|` 라이선스 연산자를 SPDX AND/OR로 변환(모호한 토큰은 원문 유지) |
| Android Scanner | Apache-2.0 | `oss_android.py` | module-info.json, MODULE_LICENSE_*, .meta_lic, NOTICE 파일 | 빌드는 하지 않음. Notice 상태 ok / ok(NA) / nok / nok(NA) 판정, 중복 제거, 포장 점검 |
| Prechecker | **GPL-3.0-only** | `oss_precheck.py` | REUSE 사양 기준 **클린룸** 구현: lint, add, convert, download | FOSSLight Prechecker의 코드는 읽지도 가져오지도 않았음. 동작은 공개 가이드의 설명과 REUSE 사양만 근거 |
| Scanner GUI | Apache-2.0 | 웹 콘솔 OSS Scanner 탭 | Electron 설치본을 가져오지 않고 기능을 같은 화면으로 | 7절 참고 |

## 3. 공통 보고서 모델 (`ossreport.py`)

- 모든 스캐너가 같은 `OssReport`를 만듭니다(항목: 종류 src/dep/bin, OSS 이름, 버전, 라이선스 목록, 다운로드 위치, 홈페이지, 저작권 문구, 제외 여부, 비고, 근거 `evidence`).
- 컬럼 이름은 FOSSLight Report 가이드에 적힌 것(OSS Name, OSS Version, License, Download Location, Homepage, Copyright Text, Exclude, Comment)을 따르고,
  의존성의 OSS 이름은 `npm:lodash`, `pypi:requests` 형식으로 씁니다(Maven/Gradle은 `group:artifact`). **FOSSLight Hub로 가져오기는 검증하지 않았습니다.**
- 출력: xlsx(시트 SRC_FL_Source / BIN_FL_Binary / DEP_FL_Dependency / Scanner Info), csv, json, yaml, spdx-json, spdx-tag, cyclonedx-json, cyclonedx-xml. 읽기: xlsx, json, yaml.
- **sbom-info.yaml** 보정: 경로(글롭)가 맞는 소스/바이너리 항목의 OSS 정보를 덮어쓰거나 제외하고, 어디에도 맞지 않는 경로는 "Loaded by"로 추가합니다. 의존성 항목에는 적용하지 않습니다(가이드와 동일).
- 정직성: 모르는 필드는 **빈 채로** 둡니다(`-`는 FOSSLight 규약인 "사내/미확인 코드" 이름에만). 모든 항목은 어떻게 찾았는지 `evidence`에 남깁니다.
- CSV/엑셀 수식 주입(`=`, `+`, `@`로 시작하는 값)은 무력화합니다.
- FOSSLight 컬럼 뒤에 두 개를 더 붙입니다: **Needs Check**(`Check` = 라이선스/식별이 추측인 항목: 바이너리 배너 일치, 매니페스트에 라이선스 없음 등)와
  **Notice Status**(Android NOTICE 상태). xlsx/yaml/json/csv 모두에 실리고 읽어 들일 때 복원됩니다. FOSSLight Hub가 추가 컬럼을 받는지는 검증하지 않았습니다.
- 신뢰할 수 없는 저장소에서 온 문자열이 출력 형식을 위조하지 못하게 합니다: SPDX tag-value는 한 줄 값의 줄바꿈을 공백으로 바꾸고 `<text>` 블록 안의 `</text>`를 무력화하며,
  CycloneDX의 `bom-ref`는 같은 purl이 두 번 나와도 유일하게(`#2` 접미) 만들고, CycloneDX XML에서는 XML 1.0이 못 담는 제어 문자를 지웁니다.
- YAML 출력은 안전하게 되읽을 수 있는 여러 줄 문자열만 블록(`|`) 형태로 쓰고, 그 밖(앞 공백, 끝 빈 줄 둘 이상, 탭 등)은 큰따옴표 이스케이프로 씁니다.

## 4. 고지문 자동화 (`notice.py`)

FOSSLight Hub 가이드의 고지문 유형을 그대로 지원합니다.

| 형식 | 내용 |
|---|---|
| `html` | OSS 이름, 버전, 라이선스, 저작권, 홈페이지 표 + 소스코드 제공 절 + **라이선스 전문(라이선스마다 한 번)** |
| `text` | 위와 같은 내용의 텍스트 |
| `simple-html` / `simple-text` | 전문 대신 SPDX 라이선스 페이지 링크 |

SPDX / CycloneDX 렌더링은 보고서 출력(`-f spdx-json` 등)이 같은 데이터로 만듭니다. 영어와 한국어(`--lang ko`) 제목·문구를 지원합니다.

**만들어 내지 않는 원칙 (이 프로젝트의 정직성 계약을 법적 문서에도 적용)**
- 라이선스 전문은 이 순서로만 가져옵니다: 항목에 담긴 텍스트 -> 소스 스캐너가 컴포넌트 **자신의 LICENSE 파일**에서 읽은 텍스트 -> `--license-dir`(`<SPDX-ID>.txt`) -> 이미 받아 둔 캐시 -> `--fetch-license-texts`를 줬을 때만 SPDX 라이선스 목록(네트워크).
  어디에도 없으면 고지문에 "전문 없음"으로 명시하고 `audit`에 올립니다. `--strict`이면 종료 코드 1입니다.
- 저작권 문구가 없으면 "기록된 저작권 고지 없음"으로 표시하고 채워 넣지 않습니다.
- 소스 공개 의무(GPL/LGPL/AGPL/MPL/EPL 등)가 있는 컴포넌트는 별도 절에 다운로드 위치와 함께 나열합니다. **서면 제안(written offer) 문단은 `--contact`를 줄 때만** 들어가고, GPL-2.0 3(b) / GPL-3.0 6(b) 관행적 문구를 바탕으로 한 **템플릿**이라 감사 결과에 "법무 검토 필요"로 표시합니다.
- 여러 라이선스가 쉼표로 적힌 항목은 AND로 보고 모든 전문을 넣으며(이중 라이선스 선택은 기록되지 않음), `OR` 식은 모든 대안을 넣고 감사에 "선택 미기록"으로 올립니다.
- 사내/독점 라이선스 항목, 제외(Exclude) 항목, 라이선스가 검출되지 않은 소스 파일은 고지문 구성요소에서 빼고 감사에만 올립니다. 같은 패키지의 라이선스 없는 중복 발견은 라이선스 있는 발견에 합칩니다.
- HTML은 모든 값을 이스케이프하고 `http(s)` 이외의 URL은 링크로 만들지 않습니다.
- **`needs_check` 항목(라이선스가 추측인 것)은 숨기지 않습니다**: 고지문에 "라이선스 미검증 - 배포 전 확인 필요"와 스캐너의 비고(왜 추측인지)를 함께 찍고, 감사의 `components_with_unverified_license`에 올리며, `--strict`에서는 문제로 취급해 종료 코드 1입니다.
- 라이선스 식의 `AND` / `OR` / `WITH`는 HTML에서도 유지합니다(`(MIT OR GPL-2.0-only)`가 "둘 다"처럼 읽히지 않게). `GPL-2.0-only WITH Classpath-exception-2.0`의 예외 문구도 전문 목록에 올립니다(`LICENSES/` 점검도 예외 전문을 요구).
- **법률 자문이 아닙니다.** 생성된 고지문과 서면 제안은 담당자 검토를 전제로 합니다.

감사 결과(`--audit file.json`)에는 구성요소 수, 라이선스별 전문 출처, 전문 누락, 라이선스/저작권 없는 구성요소, 다중 라이선스·OR 선택 미기록, 소스 공개 대상, 서면 제안 상태가 들어갑니다.

## 5. 입력 대상 준비와 안전 (`ossscan.py`)

- 폴더는 제자리에서 읽기 전용으로 분석합니다. 압축 파일(zip 계열, tar 계열, bz2, gz, rpm/src.rpm)은 항목 수·총 크기·경로 제한을 걸고 임시 폴더에 풉니다. `../` 와 절대 경로, 심볼릭 링크, 장치 파일은 건너뛰고 경고합니다. src.rpm은 안의 원본 tarball을 한 단계 더 풉니다. zstd 압축 rpm은 표준 라이브러리로 풀 수 없어 이유와 함께 거부합니다.
- git URL은 `git clone --depth 1 --no-recurse-submodules`로만 받고 훅을 끄고 `core.symlinks=false`, 위험한 전송(`ext::`, `file::`)과 이상한 호스트/브랜치 이름은 거부합니다. 복제 뒤 `.git`은 지웁니다. 압축 파일 URL은 크기 제한을 두고 내려받아 풉니다. **URL을 직접 줬을 때만** 네트워크를 씁니다.
- rpm 페이로드는 한 번에 풀지 않고 스트리밍으로 풀면서 출력 크기를 상한(`MAX_TOTAL_BYTES`)에서 바로 끊습니다(gzip/bzip2/xz 압축 폭탄 방지). 손상·잘린 cpio는 오류로 보고합니다.
- XML(`pom.xml`, `.csproj`, `packages.config`, xlsx 내부 XML 등)은 `bts_sbom/_internal/safe_xml.py`로 읽습니다: expat이 DOCTYPE/ENTITY 선언을 만나면 즉시 거부하므로 문서 어디에 있든, UTF-16 같은 어떤 인코딩이든 통과하지 못합니다.
- **웹 서비스의 URL 대상**(`/api/oss/scan`)은 호스트가 루프백·링크로컬(클라우드 메타데이터)·사설·CGNAT·멀티캐스트·예약 주소로 풀리면 거부하고, 리다이렉트 때마다 다시 검사하며, git에는 `http.followRedirects=false`를 줍니다. 사내 서버를 일부러 스캔하려면 운영자가 `BTS_OSS_ALLOW_PRIVATE_HOSTS=1`을 설정합니다. CLI는 기본으로 허용합니다(사용자 본인의 도구). 검사 시점과 연결 시점 사이에 DNS 응답이 바뀌는 경우(DNS 리바인딩)는 막지 못합니다 - 내부 주소에 닿지 않는 곳에서 서비스를 돌리세요.
- 취소는 단계 경계에서만이 아니라 파일 순회, 압축 풀기, 다운로드, git 실행(프로세스 종료) 중에도 반영됩니다.
- 분석 대상은 **실행하지 않습니다**: 패키지 매니저, 빌드, 대상 안의 스크립트, `setup.py`(정적 AST 해석만) 모두 실행하지 않습니다. 모든 스캐너는 심볼릭 링크를 따라가지 않고, 읽기/파일 수/압축 해제 크기를 제한하며, 한계에 닿으면 조용히 멈추지 않고 보고합니다.
- 기본 제외(숨김 파일/폴더, test·doc 폴더, 빌드 스크립트, 바이너리, 보정 파일 `sbom-info.yaml`)는 항목을 버리지 않고 `Exclude` 표시와 이유로 남깁니다.
- 중첩 라이선스 파일이 있는 하위 폴더(예: `third_party/zlib/LICENSE`)의 파일은 상위 `package.json`의 이름/버전을 물려받지 않습니다(출처 추측 방지).

## 6. 라이선스 위생

- Prechecker(GPL-3.0-only)는 코드 복사는 물론 소스 열람도 하지 않고 REUSE 사양과 공개 가이드의 동작 설명만으로 구현했습니다. 이 저장소는 Apache-2.0입니다.
- 다른 FOSSLight 스캐너(Apache-2.0)도 코드를 가져오지 않았습니다. 형식 이해(예: Yocto `bom.json` 키 이름)를 위해 공개 저장소의 **데이터 형식**만 참고했습니다.
- 참고한 공개 문서: FOSSLight Scanner 가이드(scanner, dependency, source, binary, yocto, android, prechecker, scanner_gui, `sbom-info.yaml`), FOSSLight Hub 가이드의 OSS Notice와 FOSSLight Report 형식 페이지.
  참고한 문서 중 한 페이지에는 지시문처럼 보이는 문구가 섞여 있었으나 따르지 않았습니다.

## 7. 웹 콘솔 OSS Scanner 탭 (FOSSLight Scanner GUI 대응)

| GUI 기능 | 구현 |
|---|---|
| 분석 대상: 폴더 / 압축 파일 / URL | 입력란 하나에 경로, 압축 파일, git URL, 압축 파일 URL(브랜치/태그 입력 포함) |
| 분석 종류 체크박스 3개 | Source / Dependency / Binary |
| 제외 경로 | 칩 입력 |
| 진행 단계 | 준비(다운로드/풀기) -> 분석 -> 정리, 취소 가능, 오류는 배너 |
| 개요 / Source / Dependency / Binary 탭 | 건수 카드, 검색·정렬·페이지, 행 펼치기(다운로드 위치, 홈페이지, 저작권, 비고, 찾은 근거) |
| License 탭(위험 등급) | High(강한/네트워크 카피레프트), Medium(약한 카피레프트), Low(허용형), Needs review + 각 의무 |
| 결과 파일 | xlsx/csv/json/yaml/spdx/cyclonedx 내려받기 |
| 고지문 | 탭에서 형식·언어·제품명·연락처 입력 -> 생성 -> 감사 결과 표시 -> 내려받기 |
| 이전 결과 다시 열기 | "Previous scans" 목록, 현재 결과와 비교 |

구현하지 않은 것: Windows 설치 프로그램, 도구 자동 설치(winget), 자동 업데이트, 결과 폴더 직접 선택(서버가 `<evidence>/oss/<job>/`에만 기록해 호출자가 쓰기 경로를 정하지 못합니다),
KB URL/토큰 입력. 서버는 인증이 없는 localhost 서비스이므로 외부에 노출하지 마세요.

`/api/oss/...`의 모든 요청(읽기 포함)은 **Host 헤더가 서비스 자신의 주소**여야 통과합니다: `localhost` 또는 IP 리터럴이고 바인드한 포트와 같을 것(공격자 페이지가 자기 DNS 이름을 127.0.0.1로 돌리는 DNS 리바인딩 차단).
리버스 프록시·머신 이름으로 접속하려면 `BTS_OSS_ALLOWED_HOSTS=이름:포트,...`로 허용합니다. 상태를 바꾸는 요청은 Origin이 다른 사이트이거나 `Sec-Fetch-Site: cross-site`이면 거부합니다.
Content-Length가 숫자가 아니거나 음수이거나 1,000,000을 넘는 POST는 400/413으로 거절합니다(앱 전체 POST에 적용). 끝난 작업은 메모리에서 `MAX_JOBS`개까지만 보관하고(오류·취소 포함) 취소 이벤트는 끝나면 해제합니다.

## 8. 한계와 검증하지 못한 것

- **FOSSLight 도구와의 결과 대조를 하지 않았습니다.** 실제 FOSSLight/ScanCode 실행 결과와 비교하지 못했고(네트워크·도구 없음), 동작은 공개 문서 기준입니다. 검출 정확도는 ScanCode에 못 미칩니다.
- Hub 업로드 호환, 실제 대형 Yocto/AOSP 트리, 수십만 파일 저장소에 대한 성능은 검증하지 못했습니다(작은 합성 데이터로 시험).
- Binary: TLSH/Binary DB 없음, Mach-O/dex/wasm/ar는 해시·KB·문자열 배너만, JAR 취약점 조회는 purl을 `osvscanner`에 넘기는 연결점만(`purls_for`).
- Dependency: 의존성 간 `depends_on`은 직접 파싱하는 형식(pnpm, Podfile.lock, uv.lock, Unity)에서만 채움. pom/Cargo/pyproject의 라이선스 필드는 **프로젝트 자신**의 것이라 의존성에 붙이지 않음(오귀속 방지). `--online`은 npm/pypi/cargo/maven만.
- Source: 파일 앞 64 KB(라이선스 문서는 256 KB)까지 검사, 큰 저장소의 상위 디렉터리 탐색은 최적화하지 않음.
- Android: `module-info.json` 키 이름은 AOSP 일반 지식 기준, `build_log`는 받기만 하고 해석하지 않음, NOTICE 포함 여부는 문자열 탐색 휴리스틱.
- Prechecker: 하위 폴더의 중첩 `REUSE.toml`과 `precedence`는 해석하지 않음.
- 고지문: 라이선스 전문이 없는 라이선스는 전문 없이 나갑니다(감사에 표시). 다중 라이선스는 AND로 취급합니다.
- SSRF 방어는 이름 해석 결과 검사입니다(위 5절): DNS 리바인딩과 연결 직전 주소 변경은 막지 못합니다.
- Prechecker `add`(헤더 추가)는 쓰기 대상이 경로 확인 이후 심볼릭 링크로 바뀌는 경쟁을 하나의 열린 파일 핸들(`O_NOFOLLOW`, 핸들과 경로의 동일 파일 확인, 하드링크 거부)로 막았지만, 이 경쟁을 실제 다중 프로세스로 재현해 시험하지는 않았습니다(경로 교체를 흉내 낸 단위 시험만).
- 검토에서 "여러 줄 저작권이 읽어 들일 때 망가진다"는 지적이 있었으나 재현해 보니 줄 사이 내용은 그대로이고 **앞뒤 공백만** 다듬어집니다(정규화로 보고 그대로 둠).

## 9. 테스트

- `tests/test_ossreport_notice.py`(보고서·형식·보정·비교·고지문), `tests/test_ossscan.py`(대상 준비·압축 안전·git/URL·오케스트레이션), `tests/test_oss_dependency.py`, `test_oss_source.py`, `test_oss_binary.py`, `test_oss_yocto_android.py`, `test_oss_precheck.py`, `tests/test_safe_xml.py`(DTD 거부), `tests/bts_sbom_app/test_oss_api.py`(웹 API·Host 고정·CSRF·Content-Length·취소·작업 정리·SSRF). 모두 오프라인(가짜 서버/주입된 fetcher/가짜 DNS)입니다.
