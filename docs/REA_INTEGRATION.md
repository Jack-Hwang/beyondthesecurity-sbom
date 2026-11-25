# REA 통합 — SBOM 이후 코드 재작성에서 개발자에게 충분한 자료를 주는 방법

목적: SBOM을 만든 다음, "이 구성요소는 패치로 끝나지 않는다"고 판단된 레거시 코드를 **실제로 다시 쓸 때** 개발자에게
충분한 정보를 준다. REA(https://github.com/morluto/rea)는 그 재작성 단계의 **레거시 분석 입력**이다. SBOM 생성의 입력이
아니다.

## 1. REA가 무엇인가 (조사 결과, 2026-11-26)

| 항목 | 내용 |
|---|---|
| 정체 | "Reverse engineer anything with agents" — Node.js CLI + MCP 서버. npm 패키지 `rea-agents`, 사이트 rea.tools |
| 라이선스 | **MIT** (REA 작성 코드). 서드파티는 각자 라이선스, Hopper/IDA/JEB 같은 상용 도구는 사용자가 합법 취득해야 함 |
| 구현 | TypeScript. Node.js `^22.23.4 \|\| ^24.22.1 \|\| >=26.12.1` 필요 |
| 실행 | `npx -y rea-agents@latest analyze-javascript-application <dir\|.asar> --json` 또는 `npm i -g rea-agents` 후 `rea ...`; 에이전트용 MCP 등록은 `rea setup` |
| 지원 대상 | JS/Electron(네이티브 엔진 불필요), 네이티브 바이너리(Hopper·Ghidra·IDA·Kuna 필요), .NET, Android APK, 펌웨어, PyInstaller, `.pyc`, 웹사이트, 네트워크 캡처 등 |
| 출력 | Evidence 레코드: `normalized_result`(관측 사실), `raw_result`(제공자 원문 — 의사코드 등), 한계(`limitations`)·커버리지·`evidence_id`. 모든 결론에 근거와 한계가 붙는다 |
| 사용 조건 | DISCLAIMER: 합법적 연구·상호운용·보존·**본인 소유 또는 분석 권한이 있는 소프트웨어** |

## 2. 가져다 쓸 수 있는가 — 판단

- MIT는 이 저장소의 Apache-2.0과 호환된다. 그러나 REA는 **Node.js 프로젝트**이고 이 앱은 stdlib-only Python
  (런타임 의존성 0, 자체 SBOM이 검증)이므로 코드를 복사·벤더링하지 않는다.
- 따라서 **선택적 외부 도구 어댑터**(`bts_sbom_app/rea_adapter.py`)로 붙인다: 설치돼 있을 때만 subprocess로 호출한다.
  이 도구는 REA를 **내려받거나 설치하지 않는다**. 없으면 `absent`로 기록하고, 개발자가 직접 실행할 명령을 dossier에 준다.
- 핀 고정된 플랫폼 파일 6개(`PLATFORM_ASSETS.sha256`)는 건드리지 않았다.

## 3. 어디에 들어가는가

```
SBOM / 스캔 레코드
   │  rewrite.candidates()   사유: license · no_fix · fix_incomplete (측정)
   │                                eol · incompatible          (선언: eol 입력 + 운영자)
   │                         context(트리거 아님): runtime_eol · major_bump_fix · eol_scheduled
   ▼
클린룸 레인 reimpl.reimpl(trigger=..., rea_provider=...)
   ├─ [독자 쪽] REA 분석 ─ extract_facts() 허용 목록 ─┐
   ├─ [독자 쪽] ast 인터페이스 읽기 (본문은 독자에 머문다)  │
   ├─ spec.md = 인터페이스 계약 + 사유 + 패턴 안내 + REA 사실 + Unknowns  ← 생성기가 받는 유일한 입력
   ├─ 생성 → 카피 게이트(생성 코드 vs 원본, 그대로) → 계약 테스트 → 원본 테스트 오라클
   └─ dossier.md / dossier.json  ← 개발자용, 생성기는 받지 않는다
```

### 개발자 자료(dossier)에 들어가는 것 (10개 절)

1. 재작성 사유와 각 근거·출처(측정/선언/맥락) 2. 정체(버전·purl·선언된 매니페스트)
3. 노출: 취약점, 수정판, 업그레이드 계획·검증 4. 라이선스와 의무, 클린룸이 법적 필수인지 정책 적용인지
5. **프로젝트 안의 사용 지점과 실제 호출 심볼**(Python은 `ast`, JS는 require/import) — 안 쓰는 API는 교체본에서 뺄 후보
6. 레거시 공개 인터페이스(시그니처+계약, 본문 없음)와 사용/미사용 표시 7. **REA 분석**: 사실·커버리지·한계, 또는
   설치되지 않았을 때 **개발자가 직접 실행할 REA 명령**(rea 문서에 있는 명령명) 8. 아키텍처 패턴 안내(책→모델 2단)
9. 검증 계획과 결과(카피 게이트·계약 테스트·원본 오라클·실행 런타임) 10. **확립되지 않은 것**(정직한 공백)

## 4. 클린룸 격벽은 어떻게 유지되는가

REA 출력은 독자 쪽 자료다. 명세로 가는 길은 `extract_facts()` 하나이며 **fail-closed 허용 목록**이다.

- 문서화된 `JavaScriptApplicationGraph` 구조만 읽는다. 구조가 다르면 `unrecognised_shape` — 아무것도 명세에 넣지 않는다.
- `raw_result`(의사코드·원문이 들어갈 수 있는 곳)는 **순회하지 않는다**.
- 식별자·경로·채널·URL 모양의 문자열만 통과(공백·따옴표·괄호·연산자 불가) + 길이·개수 상한 → 구문이나 함수 본문이 "사실"로
  끼어들 수 없다. 버려진 개수는 `dropped`에 센다.
- REA가 못 본 것(커버리지, 한계)은 명세의 **Unknowns** 절로 가서 생성기에게 "추측하지 말 것"을 알린다.
- 카피 게이트의 피연산자는 그대로다(생성 코드 vs 원본). 테스트가 게이트 호출 인자를 가로채 사실 텍스트가 0건임을 확인한다.
- EOL·비호환 사유가 있으면 명세에 "호환 목표" 절(테스트가 도는 인터프리터, 제거된 표준 라이브러리 API 금지)이 붙는다.
  라이선스 사유가 없으면 클린룸은 **정책으로** 적용한 것이지 법이 요구한 것이 아니라고 결과에 적는다.

## 5. 정직한 상태

| 상태 | 뜻 | 표시 |
|---|---|---|
| `absent` | rea CLI 미설치 | "없음"(통과 아님), 설치 힌트, 직접 실행 명령 |
| `unsupported_runtime` / `error` | Node 범위 밖 / `--version` 실패 | 사유와 함께 |
| `not_applicable` | JS/ASAR 산출물이 없음 (Python 소스는 자체 `ast` 독자가 더 정확) | 사유와 함께 |
| `failed` / `timeout` / `too_large` | 실행 실패 / 600초 초과 / Evidence 96 MiB 초과 | rea의 stderr 꼬리 |
| `unrecognised_shape` | rea가 답했지만 읽을 수 있는 그래프가 없음 | 명세에 0건 |
| `ok` | 사실이 명세와 dossier에 들어감 | 사실 수·커버리지·한계 |

트리거도 같다: EOL 입력이 없으면 "EOL 미평가"이지 "지원 중"이 아니다. 비호환은 측정하지 않고 **운영자가 선언한 것만** 기록한다.

## 6. 사용법

```powershell
# SBOM 이후: 재작성 후보와 근거 (스캔 레코드에서)
bts-sbom-app rewrite --evidence evidence/runs --project u-boot
bts-sbom-app rewrite --evidence evidence/runs --project u-boot --component concurrencytest --project-root C:/src/u-boot
bts-sbom-app rewrite --evidence evidence/runs --project app --eol eol.json --declare "oldlib=incompatible:uses removed asyncore"

# 재작성 레인(사유 + 선택적 REA + dossier)
bts-sbom-app reimpl C:/src/legacy-lib --component legacy.py --llm --rea --evidence evidence/runs --project app --sbom-component oldlib@0.9 --project-root C:/src/app
```

- 환경변수 `BTS_REA_CMD` — rea 실행 파일 경로 또는 JSON 배열(`["node","C:/x/rea.js"]`). 없으면 PATH의 `rea`.
- API: `GET /api/rewrite/<project>[?component=name@ver&format=md]`, `GET /api/rea`, `POST /api/reimpl`(`rea`, `rea_target`, `project`, `target`,
  `declared`), `GET /api/jobs/<id>/dossier`. 사유는 **서버가 레코드에서 다시 계산**한다(호출자가 보낸 reasons는 무시).
  `evidence/eol.json`이 있으면 eol 입력으로 읽는다(섹터 보고서의 `--eol`과 같은 `{component: {eol, status}}`).
- 워크벤치(🧬 Clean-Room): 재작성 후보 표(선택), REA 체크박스와 상태, `REA 분석`·`개발자 자료` 단계, 판정 카드, dossier 보기.

## 7. 하지 못한 것 / 한계 (숨기지 않는다)

- **REA를 이 환경에서 실행하지 않았다.** 실행하려면 npm 패키지를 내려받아 제3자 코드를 실행해야 하는데 승인 없이 하지 않았다.
  어댑터는 rea 문서·소스의 스키마(JavaScriptApplicationGraph)와 CLI 문서로 작성했고, 테스트는 가짜 rea 프로세스(네트워크 없음)로
  실행·파싱·실패 경로를 검증했다. **실제 rea 출력에 대한 실측은 없다.**
- 배선된 것은 정적 JS/Electron 경로 하나뿐이다. 네이티브·.NET·Android·펌웨어는 provider(Hopper/Ghidra/IDA/Kuna 등)가 필요하고
  출력 스키마를 검증하지 못해 `not_applicable`로 두고, 대신 dossier에 알맞은 **rea 명령**을 안내한다.
- 재작성(코드 생성) 레인은 Python 모듈만 다룬다. JS 레거시는 `dossier_only`(코드 생성 없음)로 끝나지만 개발자 자료는 받는다.
  Python 2 문법처럼 읽을 수 없는 모듈도 같다.
- 의존성 소스를 내려받는 일은 자동화하지 않았다(소스 경로는 사용자가 준다).
- 사용 지점 탐색은 Python `ast`와 JS require/import 정규식이며 동적 import는 못 본다(상한: 파일 3000개).
