# BTS-SBOM

**SBOM · 오픈소스 라이선스 · 취약점 · 승인형 패치 · 레거시 아키텍처 분석 · LG EXAONE 제안 · 근거 기반 RAG 챗봇 · 루프 엔지니어링**
(국방 · 자동차 · 의료 · 금융 · 선박(초안) · EU CRA · 로봇)

이 레포의 `bts_sbom_app/` 패키지입니다. 같은 레포의 `bts_sbom/` 코어(OSV, SBOM, 산업별 리포트) 위에 얹힌 표준 라이브러리 전용 계층이며,
코어와의 접점은 `bts_sbom_app/engine.py` 한 곳뿐이고 코어 파일(`bts_sbom/`)은 수정하지 않습니다. 같은 배포판(`bts-sbom`)에 들어 있어
별도 설치 의존성이 없습니다(`dependencies = []` 유지).

Pure Python standard library on top of the `bts_sbom` core in this repository (OSV, SBOM, sector
reports). English summary: BTS-SBOM clones GitHub repositories (or reads local folders), builds CycloneDX/SPDX/OpenVEX, resolves licenses
with provenance, scans OSV, plans and - only after explicit approval - patches dependency manifests with re-scan verification, analyses
legacy architecture, asks LG EXAONE for validated proposals, answers questions through a grounded chatbot, and improves itself through a
measured loop. It is a work in progress: read **Limitations** first.

## 한계 (먼저 읽으세요)

- **패치는 매니페스트만 고칩니다.** `package-lock.json`, `Cargo.lock`, `go.sum`, `Gemfile.lock` 등 락파일은 해시를 오프라인으로 다시 만들 수 없어
  직접 고치지 않고 재생성 명령만 안내합니다. 그래서 락파일 기반 프로젝트의 "재스캔으로 확인된 수정"은 일부입니다(아래 표: 1,291건 중 515건 = 0.399,
  OSV 재조회 기준 추정 705건). 패치한 코드를 **빌드·테스트하지 않았으므로** 호환성은 검증되지 않았습니다(메이저 업그레이드는 `breaking_risk=high`로 표시).
- **실제 GitHub 저장소 10개는 제가 고른 것**이고 다수가 일부러 취약하게 만든 앱입니다. 취약점 수는 일반 프로젝트를 대표하지 않습니다.
- **BTS-SBOM 자체의 GitHub push / PR 전달 기능은 실제 GitHub에 해본 적이 없습니다.** 로컬 bare 저장소로만 검증했습니다(AC-21).
  CI(`.github/workflows/bts_sbom_app_ci.yml`)는 GitHub에서 통과했습니다(ubuntu/windows × Python 3.10/3.12). `Dockerfile.bts-sbom-app` 는 빌드해 본 적이 없습니다.
- **검색은 어휘 기반**(BM25+TF-IDF)이라 의역에 약합니다. 저자가 만든 골든셋 Recall@5 = 1.0 은 낙관적이며, 튜닝에 쓰지 않은 test 셋은 0.917 / 정상 질문 응답률 0.833 입니다.
- **EXAONE 제안은 기계 검증만** 거쳤고 사람이 검토하지 않았습니다. 검증 규칙을 실제 응답을 보고 고쳤기 때문에 채택률 0.919 는 표본 내 수치입니다.
- **선박(maritime) 프로파일은 초안**이며 IACS 적합성 평가가 아닙니다. `knowledge/lecture/` 는 사용자 강의자료를 의역한 것이므로 공개 전에 저작권/약관을 확인하세요.
- 코어(`bts_sbom` v0.1.1)의 결함 3건은 [CORE_ISSUES.md](CORE_ISSUES.md) 에 기록하고 `bts_sbom_app` 쪽에서 우회했습니다(코어 수정은 하지 않았습니다).
- 아래 e2e 수치는 코어가 별도 레포일 때 **v0.1.1 스냅샷으로 고정**해 측정한 것입니다. 통합 후 코어는 같은 트리의 현재 상태를 쓰므로,
  수치를 재현하려면 `BTS_SBOM_PATH` 로 해당 스냅샷을 지정하세요(아래 사용법).

## 실제 GitHub 10개 e2e 결과 (최종 패스 14)

소스: NodeGoat, nodejs-goof, pygoat, railsgoat, java-sec-code, gin, ripgrep, flask, express, iso14229 (`evals/e2e_sources.json`). 모든 분석은 복사본에서만 했고
원본/원격은 건드리지 않았으며 받은 코드는 실행하지 않았습니다.

| 지표 | 값 |
|---|---|
| 프로젝트 성공 | 10 / 10 |
| 컴포넌트 / 취약점 | 2,478 / 1,292 (CRITICAL 147, HIGH 567, MEDIUM 471, LOW 93, UNKNOWN 14) |
| 라이선스 해소율 | 0.990 (출처: deps.dev 1,757 · 락파일 634 · npm 41 · PyPI 16 · Maven 4) |
| SPDX / CycloneDX 유효, `affects` 참조 해소 | 1.0 / 1.0 / 1.0 |
| 수정 계획이 OSV 재조회로 깨끗함 | 339 / 348 (나머지 9개는 알려진 수정 버전이 없는 잔여 취약점) |
| 승인 패치 적용 | 계획이 있는 7개 프로젝트 모두 / 재스캔 확인 515건, 추정 705건 |
| 아키텍처 import 그래프 | 10 / 10 (iso14229 C, railsgoat Ruby 는 부분 분석 표기) |
| EXAONE 제안 채택 | 10 / 10 프로젝트, 채택 57건 / 탈락 5건 (0.919) |
| 매니페스트가 없는 C 프로젝트(iso14229) | 컴포넌트 0 → `empty_project`/`unknown`: "취약점 없음"으로 보고하지 않음 |

산업 리포트(flask 예): 방산 pass 2/gap 2, 자동차 2/2, 의료 2/2/not_evidence 1, 금융 3/1, 선박(초안) 4/2/1, CRA 2/2/1, 로봇 2/1/1. 공급자 정보는 공개 레지스트리로는
채워지지 않아 gap 으로 정직하게 남습니다.

### 루프 엔지니어링: 15 + 4 패스, 한 번에 한 변수

전체 기록은 [LOOP_LOG.md](LOOP_LOG.md), 원자료는 `evidence/loop/`. 실제 e2e 가 단위테스트로 못 잡은 결함을 찾았습니다.

| 발견 | 조치 | 측정 |
|---|---|---|
| 같은 취약점이 매니페스트마다 중복 집계 | 병합 | 취약점 1,959 → 1,438 (-521, 27%) |
| RubyGems 플랫폼 변형이 별개 컴포넌트 | 병합 | 컴포넌트 -30, 취약점 -144, 라이선스 0.978 → 0.990 |
| `go.sum` 에만 있는 버전을 설치된 것으로 오인 | MVS 필터 | 컴포넌트 -21 |
| 계획 검증 dict 키 충돌 | 키를 계획 객체로 | 검증률 0.956 → 0.975 |
| `A AND (B OR C)` 의 괄호가 사라져 **의미가 바뀜** + SPDX 무효 | 구조 보존 파서 | SPDX 유효 0.8 → 1.0 |
| 라이선스 캐시가 정규화 결과를 저장 → **개선이 가려짐** | 원본 근거를 캐시 | 패스 3 의 무변화가 측정 오류였음을 확인 |
| 옛 npm `licenses[]`, Maven POM 라이선스 누락 | 폴백 확장(노브 A/B) | 해소율 0.964 → 0.978 |
| 락파일을 안 건드렸는데 134개 패치가 되돌려짐(가짜 회귀) | 회귀를 수정한 파일 기준으로 | `regression_reverted` → `applied` |
| EXAONE 제안 0/10 (빈 응답·잘림·busy 429·타임아웃) | 토큰 8192, 직렬 호출, 검증 후 캐시 | 0/10 → 8/10 |
| 검증기가 환각이 아닌 **형식 차이**(refs 에 버전 문자열)로 제안의 ~절반 탈락 | 증거 앵커 허용 + 제목 기반 복구 | 채택률 0.47 → 0.919 |
| RAG 신뢰도 게이트가 정상 질문의 67%를 "모름" 처리(범위 밖 100% 거절에 가려짐) | 절대 BM25 임계값 | test 셋 응답률 0.333 → 0.833, 범위 밖 4/4 유지 |

패스 15 이후 변경(배치를 다시 돌리지 않고 단위테스트로만 검증): 작업 복사본 삭제 버그와 `loop --work` 무시 버그(AC-68, 레포 안에 1.1GB 누적되던 것), 챗봇의 출처 포인터
정규화(AC-67). 둘 다 배치 지표를 바꾸지 않지만 "최종 트리 = 마지막 패스 코드"는 아닙니다.

## 사용법

```bash
# (레포 루트에서 실행. 코어 bts_sbom 은 같은 트리에서 가져옵니다. 다른 코어를 쓰려면 BTS_SBOM_PATH=<체크아웃 또는 태그 스냅샷> 을 앞에 붙이세요.)
# 한 프로젝트 분석 (GitHub URL, owner/repo, 또는 폴더). 받은 코드는 신뢰하지 않으므로 격리 모드(-I)로 실행:
python -I -X utf8 run_bts_sbom_app.py scan https://github.com/OWASP/NodeGoat.git

# 패치: 승인 없이는 계획만 (파일 변경 0), --approve 로 적용 + 재스캔 + fix 브랜치 커밋
python -I -X utf8 run_bts_sbom_app.py patch <소스> --approve
# 전달: --deliver branch(기본) | folder --dest DIR | inplace --allow-origin-write | github --remote URL --allow-push [--open-pr]

python -I -X utf8 run_bts_sbom_app.py arch <소스>                          # 레거시 아키텍처
python -I -X utf8 run_bts_sbom_app.py batch evals/e2e_sources.json --tag t  # 여러 소스
python -I -X utf8 run_bts_sbom_app.py loop evals/e2e_sources.json --variable "<바꾼 한 가지>"   # 골든 배치 + 게이트
python -I -X utf8 run_bts_sbom_app.py evalrag                               # 검색 + 챗봇 근거성
python -I -X utf8 run_bts_sbom_app.py evalchat                              # 거버넌스·액션 도구 8문항 라우팅 측정 (정규식 기준선 2/8, --llm-config 로 계획기 8/8)
python -I -X utf8 run_bts_sbom_app.py contextpack <로컬 폴더> --package <패키지> [--cxml]   # bounded 읽기전용 레포 뷰: 라이선스 파일 + import 사이트
python -I -X utf8 run_bts_sbom_app.py chat "CVE-2018-18074 가 뭐야" --evidence <runs 폴더> [--llm]
python -I -X utf8 run_bts_sbom_app.py serve --port 8800 --evidence <runs 폴더>   # 웹 화면 + JSON API (인증 없음: localhost 전용)
```

## 웹 화면 (Open-Source Security)

`serve` 는 BTS 플랫폼의 "Open-Source Security" 화면과 같은 구조의 페이지를 띄웁니다(제목줄, 탭 7개, 하위 칩, 1~4단계 표시, 결과 콘솔).
CSS 5개와 `sca_app.js` 는 플랫폼에서 **원본 그대로 복사**했고(`bts_sbom_app/web/NOTICE.md` 에 출처 커밋과 해시, 수정 금지), 페이지·연결 JS·변환 코드만 새로 썼습니다.

| 탭 | 내용 | 데이터 |
|---|---|---|
| Scan | Git URL 또는 로컬 경로 분석(1~4단계 진행 표시), 데모 저장소 | 실제 분석 |
| Findings | 위험 요약 카드, 심각도 막대, 상위 10건, 결과 콘솔(이슈·의존성·라이선스, "사유와 함께 무시") | 실제 |
| Prioritize | SSVC · EPSS · Exploit Mat. | **계산하지 않음**: 데이터 원천이 없어 값을 만들지 않고 그렇게 표시 |
| Graph & Health | 매니페스트별 의존성, 레거시 아키텍처(핫스팟·결합·순환·EOL) / Supply Chain | 실제 / Supply Chain 은 계산하지 않음 |
| Compliance | SBOM 문서 검사·다운로드(CycloneDX·SPDX·OpenVEX), 라이선스 위험, 산업 리포트 7종 | 실제 (NTIA 점수는 계산하지 않음) |
| Fix | 업그레이드 계획, 제안, **승인형 패치**(계획 미리보기 → 다이제스트 검토 → 승인 → 재스캔 → diff) | 실제 |
| CI/CD · History | 분석한 프로젝트 목록 | 프로젝트별 최신 1건(시계열 아님). CI 게이트는 코어의 `bts-sbom policy` |

- KEV · EPSS · 도달성 · 우선순위 · 발견별 VEX 상태는 계산하지 않으므로 리포트에서 **필드 자체를 뺍니다**("악용 안 됨"·"점수 0"으로 보이지 않게).
- "사유와 함께 무시" 결정은 증거 폴더의 `.triage.json` 에 저장됩니다. 분석 때 만든 OpenVEX 파일에는 반영되지 않지만, **`bts-sbom-app vex <프로젝트>` 와
  `GET /api/vex/<프로젝트>` 가 결정을 적용한 OpenVEX 를 새로 만듭니다**(fail-closed: 오탐은 VEX justification + 10자 이상 사유가 있어야 `not_affected`, 만료되면 다시 열림,
  규칙은 `bts_sbom_app/triage.py`). 화면이 보내는 결정에 justification 이 없으면 `affected` 로 남고 이유가 `status_notes` 에 적힙니다.
- **챗봇으로 분석·패치·VEX**: `bts-sbom-app chat --actions --evidence <폴더>`(대화형 `-i`) 또는 `serve --chat-actions` 로 열면 챗봇이 소스를 분석하고
  (격리된 작업 복사본), **사용자가 입력한 승인 토큰**으로만 패치를 적용하고(계획 미리보기에서 보여준 업그레이드에 대한 16자리 토큰, 1라운드, 재스캔, 악화되면 되돌림,
  푸시 없음, 원본 무변경), VEX 결정은 미리보기 후 **확인 코드(12자리)** 를 입력해야 기록합니다. 토큰·소스·확인 코드·사유가 질문에 그대로 없으면 모델이 계획해도 버려집니다.
  기본 세션은 읽기 전용입니다(`bts-sbom-app patch ... --approve --token` 경로 안내).
- **EXAONE 키를 웹에서 연결**: 엔진 바의 EXAONE 키 입력란에 키를 넣고 **Connect** 를 누르면 업그레이드 제안과 챗 계획에 AI 가 쓰입니다(서버 재시작 불필요).
  `save` 체크 시 `evidence/.llm_config.json` 에 평문 저장되어 다음 서버 기동 때 자동 연결됩니다(환경변수·`--llm-config` 로 시작한 설정이 우선).
  **Disconnect** 는 연결 해제와 함께 저장 파일도 지웁니다. 키는 어떤 응답으로도 돌아오지 않고 상태에는 마지막 4자만 보입니다.
  API: `POST /api/llm {api_key, base_url?, model?, remember?}`, `POST /api/llm/clear`, `GET /api/llm`.
- **레포 컨텍스트 팩**: `bts-sbom-app contextpack <로컬 폴더> [--package <패키지>] [--cxml]` 은 로컬 트리를 bounded 로 읽어 **라이선스 파일**과
  **해당 패키지의 import 사이트(주변 몇 줄 포함)** 만 담은 텍스트를 만듭니다(karpathy/rendergit 아이디어 축소판). 바이너리·200KB 초과 파일·node_modules·
  심링크/정션(Windows 포함)은 사유와 함께 제외 목록에 적히고, 전체는 `max_chars`(기본 60,000) 안에서 잘리며 넘어간 항목 수를 숨기지 않고 셉니다.
  팩의 모든 텍스트는 untrusted 취급입니다 — CXML 내보내기에서 이스케이프되고, "이전 지시를 무시하라" 류 문장이 담긴 파일은 `suspicious` 로 표시(걸러내지는 않음).
  import 사이트는 후보일 뿐 reachability 는 unknown 이며, `verify_site` 가 path:line 을 다시 읽어 확인해 줍니다.
- 재분석하면 이전 기록이 `<이름>.prev.json` 으로 남고 새 기록에 `changes` 가 붙습니다(`bts-sbom-app diff`, `GET /api/changes/<프로젝트>`).
  SBOM 규제 적합도는 `bts-sbom-app conformance`, 여러 프로젝트에 걸친 조회는 `bts-sbom-app fleet` 입니다(`docs/FOSSLIGHT_COMMUNITY_DAY_ANALYSIS.md`).
- **결정 커버리지 그래프**: `bts-sbom-app coverage <프로젝트>`(`GET /api/coverage/<프로젝트>`, 챗 도구 `coverage`)는 기록된 워크플로가 어디까지
  처리했는지를 권고별로 답합니다 — 확정된 결정(decided), 검증된 업그레이드 계획(planned), 규칙이 유지하지 못한 결정(rejected·expired),
  아무 기록도 없는 것(unhandled) — 과 미처리 작업 목록, 모든 적용 결정의 앵커(키·상태·담당자·시각), 권고별 `발견 → 계획/결정 → 결과` 체인.
  ARTEX 의 듀얼 그래프(자산 그래프 + 탐색 그래프 + 테스트 커버리지) 개념을 SBOM 거버넌스에 맞게 새로 구현한 것입니다(개념 차용, 코드 무공유).
  정직 경계: 기록된 것만 세며, unhandled 이 곧 미검토를 뜻하지는 않고 판정은 reachability 를 함의하지 않습니다.
- 승인 패치는 `approval_token`(검토한 계획의 다이제스트)이 없으면 HTTP 400 입니다. 패치는 서버가 만든 임시 작업 복사본에만 적용되고
  원본은 바뀌지 않습니다. 패치가 적용되지 않은 작업의 복사본은 작업이 끝나면 지웁니다.
- 컨테이너 이미지 분석과 파일 붙여넣기·업로드는 지원하지 않습니다(화면에 그렇게 표시).
- 화면은 CSP(`script-src 'self'`)로 서비스하고, 정적 파일은 고정 허용 목록에서만 내려줍니다(AC-71).

EXAONE: `EXAONE_API_KEY`(필수), `EXAONE_BASE_URL`(기본 `https://api.exaone.ai/v1`), `EXAONE_MODEL`(기본 `k-exaone_v2.5`) 또는 `BTS_SBOM_LLM_CONFIG=<json>`.
키가 없으면 결정적 제안으로 동작하며 `source=deterministic` 과 원인을 남깁니다. 한국어 콘솔 출력은 `BTS_SBOM_UNICODE=1`.
테스트(네트워크 전부 가짜): `python -m pytest -q tests/bts_sbom_app` · 스펙 점검: `python -m bts_sbom_app.speclint`.
(0.2.0 부터 코어 CLI 는 `PYTHONUTF8` 없이도 한국어 Windows 콘솔(cp949)·ascii·cp1252 에서 동작합니다. CI 는 안전망으로 계속 `PYTHONUTF8=1` 을 켭니다.)

## 정직 계약

- 근거가 없으면 통과가 아니다(`not_evidence`). 라이선스는 못 찾으면 미해결로 둔다. "데이터 없음"은 "취약점 없음"이 아니다.
- 원본은 바뀌지 않는다(트리 해시로 증명). push, 원본 폴더 쓰기, PR 은 각각 명시 플래그가 있어야만 한다.
- LLM 이 불가하면 결정적 제안으로 강등하고 원인을 기록한다. LLM 성공으로 위장하지 않는다.
- 결과를 줄이는 보정(중복 병합, 플랫폼 병합, go.sum 필터)은 `engine.adjustments` 에 개수를 남긴다.

## 구조

`bts_sbom_app/` — `workspace` 안전한 복사/클론 · `engine` 코어 어댑터(유일한 접점) · `licenses` · `remediate` · `patch` · `deliver` · `sbom` · `sectors` · `arch` · `llm`/`ai` ·
`rag`/`chat` · `pipeline`/`batch`/`loop`/`looplog` · `console`(기록 → 화면 데이터)/`web/`(화면)/`server`/`cli`. 설계는 [ARCHITECTURE.md](ARCHITECTURE.md),
SDD 스펙은 [specs/bts_sbom_app_features.md](../specs/bts_sbom_app_features.md)(EARS AC 77개, 전부 측정값 + 테스트 연결), 강의 방법론의 구현 여부는 [LECTURE_MAPPING.md](LECTURE_MAPPING.md).
테스트는 `tests/bts_sbom_app/`, RAG 지식은 `knowledge/`, 평가 데이터는 `evals/`, 루프 기록은 `evidence/loop/` 에 있습니다.
(RAG 코퍼스와 평가 데이터는 패키지 안이 아니라 레포 루트에 있어서, 소스 체크아웃에서 실행해야 챗봇·`evalrag` 가 동작합니다. pip 로 설치한 휠에는 들어 있지 않습니다.)

라이선스: Apache-2.0.
