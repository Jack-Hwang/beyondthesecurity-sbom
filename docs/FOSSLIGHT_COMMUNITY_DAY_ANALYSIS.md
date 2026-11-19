# 제6회 FOSSLight Community Day 분석과 BTS-SBOM 신규 기능

- 작성일: 2026-11-17
- 대상: https://fosslight.org/news/news/2026-10-28-community_day/
- 구현: `bts_sbom_app/conformance.py`, `changes.py`, `triage.py`, `fleet.py`, `cli_ext.py` (BSA-AC-150..175), 이어서 챗봇 기반 분석·패치·VEX `actions.py`, `evals_chat.py` (BSA-AC-200..210)

## 1. 먼저 밝힐 한계

- 페이지 본문에는 **발표 제목과 발표자, 일시·장소만** 있고 내용은 없습니다. 발표 자료(PDF, `/assets/files/261028/`)는 **읽지 않았습니다.**
  따라서 아래 "추론"은 제목과 FOSSLight Hub 공식 가이드의 취약점 처리 설명에서 끌어낸 것이며, 발표가 실제로 그 내용을 다뤘는지는 확인하지 못했습니다.
- 예고 글(`2026-08-18-community_day_preview`)은 404 였습니다.
- 규제 항목(CISA 2025 초안, EU CRA, BSI TR-03183-2)은 제가 아는 범위의 **부분집합**이며 검토일(`as_of`)을 코드에 넣었습니다. 공식 문서로 다시 확인해야 합니다.

## 2. 자료에서 확인한 사실

행사: 2026-10-28, 서울 서초구. 발표 8건.

| 발표 | 발표자 | 한 줄 해석 |
|---|---|---|
| FOSSLight Scanner 또 Update 되었어요 | 박원재(LG전자) | 스캐너 기능 갱신 |
| 예쁘고 쉬운 UI를 입힌 FOSSLight Scanner | 방재권(LG전자) | 스캐너 GUI, 진입 장벽 낮추기 |
| 변화하는 SBOM 규제와 트렌드 | 오혜진(LG전자 SW Security Governance팀) | SBOM 규제 기준의 이동 |
| FOSSLight Hub의 강화된 보안 취약점 검출 능력 | 최혜성(LG전자) | Hub 취약점 검출 강화 |
| FOSSLight 사용자 경험을 공유합니다 | 엄숭광(ETRI) | 현장 운영 사례 |
| 무엇이든 물어보세요, Scanner 편 / Hub 편 | 정우철, 민경선(LG전자) | 질의응답 |
| FOSSLight Enterprise를 경험해보세요 | 김경애(LG전자) | 상용 제품 소개 |

## 3. Hub 공식 가이드에서 확인한 취약점 처리 방식

(https://fosslight.org/hub-guide/tips/4_vul_info/ , https://fosslight.org/hub-guide/menu/7_vulnerability.html)

- NVD 와 OSV 를 매일 조회해 갱신한다. 점수는 CVSS v4.0, v3.1, v3.0, v2.0 순으로 고른다.
- 사용자가 입력한 OSS 이름·버전이 일치하는 취약점이 있으면 최대 점수를 보여준다. 버전이 비어 있으면 전 버전 중 최대 점수, 이름이 `-` 이면 표시하지 않는다.
- 메일 알림은 프로젝트의 Identification 이 Confirm 된 상태에서만, **임계 점수 이상 CVE 가 발견될 때와 기존 CVE 점수가 임계 아래로 내려갈 때** 발송한다. 알림을 끌 때는 **사유가 필수**다.
- 검색에는 정확 일치(exact match) 옵션과 영향 버전 범위 표기(`[` 포함, `(` 제외)가 있다.
- (검색 요약 기준) 버전 alias, Include CPE / Exclude CPE 로 NVD 매칭을 다듬고, 특정 버전을 쓰는 프로젝트를 조회할 수 있다.

## 4. 추론: 우리 서비스에 부족한 것

| 단서 | 우리 쪽 빈틈 (코드로 확인) | 만든 것 |
|---|---|---|
| SBOM 규제 변화 | NTIA 한 기준만 코어에 있고, 생성 맥락·해시·연락처 같은 새 요소는 어디에도 없음 | **적합도 매트릭스** `conformance` |
| Hub 알림 규칙 | 스캔은 한 장면뿐이라 "달라졌는가"를 말할 수 없음. 재분석하면 이전 기록이 덮어써짐 | **변경 감시** `changes` / `diff` |
| Hub 의 Include/Exclude, 사유 필수 | 콘솔의 "무시" 결정이 OpenVEX 에 반영되지 않음(WORKFLOW.md 에 명시된 공백) | **triage → OpenVEX(fail-closed)** `triage` / `vex` / `review` |
| Hub·Enterprise 의 "이 버전을 쓰는 프로젝트" | 챗봇과 API 가 프로젝트 하나 안에서만 답함 | **전체 조회·포트폴리오** `fleet`, 챗봇 `affected_projects` |
| Q&A·사용자 경험 | 질문마다 정규식 라우팅, 새 영역은 도구가 없음 | 챗봇 도구 3종(`affected_projects`, `sbom_conformance`, `what_changed`) |

## 5. 구현한 기능

모두 표준 라이브러리만 쓰고, 결정적이며 읽기 전용입니다. LLM 은 설명만 쓰고 계산된 사실에 없는 숫자·권고 ID 는 버립니다.

```bash
bts-sbom-app conformance <sbom.json | 프로젝트> [--regime ntia-2021] [--require ntia-2021]
bts-sbom-app diff <프로젝트 | before.json after.json> [--threshold 7.0] [--brief] [--llm] [--fail-on-alert]
bts-sbom-app vex <프로젝트> [--triage .triage.json] [--out vex.json]
bts-sbom-app review <프로젝트>
bts-sbom-app fleet [--cve CVE-...] [--component requests --version "<2.20,>=2.0"]
```

- **적합도 매트릭스**: NTIA 2021 · CISA 2025 초안 · EU CRA 부속서 I · BSI TR-03183-2 · 취약점/VEX 준비도를 한 문서에 동시에 대조.
  규제별 판정(conformant/partial/gaps)과 "한 번 고쳐 여러 기준을 만족" 순위. 근거가 없으면 gap 이며 법적 평가가 아님.
  분석 결과 SBOM 은 이제 `metadata.lifecycles = pre-build` 를 선언(CISA 생성 맥락).
- **변경 감시**: 재분석하면 이전 기록을 `<이름>.prev.json` 으로 남기고 `changes` 를 붙임. Hub 규칙(임계 이상 신규, 임계 교차 상승·하락) + 악성 패키지 + copyleft 도입.
  점수가 없는 항목은 라벨 하한으로만 계산. `--llm` 요약은 사실과 대조.
- **triage → OpenVEX**: 오탐은 VEX justification + 10자 이상 사유가 있어야 `not_affected`, 아니면 `affected` + 이유. 위험 수용은 담당자·만료일과 함께 `affected` 유지.
  만료되면 다시 열림, 스캔이 아직 보고하는 항목의 `fixed` 주장은 거부, 패키지 범위 결정이 전역 결정보다 우선. 콘솔 API(`POST /api/triage`)는 `justification/expires/scope/by` 를 받음.
- **전체 조회**: 권고 ID(별칭 포함) 또는 컴포넌트+버전 제약으로 영향받는 프로젝트를 찾음. 버전이 없는 컴포넌트는 `version_unknown` 으로 드러냄. 인자 없이 실행하면 포트폴리오 요약.
- **서버 API**: `/api/conformance/<p>`, `/api/changes/<p>`, `/api/vex/<p>`, `/api/fleet`, `/api/affected`.

### 5-1. 챗봇으로 분석하고, 승인하면 패치하고, VEX 를 남긴다 (2차 구현)

```bash
bts-sbom-app chat --actions --evidence evidence/runs -i
> C:/work/myrepo 분석해줘                         # 격리된 작업 복사본에서 분석, 라이선스·취약점·계획·토큰 요약
> 배포하면 라이선스 의무가 뭐야                    # license_risks (binary | saas | internal)
> 패치 해줘                                       # plan_patch: 업그레이드 목록 + 승인 토큰(변경 없음)
> 패치 승인 64a2aba63040b0e7                      # 사용자가 입력한 토큰일 때만 적용(1라운드, 재스캔, 악화 시 되돌림)
> CVE-2020-1747 오탐 vulnerable_code_not_in_execute_path 사유: 신뢰된 입력만 파싱한다   # 미리보기 + 확인 코드
> 확정 500bbe4318b9                               # 그 코드를 입력해야 기록
> VEX 내보내줘                                    # 결정이 적용된 OpenVEX 파일
```

- 기본 세션은 읽기 전용이다. `--actions` 가 있어야 분석·패치·결정 기록이 일어난다(서버는 `serve --chat-actions`).
- 모델은 계획만 세울 수 있고 승인할 수 없다. 토큰·소스·확인 코드·사유가 **질문에 글자 그대로** 없으면 버려지고, 사용자가 이름을 말하지 않은 justification 은 추정하지 않는다.
- 패치는 승인한 선택(전체 또는 지정한 컴포넌트)에 대해서만, 한 라운드만 적용한다. 원본은 바뀌지 않고 푸시하지 않는다.
- 실측(실제 OSV): requests 2.19.1 + pyyaml 5.3 → 분석(취약점 7) → 계획(업그레이드 2, OSV 검증) → 잘못된 토큰 거부 → 올바른 토큰으로 적용(7건 해결, 신규 0) → 원본 `requirements.txt` 불변,
  결정 미리보기(정당한 것은 `not_affected`, justification 없는 것은 `rejected` 로 표시) → 확인 코드로 기록 → VEX 7개 문장 중 1개 `not_affected`.
- 라우팅 측정(`evals_chat.py`): 정규식 라우터 8문항 중 2, LLM 계획기 8 중 8, 모델이 쓴 사유는 점수에서 제외(7 of 8).

## 6. 일부러 하지 않은 것

| 항목 | 이유 |
|---|---|
| CVSS v4.0 점수 계산 | 점수는 공식 매크로벡터 조회표가 필요하고, 표를 기억으로 옮기면 틀릴 위험이 큼. 표 파일(FIRST 공개본)을 받아 검증하며 구현해야 함 |
| FOSSLight Scanner 리포트(Excel/YAML) 가져오기 | 실제 샘플 파일이 없어 열 이름·형식을 검증할 수 없음. 참고로 CycloneDX/SPDX 로 내보낸 SBOM 은 `scan <파일>` 로 이미 읽힘(파일 이름과 무관, 실측) |
| 웹 콘솔에 새 패널 추가 | 플랫폼 파일 6개는 수정 금지(NOTICE.md)라 새 페이지 코드가 필요. API 는 준비됨. 별도 세션에서 진행 중 |
| LLM 이 `not_affected` 나 triage 결정을 만드는 것 | VEX 는 fail-closed. `review` 는 사람이 볼 목록만 제공 |
| 메일·티켓 자동 발송 | 외부로 나가는 동작은 별도 명시 플래그가 필요한 이 저장소의 규칙 |

## 7. 검증

- 전체 테스트 195개 통과(신규 3개 파일 · 26개 AC, 기존 테스트 회귀 없음). 스펙 린트와 AC↔테스트 양방향 추적 통과.
- 실제 OSV 로 두 번 스캔해 확인: requests 2.19.1 + flask 0.12 (취약점 9) → requests 2.32.3 + flask 3.0.3 + pyyaml 5.3 (취약점 5).
  `diff` 는 신규 2(pyyaml CRITICAL 9.8 두 건 → critical 알림 2), 해결 6, 지속 3, 버전 상승 2를 보고. `vex` 는 정당한 결정 1건을 `not_affected`, 사유 부족 1건을 거부, `chat` 은 `what_changed` 에 같은 숫자로 답함.
- 검색 품질: 지식 문서 `knowledge/domain/sbom_governance.md` 추가 후 golden 1.0/0.95, dev 1.0/0.869(불변), 보류 test recall 0.917 · MRR 0.715→0.711(게이트 허용 0.02 이내).
  첫 초안은 일반 한국어 어휘가 많아 test MRR 이 0.688 로 떨어져 문서를 좁혀 다시 썼습니다.

## 8. 남은 일

1. CVSS v4.0 점수(공식 표 파일 필요), 2. Scanner 리포트 가져오기(샘플 필요), 3. 웹 콘솔 패널, 4. 챗봇 의역 평가셋에 새 도구 질문 추가(`evals.py` 가 다른 작업으로 수정 중이라 건드리지 않음),
5. 규제 표의 정기 검토(`as_of` 가 6개월 이상 지나면 알리는 점검).
