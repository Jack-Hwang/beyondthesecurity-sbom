# ADR-0024: 코드 수정 제안은 제안 전용 — 적용은 다이제스트 토큰으로 CLI 에서만

## Status
Accepted — 사후 기록. 코드: `bts_sbom_app/codeprop.py`(신규), `bts_sbom_app/server.py`(읽기 전용 /api/codeprop/(by project)), `bts_sbom_app/cli_ext.py`(codeprop --apply). AC: BSA-AC-661~678, 테스트 `tests/bts_sbom_app/test_codeprop.py`.

## 근거 (Context)
주제 선언 4번의 "코드 수정 제안". 지금은 manifest 버전 숫자만 고치고 호출 코드는 사람이 고친다. 분석 대상 저장소의 텍스트는 신뢰할 수 없는 데이터이고(지시서 1 chat.py trust 구분), 모델 출력은 검증 전까지 데이터다(§0.2). 정직 계약: 제안은 적용이 아니다.

## 결정 (Decision)
모델은 **줄 범위 교체만** 제안하고 diff 를 직접 쓰지 않는다 — 프로그램이 작업 대상 파일의 실제 내용에 교체를 적용하고 `difflib.unified_diff` 로 만든다(diff 가 항상 원본 줄과 일치). 제안은 결정적 검증 6단계(V1 파일이 사이트 집합 안 / V2 범위가 보여 준 조각 안 / V3 파일·줄·diff 상한 / V4 새 의존성 import 금지(애매하면 거부) / V5 파이썬은 ast.parse 구문 검사(실행 아님) / V6 제어문자·과장 줄 금지)를 모두 통과해야 proposed. 제안 diff 는 `<project>/codeprop/<id>.diff` 로 저장. **적용은 CLI 전용**(`--apply --token <digest>`): 다이제스트 불일치면 변경 0건, `workspace.prepare` 로 새 작업 복사본에서 `git apply --check` → 적용 → ast 재검사 → 실패 시 복사본 revert → 성공 시 브랜치 `bts-sbom/code-proposal` 커밋(푸시 없음). 결과는 `tests_run: false` + "patched code has not been built or tested". 웹 API 는 저장된 제안 읽기만, 챗 도구에 적용 경로 0개.

## 기각 대안 (Rejected alternatives)
- 모델이 diff 를 직접 작성: 원본과 어긋나는 diff·문법적으로 무효한 diff 위험 — 줄 범위 교체 + 프로그램 적용으로 차단.
- 제안을 자동 적용: 승인 게이트 약화 — 다이제스트 토큰(사람이 diff 를 검토했다는 증거) 없이는 0 변경.
- 챗에서 적용: 채팅 입력 위조로 분석 대상 소스가 바뀔 수 있다 — 웹·챗은 읽기 전용(AC-676).

## 결과 (Consequences)
구문 검사만 하고 빌드·테스트는 하지 않는다(결과에 명시). 승인 토큰 구조는 기존 patch.py 의 다이제스트 방식과 같다(작업 1 의 ADR-0008 계열). 파이썬 외 언어는 `syntax_checked: false` 계열로 남는다(V5 na/fail 구분).
