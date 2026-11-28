# CLAUDE.md — BTS-SBOM 저장소에서 일하는 규칙 (H1 거버넌스 파일)

AI 세션(사람 포함)이 이 저장소에서 코드를 고치기 전에 읽는 규칙이다. 전부 기존 문서·게이트에서 온 것들이고,
위반은 린트와 테스트가 기계로 잡는다.

## 정직 계약 (이 제품의 품질 속성 1위)

- **근거 없이 통과시키지 않는다.** 조회 실패·미지원·측정 못 함은 `0`이 아니라 `gap`·`unverified`·`미측정`으로 쓴다.
- 문장에 **측정 수치**가 없으면 아직 요구가 아니다 — EARS 패턴(패턴 키워드 + shall + 숫자)으로 쓴다(`specs/bts_sbom_app_features.md`).
- 스킵은 통과가 아니다: 게이트 실패도 기록에 남긴다(예: 클린룸의 `compatibility_failed`는 정직 판정이다).
- 덱·문서의 수치는 **출처와 날짜**를 남긴다. 추론은 추론으로 표기한다(측정/추론/갭 3태그 관행).

## 게이트 (커밋 전 통과해야 하는 것들)

1. `python -m pytest tests -q` — 전부 통과. **루트에서 맨 `pytest`는 금지**: `.claude/worktrees/`의 저장소
   복사본까지 수집해 2,303건 수집 오류를 낸다(pyproject `testpaths=["tests"]`로도 막혀 있다).
2. `python -m bts_sbom_app.speclint` — 테스트 없는 AC 0 · 미등록 AC 참조 0.
3. `python -m bts_sbom_app doclint`, `check_md_links`, `dogfood_gate` — 문서·링크·자기 SBOM 게이트.
4. 새 AC는 **먼저 명세에 등록**하고 테스트 docstring에 `AC: BSA-AC-N`을 남긴다(양방향 추적).
5. `docs/AI_IMPACT_ASSESSMENT.md`·`DATASET_DATASHEET.md`는 버전 스탬프 게이트가 있다 — 패키지 버전을
   올렸으면 `python -m bts_sbom_app ai-impact --write docs/AI_IMPACT_ASSESSMENT.md`로 재생성한다.

## 변경 금지 (원본 보호)

- 분석 대상 저장소는 **읽기만** 하고 실행하지 않는다. 수정은 격리 작업 복사본에서만(AC-1 원본 무변경).
- 패치는 승인 토큰(= 화면에 본 플랜의 다이제스트)이 맞을 때만 적용된다(AC-14·15). 토큰이 없는
  시도도 `evidence/approvals.jsonl`에 기록된다.
- VEX `not_affected` 판정은 근거 5종 중 하나 + 10자 이상 사유가 없으면 하지 않는다(fail-closed).

## 협업 규칙 (이 저장소는 여러 AI 레인이 동시에 일한다)

- **한 레인이 커밋하면 다른 레인의 staged 파일이 흡수될 수 있다** — 커밋 전 `git status`로 내 파일만
  스테이징했는지 확인. 충돌 없는 푸시: `git push origin feature/<lane>:<대상>`.
- 체크아웃이 병행 세션의 dirty 파일로 막히면 refspec 푸시 + `git fetch origin main:main`으로 워크트리 무손상 해법.
- `pytest` 전체 실행을 **병행 세션과 동시에** 돌리지 않는다(포트·CPU 경합).
- 문서 수치는 날짜와 함께 갱신한다. 측정했는데 덱·문서가 옛 값이면 그것이 드리프트다.

## 구조 한눈에

- `bts_sbom/` — 코어 엔진(의존성 0) · `bts_sbom_app/` — 서비스 계층(웹 콘솔·챗·AI·배포) · `tests/` — 유일한 테스트 폴더.
- 웹 파일: `bts_sbom_app/web/` — 플랫폼 파일(sca_app 등)은 복사본이며 우리 파일만 수정한다(NOTICE.md).
- 배포: main 푸시 → CI 이미지(Trivy CRITICAL=0 게이트) → `scripts/gitops_deploy.py deploy --image <sha 태그>`
  (블루/그린, 스모크 실패 시 자동 롤백 — `BTS_AZ_FQDN` 필요). `deploy/azure/containerapp.applied.yaml`은
  스냅샷이라 라이브가 진실이다.
- 자세한 운영: `docs/RUNBOOK.md` · `docs/AZURE_DEPLOYMENT.md` · `docs/GIT_STRATEGY.md` · `readme.txt`(5분 데모).
