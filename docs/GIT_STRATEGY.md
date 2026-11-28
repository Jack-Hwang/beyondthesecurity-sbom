# Git 브랜치 전략 (Guru 강의 화이트보드 채택, 2026-11-28)

출처: 과정 화이트보드 "AI App Git 브랜치 전략" (사진: 과정 폴더 KakaoTalk_20261127_102033805.jpg).

## 흐름 (하→상 PR 체인)

```
PROD       master (prod)   ← PR ← release      ← hotfix/* (긴급 직접)
STG(QA)    release (stg,qa) ← PR ← dev          ← release 배정 시점 Tag YYYYMMDDHHmm
DEV        dev              ← PR ← feature/*    (개별 환경·브랜치 — 이중화팀, PL)
```

- 본 저장소에는 이미 `release/vX.Y.Z` 명명 관행이 있어 STG 라인은 **`release/stg`** 로 채택했다 (이름 충돌 회피).
- `feature/aiagent`, `feature/mcp` 는 화이트보드 예시대로 dev에서 분기. `feature/guru(x)` 는 강의사(x)라 미생성.
- **Tagging(릴리즈)**: `YYYYMMDDHHmm` 형식 + 설명 주석. release 배정 시점에 release/stg 위에 찍는다.

## 본 저장소 운용 규칙 (자동화 세션 기준)

1. 기능 구현은 `feature/<lane>` 에서 진행하고 push한다.
2. dev는 feature 브랜치를 fast-forward 병합한 뒤 push (충돌 없을 때; 있으면 재베이스 후 병합).
3. QA 실측(전체 pytest·smoke)이 통과하면 release/stg에 병합하고 **태그 `YYYYMMDDHHmm`** 를 단 뒤 push.
4. master는 release/stg의 태그 시점 커밋을 병합해 push (PROD 배포 지점 — Azure 이미지 태그와 1:1 대응).
5. 긴급 수정(hotfix/*)은 master에서 분기→수정→master 병합→release·dev에 역병합(체리픽).

## 채택 시점 상태 (2026-11-28)

- master = dev = release/stg = main = 7813e2f (CRA 컴플라이언스 레인까지). 첫 태그 `20261128021500`.
- 진행 레인: feature/aiagent (챗·에이전트 기능 루프), feature/mcp (MCP 표면).

## URecA2.0 DevOps/GitOps 도식 채택 (2026-11-28, AC-1272/1273)

URecA2.0 개선 도식(GitHub Enterprise + Actions + Argo CD/Argo Rollouts)을 이 저장소의 규모에 맞게 채택했다.
"도식 그대로"가 아니라 각 레인의 **메커니즘**을 측정 가능한 형태로 옮긴 기록:

| URecA2.0 레인 | 본 저장소 채택 | 실측 |
|---|---|---|
| PR 승인(A/A·P/A) + Merge 시 배정 작업 | 운용 규칙 1~5 유지 + 아래 승인 매트릭스 문서화 | (문서) |
| CI: 빌드→docker→ACR 등록 | `ci-image.yml`: GitHub OIDC 페더레이션(시크릿 0) → 빌드 → **Trivy CRITICAL=0 게이트** → ACR 푸시 | dispatch 실측 |
| Rollback 빌드: "이전 이미지는 최신 빌드 시 이전 Tag로" | 태그 로테이션: `latest`→`previous` 회전, 신규는 `v<버전>`+`sha-<해시>` | 위 워크플로 스텝 |
| CD: Argo Rollouts Blue/Green | `scripts/gitops_deploy.py deploy` — ACA 리비전 트래픽 가중치, 스모크가 `CONTAINER_APP_REVISION`으로 서빙 리비전 단정 | **라이브 PROMOTED 실측** |
| Rollback 배포: 이전 이미지 정보로 재배포 | `gitops_deploy.py rollback` — 구 리비전 생존 시 플립 전용, 소멸 시 원장의 기록 이미지로 재생성 | **라이브 ROLLED BACK 실측** |
| Git 배포정보→sync→적용 | `gitops_deploy.py drift` — 커밋된 applied YAML vs 라이브(이미지·스케일·환경키, 값은 유출 금지) | **라이브 DRIFT 2건 실측**(11-23 배포분 낡음 입증) |
| Argo CD GUI | 원장 `evidence/deploy_ledger.jsonl` + `status` 표시(리비전·트래픽·이미지) | (기록) |

### 승인 매트릭스 (도식의 A/A·P/A를 본 저장소 규모로)

| 대상 브랜치 | 승인 | 비고 |
|---|---|---|
| master(PROD) | A/A(2인 승인) | Azure 이미지 태그와 1:1 — hotfix/* 직행 |
| release/stg(QA) | A/P(1인 승인+QA 실측 첨부) | 태그 YYYYMMDDHHmm |
| dev | P/A(작성자 외 1인) | FF 병합 |
| feature/*, hotfix/* | 자유 | push → 원격 백업 |

### 실측에서 얻은 플랫폼 교훈 (2026-11-28 라이브)

- `az containerapp update --revision-suffix` 는 새 리비전에 **즉시 100% 트래픽을 이동**시킨다(0% 대기 아님) — Blue/Green은 update 직후 파란 리비전을 100%로 되돌리는 핀부터 시작해야 한다.
- ACA 플랫폼 변수는 `CONTAINER_APP_REVISION`(Cloud Run의 `K_REVISION`이 아님) — 스모크의 리비전 단정은 이 값을 본다. 단일 리비전 모드에선 주입되지 않아 multiple 모드가 Blue/Green의 전제.
- 트래픽 분할 명령은 `az containerapp ingress traffic set --revision-weight`(이전 `--traffic-weight`는 폐기 예정, `--distribution`은 존재하지 않는다).
- 0% 트래픽 리비전은 비활성화될 수 있다 — 인스턴트 롤백 대상이 사라지면 원장의 기록 이미지로 재생성하는 이미지 레인이 그 빈칸을 채운다.
- `az role assignment create` 가 이 구독에서 MissingSubscription으로 거부되면 raw ARM(`az rest`, Microsoft.Authorization PUT)으로 성공한다.
