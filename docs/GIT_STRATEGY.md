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
