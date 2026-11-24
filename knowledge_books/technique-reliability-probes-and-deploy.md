# technique reliability probes and deploy

출처: Architecting AI Systems + AI Agents Definitive Guide 종합 (우리 말 종합 — 원문 인용 없음)

## 핵심 원칙

- 배포 가능성은 빌드 재현성+취약점 게이트+가동부 프로브+롤백 트리거의 세트다.
- 헬스(프로세스)와 레디니스(의존성)는 다른 질문이다 — 섞지 않는다.
- 릴리스는 게이트 통과와 실측 기록이 함께 있을 때만 선언한다.

## 이 프로젝트 적용

- healthz/readyz 분리·공급망 게이트·RUNBOOK 4블록·capacity.md가 이 원칙의 구현이다 (AC-514~516, 521).
- Dockerfile NOT BUILT YET 제거 관례처럼 배포 문장은 실행자만 쓴다.
