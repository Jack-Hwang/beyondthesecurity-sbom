# Software Architecture Made Simple (Chris Woodruff) — 정제 노트

출처: 로컬 도서 "Software Architecture Made Simple — A Simplicity-First Approach to Software in the Age of
Complexity" (PDF, slug
`software-architecture-made-simple-a-simplicity-first-approach-to-software-in-the`). 추출 원문을 읽고 우리 말로
정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 채팅 `book_search`.

## 이 책의 논지

복잡성 시대의 답은 **단순성 우선(simplicity-first)**. 모든 아키텍처 결정에 정량 분석(SCI 점수 같은 복잡도 지표
기준선 대비 옵션 비교)을 붙이고, 결정은 ADR로 남기되 **재검토 트리거(revisit trigger)** 와 **측정 계획** 을 함께
적는다. 장 표지 자체가 운영 매뉴얼 형식(알림 → 첫 대응(생각보다 먼저 할 것) → 원인 후보(DB 연결 타임아웃 등) →
30분 내 미해결 시 에스컬레이션 → 사후 검토) — 아키텍처 문서가 운영 절차를 포함해야 한다는 태도.

## 핵심 개념 지도

- **복잡도 기준선(SCI 스타일)**: 현재 점수(예: 4.83)를 잰 뒤 옵션별(A: 코드 변경 없음, B: 메모리 캐시) 점수를
  예측·비교해 결정 — "감"이 아니라 기준선 대비 증분.
- **ADR 확장 형식**: Status·Context·Options Considered·Decision(근거 수치)·Revisit Trigger(다시 열 조건: 예: 요청
  급증 시)·Measurement Plan(어떤 지표로 검증할지).
- **운영 매뉴얼 장**: 알림→첫 대응→원인 후보→에스컬레이션 조건→사후 검토의 고정 흐름 — 장애 문서는 서사가
  아니라 절차다.
- **다중 지역 배포 비판적 검토**: 원데이부터 이중 지역을 "클라우드 모범 사례"로 밀면 미래 대비를 신뢰성 모자를
  쓴 과잉 투자가 된다 — 단일 지역 99.95%→다중 지역 99.99%는 연간 3.65시간 감소일 뿐이고, 그 3.65시간이
  치명적 사업 손실인 경우에만 복잡도가 정당화된다.

## 이 프로젝트 적용

- **재검토 트리거 채택**: ADR-0021의 FTS5 대안 조건("메모리·지연 실측이 임계를 넘으면")이 이 책의 revisit
  trigger 형식. 앞으로 ADR에 재검토 조건을 명시하는 것을 표준으로 — 조건 없는 ADR은 닫힌 결정이 아니라
  미완성 결정.
- **기준선 대비 증분**: capacity.md의 "측정|값|커맨드" 표가 SCI 기준선 관행 — 새 최적화 제안은 "현재 p95 → 예상
  p95" 증분을 먼저 쓴다. 게이트(loop.py)도 기준선 대비 열화만 차단하는 같은 논리.
- **운영 매뉴얼 형식**: RUNBOOK의 Deployment·Rollback·Monitoring 절이 알림→첫 대응→에스컬레이션 절차와 동형 —
  새 기능은 RUNBOOK에 운영 절차(무엇이 고장 나면 무엇을 볼 것인가)를 함께 적는다.
- **과잉 신뢰성 투자 경계**: 이 앱에 레디스·다중 인스턴스·다중 지역을 도입하지 않는 근거가 이 계산법이다 —
  가용성 증분(시간/년)을 실측·추정으로 쓰고, 그 시간이 실제 손실인지 질문한 뒤에만 복잡도를 산다.
