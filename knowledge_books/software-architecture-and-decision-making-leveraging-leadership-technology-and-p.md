# Software Architecture and Decision-Making (Srinath Perera) — 정제 노트

출처: 로컬 도서 "Software Architecture and Decision-Making — Leveraging Leadership, Technology, and Product
Management to Build Great Products" (EPUB, slug
`software-architecture-and-decision-making-leveraging-leadership-technology-and-p`). 추출 원문을 읽고 우리 말로
정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 채팅 `book_search`.

## 이 책의 논지

아키텍처 결정은 기술만이 아닌 리더십·제품·조직의 교차점에서 나온다. 매크로 아키텍처 장들을 조정(coordination)·
일관성 보존·보안·고가용성·마이크로서비스 일관성이라는 결정 주제로 조직하고, 시스템 안정성·진화를 별도 장으로
다룬다. 인증·인가 모델도 결정 사례로 취급: ACL은 사용자마다 규칙이 늘지만 **RBAC는 IDP의 사용자·그룹 위에
권한·역할 매핑을 얹으므로 새 사용자마다 규칙을 추가할 필요가 없다** — Azure의 consumers/contributors/admins
기본 그룹처럼 기존 모델을 재사용하라는 조언. RBAC의 한계(세분화·위임)도 명시.

## 핵심 개념 지도

- **매크로 결정 주제**: 조정(동기/비동기), 일관성(강·최종), 보안(인증·인가·테넌시), 고가용성(복제·장애 도메인),
  마이크로서비스 일관성(데이터 소유·사가).
- **인가 모델 선택**: ACL(자원 중심 규칙 나열) vs RBAC(역할 중심, IDP와 권한 시스템 분리, what-are-my-resources
  질의 지원) vs ABAC — 규모·변경 빈도가 선택기.
- **안정성 공학**: 서킷브레이커·타임아웃·재시도 예산·백프레셔 — 실패를 전제한 설계.
- **진화**: 마이그레이션 경계(스트랭글러), 호환성 계약, 결정 기록.

## 이 프로젝트 적용

- **인가 모델 정직성**: 이 앱은 인증 없는 localhost 서비스로 정직히 선언(RUNBOOK) — RBAC 도입을 "필요해 보여서"
  하지 않는다. 다만 배포 확장(kind) 시 "인증 계층이 아직 없다"는 미해결 항목을 명시하는 것이 이 책의 결정 기록
  방식.
- **안정성 공학 = net.py**: 서킷브레이커(연속 실패→개방→탐침)·4상태 결과·재시도 예산은 이 책의 실패 전제 설계의
  표준 구현. 새 외부 호출은 같은 계약(net.fetch_json)만 통과한다.
- **결정 주제로 문서 읽기**: ADR 작성 시 "조정·일관성·보안·가용성" 주제 중 어느 결정인지 태그 — 주제가 없는
  기술 변경은 아키텍처 결정이 아니다(구현 세부로 넘긴다).
- **호환성 계약**: evidence 기록 스키마(PROJECT_SCHEMAS_ACCEPTED)의 버전 관리는 마이그레이션 경계 관리 — 스키마
  변경은 구 스키마 수용 집합을 넓히는 방향으로.
