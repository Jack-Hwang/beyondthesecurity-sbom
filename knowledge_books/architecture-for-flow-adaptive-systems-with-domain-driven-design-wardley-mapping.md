# Architecture for Flow Adaptive Systems (Susanne Kaiser) — DDD·Wardley·Team Topologies — 정제 노트

출처: 로컬 도서 "Architecture for Flow Adaptive Systems with Domain-Driven Design, Wardley Mapping, and Team
Topologies" (PDF, slug `architecture-for-flow-adaptive-systems-with-domain-driven-design-wardley-mapping`). 추출
원문을 읽고 우리 말로 정리한 종합 — 원문 인용이 아니다. 원문 검색은 `/api/books/search` 또는 `book_search`.

## 이 책의 논지

세 도구를 하나의 순환으로 묶는다: **Wardley 매핑**(비즈니스 역량의 진화 단계 — 창신(product+rental)에서 상품화
(commodity+utility)으로) → **도메인 주도 설계**(진화 단계에 맞는 바운디드 컨텍스트 분해) → **팀 토폴로지**(인터랙션
모드와 인지부하를 고려한 팀 경계) → 시스템이 "흐름(flow)"에 적응하도록 진화. 핵심 반론 처리: 컴포넌트가 진화
단계를 넘어 팀을 옮기는 것은 일 단위가 아니라 수 년 단위의 사건 — 빈번한 인계가 아니므로 일상의 변경 흐름을
막지 않는다. 진화된(상품화된) 컴포넌트의 "모범 사례"도, 그 컴포넌트를 다뤄본 적 없는 팀에게는 반복 가능한
알고 활동이 아니므로 그대로 이식되지 않는다.

## 핵심 개념 지도

- **진화 사다리**: 창신 → 제품 → 상품 → 유틸리티. 단계마다 적합한 관리·조달·아키텍처 관행이 다르다.
- **바운디드 컨텍스트**: 진화 단계가 다른 역량은 다른 컨텍스트로 — 같은 컨텍스트에 창신 코드와 유틸리티 코드를
  섞는 것이 부패의 시작.
- **팀 토폴로지 4형(stream-aligned·platform·enabling·complicated-subsystem)과 3 인터랙션 모드(협업·지원·X-as-a-
  Service)**: 인지부하 한도 안에서 팀 경계=컨텍스트 경계.
- **흐름 지표**: 아키텍처의 선악은 변경 흐름의 속도·안정성으로 판정 — 구조 자체가 목적이 아니다.

## 이 프로젝트 적용

- **컴포넌트 진화 단계 태깅**: 재구현 레거시의 컴포넌트를 Wardley 단계로 태깅하는 관행 — "_sbom 파서(상품화:
  표준 라이브러리/외부 조달), 규제 적합도(제품: 우리가 만든다), 채팅 계획기(창신: 실험적)" — 단계가 다른 것을
  한 모듈에 섞지 않는다.
- **인계 빈도 원칙**: 모듈 소유권 이전은 드물게(연 단위) — 이 저장소의 커밋·소유 관행과 일치. 진화를 이유로
  잦은 재분해하지 않는다.
- **인지부하 상한**: 채팅 도구 카탈로그·웹 판의 개수도 인지부하 자산 — 도구 20개 이상이면 그룹화(GROUPS)로
  인지부하를 관리한다(이미 tabs·subnav로 적용).
- **흐름 지표**: gate의 실패 항목·롤백 기록(evidence/loop)이 "변경 흐름의 안정성" 측정 — 아키텍처 논쟁은 흐름
  수치로 종결한다.
