# 아키텍처 플로우 (Architecture for Flow 개념 요약)

Susanne Kaiser 의『Architecture for Flow: Adaptive Systems with Domain-Driven Design, Wardley Mapping, and Team Topologies』(Addison-Wesley) 에서 제시한 접근법을 BTS-SBOM 팀이 정리한 요약이다(원문 인용이 아니라 개념의 재서술이다).

## 사회기술 시스템 (socio-technical systems)

시스템은 기술(소프트웨어 아키텍처)과 조직(팀 구조·상호작용)의 결합체다. Conway 법칙에 따라 조직의 소통 구조가 시스템 구조에 그대로 새겨진다. 기능(레이어) 단위의 사일로 팀은 변경이 여러 레이어를 넘을 때마다 인수인계(handover)를 만들고, 이것이 대기시간과 병목이 되어 변경 흐름을 방해한다.

## Wardley 매핑 요소

- 가치 사슬(y축): 사용자 → 사용자 요구 → 구성요소의 의존 사슬. y축 위쪽일수록 사용자에게 보이고 가치가 크다.
- 진화 단계(x축): genesis → custom-built → product(+rental) → commodity(+utility) 로 왼쪽에서 오른쪽으로 진화한다. 왼쪽일수록 불확실성·변경율이 높고 시장이 정의되지 않았고, 오른쪽일수록 안정·표준화되어 있다.
- 기후 패턴: 모든 것은 공급·수요 경쟁을 통해 진화하고, 효율화가 혁신을 낳는다(더 진화된 구성요소를 재사용하면 효율 격차가 줄어든다). 과거 성공은 관성을 낳는다.
- 진화 단계별 적절한 방법: genesis/custom-built 은 인하우스 + 애자일, product 는 산출물 구매·오픈소스 + 린, commodity 는 유틸리티 아웃소싱.

## DDD 전략적 설계

- 하위 도메인(subdomain) 유형: 핵심(core, 차별화·경쟁 우위·변경 잦음·인하우스), 지원(supporting, 특화되지만 차별화 없음·인하우스 또는 구매), 일반(generic, 어디에나 있음·표준해 존재·구매/오픈소스/아웃소싱). 유형은 전략 투자 우선순위와 build-buy-outsource 판단의 근거가 된다.
- 바운디드 컨텍스트(bounded context): 하나의 도메인 모델이 유일하게 적용되는 경계. 언어적·소유권·물리적 경계를 형성하며, 높은 응집(cohesion)을 만들고 시스템을 모듈로 나누는 자연스러운 절리면(fracture plane)이 되어 stream-aligned 팀의 소유권 후보가 된다.
- 컨텍스트 맵(context map): 바운디드 컨텍스트 간 통합·팀 관계 패턴 — open-host service(OHS), published language(PL), anticorruption layer(ACL), conformist(CF), customer-supplier, shared kernel, partnership, separate ways, big ball of mud. 변경 커플링(change coupling)을 명시적으로 드러낸다. 핵심 도메인과 통합할 때는 OHS+ACL 로 느슨한 변경 커플링을 유지하는 것이 유리하다.

## Team Topologies

- 팀 유형: stream-aligned(고객 지향 변경 스트림 엔드투엔드 소유), platform(자기 서비스 플랫폼 제공), enabling(역량 갭 코칭), complicated-subsystem(특수 지식 영역).
- 상호작용 모드: collaboration(짧은 밀착 협업), X-as-a-Service(자기 서비스 소비), facilitating(역량 전수).
- 팀 인지 부하(cognitive load): 팀이 감당할 수 있는 복잡도에 한계가 있다. 책임 경계가 명확하고(한 컨텍스트는 한 팀이 소유), 구성요소가 진화 축의 왼쪽일수록 인지 부하가 커지므로 한 팀이 소유하는 컨텍스트 수를 줄여야 한다.

## 변경 흐름의 차단자 (flow blockers)

변경이 아이디어에서 고객 가치까지 흐를 때 방해하는 요인: 강하게 결합된 아키텍처(한 곳 수정이 여러 곳에 파장), 기술 부채, 명확하지 않은 소유권, 반복 인수인계, 전문가 의존, 높은 WIP 과 인지 부하, 순환 의존. 병목은 시스템 전체 성능을 지배하므로(제약 이론) 가장 큰 차단자부터 다룬다.

## 모듈화 척도와의 연결

바운디드 컨텍스트 후보 판단의 계량적 힌트: (1) 응집도가 높고(내부 의존 엣지 비중 큼), (2) 외부로부터의 유입 의존이 적으며, (3) 디렉터리·도메인으로 경계가 읽히는 모듈. 히든 디펜던시(코드가 서로 임포트하지 않는데 같이 자주 바뀌는 파일 쌍)는 숨은 변경 커플링의 신호다. 레거시는 한 번에 나누지 않고 modular monolith 로 먼저 바꾸고 Strangler Fig 로 점진 교체한다.
