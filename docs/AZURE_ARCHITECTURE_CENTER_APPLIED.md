# Azure 아키텍처 센터 전 카탈로그 → bts-sbom-app 적용 (전수 매핑, 2026-11-23)

범위: https://learn.microsoft.com/ko-kr/azure/architecture/ 의 세 축을 **전수** 조사해 우리 솔루션(단일 프로세스
stdlib HTTP 서비스 bts-sbom-app, Container Apps 스케일 0→1 단일 복제본, Azure Files 증적 볼륨, Azure OpenAI 챗,
OSV 조회, 인프로세스 스캔 잡+SSE, 무인증 공개 데모 약 2주, stdlib-only)에 추론 적용했다. 이전 라운드
(docs/AZURE_ARCHITECTURE_REVIEW.md)가 기본 웹앱 참조 아키텍처+5기둥이었다면 이번은 **카탈로그 전체**다.

## 1. 아키텍처 스타일 — 공식 6종 전수 (카탈로그가 guide/architecture-styles로 이관·2025-09 개편 확인)

| 스타일 | 판정 | 근거 |
|---|---|---|
| N계층 | 부분 | 물리 티어 분리는 단일 프로세스와 배치; **논리 계층화(handler→서비스→파일 접근, 상위만 하위 호출)**는 그대로 채택. "자주 변하지 않는 데이터 캐시"→OSV 캐시, WAF 배치 권고→프로덕션 전환 항목 |
| 웹-큐-작업자 | 부분(최근접) | HTTP 프런트+백그라운드 잡 구조 일치. **큐는 in-process EventBus로 대체** — 문서 자체가 "장기 실행 작업이 없으면 작업자는 선택 사항"으로 완화. 202+상태 엔드포인트(/api/jobs)·리비전 교체 배포 관습은 채택 |
| 마이크로서비스 | 부적합 | 분해가 의도적 배제. 단 미니어처 채택: **중앙 로깅+상관 ID+메트릭**, 구성 외부화, 오류 격리(resilience.py) |
| 이벤트 기반 | 부적합(스타일)/부분(관습) | 문서 명시 부적합 조건(단순 요청-응답·강한 일관성)이 정확히 해당. EventBus에는 상관 ID(잡 ID=seq 접두)+오류 격리를 유지 |
| 빅 데이터 | 부적합 | 볼륨 조건 미달(Azure Files 규모). 수집 초기 스크러빙·파티셔닝 위생만 채택 |
| 빅 컴퓨팅 | 부적합 | 수백~수천 코어 vs 단일 복제본 — 정반대 |
| (참고) CQRS | 부적합(패턴) | 문서 명시: "도메인이 간단·CRUD로 충분하면 부적합" — 그대로 해당. 수준 2 API 관습만 채택 |

**결론**: 어느 스타일에도 정확히 속하지 않는 **"웹-큐-작업자의 큐 제거판"**이며, 문서의 완화 조건이 이를
정당화한다. 스타일이 아니라 웹 앱 기준선(baseline) 시리즈(=AZURE_ARCHITECTURE_REVIEW.md의 기본 웹앱)에 속한다.

## 2. 클라우드 디자인 패턴 — 44개 전수 채점

**이미구현(4)**: Retry(net.py 429/5xx 백오프+Retry-After·llm.py 2시도) / **Circuit Breaker(resilience.py 호스트별
closed→open→half-open, 임계 3·쿨다운 60s, env 조정)** / Health Endpoint Monitoring(/healthz 가동·/readyz 준비 분리,
ACA 프로브 연결) / Compute Resource Consolidation(단일 프로세스·컨테이너·환경 통합 — 문서 예시 그대로).

**부분(5)**: Bulkhead(ACA 0.5vCPU/1Gi 한도+LLM 직렬화 락 — **이번에 잡 동시성 상한 1개 적용**) / Throttling
(아웃바운드 일일 예산 80+상류 Retry-After 존중 — **이번에 인바운드 429+Retry-After 추가**) / External Configuration
Store(ACA secrets+env — App Configuration 본체는 불채용) / Queue-Based Load Leveling(in-process 잡+202+/api/jobs —
외부 큐 불채용, 문서 미적용 사례 "예측 가능하고 낮은 볼륨") / Gateway Offloading·Routing(ACA ingress가 TLS·단일
엔드포인트 등가 — 서비스 1개라 본체 불채용).

**불채용(나머지 35개 패턴)** — 문서 자체의 미적용 사례에 정확히 해당: Deployment Stamps(단일 스탬프·확장 요구 없음),
Static Content Hosting(정적 볼륨 미미), Valet Key(대형 직결 전송 없음·무인증 전제 불성립), Sidecar(문서: "작은 앱에는
비용>이익"), Ambassador(문서: "단일 언어면 클라이언트 라이브러리가 더 나음" — **그 라이브러리가 net.py**),
Leader Election(레플리카 1=자연 싱글턴), Strangler Fig(레거시 없음), Saga·Compensating Transaction(분산 트랜잭션 없음),
Event Sourcing·CQRS·Materialized View·Index Table·Sharding(단순 도메인·단일 볼륨), Competing Consumers·Priority
Queue·Sequential Convoy·Messaging Bridge(큐 없음), Publisher-Subscriber(EventBus가 최소판), Claim Check(대용량
페이로드 없음), Geodes(단일 리전), Gatekeeper·Federated Identity(무인증 데모 — 프로덕션 항목), Anti-Corruption
Layer(레거시 시스템 없음), Scheduler Agent Supervisor(단일 잡 단순 조정), Cache-Aside(이미 존재: exact_cache+메모리
_DOCS), Idempotent Consumer(레코드 저장이 key 덮어쓰기=멱등), Asynchronous Request-Reply(202+/api/jobs로 구현),
Choreography(단일 서비스), Interior items 등.

## 3. 모범 사례 11문서 — 체크리스트 판정과 적용

**transient-faults**(가장 중요): 429·5xx 재시도/4xx 비재시도 ✓(net.py·llm.py), 무한 재시도 금지 ✓,
중복 재시도 계층 없음 ✓, Retry-After 우선 ✓. **이번 보강**: 재시도·타임아웃 감사(아래 §5), 단일 레플리카라
지터 불요는 문서 논리로 정당.
**background-jobs**: 컨테이너 앱 형태(작업(job) 아님) ✓, 상태 폴링 병행 ✓(/api/jobs), 리소스 경합 없음 ✓(min=max=1).
**적용**: **SIGTERM 드레인**(새 잡 거절+진행 잡 완료) — 문서의 "수락 중지→완료" 절. 전체 체크포인트/재개는 데모
범위 밖(명시).
**auto-scaling**: Container Apps KEDA 0스케일 프레임 ✓(min 0/max 1). "같은 인스턴스 가정 금지"는 단일 레플리카의
**문서화된 제약**으로 정직 기록. 콜드스타트 워밍은 N/A(응답 목표 위반 없음).
**monitoring**: 상태 엔드포인트 ✓. **적용**: **상관관계 ID**(X-Correlation-ID 응답+오류 본문) — 문서의 "활동 ID
연결" 항목. 구조화 로그·UTC·민감정보 배제는 기존 준수. OTel/App Insights는 N/A(stdlib-only, stdout→콘솔 로그 수집).
**api-implementation**: **적용: 최상위 예외 가드** — "예외 객체·스택 반환 금지": 이전에는 미처리 예외가 연결 절단
(RemoteDisconnected, KeyError 라운드 실측) → 이제 500 {"error","correlation_id"} + 서버 로그에만 traceback.
**적용: Cache-Control**(동적 no-store·파일 max-age 60). SSE 비버퍼링·끊김 처리 ✓(_serve_events의 flush·BrokenPipe
처리 — 검증 테스트 동봉). 자체 속도 제한은 일일 예산이 상향 보호(문서도 "DDoS 대체재 아님" 구분).
**api-design**: 리소스 명사·상태 코드 계약·202+상태 엔드포인트 ✓. limit 상한·HATEOAS·버전 관리는 N/A(문서 근거).
**caching**: 프로세스 내 캐시가 문서가 인정하는 정당한 형태 ✓(OSV _DOCS+exact_cache).
**cdn / host-name-preservation / message-encode**: 전면 N/A(적중률 낮음·기본 도메인·큐 없음 — 원문 근거).

## 4. WAF 검사 목록 — RE:01~10·PE:01~12

충족: RE:01(단순성=stdlib)·RE:02(흐름 2개)·RE:06(크기조정 명시)·RE:07(플랫폼 자동복구+프로브)·PE:03(서비스 선택
근거)·PE:05(조정 고정)·PE:07(최소 인프라)·PE:09(단일 흐름). 부분: RE:03(FMA=종속성 4개 실패 표, 본 문서 §2·3이
수행)·RE:04(목표 한 줄: "스캔은 재시작 후 재시딩/재개 가능")·RE:08(수동 장애 주입 1회: 컨테이너 재시작 후 스캔
재실행 확인)·RE:10·PE:04(로그 기반)·PE:06(데모 스모크)·PE:08(OSV 캐시+볼륨 구조). N/A: RE:05(중복성)·RE:09(DR)·
PE:02(용량)·PE:11(대응)·PE:12(지속최적화) — SLO 없는 2주 데모(문서가 "비즈니스 요구에 따라" 전제).

## 5. 이번 라운드 코드 적용 실측 (AC-617·618)

1. **최상위 예외 가드**(server.py do_GET/do_POST 래퍼): 미처리 예외 → 서버 로그에만 traceback, 응답은
   `500 {"error":"internal error","correlation_id":...}` — 이전의 연결 절단(RemoteDisconnected) 해소.
2. **잡 동시성 상한**(State.acquire_job, env BTS_SBOM_MAX_JOBS 기본 1): /api/scan·/api/reimpl 초과 시
   `429 + Retry-After: 30` — Bulkhead·Throttling·QBLL 3 문서의 고려사항 동시 충족.
3. **SIGTERM 드레인**(serve()+State.begin_drain): 새 잡 `503 + Retry-After: 60`, 진행 잡은 ACA 유예 안에 완료.
4. **상관관계 ID**: 요청당 uuid12 → 모든 응답 `X-Correlation-ID` + 오류 본문 echo.
5. **Cache-Control**: API 응답 no-store, 서빙 파일 public max-age=60.
6. **timeout 감사**: 모든 아웃바운드 urlopen에 timeout 명시 확인(net.py 154·llm.py 192·osv_local_db.py 50 —
   누락 0건).

## 6. N/A 스킵의 인용 근거 (정직 스킵 — 모두 원문 인용)

CDN(적중률 낮음·프라이빗) / 공유 캐시·Redis(단일 프로세스는 인메모리로 충분하다고 문서 명시) / 자동확장 규칙·
쿨다운·플래핑(min=max=1은 발동 조건 없음) / 중복성·DR·용량 계획·지속 최적화(SLO 없는 2주 데모; Azure Files 백업
한 줄만 유지) / 데이터 파티셔닝(WAF design-guide로 이관, 저장소 확장성 대상) / 재시도 일반·서비스별 문서(일시적
오류 처리로 통합 확인) / 호스트 이름 유지(쿠키·절대 URL 없음) / 메시지 인코딩(큐 없음) / HATEOAS(문서: "수준 2로
대략 맞춘다") / API 버전 관리(문서: "버전 관리 없음 — 일부 내부 API에서 작동") / 다중 테넌트 / API Management
(비용+홉 추가) / 자체 429·WAF·DDoS(문서: "네트워크 계층 DDoS 보호의 대체재가 아님" — 예산 80이 상한) /
OTel·App Insights(stdlib-only; stdout→콘솔 로그 수집이 최소 충족) / SignalR(stdlib SSE가 동일 역할) /
Chaos Studio·Load Testing(수동 모의 429/500+컨테이너 재시작 1회로 POC 충족).

## 7. 남은 것 (데모 종료 후 프로덕션 승격 시)

Easy Auth(보안 기둥 유일 미달)·Key Vault 참조·min replicas 1·WAF·배포 자동화(Bicep)·Log Analytics 보존 정책·
체크포인트/재개(인메모리 잡 상태의 영속화) — docs/AZURE_ARCHITECTURE_REVIEW.md §6과 동일한 순서.
