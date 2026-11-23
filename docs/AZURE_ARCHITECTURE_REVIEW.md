# Azure 아키텍처 센터 기준 추론 리뷰 — u-boot 데모 배포 (bts-sbom @ Azure Container Apps)

상태: **완료 (2026-11-23)**. 근거 문서(2026-11-23 접근, ko-kr):
① [기본 웹앱 애플리케이션 참조 아키텍처](https://learn.microsoft.com/ko-kr/azure/architecture/web-apps/app-service/architectures/basic-web-app) — 우리 배포와 **동일한 등급(POC/학습용)**인 참조 아키텍처로, MS 자체가 기둥별로 "POC에서 생략하는 것 / 포함하는 것"을 채점해 둔 문서
② [Azure Well-Architected Framework](https://learn.microsoft.com/ko-kr/azure/well-architected/) — 5 기둥(안정성·보안·비용 최적화·운영 효율성·성능 효율성).
대상: docs/RUNBOOK.md Delivery State "2026-11-23: FIRST AZURE DEPLOYMENT"의 라이브 인스턴스
(https://bts-sbom.yellowdesert-36032bc5.koreacentral.azurecontainerapps.io — u-boot v2026.10 스캔 데모, 약 2주).

## 1. 추론: 우리는 어느 아키텍처 스타일인가

Azure 아키텍처 센터의 축은 **아키텍처 스타일**(기본 웹앱·N계층·Web-Queue-Worker·마이크로서비스·이벤트 기반 등),
**참조 아키텍처**(스타일마다 검증된 배치도), **Well-Architected 5 기둥**(품질 채점 기준), **클라우드 디자인 패턴**(해법 카탈로그)이다.

추론 결과: 우리 배포는 MS 용어로 **"기본 웹앱 애플리케이션"(basic web application) 스타일 — POC 등급**이다.
MS의 POC 정의(학습·개념 증명, "프로덕션 애플리케이션에 사용되지 않음", 단순성·비용 효율 우선)와 우리의
"과제 체크용 약 2주 데모"가 **정확히 같은 등급**이므로, 이 참조 아키텍처의 기둥별 생략/포함 채점을 우리에게
그대로 적용하는 것이 정당하다. (프로덕션 상위판은 MS가 "가용성이 높은 영역 중복 웹 애플리케이션"으로 따로
정의 — 우리는 이번 라운드에서 대상 아님, §6에 승격 경로만 남긴다.)

## 2. Well-Architected 5 기둥 채점 — 적용 전 → 적용 후

| 기둥 | 적용 전(2026-11-23 배포 직후) | 이번 라운드 적용 | 적용 후 |
|---|---|---|---|
| **운영 효율성** | 진단 로깅 0(로그 유실·추적 불가), 프로브 없음(Dockerfile HEALTHCHECK는 ACA가 안 읽음) | ① **진단 설정 생성**: ConsoleLogs·SystemLogs·AllMetrics → Log Analytics `btsbom-logs` ② **ACA 프로브 3종**(Startup /readyz·Liveness /healthz·Readiness /readyz) — 리비전 `bts-sbom--0000003`로 실측 | **POC 등급 충족** (MS POC 권장 2종: 진단 로깅 전원·Log Analytics 중앙화) |
| **보안** | HTTPS 강제·ACA secrets(secretRef)·ACR 관리 ID 풀 — MS POC 등급 수준. **Easy Auth 없음 = MS POC 대비 유일 미달** (완화: 일일 예산 80·수명 2주·철수 절차 문서화) | 코드 변경 없음 — MS POC 문서의 "POC 단계에서는 OK" 항목으로 분류하고 편차를 정직 기록(RUNBOOK) | **POC 등급(무인증 편차 1건 명시)** |
| **안정성** | 단일 레플리카(단일 프로세스 계약), 영속 evidence(Azure Files), scale 0-1 | 프로브 추가로 **얼어붙은 컨테이너 자동 재시작 + 미준비 시 트래픽 차단**이 플랫폼 수준에서 보장 | **POC 등급 충족** |
| **비용 최적화** | scale 0-1(≈$3+사용분) — MS POC의 "비용 우선"과 동일 방향 | Log Analytics 최소 수집(콘솔·시스템 로그 수 MB — 데모 규모에서 $1 미만) | 유지 |
| **성능 효율성** | 0.5 vCPU/1Gi(deploy/kind 실측 근거), NodeGoat 전체 스캔 ~355s 실측, 콜드스타트 20~40초 문서화 | Startup 프로브가 콜드스타트 초기(books 인덱스 재구성 포함 ~120s)를 보호하도록 failureThreshold 24×5s | 유지 + 보호 추가 |

## 3. 클라우드 디자인 패턴 대응 (아키텍처 센터의 패턴 카탈로그 기준)

| 패턴 | 우리 상태 | 근거 |
|---|---|---|
| Health Endpoint Monitoring | **구현 + 이번에 ACA 프로브로 확장** (Docker HEALTHCHECK만으론 ACA가 프로브로 안 씀 — 리비전 0000003에서 적용) | /healthz(가동)·/readyz(준비: evidence 볼륨 쓰기·DB 확인) |
| Retry | **구현** | llm.py: 429/5xx 백오프 재시도, 실패도 예산 장부에 기록 |
| Bulkhead | **구현(예산 형태)** | BTS_SBOM_LLM_DAILY_BUDGET — 제3자 남용이더라도 하루 80호출로 상한 |
| External Configuration Store | **구현** | ACA env+secrets(secretRef), 코드 변경 0로 Host knob 등 주입 |
| Deployment Stamps(리비전) | **구현** | activeRevisionsMode single + revision list/rollback(리비전 0000001→0000003 전이 실측) |
| Queue-Based Load Leveling | **불채용(의도)** | 단일 프로세스·단일 레플리카 계약에서 인프라 큐는 과잉설계; 잡은 인프로세스 EventBus로 이미 레벨링됨 |
| Strangler Fig / Microservices | **불채용(의도)** | stdlib 단일 서비스가 제품 정체성(RUNBOOK 범위 선언) — MS POC 생략 목록과 동일 성격 |

## 4. MS POC 생략 목록과의 대조 (우리가 같이 생략한 것 — 프로덕션 전환까지 유지)

영역 중복·가용성 영역 간 복제 / WAF(웹 애플리케이션 방화벽) / 프라이빗 네트워킹·Private Link / Key Vault
(우리는 ACA secrets로 대체 — MS도 "PoC 단계에서는 앱 설정 저장이 적절"이라 명시) / 자동 확장(우리는 max 1 고정)
/ Defender for Cloud. **우리만의 추가 편차 1건**: 무인증 external ingress(Easy Auth 미설정) — MS POC는
Easy Auth를 포함한다. 완화·수명·철수 절차는 RUNBOOK Delivery State 기술.

## 5. 이번 라운드 실측

- 프로브: `az containerapp update --yaml` → 리비전 **bts-sbom--0000003**, probes = [Liveness /healthz, Readiness /readyz, Startup /readyz(initial 5s·period 5s·threshold 24 — 콜드스타트 ~120s 보호)], 업데이트 후 /healthz 200 재실측.
- 진단: Log Analytics 워크스페이스 **btsbom-logs** 생성 + 진단 설정 **to-btsbom-logs**(ContainerAppConsoleLogs·ContainerAppSystemLogs·AllMetrics → 워크스페이스). 카테고리 이름은 `diagnostic-settings categories list`로 서버에서 조회(문서의 ConsoleLogs 이름은 이 리소스형과 다름).
- 적용 선언: **deploy/azure/containerapp.applied.yaml** — 라이브에서 export한 실제 적용 상태(시크릿 값은 Azure가 마스킹) — 재배포 가능한 참조.

## 6. 프로덕션 승격 체크리스트 (데모 종료 후, MS가 가리키는 상위판으로)

1. Easy Auth(Entra ID) 활성 — MS POC조차 포함하는 항목(현재 유일한 미달).
2. Key Vault 참조로 시크릿 이동 + 앱의 ACR 풀을 이미 관리 ID로 유지.
3. min replicas 1(스케일 0 해제 — 콜드스타트 제거) + 영역 중복 환경.
4. Log Analytics 보존 정책·가용성 경보(action group+email) — 데모에서는 수집만.
5. 배포 자동화(README의 az 절차를 Bicep/ARM으로) — MS POC 권장 "PoC 단계에서 시작".
6. WAF·프라이빗 네트워킹 — 트래픽이 실제 사용자를 갖기 전에.
