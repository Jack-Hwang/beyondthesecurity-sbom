# ADR-0016: App Service (Linux container + staging slot) as the hosting platform

## Status
Accepted — 사후 기록. 코드: `infra/main.bicep`, `infra/main.parameters.json`, `azure.yaml`. AC: BSA-AC-497~505, 테스트 `tests/bts_sbom_app/test_infra_static.py`.

## 근거 (Context)
강의 1주차 1차시의 호스팅 결정 트리(GPU? → 상태? → 트래픽 패턴 → K8s 운영 역량 → 데이터 주권)를 이 서비스에 적용하면: GPU 불필요, **상태 있음**(증거 폴더·작업 기록 — ADR-0019), 사용자 수 적고 간헐적, K8s 운영 역량 없음. 참조 인프라 산출물은 키리스(관리 ID + RBAC), TLS 1.2, healthCheckPath, 예산 알림을 요구한다.

## 결정 (Decision)
App Service(Linux 컨테이너) + `staging` 슬롯. Plan 용량 1, 자동 확장 없음(단일 쓰기 전제 — ADR-0019). 전부 키리스: 관리 ID에 AcrPull(ACR 관리자 계정 비활성)과 Key Vault Secrets User(RBAC 인증, soft delete)만 부여. 웹앱: httpsOnly, minTlsVersion 1.2, ftpsState Disabled, healthCheckPath /readyz, 앱 설정 BTS_SBOM_CLOUD=1·WEBSITES_PORT=8800·BTS_SBOM_API_TOKEN(Key Vault 참조 — 값은 템플릿에 없음)·BTS_SBOM_SOURCE_HOSTS·BTS_OSS_ALLOWED_HOSTS. 필수 태그 3종(team/week/owner, 기본값 없음), 월 예산(50/80/100% 알림). 증거 영속은 컨테이너의 영속 /home(`WEBSITES_ENABLE_APP_SERVICE_STORAGE`)이 기본안이나 동작 확인 전 템플릿에 넣지 않았다(확인 필요).

## 기각 대안 (Rejected alternatives)
- VM: OS 패치·런타임 관리 운영 부담 — K8s 역량 없음과 같은 이유로 배제.
- Container Apps: scale-to-zero가 메모리 상태를 지우고(작업 6·13의 영속화가 있어도) 콜드 스타트·공유 파일시스템 동작이 불확실 — 간헐 트래픽엔 매력적이지만 상태 보존이 우선.
- AKS: 과설계 — 강의의 비례성 원칙("AKS 가 과설계인지 먼저 검토")에 걸린다. 단일 컨테이너 서비스에 클러스터 운영은 맞지 않다.
- 서버리스 함수: 장기 스캔 작업·파일 증거와 안 맞는다(타임아웃·파일시스템 모델).

## 결과 (Consequences)
배포 파이프라인(작업 16)은 OIDC 로그인 → ACR 푸시 → staging 배포 → /readyz 확인 → 수동 승인 environment 에서 스왑의 순서를 따른다. 슬롯이 필요로 하는 요금제 등급(S1 이상으로 알려짐)은 확인 필요 — 파라미터로 뒀다. 경보용 메트릭 이름을 확인하지 못해 메트릭 경보 규칙은 템플릿에 없다(RUNBOOK "확인 필요").
