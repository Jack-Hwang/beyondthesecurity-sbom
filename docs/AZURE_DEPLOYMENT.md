# MS Azure 배포 검토 (Azure Deployment Review) — bts-sbom-app

상태: **배포 완료 — 라이브 (2026-11-23, 데모·약 2주 운영 후 삭제 예정)**.
URL: https://bts-sbom.yellowdesert-36032bc5.koreacentral.azurecontainerapps.io — 실측 전문은 docs/RUNBOOK.md
Delivery State "2026-11-23: FIRST AZURE DEPLOYMENT" 항목과 deploy/azure/README.md의 첫 배포 실측을 볼 것.
이 문서의 나머지는 검토(2026-11-22) 시점의 근거를 그대로 보존한다.

## 0. 무엇을 올리나

`Dockerfile.bts-sbom-app`(python:3.12-slim, UID 10001, 0.0.0.0:8800, readyz 헬스체크)로 빌드된 컨테이너 하나.
상태는 전부 `evidence` 폴더(분석 기록·트리아지·LLM 장부·saved key) — 컨테이너 안 `/tmp/evidence`(임시).

## 1. 제약 (정직성 계약이 걸리는 지점)

RUNBOOK의 서비스 범위 선언: **"localhost, single-process, no authentication"** — 배포는 이 선언을 바꾸는
행위이므로 각 항목을 명시적으로 닫아야 한다.

| 제약 | Azure에서의 함의 | 닫는 방법 |
|---|---|---|
| **무인증** | 공개 ingress는 인터넷에 관리 화면·분석·패치 승인을 여는 것 — 계약 위반 | Container Apps **Easy Auth(AAD)** 필수, 또는 VNet 내부 ingress만. 인증 전까지는 internal ingress + VPN/Bastion |
| **단일 프로세스·evidence 공유** | 레플리카 2개는 evidence를 공유해 손상 | replicas **1 고정**, KEDA 0스케일 배제(콜드스타트·볼륨 재부착) |
| **evidence 임시 볼륨** | 재시작 시 분석 기록 소실 | **Azure Files 2Gi** 마운트(RWX 불필요, RWO) — deploy/kind의 PVC 선례와 동일 |
| **Host 검사(oss/arch/books sub-API)** | ingress가 Host를 FQDN으로 바꿔 403 | env **`BTS_OSS_ALLOWED_HOSTS=<배포 FQDN>`** (기존 knob — 코드 변경 0) |
| **LLM 키·일일 예산** | 키는 이미 Azure형 저장 지원(azure_api_key/…) | ACA **secrets** → env로 주입, `BTS_SBOM_LLM_DAILY_BUDGET` 기본 80 유지 |
| **OSV.dev/deps.dev 아웃바운드** | 아웃바운드는 자유 — 문제 없음 | (egress 기본 허용) |

## 2. 옵션 비교

| 옵션 | 판정 | 이유 |
|---|---|---|
| **Container Apps** | **권장** | 컨테이너 그대로, Azure Files 마운트, Easy Auth 내장, 리비전 롤백 내장, min-replicas=1 고정 가능, AKS보다 운영 최소 |
| App Service (Linux 컨테이너) | 가능 | 웹 앱에 최적화 — SSE 스트림(/api/chat/stream)은 App Service에서 웹소켓/스트림 설정 주의 필요, 장기 실행 스캔 job에 불리 |
| Container Instances (ACI) | 검증용만 | 영속 볼륨·리비전·인증이 없어 운영 부적합 — 스모크 테스트 용도 |
| AKS | 과잉 | 단일 서비스에 클러스터 운영 비용이 부당 (deploy/kind가 로컬 검증용) |

## 3. 권장 구성 (Container Apps)

- 리소스: rg 1, Container Apps Environment 1(Log Analytics 포함), Storage Account(FileShare `evidence`, 2Gi), ACA app 1.
- Ingress: HTTP, targetPort 8800, **external + Easy Auth(AAD, 미설정 시 internal)**, transport auto(SSE 지원).
- 컨테이너 리소스: CPU 0.5 / Mem 1Gi (deploy/kind 요청치와 동일 — 실측 근거 유지).
- Scale: min 1 / max 1 (단일 프로세스 계약).
- Secrets: `azure_api_key`(또는 exaone key), `azure_base_url`, `azure_deployment`, `azure_api_version` → env로 주입.
- env: `BTS_OSS_ALLOWED_HOSTS=<app FQDN>`, `BTS_SBOM_LLM_DAILY_BUDGET=80`(기본), `BTS_SBOM_UNICODE=1`.
- 검증 절차: 배포 → `/healthz`·`/readyz` 200 → Easy Auth 로그인 → 스캔 1건 → SSE 대화 1턴 → 리비전 롤백 리허설.

## 4. 비용 (월, 공개 요금 × 수식 — 견적 아님, 2025 공개 단가 기준)

단가: vCPU-초 $0.000024, GiB-초 $0.0000093, 월 730h(2,628,000초). 무료 공제: 월 vCPU-초 180,000 · GiB-초 360,000.
LLM 토큰 비용은 별도 과금(Azure OpenAI 리소스 — 우리 사용량 규모로 월 $1~3 수준). Files Standard-LRS 2Gi ≈ $0.4.

| 옵션 | 구성 | 계산 | 월액(USD→원) |
|---|---|---|---|
| **A. 상시 1레플리카 (권장)** | 0.5 vCPU / 1Gi | vCPU (1,314,000−180,000)×$0.000024=$27.2 · Mem (2,628,000−360,000)×$0.0000093=$21.1 | **≈ $50 ≈ 6.8만원** |
| B. 저사양 상시 | 0.25 vCPU / 0.5Gi | vCPU (657,000−180,000)×$0.000024=$11.4 · Mem (1,314,000−360,000)×$0.0000093=$8.9 | ≈ $21 ≈ 2.8만원 |
| C. 스케일 0 (호출 시 기동) | 0.5/1Gi, 하루 1시간 사용 가정 | 3,600초/일 × $0.0000213/초 × 30일 + Files | ≈ $3 ≈ 4천원 |

- A는 24시간 즉시 응답; B는 절반 가격이나 0.25 vCPU는 스캔 피크(북 인덱스 13초 재구성·다중 도구)에서 스로틀 위험 — 채택 시 실측 필요; C는 콜드스타트 20~40초(컨테이너 부팅+books 인덱스 재구성)를 감수하는 대신 거의 공짜, evidence는 Azure Files에 영속이라 안전.
- 환율 가정 ₩1,350/$. 대역폭은 이 서비스 규모에서 무시 가능(월 100GB 무료 공제 내), Log Analytics 켜면 +$2~5.
- Easy Auth/AAD 무료.

## 4.1 LLM 배포 현황 (실측 2026-11-22, az cognitiveservices deployment list)

리소스 `bts-sbom-openai-9f2c`(rg-bts-openai, 구독 "Azure in Open")에는 **gpt-5-mini 1개만 배포됨**
(version 2025-08-07, GlobalStandard, capacity 10). 앱은 deployment 이름을 설정값으로만 쓰므로 다른 모델
호출에 코드 변경은 불필요 — 포털에서 배포를 추가한 뒤 `azure_deployment` 값(gitignored 설정 파일 또는
ACA secret)만 바꾼다. **시연 때만 업로드**하는 운영이라면 스케일 0(옵션 C)이 정답: 상시 과금 없이
구동 시간만 과금되어 시연 1회당 수백 원 수준(2시간 기준 ≈ $0.25), 종료 후 `az containerapp delete`로
잔여 과금도 제거한다(Files 2Gi만 유지 시 월 $0.4).

## 5. 배포 절차

deploy/azure/README.md의 az CLI 복붙 절차(rg → env → Files → secret → containerapp create → 검증)를 따른다.
배포 후 RUNBOOK의 Delivery State에 실측(배포 소요·probe 결과·SSE 확인)을 기록하고, 무인증 선언을 Easy Auth
활성 사실로 갱신한다 — 그 전까지 이 서비스의 배포 상태는 "검토 완료·미배포"로 유지한다.
