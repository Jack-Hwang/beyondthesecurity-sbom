# MS Azure 배포 검토 (Azure Deployment Review) — bts-sbom-app

상태: **검토 완료·미배포** (2026-11-22, 사용자 요청 "우리 서비스를 ms azure에 올리고 싶다 — 검토 해봐").
실제 배포는 `az login` 이후 deploy/azure/README.md 절차로 진행한다 — 이 문서는 검토와 준비물만 다룬다.

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

## 4. 비용 대략 (월, 대략치 — 견적 아님)

- Container Apps: 소비 플랜 기준 min 1 replica 상시(CPU 0.5·Mem 1Gi) ≈ 3~6만원대 + 로그·대역폭·Files(2Gi ≈ 1천원대).
- Easy Auth/AAD: 무료(티어 기본). 정확한 청구는 Azure 계산기로 확정할 것 — 이 표는 규모 감각만 제공.

## 5. 배포 절차

deploy/azure/README.md의 az CLI 복붙 절차(rg → env → Files → secret → containerapp create → 검증)를 따른다.
배포 후 RUNBOOK의 Delivery State에 실측(배포 소요·probe 결과·SSE 확인)을 기록하고, 무인증 선언을 Easy Auth
활성 사실로 갱신한다 — 그 전까지 이 서비스의 배포 상태는 "검토 완료·미배포"로 유지한다.
