# Azure 배포 절차 (Container Apps) — bts-sbom-app

상태: **첫 배포 완료 (2026-11-23, 데모·약 2주)** — 앱 `bts-sbom` /
https://bts-sbom.yellowdesert-36032bc5.koreacentral.azurecontainerapps.io. 아래 절차는 검토 시점의 계획이고,
실제 배포에서 달라진 점은 문서 끝의 "첫 배포 실측"을 볼 것. 배포 검토의 근거와 제약은 `docs/AZURE_DEPLOYMENT.md`를 먼저 읽을 것 —
특히 **무인증 서비스이므로 Easy Auth(AAD) 또는 internal ingress 없이는 공개 배포 금지**. 이 문서는 복붙형
`az` CLI 절차다(2026-11-22 기준 명령어; az 버전에 따라 옵션명이 다를 수 있음). 모든 명령은 bash 기준.

## 0. 전제

- Azure 구독 + `az login` 완료 (interactive). 이 저장소에서 실제 배포는 아직 수행된 적 없음 — 첫 배포 후
  실측(소요 시간·probe 결과)을 이 문서와 RUNBOOK Delivery State에 기록할 것.
- 컨테이너 이미지가 필요하다: `docker build -f Dockerfile.bts-sbom-app -t <registry>/bts-sbom-app:<tag> .`
  레지스트리는 ACR 권장(`az acr create --sku Basic`), 없으면 Docker Hub.

## 1. 리소스 그룹·환경

```bash
RG=bts-sbom-rg
LOC=koreacentral
az group create --name $RG --location $LOC

az containerapp env create \
  --name bts-sbom-env --resource-group $RG --location $LOC \
  --logs-workspace-id none   # 로그 애널리틱스는 필요 시 생략 가능(비용)
```

## 2. 이미지 푸시 (ACR 예)

```bash
ACR=btsbomacr            # 소문자만
az acr create --name $ACR --resource-group $RG --sku Basic --admin-enabled true
az acr build --registry $ACR --image bts-sbom-app:8.1.0 -f Dockerfile.bts-sbom-app .
```

## 3. evidence 영속 볼륨 (Azure Files)

```bash
STG=btsbomstorage$RANDOM
az storage account create --name $STG --resource-group $RG --location $LOC --sku Standard_LRS
az storage share create --name evidence --account-name $STG --quota 2

az containerapp env storage set --name bts-sbom-env --resource-group $RG \
  --storage-name evidence-files \
  --azure-file-account-name $STG --azure-file-account-key <storage-key> \
  --azure-file-share-name evidence --access-mode ReadOnly
# 위 access-mode는 "ReadOnly"(마운트 모드)이지만 컨테이너 쓰기는 container-app의 volume 설정이 결정한다.
# 쓰기가 필요하므로 storage set 의 access-mode 를 "ReadWrite" 로 둘 것.
```

주의: 컨테이너는 UID 10001로 실행된다. Azure Files 마운트는 UID 매핑이 없어 **권한 문제가 날 수 있다** —
첫 배포 후 `/readyz`의 `evidence_writable` 실패 시 volume의 `uid`/`gid`(10001)를 containerapp YAML의
volume 옵션으로 지정하거나, subPath 폴더를 미리 만들어 권한을 연다. 이 항목은 **첫 배포에서 반드시 확인할
미검증 항목**이다 (deploy/kind의 fsGroup 미검증과 같은 성격).

## 4. 배포 (secrets 포함)

```bash
FQDN.placeholder=none
az containerapp create \
  --name bts-sbom --resource-group $RG --environment bts-sbom-env \
  --image $ACR.azurecr.io/bts-sbom-app:8.1.0 \
  --target-port 8800 --ingress external \
  --secrets azure-api-key="<AZURE_OPENAI_KEY>" azure-base-url="https://<resource>.openai.azure.com" \
            azure-deployment="gpt-5-mini" azure-api-version="2025-04-01-preview" \
  --env-vars AZURE_OPENAI_API_KEY=secretref:azure-api-key \
             AZURE_OPENAI_BASE_URL=secretref:azure-base-url \
             AZURE_OPENAI_DEPLOYMENT=secretref:azure-deployment \
             AZURE_OPENAI_API_VERSION=secretref:azure-api-version \
             BTS_OSS_ALLOWED_HOSTS=<할당된 FQDN> \
             BTS_SBOM_LLM_DAILY_BUDGET=80 BTS_SBOM_UNICODE=1 \
  --min-replicas 1 --max-replicas 1 \
  --cpu 0.5 --memory 1.0Gi
# 볼륨 마운트는 YAML 경로가 편하다: deploy/azure/containerapp.yaml 편집 후
#   az containerapp update --name bts-sbom --resource-group $RG --yaml deploy/azure/containerapp.yaml
```

## 5. 인증 (필수 — 무인증 서비스)

```bash
az containerapp auth microsoft update --name bts-sbom --resource-group $RG \
  --client-id <AAD-app-id> --client-secret-name msauth-secret --issuer https://login.microsoftonline.com/<tenant>/v2.0
# 또는 인증 전까지: az containerapp ingress update --name bts-sbom -g $RG --type internal
```

## 6. 검증

```bash
FQDN=$(az containerapp show --name bts-sbom -g $RG --query properties.configuration.ingress.fqdn -o tsv)
curl -s https://$FQDN/healthz ; curl -s https://$FQDN/readyz
# 스캔 1건 + SSE 대화 1턴(브라우저) + /api/code-metrics/<p> 200
az containerapp revision list --name bts-sbom -g $RG -o table   # 롤백 리허설: revision activate
```

## 7. 첫 배포 후 기록할 것

배포 소요, probe 통과, evidence_writable(볼륨 UID) 결과, SSE 동작, Easy Auth 설정, 월 예상 비용 —
`docs/AZURE_DEPLOYMENT.md`와 RUNBOOK Delivery State에 날짜와 함께 기록한다. 측정 못한 항목은 "미검증"으로
남긴다 (규칙: 측정 안 된 수를 지우거나 희망으로 채우지 않는다).

## 8. 첫 배포 실측 (2026-11-23 — 검토 절차와 실제가 어디서 갈렸는지)

- **빌드**: `az acr build`(클라우드 빌드 — 로컬 docker 불필요) 2회 모두 **2분 14~16초**. 태그는
  `0.5.0-uboot`, `/app/evidence` 픽스 후 `0.5.0-uboot2`.
- **리소스 프로바이더**: 이 구독("Azure in Open")은 `Microsoft.ContainerRegistry`, `Microsoft.App`,
  `Microsoft.Storage`, `Microsoft.Network`, `Microsoft.OperationalInsights`가 모두 미등록이었다 —
  `az provider register` 후 각각 Registered 대기(수 분).
- **ACR 인증의 갈림길**: `--registry-username/--registry-password`는 az가 ACR 로그인 서버 문자열에서 시크릿
  이름을 자동 생성하는데(`btsbomacr1123azurecrio-`) 말단 `-`라 `ContainerAppInvalidSecretName`으로 실패한다.
  통과한 경로는 **YAML `configuration.registries` + 명시적 `passwordSecretRef`**(deploy/azure/containerapp.yaml
  구조). 대안으로 user-assigned 관리 ID + `AcrPull`이 있으나, 이 구독 CLI에서는 스코프형 role assignment 호출이
  `MissingSubscription` 오류로 깨져 있어(az rest 포함) YAML이 유일하게 통과했다.
- **볼륨 UID 미검증 항목의 답**: **문제 없었다.** Azure Files 마운트(storage key 인증)에서 UID 10001의 쓰기가
  그대로 성공 — 첫 부팅 `/readyz` 200, `failed: []`.
- **진짜 배포 버그(코드 수정 1건)**: LLM 호출 장부가 `<root>/evidence/.llm_ledger.json`(/app/evidence)로
  쓰이는데 컨테이너의 /app은 UID 10001에 읽기 전용 → **모든 챗 턴이 `llm._bump` PermissionError로 503**.
  Dockerfile에 `RUN mkdir -p /app/evidence && chown 10001:10001` 한 줄로 수선(장부는 일일 카운터라 컨테이너
  임시 저장으로 충분; 영속 상태는 전부 evidence 볼륨에 있다).
- **evidence 시딩**: Azure Files의 `evidence/`(subPath)에 u-boot·django-nV 프로젝트 기록 10파일 + 시딩된 OSV
  DB(bts_sbom_osv_local.db, PyPI 153 레코드)를 업로드. `az storage directory create`는 --path를 지원하지
  않으므로(이 az 버전) 디렉터리는 `--name "evidence/u-boot"` 전체경로로 만든다. 컨테이너 env에
  `BTS_SBOM_OSV_DB_PATH=/tmp/evidence/bts_sbom_osv_local.db`를 추가해 nl2sql이 영속 DB를 보게 한다.
- **라이브 검증**: /healthz 200(0.3s), /readyz 200, 페이지 렌더, SSE 챗(u-boot 개요 — LLM 라우팅·한국어),
  nl2sql(success, PyPI 153), **원격 스캔**(OWASP/NodeGoat GitHub URL → 1,091 구성요소 / 311 취약점 / 라이선스
  98.5% 해결, ~355초 at 0.5 vCPU, scale 0→1 재할당 중 일시 503은 정상 동작).
- **2주 운영·철수**: 과제 검토 기간(약 2주) 후 `az group delete --name bts-sbom-rg --yes`로 rg·환경·ACR·
  Files 전부 제거(잔여 과금 0). 그 전까지 월 예상 ≈ $3 + 스캔 사용분(스케일 0). 인증은 데모 목적으로
  Easy Auth 미설정(무인증 external) — 앱 자체 일일 예산 80이 제3자 LLM 남용의 상한이며, 이 편차는 RUNBOOK
  Delivery State에 기록되어 있다.
