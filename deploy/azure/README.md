# Azure 배포 절차 (Container Apps) — bts-sbom-app

상태: **재배포 완료 (2026-11-27)** — 앱 `bts-sbom` /
https://bts-sbom.wittyforest-2c8fae00.koreacentral.azurecontainerapps.io (액세스 토큰 게이트 ON). 첫 배포(2026-11-23, 철수됨)의 주소는
yellowdesert-36032bc5 였다. 아래 절차는 검토 시점의 계획이고, 실제 배포에서 달라진 점은 문서 끝의 "첫 배포 실측"(§11)과 "두 번째 배포 실측"(§12)을 볼 것.
Git Bash 에서는 `export MSYS_NO_PATHCONV=1` 을 먼저 걸 것(`/tmp/...` 인자가 Windows 경로로 바뀐다). 배포 검토의 근거와 제약은 `docs/AZURE_DEPLOYMENT.md`를 먼저 읽을 것 —
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

가장 간단한 길은 앱 자체 **액세스 토큰 게이트**다: `python -m bts_sbom_app access-token` 으로 만든 값을 ACA secret `access-token` 으로 넣고 env `BTS_SBOM_ACCESS_TOKEN` 에 `secretRef` 로 연결한다
(템플릿에 이미 있다). `/healthz`·`/readyz` 외 모든 경로가 Basic 비밀번호(브라우저가 한 번 묻는다) / Bearer / `X-BTS-Token` 을 요구하고 토큰 없이는 401 이다. 사용자 계정이 필요하면 아래 Easy Auth.

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

## 9. 거버넌스 태그 · 예산 경보 (team/week/owner, 50/80/100%)

강의(과제4/5_가이드 §09 비용 안전 수칙): 이 배포는 **태그 3종**(team/week/owner)을 반드시 달고,
**예산 경보 50/80/100%**를 설정한다. 이 저장소는 stdlib-only이므로 실제 `az consumption budget create`
호출은 만들지 않고(비용이 발생하는 외부 호출), 그 대신 정확한 명령을 **dry-run으로만** 출력하는
스크립트를 두고, 사람이 검토 후 직접 실행한다.

### 9.1 태그

`deploy/azure/containerapp.yaml`의 최상위 `tags:` 블록이 정의를 가진다(`team`/`week`/`owner`,
세 키 모두 비어있으면 안 됨). `week`는 매 배포(redeploy)마다 그 시점의 ISO 주차로 갱신하고,
`owner`는 현재 on-call 담당자의 연락처로 갱신한다. 정적 테스트
(`tests/bts_sbom_app/test_azure_redeploy.py`)가 이 세 키가 항상 존재하는지만 확인한다 — 값은
사람이 매 배포마다 직접 채운다(az CLI에는 리소스 태그용 별도 플래그가 있다:
`az containerapp update --tags team=... week=... owner=...` 또는 `az resource tag`).

### 9.2 예산 경보 dry-run

```bash
python scripts/azure_budget.py --dry-run \
  --resource-group bts-sbom-rg --amount 80 \
  --team bts-sbom --week 2026-W48 --owner <on-call 연락처> \
  --contact-email <예산 경보 수신 주소>
```

출력은 (1) 비실행 주석(태그 안내 + 알림 임계치 안내)과 (2) **실행 가능한 한 줄**
(`az consumption budget create`, `--resource-group`/`--budget-name`/`--amount`/`--time-grain`/
`--start-date`/`--end-date`/`--category`만 사용)로 나뉜다. 이 플래그 집합은 설치된 az CLI
(`az consumption budget create --help`, azure-cli 2.93.0 기준)로 직접 검증한 것이며,
`scripts/azure_budget.py`의 `AZ_CONSUMPTION_BUDGET_CREATE_FLAGS`에 화이트리스트로 고정되어 있어
테스트(`tests/bts_sbom_app/test_azure_redeploy.py`)가 검증되지 않은 플래그가 끼어들는 것을 막는다.

**중요:** 이 az CLI 버전의 `consumption budget create`에는 `--notifications`도 `--tags`도 없다
(`az costmanagement`는 확장 설치가 필요해 이 스크립트가 의존하지 않는다). 그래서 50/80/100% 알림
임계치와 team/week/owner 태그는 실행 줄에 들어가지 않고, 출력의 주석(`#`로 시작, 쉘에서 실행되지 않는
단순 텍스트)으로만 안내된다 — **예산 생성 후 사람이 직접** Azure Portal(Cost Management + Billing >
Budgets > <budget-name> > Edit > Alert conditions)에서 알림을 추가하고, 태그는
`az containerapp update --tags team=... week=... owner=...` 또는 `az resource tag`로 Container
App 리소스에 적용한다(9.1절과 동일).

**이 스크립트는 `az`를 실행하는 코드 경로가 아예 없다** — `--dry-run`을 생략하면
아무것도 출력하지 않고 종료코드 2로 종료한다(실수로 예산이 생기는 것을 막는 안전장치).
출력된 실행 줄을 검토한 뒤 사람이 복사해 직접 실행하고, 주석으로 안내된 후속
단계(알림/태그)도 빠짐없이 직접 수행한다.

## 10. 배포 후 스모크 테스트 (scripts/smoke_deployed.py)

재배포(redeploy) 직후 매번 손으로 확인하던 4가지(healthz, readyz, SSE 첫 바이트, 인증 게이트)를
한 명령으로 묶은 stdlib-only 스크립트. urllib만 쓰고 네트워크가 없는 테스트는 로컬 인프로세스
서버(`tests/bts_sbom_app/test_access_gate.py`와 같은 패턴)로 대체한다
(`tests/bts_sbom_app/test_azure_redeploy.py`).

```bash
# BTS_SBOM_ACCESS_TOKEN이 설정된 배포에는 --token 또는 동명 환경변수로 토큰을 넘긴다
python scripts/smoke_deployed.py https://bts-sbom.<env>.azurecontainerapps.io --token <token>
```

PASS/FAIL 표를 출력하고, 하나라도 실패하면 종료코드 1로 끝낸다(CI/운영에서 그대로 게이트로 쓸 수
있다). 토큰은 출력에 나타나지 않는다(상태코드만).

## 11. 첫 배포 실측 (2026-11-23 — 검토 절차와 실제가 어디서 갈렸는지)

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

## 12. 두 번째 배포 실측 (2026-11-27 - 액세스 토큰 게이트 + 소스 경계 + 로컬 OSV 복사)

- **리소스** (구독 "Azure in Open", koreacentral, 모든 리소스에 태그 team=bts-sbom / week=2026-W48 / owner=bts-sbom-operator): 리소스 그룹 `bts-sbom-rg`, ACR `btsbomacr1126`(Basic),
  Log Analytics `btsbom-logs`, Container Apps 환경 `bts-sbom-env`, Storage `btsbomstg1127`(Azure Files 공유 `evidence` 2Gi, ReadWrite), 앱 **`bts-sbom`** ->
  https://bts-sbom.wittyforest-2c8fae00.koreacentral.azurecontainerapps.io . LLM 은 기존 `rg-bts-openai` 의 `bts-sbom-openai-9f2c` / `gpt-5-mini` (그대로 두었고 이 그룹 삭제에 포함되지 않는다).
- **빌드**: `.dockerignore` 허용 목록(AC-1200)으로 컨텍스트 **1.925 MiB** 만 올라갔다(허용 목록이 없으면 `az acr build .` 는 저장된 LLM 키가 든 `evidence/` 와 4 GB `_attic/` 까지 올린다). 이미지
  `btsbomacr1126.azurecr.io/bts-sbom-app:0.5.0-final1127b`. 두 번 빌드(`...final1127`, `...final1127b`).
- **선언**: `python scripts/azure_render_app.py deploy/azure/containerapp.yaml <out>` 가 템플릿의 자리표시자를 환경변수로 채운다(AC-1224). 비밀값이 든 출력 파일은 `az containerapp create --yaml` 직후 삭제한다.
  az 는 YAML 을 Windows ANSI 코드페이지로 읽어 한글 주석이 있으면 `'cp949' codec can't decode` 로 실패하므로 렌더 결과는 ASCII 만 담는다. 스케일 **0->1**(데모 비용 상한; 상시 1 로 고정하려면
  `az containerapp update --min-replicas 1`), 0.5 vCPU / 1 Gi, 프로브 3종(Startup/Liveness/Readiness).
- **인증**: `BTS_SBOM_ACCESS_TOKEN`(ACA secret `access-token`)을 켰다. 토큰 없이 `/` 401, `/healthz`·`/readyz` 200. 토큰은 로컬 `C:\Users\Administrator\.bts-sbom\azure_access_token.txt` 에만 있고 레포·로그에
  없다(조회: `az containerapp secret show -n bts-sbom -g bts-sbom-rg --secret-name access-token`). Easy Auth(AAD)는 앱 등록이 필요해 하지 않았다 - 사용자 계정·권한 분리는 없다.
- **소스 경계**: `BTS_SBOM_ALLOWED_ROOTS=/srv/bts-sources`(이미지에 없는 폴더라 로컬 경로 소스는 전부 거부, git URL 만 가능). 라이브 확인: `/etc`, `C:/Windows`, `file:///etc`, `https://169.254.169.254/...`,
  `https://127.0.0.1/x.git` 5건 모두 400 거부.
- **라이브 검증**: `scripts/smoke_deployed.py` 4/4 PASS(healthz 125 ms, readyz 93 ms, 인증 게이트 401/200, SSE 첫 바이트 281 ms). 시드한 프로젝트 3개(NodeGoat, django-nV, u-boot)와 OSV DB 가 보인다
  (`/api/db/schema`: vulns 153 · pkg_map 108 · exact_cache 82). 에스컬레이션이 증거 볼륨에 기록된다. LLM 채팅(`gpt-5-mini`, 한국어, 인용 정확도 1.0, 12.2 s)과 NL2SQL(LLM 레인, 1회 시도 성공, 수정한
  `패키지별` 질의 포함). 원격 스캔: `pypa/sampleproject` 8 s, `anxolerd/dvpwa` 24 s(20 컴포넌트, 라이선스 100 %), **OWASP/NodeGoat 1,091 컴포넌트 / 311 취약점 / 라이선스 98.5 %** (아래 참조).
- **진짜 결함 1건(코드 수정)**: OSV DB 를 Azure Files(SMB) 위에 두고 스캐너가 캐시를 쓰자 `store_exact failed ...: database is locked` 가 건마다 락 타임아웃(5 s)을 기다려 **NodeGoat 스캔이 780 s**
  (이전 배포 355 s). SQLite 는 네트워크 공유 위의 동시 쓰기를 못 견딘다. 시작 시 시드(`BTS_SBOM_OSV_SEED_DB`, 공유 위의 읽기 전용 스냅샷)를 로컬 디스크(`BTS_SBOM_OSV_DB_PATH=/tmp/osvdb/...`)로 한 번 복사하게 했다
  (`server.seed_local_osv_db`, AC-1226~1227). 같은 스캔이 **96 s**, 락 오류 0, 결과 동일(1,091 / 311 / 98.5 %).
- **셸 함정**: Git Bash 는 `az` 의 `/tmp/...` 인자를 `C:/Users/.../Temp/...` 로 바꿔 보낸다(리비전 `0000001` 이 그렇게 잘못 배포됐다). `export MSYS_NO_PATHCONV=1` 을 걸고 다시 배포한 것이 리비전 `0000002`(현재 100 %).
- **적대적 점검(레드팀, 로컬 인스턴스에서만)**: 에이전트 3명(인증 게이트 / 한도·자원 / 소스 경계·SSRF)이 공격 48가지를 시도해 11건을 재현했고 반박 검증도 모두 통과했다. 전부 고쳤다
  (AC-1230~1240): ① 요청을 다 보내지 않고 멈춘 연결이 스레드를 무한정 붙잡음(slowloris, 게이트 **아래**에서 일어나 토큰이 소용없음) -> 연결 읽기 타임아웃 15 s + 동시 연결 상한 128(초과는 즉시 503),
  ② 채팅 한 턴마다 프롬프트 레지스트리 digest 로 패키지 85개를 다시 파싱(약 1 CPU 초) -> 패키지 파일 서명 기준 캐시 + 시작 시 예열, ③ `2130706433`·`0x7f000001`·`0177.0.0.1`·`127.1`·`localhost.` 같은 레거시 IPv4 표기가
  git/fetch SSRF 가드를 통과 -> 두 가드가 하나의 파서(`netaddr.py`)를 공유, ④ `file://호스트/경로` 의 검사 경로와 실행 경로가 다름 -> authority 가 있으면 거부, ⑤ DNS 리바인딩(검사 후 git 이 다시 해석) ->
  검사한 공개 주소를 `http.curloptResolve` 로 https 클론에 고정, ⑥ 실패한 자격증명에 속도 제한 없음 -> 호출자별 20회/분 초과 시 토큰 검사 없이 429, ⑦ X-Forwarded-For 위조 -> 운영자가
  `BTS_SBOM_TRUST_FORWARDED=1` 을 선언할 때만 신뢰, ⑧ 중첩 200,000단 JSON 이 RecursionError -> 400, ⑨ Server 헤더가 Python 버전 노출 -> `bts-sbom`.
- **라이브에서만 보인 결함(수정)**: Container Apps 인그레스는 `100.100.0.x`(공유 주소 공간 100.64.0.0/10)에서 접속하는데 `ipaddress.is_private` 가 이를 False 로 보아 X-Forwarded-For 를 신뢰하지 않았고, 모든 호출이
  인그레스 인스턴스 IP 로 묶였다 - 호출자별 속도 제한이 **라이브에서 한 번도 걸리지 않았다**(36회 호출 전부 200). 진단용 옵트인 헤더(`BTS_SBOM_DEBUG_CALLER=1`, 토큰 보유자에게만, 확인 후 제거)로
  `peer=100.100.0.64 xff=<실제 IP>` 를 확인하고 "공개 라우팅이 아닌 주소"로 판정을 넓혔다. 수정 후 라이브: 채팅 36회 중 200 x30 / 429 x6, 잘못된 토큰 25회 중 401 x20 / 429 x5(잠긴 호출자는 올바른 토큰도
  대기, 프로브는 영향 없음).
- **현재 리비전**: `bts-sbom--0000006`, 이미지 `0.5.0-final1127f`(빌드 6회). 같은 날 연결 거부 시 OS 가 보낸 RST 가 응답을 지우는 Windows 경합(`WinError 10053`, `test_oss_api` 의 간헐 실패)도 거부 응답 뒤 지연 종료(lingering close)로 잡았다.
- **정리 대상**: 라이브 검증으로 증거 볼륨에 생긴 `dvpwa`, `sampleproject` 기록과 시험 에스컬레이션 로그는 데모 데이터가 아니므로 삭제했다.
- **월 예상**(공개 단가 x 사용량, 견적 아님): ACA 스케일 0->1 은 사용 시간만 과금(하루 1 시간 가정 약 $3), ACR Basic 약 $5, Files 2 Gi 약 $0.4, Log Analytics 소량, LLM 토큰은 별도. 철수: `az group delete --name bts-sbom-rg --yes`
  (`rg-bts-openai` 는 남는다).
