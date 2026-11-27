# Azure Identity 최적화 (Managed Identity 적용 + Workload Identity 방향, 2026-11-28)

서비스 방향: 단일 레플리카 SCA/SBOM 서비스 — **외부 자격증명을 설정 파일에서 제거하는 것이 1순위**이고,
사용자 위임(Workload Identity 연합)은 Key Vault 연계 시점에 도입한다.

## 1. 적용 완료: ACR pull = 시스템 할당 Managed Identity (리비전 bts-sbom--0000008 라이브)

| 단계 | 명령/결과 |
|---|---|
| 시스템 할당 MI | `az containerapp identity assign --system` → principal `a597a9ae-…-3481` |
| AcrPull 권한 | `az role assignment create --role acrpull --scope <acr-id>` → AcrPull 1건 확인 |
| 레지스트리 전환 | `az containerapp registry set --identity system` → `passwordSecretRef=False, username=False` |
| 풀 검증 | env 터치로 신규 리비전 0000008 → **Healthy / 100% 트래픽** (MI로 이미지 풀 실측) |
| 자격증명 제거 | `az containerapp secret remove --secret-names acr-password` + `az acr update --admin-enabled false` (**관리자 계정 OFF**) |
| 라이브 스모크 | healthz 200 · readyz 200 (토큰) · /api/cra/u-boot 200 |

**효과**: 앱 설정·시크릿·빌드 문서 어디에도 ACR 비밀번호가 없어짐(이전: ACA secret `acr-password` + 관리자 계정).
리비전 내보내기(`containerapp.applied.yaml` 스타일)에서 registry 항목이 `identity: system`만 남는다.
README §12의 "YAML registries + passwordSecretRef 우회" 절차는 폐기 — 재배포 시 `--identity system` 한 줄.

## 2. 방향: Workload Identity (연합 자격증명) — Key Vault 연계 시점에

| 항목 | 설계 |
|---|---|
| 대상 | LLM 키(`azure-api-key` 등 ACA secret 4종)·외부 API 키를 **Key Vault 참조**로 이관할 때 |
| 구성 | 사용자 할당 MI `bts-sbom-wi` + `az containerapp env … workload-identity profile`(환경 단위 활성화) + 연합 자격증명(issuer `https://*.azurecontainerapps.io`, subject `system:serviceaccount:…:bts-sbom`) |
| 앱 접근 | KV RBAC `Key Vault Secrets User`를 bts-sbom-wi에 부여, 앱은 `AZURE_KEYVAULT_RESOURCE_ENDPOINT` + `credential`로 SDK 획득 |
| 지금 안 하는 이유 | stdlib 전용 런타임에는 Azure SDK가 없어 KV 조회를 표준 라이브러리만으로 해야 함(토큰 REST 핸드셰이크 필요) — Key Vault 참조는 플랫폼이 대신 주입하는 방식이라 앱 코드 변경 0이지만 env 단위 활성화가 이 az 버전에서 미확인. 다음 배포 창에서 `az containerapp env update --help` 확인 후 적용 |
| 대안(즉시 가능) | ACA secret은 플랫폼 암호화 저장이며 내보내기에서 마스킹 검증됨(AC-1200대) — KV 이관의 보안 이득은 "사람이 KV에서 로테이션"이므로 키 로테이션 주기가 생길 때 |

## 3. 남은 권한 표면 (정직)

- 구독 레벨 az 세션(사람)이 배포·롤백·리비전 작업을 수행 — 앱 런타임에는 ACR pull 이외의 Azure 권한이 없다(최소 권한 충족).
- LLM 키 4종·액세스 토큰은 여전히 ACA secret(플랫폼 암호화) — §2 계획대로 KV 이관 예정.
- Easy Auth(AAD) 미적용 — 사용자 계정이 없는 단일 토큰 게이트(README §12 결정 유지).
