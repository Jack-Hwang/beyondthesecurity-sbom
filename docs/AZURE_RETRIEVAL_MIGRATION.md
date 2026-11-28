# Azure 운영 환경 전환 마이그레이션 설계 (2026-11-28 실측판)

- 상태: **설계 확정 + 핵심 경로 실물 검증 완료** (검증은 이 문서 §4의 실측 그대로 — 미측정 항목은 "설계치"로 표기)
- 서비스 방향: 단일 레플리카 SCA/SBOM 서비스(stdlib 전용 런타임)가 Azure 운영 환경에서 검색·벡터·그래프를 운영하기 위한 최소 인프라 확정
- ID 전략 선행 문서: docs/AZURE_IDENTITY.md (ACR pull = 시스템 할당 MI 이미 라이브, 리비전 0000008에서 실측)

## 1. 마이그레이션 결정 (사용자 확정 방향)

| # | From | To | 이유 |
|---|---|---|---|
| 1 | Elasticsearch 9.5.6 + nori (자체 호스팅) | **Azure AI Search 하이브리드** | ES+Qdrant 2개 자체호스팅 → 1개 관리형으로 통합. BM25(한글 분석기)+벡터+RRF 융합이 한 서비스 안에 있다 |
| 2 | Qdrant 1.20.1 (자체 호스팅) | **Azure AI Search 벡터 필드** | HNSW 인덱스·필터·`@search.score`까지 동일 기능을 위 표의 인덱스 안에서 수행 — 별도 벡터 DB 소멸 |
| 3 | Neo4j community (자체 호스팅) | **PostgreSQL Flexible Server + Apache AGE** | 컴포넌트↔어드바이저리 그래프(영향 추적)를 PG 1개에 통합. Azure 허용목록에 AGE 존재 **실물 확인**(§4) |

## 2. 보안: Managed Identity · Workload Identity 최적화

### 2.1 지금 (라이브 실측 완료)
- Container Apps 앱 `bts-sbom`: **시스템 할당 MI**(`principalId a597a9ae-…-3481`).
- ACR pull: 레지스트리 `identity: system`, ACR 관리자 계정 **OFF**, `acr-password` 시크릿 제거 — 이미지 풀을 MI로 실측(리비전 0000008, Healthy/100%).
- 앱 런타임의 Azure 권한은 ACR pull뿐(최소 권한). LLM 키 4종·액세스 토큰은 ACA secret(플랫폼 암호화).

### 2.2 마이그레이션 리소스의 ID 부착 설계 (키·연결문자열 0원칙)
| 리소스 | 인증 | 앱이 받는 RBAC 역할 |
|---|---|---|
| Azure AI Search | **Entra ID 토큰(데이터 플레인 RBAC)** — admin/query key 미사용 | `Search Index Data Reader`(조회), 색인 주입 배치 잡에는 `Search Index Data Contributor`(MI에 부여) |
| PostgreSQL Flexible (AGE) | **Microsoft Entra 인증**(앱 MI를 PG 사용자로 생성, 토큰으로 접속) — 비밀번호 인증 금지 | PG 측 `az_runtime` 스키마 접근(최소) |
| Key Vault (WI 도입 시점) | 사용자 할당 MI `bts-sbom-wi` + **Workload Identity 연합**(ACA OIDC issuer ↔ subject `system:serviceaccount:…:bts-sbom`) | `Key Vault Secrets User` |

- **Workload Identity**: 연합 자격증명은 Key Vault 연계 시점(키 로테이션 주기 발생 시)에 활성화 — docs/AZURE_IDENTITY.md §2 설계 유지. 이번 검증에서 환경 `bts-sbom-env`의 응답에 WI 프로필 issuer가 노출되지 않은 점을 확인했고, 이는 "활성화는 다음 배포 창에서 확인" 계획의 근거가 된다.
- 원칙: 앱 설정·시크릿·이 문서 어디에도 **비밀번호·연결문자열·admin key가 생기지 않는다** — Entra 토큰(30~60분 수명)만 쓴다.

### 2.3 설정 절차 (실제 이관 시 순서)
1. `az search create`(Basic 권장, Free는 용량 50MB 한정) → AI Search 데이터 플레인 RBAC: `Search Service Contributor`+`Search Index Data Contributor`를 앱 MI에 부여(admin key 발행 불요).
2. PG Flexible: `--auth-type AAD` 구성, `az postgres flexible-server ad-admin create`로 앱 MI를 Entra 관리자/사용자로 등록, AGE를 `azure.extensions` 허용목록에 추가(§4 실측 절차).
3. 앱 코드: stdlib urllib로 Entra 토큰 획득(MI 엔드포인트 `IDENTITY_ENDPOINT`/ACA WI `AZURE_FEDERATED_TOKEN_FILE` 2계열) — env로 계열 선택.
4. 리비전 배포 → `BTS_SBOM_CHAT_ACTIONS`·토큰 게이트는 기존 운영 그대로.

## 3. 검색 서비스 대체 설계 (1·2번)

- **인덱스**: 문서 단위 = 도구 결과·증거 청크(제목/본문/kind/임베딩). 본문 필드 `analyzer: ko.lucene`, 벡터 필드 HNSW 프로필 — §4 실측으로 인덱스 스키마 그대로 검증됨.
- **하이브리드 질의**: `search`(텍스트) + `vectorQueries`(kNN) 동시 전송 → 서비스가 RRF 융합(실측 §4: 융합 점수 0.0331 동률로 재정렬 확인).
- **필터**: `kind eq 'deploy'` 등 SBOM 패싯 필터 실측 통과.
- **임베딩 원천 (열린 결정)**: Azure OpenAI text-embedding 계열(rg-bts-openai에 배포 필요) 또는 stdlib 해시 임베딩(비의미·역참조 전용). 이번 실측은 합성 8차원 벡터로 **역학만** 검증했다 — 품질은 임베딩 원천 확정 후 재측정한다.
- **정직한 갭 (실측 발견)**: AI Search `ko.lucene` 분석기의 한글 토큰은 **2음절 바이그램**(`['취약','약점','점을',…]`) — ES nori의 형태소 토큰과 다르다. 질의어도 동일하게 쪼개지므로 lexical 매칭은 동작하지만(실측: "취약점"→d1 4.07점), 형태소 정확도(조사·어미 제거)는 nori가 우위. 완화: semantic ranker(과금 검토)·커스텀 분석기 검토·질의어 사전 정규화 — 전환 시 검색 품질 A/B를 명시 게이트로 요구한다.
- **용량**: Free SKU(50MB·3인덱스)는 실측용. 운영은 Basic(문서 수·임베딩 차원에 비례) — 구체 수치는 청크 규모 확정 후.

## 4. 실물 검증 결과 (2026-11-28, 리소스는 검증 후 전부 철수)

| 검증 | 방법 | 결과 |
|---|---|---|
| AGE 그래프 경로 (로컬) | docker `apache/age` (AGE 1.8.0 / PostgreSQL 18.6) | `create_graph`·Cypher CREATE/MATCH(Component→Advisory) 성공 — 설계 쿼리 경로 유효 |
| **Azure PG AGE 허용목록** | Flexible Server 실물 생성(koreacentral, PG16, D2ds_v4) 후 `azure.extensions` 허용목록 조회 | **AGE 존재 확인** (78개 확장, `…standardizer_data_us, age, amcheck…`) |
| **Azure PG AGE 실가동** | 허용목록+`shared_preload_libraries=age`+재시작 → **새 데이터베이스**에 CREATE EXTENSION → `create_graph`·Cypher CREATE/MATCH | **성공** (MATCH가 `requests`/`CVE-2024-35195` 반환). 주의: 구 DB에서의 `LOAD 'age'`는 플랫폼 게이트(`access to library "age" is not allowed`)에 막힌다 — **새 DB 설치 경로가 Azure의 동작 경로** |
| **AI Search 한글 분석기** | Analyze API `ko.lucene` | 200, 바이그램 토큰 실측 — **nori 패리티 갭 확인**(§3 완화 항목) |
| **AI Search 벡터** | HNSW 프로필 인덱스 + kNN 쿼리 | 200, 코사인 점수 d1 0.9997 / d2 0.9986 / d3 0.5606 (유사 순위 정확) |
| **AI Search 하이브리드** | text+vector 동시 쿼리 | 200, RRF 융합 재정렬 실측(d1·d2 0.0331) |
| **AI Search 필터** | `kind eq 'deploy'` | 200, deploy 1건만 반환 |
| ID 포스트처리 | 라이브 ACA 상태 조회 | SystemAssigned MI·ACR `identity: system`(MI 풀)·토큰 게이트 401 유지 — §2.1 재확인 |

환경 함정 기록: PG 생성 시 `Microsoft.DBforPostgreSQL` 프로바이더 미등록 → `az provider register` 후 재시도(첫 배포 때와 동일한 함정), koreacentral에서 Burstable B1ms/B2s는 SkuNotAvailable → **D2ds_v4**가 동작, AI Search 2024-07-01 API에서 벡터 프로필 키는 `algorithm`(algorithmConfigurationName 아님), 알고리즘 파라미터(m·efConstruction)는 이 API 버전에서 미수용(기본값 사용).

## 5. 단계별 이행 (각 단계 독립 롤백)

1. **준비**: AI Search Basic 생성 + RBAC 부여(§2.2) — 앱 변경 0.
2. **색인 배치**: 기존 증거(evidence runs·book KB 청크)를 문서로 색인(임베딩 원천 확정 후) — 기존 경로 영향 0.
3. **이중 조회 기간**: 챗 도구가 로컬 인덱스와 AI Search 하이브리드를 **나란히** 수행해 실측 비교(회수율·정확도는 사용자 판정으로) — 이중 경로 유지.
4. **전환**: AI Search를 1차로 승격, 로컬 인덱스는 폴백으로 보존.
5. **그래프**: PG Flexible+AGE 생성(§4 실측 절차) → 증거에서 Component→Advisory 그래프 구축 → 영향 추적 쿼리 서빙. **Azure 라이브 AGE LOAD 게이트 건이 해소될 때까지는 "평가 단계"로 유지**(self-hosted AGE나 로컬 경로가 대안).
6. **ES·Qdrant·Neo4j 자체호스팅 종료**(해당 자원이 실제 운영되기 전이므로 지금은 설계만).

## 6. 정직 한계

- AI Search 실측은 **역학**(분석기·HNSW·하이브리드 융합·필터)만 — 검색 품질은 임베딩 원천 확정 후 재측정.
- Azure PG AGE의 LOAD 게이트 건: Microsoft 지원/업데이트에 따라 해소 가능 — 재검증 절차는 §4 표와 동일(서버 생성→허용목록→새 DB 설치).
- WI 연합 활성화는 다음 배포 창 과제(docs/AZURE_IDENTITY.md §2 계획 유지).
- ES 9.5.6·Qdrant 1.20.1·Neo4j community는 실제 운영된 적이 없는 "학습/설계 기점" 버전이므로 데이터 이관 부담은 0 — 이 문서의 이행은 첫 운영 인프라 배치다.
