# COST — 비용 안전 (과제 공통 수칙)

이 문서는 추정(estimate)이지 청구 금액이 아니다. 모든 Azure 가격은 이 저장소에 지어 넣지 않는다 —
`docs/cost_assumptions.json` 의 가격 필드는 사용자가 Azure 가격 계산기로 채운다(채워질 때까지 null).

## 추정 수식

```
월 비용 ≈ 플랜 시간당 가격 × 730시간 × 인스턴스 수      (App Service, capacity 1)
        + 저장소 GB × 저장소 GB당 월 가격              (증거 폴더, 파일/디스크 등급)
        + 로그 GB × 로그 GB당 가격                   (Log Analytics: 요청마다 JSON 한 줄)
        + LLM 호출 수/일 × 30 × 호출당 비용            (EXAONE 은 Azure 외부 API — 별도 항목)
        + egress GB × egress GB당 가격
```

실행: `python -I -X utf8 tools/cost_estimate.py` — 입력이 채워지지 않으면 항목이 "unknown"으로 남고
합계는 "INCOMPLETE"로 표시된다(추측한 숫자를 보여 주지 않는다). 출력 항상 "estimate — not a billed amount"를 명시.

## 입력 표 (전부 가정)

| 입력 | 기본값(가정) | 단위 | 비고 |
|---|---|---|---|
| plan_hours_per_month | 730 | hours | 항상 켜진 단일 인스턴스 |
| instances | 1 | count | capacity 1, 자동 확장 없음(ADR-0016/0019) |
| plan_price_per_hour | **null** | USD/hour | Azure 가격 계산기에서 채움 |
| storage_gb | 5 | GB | 증거 폴더 증가 추정 |
| storage_price_per_gb_month | **null** | USD/GB-month | Azure 가격 계산기 |
| log_gb | 2 | GB | 요청 로그·진단 |
| log_price_per_gb | **null** | USD/GB | Azure 가격 계산기 |
| llm_calls_per_day | 80 | calls/day | 로컬 일일 한도 기본값과 동일 |
| llm_cost_per_call | **null** | USD/call | EXAONE 요금 — Azure 외부 |
| bandwidth_gb | 1 | GB | egress 추정 |
| bandwidth_price_per_gb | **null** | USD/GB | Azure 가격 계산기 |

## 예산 경보 50 / 80 / 100%

`infra/main.bicep` 의 월 예산(Consumption Budget)은 3단계 알림을 선언한다:

- **50%**: 진행 알림 — 이번 달 지출이 예산의 절반. 태그(team/week/owner)로 원인을 분류한다.
- **80%**: 경고 — 더 이상 데모 확장을 시작하지 않는다. 필요하면 리소스를 정리한다.
- **100%**: 한도 도달 — 즉시 정리 절차를 실행하고 남은 과금을 확인한다.

## 정리 절차 (데모 종료 시)

1. `azd down --purge` — azd 가 만든 리소스 그룹을 삭제하고 soft-delete 된 Key Vault 도 영구 삭제한다.
2. 구독에 남은 리소스 확인: `az resource list --query "[].{name:name, type:type, tags:tags}" -o table`
   태그 없는 리소스가 보이면 이 저장소 소유가 아닐 수 있으니 지우기 전에 확인한다.
3. 예산·경보는 리소스 삭제로 함께 사라진다. 구독 단위 남은 과금(예: Log Analytics 보존)은
   `az costmanagement query` 또는 포털 Cost Management 에서 확인한다.
4. 컨테이너 레지스트리에 남은 이미지(과금 대상)는 `az acr repository delete` 로 정리한다.

## 비용 안전 수칙 체크리스트

- [ ] 모든 리소스에 태그 3종(team, week, owner) — 태그 없으면 정책이 거부
- [ ] 예산 경보 50/80/100% 선언
- [ ] 가격은 저장소에 지어 넣지 않는다(가격 필드는 null, 사용자가 채움)
- [ ] 차시 종료 시 `azd down --purge` + 남은 리소스 확인
- [ ] 추정 출력에는 항상 "estimate — not a billed amount" 가 붙는다
