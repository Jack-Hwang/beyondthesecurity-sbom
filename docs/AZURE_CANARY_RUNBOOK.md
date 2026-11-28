# Azure 카나리 배포 런북 (C82 — 롤백 트리거의 기계 판정)

강의 5-4: "롤백 트리거는 감이 아니라 런북의 수치 조건으로 — 예: 근거성·오류율이 기준선을 벗어남."
이 런북의 트리거는 `bts_sbom_app/canary.py:evaluate()`가 코드로 판정한다. 판정은 세 값뿐이다:
`promote` / `rollback` / `hold`(데이터가 없어 판정 불능 — 조용한 통과가 아니다).

## Delivery State

- blue: 현행 리비전 (100%)
- green: 신규 리비전 (0%, 카나리 대기)

## Rollback Trigger (기계 판정 — 수치 조건)

기준선 캡(운영자가 아래 값을 기록한다):

| 지표 | 캡 | 방향 |
|---|---|---|
| grounding_f | ≥ 0.90 (TOP-10 A1 게이트와 같은 값) | min |
| error_rate | ≤ 0.02 | max |
| p95_ms | ≤ 800 | max |

```python
from bts_sbom_app import canary
decision, reasons = canary.evaluate(
    baseline={"grounding_f": 0.90, "error_rate": 0.02, "p95_ms": 800},
    current={"grounding_f": 0.83, "error_rate": 0.01, "p95_ms": 640})
# decision == "rollback", reasons 에 어느 지표가(실측값과 캡 값을 대조해) 깼는지 이름으로 나온다
```

- 캡이 기록 안 된 지표는 그 실행의 게이트가 아니다 — 사유로 그렇게 이름이 나온다 (안 쓴 게이트가 통과한 게 아니다).
- 현재 측정이 없는 지표는 `hold` — 조용한 통과 없음(D1 §20 조용한 실패 규칙).

## 절차

1. `canary.plan("blue", "green", weight=10)` 이 만드는 **명령 텍스트**를 운영자가 검토하고 실행한다 (이 모듈은 실행하지 않는다).
2. 10% → 지표 수집 → `evaluate()` → `promote`면 50% → 100%. `rollback`이면 롤백 명령(비율 복귀 — 배포 삭제가 아니다) 실행.
3. 실행·판정·조치는 `05_operate` delivery 상태에 기록한다. p95 벤치 회귀는 `bts_sbom_app/bench_gate.py:gate()`가 bench 이력으로 별도 판정한다(C59).
