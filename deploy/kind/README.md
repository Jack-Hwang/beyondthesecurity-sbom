# bts-sbom-app on kind — 산출만 (G1, brief 5)

**상태: 산출만, 미배포 (2026-11-22).** 이 호스트에 `kind` 바이너리가 없어 클러스터를 만들지 못했고,
그래서 매니페스트가 실제 클러스터에 적용된 적도 없다. 검증된 것: `kubectl apply --dry-run=client
--validate=false -f deploy/kind/bts-sbom.yaml`가 4개 문서(namespace/pvc/deployment/service)를 전부
파싱 (EXIT 0) — 정적 테스트 `tests/bts_sbom_app/test_kind_manifests.py`가 이 규칙들을 고정한다.
kind를 설치해 적용하는 순간 이 README의 "미배포" 문장은 실측으로 바뀌어야 한다.

## 파일

| 파일 | 내용 |
|---|---|
| `bts-sbom.yaml` | Namespace + evidence PVC(2Gi) + Deployment(replicas 1, Recreate) + Service(ClusterIP) |
| `kind-config.yaml` | kind 1노드 클러스터 설정 (컨트롤플레인 하나가 전부) |

## 설계 결정 (그 이유까지 기록)

- **replicas 1 + Recreate 전략**: 이 제품의 유일한 공유 상태는 evidence 볼륨이고, 프로세스는 단일 프로세스
  전제(docs/RUNBOOK.md 스코프). 롤링 업데이트로 두 파드가 같은 PVC(RWO)를 붙이려 하면 실패한다 — 실패를
  막는 것이 아니라 애초에 그 배치를 하지 않는다.
- **readiness `/readyz`, liveness `/healthz`**: `/readyz`는 evidence 쓰기·코어 import·지식 코퍼스를 실제로
  검사하고, `/healthz`는 검사 없이 응답한다. 프로세스 살아있음은 liveness, 서빙 가능은 readiness — 역할을
  바꿔 쓰면 evidence 볼륨이 붙지 않은 파드가 트래픽을 받는다.
- **ClusterIP 고정, NodePort/LoadBalancer 금지**: 이 서비스는 무인증이다. 노출 축을 늘리는 순간 리버스
  프록시 + 인증이 전제가 되고, 그 시점에 런북과 매니페스트는 재작성 대상(패치 아님).
- **비루트 UID 10001**: Dockerfile의 `USER 10001`과 같은 숫자 ID(`/etc/passwd` 엔트리 불필요).
  readiness가 evidence 폴더 쓰기를 검사하므로 PVC는 이 UID가 쓸 수 있어야 한다 — kind의 local-path
  프로비저너는 마운트를 root:root로 만들 수 있어, 적용 시 `fsGroup: 10001`이 필요한지 **적용 후 실측으로
  확인**할 것(미배포라 미검증 항목).
- **이미지 태그 `bts-sbom-app:gate`**: `scripts/supply_chain_gate.py`가 만든 실측 통과 이미지.
  `:latest` 금지는 Dockerfile 정책과 동일. 적용 전 `kind load docker-image bts-sbom-app:gate --name bts-sbom`.

## 적용 절차 (kind 설치 후)

```sh
kind create cluster --config deploy/kind/kind-config.yaml
kind load docker-image bts-sbom-app:gate --name bts-sbom
kubectl apply -f deploy/kind/bts-sbom.yaml
kubectl -n bts-sbom rollout status deploy/bts-sbom-app        # readiness 통과 대기
kubectl -n bts-sbom port-forward svc/bts-sbom-app 8800:8800   # 무인증: 로컬 포트로만 노출
curl -s http://127.0.0.1:8800/readyz
```

## 롤백

kind 안의 롤백도 단일 파드 교체다: 이전 이미지 태그로 `kubectl -n bts-sbom set image deploy/bts-sbom-app
app=<이전태그>` 후 readiness 확인 — 트리거와 판정은 `docs/RUNBOOK.md` Rollback 절과 동일(이 매니페스트는
트리거를 새로 만들지 않는다). PVC 안의 evidence는 파드 재시작에 유지된다.
