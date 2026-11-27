# 패치 호환성 게이트 (AC-630~636)

**질문**: 취약점 패치로 올린 버전에서 *이 프로젝트가* 여전히 동작하는가? 이전에는 "메이저 버전이 바뀌면 high" 한 비트가
전부였고, 설치도 테스트도 하지 않았다. 이 게이트는 매니페스트를 고치기 **전에** 측정한다.

## 무엇을 측정하나 (정적, 오프라인 테스트 가능 — `bts_sbom_app/compat.py`)

| 축 | 방법 | 판정 근거 |
|---|---|---|
| 사용 API | 프로젝트 `.py`를 `ast`로 파싱: import, 속성 체인, **호출 지점의 위치/키워드 인자 모양**, 상속 | `toylib.fetch("u", 5, True)`처럼 실제 호출 |
| API 차이 | 현재/대상 릴리스의 wheel·sdist를 **메모리에서** 파싱(실행·임포트 없음) → 사용 심볼만 비교 | 제거, 이동(힌트), 새 시그니처가 거절하는 호출, 신규 deprecated, 제거된 메서드 이름 일치, 서브클래스 손실 |
| 핀 제약 | 대상의 `Requires-Dist` ↔ 프로젝트가 고정한 다른 패키지, 그리고 반대 방향 | pip 리졸버가 실패하는 조합. 같은 패치에서 둘을 함께 올리면 충돌 아님(핀을 패치 후 버전으로 겹쳐 계산) |

판정(플랜별): `compatible` · `partial`(검증된 비율 표시) · `review` · `breaking` · `unverified` · `not_direct`.
**증거가 얇으면 compatible이 아니다**: 오프라인, PyPI 외 생태계, 아카이브 없음, 동적 모듈(`__getattr__`), C 확장,
예산 초과는 모두 `unverified`/`partial`이며 **보류하지 않는다**(증거 없음은 파손의 증거가 아님).

## 동작 (CLI)

```powershell
bts-sbom-app patch <source>                       # 플랜 미리보기: 각 행에 Compat(측정) 표시, 아무것도 안 바뀜
bts-sbom-app patch <source> --approve --token <digest>            # 기본 --compat block
bts-sbom-app patch <source> --approve --compat warn               # 보고만, 보류 안 함 (리뷰가 breaking을 reject)
bts-sbom-app patch <source> --approve --compat-runtime            # + 프로젝트 자체 테스트 전/후 (옵트인)
```

* `block`(기본): **breaking인 플랜만 보류**하고 나머지는 적용한다. 승인 다이제스트는 모든 플랜에 대해 계산되므로
  보류는 승인된 변경보다 *작은* 변경일 뿐이다. 전부 보류되면 상태 `compat_held`, 파일은 0개 변경.
* 보류 사유는 결과 행(`status: held`)과 `compat.plans[].findings`에 **규칙·심볼·호출 위치**로 남는다.
  보류된 패키지는 그 호출부/핀을 고치기 전까지 취약한 채로 남는다 — 리뷰가 이를 `RV-COMPAT-HELD`로 적는다.

## 런타임 차등 (옵트인, `compat_runtime.py`)

시그니처가 같은데 동작이 바뀐 경우는 정적 분석으로 못 본다. `--compat-runtime`은 프로젝트의 테스트를 **원본 핀 / 패치 핀**에서
각각 돌려 *통과하던 테스트가 실패*하면 `regression` → 패치 전체를 되돌린다(`compat_runtime_reverted`).

안전 장치(이 기능은 스캔 대상 프로젝트의 코드를 실행한다 → 기본 꺼짐): 일회용 복사본(.git 제외)에서만 실행, `--only-binary=:all:`
(의존성의 `setup.py` 미실행), 테스트 프로세스에는 최소 환경변수만(토큰·프록시·인덱스 자격 없음), 모든 하위 프로세스에 타임아웃.
테스트가 없거나/요구 파일이 없거나/베이스라인 설치가 안 되면 `unverified` — 절대 ok가 아니다.

## 한계 (정직하게)

* **이 문서의 정적 레이어는 PyPI(Python 소스).** **C/C++ 라이브러리는 `compat_c.py`**(헤더 비교 + 컴파일러 차등, AC-637~644, docs/CLEANROOM_C_CPP.md)가 처리한다. npm/Maven/Go 등은 `unverified` + 기존 메이저 prior.
* 반환 객체의 메서드는 추적하지 않는다(타입 추론 없음): 패키지 네임스페이스에서 닿는 심볼만 판정한다.
* C 확장·동적 생성 모듈은 해석 불가 → `partial`/`unverified`로 계산.
* 시그니처 안쪽의 동작 변화는 정적 레이어가 못 본다 → 런타임 차등이 필요하다(옵트인).
* 런타임 차등은 패치 전체를 한 번에 판정한다(어느 패키지 탓인지 이분 탐색하지 않음).
* 보류된 업그레이드를 AI가 호출부 수정으로 풀어 주는 단계(어댑터/shim 생성 + 재검증)는 **아직 없다** — 다음 단계.

## 코드 지도

`compat.py`(사용 API → 표면 비교 → 핀 제약 → 보류 판정) · `compat_runtime.py`(venv 차등) · `patch.apply(hold=)` ·
`pipeline._CompatState`(루프 연결) · `review._compat_findings`(RV-COMPAT-*, RV-RUNTIME-*) · `net.fetch_bytes`(아카이브) ·
테스트 `tests/bts_sbom_app/test_compat.py`(23개, 런타임은 손으로 만든 로컬 wheel + 실제 venv, 오프라인).
