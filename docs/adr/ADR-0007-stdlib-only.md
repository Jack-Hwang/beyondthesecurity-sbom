# ADR-0007: 표준 라이브러리 전용, 의존성 0

## Status
Accepted — 사후 기록. 근거 코드: `pyproject.toml` (dependencies = []), `bts_sbom_app/llm.py`(urllib 기반 클라이언트), README 의 "standard library only". AC: BSA-AC-425~432 계열의 테스트 스타일과 `tests/bts_sbom_app` 전체가 네트워크 훅으로만 동작한다.

## 근거 (Context)
SBOM·라이선스·취약점 도구는 다른 환경(오프라인 강의실, 감사 대상 기업 내부, 제한된 컨테이너)에서 그대로 돌아가야 한다. 서드파티 의존성은 공급망 위험(SCA 도구가 스스로 공급망 문제를 만드는 아이러니)과 버전 관리 비용을 만든다. Python 3.10~3.12, Windows(cp949 콘솔)와 Linux 모두 지원해야 한다.

## 결정 (Decision)
런타임 의존성 0(`pyproject.toml` 의 `dependencies = []` 유지). HTTP 는 urllib, JSON 파싱·해시·압축 해제·템플릿 렌더링 모두 표준 라이브러리. `requirements.txt` 파싱과 CycloneDX/SPDX 생성도 직접 구현한다.

## 기각 대안 (Rejected alternatives)
- `requests`/`httpx`: 편의성 대비 재배포·감사 비용. retries/TLS 세부를 이미 `net.py` 가 담당하므로 이득이 작다.
- 벤더링(vendoring): 의존성 0 의 취지는 유지되지만 코드 크기·업데이트 부담이 커진다 — 필요한 기능만 직접 구현하는 편이 정직하다.

## 결과 (Consequences)
모든 테스트가 오프라인(TRANSPORT 훅)으로 동작하고, 컨테이너 이미지가 작다. 대신 일부 기능(리다이렉트 세부 제어 등)은 표준 라이브러리의 한계를 그대로 받는다 — `net.py` 의 문서에 한계를 기록한다.
