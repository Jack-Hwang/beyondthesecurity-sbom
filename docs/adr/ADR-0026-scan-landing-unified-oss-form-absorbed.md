# ADR-0026: Scan 랜딩 통합 — OSS Scanner 화면을 Scan 섹션 한 폼으로 흡수

## Status

Accepted (2026-11-22, 사용자 지시: "우선 이화면은 scan 부분에 싹다 통합해" — OSS Scanner 화면 스크린샷 첨부,
선택지 3종 중 "폼까지 하나로 병합" 사용자 선택)

## 근거 (Context)

메인 파이프라인(🌐 Scan 랜딩의 git/로컬 경로 입력)과 OSS 스캔 엔진(별도 최상위 "📜 OSS Scanner" 그룹의
폴더/아카이브/git 폼)은 엔진이 다름에도(파이프라인 vs oss_api) 진입점이 둘로 갈라져 있었다. ADR-0008 계열의
"한 번의 Analyze" 정신(AC-533 체인)은 체크박스(#scaOss "OSS 성과물")가 켜져 있어야만 작동했고, exclude·
branch·분석 유형·sbom-info 보정 같은 OSS 고급 옵션은 OSS 탭에서 따로 입력해야 체인에 반영되지 않는
(체인은 modes 고정·excludes 빈 배열 하드코딩) 반쪽 통합이었다. 사용자는 OSS Scanner 화면(통합 분석 폼 +
Previous scans) 전체를 Scan 부분에 통합하기를 선택했고, 3안 중 폼 자체를 하나로 병합하는 안을 고른다.

## 결정 (Decision)

1. **한 폼 병합**: 🌐 Scan 랜딩(#scaRepoPanel)이 유일한 분석 진입점이 된다. 대상 입력(#scaGitUrl — git
   URL·owner/repo·로컬 폴더·아카이브 전부) + branch/tag(#ossBranch) + offline·EXAONE(메인 파이프라인
   옵션) + OSS 분석 유형(source/dependency/binary + sbom-info.yaml 보정) + exclude 칩이 같은 상자에
   있고, 그 아래 Previous scans(#ossHistoryLanding, Open/Compare)가 붙는다. #scaOss 체크박스는 폐기 —
   체인이 기본 동작이다.
2. **그룹 흡수**: 최상위 "📜 OSS Scanner" 사이드바 그룹을 제거하고 'oss'를 'git' 그룹의 멤버로 편입한다
   (최상위 그룹 1개 감소). 라벨은 "📜 OSS 결과"가 되어 이 탭의 역할(진행 단계·결과 테이블·공개문·내보내기)을
   정직하게 표시한다. 폼 조각(모드·exclude)과 이력은 랜딩 컨테이너(#scaOssModes/#scaOssExcludes/
   #ossHistoryLanding)에 oss_scanner.js가 채우고, #paneOss는 결과만 담는다.
3. **체인 재계약**: analyse()는 매번 BtsOss.readForm()으로 폼 값을 읽고 runOssChain에서 BtsOss.start로
   스캔을 시작한다. 메인 파이프라인이 실패해도(아카이브 등 파이프라인이 못 읽는 대상) OSS 단계는 계속
   실행되며, 어떤 경우에도 조용한 생략이 없다(엔진 스크립트 미로드·분석 유형 0개 선택은 배너에 기록).
   excludes/branch/보정은 체인에 실제로 반영된다. (BSA-AC-533 재정의)
4. **탭 점프 계약**: pane 스크립트(oss_scanner.js)가 `bts:activate` 커스텀 이벤트(detail=서브뷰 id)를
   발행하면 bts_console.js가 activate()로 이어받는다 — 이력 Open·성공 배너 버튼이 OSS 결과 서브탭으로
   점프한다. CSP상 인라인 핸들러는 여전히 0개. (BSA-AC-563)

## 기각 대안 (Rejected alternatives)

- **네비 재배치만(서브탭 이동)** — "싹다 통합" 요구에 비해 화면 변화가 없고, 폼 2개·진입점 2개 문제가 그대로 남는다.
- **두 폼 나란히 배치(병합 없음)** — 랜딩에 같은 대상을 두 번 입력하는 폼이 2개 생겨 통합이 아니라 나열이다.
  체크박스 기반 체인의 반쪽 통합(옵션 미반영)도 해소되지 않는다.
- **플랫폼 원본 화면 복원(사이드바 폐기·결과 인라인)** — ADR-0022 데스크탑 셸·Report 별도 탭 결정을 되돌리는
  것이고 결과 테이블이 랜딩을 덮어 단일 화면이 비대해진다.
- **메인 실패 시 OSS 체인 중단 유지(기존 계약)** — 아카이브(.whl/.rpm/.zip) 대상은 파이프라인이 못 읽어
  OSS 단계가 영원히 실행되지 않는다. 스크린샷 화면의 핵심 기능(아카이브 스캔)이 죽는 결과라 기각.

## 결과 (Consequences)

긍정: 분석 진입점이 1개로 모여 같은 대상에 대해 SBOM/CVE 리포트와 OSS 성과물(공개문·엑셀·바이너리
목록)이 항상 함께 만들어진다, exclude·branch·보정이 체인에 실제로 반영된다, 아카이브 대상도 정상 동작한다,
사이드바 최상위 그룹이 하나 줄어든다. 부담: 모든 Analyze가 OSS 스캔을 추가 실행하므로 대형 저장소에서 시간이
더 든다(거부 스위치 없음 — 사용자 결정), oss_scanner.js와 bts_console.js가 폼을 나눠 소유하므로 두 파일의
컨테이너 id 계약(#scaOssModes/#scaOssExcludes/#ossHistoryLanding/#ossBranch)이 깨지면 화면이 반쪽이
된다(정적 구조 테스트가 강제), 랜딩이 이전보다 길어진다.
