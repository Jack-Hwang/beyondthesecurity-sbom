# UNDERSTAND REA FINDINGS — SciTools Understand 8.1.1269 (2026-11-28)

"지하 500층" 하강 기록: payload.7z 사본(손상) → 공식 Web 설치기(38MB) → Qt Installer Framework 역분석
→ 컴포넌트 저장소 매니페스트 → **헤드리스 설치 3.9GB** → conf/understand/metrics.json **공식 메트릭
카탈로그 140종** 확보 → BTS-SBOM code_intel 채택. 모든 단계는 실측 명령과 결과를 남긴다.

## 1. 하강 경로 (실패와 돌파구 모두 기록)

| 단계 | 명령/관측 | 결과 |
|---|---|---|
| payload.7z | 7z l → "Is not archive" | **손상 파일**: 7z 매직 뒤 7z 자체 에러 문자열 테이블+찌꺼기. 복구 불가 판정 |
| Web 설치기 PE | e_lfanew 0x140, x64, 2026-03-10 빌드, Qt6 DLL 흔적(.qtmimed) | **Qt Installer Framework** 바이너리 판정 |
| 7z 추출 | PE 섹션 분리만 성공 | 제품 페이로드 없음 — Web 설치기는 다운로드형 |
| 문자열 채굴 | .rdata ASCII 스캔 | **`builds.scitools.com/all_builds/b1269/Understand/components-win64`** 발견 |
| 저장소 매니페스트 | `Updates.xml` GET | **컴포넌트 6종 + 압축/비압축 크기 + SHA1** 확보 (2026-11-24 빌드) |
| 직접 7z | components-win64/com.scitools.understand.cmd/bin.7z | **403 AccessDenied** — S3 프라이빗(설치기가 서명 URL 생성) |
| **헤드리스 설치** | `Understand-Web-...exe in --default-answer --confirm-command --root <dir>` | **성공: 3.9GB 설치 완료**(accept-messages와 default-answer는 상호배타 — 첫 시도 도움말로 낭비) |

설치 컴포넌트(IFW Updates.xml 실측): cmd(und/uperl CLI, 15MB) · docs(121MB) · icarus(오프라인 라이선스) ·
samples(369MB) · static(Qt·Perl·GCC·Graphviz 런타임, 229MB) · 본체. **"AI model download complete" 로그 —
8.1은 llama.cpp 기반 로컬 LLM(ullama-server.exe·ullama-models.conf·llama.dll)을 동반한다.**

## 2. 설치 트리에서 캐낸 것

- **und.exe** — CLI 3모드(텍스트 일괄/명령 나열/인터랙티브): `create -db x.und -languages ... add @files analyze -all`
- **undmcp.exe** — Understand이 **자체 MCP 서버**를 제공(우리 mcp_server.py와 같은 아이디어)
- **ullama-*** — llama.cpp 로컬 LLM 서비스 + recommend/generate 실행기(설치기가 모델까지 받음)
- **conf/understand/** — 언어별(grafs/configs/metrics/python/clang...) 정의 디렉터리. **metrics/metrics.json이
  공식 메트릭 카탈로그 140종**(description HTML 포함), categories.json(범주), availability.json(언어별 가용)
- docs/html — 사용자 가이드·API 레퍼런스(121MB)

## 3. 140종 카탈로그 ↔ BTS-SBOM code_intel 매핑

| Understand | 정의(카탈로그 원문 요지) | 우리 구현 | 상태 |
|---|---|---|---|
| Cyclomatic | 결정점+1 | complexity | 기존 |
| CyclomaticModified / Strict | 체인당 1 / 피연산자마다 +1(unary not 포함) | complexity_modified / complexity_strict | **신규 채택** |
| Essential | 제어그래프 축약 후 결정점+1 | essential (구문계 구조결정 제거, 식 계열 유지 — 근사 명시) | **신규 채택** |
| Knots | 겹치는 점프 | knots (breaks+continues+비말단 return) | **신규 채택** |
| CountPath | 고유 경로(비정상 종료 제외) | path_count = 2^결정점(상한 65536, 상계 근사 명시) | **신규 채택(근사)** |
| MaxNesting | 최대 중첩 | nesting | 기존 |
| CountLine / Code / Comment / Blank / RatioCommentToCode | 행 분류 | count_line / eloc / count_line_comment / count_line_blank / ratio_comment_to_code | **신규 채택** |
| CountStmt / StmtDecl / StmtExe / StmtEmpty | 문장 분류(정의문/실행문/빈문장) | stmt_total / stmt_decl / stmt_exe / stmt_empty (+assigns/returns/breaks/continues) | **신규 채택** |
| CountInput / CountOutput | 호출자+전역읽기 / 피호출자+전역쓰기 | count_input / count_output | **신규 채택** |
| PercentLackOfCohesion | Henderson-Sellers LCOM* | classes[].lcom (메서드 0·속성 0이면 None — 정의 불가를 정직 표기) | **신규 채택** |
| CountClassCoupled (CBO) | 결합된 타 클래스 수 | classes[].cbo (프로젝트 내부 참조 근사) | **신규 채택** |
| CountClassBase / Derived | 직계 부모/자식 | hierarchy dit/noc | 기존 |
| CountDeclClass*Changed/New/Removed | **비교 DB 대비 변경/신규/제거** | snapshot_diff → deep.changed_entities | **동형 이미 채택** (이름만 다름) |
| CountInput fan 계열, Butterfly, Call/CallRev | 버터플라이·역호출 | butterfly() + fan_in/fan_out | 기존 |
| 나머지(예: AvgCyclomaticExec, 다언어 인바이런먼트 계열 등) | — | 미채택 — Python 단일 언어 레인 범위 밖(레인 한계를 정직히 명시) | 보류 |

**결론**: 140종 중 우리가 이번 라운드로 커버한 핵심 함수/클래스 메트릭 패밀리는 Cyclomatic 3종·Essential·
Knots·CountPath·행 5종·문장 4종+보조·Input/Output·LCOM·CBO·DIT/NOC·변경추적 — Understand의 Python 관측
면에서 실효 커버리지 대부분. 미채택은 언어 특화(COBOL/Ada/VHDL...)·GUI 전용·프리프로세서 계열.

## 4. 우리 제품 반영 (AC-1274/1275/1278)

- code_intel.analyze: 함수별 심층 메트릭 전부 + deep 섹션(체인·사이클·위계·파일의존·변수·엔터티 인벤토리·
  스냅샷) + changed_entities(prev_snapshot 인자)
- /api/code-dossier/<project>?function= — Understand의 Information Browser 동형(함수·클래스 양 종)
- code-metrics CSV 18열 확장
- 시험: test_code_intel_deep.py 8건(손계산 기대값) — 전부 통과

## 5. 다음 몫 (명시적 보류)

- **메트릭 봉투의 클린룸 명세 채널 주입**: 병행 세션이 UML 설계 뷰(EA 재하강)를 명세 채널에 넣은 것과 같은
  패턴으로, 함수별 행동 봉투(복잡도·문장 수·eLOC)를 명세에 실어 AI 역구현의 구조 충실도를 올리는 것 —
  레인 충돌을 피해 이번 라운드는 보류(uml_design/reimpl은 병행 레인이 소유 중), 다음 라운드 명세 채널로.
- und.exe의 DB 스키마(.und SQLite) 직접 파싱 레인, docs/html의 언어별 메트릭 세칙 대조.
