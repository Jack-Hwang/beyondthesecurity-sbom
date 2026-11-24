# ADR-0023: Code Intel — Understand의 기능을 설치·의존 없이 자체 재구현 (Python-first)

## Status

Accepted (2026-11-22, 사용자 결정: "기능 조사 후 자체 재구현" — 설치러 REA 확인 후 다른 선택지 기각)

## 근거 (Context)

사용자가 SciTools Understand 8.1 설치러(`Understand-Web-8.1.1268-Windows-64bit.exe`, sha256 abf5f929…)를
다운로드해 "싹 REA해서 기능을 통합"을 요청했다. REA 정적 조사 결과: 단일 x64 PE, 관리형 아님(cli directory
absent, ev_555081ae), 본문에서 **Qt Installer Framework** 확인 — `TargetDir=@ApplicationsDir@/SciTools`,
`RunProgram=bin/pc-win64/understand.exe`, Publisher "Scientific Toolworks, Inc." (공식 배포판). 이하 선택지가
있었다: (a) 설치 후 `und` CLI/understand.py를 외부 엔진으로 연결, (b) IFW 페이로드 정적 추출, (c) 기능 조사 후
자체 재구현. 사용자는 (c)를 선택했다 — 설치·상용 라이선스·외부 의존 없이, ADR-0007의 stdlib-only 원칙 안에서
Understand의 핵심 코드-이해 기능(함수 콜그래프·순환 복잡도·데드코드·중복 코드 검출·코드 브라우저)을 우리
arch 레인에 흡수한다. 제품의 그래프 UI·멀티언어 파서 전체를 재현하는 것은 범위가 아니며, bts-sbom-app arch
레인에 없던 **함수 레벨** 사실만 추가한다(기존 arch.py는 모듈 레벨, 복잡도는 파일당 regex 프록시였다).

## 결정 (Decision)

1. **`code_intel.py` (순수 stdlib ast, LLM 없음, 결정론)**: 함수 인벤토리(name/file/line/params/loc/sloc),
   복잡도 = 1 + 분기(If/For/While/Except/IfExp/Assert/BoolOp 여분/comprehension+ifs/match case),
   콜 해석은 **프로젝트 전역 함수 이름 기반**(문서화된 근사 — 미해석은 unknown으로 세고 추측하지 않음),
   데드코드 = fan-in 0 − 명시적 제외(main/cli/run/setup/teardown·던더·test_*·decorator 부착 — rules를 notes로
   공개), 클론 = 식별자·리터럴을 정규화한 토큰 시퀀스 해시(≥24토큰). 모든 상한은 측정 기록. (BSA-AC-553..556)
2. **Python-first 정직성**: 다른 언어는 기존 모듈 레벨 분석을 유지하고 그 한계를 notes·UI로 밝힌다. 정규식
   콜그래프 반쪽짜리를 만들지 않는 것이 이 결정의 핵심이다.
3. **결합 지점**: `arch.analyze()["code"]` → `console.build_view` 바운드 projection(함수 15·엣지 40, 빈 레인은
   None) → 콘솔 **🔎 Code Intel** 판; `arch_intel.structure()["code"]`(top 12 함수·엣지 40·데드 10·클론 5) →
   `arch_flow.code_smells` 인사이트(복잡도 아웃라이어·평균 과분기·데드코드·중복 — measured evidence 인용) +
   `prompt_evidence` **메타데이터만**(BSA-AC-447 소스-라인 금지 불변식 유지) + 결정론 `mermaid_callgraph`
   (fan 상위 함수 간 실측 엣지 ≤24 — 모델은 mermaid를 쓰지 않는 ADR-0014 계약 유지).
4. **modernization 연동**: fan-in 0 함수 상위 2개를 `remove_dead_code` 후보로 추가(우선순위 low).
5. **v2 후속(동일일, 설치러 채굴 어휘 반영)**: 설치러 문자열에서 Understand의 그래프 어휘(Butterfly·
   Interaction·Dependencies·Essential·Clone·Compare)와 `und` CLI를 추가 확인(정적 채굴 — IFW 페이로드 자체는
   전용 포맷이라 정적 경계 밖을 기록). 이를 반영해 v2를 출하했다: ① 클래스 인지 콜 해석(`self.method`는
   호출자의 클래스, `Cls.method`, 동일 파일 우선 — 동명 함수가 여러 파일이어도 실제 호출 파일만 fan-in) +
   클래스 인벤토리(bases·메서드 수) ② 함수별 callers/callees 이웃(Butterfly 아날로그)을
   `GET /api/code-butterfly` 로 ③ 함수 메트릭 전수 CSV `GET /api/code-metrics`(metrics export 아날로그)
   ④ nesting depth 메트릭. (BSA-AC-560..562)

## 기각 대안 (Rejected alternatives)

- **Understand 설치 + `und`/understand.py 외부 엔진 연결(pdftotext 패턴)** — 사용자 기각: 상용 설치·라이선스
  의존이 ADR-0007 정신과 충돌하고, CI/다른 머신 재현이 깨진다.
- **IFW 페이로드 정적 추출** — Qt Installer Framework 페이로드는 정적 추출 경계가 불안정하고, 얻어도 라이선스
  있는 바이너리라 실행 불가(실행=사용자 기각 항목).
- **정규식 기반 C/C++·Java 함수 콜그래프** — 전처리·매크로·오버로드를 거치지 못하는 반파서는 근거 없는 그래프를
  만든다(정직성 계약 위반). Python(ast)만 함수 레벨, 타 언어는 모듈 레벨 유지로 답했다.
- **LLM이 콜그래프를 쓰게 함** — ADR-0014 위반(다이어그램은 결정론 빌더만).

## 결과 (Consequences)

긍정: 설치·의존 0으로 Understand의 핵심 4기능(콜그래프·복잡도·데드코드·클론)이 콘솔과 Arch Intel에 상주,
복잡도가 파일 regex 프록시에서 함수 AST 실측으로 승격, 데드코드가 modernization 후보로 유입, 프롬프트는
메타데이터만 추가(기준선 불변 — ragloop으로 확인). 부담/한계: Python만 함수 레벨(타 언어는 모듈 레벨 notes),
콜 해석은 이름 기반 근사(동명 함수 전부 타깃, 동적 디스패치·getattr는 unknown), 데드코드 제외 규칙을
거친 목록이며 프레임워크 암묵 등록은 보수적으로 유지, 클론은 정규화 완전일치만(근사 클론은 미검출을 notes로
밝힘). Understand 자체는 여전히 더 많은 언어·인터랙티브 그래프를 제공한다 — 우리는 재구현 범위를 정직하게
"파이프라인이 상주하는 함수 레벨 사실"로 한정했다.
