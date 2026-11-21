# PyPI Release Guide — bts-sbom

> 2026-11-21 검증 절차 기록. 빌드·설치·CLI 스모크는 실측 완료. 업로드만
> 소유자 계정 토큰이 필요하다 (이 가이드의 마지막 단계).

## 0. 사전 상태 (이 문서 작성 시점 실측)

- `pyproject.toml` version = **0.2.0** (stdlib-only, `dependencies = []`)
- `python -m build` 성공 → `dist/bts_sbom-0.2.0.tar.gz` (1.0MB) +
  `dist/bts_sbom-0.2.0-py3-none-any.whl` (939KB, 190 entries)
- wheel/sdist 민감 감사 0건 (llm_local · KESE · MathWorks · *.db · evidence/ 미포함)
- 격리 venv 설치 스모크: `pip install <wheel>` → `bts-sbom --version` = 0.2.0,
  `import bts_sbom, bts_sbom_app` OK

## 1. 빌드 (재현)

```bash
python -m pip install build
python -m build            # 저장소 루트에서 — dist/ 산출
```

## 2. 배포 전 감사 (푸시/업로드 전 매번)

```bash
# 2-1. 산출물 안에 민감 파일이 없는지
python - <<'EOF'
import tarfile, zipfile
for n in tarfile.open("dist/bts_sbom-0.2.0.tar.gz").getnames():
    assert not any(k in n.lower() for k in ("llm_local","kese","mathworks",".db","evidence/")), n
for n in zipfile.ZipFile("dist/bts_sbom-0.2.0-py3-none-any.whl").namelist():
    assert not any(k in n.lower() for k in ("llm_local","kese","mathworks",".db")), n
print("audit clean")
EOF

# 2-2. 메타데이터 정합
python -m pip install twine
python -m twine check dist/*
```

## 3. PyPI 계정 준비 (소유자만)

1. pypi.org 계정 → Account settings → API 토큰 발급 (scope: project 또는 전체).
2. 로컬 `~/.pypirc` 작성 (토큰을 셸 히스토리에 남기지 않는다):

```ini
[pypi]
username = __token__
password = pypi-AgEIcHl...   # 발급받은 토큰
```

3. (권장) TestPyPI로 먼저: 동일 절차, `repositoryUrl`만 test.pypi.org로.

## 4. 업로드

```bash
python -m twine upload dist/*              # PyPI
# 리허설:
# python -m twine upload --repository-url https://test.pypi.org/legacy/ dist/*
```

업로드 후 확인:

```bash
python -m pip install --index-url https://test.pypi.org/simple/ bts-sbom   # 리허설
python -m pip install bts-sbom                                             # 본 업로드
bts-sbom --version
bts-sbom sbom --help
```

## 5. 버전 규칙

- 버전 단일 소스: `pyproject.toml` `[project] version` (코드 내 중복 금지).
- 엔진 신규 기능(라운드 2~3) → minor bump, 수리 → patch bump.
- 태그: `git tag v0.2.0 && git push origin v0.2.0` (v0.1.0/v0.1.1 선례).
- CI의 자기-SBOM 데모(`selfsbom`)가 `dependencies = []`를 계속 증명해야 한다 —
  외부 의존 추가 시 이 문서 §0의 "stdlib-only" 문장과 함께 갱신.
