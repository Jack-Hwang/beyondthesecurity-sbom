# SBOM 형식과 품질 (SBOM formats and quality)

## 산출물

SBOM+ 는 프로젝트마다 세 문서를 만든다: CycloneDX 1.5 JSON(컴포넌트, 라이선스, 취약점 포함), SPDX 2.3 JSON(bts_sbom 코어의 빌더와 검증기 사용), OpenVEX 0.2(취약점 상태).

## CycloneDX 규칙

모든 컴포넌트는 고유한 `bom-ref`(보통 purl)를 가진다. 모든 취약점의 `affects` 참조는 실제 컴포넌트 `bom-ref` 로 해소되어야 한다.
SBOM+ 는 이를 `ref_integrity` 로 측정한다(목표 100%). 해소되지 않는 참조는 만들지 않는다(dangling reference 금지).
라이선스 근거가 없는 컴포넌트에는 `licenses` 항목을 넣지 않는다. NOASSERTION 으로 채워 통과처럼 보이게 하지 않는다. 공급자(supplier)도 지어내지 않는다.

## NTIA 최소 요소

공급자 이름, 컴포넌트 이름, 버전, 고유 식별자, 의존 관계, SBOM 작성자, 타임스탬프. 공급자 정보는 공개 레지스트리 메타데이터로는 대부분 채워지지 않아 산업 리포트에서 gap 으로 정직하게 드러난다.

## VEX

열린 취약점은 `affected`(수정 버전을 action_statement 에 기재), 패치 후 검증이 끝난 것만 `fixed` 로 표기한다.
`not_affected` 는 도달 가능성(reachability) 같은 근거가 있을 때만 쓰며, SBOM+ 는 근거 없이 이 상태를 만들지 않는다.

## 의존 관계

직접 의존(direct)과 전이 의존(transitive)을 구분한다. 매니페스트만 있고 락파일이 없으면 버전 범위가 확정되지 않아 `version_unresolved` 로 집계된다.
지원 매니페스트: requirements.txt, poetry.lock, Pipfile.lock, package.json, package-lock.json, yarn.lock, Cargo.toml, Cargo.lock, go.mod, go.sum, pom.xml, build.gradle, gradle.lockfile, composer.lock, Gemfile.lock, pubspec.lock, mix.lock, packages.lock.json, conanfile, vcpkg.json.
