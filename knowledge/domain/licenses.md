# 오픈소스 라이선스 (Open-source license)

## 라이선스는 어떻게 찾는가 (resolution chain)

BTS-SBOM 는 컴포넌트마다 라이선스를 세 단계로 찾고, 어디서 찾았는지(`license_source`)를 기록한다.
1. `lockfile`: package-lock.json(v2/v3)과 composer.lock에 들어 있는 license 필드.
2. `deps.dev`: Google Open Source Insights API. npm, PyPI, Go, Maven, Cargo, NuGet, RubyGems를 한 곳에서 조회한다.
3. `registry`: deps.dev에 없을 때 PyPI JSON 또는 npm 레지스트리를 직접 조회한다.
근거를 못 찾은 컴포넌트는 **미해결(unresolved)로 남긴다**. 이름만 보고 추측하지 않는다 (Honesty: an unresolved license stays unresolved).

## 소스 트리에서 찾는 라이선스

`scan_tree` 는 프로젝트 루트의 LICENSE/COPYING 파일 전문을 서명 문구로 식별하고(MIT, Apache-2.0, BSD, GPL, LGPL, AGPL, MPL-2.0, ISC, Unlicense 등),
소스 파일 머리말의 `SPDX-License-Identifier` 태그를 집계하며, 하위 폴더에 들어 있는 vendored 라이선스 파일을 따로 보고한다.
루트 라이선스 파일이 없으면 SPDX 태그 다수결을 쓰고 그 사실을 `project_license_source` 에 적는다.

## SPDX 정규화와 분류 (category)

"Apache 2.0", "GPLv3", "BSD" 같은 표기를 SPDX 식별자(Apache-2.0, GPL-3.0-only, BSD-3-Clause)로 바꾼다. 복합식은 OR/AND/WITH 를 유지한다.
분류: permissive(MIT, Apache-2.0, BSD, ISC), public-domain(Unlicense, CC0), weak-copyleft(LGPL, MPL-2.0, EPL),
strong-copyleft(GPL), network-copyleft(AGPL, SSPL), restricted(BUSL, Elastic-2.0, 비상업 CC), unknown.
`A OR B` 는 가장 관대한 쪽을 선택지로 보고, `A AND B` 는 가장 엄격한 쪽을 따른다. `GPL-2.0-only WITH Classpath-exception-2.0` 은 weak-copyleft 로 본다.

## 정책 판정 (policy)

배포 형태(distribution)에 따라 달라진다. binary 배포: network-copyleft 와 restricted 는 deny, strong/weak copyleft 와 unknown 은 review.
saas: AGPL 계열은 deny. internal(외부 배포 없음): copyleft 소스 제공 의무가 발생하지 않으므로 review 에서 제외한다.
프로젝트 라이선스가 permissive 인데 strong-copyleft 의존성이 있으면 conflict 로 보고한다. 이는 엔지니어링 신호이며 법률 자문이 아니다.

## 의무 (obligations)

permissive: 저작권과 라이선스 고지 유지. weak-copyleft: 라이브러리 수정분 공개와 재링크 허용. strong-copyleft: 결합 저작물 배포 시 대응 소스 제공.
network-copyleft: 네트워크 사용자에게도 소스 제공. unknown: 먼저 라이선스를 식별해야 의무를 판단할 수 있다.

## 주요 라이선스 의무 요약 (GPL-2.0 / GPL-3.0 / Apache-2.0 / MIT / BSD)

GPL-2.0-only는 강한 카피레프트(strong copyleft)다. 바이너리를 배포하면 소스 코드 전체를 같은 GPL-2.0으로
공개해야 하고(저작권 고지·보증 부인 고지 유지), 내부에서만 사용하면 공개 의무가 없다. 특허 방어 조항이 없어
기여자의 특허 주장에 대한 보호가 GPL-3.0보다 약하다. Linux 커널이 대표 사용처다.

GPL-3.0-only는 GPL-2.0의 의무에 더해 명시적 특허 허가(patent grant)와 타이와mium 방지 조항이 있다.
배포 시 소스 공개·동일 라이선스 유지는 GPL-2.0과 같은 강한 카피레프트다.

Apache-2.0은 허용형(permissive)이다. 소스 공개 의무가 없고, 저작권·고지(NOTICE) 유지만 요구하며,
명시적 특허 허가가 들어 있어 기여자 특허 리스크가 낮다. 수정 파일에는 변경 표시를 남기는 관행 요건이 있다.

MIT와 BSD(2·3-clause)는 가장 관대하다. 저작권 고지 유지만 하면 소스 비공개·독점 라이선스화가 자유이며,
BSD 3-clause는 추가로 기여자 이름을 홍보에 쓰지 못하는 조항이 붙는다.

라이선스 호환 방향: BSD·MIT·Apache 코드는 GPL 프로젝트에 합류할 수 있지만, GPL 코드를 Apache/MIT 프로젝트에
합치면 그 부분이 GPL 의무를 물려준다(카피레프트는 업스트림 방향으로만 전염된다). Weak copyleft(LGPL,
GPL-2.0 WITH Classpath-exception)는 라이브러리 경계에서 링크만 허용하고 라이브러리 자체 수정은 공개한다.
