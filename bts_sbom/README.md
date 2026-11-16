# bts-sbom

**Regulatory-sector SBOM/SCA toolkit — CRA · FDA 524B · UNECE R155/R156 · EO 14028 · 금융 OSS 가이드 · 로봇/ISO 10218**

`bts-sbom` builds SBOMs (SPDX 2.3 + CycloneDX), scans dependencies against OSV,
emits and consumes OpenVEX, runs function-level reachability analysis for C/C++,
detects typosquatting / dependency-confusion / homoglyph supply-chain attacks,
and checks your documents against the requirements of six regulatory sectors —
in one dependency-free Python package.

**Zero third-party runtime dependencies.** Everything runs on the Python
standard library (Python >= 3.10). The package can prove it:

```console
$ python -m bts_sbom selfsbom
{ "bomFormat": "CycloneDX", ... "dependencies": [{ "ref": "pkg:pypi/bts-sbom@0.1.0", "dependsOn": [] }],
  "compositions": [{ "aggregate": "complete", ... }] }
```

## Quickstart

```console
$ pip install bts-sbom            # or: pip install ./bts_sbom

# 1. Build an SPDX 2.3 SBOM from a lockfile/manifest
$ bts-sbom sbom requirements.txt --name my-product

# 2. Scan a project for known vulnerabilities (OSV.dev; or --offline)
$ bts-sbom scan ./my-project --fmt table
$ bts-sbom scan ./my-project --offline --gate   # CI gate: 0/1/2 exit codes

# 3. Emit OpenVEX from a scan result
$ bts-sbom scan ./my-project --fmt json > scan.json
$ bts-sbom vex --from-scan scan.json

# 4. Regulatory-sector report (SPDX/CycloneDX JSON in, verdicts out)
$ bts-sbom sector --sector cra --sbom sbom.json --vex vex.json
$ bts-sbom sector --sector fda --sbom sbom.json --eol eol.json --out fda-report.json
```

The `sector` command also works as a library:

```python
import json, bts_sbom
report = bts_sbom.sector_report("cra", json.load(open("sbom.json")))
print(report["verdict"], report["summary"])
```

## The 6-sector requirement matrix

`bts-sbom sector --sector <name>` checks each sector's SBOM-relevant
requirements against your actual documents. Every row carries a measured
verdict — `pass`, `gap`, or `not_evidence` — with the evidence numbers inline.

| Sector | Regulation / guide | What is checked |
|---|---|---|
| `cra` | EU Cyber Resilience Act — Regulation (EU) 2024/2847 (in force 2024-12-10; vulnerability reporting from 2026-09-11; **full application 2027-12-11**, Annex I) | machine-readable SBOM format declared · NTIA minimum elements · supplier coverage ≥ 80% · vulnerability-handling evidence (VEX, Art. 13-14) · end-of-support dates per component |
| `fda` | FD&C Act §524B (2023-03) + FDA final guidance "Cybersecurity in Medical Devices" (2025-06) | machine-readable SBOM · NTIA minimum elements · supplier per component · **support status + end-of-support date per component (2025-06 NEW)** · known vulnerabilities documented (VEX) |
| `r155` | UNECE **R155 (CSMS) / R156 (SUMS)** — full new-type coverage 2027 | RXSWIN identification in SBOM metadata · component inventory · supply-chain vulnerability monitoring (VEX) · update impact analysis (dependency graph) |
| `dod` | EO 14028 (2021-05-12) · OMB M-22-18 · CISA SBOM self-attestation common form · DoD Software Pathway | SBOM automation evidenced (creator/tool declared) · VEX triage evidence · supplier fields · NTIA minimum elements |
| `finance` | 금융보안원 「금융분야 OSS 활용·관리 안내서」 · KISA SW 공급망 보안 가이드라인 | license inventory completeness (0 NOASSERTION) · CVE matching coverage (VEX) · SBOM maintenance evidence (timestamp) · supplier + version fields |
| `robot` | KISA 로봇 보안모델·체크리스트 · **ISO 10218-1:2025** · EU CRA overlap | component vulnerability check (VEX) · component inventory · CRA-overlap readiness (format + end-of-support) · machine-readable format |

SBOM quality is scored with the **NTIA minimum elements** (2021): supplier name,
component name, version, unique identifier, dependency relationships, SBOM
author, and timestamp.

## Honesty discipline

This toolkit exists because SBOM tooling routinely launders missing evidence
into green checkmarks. The rules here are enforced, not aspirational:

* **Absent evidence is never a pass.** A requirement whose input is missing
  (no VEX document, no end-of-support data, empty inventory) is reported as
  `not_evidence` — never `pass`, never an invented fail.
* **"No data" is never reported as "no vulnerability".** A scan whose advisory
  answers are incomplete carries `data_status`/`vulnerability_presence` fields;
  an empty vulnerability list is a verified pass only when every component was
  authoritatively queried (`scan --gate` maps this to CI exit codes).
* **Every row carries its evidence** — measured percentages, counts, and the
  basis each verdict rests on — so a reviewer can apply a stricter bar.
* **VEX is fail-closed.** A `not_affected` statement without a spec-valid
  justification raises an error instead of silently suppressing a finding;
  an unreachable-vulnerability verdict is never relaxed by an incomplete call
  graph (reachability UNKNOWN is never treated as safe).
* **NOASSERTION by default.** Offline, download locations, suppliers, and
  licenses stay NOASSERTION unless the documents actually say otherwise.

## What is inside

* `sbom` — SPDX 2.3 generator (content-digested namespaces, DEPENDS_ON from
  real graphs only) and CycloneDX 1.6/1.5 builder with NTIA element coverage.
* `scan` — OSV-Scanner-style pipeline: manifest/lockfile/SBOM discovery
  (npm, PyPI, Go, Cargo, Maven, NuGet, Gradle, mix, Conan, dpkg, rpm, ...),
  alias grouping, CVSS v3.1/v4.0 scoring, guided remediation, SARIF output,
  parallel OSV queries, offline sqlite cache.
* `vex` — OpenVEX v0.2.0 generation (incl. reachability-driven
  `not_affected` with correct justifications) and ingestion with auditable
  suppression.
* `reachability` — C/C++ function-level call-graph reachability for CVE
  triage, with graph-completeness evidence attached to every verdict.
* `supply_chain` — typosquat / homoglyph / dependency-confusion detection.
* `sector` — the 6-sector regulatory report engine (`sector_report()`).

## Status & scope honesty

Vendored from the BTS platform's SCA stack (Apache-2.0). Deliberately NOT
included in this package: the platform's bulk-intel sqlite layer, its
config/dotenv service settings, FastAPI server, and UI — everything here is
pure CLI + library. Network features (OSV.dev queries, deps.dev license
resolution, EPSS/KEV enrichment) degrade honestly to offline/cached/curated
data when the network is unavailable, and say so in the output.

## 한국어 요약 (KO)

**bts-sbom**은 규제 섹터별 SBOM/SCA 도구 모음입니다 — EU CRA · FDA 524B ·
UNECE R155/R156 · EO 14028 · 금융 OSS 가이드 · 로봇/ISO 10218.

* SBOM 생성 (SPDX 2.3 / CycloneDX), OSV 취약점 스캔, OpenVEX 생성·소비,
  C/C++ 함수 수준 도달가능성(reachability) 분석, 오타스쿼팅/의존성 혼동 공급망
  공격 탐지를 단일 패키지로 제공합니다.
* `bts-sbom sector --sector <섹터>` 명령으로 6개 섹터의 규제 요구를 실제
  문서(SBOM/VEX/EOL)와 대조합니다. 증거가 없는 요구는 절대 통으로 처리되지
  않고 `not_evidence`로 정직 표기됩니다.
* **서드파티 런타임 의존성 0개** (표준 라이브러리만 사용, Python >= 3.10).
  `python -m bts_sbom selfsbom`로 자기 자신의 SBOM을 생성해 증명합니다.

```console
$ pip install bts-sbom
$ bts-sbom sector --sector cra --sbom sbom.json
```

## License

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2025 BTS authors.
