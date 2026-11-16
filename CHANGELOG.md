# Changelog

All notable changes to bts-sbom are documented here.

## Unreleased

* **SBOM+ (`sbomplus/`, CLI `sbomplus`) merged into this repository** from the standalone `sbom-plus` work folder. It is a second
  stdlib-only package in the same distribution, built on the `bts_sbom` core through a single adapter (`sbomplus/engine.py`);
  no `bts_sbom/` file was modified and `dependencies` stays empty. Adds: license resolution with provenance (lockfile -> deps.dev ->
  PyPI/npm/Maven), alias-merged findings with CVSS v3 and fixed versions from ECOSYSTEM/SEMVER ranges, OSV-verified remediation
  plans, approval-gated manifest patching with re-scan verification and revert, delivery targets (branch / folder / origin /
  GitHub remote behind explicit flags), CycloneDX 1.5 / SPDX 2.3 / OpenVEX output, industry reports (defense, automotive, medical,
  finance, maritime draft, CRA, robot), legacy-architecture analysis, LG EXAONE proposals with four-layer validation and
  deterministic fallback, a grounded RAG chatbot, a stdlib HTTP service, and a loop-engineering harness.
  Tests live in `tests/sbomplus/` (69 tests, network faked); the EARS spec is `specs/sbomplus_features.md` (68 ACs, each traced to a
  test); measured e2e evidence is in `evidence/` and documented in `docs/SBOMPLUS.md`. Not yet verified: push/PR on real GitHub,
  the new CI workflow, building patched code.
* Open core defects found while building SBOM+ are listed in `docs/CORE_ISSUES.md` (not fixed here).

## 0.1.0 — initial OSS release

First standalone, stdlib-only release of the BTS regulatory-sector SBOM/SCA
toolkit (vendored from the BTS platform SCA stack, Apache-2.0).

* **6-sector regulatory reports** (`sector`): CRA (EU 2024/2847), FDA FD&C
  §524B + 2025-06 guidance, UNECE R155/R156, EO 14028 / CISA attestation /
  DoD Software Pathway, 금융 OSS 가이드, KISA 로봇 보안모델 / ISO 10218-1:2025 —
  with `pass` / `gap` / `not_evidence` verdicts and measured evidence per row.
* **SBOM generation**: SPDX 2.3 (`sbom`) and CycloneDX 1.6 builders, NTIA
  minimum-element scoring, honest NOASSERTION defaults.
* **Vulnerability scanning** (`scan`): OSV-Scanner-style pipeline over
  manifests/lockfiles/SBOMs — alias grouping, CVSS v3.1/v4.0 scoring, guided
  remediation, SARIF/table/markdown/vertical output, offline sqlite cache,
  data-completeness contract ("no data" is never "no vulnerability").
* **VEX**: OpenVEX v0.2.0 generation (incl. reachability-driven
  not_affected), fail-closed ingestion and auditable suppression.
* **Reachability**: C/C++ function-level call-graph analysis with
  graph-completeness evidence; UNKNOWN is never relaxed to UNREACHABLE.
* **Supply-chain analysis**: typosquat / homoglyph / dependency-confusion
  detection with an honest popular-name seed list.
* **Self-SBOM** (`selfsbom`): the package emits its own CycloneDX document,
  asserting a complete, empty dependency graph (zero third-party deps).
* **Zero third-party runtime dependencies** (Python >= 3.10 standard library
  only). The platform's pydantic/requests/license_expression/dotenv-bound
  layers were replaced with stdlib equivalents during vendoring; behavior
  gaps are documented in the module headers (`bts_sbom/_internal/`).
