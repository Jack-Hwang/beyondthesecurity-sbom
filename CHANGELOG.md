# Changelog

All notable changes to bts-sbom are documented here.

## Unreleased

* **End-to-end workflow (analyse, patch, architecture, chatbot) added to BTS-SBOM** as the package `bts_sbom_app/` (command `bts-sbom-app`;
  environment variables `BTS_SBOM_LLM_CONFIG`, `BTS_SBOM_LLM_DAILY_BUDGET`, `BTS_SBOM_UNICODE`; requirement ids `BSA-AC-n`; SBOM property
  namespace `bts-sbom:`; record schema ids `bts-sbom.project.v1` / `bts-sbom.batch.v1`, and records written under the earlier project
  schema id are still read). It is a second
  stdlib-only package in the same distribution, built on the `bts_sbom` core through a single adapter (`bts_sbom_app/engine.py`);
  no `bts_sbom/` file was modified and `dependencies` stays empty. Adds: license resolution with provenance (lockfile -> deps.dev ->
  PyPI/npm/Maven), alias-merged findings with CVSS v3 and fixed versions from ECOSYSTEM/SEMVER ranges, OSV-verified remediation
  plans, approval-gated manifest patching with re-scan verification and revert, delivery targets (branch / folder / origin /
  GitHub remote behind explicit flags), CycloneDX 1.5 / SPDX 2.3 / OpenVEX output, industry reports (defense, automotive, medical,
  finance, maritime draft, CRA, robot), legacy-architecture analysis, LG EXAONE proposals with four-layer validation and
  deterministic fallback, a grounded RAG chatbot, a stdlib HTTP service, and a loop-engineering harness.
  Tests live in `tests/bts_sbom_app/` (78 tests, network faked); the EARS spec is `specs/bts_sbom_app_features.md` (77 ACs, each traced to a
  test); measured e2e evidence is in `evidence/` and documented in `docs/WORKFLOW.md`. The `BTS-SBOM app CI` workflow has run green on
  GitHub (ubuntu/windows x py3.10/3.12). Not yet verified: push/PR delivery against real GitHub, building patched code.
* **Open-source security web screen**: `bts-sbom-app serve` now serves the BTS platform's "Open-Source Security" screen (7 tabs, sub-tabs,
  1-4 step bar, result console) backed by real BTS-SBOM data - findings, dependencies per manifest, architecture, SBOM/VEX downloads,
  licences, industry reports, upgrade plan and an approval-gated patch with plan preview, digest review and diff. Six platform files
  are copied unmodified into `bts_sbom_app/web/` (provenance and sha256 in `NOTICE.md`; a test detects edits); the page, `bts_console.js`
  and `bts_sbom_app/console.py` are new. Values BTS-SBOM does not compute (KEV, EPSS, SSVC, reachability, priority) are left out and the
  panes say so. Service hardening: strict Content-Security-Policy, fixed static allow-list, `approval_token` required for an approved
  scan, server-made work copies removed after the job unless a patch was applied. New endpoints: `/api/view`, `/api/history`,
  `/api/engine`, `/api/sbom`, `/api/doc`, `/api/triage`. Ignore decisions are stored but not yet written into OpenVEX.
* Open core defects found while building BTS-SBOM are listed in `docs/CORE_ISSUES.md` (not fixed here).

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
