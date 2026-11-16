# Changelog

All notable changes to bts-sbom are documented here.

## 0.1.1 — round 2: engine features + cross-platform hardening

* **Precise version-range matching** (`_internal/version_match.py`): PEP 440
  specifier operators (`==`, `!=`, `<=`, `>=`, `<`, `>`, `~=`, `==X.Y.*`,
  `===`) and npm/cargo SemVer ranges (`^`, `~`, `>=`, `<`, `=`, x-ranges,
  `*`, npm prerelease opt-in) plus go semver-ish ordering. Wired into the
  scan/remediation fixed-bound selection (previously the generic tolerant
  comparator), cutting pre-release boundary false positives.
* **Guided remediation** (`_internal/remediation.py`): every scan result now
  carries a `remediation` block suggesting the SMALLEST fixed version >= the
  installed one per finding, with the constraint source cited; ranges with
  only `last_affected` are honestly reported as `no-fixed-event`. Disable
  with `scan --no-remediation`.
* **Policy engine** (`_internal/policy.py` + new `policy` subcommand):
  severity_min / licenses_deny / max_severity_score rules over the scan
  output shape, SBOM components for license rules; exit 1 on violation
  (CI gate mode), 0 on pass, 2 on input errors.
* **VEX at the decision point**: `vex_evaluate()` groups findings against
  VEX statements (`not_affected`/`fixed` suppress — auditable and
  fail-closed on a malformed document); wired as `policy --vex`.
* **Transitive dependency audit**: per-manifest transitive status verified;
  Cargo.lock entries are now classified direct/transitive from the sibling
  Cargo.toml instead of labeling every entry `direct`.
* **Cross-platform hardening**: every text-mode file read/write carries an
  explicit UTF-8 encoding (`utf-8-sig` + `errors="replace"` for scan
  inputs, so Windows-BOM lockfiles parse identically on Linux); shared
  `pathutil.norm_rel_path()` for `/` ↔ `\` manifest path routing; CI
  matrix extended to ubuntu-latest + windows-latest + macos-latest x
  Python 3.10/3.12 with `PYTHONUTF8=1` (Windows encoding guard).
* Still **zero third-party runtime dependencies** — all new modules are
  stdlib-only (asserted by the package's own test suite).

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
