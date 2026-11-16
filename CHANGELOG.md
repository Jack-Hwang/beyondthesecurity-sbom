# Changelog

All notable changes to bts-sbom are documented here.

## 0.2.0 - 2026-11-17

BTS-SBOM 0.2.0 adds the end-to-end workflow layer next to the core (second package `bts_sbom_app/`, same distribution, still zero
third-party runtime dependencies) and repairs the core's console-encoding crash and its red CI.

### Workflow layer (`bts_sbom_app/`)

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

### Core (`bts_sbom/`)

* **Fix: `bts-sbom --help` (and every sub-command help) crashed with
  `UnicodeEncodeError` on non-UTF-8 consoles** - e.g. a Korean Windows terminal
  (cp949), cp1252 or an ASCII locale - because the help text contained U+2014 /
  U+2192 (and the top-level description Korean text). CI never saw it because the
  0.1.1 matrix exported `PYTHONUTF8=1`. Help/error text is now pure ASCII (a test
  asserts it), and `main()` additionally switches stdout/stderr to
  `errors="replace"`, so an un-encodable character in human-readable output
  degrades to `?` instead of aborting the command.
* **JSON/SARIF on stdout stays lossless.** If the console cannot encode the
  document (e.g. the Korean sector titles on an ASCII/cp1252 console), it is
  re-serialised with `ensure_ascii=True` (unicode escapes) instead of being
  degraded to `?`; `--out FILE` always writes UTF-8. Tests: every sub-command's
  `--help` under ascii / cp949 / cp1252 with `PYTHONUTF8` unset, and a strict
  decode + `json.loads` round-trip of `sector --sector finance`.
* **Fix: emitted documents claimed a stale (or no) tool version.** CycloneDX
  `metadata.tools[].version`, the SPDX `creators` entry (`bts-sbom sbom` emitted
  `Tool: bts-sbom` with no version at all; the internal builder hard-coded
  `0.1.0`) and the HTTP `User-Agent` headers now read the single source of truth
  `bts_sbom/_version.py`. A test pins pyproject(s), `__version__`, both CHANGELOGs,
  the README sample output and the emitted documents to the same value.
* Known limitation (unchanged scope): several human-readable report strings still
  contain typographic characters (dashes, arrows); on a non-UTF-8 console they
  print as `?`. Machine-readable output is unaffected (see above).
* **CI turned green again.** The core workflow had been red on every matrix job since 0.1.0: the unpinned `ruff` on the runners
  (0.17.5) enabled the import-sorting rule I001 by default. `ruff` is now pinned (`==0.14.10`) and the rule set is explicit
  (`[tool.ruff.lint] select = ["E4", "E7", "E9", "F"]` in both pyprojects); a workflow path filter that pointed at a non-existent
  file was corrected. `_stdout_safe` also tolerates a stream whose `encoding` attribute is not a string.
* `docs/CORE_ISSUES.md` item 4 (cp949 `--help` crash) is fixed by this release.
* No behaviour change to scanning, remediation, policy or VEX. Still **zero
  third-party runtime dependencies**.

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
