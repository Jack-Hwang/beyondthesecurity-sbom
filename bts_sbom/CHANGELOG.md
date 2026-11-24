# Changelog

All notable changes to bts-sbom are documented here.

## 0.5.0 - 2026-11-22: Clean-room reimplementation lane + book KB + MCP server + architecture tools

- Clean-room reimplementation workbench (`bts-sbom-app reimpl` / POST /api/reimpl): interface spec ->
  NEW code generated behind a two-wall process (the generator never sees the original source) ->
  measured copy gate (line-shingle overlap, docstrings excluded as spec-derived) -> generated contract
  tests + the upstream legacy suite as behaviour oracle under a legacy-runtime shim -> best-of-N
  candidates by measured compatibility -> publish. Live SSE events for every stage.
- Book knowledge base (two-tier extraction: stdlib EPUB spine parsing + pdftotext with honest skips;
  serve-time-only raw index + distilled notes; eval-corpus isolation measured, ADR-0021) with a
  book_search chat tool, /api/books registry|outline|search|ingest and a Book KB tab.
- MCP server over stdio JSON-RPC 2.0 (`python -m bts_sbom_app mcp`): tools/list, tools/call,
  resources/list, resources/read; tools delegate to the real modules.
- A2A-style agent card at GET /api/agent-card: 7 skills with their real gates, honest securitySchemes.
- Chat upgrades: multi-turn conversation memory with deterministic follow-up resolution, compound-
  question decomposition, lost-in-the-middle passage reordering, upstream-oracle compatibility loop for
  generated code, 7-event chat-level SSE with HITL approval, and the REAL Visual Studio layer-model
  semantics (ForbiddenNamespace, obsolete layers, unique names, moniker ambiguity, participation
  opt-out) adopted from the Visual Studio layer-model semantics.
- DGML export of the measured import graph (Visual Studio Code Maps interop) with directory groups,
  hotspot/cycle categories and a layer-validation map; supply-chain gate (docker build -> Trivy
  CRITICAL gate -> CycloneDX SBOM -> own-repo SBOM -> /healthz bench) measured end to end.
- Batch experiment dataset: 64 legacy PyPI packages run through the lane (146 dataset rows; latest-run
  verdicts ok 31 / compatibility_failed 1 / tests_failed 0 of 32 laned) with the full analysis in
  evidence/reimpl_batch/ANALYSIS.md.

## 0.3.0 - 2026-11-21: Arch Intel - license verdict + AI architecture deep-dive, deterministic insights

* **New: the Arch Intel screen** (`/api/arch/*`, pipeline `bts_sbom_app/arch_intel.py`, pure renderer
  `web/arch_intel_render.js`). An open-source tree (local folder or GitHub repo) is measured - never executed -
  and reported as a license verdict (distribution-mode checklist, compatibility matrix, notice obligations),
  a deterministic structure view (stack, import graph, clusters, hotspots, entry points) and an EXAONE AI lane
  that sees metadata only. Mermaid diagrams render from vendored mermaid@11.12.2 with the raw source kept in a
  hidden pre as the fallback. Clean-room guardrails are testable invariants (ADR-0014).
* **New: deterministic architecture insights** (`bts_sbom_app/arch_flow.py`) - flow blockers, bounded-context
  candidates, a style hypothesis, antipattern signals and a modularity summary, each derived only from the
  measured structure and each carrying an honesty note: a heuristic, never a verdict.
* **New: the chat `latest_arch` tool** - the latest recorded Arch Intel run summarised from the evidence folder.

## 0.2.0 - 2026-11-17: console-encoding fix, version-metadata consistency, green CI

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
* **Fix: the core CI was still red after the lint fix, for two older reasons that the lint failure had been hiding.** (1) On Python 3.10
  (declared supported, in the CI matrix) the package used `tomllib`, which exists from 3.11: a TOML manifest was reported as
  "corrupt toml manifest: No module named 'tomllib'", blaming a healthy file. It is now reported as "unsupported on this Python ...
  need tomllib" (the scan still ends `parse_failed` / presence `unknown`, never as no findings), the stdlib-only test accepts the guarded
  `tomllib` import, and the Cargo direct/transitive test runs only where `tomllib` exists. Two new tests pin both the honest message and
  that a truly corrupt TOML file is still called corrupt. (2) The CI lockfile demo wrote `demo-requirements.txt`, a name the parser
  does not recognise ("no parser for ..."); it now writes `demo-lock/requirements.txt`. The remaining CI steps (policy gate smoke,
  artifact upload) had never run before and were replayed locally.
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
