# Changelog

All notable changes to bts-sbom are documented here.

## 0.6.1 - 2026-11-28: GitOps deploy lane + secretless CI + ubuntu CI green + public access

- **GitOps deploy lane (AC-1272/1273)**: scripts/gitops_deploy.py - blue/green via ACA revision traffic
  weights (the smoke asserts the served CONTAINER_APP_REVISION), a rollback lane driven by the
  evidence/deploy_ledger.jsonl ledger (flip while the previous revision is alive, rebuild from the
  recorded image when it is gone), and a committed-YAML vs live drift gate that never prints env values.
  Measured live: PROMOTED and ROLLED BACK on the real app; drift honestly named a stale image.
- **Secretless CI image lane**: .github/workflows/ci-image.yml authenticates by GitHub OIDC federation
  (bts-sbom-ci app registration, AcrPush/AcrPull assigned via raw ARM after the CLI refused this
  subscription), gates on Trivy CRITICAL=0 before pushing, rotates the rollback tags
  (latest -> previous, new as v<version> + sha-<commit>).
- **Ubuntu CI green again**: five measured environment gaps repaired - Linux gcc's unconditional
  Unicode quotes normalized at both parser capture points, the SSE heartbeat test no longer races a
  fast stream (the turn deterministically outlives one interval), healthz's new revision field accepted,
  the marker-macro repair shape (expected ';' before 'static') added to the C repair loop, honest skips
  for the gitignored book corpus and PyYAML-dependent kubectl fixture.
- **Public access by owner decision**: the 401 callers saw was the app's own BTS_SBOM_ACCESS_TOKEN gate
  (never Easy Auth - az containerapp auth show returns {}); the token env was removed so evaluators open
  the app directly; the approval chain still guards patches and the daily LLM budget still caps spend.
- Deployed end to end: CI-gated images sha-5c7484b and sha-b03650a promoted to the live app through the
  blue/green lane; the committed applied YAML matches the live app ("no drift").

## 0.6.0 - 2026-11-28: Course re-analysis upgrades + CRA compliance + incident-response lane + governance/chat ops + oracle honesty

- **Full course re-analysis shipped (AC-1100..1263)**: every document of the Metanet course folder
  (PDF 23 / pptx 7 / xlsx 1 / zip 6) re-read in 27 agent groups against two repository searches each;
  116 remaining gaps merged into 87 scored candidates; 40 upgrades built in file-disjoint bundles,
  each adversarially reviewed and only reproduced defects fixed. Access-token gate for the UI.
- **CRA compliance lane (AC-1241..1246)**: security.txt (/.well-known, CVD contact knob), 5-year support
  verification, Article 14 reporting clocks (T0 -> 24h/72h/14d/1mo), readiness 8-check, Annex J registers;
  measured on u-boot: 37.5% -> 75.0% readiness, honest "미판정" where KEV/EUVD is not integrated.
- **Incident-response lane (AC-1261..1263)**: the KISA RFP mapped onto the product - a forward-only stage
  machine with the RFP SLA clocks, four report builders (초동/원인분석/증거체크리스트/대응방안 모음집),
  an IoC registry with supply-chain cross-check, and the 🚨 사고 대응 pane.
- **Governance + chat operations**: approval ledger (JSONL, digest-mismatch attempts recorded), an
  overridable remediation policy (validated atomically), honest blocked-lookup reasons, eval-candidate
  feed; chat turns gained cancellation between tool calls, an SSE heartbeat (BTS_SBOM_SSE_HEARTBEAT_SECONDS),
  and one trace_id linking request -> job -> SSE -> escalation (AC-1247..1260).
- **UI cards 19/27 tools + live HITL**: the a2ui-style card catalog covers 19 of 27 chat tools; the full
  approval chain was measured live on Azure (stale-token refusal, isolated apply 80.7s, source-boundary
  refusal) behind Easy Auth, BTS_SBOM_CHAT_ACTIONS=1.
- **Oracle honesty round (clean-room lane)**: FunctionTestCase suites (mimeparse 0.1.3 shape, 29 cases,
  zero TestCase classes) now run - the static skip note no longer outranks the shim's measured output;
  best-of-N parses `FAILED (failures=N)`; the LLM JSON envelope salvages bare backslashes. Measured
  mimeparse live: 14 -> 4 of 29 legacy failures, reproduced twice; the remaining 4 are named.
- **Azure operations**: system-assigned managed identity pulls from ACR (admin user OFF), nightly drift
  workflow (schedule-only, offline battery), CI quota discipline, the self-dogfood gate proves the
  stdlib-only claim (declared_runtime_deps=[]), and the repository is public.

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
