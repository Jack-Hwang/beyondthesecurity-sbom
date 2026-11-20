# Changelog

All notable changes to bts-sbom are documented here.

## Unreleased

### `bts_sbom_app/`

* **Loop gate no longer passes on absent evidence** (`loop.gate`, `run_rag_pass`): a blocking metric the baseline has but the candidate
  lacks is `undecidable` and blocks acceptance; component/vulnerability counts are gated (blocking below 50% of the baseline, advisory
  for smaller drops). New `gate["undecidable"]` field. A pass that previously compared fewer metrics may now roll back - that is intended.
* **Chatbot plans its tool calls with the LLM** (`--llm`): read-only tools incl. new `what_if_upgrade`, plan validated (tool, arguments,
  component names that exist in the project, advisory ids well-formed - an absent id gets an honest "not present" answer; the model sees only trusted passages), regex router kept as the stated fallback (`routing`, `routing_note`). Costs one extra LLM call per
  question against the daily budget. Paraphrase baseline of the regex router: 0 of 5 (`evals.chat_paraphrase_eval`).
* **Chatbot hardening**: an unknown `project` id answers `found=false` instead of the only loaded project; advisory text is a separate
  `untrusted-quote` passage (`contains_untrusted`).
* **License council** (`bts_sbom_app/council.py`, commands `council` and `evallicense`): several models read unresolved license evidence
  independently, review each other anonymously, a chairman picks; the decision is code (2/3 endorsement, < 1/3 abstaining, verbatim quote,
  known SPDX ids) and a reading that conflicts with the deterministic one is `needs_human`. Suggestions only - nothing is written into a
  component's license. Needs `BTS_SBOM_COUNCIL_CONFIG` with >= 2 members; 7 calls per item for 3 members. New `evals/license_gold.json`
  (44 hand-written cases) with a measured deterministic baseline: 21 correct / 6 confident wrong / 10 missed / 7 abstained correctly.
  `licenses.scan_tree` now keeps a 3000-character excerpt of undetected license files; `LGPLv2+` is no longer returned verbatim as an SPDX id.
* **Repository context pack** (`bts_sbom_app/contextpack.py`, command `contextpack <folder> [--package P] [--cxml]`): bounded read-only view of a local tree - license files plus the import sites of one package with context; binaries, oversized files, node_modules and symlinks excluded and listed; all text untrusted (escaped CXML, instruction-like files flagged); import sites are candidates, reachability stays unknown; `verify_site` re-confirms a path:line. Spec BSA-AC-176..181 and 211..215; `evalchat` measures the routing baseline (BSA-AC-209).
* Spec: BSA-AC-88..112; tests: `tests/bts_sbom_app/test_council.py`, `evallicense --max-cases N` bounds a council run (44 cases x 7 calls = 308 calls for 3 members).
* Spec (earlier line, kept for the chat/gate part): BSA-AC-88..96, 97, 98; tests: `tests/bts_sbom_app/test_chat_tools_gate.py`.

### `bts_sbom_app/` - SBOM governance and vulnerability follow-up (from the 6th FOSSLight Community Day, 2026-10-28)

Inferred from the talk topics (changing SBOM regulations, Hub's strengthened vulnerability handling, Hub + Enterprise operations); the
slides themselves were not read - see `docs/FOSSLIGHT_COMMUNITY_DAY_ANALYSIS.md` for the evidence, the inference and what was left out.

* **SBOM conformance matrix** (`conformance.py`, command `conformance`, `GET /api/conformance/<project>`): one CycloneDX / SPDX document checked
  against NTIA 2021, the CISA 2025 draft, EU CRA Annex I Part II(1), BSI TR-03183-2 and a vulnerability/VEX-readiness baseline, with per-element
  coverage and a "fix once, satisfy many" ranking. Absent evidence is a gap; the regimes are a checked subset with a review date
  (`as_of`), not a legal assessment. `--require REGIME` gates CI. Every analysed project now records its matrix, and the CycloneDX declares
  `metadata.lifecycles` = `pre-build` when it was made from source manifests (CISA generation context).
* **Change tracking and alerts** (`changes.py`, command `diff`, `GET /api/changes/<project>`): a second analysis keeps the earlier record as
  `<name>.prev.json` and attaches `changes`; also compares two records or two SBOM documents. Alerts follow Hub's mail rule (finding at or
  above the threshold appears / an existing one crosses it up or down) plus malicious package and copyleft introduced; unscored findings count
  as the lower bound of their label. `--fail-on-alert` for CI; nothing is sent. `--llm` narrative is verified against the computed facts.
* **Triage -> OpenVEX, fail-closed** (`triage.py`, command `vex` / `review`, `GET /api/vex/<project>`, `POST /api/triage` extra fields
  `justification`, `expires`, `scope`, `by`): closes the documented gap that console decisions never reached the OpenVEX document.
  `false-positive` is `not_affected` only with an OpenVEX justification and a 10+ character reason; acceptances stay `affected` with owner and
  end date; expired decisions reopen; a `fixed` claim the scan contradicts is refused; scoped decisions (`ID@package`) beat global ones.
  `sbom.openvex(..., triage=, today=)` and `sbom.cyclonedx(..., lifecycle=)` gained optional arguments.
* **Affected-projects lookup and portfolio roll-up** (`fleet.py`, command `fleet`, `GET /api/fleet`, `GET /api/affected`): which analysed projects
  use a component (with version constraints such as `<2.20,>=2.0`) or are hit by an advisory (any alias); versionless components are reported as
  `version_unknown`; the roll-up lists weighted ranking and advisories / components shared by projects.
* **Decision coverage graph** (`coverage.py`, command `coverage`, `GET /api/coverage/<project>`, chat tool `coverage` - the tool catalog is now 21):
  which advisories a standing decision or a verified plan already handles and which are still open - decided / planned / rejected / expired /
  unhandled per advisory (fail-closed through `triage.decide`), the unhandled worklist, every applied decision anchored to its advisory
  (key, state, owner, time) and a per-advisory `finding -> plan/decision -> outcome` chain. Concept after ARTEX's dual-graph architecture
  (github.com/Autumn-27/ARTEX, AGPL-3.0 - idea credit only; no ARTEX code or text is used). Computed from recorded data only: unhandled does
  not mean unexamined, and a verdict never implies reachability. Spec BSA-AC-219..222; tests: `test_coverage.py`.
* **Chatbot**: three more read-only tools (12 in total): `affected_projects` (answers without naming a project), `sbom_conformance`,
  `what_changed`; the LLM planner may choose them, the regex router is the fallback. Knowledge file `knowledge/domain/sbom_governance.md`
  (retrieval metrics unchanged: golden 1.0 / 0.95, dev 1.0 / 0.869, held-out test recall 0.917, MRR 0.715 -> 0.711).
* **FOSSLight Scanner features integrated** (guide fosslight.org/fosslight-guide/scanner/; FOSSLight Scanner is Apache-2.0, feature
  inspiration credited, code is ours): `srcscan <folder>` walks a LOCAL tree per file - SPDX-License-Identifier tags, copyright lines
  (license files included) and every license-named file detected by text, with the FOSSLight "Scanner Info" header (tool, version,
  started, path, excluded: skipped dependency folders, links, binaries, oversized, unreadable) and CSV output; `binscan <folder>`
  collects the binary list (NUL-sniff) and extracts bounded license/copyright **string evidence** - this tool ships no binary DB, so
  it is a lead for a human, never an identification, and nothing is unpacked or executed; `selfcheck <project>` (`GET
  /api/selfcheck/<project>`, CSV download button in the License Risk pane) generates the FOSSLight-style self-check sheet from the
  record - OSS Name / Version / License / Category / Source / Ecosystem / Vulns, unresolved licenses stay empty. Dependency scanning
  and compare (`diff`) were already covered by the pipeline; Excel output is deliberately replaced by CSV (zero third-party
  dependencies). Spec BSA-AC-223..225; tests: `test_fosslight_scan.py`.
* Spec: BSA-AC-150..175 and 219..222 (BSA-AC-95 now counts 21 tools); tests: `test_sbom_conformance.py`, `test_changes_triage.py`, `test_fleet_chat.py`, `test_coverage.py`.
* Not done (needs input we do not have): CVSS v4.0 scoring (needs the official macro-vector lookup table), FOSSLight Scanner report import
  (needs sample files), web-console panes for the new data (API and CLI only).

### `bts_sbom_app/` - chat-driven analysis, approved patching and VEX decisions

* **Chat actions** (`actions.py`, `chat --actions [-i]`, `serve --chat-actions`): in a session opened with actions the chatbot can analyse a source
  (isolated work copy, normal pipeline), apply an approved patch and record a VEX decision; the default session stays read-only. Every effect keeps
  its gate and only the user's own text can open it: a patch needs the 16-hex approval token of exactly the plan that `plan_patch` showed (computed
  from the recorded plans, so a token for all upgrades does not open a subset), is applied for ONE round (no follow-up plans nobody approved), is
  re-scanned and reverted on a regression, and ends as a branch in the work copy - nothing is pushed, the origin is never written; a VEX decision
  is previewed (effect under the triage rules, nothing written) and recorded only with the 12-hex confirm code of that exact content (staged in
  `.pending_decisions.json`, 24 h, content-hashed). `validate_calls(calls, rec, question)` drops a token, source, confirm code or reason that is not
  verbatim in the question and a justification the user did not name, so a model plan cannot authorise anything; regex-built calls pass the same
  validator.
* **New chat tools** (20 in total, 3 of them offered only to sessions with actions): `license_risks` (policy screening per distribution model, obligations,
  unresolved licenses), `proposals` (LLM-written ones are tagged untrusted-quote), `plan_patch`, `export_vex` (writes `<project>.triaged.vex.json` only
  with actions), `record_decision`, `analyze_project`, `apply_patch`, `confirm_decision`. Routing measured in `evals_chat.py`: regex router 2 of 8
  paraphrased governance questions, LLM planner 8 of 8 (a forged reason is not credited: 7 of 8).
* **Regime table review date**: the conformance result, Markdown, record and chat answer say when the table was last reviewed and flag a review as
  due after 6 months.
* **EXAONE connection from the web console** (`POST /api/llm`, engine bar of the page): an API key typed into the page connects the AI for upgrade
  proposals and LLM chat planning without a restart; with `save` it is kept in `evidence/.llm_config.json` (plain text - the evidence folder is local)
  and a restarted server reconnects from it, while an explicit startup configuration (env / `--llm-config`) still wins. `POST /api/llm/clear`
  disconnects and removes the saved file. The status shows at most the last 4 characters of the key, never the key itself; only a localhost
  base_url may connect without a key. Spec: BSA-AC-216..218; tests: `test_server_cli.py`.
* Spec: BSA-AC-200..210 (BSA-AC-95 now counts a catalog of 20 tools); tests: `test_chat_actions.py`, `test_sbom_conformance.py`.

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
