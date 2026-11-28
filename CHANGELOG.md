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

- **Full course re-analysis shipped (AC-1100..1240)**: every document of the Metanet course folder
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

## Unreleased - 2026-11-27: Full course re-analysis, 40 follow-up upgrades, access-token gate, Azure redeploy (AC-1100..1225)

- Analysis: every document of the course folder (23 PDF, 7 pptx, 1 xlsx, 6 zip) re-read in 27 groups and verified against the code; 116 remaining gaps merged
  into 87 candidates and scored by 3 independent lenses; the top ones built in 10 file-disjoint bundles, each reviewed by 2 adversarial reviewers and a refuting
  verifier (24 confirmed defects fixed). Full mapping, measured findings and the not-built list: `docs/METANET_FULL_REANALYSIS.md`.
- Security / deployment: `access.py` shared-secret gate (`BTS_SBOM_ACCESS_TOKEN`: Basic password / Bearer / `X-BTS-Token`, probes open, constant-time compare);
  `BTS_SBOM_ALLOWED_ROOTS` source boundary + non-public git host refusal (`workspace.py`); egress SSRF guard in `net.py`; `secretscan.py` (file+line+rule, never the value,
  skipped files make the scan partial); allowlist `.dockerignore` (the cloud build no longer uploads `evidence/` with the saved LLM key); `scripts/azure_render_app.py`.
- Chat: per-call tool isolation (`status: partial`), numeric-citation completeness, CaseFacts memory, escalation root cause, PII/secret redaction (`pii_guard.py`),
  contradiction gate, version stamp, nl2sql snapshot freshness; console shows handoff / which-project / partial-coverage / partial-turn / reviewer-note / version stamp.
- Measured upgrades: injection guard dev recall 0.48 -> 1.0 and holdout 0.182 -> 1.0 (false positives 0.0); English retrieval found 0.50 -> 0.812 with every Korean metric
  unchanged; NL2SQL per-package template fixed (EX no longer counts both-sides-failed as a match); RAG gate calibration (`evalrag --calibrate`).
- Red team (local instance, 3 agents, 48 attacks, 11 reproduced + verified, all fixed, AC-1230..1240): slowloris below the gate (read timeout + connection cap), uncached prompt digest per chat turn, legacy IPv4
  spellings through both SSRF guards (shared `netaddr.py`), file:// authority, DNS rebinding pin, failed-credential throttle, forwarded-for trust switch, deep-JSON RecursionError, Server header; live-only: the
  Container Apps ingress peer (100.100.0.x) was not treated as a proxy so per-caller limits never fired - fixed and re-measured live.
- Ops: LLM budget tiers, token/cost ledger, Retry-After, per-caller chat rate + concurrency caps, 4000-char question cap; MCP: operator-gated LLM, nl2sql tool/resource,
  prompts primitive, scan tool with progress; batch `--retry-failed`; `audit` sampling, `govgate` 6 gates, `prompts --update --require-loop-evidence`.

## Unreleased - 2026-11-26: Week 5-6 course analysis - coverage gaps, escalation, eval-set integrity, prompt registry (AC-1000..1088)

- Coverage gaps (`gaps.py`): a partial scan (offline, unqueried components, unsupported manifests, core data status, stage errors) is named in every chat
  answer, fleet query and analysis report; "not found in a partial scan" is "not verified", never "clean". Records without engine facts show no gap.
- Escalation (`escalation.py`): three triggers decided by code (human request, policy gap: legal judgment / certification, no progress: 3rd consecutive
  unanswered question), a structured handoff payload (question verbatim as an untrusted quote, attempted actions, evidence refs; no sentiment or confidence
  field), an append-only `escalations.jsonl`, resolution notes fed back as data, `GET /api/escalations` + resolve, CLI `escalations`. Ambiguous projects get
  a clarifying question instead of a guess; patch plans and VEX previews state decision / if approved / if not / deadline.
- Eval integrity (`evalguard.py`): per-segment retrieval metrics and a segment gate (a segment drop blocks even when the total is flat), eval-set fingerprint
  pin (another version = comparison undecidable; `ragloop --rebaseline REASON`, refused when no set changed), leak / duplicate / dangling-expectation check
  and composition table (`evalsets`). Measured: the holdout is clean; one dev query is copied into the corpus (warning); no English in-domain query exists.
- Prompt registry (`promptreg.py`, `evals/prompt_registry.json`, CLI `prompts`): 15 prompts fingerprinted from source (AST); drift, unpinned, missing and
  changed-without-PROMPT_VERSION-bump fail the check; loop passes record the prompt digest. RAG metrics unchanged (golden 1.0/0.95, dev 1.0/0.836, test 0.917/0.75).
- Docs: `docs/METANET_WEEK56_MAPPING.md` (what was inferred, what already existed, what was built, what was deliberately not built).

## Unreleased - 2026-11-24c: C/C++ support - clean-room reimplementation + compatibility gate (AC-637..644)

- `cparse.py`: stdlib C/C++ declaration reader + usage scanner (functions, types, enums with values, macros, variables, doc comments;
  bodies never stored). Vs Universal Ctags on u-boot: 625 headers recall 0.997 / precision 0.998, 0 crashes.
- `reimpl_c.py`: the clean-room lane for .c/.cc/.cpp (dispatched by `reimpl.reimpl`): interface-only reader, deterministic self-contained header,
  identifier-normalised token copy gate (numeric tables and forced prototypes are facts), real gcc compile + nm export proof, upstream test mains and a
  generated DIFFERENTIAL driver against the original built on this host (return values, output buffers, published tables), one regeneration from the
  observed mismatches. `contract_only` (never `ok`) when no oracle exists; `toolchain_missing` without a compiler.
- Original-build repairs for kernel-style code (include order, conflicting header stubs, typedef/marker/feature-macro repairs, header shadowing).
  Real GPL u-boot: lib/crc8.c (132 cases, 0 mismatches) and lib/crc16.c (function + 256-entry table) verified; 13 of 77 lib files build standalone.
- `compat_c.py`: C/C++ upgrade gate - header diff on the symbols the project uses (removed function/macro/enumerator/variable, call-argument count,
  removed struct field = breaking; value/type/layout = review) + compiler differential (`-fsyntax-only` old vs new headers) via dir/git-tag providers.
- Console: clean-room verdict card shows language/compile and the differential oracle. Docs: docs/CLEANROOM_C_CPP.md.

## Unreleased - 2026-11-24: Patch compatibility gate (AC-630..636)

- New `compat.py`: before a manifest is edited, every PyPI upgrade is measured against what the project actually uses
  (ast: imports, attribute chains, call-site shape, base classes) vs the public API of the current and target release
  (wheel/sdist parsed in memory, never executed), plus Requires-Dist pin conflicts in both directions. Verdicts:
  compatible / partial / review / breaking / unverified / not_direct - thin evidence is never "compatible".
- `block` (default) holds ONLY breaking plans (`patch.apply(hold=)`), applies the rest under the unchanged approval
  digest; all-held finishes as `compat_held` with 0 files written. `--compat off|warn|block`.
- Opt-in `--compat-runtime` (`compat_runtime.py`): the project's own tests before/after in throw-away venv copies
  (binary-only installs, minimal env); a passing-then-failing test reverts the patch (`compat_runtime_reverted`).
- Review gains RV-COMPAT-* / RV-RUNTIME-* rules; the patch pane shows the measured compatibility, held count and findings.
- `net.fetch_bytes` for bounded archive downloads. Limits (PyPI only, no type inference, C extensions unresolved):
  docs/COMPAT_GATE.md.

## Unreleased - 2026-11-23b: u-boot real-world E2E + Clean-Room workbench UI + honest scanning surfaces

- u-boot v2026.10 E2E measured end to end (evidence/uboot_e2e/E2E.md): scan 68 components / 43 advisories,
  GPL-2.0-or-later via SPDX-header majority; clean-room lane generated dtoc/src_scan.py from the spec only
  (copy gate 0.0, contract tests 5/0), oracle honestly compatibility_failed on the suite's POSIX-pty helper.
- Clean-Room workbench pane (🧬): the two-wall lane with its SSE stage strip and verdict cards, previously
  API/CLI only; dock chips/slash entries (라이선스 리스크·공급망 혼동, /reimpl, /license-risk).
- Live scan progress from the job SSE stream; honest "Unknown — not a pass" banner for 0-component/unknown runs.
- Project-copyleft duty finding for strong-copyleft projects under binary distribution + /api/policy
  distribution selector; setup.py disclosed in the core manifest roster.
- Adopted-oracle hardening (AC-616): package-import rebinding, helper resolution, mainless-suite injection,
  zero-test skips, shim argv/result fixes, 16384-token generation budget for reasoning deployments.
- Fixed: the db pane's first-render null binding killed the whole console init chain before loadHistory.

## Unreleased - 2026-11-23: Chat quality gates (TOP-10) + the approval loop as evidence + supply-chain pane + nl2sql lane

- Chat quality TOP-10 scorecard (`python -m bts_sbom_app.evals_top10` -> evals/top10_report.md): grounding F
  >= 0.90, completeness >= 0.90, read tool-call accuracy >= 0.95 (gated from the live suite log, regex floor
  documented beside it), write lane = 1.0 (every forged token/code/source/reason dropped, write tools never
  offered read-only), over-refusal <= 5% - each metric with its gate and a loop.gate delta (>= -0.02).
- HITL action runner (`scripts/chat_actions_run.py` -> evidence/chat_actions/report.json): the approval chain
  replayed end to end over real HTTP - analyse, plan + token, approve, applied in an isolated work copy, record,
  decision preview, confirm code, .triage.json, and the flag-less server refusing read-only (7/7 steps).
- Supply-chain substitution risks wired in: pipeline stage (typosquatting / namespace confusion / dependency
  confusion), `supply_chain` chat tool, and the Supply Chain pane renderer (was: honest placeholder).
- NL2SQL chat lane + DB query pane: nl2sql chat tool (read-only SELECT, 4-state honest results),
  POST /api/db/query + GET /api/db/schema, the DB pane, and scan-evidence seeding (scripts/seed_osv_local_db.py).
- Console UI states: dock fresh-conversation hint, thinking skeletons, stream-failure retry button, governance
  card skeletons, honest empty report tab; the db pane recovered its missing rpane div (+ the static
  GROUPS<->page pin that keeps it that way).

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

## 0.3.0 - 2026-11-21

### Arch Intel: license verdict + AI architecture deep-dive (`bts_sbom_app/arch_intel.py`, `bts_sbom_app/arch_api.py`, web pane)

One input (a local folder or a git URL) -> license verdict (category, obligations, per-distribution verdict,
GPL/AGPL notice checklist incl. AGPL §13, pairwise compatibility matrix) -> deterministic architecture facts
(entry points, import graph, hotspots, cycles) -> an EXAONE architecture lane that follows the ai.propose contract
(prompt-hash cache, four validation layers, honest deterministic fallback) -> component / sequence / activity
diagrams generated deterministically from the VALIDATED analysis -> bounded, syntax-highlighted code excerpts
anchoring the architecture in real files. Served under `/api/arch/...` (scan, jobs, SSE events, result, report
download, history) behind the same Host/CSRF guards as the OSS screen, and rendered in a new "Arch Intel" tab
(`web/arch_intel_render.js` pure renderers under the Node harness + `web/arch_intel.js` wiring).
Specs: BSA-AC-443..460. ADR-0014 documents the clean-room guardrails (the LLM prompt carries metadata only;
code-shaped model output is dropped; the analysed tree is never executed) and the vendored Mermaid asset
(`web/vendor/mermaid.min.js`, NOTICE.md, lazy-loaded, source-text fallback).

## Unreleased

### Course methodologies applied (`bts_sbom_app/`, docs) - offline-measured, not run on GitHub or in Docker

Chosen from the AI-application course material (weeks 1-4 plus the governance and portfolio guides) after checking what `main` and
`rel/v0.2.0` already had; all additive (no existing return value, status code or CLI argument changed). Specs: BSA-AC-301..400.

* **Circuit breaker and honest no-answer outcomes** (`resilience.py`, `net.fetch_json` / `fetch_text`): per-host breaker (3 consecutive
  failed calls -> open for 60 s -> one probe), four outcome states, `Retry-After` honoured (cap 30 s), `net.STATS` gains `short_circuited` /
  `empty` / `partial`. `http_json` / `http_text` keep their return values. `BTS_SBOM_BREAKER_THRESHOLD=0` switches it off. The existing
  callers (`licenses.py`, `osv.py`, `arch.py`) still use the unchanged wrappers, so they do not yet report the four states separately.
* **Patch regression quadrants and independent review** (`impact.py`, `review.py`, `pipeline._patch_loop`): direct / upstream / downstream /
  shared classification; a quadrant without data is `unverified`, never `ok`. From `_patch_loop` the fleet half of "shared" is always
  `unverified` (no fleet access there). The reviewer is advisory and takes artifacts only.
* **Scan progress events (SSE)** (`events.py`, `GET /api/jobs/<id>/events`, `run_project(progress=...)`), **`/healthz` and `/readyz`**,
  Dockerfile hardening (numeric non-root user, HEALTHCHECK) and `docs/RUNBOOK.md`. `docker build` was NOT run (no daemon in the build
  environment); the Dockerfile is only checked by static policy tests.
* **Design-rationale and governance pack**: `docs/adr/` (0007-0013, each with rejected alternatives), `docs/governance/` (AI impact
  assessment - a self-assessment, not legal advice -, model card, origin lineage, data contract), `docs/ENFORCEMENT_MAP.md`, and
  `python -m bts_sbom_app.doclint [--strict]` (new CI step).
* **Traceability and evidence**: `bts-sbom-app trace` (AC x module x test; `docs/TRACEABILITY.md`), `portfolio export`, `proof`
  (PASS / FAIL / NOT RUN; NOT RUN is never PASS; evidence sidecar). EARS State-pattern ACs go from 0 to 5.
* **Fixes found by an independent review of the above** (BSA-AC-358..360, 441, 442): a failed license lookup (outage or an open
  circuit) is no longer cached as "no license" for a week (`licenses.resolve` reports `lookup_unavailable`; before this the breaker
  could have turned a short blip into 7 days of missing licenses); a late failure of a call that began before the breaker opened can no
  longer reopen it under the half-open probe; `portfolio export` and the enforcement-map check refuse paths that leave the repository
  (symlinks, `..`, absolute paths); the in-memory event buses are capped at 64 (closed ones go first).


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
* **Repository context pack** (`bts_sbom_app/contextpack.py`, command `contextpack <folder> [--package P] [--cxml]`): bounded read-only view of a local tree - license files plus the import sites of one package with context; binaries, oversized files, node_modules and symlinks excluded and listed; all text untrusted (escaped CXML, instruction-like files flagged); import sites are candidates, reachability stays unknown; `verify_site` re-confirms a path:line. Spec BSA-AC-223..181 and 211..215; `evalchat` measures the routing baseline (BSA-AC-209).
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

### `bts_sbom_app/` - CVSS v4.0 scoring

* **CVSS v4.0 scores** (`cvss4.py`, tables in `cvss4_data.py`): findings whose advisory has a v4 vector are scored instead of falling back to the
  advisory label or UNKNOWN. A faithful port of FIRST's reference calculator (270 macro vectors, severity-distance interpolation, threat and
  environmental metrics, specified defaults); invalid or incomplete vectors give no score. The tables come from FIRST's `cvss-v4-calculator`
  (BSD-2-Clause, notice kept in `cvss4_data.py`, sha256 of the source files recorded there), downloaded 2026-11-20 with the user's permission and
  turned into a data module by a generator that checks the 270 valid keys. `cvss.severity_of(prefer=)` / `BTS_SBOM_CVSS_PREFER=v4` choose the
  primary version (default v3, so existing scores do not move; Hub prefers v4); records keep `cvss_v3` / `cvss_v4` when present and the CycloneDX
  vulnerability gets one rating per version with its `method` (CVSSv4 / CVSSv31). Verified against 25 published FIRST examples (25 of 25).
* Spec: BSA-AC-250..254; tests: `tests/bts_sbom_app/test_cvss4.py`.

## 0.2.0 - 2026-11-17

BTS-SBOM 0.2.0 adds the end-to-end workflow layer next to the core (second package `bts_sbom_app/`, same distribution, still zero
third-party runtime dependencies) and repairs the core's console-encoding crash and its red CI.

### `bts_sbom_app/web/` - governance panes on the open-source security screen

The data of the governance features above is now visible without calling the endpoints by hand. Nothing in the six copied platform files changed (pins and BSA-AC-75/83 still match).

* **New tabs**: Findings -> *What changed* (`/api/changes`: verdict, 8 count cards, alerts, new / resolved / rescored findings, version and licence changes, copyleft
  introduced; "nothing to compare" when the project was analysed once), Compliance -> *SBOM conformance* (`/api/conformance`: verdict per regime with the
  **DRAFT** flag, the review date of the regime table with a **Review due** flag when it is 6 months or more old, and an always-visible "not a legal assessment" line, per-element coverage matrix, "fix once, satisfy many" ranking; NO_DATA and errors are
  stated, never a verdict) and *VEX - Decisions* (`/api/vex`: the OpenVEX with decisions applied, what each decision did, the recorded decisions with expired ones
  marked), CI/CD - History -> *Fleet - Affected* (`/api/fleet`, `/api/affected`: ranking with the age of each analysis, shared advisories and components, search by advisory,
  component and version constraint; "not found" is never worded as "unaffected").
* **Decision form** (VEX - Decisions): finding, decision, the five OpenVEX justifications, reason, end date, scope, owner. The page says that without a justification
  and a reason of at least 10 characters a false positive stays *affected*, and a live line shows the effect on the OpenVEX statement; that prediction is a mirror of
  `triage.decide` and a test compares it with the service for 375 input combinations. Nothing is preselected.
* **Honesty**: every value from analysed data is escaped in one place (`bts_ui.js`; a JSON object with an `html` key can no longer pass as markup - the old `{html}`
  duck-typing of `cell()` is gone); an absent field is a dash, never a default 0; a score that is only the floor of a severity label reads `>= 7.0 (label)`; a cut list says
  "first N of M".
* **Fixed**: the VEX pane still said decisions were "not yet written into the OpenVEX file", and the SBOM-documents pane said no NTIA score is computed; both were stale since
  the governance features. The OpenVEX button there is now labelled "as analysed" and points to the decision-aware download.
* New files `web/bts_ui.js`, `web/bts_governance.js`; `bts_console.js` now only fetches and wires. Spec: BSA-AC-226..240; tests: `tests/bts_sbom_app/test_governance_ui.py`
  (render/form tests run the page scripts under Node via `tests/bts_sbom_app/js/render_harness.js` and skip when Node is absent; the fetch + wiring in `bts_console.js` was
  checked by hand in a browser and by the page-shape test, there is no DOM test).

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

### OSS scanners and OSS notice automation (`bts-sbom oss ...`, `bts-sbom notice`)

* **FOSSLight-style scanner suite, native and offline** (standard library only; reimplemented from FOSSLight's public user guides - no FOSSLight
  code is used; the GPL-3.0 Prechecker was written clean-room from the REUSE specification): source scanner (SPDX tags, license headers, LICENSE
  files, copyrights, package identity, license/NOTICE text capture, default-exclusion flags), dependency scanner (static parsing of npm/yarn/pnpm,
  pip incl. setup.py/uv.lock, maven/gradle, cocoapods, carthage, swift, pub, go, nuget, helm, unity, cargo - no package manager is run),
  binary scanner (magic-byte detection, hashes, local KB match, JAR/pom analysis, version banners, embedded Go/Rust/.NET/ELF metadata),
  Yocto scanner (bom.json, buildhistory, installed packages, license.manifest), Android scanner (module-info, MODULE_LICENSE, NOTICE states),
  and a REUSE-style precheck (lint / add / convert / download). TLSH matching against FOSSLight's Binary DB, SCANOSS and the LGE KB are not implemented.
* **One report model** (`bts_sbom/ossreport.py`) with FOSSLight-Report column names; xlsx / csv / json / yaml / spdx-json / spdx-tag /
  cyclonedx-json / cyclonedx-xml output, xlsx / json / yaml input, `sbom-info.yaml` corrections (stdlib YAML-subset reader), report compare.
* **OSS notice generator** (`bts_sbom/notice.py`): html, text, simple-html, simple-text (en / ko). License texts come from the component's own
  license file, a local directory or - only on request - the SPDX list; a missing text, license or copyright is reported in an audit and never
  invented; the source-code written offer is an opt-in template that needs a contact and is flagged for legal review.
* **Targets**: folder, archive (zip family, tar family, bz2, gz, rpm / src.rpm), git URL, archive URL - safe extraction limits, hooks-off shallow
  clone, dangerous transports refused. **Web console**: a new "OSS Scanner" tab (scan stages, result tables, license risk tiers, downloads, notice,
  previous scans, compare) backed by `bts_sbom_app/oss_api.py`; every request must carry the service's own Host (DNS-rebinding guard), mutating
  requests from another origin / `Sec-Fetch-Site: cross-site` are refused, URL targets resolving to non-public addresses are refused
  (`BTS_OSS_ALLOW_PRIVATE_HOSTS=1` to opt in), cancel works mid-walk / mid-extraction / mid-download / mid-clone.
* **Hardening found by an adversarial review of the suite and fixed with regression tests**: Prechecker `add` writes through one verified
  descriptor (no symlink/hard-link redirect between check and write); `WITH` exceptions are kept in licenses and their texts required; notice
  flags `needs_check` (unverified) licenses in the audit, the document and `--strict`, and keeps `AND`/`OR`/`WITH` in HTML; rpm payloads
  are inflated as a bounded stream (decompression bomb), corrupt cpio is a clean error; XML goes through `safe_xml` (DOCTYPE/ENTITY refused in any
  encoding or position); reports carry `Needs Check` / `Notice Status`; SPDX tag-value injection closed and CycloneDX `bom-ref` made unique; the YAML
  writer/reader round-trips multi-line strings exactly and reads multi-line flow collections with quoted brackets; Podfile.lock `direct` is
  per full subspec name; pnpm v9 peer-suffixed snapshots and single-line uv.lock arrays are read; a POST with a bad `Content-Length` is a
  400/413 instead of a crash or a hang (applies to the whole app server); finished/failed scan jobs no longer accumulate in memory.
* Design, FOSSLight mapping, limits: `docs/OSS_SCANNERS.md`.

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
