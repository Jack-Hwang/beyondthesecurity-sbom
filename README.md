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
{ "bomFormat": "CycloneDX", ... "dependencies": [{ "ref": "pkg:pypi/bts-sbom@0.5.0", "dependsOn": [] }],
  "compositions": [{ "aggregate": "complete", ... }] }
```

## What's new since 0.5.0 (unreleased) — u-boot clean-room E2E + workbench UI + honest banners

- **u-boot v2026.10 real-world E2E** (`evidence/uboot_e2e/E2E.md`): scanned 68 components / 43 advisories
  (CRITICAL certifi, urllib3, jinja2) out of a 388 MB C tree, project license GPL-2.0-or-later from SPDX-header
  majority; clean-room lane really generated `tools/dtoc/src_scan.py` from the spec (copy gate 0.0, contract
  tests 5/0) and graded the upstream oracle honestly (compatibility_failed: the suite's helper needs POSIX pty).
- **Clean-Room workbench pane** (🧬 Clean-Room): POST /api/reimpl + job SSE rendered as a per-stage strip
  (interface → spec → code → copy gate → contract tests → adopted oracle) with the verdict record.
- **Live scan progress**: the step bar consumes the job's SSE stream (stage names + done counts) instead of only
  ticking seconds; the honest "Unknown — not a pass" banner replaces a green pass on 0-component/unknown runs.
- **The project's own copyleft duty**: a GPL project screened for binary distribution now yields the
  source-offer finding (u-boot's duty was invisible before); the License Risk pane gains a distribution selector
  (GET /api/policy/<project>?distribution=); setup.py manifests are disclosed, never silent.
- **Adopted-oracle hardening**: package-context imports rebind to the NEW module, helper packages resolve from
  the source tree, mainless TestCase suites get a runner tail injected, zero-test files are recorded skips, and
  the generation budget covers reasoning deployments (16384).

## What's new since 0.5.0 (unreleased) — chat quality gates + the approval loop + supply-chain pane

- **Chat 품질 TOP-10 스코어카드** (`python -m bts_sbom_app.evals_top10`, `evals/top10_report.md`): grounding F
  (claim support × source coverage), completeness of procedure answers, tool-call accuracy from the live suite
  log, forged-write blocking, and the over-refusal rate - each with its gate and a per-metric loop.gate delta
  (>= -0.02). No LLM judge: grounding is quote-in-document computation.
- **HITL approval chain as replayable evidence** (`scripts/chat_actions_run.py`,
  `evidence/chat_actions/report.json`): analyse -> plan + 16-hex token -> approve -> applied in an isolated work
  copy -> record -> VEX decision preview -> 12-hex confirm code -> .triage.json, plus the flag-off server
  refusing read-only. 7 of 7 steps over real HTTP.
- **Supply-chain substitution risks wired in**: the core analyzer (typosquatting, npm namespace confusion,
  dependency confusion) now runs in the pipeline, answers the `supply_chain` chat tool, and renders in the
  ⛓ Supply Chain pane.
- **NL2SQL chat lane + DB query pane** (AC-602..604): natural-language questions over the local OSV database
  (`POST /api/db/query`, `GET /api/db/schema`, 🗄 DB 질의 pane, dock chip), seeded from scan evidence
  (`scripts/seed_osv_local_db.py`).
- **Console UI states**: fresh-conversation hint and thinking skeletons in the chat dock, a retry button after a
  failed stream, skeleton loaders on the governance cards, and an honest empty state for the report tab.

## What's new in 0.5.0 — clean-room reimplementation + architecture tools

The headline of this release: the toolkit no longer only *scans* — it can now **re-implement** a
compliance-risky legacy component from its measured architecture, prove the result, and publish it:

- **Clean-room reimplementation workbench** (`bts-sbom-app reimpl <source> --component <module>` /
  `POST /api/reimpl`): interface spec -> NEW code generated behind a two-wall process (the generator
  never sees the original source) -> measured copy gate (line-shingle overlap with docstrings excluded
  as spec-derived) -> generated contract tests **plus the upstream legacy test suite** adopted as the
  behaviour oracle (run under a legacy-runtime shim for 2008-era runners) -> best-of-N candidates by
  measured compatibility -> publish. Every stage streams live (`adopted_tests_passed`, `copy_gate`,
  `published`, ...). Batch-verified on 64 real legacy PyPI packages (dataset: 146 rows, 32 packages
  through the lane, 31/32 behaviour-compatible in the latest run; full analysis in
  `evidence/reimpl_batch/ANALYSIS.md`).
- **Architecture tools**: DGML export of the measured import graph
  (`arch --dgml`, opens in VS Code Maps) with directory groups, hotspot/cycle categories and a
  layer-validation map (`arch --dgml-layers`); layer validation with declarative deny-list semantics —
  ForbiddenNamespace deny-lists, obsolete layers, unique names, moniker ambiguity, participation
  opt-out — and VS's own error message wording.
- **Book knowledge base**: two-tier extraction of local PDF/EPUB libraries (stdlib EPUB spine parsing,
  pdftotext subprocess with honest skips, SHA-256 dedupe; serve-time-only raw index + distilled notes;
  eval-corpus isolation measured, ADR-0021). `book_search` chat tool, `/api/books/*`, Book KB tab.
- **MCP server** (`python -m bts_sbom_app mcp`): Model Context Protocol over stdio JSON-RPC 2.0 —
  tools/list, tools/call, resources/list, resources/read; the tools delegate to the real modules.
- **A2A-style agent card** (`GET /api/agent-card`): 7 skills with their real gates, honest
  securitySchemes, and the MCP surface.
- **Chatbot upgrades**: multi-turn conversation memory with deterministic follow-up resolution
  ("그중 HIGH만 보여줘" now routes with the previous turn), compound-question decomposition,
  lost-in-the-middle passage reordering, 7-event chat-level SSE with a HITL approval gate, and the
  VS error-message wording for layer findings.
- **Ops**: supply-chain gate measured end to end (docker build -> Trivy CRITICAL gate -> CycloneDX SBOM
  -> own-repo SBOM -> /healthz bench), RUNBOOK/capacity docs updated with the measured delivery state.

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

## Tutorials (교육 자료)

3-step education track (Korean, workshop-ready) in [`tutorials/`](tutorials/):

1. [SBOM 기초와 실습](tutorials/01_sbom_basics.md) — what/why, SPDX vs CycloneDX, NTIA minimum elements, hands-on build
2. [OSV 취약점 스캔과 수정 제안](tutorials/02_vulnerability_scan.md) — Google OSV scan, guided remediation, CI policy gate
3. [섹터 규제 컴플라이언스](tutorials/03_sector_compliance.md) — one SBOM against CRA · FDA 524B · UNECE R155/R156 · EO 14028 · finance · robot

Example inputs live in [`examples/`](examples/).

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

## Implementation status (구현 내역)

Implemented as of 2026-11-20 (module → capability → tests). The core (`bts_sbom`):

| Module | Implements | Key API / CLI | Tests |
|---|---|---|---|
| `sbom.py` | SPDX 2.3 generator (content-digested namespaces, real-graph DEPENDS_ON only, honest `NOASSERTION` licensing) | `build_spdx_document()`, CLI `sbom` | pkg suite |
| `_internal/sbom.py` | CycloneDX 1.6/1.5 builder with NTIA element coverage | `bom` output / CLI `sbom --fmt` | pkg suite |
| `osvscanner.py` + `_internal/osv_client.py` | **Google OSV integration** — api.osv.dev `query`/`querybatch`, alias grouping, CVSS v3.1/v4.0 scoring, parallel queries | CLI `scan` | pkg suite |
| `_internal/osv_local_db.py` | OSV bulk-dump offline mode (GCS public data, sqlite cache) — air-gapped scanning | `BTS_SBOM_OSV_DB_PATH` env | pkg suite |
| `_internal/version_match.py` | PEP 440 (pip) + semver (npm/cargo/go) range matching against OSV ranges — precise match verdicts with explanations | `match_range()`, `explain_match()` | unit table |
| `_internal/remediation.py` | guided remediation — minimal fixed-version suggestion from OSV `fixed` events; `no-fixed-event` stated honestly | scan `remediation` block, `--no-remediation` | unit |
| `_internal/policy.py` | policy engine (Black Duck-style) — severity/license deny rules → CI gate exit codes | CLI `policy` (exit 1 = fail) | unit |
| `vex.py` | OpenVEX v0.2.0 generation + ingestion (reachability-driven `not_affected`, auditable suppression) | `statement()`, `build_document()`, CLI `vex` | pkg suite |
| `reachability.py` | C/C++ function-level call-graph reachability for CVE triage with graph-completeness evidence | `reachability` API | pkg suite |
| `sectors.py` | **6-sector regulatory reports** — cra (5 reqs) · fda (5) · r155 (4) · dod (4) · finance (4) · robot (4); verdicts pass/gap/not_evidence with measured evidence | `sector_report()`, `write_evidence()`, CLI `sector` | 42 tests |
| `supply_chain.py` | typosquat / homoglyph / dependency-confusion detection | `supply_chain` API | pkg suite |
| `_internal/ntia_check.py` | NTIA minimum-elements scoring (SPDX + CycloneDX), reused by sector profiles | `evaluate()` | ntia tests |
| `_internal/manifests/*` | lockfile/manifest parsers: npm, pip, gomod, cargo, maven, nuget, gradle, mix, conan, dpkg, rpm (+extras) | `manifests` API | pkg suite |
| `_internal/{epss_kev,epss_offline}.py` | EPSS scores + CISA KEV curation (online + offline tables) | vuln enrichment | pkg suite |
| `_internal/{license_spdx,license_norm,license_scan,license_categories}.py` | SPDX expression parsing/normalization/scanning, license risk categories | license inventory | pkg suite |
| `_internal/{fix_planner,callgraph,points_to,depsdev}.py` | fix planning, call-graph, points-to facts, deps.dev enrichment | internal APIs | pkg suite |

Cross-platform: Windows / Linux / macOS (CI matrix `ubuntu-latest, windows-latest,
macos-latest` × Python 3.10/3.12; UTF-8 enforced on Windows jobs). Zero
third-party runtime dependencies — asserted by the self-SBOM.

The 0.2 workflow layer (`bts_sbom_app/`, same distribution, standard library only, built on top of the core without modifying its files):

| Module | Implements | Key API / CLI | Tests |
|---|---|---|---|
| `workspace.py`, `pipeline.py`, `engine.py` | clone/read a source → one analysis record (SBOM, licenses with provenance, OSV findings, remediation, architecture) | `run_project()`, CLI `scan` / `batch` | app suite |
| `remediate.py`, `patch.py`, `deliver.py` | OSV-re-verified upgrade plan; **approval-gated** manifest patch with re-scan and revert on a regression; delivery (branch / folder / inplace / GitHub PR) | `patch --approve --token`, `--deliver` | `test_patch_delivery.py` |
| `licenses.py`, `council.py` | license resolution with recorded provenance; multi-model license **council** with a chairman decision (suggestions only, nothing written) | `council`, `evallicense` | `test_council.py`, `test_engine_licenses.py` |
| `conformance.py`, `changes.py`, `triage.py`, `fleet.py` | SBOM conformance matrix (NTIA 2021, CISA 2025 draft, EU CRA, BSI TR-03183-2) with a review date; diff alerts; **fail-closed** triage → OpenVEX; portfolio lookup | `conformance`, `diff`, `vex`, `fleet` | `test_sbom_conformance.py`, `test_changes_triage.py`, `test_fleet_chat.py` |
| `coverage.py` | **decision coverage graph**: per advisory, whether a standing decision or a verified plan already handles it (decided / planned / rejected / expired / unhandled), the unhandled worklist, decision lineage and `finding → plan/decision → outcome` chains (concept after ARTEX's dual-graph architecture, reimplemented) | `coverage`, `GET /api/coverage/<project>`, chat `coverage` | `test_coverage.py` |
| `srcscan.py`, `binscan.py`, `selfcheck.py` | FOSSLight Scanner features rebuilt on this package's rules: per-file source scan (SPDX tags, copyright lines, license files) with the FOSSLight Scanner-Info header, binary list + embedded license/copyright **string evidence** (no binary DB - a lead, not an identification), and the self-check sheet as CSV from the record | `srcscan`, `binscan`, `selfcheck`, `GET /api/selfcheck/<project>` | `test_fosslight_scan.py` |
| `chat.py`, `rag.py`, `actions.py`, `evals_chat.py` | grounded chatbot (20-tool catalog, the LLM plans the calls, the validator drops forged authority); **chat actions**: analyse / approved patch / VEX decisions, each behind user-typed approvals | `chat [--actions]`, `evalchat` | `test_chat_tools_gate.py`, `test_chat_actions.py` |
| `contextpack.py` | bounded read-only view of a local tree: license files + the import sites of one package; binaries, oversized files and symlinks excluded and listed; all text untrusted | `contextpack [--package P] [--cxml]` | `test_contextpack.py` |
| `console.py`, `server.py`, `web/` | Open-Source Security web screen + JSON API; EXAONE key connection from the page (`POST /api/llm`, masked status, saved key file) | `serve [--chat-actions]` | `test_server_cli.py`, `test_console_ui.py` |
| `llm.py`, `ai.py` | EXAONE / OpenAI-compatible client with a daily-budget ledger; LLM upgrade proposals behind a four-layer validator | `BTS_SBOM_LLM_CONFIG`, `EXAONE_API_KEY` | `test_ai_rag_loop.py` |
| `loop.py`, `evals.py` | loop-engineering harness: golden/dev/test sets, regression gate where absent evidence is `undecidable` and blocks acceptance | `loop`, `ragloop`, `evalrag` | `test_ai_rag_loop.py` |

## End-to-end workflow: analyse, patch, architecture, chatbot (`bts_sbom_app/`, command `bts-sbom-app`)

Part of BTS-SBOM: a second, standard-library-only package in this repository (`bts_sbom_app/`, command `bts-sbom-app`),
built **on top of** the `bts_sbom` core (one adapter, `bts_sbom_app/engine.py`; the core's files are not
modified). It turns the core's scan into an end-to-end workflow: clone or read a
source, SBOM (CycloneDX 1.5 / SPDX 2.3 / OpenVEX), license resolution with provenance, OSV findings with alias merge,
a remediation plan re-verified against OSV, **approval-gated** manifest patching with re-scan verification and revert, legacy
architecture analysis (hotspots, change coupling, import cycles, runtime EOL), industry reports (defense, automotive, medical,
finance, maritime draft, CRA, robot), LG EXAONE proposals behind a four-layer validator with a deterministic fallback, a grounded
RAG chatbot, and a measured loop-engineering harness.

What 0.2 and the work after it added (every feature spec'd in `specs/bts_sbom_app_features.md` with measured acceptance criteria):

* **Governance** (BSA-AC-150..175, 219..222): SBOM conformance matrix (NTIA 2021, CISA 2025 draft, EU CRA, BSI TR-03183-2) with a "fix once, satisfy many"
  ranking and a regime-table review date; Hub-style diff alerts; triage decisions that reach OpenVEX fail-closed; fleet lookup across all analysed
  projects; and the decision coverage graph — which advisories are handled (decided / planned) vs still open, with the lineage of every recorded
  decision (concept after ARTEX's dual-graph architecture, reimplemented from scratch); FOSSLight Scanner features (source scan, binary string
  evidence, self-check sheet) rebuilt with honest bounds and the License Risk pane styled after the FOSSLight report.
* **License council** (BSA-AC-88..112): several models read unresolved license evidence independently, review each other anonymously, a chairman
  picks; deterministic baseline measured on 44 hand-written cases.
* **Chat** (BSA-AC-88..98, 200..210): the LLM plans tool calls against a 21-tool catalog (regex fallback, its misses measured by `evalchat`); with
  `--actions` the chatbot can also analyse a source (isolated work copy), apply an approved patch and record VEX decisions — only a token or confirm
  code typed by the user authorises anything, a model-invented one is dropped.
* **Web console** (BSA-AC-216..218): the Open-Source Security screen + JSON API; the EXAONE key can be entered in the page (`POST /api/llm`) —
  proposals and chat planning use the AI immediately, the key survives a restart in `evidence/.llm_config.json` when saved, and Disconnect removes
  it; responses show at most the last 4 characters of the key.
* **Evidence plumbing**: the repository context pack (BSA-AC-176..181, 211..215) and a hardened loop gate where absent evidence is `undecidable`
  and blocks acceptance instead of passing.

```console
$ python -I -X utf8 run_bts_sbom_app.py scan https://github.com/OWASP/NodeGoat.git
$ python -I -X utf8 run_bts_sbom_app.py patch <source> --approve     # without --approve: plan only, 0 files changed
$ python -I -X utf8 run_bts_sbom_app.py contextpack <folder> --package <name> --cxml   # bounded read-only repo view for an LLM
$ python -I -X utf8 run_bts_sbom_app.py chat --actions -i            # chat that can also patch (with YOUR typed token) and record VEX decisions
$ python -I -X utf8 run_bts_sbom_app.py serve --port 8800 --evidence <runs folder>   # the Open-Source Security web screen
$ python -m pytest -q tests/bts_sbom_app                              # 183 tests, all network faked
```

Measured on 10 real GitHub repositories (chosen by the author, several deliberately vulnerable): 2,478 components,
1,292 findings, license resolution 0.990. Limits first - patching edits manifests only (lockfiles get regeneration commands),
patched code was not built or tested, push/PR was verified against a local bare repository only, and retrieval is lexical.
Full detail, commands and the honest gap list: [docs/WORKFLOW.md](docs/WORKFLOW.md); open core defects found on the way:
[docs/CORE_ISSUES.md](docs/CORE_ISSUES.md).

SBOM governance commands (read-only, from the 6th FOSSLight Community Day analysis in
[docs/FOSSLIGHT_COMMUNITY_DAY_ANALYSIS.md](docs/FOSSLIGHT_COMMUNITY_DAY_ANALYSIS.md)): `bts-sbom-app conformance <sbom|project>` checks one
SBOM against NTIA 2021, the CISA 2025 draft, EU CRA, BSI TR-03183-2 and VEX readiness; `diff` compares two analyses with Hub-style threshold
alerts; `vex` exports OpenVEX with triage decisions applied fail-closed; `fleet` finds the projects hit by an advisory or using a component.
The web screen shows the same data: **Findings → What changed**, **Compliance → SBOM conformance** and **VEX · Decisions** (with the decision form), **CI/CD · History → Fleet · Affected**.

Chat actions and the repository context pack (`bts_sbom_app/actions.py`, `contextpack.py`, `evals_chat.py`; spec BSA-AC-176..181,
200..215): `chat --actions` (or `serve --chat-actions`) lets the chatbot analyse a source (isolated work copy), apply an approved patch
and record VEX decisions — but nothing is authorised by the model: a patch needs the 16-hex approval token of exactly the plan it was
shown and a decision the 12-hex confirm code of its preview, both typed by the user, and every token, source and reason the model
invents is dropped by the validator. The patch is applied for ONE round in the work copy, re-scanned, reverted on a regression, and
nothing is pushed; a default session is read-only. `contextpack <folder> [--package P] [--cxml]` builds a bounded read-only view of a
local tree — license files plus the import sites of one package with context — excluding binaries, oversized files, node_modules and
symlinks with reasons; all repository text is untrusted (escaped CXML, instruction-like files flagged) and import sites are candidates:
reachability stays unknown, `verify_site` re-confirms a claimed path:line. `evalchat` measures tool routing on 8 paraphrased
governance/action questions (regex router 2/8 measured, LLM planner 8/8; a reason the user did not type is never credited).

## Status & scope honesty

Vendored from the BTS platform's SCA stack (Apache-2.0). Deliberately NOT
included in the `bts_sbom` package: the platform's bulk-intel sqlite layer, its
config/dotenv service settings, FastAPI server, and UI — `bts_sbom` itself is
pure CLI + library. Network features (OSV.dev queries, deps.dev license
resolution, EPSS/KEV enrichment) degrade honestly to offline/cached/curated
data when the network is unavailable, and say so in the output.

The separate `bts_sbom_app` package is broader: it can call LG EXAONE (opt-in, needs a key, daily-budget ledger) and ships a
stdlib HTTP service (`bts-sbom-app serve`) with **no authentication** that must stay on localhost.

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
* **엔드투엔드 워크플로** (`bts_sbom_app/`, 명령 `bts-sbom-app`, 0.2.0): BTS-SBOM 코어 위에 얹은 상위 기능 — 라이선스 자동 식별(다중 모델 카운슬 포함),
  취약점 리포트, 승인형 패치(재스캔 검증, 회귀 시 되돌림), 레거시 아키텍처 분석, LG EXAONE 제안, 근거 기반 RAG 챗봇(도구 20종, `--actions` 로 승인형
  분석·패치·VEX 기록), SBOM 규제 적합도·차이 알림·fail-closed OpenVEX·포트폴리오 조회, 레포 컨텍스트 팩, 웹 콘솔(페이지에서 EXAONE 키 연결).
  자세한 내용과 한계는 [docs/WORKFLOW.md](docs/WORKFLOW.md).

```console
$ pip install bts-sbom
$ bts-sbom sector --sector cra --sbom sbom.json
```

## License

Apache-2.0 — see [LICENSE](LICENSE). Copyright 2025 BTS authors.
