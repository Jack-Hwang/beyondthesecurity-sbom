# RUNBOOK: bts_sbom_app service

Scope: the stdlib HTTP service started by `python -m bts_sbom_app serve` (`bts_sbom_app/server.py`), packaged by
`Dockerfile.bts-sbom-app`. **This is a localhost, single-process, single-node tool with no accounts** (see the
module docstring of `server.py`); when it is reachable beyond localhost the one switch that closes the gap is the shared access token
`BTS_SBOM_ACCESS_TOKEN` (`access.py`; `/healthz` and `/readyz` stay open) together with `BTS_SBOM_ALLOWED_ROOTS` for local sources: nothing below assumes a load balancer, an autoscaler, multiple replicas, a service
mesh, or a reverse proxy/API gateway doing auth. If one of those gets added later, this document stops being accurate
for that part and needs rewriting, not patching.

## Delivery State
- **2026-11-28: A2UI-style UI cards live.** The a2ui-project analysis (docs/A2UI_INTEGRATION.md, Apache-2.0, spec-level clean-room) became a closed 8-kind card catalog over chat tool results: deterministic post-processing of measured records, strict validation (unknown kinds/fields/oversized/non-scalar dropped and named - prose always rides along), catalog negotiation at GET /api/ui/catalog, native rendering in the chat dock and the non-stream answer, and a deliberate no-agent-actions deviation keeping the typed-token approval gates. Deployed as Container Apps revision 0000009 (image 0.5.0-a2ui1128); live: NodeGoat overview answers with a stat_row card (1091/311/CRITICAL 32), smoke_deployed 4/4, supply-chain gate pass (AC 645-646).


What exists today and what was actually checked, in this worktree, as of this change:

- `bts_sbom_app/events.py` (SSE event schema `bts-sbom.events.v1` + `EventBus`), the `GET /api/jobs/<id>/events`
  endpoint, `GET /healthz`, `GET /readyz`, and the `pipeline.run_project(..., progress=...)` hook are implemented and
  covered by `tests/bts_sbom_app/test_events_sse.py` and `tests/bts_sbom_app/test_ops_probes.py` (offline, fake
  pipeline / fake probes - no network, no real subprocess server other than the `ThreadingHTTPServer` the tests start
  on an OS-assigned port, same pattern as `tests/bts_sbom_app/test_server_cli.py`).
- `Dockerfile.bts-sbom-app` was edited (non-root numeric `USER 10001`, a `HEALTHCHECK` that calls `/readyz` with
  `urllib`, no `:latest`, no secret `ENV`/`ARG`, `EXPOSE` matching the server's port) and is covered by
  `tests/bts_sbom_app/test_container_policy.py`, which is a **static** check: it reads the Dockerfile's text with
  regular expressions. It does **not** invoke the Docker daemon.
- **2026-11-22: the build and the running container were measured for the first time** (`python scripts/supply_chain_gate.py`,
  evidence in `evidence/supply_chain/`): `docker build` completed in 50.61 s (12.89 s warm-cache on the second run);
  Trivy (via the aquasec/trivy container, since no native trivy is installed) found **0 CRITICAL** in the image;
  the image's CycloneDX SBOM has 122 components (`image.cdx.json`); the same command produced this repository's own
  SBOM (6,298 components; pipeline 31.7 s / step total 104.31 s) and a bench that grew from a single `/healthz`
  sweep (p50 0.54 ms, p95 18.11 ms - a no-check endpoint) to three latency classes (see Monitoring and
  `docs/capacity.md` 2.1). Separately the built image was started
  (`docker run --rm -p 127.0.0.1:8811:8800 bts-sbom-app:gate`): `/readyz` returned 200 and the Docker HEALTHCHECK
  reached `healthy` (FailingStreak 0). The Dockerfile's `NOT BUILT YET` comment was updated accordingly, by the
  person who ran those commands.
- **2026-11-22: Book KB (아키텍처 도서 지식 베이스, ADR-0021, BSA-AC-523..532) built and measured**: the user's own
  local library — 30 files, 20 PDF + 10 EPUB, 422 MB, `C:\Users\Administrator\Documents\HBJ_2025하반기부터\아키텍처책모음` —
  was ingested with `python -m bts_sbom_app books "<folder>"` (실측 130.5 s): **29 ok / 0 skipped / 1 duplicate**
  (동일 사본 SHA-256 중복 1건), 270 섹션, 31.4 MB 텍스트, per-book stats in `evidence/books/registry.json`
  (gitignored — 저작물 원문은 저장소 밖). Extraction found and fixed a real defect: the mingw64 poppler opens
  non-ASCII paths through a non-Unicode argv (em-dash → `?`), so 5 ISO PDFs failed until `extract_pdf` routed such
  paths through a temporary ASCII-named copy (`bts_sbom_app/books.py:extract_pdf`, measured before/after). The
  serve-time second index measured 22,857 chunks, load 1.3 s + build 13.4 s (cached once per registry signature),
  search p50 129.8 ms / p95 240.7 ms over 48 queries (`evidence/loop/books_index_measure.json`). 29 distilled notes
  live in `knowledge_books/` (serve-time only). **RAG baselines unchanged by the book layer** — the raw chunks and
  the notes are both excluded from `evals.build_index` (테스트 강제, `books_eval_baseline.json` == post-ingestion
  측정). The chat answers from the library via the `book_search` tool and the Book KB tab serves registry, outline,
- **2026-11-22: bottom chat dock + Azure deployment review.** The 💬 Chat tab was replaced by a
  Claude-Code-desktop-style **bottom chat dock** (bts_chat_panel.js) docked on every tab: a turn = one
  `/api/chat/stream` call whose 7 events render as a collapsible activity card, the `final` event now carries
  the answer body (+ conflicts, retrieval top, routing) so the stream alone completes a turn (one LLM budget
  per turn), and an `awaiting_approval` event renders an inline approve button that posts the token question
  (real approval still requires `--chat-actions`). The SSE client moved from bts_stream.js (removed) into the
  panel. Separately, the MS Azure deployment **review** was completed and written up (`docs/AZURE_DEPLOYMENT.md`
  + `deploy/azure/containerapp.yaml` + `deploy/azure/README.md`): recommended target **Azure Container Apps**
  (single replica, Azure Files 2Gi evidence volume, Easy Auth mandatory for public ingress - the service stays
  unauthenticated by design), `BTS_OSS_ALLOWED_HOSTS=<fqdn>` un-blocks the oss/arch/books Host checks behind
  ingress, zero code changes required. Deployment status: **검토 완료·미배포** (az login + first-deploy
  measurements pending; the README lists the volume-UID item as the must-verify unknown).
- **2026-11-27: SECOND AZURE DEPLOYMENT - token-gated, live** at https://bts-sbom.wittyforest-2c8fae00.koreacentral.azurecontainerapps.io (resource group `bts-sbom-rg`, ACR `btsbomacr1126`,
  Storage `btsbomstg1127`, environment `bts-sbom-env`, app `bts-sbom`, scale 0->1, image `0.5.0-final1127b`). Access-token gate ON (401 without the token, probes open), source boundary
  `BTS_SBOM_ALLOWED_ROOTS=/srv/bts-sources` (5 of 5 live boundary probes refused), allowlist `.dockerignore` (build context 1.925 MiB). Measured live: smoke 4/4 PASS, LLM chat + NL2SQL + escalation log,
  remote scans (sampleproject 8 s, dvpwa 24 s, OWASP/NodeGoat 1,091 components / 311 advisories / 98.5 % licences). One real defect found and fixed: SQLite on the Azure Files share made every scanner cache write
  wait out a 5 s lock (`database is locked`; NodeGoat 780 s) - the OSV snapshot is now copied once to local disk at start-up (`BTS_SBOM_OSV_SEED_DB` -> `BTS_SBOM_OSV_DB_PATH`), the same scan takes 96 s with 0 lock errors.
  An adversarial pass on a local instance (3 agents, 48 attacks, 11 reproduced and verified) found and fixed: slowloris below the gate (read timeout 15 s + 128-connection cap), a ~1 CPU-second prompt-digest
  re-parse per chat turn (cached), legacy IPv4 spellings (2130706433, 0x7f000001, 127.1, localhost.) slipping through both SSRF guards (one shared parser), file:// authority mismatch, DNS rebinding (checked address
  pinned into the https clone via http.curloptResolve), no throttle on failed credentials (20 per caller per minute, then 429 without checking the token), forgeable X-Forwarded-For (trusted only with
  BTS_SBOM_TRUST_FORWARDED=1), RecursionError on deeply nested JSON, Server header version leak. Live-only finding: the Container Apps ingress connects from 100.100.0.x (shared address space) which
  ipaddress.is_private does not cover, so every caller shared two ingress addresses and the per-caller chat limit never fired (36 of 36 calls 200); fixed and re-measured live (200 x30 / 429 x6; wrong tokens 401 x20 / 429 x5).
  Current revision bts-sbom--0000006 (image 0.5.0-final1127f). Not done: Easy Auth/AAD (needs an app registration; the service has no per-user accounts), a budget alert (the installed `az consumption budget create` cannot express notifications), min replicas stays 0. Details: `deploy/azure/README.md` §12.
- **2026-11-23: FIRST AZURE DEPLOYMENT — live on Azure Container Apps (demo, ~2 weeks)**. Target: resource group
  `bts-sbom-rg` / environment `bts-sbom-env` (koreacentral) / app **`bts-sbom`** →
  https://bts-sbom.yellowdesert-36032bc5.koreacentral.azurecontainerapps.io — image
  `btsbomacr1123.azurecr.io/bts-sbom-app:0.5.0-uboot2` (ACR cloud build: 2 min 16 s per build, no local docker),
  scale **0→1** (call-woken, demo economics; a full NodeGoat scan took ~355 s at 0.5 vCPU), evidence on
  **Azure Files 2Gi** mounted at /tmp/evidence (subPath `evidence`) — **the volume-UID unknown did NOT bite**:
  /readyz 200 with `failed: []` on the first boot. Measured live over the public URL: /healthz 200, /readyz 200,
  console page served, SSE chat turn (planner → Korean answer over the u-boot record: 68 components / 43
  advisories), nl2sql over the seeded OSV DB (PyPI 153 rows), and a full remote scan of OWASP/NodeGoat from its
  GitHub URL (1,091 components, 311 advisories, license resolve 98.5 %). Seeded demo records: u-boot v2026.10 and
  django-nV project records + the OSV DB were uploaded into the share's `evidence/` folder. Two real defects were
  found and fixed by this deployment: ① the LLM call ledger resolves to `<root>/evidence/.llm_ledger.json`, and
  /app is read-only for UID 10001 — every chat turn 503'd at `llm._bump` until the Dockerfile grew a writable
  `/app/evidence` (image retagged `0.5.0-uboot2`); ② `az containerapp create --registry-username/password` derives
  an invalid auto secret name from the ACR login server — the working path is a user-assigned managed identity +
  AcrPull, or the YAML `configuration.registries` block with an explicit `passwordSecretRef` (this repo uses the
  YAML path; deploy/azure/README.md documents both). **Contract deviation, deliberate and temporary**: this demo
  instance is **public ingress without authentication** (Easy Auth was skipped for demo friction; the app's own
  `BTS_SBOM_LLM_DAILY_BUDGET=80` caps any third-party LLM use). The localhost no-auth contract above still governs
  the code; the Azure instance is a demo mirror that gets deleted after the review window
  (`az group delete --name bts-sbom-rg --yes` removes everything including the registry and the Files share). **2026-11-24: the demo window was closed early — the resource group was deleted as planned**
  (ResourceGroupNotFound verified; the only survivor is the separate rg-bts-openai LLM endpoint). Before
  deletion the live-only NodeGoat scan record (1,091 components / 311 advisories) was pulled down to
  evidence/runs/NodeGoat/, so every measured artifact now lives in this repository. Re-deployment path is
  documented in deploy/azure/README.md §8.
- **2026-11-22: Code Intel — Understand(SciTools)의 함수 레벨 기능을 설치·의존 없이 자체 재구현** (ADR-0023,
  BSA-AC-553..557): AST 기반 콜그래프·순환 복잡도·데드코드·클론 검출이 `arch.analyze()["code"]`로 상주하고,
  콘솔 🔎 Code Intel 판 + Arch Intel Code Intel 섹션(결정론 콜그래프)으로 표시된다. Python-first이며 타 언어는
  모듈 레벨 유지를 notes로 명시. 실측(django.nV): 49 함수, 최대 복잡도 9(task_details), 데드 40, 콜 해석 2/329.
  Understand 설치러 자체는 REA로만 식별(Qt Installer Framework)하고 설치·실행하지 않았다(사용자 결정).
  search and re-ingest.
- **2026-11-22: real user test of the full 5-step scenario (구글링 → 신규 폴더 clone → 스캔·리포트 → AI 재구현 →
  시퀀스 다이어그램) found and fixed 4 real defects**, then a 100-round HTTP loop (`scripts/usertest_loop.py`,
  artifacts `evidence/usertest/findings.json`) passed **100/100** (5 heavy = the full scenario incl. patch plan +
  sequence, 15 medium = report/governance/chat surface, 80 light = always-on endpoints) in 39 s. The defects,
  each reproduced through the real UI or API before the fix:
  1. the analysis never auto-switched to the new Report tab - `runJob`'s promise chain returned the
     `selectProject` result (undefined) instead of the job, so the `job.state` check never fired (bts_console.js);
  2./3. the saved console key was invisible: `State._llm_config_path` looked under the --evidence runs folder
     (and only understood the generic key shape, not the Azure shape the console had written) - both now
     root-based like the ledger (server.py); with the fix the saved gpt-5-mini key auto-connects on restart;
  4. a project whose every LLM scenario fails validation lost the Sequence view entirely (django.nV: 5 dropped,
     sequence count 0) - the deterministic static-inference startup flow now fills in, honestly labelled
     (arch_intel.py, ai_note states the replacement).
  One incident, owned and then RECOVERED: while fixing 2/3, the pre-existing LLM tests pointed `State.root` at
  the REAL repository and overwrote the user's saved `evidence/.llm_config.json` with a test key. Recovery (same
  day, on the user's request "복구해봐"): the live server process had loaded the Azure key before the clobber, so
  a minidump of that process (ctypes MiniDumpWriteDump with full memory; the helper lives outside the repo at
  C:\firebaseprojects\usertest\recovery\dump_and_search.py and stores no key material) was searched for a key
  whose 4-char tail matched the masked tail /api/llm had reported (xv5v); one 84-char candidate was validated
  with a single real completion call and the Azure-shaped config was written back. Post-recovery state:
  configured gpt-5-mini, tail xv5v, saved - identical to pre-clobber. The dump and the candidate files were
  deleted after recovery. Root cause of the incident is fixed: the test fixture now uses a tmp root and cannot
  touch the real repository (test_server_cli.py).
- **2026-11-22: `bts-sbom-app ragloop` pass 5 is RED — and the books layer is not the cause.** The gate compares
  against pass 4 (brief1-era baseline: dev recall 1.000, dev mrr 0.869, dev ood 1.000) and fails on drift that was
  introduced by the earlier round-1/brief-5 work (now commit `ec58c1b`): the `knowledge/lecture/*.md` corpus
  additions plus the `rag.py` synonym-table extension. Evidence: the current metrics (dev recall 0.933,
  mrr 0.802, ood 0.800) exactly equal the snapshot taken **before** any books-layer change
  (`evidence/loop/books_eval_baseline.json`), the book chunks and notes are provably excluded from the eval corpus
  (BSA-AC-529 test), and the OOD miss is traceable to a lecture chunk (e.g. `knowledge/lecture/rag_methods.md`
  matching the "축구 경기 결과를 알려줘" out-of-domain query via "경기"). Re-baselining the gate is a separate
  decision — it redefines what "regression" means for the pass-4 golden/dev/test sets.
- **2026-11-22 (second release, book-library integration)**: the gate re-ran on the code that adds the MCP
  stdio server (`python -m bts_sbom_app mcp`), the A2A-style `/api/agent-card`, the lost-in-the-middle passage
  ordering and the 30 distilled book notes - verdict pass, Trivy CRITICAL 0, build 15.84 s warm, bench p95
  `/healthz` 22.7 ms / `/readyz` 16.6 ms / `/api/history` 68.6 ms. The release container was started:
  `/readyz` 200, `/api/agent-card` 200 **inside the container**, HEALTHCHECK `healthy` (FailingStreak 0).
  RAG 6-metric baselines re-measured unchanged (recall 1.0 / mrr 0.975 / ndcg 0.95 / ood 1.0) - the books
  integration stays outside the eval corpus by construction (ADR-0021).
- **kind manifests for a single-node cluster were produced but NOT deployed** (`deploy/kind/`, brief 5 G1 산출만):
  `kubectl apply --dry-run=client --validate=false` parses all four documents; the cluster apply itself is blocked
  on `kind` not being installed here - the honest status lives in `deploy/kind/README.md`.
- **2026-11-22 (third release, EA-17.2 diagram catalog + DMN-style decision engine)**: the REA of
  `C:\firebaseprojects\REA\scitools\easetup_x64.msi` identified the artefact as **Sparx Enterprise Architect
  Trial 17.2.1721.15** (not SciTools - see `docs/EA_REA_FINDINGS.md`), extracted the embedded New-Diagram
  registry from EA.exe and the MDG technology files, and the product now mirrors that catalog natively:
  `bts_sbom_app/diagrams.py` draws 37 diagram kinds (36 measured builders + 1 honest "not derivable" wireframing
  entry; the round-2 REA re-verification corrected the first-pass SysML claim and added SysML BDD/IBD/Parametric + ICONIX Robustness) as Mermaid over the analysed record, `bts_sbom_app/decision.py` runs a DMN-style decision table
  (hit policies F/U/A/P, band-rank severity comparison, absent facts never match) over the measured facts with
  the shipped `remediation-policy` table, the chat dock and the new 🖼 Diagrams tab render the same `.arc-dwrap`
  markup contract through the vendored mermaid (source-text fallback), and `/api/diagrams` serves the catalog and
  per-kind builds (spec AC-573..578, ADR-0024; tests `test_diagrams.py` 26 + `test_decision.py` 10). The chat
  tools `draw_diagram`/`decide` are read-only and pass the same call validator as every other tool; a kind whose
  measured inputs are missing draws nothing and says why. The extracted installer contents remain under
  `C:\firebaseprojects\REA\scitools\extract\` unexecuted.
- Everything else in this file (the specific rollback thresholds and monitoring fields) is read off the code that
  ships with this change, not off a deployment that has run in production - there is no production deployment of this
  tool today.

## Deployment

1. Build: `docker build -f Dockerfile.bts-sbom-app -t bts-sbom-app .` (first measured run: 50.61 s, 2026-11-22 -
   see Delivery State). The one-command build-and-verify is `python scripts/supply_chain_gate.py`: build + Trivy
   CRITICAL gate + image SBOM + own-repo SBOM + `/healthz` bench, writing `evidence/supply_chain/` - run it after
   any Dockerfile or dependency change and before declaring a version deliverable. A tool-less environment degrades
   the gate to honestly-labelled skips, never to a silent pass.
2. Run, binding the published port to localhost only (the service has no authentication of its own):
   `docker run --rm -p 127.0.0.1:8800:8800 -e EXAONE_API_KEY=... -v <evidence-dir>:/tmp/evidence bts-sbom-app`.
   Mount a persistent volume at `/tmp/evidence` if analysis history (`/api/history`, `/api/changes/<project>`) should
   survive a container restart; without it, every restart starts with an empty evidence folder.
3. Without Docker: `python -m bts_sbom_app --root <repo> serve --host 127.0.0.1 --port 8800 --evidence <dir>`
   (`run_bts_sbom_app.py` does the same with its own defaults).
4. Readiness: wait for `GET /readyz` to return `200` before sending it traffic (see Monitoring). A `503` names which
   probe(s) are failing in `{"ready": false, "failed": [...]}` - the names only, never a path or an exception message.
5. There is exactly one process and no shared state outside its own `evidence` folder: "deployment" here means
   replacing that one process, not a rolling update across replicas. A patch job holding an applied-and-kept work
   copy (`job["work_copy"]`) is mid-flight state that a restart does not clean up by itself (see Rollback).

## Rollback

There is no previous-version traffic shift to perform (single process, no replicas) - "rollback" means stopping the
new container/process and starting the previous image/checkout again, with the same mounted evidence folder (project
records and `.prev.json` snapshots are forward-compatible by construction: `pipeline.PROJECT_SCHEMAS_ACCEPTED` still
reads records written by an older schema name). Triggers, each a measurement this service itself exposes:

- **`GET /readyz` returns 503 on 3 consecutive checks** (matching the `HEALTHCHECK`'s own `--retries=3`): one of
  `evidence_writable` / `core_import` / `knowledge_corpus` has been failing for at least `3 * --interval` (90s at the
  Dockerfile's current `--interval=30s`). Roll back if the previous version's `/readyz` was clean under the same
  evidence mount - the fault is in this version or its environment, not transient. The course's "readiness failing
  for 5 minutes" example is covered by this stricter measured trigger (90s fires well before 5 minutes); 5 minutes
  of continuous 503 means the rollback already happened late.
- **The supply-chain gate fails on a rebuild** (`python scripts/supply_chain_gate.py` reports `verdict: fail`, e.g.
  Trivy finding a CRITICAL that was absent in the recorded `evidence/supply_chain/gate_<ts>.json` baseline): the new
  image does not ship; roll back to the last image whose gate report shows `critical_found: 0` and re-examine the
  dependency change that introduced the finding.
- **A job's `final.state == "error"` for more than 1 of the last 5 completed jobs** (a rate, not one failure - a
  single bad `source` is a client error, not a service fault). Read `GET /api/jobs/<id>` (`state`, `error`) or the SSE
  `error` event (`error_type`, `retryable`, `recovery_hint`) for the reason before deciding; an `error_type` that
  repeats across unrelated sources points at the deployed code, not the inputs.
- **`net.STATS["failures"] / net.STATS["requests"]` climbing with every job** (read it from the batch `summary.json` or the `net` block of the license stats - `GET /api/engine` does not expose it - or
  directly in-process): the outbound calls this service makes (OSV, deps.dev, PyPI/npm/Maven for licenses) are
  failing at a rate past what the already-built retries absorb.
- Not a trigger: `stage_errors` on an individual job's record is normal partial-result reporting (see the pipeline
  module docstring: "a failing stage is recorded ... and the rest of the run continues") - it means one source had a
  problem, not that the service is unhealthy.

Rollback step: stop the container (`docker stop`), start the previous image against the same evidence volume, confirm
`/readyz` is `200` and one known-good source analyses cleanly before resuming traffic.

## Monitoring

Everything below is read from this process - there is no separate metrics backend, no autoscaler signal and no APIM/
gateway dashboard to wire up (none of those exist for this tool).

| Signal | Where | What it means |
|---|---|---|
| `GET /healthz` | always `200`, minimal JSON, answers without doing any check | the HTTP server thread itself is alive and accepting connections; a timeout or connection refused here means the process/container is down, not just unready |
| `GET /readyz` | `200` / `503` + `failed: [...]` | `evidence_writable` (the evidence folder cannot be written - disk full, permissions, or a missing mount), `core_import` (the `bts_sbom` core cannot be imported - a broken install), `knowledge_corpus` (the `knowledge/` folder the chatbot's RAG index reads is missing or empty - a bad image or a bad `--root`) |
| `GET /api/jobs/<id>` | `state` (`running`/`done`/`error`), `stage_errors`, `metrics.stage_errors` (count) | per-job outcome; `metrics.elapsed_s` for how long a run took |
| `GET /api/jobs/<id>/events` (SSE) | `job_start`, `step_start`/`step_end` (`ok`, `seconds`), `patch_gate`, then `final` or `error` | the same job as it happens, for a live progress UI; a connection that gets nothing but heartbeat comments for several intervals has a job that is either between stages (normal for a slow stage) or stuck (compare against `step_start` with no matching `step_end` for an unusually long time) |
| `net.STATS` (`requests`, `failures`, `last_error`, `short_circuited`, `empty`, `partial`) | in-process; written to the batch `summary.json` and the `net` block of the license stats (not exposed by `GET /api/engine`) | outbound call volume and failure count across all jobs since the process started (or since the last `net.reset_stats()`, which the tests and `bts-sbom-app batch` call); `short_circuited` = calls skipped because a host's circuit was open (the answer is "could not check", never "clean"), `empty` = the server answered "not found" (404), `partial` = a body cut at the read limit |
| `GET /api/history` | one row per analysed project, `analysed_at` | staleness of the evidence folder's content - a project that should be re-scanned periodically but has an old `analysed_at` was not |
| `POST /api/chat/stream` (SSE) | `step_start`, `tool_call`/`tool_result`, `awaiting_approval`, `handoff`, then `final` or `error` (with an error *envelope*: severity, retry_budget, completed_steps, coverage_gap) | one chat turn as it happens, at a finer grain than the job stream; an `error` with a recoverable envelope is a partial result (the turn continued), a fatal one means the turn produced nothing; `awaiting_approval` is the HITL gate - nothing is applied until the user answers with the approval token |
| `evidence/supply_chain/bench/bench_latest.json` | the gate's last bench step (`endpoints`: per-path `p50_ms`/`p95_ms`/`http_status` for `/healthz`, `/readyz`, `/api/history`) | the serving-latency baseline from the last gate run (2026-11-22 07:56: `/healthz` p95 23.9 ms, `/readyz` p95 23.5 ms - the real checks cost nothing measurable at p50 - and `/api/history` p95 60.7 ms, the tightest path against the 100 ms SLO); a future bench step whose p95 grows materially against this baseline is a regression signal - the SLO math that consumes these numbers lives in `docs/capacity.md` 2.1 |

**Circuit breaker**: after 3 consecutive failed calls to one host the breaker opens for 60 seconds and further calls to that host are not sent (`short_circuited` counts them); one probe call is allowed afterwards. Set `BTS_SBOM_BREAKER_THRESHOLD=0` to switch the breaker off. A rising `short_circuited` with a flat `requests` count means an upstream (OSV, deps.dev, a registry) is down, not that the project is clean.
