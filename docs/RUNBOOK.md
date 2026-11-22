# RUNBOOK: bts_sbom_app service

Scope: the stdlib HTTP service started by `python -m bts_sbom_app serve` (`bts_sbom_app/server.py`), packaged by
`Dockerfile.bts-sbom-app`. **This is a localhost, single-process, single-node tool with no authentication** (see the
module docstring of `server.py`): nothing below assumes a load balancer, an autoscaler, multiple replicas, a service
mesh, or a reverse proxy/API gateway doing auth. If one of those gets added later, this document stops being accurate
for that part and needs rewriting, not patching.

## Delivery State

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
  search and re-ingest.
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
