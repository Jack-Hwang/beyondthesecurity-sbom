# ADR-0020: NL2SQL three-layer safety without sqlglot, honest supply-chain gate, chat stream as observation, capacity math

## Status

Accepted (brief 5 — MetaNet 3~4주차 + 별첨 2종 적용, 2026-11-22). Covers the four decisions behind
AC-510~520 that needed a recorded why: the B/C/D/E phases of `docs/GLM_IMPLEMENTATION_BRIEF_5.md`.

## 근거 (Context)

The 3-2차시 lecture's text-to-SQL lane prescribes a validator library (the course shows sqlglot) in front of a
read-only database. The repo's stdlib-only principle makes every new dependency an explicit exception, and a SQL
validator library can be *wrong* in exactly the way that matters here (a parse gap becomes a write path). The
4-1차시 supply-chain pipeline (build → scan → SBOM → bench) had never been run on this product: the Dockerfile
carried a `NOT BUILT YET` comment, the Docker CLI existed without a running daemon, and no Trivy was installed.
The 4-3차시 error envelope/handoff/7-event SSE/HITL existed only at the *job* level (`events.py`); a chat turn
had no event contract at all. The 4-2차시 SLO/capacity formulas had no measured input anywhere in the repo.

## 결정 (Decision)

- **NL2SQL safety is layered so that no single layer is trusted** (`nl2sql.py`, AC-510~513): (1) a stdlib
  tokenizer validator — single statement, SELECT/WITH only, write tokens rejected anywhere including CTE
  bodies, LIMIT forced — (2) the connection itself is `file:...?mode=ro` + `PRAGMA query_only`, so a validator
  bypass still meets the database refusing the write, (3) a 4-state executor (`success` / `empty_result` /
  `partial_result` / `access_failure`) that never turns a legitimate 0 rows into an error or an error into
  empty rows. Generation is a deterministic template router first (EX-evaluable offline), the LLM lane is
  optional, and the self-correction loop re-prompts with the *concrete* previous error, stops on a repeated
  error, and caps at 3 attempts. sqlglot stays **rejected** until a real query surface outgrows the token
  validator.
- **The supply-chain gate degrades honestly, never silently** (`scripts/supply_chain_gate.py`, AC-514~516):
  the plan is computed from tool availability *before* anything runs, every skip carries a reason, a vanished
  tool (exit 127) is recorded as a skip rather than a vulnerability, and the Trivy CRITICAL gate fails the run
  on any failed step. First measured run (2026-11-22): build 50.61 s, CRITICAL 0, image CycloneDX 122
  components, own-repo SBOM 6,298 components, `/healthz` p50 0.54 ms / p95 18.11 ms; the container then
  reached `/readyz` 200 and HEALTHCHECK `healthy`. `NOT BUILT YET` was updated by the person who ran it.
- **Chat streaming adds observation, not behavior** (`chat_stream.py` + `POST /api/chat/stream`, AC-517~520):
  `StreamingChatbot` subclasses `Chatbot` — the regex router, LLM planner, validators and approval gates are
  inherited untouched — and emits the 7 course events (`step_start`, `tool_call`, `tool_result`,
  `awaiting_approval`, `handoff`, `final`, `error`). A tool failure becomes a `recoverable` envelope and the
  turn continues; `plan_patch` emits `awaiting_approval` carrying the same patch-gate states `events.py`
  defines, so the user — never the model — closes the HITL loop. `handoff.py` provides the envelope
  (`error_type`/`severity` warning·recoverable·fatal/`retry_budget`/`completed_steps`/`partialResult`/
  `coverage_gap`) and the explicit stage contract (`schema_version`/`task`/`context`/`constraints`/
  `not_passed`); the council adapter emits **no envelope when nothing failed** — a lying envelope is as bad as
  a hidden failure.
- **Capacity numbers are measured, formula'd, or absent** (`docs/capacity.md`): every value in the document is
  a real measurement (with the command and artifact path), a formula applied to a measurement (Little's Law,
  `λ_max = 3600/W` with the conservative 34 scans/hour), or explicitly marked 미측정. The p95 SLO is derived
  from the measured 18.11 ms with its honesty limit stated: it measures `/healthz`, a no-check endpoint.

## 기각 대안 (Rejected alternatives)

- **sqlglot as the validator** — a third-party parse gap is a silent write path; the read-only URI + query_only
  database layer enforces the invariant below the validator, so the validator's job shrinks to UX (early,
  clear refusals). Revisit only when a read-only mirror gets a real multi-dialect query surface.
- **Invoking native trivy as a hard requirement** — trivy is absent on this host; the gate hosts it through
  the aquasec/trivy container against the same daemon. Requiring a native install would have made the first
  gate run a skip instead of a measurement.
- **Editing `chat.py` to add streaming hooks** — the file is concurrently owned by another workstream; a
  subclass adds the same observation with zero collision surface, and keeps the stream a *viewer* that cannot
  drift from the gates it observes.
- **Filling the capacity document with targets** — HPA/KEDA-style formulas without a replication unit (this
  is a single localhost process) would be fiction; the document states the scale axis (process + evidence
  volume) instead and marks what is not yet measured.

## 결과 (Consequences)

AC 510~513 (NL2SQL), 514~516 (gate), 517~520 (envelope/handoff/stream), 521~522 (bench three latency
classes + kind manifests 산출만). Evidence lives in `evidence/supply_chain/` (gate reports, image + project
SBOMs, bench), the SLO math in `docs/capacity.md`, the runbook blocks in `docs/RUNBOOK.md`. The bench grew
from a single `/healthz` sweep to three latency classes, and the second measurement already paid for itself:
`/readyz` p95 23.5 ms shows the real checks cost nothing measurable at p50, while `/api/history` p95
60.7 ms is the tightest path against the 100 ms SLO (headroom 1.6x) - the pagination candidate if history
grows. Remaining honest gaps, each recorded where it belongs: other `/api/*` paths (scan submit, LLM chat,
SSE) are unmeasured, concurrent-scan memory is unmeasured, availability has no uptime monitor, and the kind
manifests are parsed but not cluster-applied (`kind` absent - `deploy/kind/README.md` carries the
apply procedure and the unverified fsGroup item).
