# ADR-0013: Server-Sent Events for scan progress, not polling, WebSocket or long polling

## Status

Accepted (this change). Scope: `GET /api/jobs/<id>/events` only - the existing `GET /api/jobs/<id>` polling endpoint
is unchanged and stays supported (additive change, per the course brief's "existing API/return values/status codes/CLI
arguments are not changed" rule).

## 근거 (Context)

`bts_sbom_app/server.py` already runs a scan as a background thread per job and exposes its outcome through
`GET /api/jobs/<id>` (`state`, `metrics`, `stage_errors`, ...). A client that wants to show progress while a job is
running (a scan can take anywhere from under a second on a tiny fixture to tens of seconds on a real repository with
many components, per `pipeline.run_project`'s own `timings` dict) has only one option today: poll that endpoint on a
timer and infer progress from nothing, because the job record carries no per-stage detail while `state == "running"`.
`pipeline._Stages` already times every stage internally (`rec["timings"]`, `rec["stage_errors"]`) - that information
simply never leaves the process before the job finishes.

The service is explicitly localhost-only with no authentication (`server.py`'s module docstring), single process, and
has zero third-party dependencies (`pyproject.toml`: `dependencies = []`). Any mechanism to stream progress has to be
built on `http.server` alone.

## 결정 (Decision)

Use **Server-Sent Events** (one `GET` per job, `Content-Type: text/event-stream`) carrying a small, closed event
schema (`bts-sbom.events.v1`, `bts_sbom_app/events.py`): `job_start`, `step_start`, `step_end`, `patch_gate`, and
exactly one of `final`/`error` to end the stream. Implementation:

- `EventBus` (one instance per job, held by `server.State`) is an in-memory, thread-safe, append-only event log with a
  monotonically increasing `seq` and a `threading.Condition` so a reader blocks efficiently instead of polling the bus
  itself.
- `pipeline.run_project` gained one optional keyword, `progress=None`; `_Stages.run` calls it around each stage. When
  `progress` is `None` (every existing caller), behaviour and return value are provably unchanged - the only new code
  path is a function call that is skipped entirely.
- The HTTP handler reads `Last-Event-ID` (standard SSE resume header) or `?after=` and replays only events with a
  higher `seq`, so a dropped connection resumes without re-sending the whole history.
- A periodic heartbeat comment line (`: heartbeat\n\n`) is written whenever `EVENTS_HEARTBEAT_SECONDS` passes with no
  new event, so a client (and an intermediary, if one is ever added) can tell "no progress yet" from "connection
  dead" - this is also what lets a test shrink the interval and get a heartbeat inside a fast test run.
- A hard subscriber cap of `EventBus.MAX_SUBSCRIBERS = 4` per job bounds the number of `ThreadingHTTPServer` worker
  threads one job's spectators can hold open at once (this server has no connection pool separate from its thread
  pool).

## 기각 대안 (Rejected alternatives)

- **Keep polling only.** Simplest, zero new code, but gives no stage-level detail during `state == "running"` and
  does not meet the brief's requirement for a progress stream. Rejected: does not solve the actual gap (`pipeline`
  already computes per-stage timing/errors; polling cannot surface them before the job ends).
- **WebSocket.** Bidirectional, but this feature is one-directional (server -> client) and `http.server` has no
  built-in WebSocket support - a full handshake (RFC 6455: `Sec-WebSocket-Key`/`Accept`, frame masking/unmasking,
  ping/pong) would have to be hand-rolled from scratch with zero dependencies allowed. That is materially more
  protocol surface to get right (and to keep secure against malformed frames) for a feature that never needs the
  client to send anything mid-stream. Rejected: cost far exceeds what the one-directional requirement needs.
- **Long polling** (client repeats a `GET` that blocks until the next event or a timeout). Needs no new response
  content type and reuses the existing JSON response shape, but every single event (or timeout) requires a brand new
  TCP connection and HTTP request from the client, which is both more total request overhead on a
  `ThreadingHTTPServer` (one thread per in-flight request) and more client-side complexity (the client, not the
  server, has to drive the retry loop and track the last-seen position itself with no standard header for it).
  Rejected: SSE gives the same "block until something happens" behaviour over one connection, with `Last-Event-ID`
  already standardising the resume position so the client does not have to invent its own.

Reducing the lecture material's 7 illustrative event types to this product's **6** (`job_start`, `step_start`,
`step_end`, `patch_gate`, `final`, `error`) was also a decision made here, not inherited: this service's progress is
exactly "a job ran some stages, optionally asked for patch approval, and ended" - there is no deploy/traffic-shift
step in this tool's lifecycle for a generic "tool_call" or "retrieval" event type to describe, so those categories
from the lecture material were not carried over as separate event types.

## 결과 (Consequences)

- `GET /api/jobs/<id>` keeps working exactly as before for any caller that does not need per-stage detail; the SSE
  endpoint is additive.
- Every `ThreadingHTTPServer` worker thread serving an open SSE connection is held for as long as that connection
  stays open (bounded per job by `MAX_SUBSCRIBERS = 4`) - this is a real resource cost on a server that has no other
  concurrency model, which is why the cap exists and why `docs/RUNBOOK.md` documents it rather than treating it as
  unlimited.
- A process restart drops all `EventBus` instances (in-memory only, by design - they are not meant to survive past
  the job whose progress they describe, and a finished job's full history is already in `GET /api/jobs/<id>` and the
  persisted project record). A client reconnecting after a restart with an old `Last-Event-ID` gets a plain 404 (the
  job id is gone from `st.jobs`/`st.buses`), which is the same behaviour an unknown job id has always had.
- The schema is intentionally closed (6 named types, each with required fields `events.validate` enforces) rather
  than a free-form payload, so a consumer can be written against it once; adding a 7th event type later is possible
  but is a new decision, not a silent addition.
