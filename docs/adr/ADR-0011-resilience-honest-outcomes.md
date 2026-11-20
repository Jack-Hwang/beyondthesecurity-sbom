# ADR-0011: Per-host circuit breaker and a four-shape "no answer" outcome for net.py

## Status

Accepted (2026-11-20).

## 근거 (Context)

`bts_sbom_app/net.py`'s `http_json`/`http_text` already retried transient failures with backoff and counted
requests/failures for the evidence file, but two gaps showed up when reading the code next to the course
material on resilience (lecture 3-1 p.25,30: retry judgement + 3-state circuit breaker; lecture 3-2 p.44:
"the four shapes of no answer" - success/empty/partial/access-failure):

1. **No breaker.** A host that is actually down (DNS failure, outage, firewall) is retried exactly the same
   way for every one of the components a scan touches. License resolution (`licenses.py`) calls deps.dev,
   the registry and Maven Central per component; OSV verification (`osv.py`) calls `api.osv.dev` per batch.
   For a large SBOM (thousands of components) a dead host turns into thousands of retried, timed-out calls
   instead of a handful.
2. **Folded failure shapes.** `http_json`/`http_text` return `None` for BOTH "the server answered: no such
   resource" (HTTP 404 - a legitimate, informative answer) and "we never got a trustworthy answer" (timeout,
   5xx exhausted, circuit open). A caller cannot tell "nothing to report" from "we do not know" - exactly the
   gap the lecture's four-shape model names.

Verified not already present: `git grep -n "CircuitBreaker\|circuit_breaker\|Outcome(" -- bts_sbom_app` on
`main` and `rel/v0.2.0` (this worktree's parent branches) returns nothing; `net.py`'s `TRANSPORT` test hook
and `STATS` dict are the only existing resilience-adjacent code.

## 결정 (Decision)

Add `bts_sbom_app/resilience.py`:

- `CircuitBreaker(failure_threshold=3, open_seconds=60.0, clock=time.monotonic)` with three states
  (closed/open/half_open), a `threading.Lock` guarding every state transition, and an injectable clock so
  tests drive cooldowns without real sleeps. `allow()` performs the open -> half_open transition and claims
  the single probe slot atomically; `on_success()`/`on_failure()` are guarded against races where a call that
  started under "closed" finishes after a sibling call has already opened the breaker (an earlier draft of
  this breaker double-counted `opens` and let a late success silently re-close an open breaker - caught by
  `tests/bts_sbom_app/test_resilience.py::test_concurrent_failing_calls_open_breaker_exactly_once`).
- A per-host registry (`urlsplit().netloc`), `get_breaker()`/`reset_breakers()`/`snapshot()`. The failure
  threshold is read from `BTS_SBOM_BREAKER_THRESHOLD` at breaker-creation time; `0` disables the breaker.
- `Outcome(state, data, status, reason, attempts)` with `state` in
  `{success, empty_result, partial_result, access_failure}`.

Extend `bts_sbom_app/net.py` additively:

- `fetch_json`/`fetch_text` return an `Outcome`. 404 is `empty_result` and is explicitly NEUTRAL to the
  breaker (neither success nor failure - the host answered). A body truncated at the byte `limit` is
  `partial_result` and the (truncated) data is still returned. Exhausted retries or an open breaker are
  `access_failure` with a `reason` (`circuit_open`, `http_5xx`, `retries_exhausted`, ...).
- `http_json`/`http_text` become thin wrappers that keep their EXACT original return contract (data, or
  `None` on 404/failure) - every existing caller (`licenses.py`, `osv.py`, `arch.py`) is unaffected; see
  `tests/bts_sbom_app/test_resilience.py::test_http_json_contract_unchanged_across_four_response_shapes`.
- A `Retry-After` response header is honoured (capped at 30s) via an injectable `net.SLEEP` module variable.
- The breaker counts exactly ONE failure per outer call, after its own retries are exhausted - not once per
  retry attempt (otherwise a single slow call could look like several consecutive failures and trip the
  breaker on its own).
- The `net.TRANSPORT` test hook (used by the ~200 pre-existing offline tests) stays a SINGLE attempt per call
  (no retry loop), exactly as before this change. This was a deliberate, measured choice - see Rejected
  alternatives.

## 기각 대안 (Rejected alternatives)

- **Loop retries through `TRANSPORT` too (uniform code path).** Tried first: one `_fetch()` retry loop
  covering both the real network and the test hook. Measured consequence: `tests/bts_sbom_app/
  conftest.py`'s `FakeWorld.http` returns HTTP 503 when `fail_osv=True`
  (`tests/bts_sbom_app/test_engine_licenses.py::test_osv_failure_is_unverified_not_clean`), which is a
  RETRYABLE status - the existing test suite never monkeypatches `net.SLEEP`, so every retry would call real
  `time.sleep()`, adding ~3.5s of real wall-clock delay to that one test and risking the same for any future
  test with a retryable fake status. Rejected: keeping the test-hook path single-attempt (matching its
  pre-existing behaviour exactly) avoids this regression entirely while still letting the breaker observe
  every call's outcome (opens/closes on CALLS, which is what the course ACs measure, not on retries inside
  one call). The real urllib retry/backoff path is instead covered by monkeypatching
  `urllib.request.urlopen` directly in `test_resilience.py`, so the actual production retry code is still
  exercised offline.
- **A single global breaker instead of per-host.** Rejected: one failing registry (e.g. a firewalled
  `repo1.maven.org`) would short-circuit OSV and deps.dev calls too, which have nothing to do with the
  failure - over-blocking exactly the kind of honest-reporting gap this ADR is trying to close.
- **Replace `http_json`/`http_text` with an exception-raising API.** Rejected: every existing call site
  (`licenses.py`, `osv.py`, `arch.py`) would need a `try/except`, which is exactly the "existing API/return
  values must not change" constraint this package is built under. The additive `fetch_*` + unchanged
  `http_*` wrapper split avoids a breaking change while still giving new/updated callers the Outcome shape
  when they want it.

## 결과 (Consequences)

- Positive: a dead host now costs at most `failure_threshold` failed calls before the rest of a large scan's
  calls to that host are skipped (`STATS["short_circuited"]`), instead of retried individually; 404 vs.
  "could not reach the host" is now distinguishable for any NEW caller that uses `fetch_json`/`fetch_text`.
- Negative / limitation: the breaker is in-process, per-run state - it does not persist across separate CLI
  invocations, and (per the product's "no global config file" stance) its threshold can only be tuned via the
  `BTS_SBOM_BREAKER_THRESHOLD` environment variable, not a config option.
- Test risk, mitigated: per-host breaker state is a module-level global, so one test's failures could open a
  breaker that a later, unrelated test then observes as already open. `tests/bts_sbom_app/conftest.py` gained
  an autouse `_reset_circuit_breakers` fixture (calling `net.reset_breakers()` before AND after every test) to
  close this off; it does not touch the pre-existing `no_network` fixture.
- Not yet done (left as a future loop iteration, not hidden): no existing caller (`licenses.py`, `osv.py`,
  `arch.py`) was switched from `http_json`/`http_text` to `fetch_json`/`fetch_text` - the brief for this
  package restricts code changes to `resilience.py` (new) and `net.py` (additive only); wiring the richer
  `Outcome` into those callers' own evidence output is future work for whichever package owns them.
