# Batch reimplementation analysis

Dataset: 151 rows over 64 unique packages (latest run per package wins). Model: the configured Azure lane, attempts=2, best-of-N.

## Verdicts (latest per package)

| verdict | count |
|---|---|
| ok | 31 |
| compatibility_failed | 1 |

Skipped before the lane (py2-era syntax, no root module, no fitting release): 32 — these are exactly the packages where the reimpl lane is the only viable path once a python3-parsable release is chosen.

## Oracle strength of the 31 'ok' packages

- with the upstream legacy suite adopted (strong evidence): **0** — -
- without an upstream suite (contract-only evidence): **31** — argh, beaker, blinker, chardet, click, decorator, genshi, html5lib, humanize, idna, isodate, itsdangerous, jinja2, kombu, mimeparse, mock, nose, paste, pep8, pika, pyflakes, six, sortedcontainers, sqlobject, supervisor, tabulate, toposort, validators, webencodings, wrapt, xmltodict
- compatibility_failed: **1** — pytz

## Observations

- **pytz**: the upstream legacy test suite failed - the reimplementation is not behaviour-compatible yet
- failures taxonomy needs a bigger compatibility_failed sample; the dataset keeps every run so later rounds can mine the failing-case tails.

## Reproduce

`python scripts/batch_reimpl.py --limit 60 --attempts 2 --skip-scan` then this script. Raw rows: dataset.jsonl (append-only).

## Mimeparse deep round (2026-11-28): the oracle regression, fixed, then measured live

Preparing the structured-feedback live run caught a REAL oracle regression: since the u-boot round, a
legacy suite shaped like mimeparse 0.1.3 (module-level test functions wired through
`unittest.FunctionTestCase` inside `run_tests()`, a self-running `__main__` guard, ZERO TestCase classes)
was being skipped by the static "no runnable tests" note even though the shim's own output said
`Ran 29 tests`. The static note outranked measured runtime evidence; every FunctionTestCase-style oracle
in the batch had silently graded nothing (mimeparse's batch row above reads "contract-only evidence"
because of exactly this). Fixes, all measured:

- `run_adopted_tests`: runtime evidence now outranks the static note - the skip needs the runtime to agree
  (nothing ran AND a clean exit or a statically helper-shaped file).
- `_reconcile_adopted_test`: FunctionTestCase suites count as runnable cases; a suite with its own
  `__main__` guard needs no injected `unittest.main` tail (injected into a FunctionTestCase suite it
  would run 0 tests and exit 5, flipping a pass into a fail).
- the best-of-N bookkeeping parsed only `FAILED (failures=N, errors=M)`; suites printing
  `FAILED (failures=N)` alone read as 10**6 and never engaged best-of-N. Now any counts list parses.

Live measurements on mimeparse 0.1.3, azure gpt-5-mini, oracle restored (report.json in evidence/reimpl/,
local-only):

| run | attempts | legacy failures (of 29) | note |
|---|---|---|---|
| e2e2 (pre-regression code, re-measured today) | 2 | 14 | the 7/29 previously reported was measured before the skip rule existed |
| e2e4 | 4 | **4** | best attempt 3, copy gate 0.0, contract tests pass |
| e2e5 | 4 | **4** | independent re-run: the plateau reproduces |
| e2e6 | 8 | 7 | attempt degraded: one generation returned a bare `\d` inside the JSON envelope, strict parse refused, scaffold fallback broke the loop |

Structured feedback (assertion lines ride the retry prompt) + working best-of-N moved 14 -> 4. The
remaining 4 are algorithm subtleties the model does not reach in 4 attempts: the legacy `q=2` clamp
(parse_media_range normalises q>1 to '1'), two `level=3` exact-param quality rows (unmatched params must
not inherit the bare type's q), and the wildcard best_match label row (`image/*` must be returned, not
the empty string). Attempts=8 additionally exposed a second measured defect - the JSON envelope salvage
in `ai._parse_json` (bare backslashes inside strings, lookbehind placed BEFORE the match - an
after-position assertion always sees the backslash it just consumed) - now unit-tested.

Batch impact: FunctionTestCase-style oracles across the dataset now grade honestly; the 31 'ok' verdicts
were contract-only evidence and stay so until each is re-run - no verdict is retroactively upgraded here.

## Metrics-envelope round (2026-11-28 night, AC-1279): plateau confirmed at 4

The Understand-catalog behavioral envelope (per-function complexity/essential/statements/eLOC/Halstead
volume from the recovered 140-metric catalog) now rides the clean-room SPEC channel next to the UML
design view - numbers only, wall-2 honesty test-enforced. Live mimeparse with the envelope: **4 of 29
legacy failures, best attempt 2** - identical to the pre-envelope baseline (e2e4/e2e5). Three
configurations now converge on 4: the remaining cases (the legacy q=2 clamp, the two level-param rows,
the wildcard best_match label) need the legacy oracle's EXAMPLES, not more shape information. Next
levers: oracle example rows through the spec channel (measured once already - counterproductive at full
table, untested bounded), or a different deployment model for one attempt.

## Targeted-example round (2026-11-28 night, AC-1280): the plateau is MODEL-bound

The retry feedback now carries the FAIL blocks' exact (function, args, expected) pairs - the failing
rows only, capped at eight, prompt budget 800->1200. Live mimeparse: **4 of 29 remain, best attempt 3**
- identical to every previous configuration. Four configurations (plain feedback / best-of-N / metrics
envelope / targeted examples) all converge on exactly 4: with assertion lines, shape facts AND exact
input-output pairs all delivered, the residual 4 cases (the legacy q=2 clamp, the two level-param rows,
the wildcard best_match label) are beyond gpt-5-mini's reach in this prompt family. The lever was
implemented and measured honestly; the next lever is a stronger deployment model for one attempt, not
more prompt engineering.
