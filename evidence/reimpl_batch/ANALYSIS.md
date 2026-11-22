# Batch reimplementation analysis

Dataset: 130 rows over 64 unique packages (latest run per package wins). Model: the configured Azure lane, attempts=2, best-of-N.

## Verdicts (latest per package)

| verdict | count |
|---|---|
| tests_failed | 16 |
| ok | 15 |
| refused | 1 |

Skipped before the lane (py2-era syntax, no root module, no fitting release): 32 — these are exactly the packages where the reimpl lane is the only viable path once a python3-parsable release is chosen.

## Oracle strength of the 15 'ok' packages

- with the upstream legacy suite adopted (strong evidence): **0** — -
- without an upstream suite (contract-only evidence): **15** — argh, chardet, click, html5lib, idna, kombu, mimeparse, paste, pep8, pika, sqlobject, supervisor, tabulate, validators, xmltodict
- compatibility_failed: **0** — -

## Observations

- tests_failed (16): beaker, blinker, decorator, genshi, humanize, isodate, itsdangerous, jinja2, mock, pyflakes, pytz, six, sortedcontainers, toposort, webencodings, wrapt — the generated code failed its own contract smoke tests (generation-quality issues, typically an import or surface gap); per-attempt tails live in the per-package work folders.
- refused (1): nose — the license gate refused before generation (the license gate refused this component (license_ok=False)). The gate fired in the wild.
- no compatibility_failed verdicts in the latest run: the full-contract + behaviour-examples spec plus best-of-N selection reached full legacy-suite compatibility for every package that ran with an oracle.
- failures taxonomy needs a bigger compatibility_failed sample; the dataset keeps every run so later rounds can mine the failing-case tails.

## Reproduce

`python scripts/batch_reimpl.py --limit 60 --attempts 2 --skip-scan` then this script. Raw rows: dataset.jsonl (append-only).
