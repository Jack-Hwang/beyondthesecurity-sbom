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
