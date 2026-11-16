# Contributing to bts-sbom

Thanks for considering a contribution. Keep it small, honest, and tested.

## How to propose a change

1. Open an issue first for anything bigger than a typo fix — describe the
   behavior change and the honesty implications (see below).
2. Fork / branch, keep one logical change per PR.
3. PRs must include tests. CI runs `pytest tests/` and `ruff check bts_sbom/`.

## Development setup

```console
$ pip install -e .
$ pip install pytest ruff
$ pytest tests/
$ ruff check bts_sbom/
```

## Non-negotiables

* **Stdlib-only.** No third-party runtime dependencies. If you need network
  I/O, use `urllib`. The self-SBOM (`python -m bts_sbom selfsbom`) asserts a
  complete, empty dependency graph — a new dependency breaks that claim.
* **Honesty discipline.** Absent evidence is `not_evidence` / `unknown`, never
  a pass. "No data" must never render as "no vulnerability". Every verdict
  carries its measured evidence. If your feature cannot state what it does NOT
  know, it does not ship.
* **Python >= 3.10.** The vendored modules in `bts_sbom/_internal/` carry
  `# vendored from ...` headers — prefer fixing behavior in the right place and
  note in the PR description what was changed relative to the platform source.

## Commits & style

* `ruff`-clean code, line length 100.
* Plain commit messages in imperative mood ("add eol fallback to cra readiness
  check"), no noise commits.
