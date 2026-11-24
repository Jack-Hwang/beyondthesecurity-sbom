# ADR-0007: Standard-library-only, zero third-party runtime dependencies

## Status

Accepted. Post-hoc record: this decision was already in force in `main` before this ADR was written (`pyproject.toml`
has shipped `dependencies = []` and the self-SBOM proof since before 0.2.0); this document only writes the reasoning
down. Current as of 2026-11-20.

## 근거 (Context)

`pyproject.toml` declares `dependencies = []` with the comment "HONESTY: zero third-party runtime dependencies —
verified by the self-SBOM" (line 27-29), and the package proves this of itself at runtime: `python -m bts_sbom
selfsbom` emits a CycloneDX document whose own `dependsOn` list is empty (README.md, "Zero third-party runtime
dependencies" section). `requires-python = ">=3.10"` is declared in the same file.

Every piece of functionality that would normally reach for a popular third-party library has been built on the
standard library instead, and the code says so at the point where it would otherwise have taken a shortcut:

- HTTP: `bts_sbom_app/net.py` is a hand-written `urllib.request` wrapper with its own retry/backoff and request
  counting ("Minimal HTTP JSON helper (stdlib urllib) with retry/backoff and honest failure accounting" — module
  docstring), used by every outbound call in the app (`licenses.py`, `osv.py`, `arch.py`'s `endoflife.date` lookup).
- The LG EXAONE client (`bts_sbom_app/llm.py`) is a hand-rolled OpenAI-compatible chat-completions client over
  `urllib.request`, not an SDK ("LG EXAONE (K-EXAONE, OpenAI-compatible chat completions) client - stdlib only" —
  module docstring).
- CVSS v4.0 scoring (`bts_sbom_app/cvss4.py`, `cvss4_data.py`) is "a faithful port of the scoring procedure of FIRST's
  reference calculator" rather than a dependency on an existing CVSS library.
- The CLI (`bts_sbom_app/cli.py`) is built on `argparse`, not `click`/`typer`.
- Document/record validation (`sbom.validate_cyclonedx`, `sbom.validate_spdx`, `speclint.lint`, this package's own
  `doclint.py`) is hand-written string/structure checking, not a schema-validation framework such as `pydantic` or
  `jsonschema`.

## 결정 (Decision)

BTS-SBOM (both the `bts_sbom` core and the `bts_sbom_app` workflow layer) ships with `dependencies = []` and uses
only the Python standard library at runtime, for Python 3.10 through 3.12, on both Windows (cp949 console) and
Linux. The claim is falsifiable by the reader, not just asserted: `python -m bts_sbom selfsbom` builds this
package's own CycloneDX SBOM and that document's `dependsOn` is empty. Development-only tools (`pytest`, `ruff`) are
not runtime dependencies and are not shipped with the installed package.

## 기각 대안 (Rejected alternatives)

- **`requests` / `httpx` for HTTP calls.** Would remove the retry/backoff/circuit-style bookkeeping now hand-written
  in `net.py` and `llm.py`. Rejected because a dependency-free supply-chain-security tool that itself depends on
  third-party packages undercuts its own pitch — a CRA/FDA-524B/finance-sector user vetting their software supply
  chain would have to vet and vendor this tool's HTTP library too.
- **`pydantic` (or another schema-validation framework) for SBOM/VEX/project-record validation.** Rejected in favor
  of small, inspectable stdlib validators (`sbom.validate_cyclonedx`, `sbom.validate_spdx`, and this package's own
  `doclint.py`/`speclint.py`) so every validation rule is a readable function, not a framework's generated code path,
  and so the "정직 계약" (no pass without evidence) is enforced in code anyone can read without learning a library.
- **`click`/`typer` for the CLI.** Rejected in favor of `argparse` (stdlib); `bts_sbom_app/cli.py` already builds its
  parser with `argparse.ArgumentParser`, so adding a second CLI framework for new subcommands would be inconsistent
  for no measured benefit.

## 결과 (Consequences)

- The self-SBOM dependency proof (`selfsbom`) is trivially and permanently true, and the package is straightforward
  to vendor, review line-by-line, or run air-gapped — a real requirement for the regulated sectors this tool targets
  (CRA, FDA 524B, UNECE R155/R156, EO 14028, 금융, 로봇/ISO 10218).
- The project re-implements functionality a dependency would give for free: CVSS v4.0 scoring, HTTP retry/backoff,
  an OpenAI-compatible chat client, markdown/doc linting. Each re-implementation is a maintenance surface this
  project owns outright (e.g. `cvss4_data.py` must be re-synced by hand if FIRST changes its reference tables).
  Python-3.10 compatibility additionally rules out some newer stdlib conveniences repo-wide (`tomllib`,
  `datetime.UTC`, `ExceptionGroup`, `typing.Self` are all 3.11+ and must not be used).
- This ADR's own companion module, `bts_sbom_app/doclint.py`, follows the same rule: it uses standard-library modules
  only (`argparse`, `glob`, `os`, `re`, `sys`, `typing`).
