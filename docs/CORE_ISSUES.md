# Open issues in the `bts_sbom` core, found while building BTS-SBOM

BTS-SBOM (`bts_sbom_app/`) is built on the `bts_sbom` core in this repository and never edits it. Defects found by measuring against
real repositories are recorded here as a work list for the core; each one has a workaround inside `bts_sbom_app/` so BTS-SBOM results stay
correct meanwhile. **Items 1-3 are still open (fixing them is a core change that belongs to whoever owns that package); item 4 was
fixed in 0.2.0.** When one is fixed, delete the matching workaround and its test.

## 1. Guided remediation returned git commit SHAs as "safe versions" (v0.1.0)

`OsvScanner.scan(..., guided_remediation=True)` took the highest `fixed` event across ALL OSV range types, including `GIT`
ranges, so e.g. `requests 2.19.1 -> safe_version 74ea7cf7a6a27a4eeb2ae24e162bcc942a6706d5`.
BTS-SBOM does not use the core planner: `engine.fixed_versions` keeps only ECOSYSTEM/SEMVER ranges that contain the installed
version (`tests/bts_sbom_app/test_engine_licenses.py::test_fixed_versions_never_a_commit_sha`). Not re-checked against v0.1.1 (its
`remediation.py` addresses this class of problem).

## 2. SPDX writer strips a closing parenthesis (v0.1.1)

`bts_sbom.sbom._valid_expression` returns `expression_string(node).strip("()")`. `strip` removes characters from BOTH ends, so
`BSD-3-Clause AND (Apache-2.0 OR MIT)` becomes `BSD-3-Clause AND (Apache-2.0 OR MIT` and is written into
`licenseConcluded` / `licenseDeclared`; `validate_spdx` then rejects the document ("non-SPDX license value").
Suggested fix: remove ONE pair of outer parentheses only when they wrap the whole expression.
BTS-SBOM workaround: `sbom.spdx()` restores the original expression when the core's value has unbalanced parentheses
(`tests/bts_sbom_app/test_engine_licenses.py::test_parentheses_survive_and_spdx_validates`).

## 3. `go.sum` entries are reported as installed packages (v0.1.0/v0.1.1)

`go.sum` lists every module version that was ever considered, not the versions selected for the build (MVS), so e.g.
`gopkg.in/yaml.v3 v3.0.0-2020...` and `golang.org/x/sys v0.6.0` appear next to the selected `go.mod` versions and inflate the
findings. BTS-SBOM ignores go.sum-only entries when a sibling `go.mod` exists (see CHANGELOG / loop pass notes).

## 4. `python -m bts_sbom --help` crashed on a cp949 console (FIXED in 0.2.0)

On a Korean Windows console (default code page cp949) `bts-sbom --help` exited 1 and `bts-sbom sector ...` exited 2 with
`'cp949' codec can't encode character U+2014` (an em dash in the help/output text). The core CI hid it because its workflows set
`PYTHONUTF8=1`.

**Fixed in 0.2.0** (ported from the platform copy's commit `0d8e5e6` and extended): help and error text is pure ASCII; `main()`
switches stdout/stderr to `errors="replace"` for human-readable output; JSON/SARIF on stdout is re-serialised with
`ensure_ascii=True` when the console cannot encode it, so machine-readable output stays lossless. Regression tests in
`tests/test_bts_sbom_pkg.py`: `test_cli_help_survives_non_utf8_console`, `test_help_text_is_pure_ascii`,
`test_json_stdout_is_lossless_on_non_utf8_console` (cp949 / cp1252 / ascii, `PYTHONUTF8` unset). BTS-SBOM's own ASCII-by-default
console output (`BTS_SBOM_UNICODE=1` opts in) was a workaround for this defect and can be simplified in a later release.
