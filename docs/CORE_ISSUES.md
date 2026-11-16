# Open issues in the `bts_sbom` core, found while building BTS-SBOM

BTS-SBOM (`bts_sbom_app/`) is built on the `bts_sbom` core in this repository and never edits it. Defects found by measuring against
real repositories are recorded here as a work list for the core; each one has a workaround inside `bts_sbom_app/` so BTS-SBOM results stay
correct meanwhile. **None of these has been fixed in `bts_sbom/` by the integration** - fixing them is a core change that belongs
to whoever owns that package. When one is fixed, delete the matching workaround and its test.

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

## 4. `python -m bts_sbom --help` crashes on a cp949 console (found during the integration)

On a Korean Windows console (default code page cp949) `bts-sbom --help` exits 1 and `bts-sbom sector ...` exits 2 with
`'cp949' codec can't encode character '—'` (an em dash in the help/output text). With `PYTHONUTF8=1`
all 28 core tests pass, which is why the CI workflow sets it; without it `tests/test_bts_sbom_pkg.py::test_cli_help` and
`::test_cli_sector_all_six_sectors` fail on such a machine. Suggested fix: keep console output ASCII (or reconfigure stdout to
UTF-8) in the CLI. BTS-SBOM avoids the problem by printing ASCII unless `BTS_SBOM_UNICODE=1`.

**Already fixed elsewhere, not yet here:** the BTS platform's copy of the package (`ECU_Sentinel/bts_sbom`) fixed exactly this in
its commit `0d8e5e6` (ASCII-only help text, `errors=replace` on stdout/stderr, plus a regression test over every subcommand x 3
encodings). That commit is not in this repository's v0.1.1, so the fix has to be ported here (a core change that needs the core
owner's decision and a push - not done by the integration). Note the same drift in the other direction: the platform copy still
reports `__version__ = "0.1.0"` while this repository is 0.1.1.
