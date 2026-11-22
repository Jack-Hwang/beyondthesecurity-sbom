# Web assets copied from the BTS platform

The page served by `bts-sbom-app serve` reuses the platform's "Open-Source Security" screen so BTS-SBOM looks and is organised like
the rest of the BTS workbench. These six files are **copied unmodified (compared as LF-normalised bytes, so Windows/Linux checkouts agree) and must not be edited here**; changes belong in the
platform repository and are then re-copied (update `PLATFORM_ASSETS.sha256` at the same time - a test compares the hashes).

| file here | source in the platform repository (`ECU_Sentinel`) | last platform commit | sha256 (first 16) |
|---|---|---|---|
| `css/tokens.css` | `server/static/css/tokens.css` | `bd75086` | `c0309e605bffc59b` |
| `css/app.css` | `server/static/css/app.css` | `bd75086` | `0241c0cbff7a902b` |
| `css/light_theme_overrides.css` | `server/static/css/light_theme_overrides.css` | `07d1def` | `cdf933fb7d36ee6a` |
| `css/view_scan.css` | `server/static/css/views/view_scan.css` | `bd75086` | `e1192d8af8c05da9` |
| `sca_app.css` | `server/static/sca_app.css` | `21c3eac` | `693dcd5c9515406b` |
| `sca_app.js` | `server/static/sca_app.js` | `41dafaa` | `77c8805e18f27ab0` |

Everything else in this folder (`index.html`, `bts_console.js`, `bts_console.css`) is new code written for BTS-SBOM. To look like the
platform, it reproduces some platform *values* by hand rather than by copying files: the pane layout (title row, grey description,
dark summary cards, flat table) of the platform's `server/static/index.html` panes, and the sub-tab chip style of
`server/static/css/views/view_consolidation.css` (section 4). Two title colours were darkened because the platform's pale green and
lime are hard to read on the light page.

Provenance and licence: the files come from the same authors (BTS) and the core's README describes the SCA stack as vendored
from the platform under Apache-2.0. The platform repository's own licence file was not checked here - confirm it before
redistributing these six files outside this repository.

What the renderer does and does not know: `sca_app.js` is a pure renderer (`ScaApp.render(mount, report, opts)`, no network
calls). BTS-SBOM supplies the report through `bts_sbom_app/console.py`; fields BTS-SBOM does not compute (KEV, EPSS, reachability,
priority, VEX status per finding) are left out of the report rather than invented, and the renderer shows them as absent.

Two labels inside `sca_app.js` say "AutoGuard" (the organisation badge and the breadcrumb) and the renderer has no option for them.
Because the file must stay an unmodified copy, `bts_console.js` rewrites those two labels to "BTS-SBOM" after every render
(`rebrand()`); the copy itself is unchanged.
