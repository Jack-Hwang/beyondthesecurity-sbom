# Web assets copied from the BTS platform

The page served by `bts-sbom-app serve` reuses the platform's "Open-Source Security" screen so BTS-SBOM looks and is organised like
the rest of the BTS workbench. These six files are **copied byte-for-byte and must not be edited here**; changes belong in the
platform repository and are then re-copied (update `PLATFORM_ASSETS.sha256` at the same time - a test compares the hashes).

| file here | source in the platform repository (`ECU_Sentinel`) | last platform commit | sha256 (first 16) |
|---|---|---|---|
| `css/tokens.css` | `server/static/css/tokens.css` | `bd75086` | `c0309e605bffc59b` |
| `css/app.css` | `server/static/css/app.css` | `bd75086` | `908abeef933429ff` |
| `css/light_theme_overrides.css` | `server/static/css/light_theme_overrides.css` | `07d1def` | `4e8952bc12e19d44` |
| `css/view_scan.css` | `server/static/css/views/view_scan.css` | `bd75086` | `5d87d7e2060d22c1` |
| `sca_app.css` | `server/static/sca_app.css` | `21c3eac` | `886af250bc3735ef` |
| `sca_app.js` | `server/static/sca_app.js` | `21c3eac` | `35e64224ee2a80a5` |

Everything else in this folder (`index.html`, `bts_console.js`) is new code written for BTS-SBOM.

Provenance and licence: the files come from the same authors (BTS) and the core's README describes the SCA stack as vendored
from the platform under Apache-2.0. The platform repository's own licence file was not checked here - confirm it before
redistributing these six files outside this repository.

What the renderer does and does not know: `sca_app.js` is a pure renderer (`ScaApp.render(mount, report, opts)`, no network
calls). BTS-SBOM supplies the report through `bts_sbom_app/console.py`; fields BTS-SBOM does not compute (KEV, EPSS, reachability,
priority, VEX status per finding) are left out of the report rather than invented, and the renderer shows them as absent.

Two labels inside `sca_app.js` say "AutoGuard" (the organisation badge and the breadcrumb) and the renderer has no option for them.
Because the file must stay an unmodified copy, `bts_console.js` rewrites those two labels to "BTS-SBOM" after every render
(`rebrand()`); the copy itself is unchanged.
