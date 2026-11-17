# ADR-0005: tokens.css is a separate, behaviour-neutral stylesheet linked first

Status: accepted
Decider: human (project owner); Claude explored the alternatives below, the
decision itself was made by a person, not by Claude.
Related: `bts_sbom_app/web/css/tokens.css`, `bts_sbom_app/web/css/app.css`

## Context

The BTS-SBOM web UI (WS7, UI-AC-3) originally held every colour as a literal
hex value scattered across `server/static/css/**`. A pass-1 codemod scanned
those stylesheets, ranked the most frequent hex colours, and extracted the
top 30 into `--c-*` custom properties; pass 2 (2026-11-14) extended that to
60. The question this ADR records: where do the extracted tokens live, and
in what load order, so the extraction stays behaviour-neutral (no visual
change) instead of silently becoming a new source of truth.

## Decision

Extracted colours live in their own file, `bts_sbom_app/web/css/tokens.css`,
and that file is linked FIRST in `<head>`, before `/css/app.css` and before
`light_theme_overrides.css`. Each `--c-*` token is an exact-value alias: it
resolves to the identical literal colour the original rule held, nothing is
renamed or merged across near-duplicate shades. The original 30 token lines
added in pass 1 are left untouched by pass 2; pass 2 only appends the next
most-frequent colours below them.

## Rationale

- Loading tokens.css first means every later stylesheet can reference a
  `var(--c-*)` and have it already defined; loading it last (or inline)
  would require a flash-of-unstyled-content guard or `!important` overrides
  that this change does not need.
- A separate file (rather than inlining the tokens into `app.css`) keeps the
  extraction a mechanical, reviewable diff: the token file is generated from
  a frequency scan and can be regenerated independently of hand-written
  rules in `app.css`.
- Exact-value aliasing (no renaming/merging of near-duplicate hex values)
  was chosen over a "cleaned up" palette because the goal of this pass is a
  behaviour-neutral refactor (Well-Architected: operational excellence over
  a cosmetic improvement) -- merging shades is a separate, visual decision
  that a human should make deliberately, with a visual diff in hand, not as
  a side effect of a token-extraction pass.

## Rejected Alternatives

| Alternative | Why rejected |
| --- | --- |
| Inline the `--c-*` custom properties directly into `app.css` | Mixes a mechanically generated block with hand-maintained rules; every future codemod pass would need to diff around hand edits instead of replacing one file. |
| Load tokens.css last (after app.css / overrides) | Later rules would reference custom properties that are not yet defined on first paint, which is exactly the flash-of-unstyled-content failure this ADR exists to avoid. |
| Merge near-duplicate hex shades into a single token while extracting | Changes the rendered colour in some places (not behaviour-neutral); rejected for this pass, left as a possible deliberate follow-up. |
| Use a CSS preprocessor (Sass/Less) variable instead of a custom property | Adds a build step to a project whose server-side code stays stdlib-only; a native CSS custom property needs no build step and is resolved by the browser itself. |

## Consequences

- Benefit: the extraction is behaviour-neutral and mechanically verifiable
  -- every `var(--c-*)` resolves to the exact original literal, so a diff
  review only needs to check the token table, not every call site.
  Measured: 60 tokens extracted from the two pass-1/pass-2 scans, with the
  original 30 pass-1 lines unmodified by pass 2.
- Trade-off: tokens.css is a third stylesheet that must be kept in the
  correct `<head>` order; dropping it or moving it after app.css silently
  reintroduces the flash-of-unstyled-content / undefined-custom-property
  failure mode with no error at build time (CSS custom properties resolve
  silently to nothing).
- Follow-up: a later, explicitly visual pass may merge near-duplicate hex
  shades (rejected alternative above) once a human reviews a rendered
  before/after diff; that is out of scope for this ADR.
