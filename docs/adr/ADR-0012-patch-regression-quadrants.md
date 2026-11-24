# ADR-0012: Four-quadrant patch regression impact + artifacts-only independent review

## Status

Accepted (2026-11-20).

## 근거 (Context)

`pipeline._patch_loop`'s regression check (the `scoped()` comparison right before the `regression_reverted`
branch) only looks at findings attributable to the files the patch EDITED. The comment next to it is explicit
about why ("a lockfile we deliberately did not touch still pins the old versions") but that same scoping means
the loop is structurally blind to the other three places a regression can hide:

- a sibling, untouched component declared in the SAME manifest we just edited;
- a transitive dependency the upgrade pulls in;
- the SAME vulnerable component still declared, unpatched, in a DIFFERENT manifest of this project or a
  DIFFERENT project entirely.

The course material's database regression quadrants (lecture 3-3 p.56: direct/upstream/downstream/shared)
name exactly this shape of gap, and calls out "shared" as the one most often missed in practice - a query is
"fixed" but another, untouched query reads the same table. For BTS-SBOM, the direct SBOM analogue of that
anti-pattern is: a vulnerable package is upgraded in one `requirements.txt`, the patch pipeline reports
success, but a second `requirements.txt` in the same repository (or a second project entirely, visible only
through `fleet.py`'s cross-project registry) still declares the exact same vulnerable version - unpatched.

Verified not already present: `git grep -n "quadrant\|direct.*upstream.*downstream.*shared"` on `main` and
`rel/v0.2.0` returns nothing; the only existing regression judgement is the `scoped()` comparison described
above. Likewise no independent-review step exists between `patch.apply()` (sandbox apply) and the human
approval token - the lecture's propose -> sandbox -> independent review -> human approval -> apply pipeline
(3-3 p.54) currently skips straight from sandbox to the existing 16-character approval-token gate.

## 결정 (Decision)

`bts_sbom_app/impact.py`: a PURE function `classify(before_components, before_vulns, after_components,
after_vulns, changed_files, plans, *, regenerate=None, fleet=None)` that translates the four DB quadrants into
SBOM terms (see the module docstring's table) and returns one `{status, checked, counts, evidence}` block per
quadrant plus an aggregate `verdict`. The honesty rule drives the design: a quadrant with data it cannot read
(no re-scan happened, no fleet registry given) is `"unverified"`, never silently `"ok"` - and the aggregate
`verdict` is `"clean"` only when every quadrant is `"ok"`/`"n/a"`, `"incomplete"` when something is
`"unverified"` with no regression found, and `"regression"` the moment any quadrant finds one. This closes the
project's measured State-pattern gap (0 of 190 existing ACs used "While ..." - counted with
`speclint.parse` on the base spec) with BSA-AC-321: *while any quadrant is unverified,
the verdict shall never equal clean*.

`bts_sbom_app/review.py`: a deterministic function `review(*, plan_digest, changed_files, planned_manifests,
diff_stats, impact, plan_summary, major_bump_confirmed=False, max_diff_lines=400)` that takes ONLY the patch's
ARTIFACTS - never the planner's internal plan objects, never a parameter named `rec` (enforced by
`tests/bts_sbom_app/test_impact_review.py::test_review_signature_has_no_rec_parameter` inspecting the live
function signature, not a convention anyone could quietly break). It returns
`{verdict, findings, reviewer: "deterministic-v1", independent: True}` and is advisory only: it has no write
access to anything and cannot itself approve or apply a patch - the existing 16-character approval-token gate
in `patch.py` is completely unchanged.

`pipeline._patch_loop` (the only part of `pipeline.py` this package may touch): once the loop's final status
is decided (every path past the `not_approved` early return), it builds the plan list enriched with each
plan's `patch.apply()` outcome (`"apply_status"`, used only to surface upper-bound blocks in the upstream
quadrant), calls `impact.classify()` with the pre-patch `rec["components"]`/`rec["vulns"]` and the LAST
post-patch re-scan it already computed internally (previously discarded once the loop moved to the next
round), and adds `out["impact"]`/`out["review"]` to its result. `fleet` is always passed as `None` from this
call site (`_patch_loop` has no access to the cross-project registry and this package may not change
`run_project`'s signature to add one) - the shared quadrant's fleet half is therefore always `"unverified"`
when reached only through the patch loop, which is the honest answer, not a guess.

## 기각 대안 (Rejected alternatives)

- **Keep judging regression only on edited files (status quo).** Rejected: this is the exact gap the ADR
  exists to close, and the course material explicitly flags it as the most commonly missed quadrant.
- **An LLM-based reviewer.** Rejected: the product's "zero network/LLM calls in tests" rule and the "origin
  untouched, patch only after explicit approval" honesty contract both favour a reviewer whose verdict is
  reproducible from the same inputs every time; an LLM reviewer would also need network/LLM access that is
  explicitly out of scope for this package and would turn a deterministic policy check into a probabilistic
  one for a security-relevant gate.
- **Let the reviewer see the planner's full internal state (`rec`) and/or let it approve the patch itself.**
  Rejected on two separate grounds: (1) the lecture's "independent review" step is independent BECAUSE it
  only sees what a real external reviewer would be handed (artifacts), not how the planner got there; (2)
  giving the reviewer the power to approve would duplicate/bypass the existing, already-reviewed 16-character
  approval-token human gate - this ADR adds a second, ADVISORY opinion, not a second authority.
- **Classify regression only on "the patch failed to produce fewer vulnerabilities" (a simple total-count
  delta).** Rejected: a project-wide total hides exactly which of the four quadrants moved, so a caller could
  not tell "the upgrade itself is clean but a sibling manifest wasn't fixed" from "everything is fine" - the
  same loss of information the per-file `scoped()` comparison already has, just at a different scope.

## 결과 (Consequences)

- Positive: the shared-quadrant anti-pattern from the lecture (same component, two manifests, one patched) is
  now mechanically detected (`tests/bts_sbom_app/test_impact_review.py::
  test_shared_regression_same_component_two_manifests_one_patched`), and the same check extends to other
  projects when a fleet registry is supplied by a caller that has one (e.g. a future web/CLI command, not
  `_patch_loop` itself).
- Negative / limitation: `_patch_loop` itself can only ever pass `fleet=None` (see Decision), so the shared
  quadrant's cross-project half is always `"unverified"` when driven purely through the patch loop; a caller
  that has its own fleet data (e.g. a future CLI/web command building on `impact.classify()` directly) can
  pass it and get the full check. This is recorded, not hidden, in each result's own `evidence` list.
- Negative / limitation: the "transitive" classification (`relationship != "direct"`) depends on the
  underlying scanner actually reporting dependency relationships; ecosystems/scanners that cannot determine
  depth report `relationship=""`, which this module treats as "not proven direct" (conservatively counted as
  downstream) rather than guessing.
- Test risk, mitigated: a computation failure in either `impact.classify()` or `review.review()` inside
  `_patch_loop` is caught and recorded as `{"error": ...}` rather than raised, so a bug in this ADDITIVE
  feature can never turn an otherwise-successful patch result into an exception for the caller; the existing
  patch tests (`tests/bts_sbom_app/test_patch_delivery.py`) all still pass unchanged (verified: `python -X
  utf8 -m pytest -q tests/bts_sbom_app` - full suite including the pre-existing 232).
