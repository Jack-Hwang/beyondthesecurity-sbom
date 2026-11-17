# AI suitability registry

BTS-SBOM uses one LLM (LG EXAONE, via `bts_sbom_app.llm.ChatClient`) for judgment that a rule table
cannot express. Every place the app calls the model directly must be named in
`bts_sbom_app.ai.AI_CALL_SITES` together with (a) why a deterministic rule was judged insufficient
and (b) a `fallback_test` pytest node id proving the deterministic path still works when the model
is unavailable, over budget, or returns something that fails validation. The habit this file exists
to support: do not reach for an AI call where a rule can already decide the answer, and never ship
one without a tested fallback.

`bts_sbom_app.ai.check_registry()` enforces this statically: it AST-parses `bts_sbom_app/ai.py`
(never executes it, makes no network call) for direct `client.complete(` / `ChatClient(` calls,
and fails if the enclosing function has no matching registry entry, or if a registered
`fallback_test` file or function cannot be found. Absence of a registry entry is reported as a
problem; it is never treated as "nothing to check".

## Checklist before adding a new AI call site

1. Can a deterministic rule (known-safe-version lookup, license policy, EOL date table, cycle
   detection, ...) already answer this exactly, every time? If yes, do not call the model.
2. Does this step require judgment over unstructured or free-form input - ranking competing valid
   answers, phrasing a rationale - that a rule table cannot express?
3. Is a wrong model answer recoverable? There must be a validation layer that drops anything not
   grounded in the evidence, and a deterministic fallback that produces an honest, usable result
   when the model is unavailable or its output does not validate (this product never reports a
   model success it did not have).
4. Add an entry to `bts_sbom_app.ai.AI_CALL_SITES`: a key, the enclosing function name as `site`,
   `why_not_rule_based`, and a `fallback_test` node id that exercises the fallback path.
5. `bts_sbom_app.ai.check_registry()` must return `[]` (no problems) after the change.

## Registered call sites (1 of 1 accounted for)

### `propose.remediation_ranking` -- `bts_sbom_app.ai.propose`

- **Why not rule-based**: `bts_sbom_app.ai.deterministic` already covers every remediation a rule
  table can express (apply the verified safe version, flag no-fix components, flag EOL runtimes,
  flag dependency cycles, flag extraction candidates). Ranking which of those competing findings
  matters most for a specific project, and phrasing a rationale grounded in its own evidence, is
  open-ended judgment over free-form input, not a lookup.
- **Guardrail already in place**: `bts_sbom_app.ai.validate` (schema / rule / semantic / cross-field,
  4 layers) drops any proposal not grounded in the evidence before it reaches a user.
- **Fallback test**:
  `tests/bts_sbom_app/test_ai_rag_loop.py::test_http_429_day_limit_downgrades_after_one_call` -
  asserts `ai.propose` returns `source == "deterministic"` with real items when EXAONE is
  unavailable (here: a provider day-limit response), after exactly 1 call, never a guessed value.

New call sites in `bts_sbom_app/chat.py` or `bts_sbom_app/loop.py` are out of scope for this
registry today (tracked by the audit under the same method id, w1s3:w1s3-13); extending
`check_registry()` to parse those modules too is a follow-up, not covered here.
