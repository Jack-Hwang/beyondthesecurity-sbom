# ADR-0015: Arch Intel insights — book-grounded deterministic heuristics, never a verdict

## Status

Accepted (v0.3.0). Scope: `bts_sbom_app/arch_flow.py` (new), integration points in
`bts_sbom_app/arch_intel.py` (structure manifests, prompt evidence, report section), the `latest_arch` chat tool
(`bts_sbom_app/chat.py`, `bts_sbom_app/server.py`), and the Insights pane in `web/arch_intel_render.js`.
Additive: no existing route, tool, CLI argument or return value changes.

## 근거 (Context)

The Arch Intel screen (ADR-0014) measures a tree's structure but stops at facts: import edges, cycles, clusters,
hotspots. An architect looking at the screen still has to do the first interpretive pass alone — *what slows a
change down here, where could this be split, what style is this?* Three constraints shaped the answer:

1. **The concepts are book knowledge, not code.** The heuristics restate what the team read in the architecture
   canon — flow blockers and bounded contexts (Kaiser, *Architecture for Flow*), bad smells as architecture
   signals (Fowler, *Refactoring*), styles/characteristics and modularity fitness (Richards/Ford/Gandhi,
   *Fundamentals of Software Architecture*, summarised in `knowledge/domain/`). Ideas are not copyrighted, but
   the provenance is documented on purpose: each insight names its intellectual basis in code comments and the
   knowledge notes, and no code of any book, tool or platform was copied (clean-room posture of ADR-0014).
2. **A heuristic that poses as a verdict is dishonest.** "This is a big ball of mud" from a tangle ratio is not a
   finding — it is a signal. The house honesty rule (absent data is `—`, no invention) applies with double force
   to interpretations, because a wrong "verdict" from a deterministic pipeline carries false authority.
3. **The AI lane must not become the interpretation layer.** The LLM lane is metadata-only and optional
   (ADR-0014); interpretations that should be available offline and deterministically belong in code, where they
   are testable and identical on every run.

## 결정 (Decision)

- **One pure module, five insight families.** `arch_flow.build_insights(structure, manifests)` derives, from the
  already-measured structure only: `flow_blockers` (import cycles, unstable hubs, hidden change coupling,
  hotspot concentration, high tangle), `bounded_context_candidates` (cohesive clusters with low inbound),
  `style_hypothesis` (layered / modular-monolith / distributed from layout + manifests),
  `antipattern_signals` (tangle+cycles, cohesion collapse, root sprawl, hub pressure) and `modularity`
  (per-cluster fitness numbers). No LLM, no network, no execution — `arch_flow` imports nothing but `typing`.
- **Every blocker cites its evidence and its threshold.** A cycle blocker says "import graph SCC"; an unstable
  hub says "fan-in ≥ 5, instability > 0.5"; the style hypothesis lists its raw signals. The renderer and the
  report section show these citations, so a reader can always walk the claim back to the measurement.
- **Hypothesis wording, everywhere.** The family notes, the pane's subtitle and the chat tool's closing line all
  say the same thing: heuristics over measured facts, never a verdict — the build/buy and team-boundary
  judgement stays with the architect. There is no "style" key when no signal exists (empty string, not a guess).
- **The chat reads the evidence folder, nothing more.** The `latest_arch` tool loads recorded runs from
  `evidence/archintel/` and summarises the one with the latest `finished` stamp (7 honest lines, or 1 honest line
  when nothing is recorded). It needs no analysed project and re-analyses nothing.
- **The pane is one more model-browser item.** Insights join the Arch Intel canvas as their own tree section; the
  result view stays the single source of truth the chat tool summarises.

## 기각 대안 (Rejected alternatives)

- **Let the EXAONE lane write the architecture narrative** — rejected: it would make the interpretation
  non-deterministic, unavailable offline, and prompt-shaped; the LLM lane already has a strictly separate job
  (naming components/scenarios from metadata), and mixing roles would weaken both validation layers.
- **Ship a numeric quality score (e.g. 0-100 "architecture health")** — rejected: a single composite number
  reads as a verdict, invites benchmarking across unlike projects, and hides which threshold fired. Signal lists
  with thresholds keep the uncertainty visible.
- **Reuse a copied heuristic implementation (e.g. an open-source designite/pylint-clone module)** — rejected on
  license and grounding grounds: the thresholds and semantics here must match *our* measured structure and stay
  standard-library-only (ADR-0007); clean-room specification from the books, with provenance documented, is both
  safer and smaller.
- **Derive insights from git history inside arch_flow** (change coupling, hotspots) — rejected: those
  measurements already exist one layer down (`arch`/`arch_intel.structure`); a second history walk would double
  the cost and risk divergent numbers on the same screen.

## 결과 (Consequences)

- The Arch Intel screen now answers the first interpretive question deterministically and offline; the AI lane
  and the insights layer cross-check each other (the prompt sees insight counts and candidate names only —
  BSA-AC-477 keeps the metadata-only invariant intact).
- Thresholds are constants in one module with tests pinning each one (BSA-AC-461..475); tuning a threshold is a
  one-line, test-visible change, never a silent behaviour drift.
- The `latest_arch` chat tool makes the recorded deep-dive reachable from the chat pane without a project loaded;
  its honesty when nothing is recorded (1 line, no invention) matches the screen.
- Renderer regressions found while landing this (sequence/activity items dropped from the model browser, the
  code view's Safe-wrapper bug) are fixed and pinned by the same AC set (BSA-AC-459/460, BSA-AC-478).
- `knowledge/domain/` gains the five notes the heuristics cite; future insight families must extend both the
  notes and the provenance comment, or their basis is undocumented.
