# ADR-0014: Arch Intel — vendored Mermaid, metadata-only prompts, and clean-room guardrails as tested invariants

## Status

Accepted (v0.3.0). Scope: the new "Arch Intel" screen (`bts_sbom_app/arch_intel.py`, `bts_sbom_app/arch_api.py`,
`web/arch_intel*.js`, `/api/arch/...`) plus one vendored browser asset (`web/vendor/mermaid.min.js`). Additive: no
existing route, pane, CLI argument or return value changes.

## 근거 (Context)

The screen answers one user question about an open-source tree: "이 라이선스는 무엇이고, 이 아키텍처는 어떻게
생겼는가 — 그리고 그 요소가 실제 코드의 어디에 있는가". Three constraints shaped the design:

1. The project is standard-library-only on the Python side (ADR-0007) and the page runs under a strict CSP
   (`script-src 'self'`, no CDN). UML rendering therefore cannot pull Mermaid from a CDN, and a hand-rolled
   sequence/activity renderer would be a large, low-fidelity bespoke component.
2. The screen displays excerpts of a **copyrighted work** (the analysed tree) next to AI-generated analysis. An
   analysis tool that let a model echo source code back would turn the tool into a redistribution channel for
   copyleft works — the exact risk the GPL/AGPL verdict on the same screen warns about. The guardrail belongs in
   code and tests, not in a policy sentence.
3. The house honesty rule (absent data is `—`, "not computed" beats invented) applies to the dynamic view: the
   analysed tree is never executed, so every "dynamic" diagram is a static inference and must say so.

## 결정 (Decision)

- **Vendored Mermaid, lazily loaded.** `web/vendor/mermaid.min.js` (mermaid 11.12.2, MIT, sha256 pinned in
  `web/NOTICE.md`) is served from `/static/vendor/` (CSP-compatible) and injected by `arch_intel.js` only when a
  diagram is actually rendered, with `securityLevel: 'strict'`. Every diagram keeps its Mermaid source in a hidden
  `pre.arc-mermaid-src`; if the renderer cannot load, the pane shows that source text instead of an empty box.
  ADR-0007 is unaffected: this is a browser asset, not a Python dependency.
- **The model never sees source and never writes Mermaid.** `arch_intel.prompt_evidence` builds the LLM prompt from
  metadata only (paths, LOC, import edges, entry points); `validate_arch` drops any item whose strings carry code
  fences or code-shaped lines; the diagrams are generated deterministically from the *validated* analysis, so
  Mermaid syntax errors and ungrounded nodes are structurally impossible. Each layer is an AC
  (BSA-AC-447..449, BSA-AC-451).
- **Grounding by construction.** Every file a model names must exist in the analysed tree (else the component is
  dropped), every scenario participant must be a known component or entry point, and code excerpts are read with
  hard bounds (≤ 60 lines, anchor-windowed, server-side escaped and tokenized by `arch_intel.highlight`).
- **License verdict from existing machinery.** `licenses.scan_tree` + `licenses.category` + `OBLIGATIONS` for the
  verdict, `license_categories.compatible` for a pairwise compatibility matrix against common product licenses,
  plus a clause-level notice checklist (GPL §4-§7, AGPL §13) and a per-distribution verdict (binary/saas/internal).
- **Dynamic views are labelled static inferences.** Sequence/activity diagrams derived without an LLM are flagged
  `static inference`; scenario-level flows that need the LLM render "Not computed" when no key is configured.

## 기각 대안 (Rejected alternatives)

- **Mermaid from a CDN at page load** — rejected: the CSP (`script-src 'self'`) forbids it, and the screen must
  work offline like every other pane.
- **A bespoke SVG diagram renderer** — rejected for now: sequence diagrams with lifelines, activations and return
  arrows are a project of their own; the fallback (Mermaid source text) already keeps the pane honest and useful.
- **Letting the LLM emit Mermaid directly** — rejected: it couples grounding (file names) to rendering (diagram
  syntax) in one unvalidated channel; the deterministic generator keeps validation and rendering separate.
- **Showing full files instead of bounded excerpts** — rejected: the tool's job is anchoring, not redistribution;
  full text lives in the (temporary, deleted) work copy, not in evidence.
- **Executing the tree to obtain real traces** — rejected outright: the workspace contract ("nothing in the clone
  is ever executed") is a hard safety boundary.

## 결과 (Consequences)

- The Arch Intel pane can render real UML diagrams offline with a graceful textual fallback; `web/NOTICE.md` gains
  a vendored-asset table that any future `vendor/` member must extend.
- The clean-room posture is mechanically enforced and tested (BSA-AC-447..449): the tool can analyze a GPL work and
  present its architecture while provably never becoming a code-echo channel — and it says so on the screen.
- Analysis results duplicate the tree's *structure* (paths, edges) into `evidence/archintel/<job>/result.json`;
  excerpts stay bounded and carry their license in the payload, so the evidence folder remains distributable only
  under the same caution as the source tree itself.
- Two new in-memory job tables (`arch_jobs`, buses) follow the OSS screen's eviction pattern (running jobs and
  open buses are never dropped; finished jobs past MAX_JOBS=60 are).
