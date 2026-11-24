# ADR-0008: Approval-gated manifest patching (digest token, re-scan, revert)

## Status

Accepted. Post-hoc record: `bts_sbom_app/patch.py` and the patch loop in `bts_sbom_app/pipeline.py` already implement
this; this document records why, citing the acceptance criteria that measure it. Current as of 2026-11-20.

## 근거 (Context)

`patch.approval_digest(plans)` hashes the exact set of proposed upgrades; `patch.apply(root, plans, approved=...,
token=...)` only writes manifest edits when `approved=True` **and** `token == approval_digest(plans)` — otherwise it
reports `status="not_approved"` or `status="digest_mismatch"` and changes 0 files. This is measured directly:

- `BSA-AC-14` — "When a patch is requested without approval, the system shall change 0 files and report
  not_approved" (test: `tests/bts_sbom_app/test_patch_delivery.py::test_no_approval_changes_nothing`).
- `BSA-AC-15` — "If the approval token does not match the plan digest, the system shall apply 0 changes and report
  digest_mismatch" (test: `tests/bts_sbom_app/test_patch_delivery.py::test_digest_mismatch_applies_nothing`).
- `BSA-AC-18` — "If a re-scan after patching shows more vulnerabilities, the system shall reset the work copy to the
  pre-patch commit and report regression_reverted" (test:
  `tests/bts_sbom_app/test_patch_delivery.py::test_regression_after_patch_is_reverted`).
- `BSA-AC-1` — the origin tree hash stays byte-identical throughout (test:
  `tests/bts_sbom_app/test_patch_delivery.py::test_pipeline_patch_flow_origin_untouched_and_findings_to_zero`),
  because everything above happens in an isolated work copy (`workspace.prepare`), never the caller's own checkout.

`pipeline._patch_loop` re-scans after every applied round and compares findings scoped to the files the patch itself
edited (its own comment explains why: a lockfile the patch did not touch still pins old versions, so comparing grand
totals "blamed the patch for findings it cannot influence" — measured: "a package.json-only npm patch of 134
packages was reverted because ONE new advisory appeared at an upgraded version"). On a scoped regression it calls
`patch.revert(path, base)` and reports `regression_reverted`. The chat layer adds one more gate on top: `actions.py`
(`ChatActions.patch_apply`) requires the token to be "exactly the plan it was shown" and the chat tool-call validator
drops any token, source, or confirm code the model invents rather than copies verbatim from the user's own message
(`BSA-AC-203`).

## 결정 (Decision)

A patch to a project's manifests is applied if and only if the caller supplies `approved=True` and a `token` equal
to `patch.approval_digest()` of the exact plan being applied. There is no other path to writing a manifest edit in
this codebase. Once applied, the result is re-verified by re-running the same analysis (`engine.analyze`) on the
patched work copy; if the findings scoped to the edited files got worse, the work copy is reset to the commit
recorded before patching (`workspace.head(path)["commit"]`) and the result is reported as `regression_reverted`,
never as a silent "applied". The origin source tree is never touched by any of this (patch, re-scan, revert all
happen in a disposable work copy; delivery to the origin, if ever done, is a separate explicit `deliver_target`
flag).

## 기각 대안 (Rejected alternatives)

- **Apply upgrades automatically whenever OSV confirms the candidate version is clean.** Rejected: "clean per OSV"
  only means no *known* vulnerability at that version, not that the upgrade is safe to adopt (a major version bump
  can break the caller's code with no CVE involved). The product's own honesty contract — "푸시·적용은 명시 플래그와
  사람 승인 뒤에만" — requires an explicit, out-of-band human approval before anything is written, even to a
  disposable work copy.
- **Approve by naming the component instead of hashing the whole plan.** Rejected: a plan recomputed between being
  shown and being applied (e.g. a new OSV advisory lowers the "safe" version between two calls) must not be silently
  approved under a stale description. Hashing the plan's exact content, not just a label, is why a token issued for
  one component selection is refused — not silently reused — for a different selection (`actions.py`'s separate
  per-selection digest, exercised by `BSA-AC-202`).
- **Keep retrying after a detected regression instead of reverting.** Rejected: `_patch_loop` already has a spinning
  guard (`seen_plan_sets`) and a bounded `rounds` count; silently retrying a regressing patch would hide a real
  break behind an eventually-accepted status rather than surfacing it as `regression_reverted`.

## 결과 (Consequences)

- Every manifest change this tool ever makes is attributable to one explicit `(plan digest, human approval)` pair,
  is re-verified against the same analysis pipeline after being written, and has an automatic rollback path when the
  re-verification is worse than before. This is the write-side half of "근거가 없으면 통과가 아니다 / 원본은 건드리지
  않는다".
- The regression check is scoped to files the patch itself edited, by deliberate design (see the comment in
  `pipeline.py` above `_patch_loop`'s `scoped()` helper) — a regression introduced in a file the patch did not touch,
  or in a different manifest that declares the same component, is outside this gate's detection by construction.
  This ADR does not change that scope, only records that it is a deliberate, measured tradeoff (fewer false
  reverts) rather than an oversight.
