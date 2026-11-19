# SBOM governance (conformance, changes, triage, fleet)

Origin: 6th FOSSLight Community Day, 2026-10-28. Commands: conformance, diff, vex, review, fleet. Deterministic and read-only; an LLM may only narrate verified figures.

## conformance: SBOM regimes

Command `bts-sbom-app conformance <sbom-file | project>`. One document is checked against five regimes at once.
Regimes: ntia-2021 (7 NTIA fields), cisa-2025-draft (CISA 2025 draft: hash, license, tool name, generation context; DRAFT), eu-cra-annex-i (EU CRA Annex I Part II(1): machine-readable SBOM with top-level dependencies),
bsi-tr-03183-2 (BSI TR-03183 Part 2 data fields), vuln-ready (internal: exact version and purl per component).
Verdict per regime: conformant, partial or gaps. Missing evidence is a gap, never a pass. The matrix is a subset of fields with a review date (as_of), not a legal assessment.
Fix once, satisfy many: one missing field such as supplier blocks NTIA, the CISA draft and BSI together.
A component without version cannot get a version-specific vulnerability list (FOSSLight Hub behaves the same).
Generation context: an SBOM made from source manifests declares lifecycle phase pre-build; an SBOM supplied by someone else declares none.

## changes: diff and alerts

A second analysis of the same project keeps the earlier record as `<name>.prev.json` and attaches `changes`. Also `bts-sbom-app diff <project | before.json after.json>`.
Alert rules copy Hub mail notification: a finding with score at or above the threshold (default 7.0) appears, or an existing finding crosses the threshold up or down.
Extra alerts: malicious package advisory, copyleft license introduced. A finding without score counts as the lower bound of its label (HIGH 7.0, CRITICAL 9.0).
`--fail-on-alert` exits 1 on a critical or high alert for CI. Nothing is sent; `--llm` narrative is dropped when it holds a figure absent from the facts.

## triage and OpenVEX, fail-closed

Decision store `.triage.json`: note, justification, expires, scope, by. Export with `bts-sbom-app vex <project>`.
false-positive becomes not_affected only with an OpenVEX justification and a reason of 10 characters or more; otherwise affected plus status_notes.
accepted and wontfix stay affected; the action statement names reason, owner and end date. An expired decision reopens the finding.
A fixed claim is refused while the scan still reports the finding. A scoped decision (ID@package) beats a global one.
`bts-sbom-app review <project>` lists weak matches (no confirming range, dev-only dependency) as a worklist; the model never creates a decision.

## fleet: affected projects

`bts-sbom-app fleet --cve CVE-... ` or `--component requests --version "<2.20,>=2.0"` finds the affected projects, like Hub lookup of projects using a version.
A component with no recorded version is reported as version_unknown. Without arguments it prints the portfolio roll-up: weighted ranking, shared advisories, shared components. The ranking is an ordering aid, not a risk metric.

## chatbot tools

Read-only tools affected_projects (all projects, no project name needed), sbom_conformance, what_changed. A missing record is answered as not recorded.

## chat actions: analyse, patch, VEX decision

Command `bts-sbom-app chat --actions --evidence <dir>` (interactive: `-i`) or `bts-sbom-app serve --chat-actions`. Without it the chat is read-only.
Flow: ask to analyse a source (path or URL); license_risks for a distribution model (binary, saas, internal); plan_patch prints an approval token for exactly the upgrades shown;
reply `apply patch <token>` to apply them in an isolated work copy, one round, re-scan, revert on regression; the origin is untouched and nothing is pushed.
VEX decision: write the advisory id, false-positive, accepted or wontfix, an OpenVEX justification name and the reason last after `reason:`; the preview shows the effect and a confirm code; reply `confirm <code>` to record it.
Token, source, confirm code and reason must be typed by the user; a model plan that supplies them itself is dropped.
