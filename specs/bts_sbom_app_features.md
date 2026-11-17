# BTS-SBOM feature spec (SDD)

Canonical acceptance criteria. Pattern keywords: Ubiquitous / Event / State / Optional / Unwanted. **Every AC carries a
measured number.** One AC = at least one test; a test names the AC it proves with `AC: BSA-AC-n` in its docstring
(`tests/test_specs.py` enforces EARS shape, numbers and traceability, both ways).

Honesty contract: absent evidence is never a pass; an unresolved license stays unresolved; an unavailable LLM is recorded as
a downgrade (never as an LLM success); the origin is never modified and nothing is pushed without its own explicit flag;
a stage that cannot run is recorded, not hidden.

## Workspace (bts_sbom_app/workspace.py)

- BSA-AC-1 [Event] When a local folder is analysed and patched with approval, the system shall leave the origin tree hash byte-identical (1 of 1 origin trees unchanged).
- BSA-AC-2 [Unwanted] If the source is an ext:: transport, an option-like value or plain http, the system shall refuse it and clone 0 repositories (3 of 3 unsafe forms refused).
- BSA-AC-3 [Event] When a git URL is cloned, the system shall pass 3 of 3 safety settings (no hooks, no submodules, ext transport disabled).
- BSA-AC-68 [Unwanted] If the destination of a work copy already exists with read-only files (git objects on Windows), the system shall remove it and reuse the name, leaving 0 suffixed leftover copies (found by a 1.1 GB leak across 15 passes).

## Engine (bts_sbom_app/engine.py, cvss.py, versions.py)

- BSA-AC-4 [Ubiquitous] The system shall derive fixed versions only from ECOSYSTEM and SEMVER ranges that contain the installed version, so 0 of the reported fixed versions is a 40-hex commit SHA.
- BSA-AC-5 [Event] When 3 advisory records (GHSA, CVE, PYSEC) share aliases, the system shall report exactly 1 finding.
- BSA-AC-6 [Ubiquitous] The system shall compute CVSS v3.1 base scores equal to the specification for 3 of 3 reference vectors (9.8, 7.5, 6.1).
- BSA-AC-7 [Unwanted] If an OSV query fails, the system shall mark the plan verification unverified (clean null) and never clean (1 of 1 failed queries unverified).

## Licenses (bts_sbom_app/licenses.py)

- BSA-AC-8 [Event] When 12 raw license spellings are normalized, the system shall map the 10 mappable ones to SPDX expressions and leave 2 unmapped instead of guessing.
- BSA-AC-47 [Unwanted] If a compound license expression contains parentheses, the system shall keep them, so 1 of 1 expressions with different AND/OR precedence stays unchanged and the core SPDX validator reports 0 errors (found by the first real e2e pass: the flattened form changed the meaning).
- BSA-AC-48 [Event] When 3 well-formed SPDX identifiers unknown to the category table and 3 non-SPDX spellings are normalized, the system shall resolve the 3 identifiers and leave the 3 spellings unmapped.
- BSA-AC-49 [Event] When the npm registry holds only a legacy licenses array and Maven Central holds a POM license name, the system shall resolve both (2 of 2) with sources registry:npm and registry:maven.
- BSA-AC-50 [Event] When the license normaliser changes after a miss was cached, the system shall re-interpret the cached raw evidence with 0 remote lookups (1 cache hit re-resolved), because the cache stores raw evidence and not the normalised outcome.
- BSA-AC-51 [Optional] Where extra registry fallbacks are switched off, the system shall consult neither the npm legacy licenses array nor Maven Central (0 of 2 resolved, 0 POM requests), so each fallback can be measured as one loop variable.
- BSA-AC-52 [Event] When the same advisory on the same package version is reported by 2 manifests, the system shall report 1 finding listing both files and count 1 merged duplicate (measured on real repositories: 521 of 1959 findings were duplicates).
- BSA-AC-53 [Event] When a Gemfile.lock lists one gem version and 2 platform variants of it, the system shall report 1 component with 2 platforms and count 2 merged variants.
- BSA-AC-54 [Event] When go.sum lists 1 module version that the sibling go.mod did not select, the system shall drop it (1 dropped, 1 selected version kept) and report the count in the adjustments.
- BSA-AC-9 [Event] When a package-lock.json carries a license field, the system shall resolve that component offline with source lockfile and leave the 1 component without any evidence unresolved.
- BSA-AC-10 [Event] When deps.dev answers for 2 of 3 components, the system shall record source deps.dev for exactly those 2 and the registry fallback for the third.
- BSA-AC-11 [Event] When a project root holds an MIT license file and 3 SPDX-tagged sources, the system shall report the project license MIT with source root license file.
- BSA-AC-12 [Event] When the project license is permissive and 1 dependency is GPL-3.0, the system shall report 1 conflict finding for binary distribution and 0 for internal distribution.

## Remediation, patch, delivery (bts_sbom_app/remediate.py, patch.py, deliver.py)

- BSA-AC-13 [Event] When a candidate fix version is itself affected by 1 advisory fixed in a later version, the system shall bump to the later version within 3 rounds (1 bump, final candidate verified clean).
- BSA-AC-14 [Event] When a patch is requested without approval, the system shall change 0 files and report not_approved.
- BSA-AC-15 [Unwanted] If the approval token does not match the plan digest, the system shall apply 0 changes and report digest_mismatch.
- BSA-AC-16 [Unwanted] If an upper bound excludes the safe version, the system shall report blocked and keep the requirement line unchanged (1 of 1).
- BSA-AC-17 [Event] When a requirements.txt is patched with approval, the system shall change exactly the 3 planned pins and create 1 commit on branch bts-sbom/auto-fix.
- BSA-AC-18 [Unwanted] If a re-scan after patching shows more vulnerabilities, the system shall reset the work copy to the pre-patch commit and report regression_reverted (1 of 1 injected regressions reverted).
- BSA-AC-59 [Event] When a gem is only a transitive dependency of the Gemfile, the plan shall be manual with a bundle update --conservative command and 0 blocked results (1 manual, 0 blocked).
- BSA-AC-60 [Event] When an advisory id or alias starts with MAL-, the finding shall be CRITICAL with score_source malware-advisory and malicious true (1 of 1).
- BSA-AC-66 [Unwanted] If a package.json-only patch leaves the untouched lockfile pinning the old versions and 3 unrelated advisories appear in that lockfile, the system shall not revert (0 of 1 reverted) because regression is judged only on findings of the edited files.
- BSA-AC-19 [Event] When a dependency is declared only in a lockfile, the system shall edit 0 lockfiles and return 1 manual regeneration command.
- BSA-AC-20 [Unwanted] If delivery target inplace or github is requested without its explicit allow flag, the system shall change 0 origin files and push 0 refs (2 of 2 refused).
- BSA-AC-21 [Event] When delivery target github is requested with allow_push and a local bare remote, the system shall push exactly 1 branch.
- BSA-AC-22 [Event] When delivery target folder is requested, the system shall write at least 3 artifacts (fix.patch, PATCH_REPORT.md and the changed files).
- BSA-AC-46 [Event] When 2 plans share the same package and the same candidate version, the system shall verify both of them (2 of 2 plans verified clean, found by the first real e2e pass).

## SBOM and industries (bts_sbom_app/sbom.py, sectors.py)

- BSA-AC-23 [Ubiquitous] The system shall emit a CycloneDX 1.5 SBOM in which 100% of vulnerability affects references resolve to an existing component bom-ref.
- BSA-AC-24 [Unwanted] If a component has no license evidence, the system shall emit 0 licenses entries for it.
- BSA-AC-25 [Event] When 1 dangling affects reference is injected, the validator shall report at least 1 error.
- BSA-AC-26 [Ubiquitous] The system shall emit an SPDX 2.3 document that passes the core validator with 0 errors.
- BSA-AC-27 [Unwanted] If no VEX and no end-of-support input is supplied, the maritime report shall mark the 2 dependent requirements not_evidence and pass 0 of them.
- BSA-AC-28 [Ubiquitous] The system shall produce reports for 7 industries from one SBOM.

## Architecture (bts_sbom_app/arch.py)

- BSA-AC-29 [Event] When the fixture Python project contains a 2-module import cycle, the architecture analysis shall report at least 1 cycle and 2 modules.
- BSA-AC-58 [Event] When 3 Ruby files form a require_relative ring, the architecture analysis shall report 3 import edges and at least 1 cycle, and shall note that the Ruby graph is partial (1 note).
- BSA-AC-30 [Event] When a repository has 5 commits touching 2 files, the hotspot ranking shall list the more frequently changed file first.
- BSA-AC-31 [Unwanted] If the folder has no .git directory, the system shall skip hotspot analysis with 1 note and report 0 fabricated hotspots.
- BSA-AC-32 [Event] When a Dockerfile declares python 3.7, the runtime check shall report status eol from the embedded table marked unverified (1 runtime).

## AI lane (bts_sbom_app/llm.py, ai.py)

- BSA-AC-33 [Unwanted] If EXAONE answers HTTP 429 with a day-limit message, the system shall return source deterministic with the 429 text in llm_note after exactly 1 call and 0 retries.
- BSA-AC-34 [Event] When EXAONE returns 4 proposals of which 1 has a bad action, 1 cites an unknown id and 1 proposes a version different from the plan, the system shall keep exactly 1 and report dropped rule 1, semantic 1 and cross_field 1.
- BSA-AC-65 [Event] When EXAONE lists only version strings in refs and its title names exactly 1 evidence package, the validator shall repair the refs from the title (1 repaired, 1 kept), and when the title names 2 packages it shall not repair and shall drop the proposal (1 cross_field), because an audit of real answers showed about half of the semantic drops were version or section refs and not invented entities.
- BSA-AC-35 [Event] When the same evidence is proposed twice, the system shall call EXAONE exactly 1 time.
- BSA-AC-36 [Unwanted] If the local daily budget is reached, the client shall make 0 network calls.
- BSA-AC-37 [Unwanted] If a provider error echoes the API key, the surfaced message shall contain 0 occurrences of the key.
- BSA-AC-64 [Unwanted] If EXAONE returns a truncated answer that fails validation, the system shall write 0 cache files for it, so identical evidence is retried instead of replaying the broken answer (1 of 1).
- BSA-AC-62 [Unwanted] If 2 threads request a completion at the same time, the client shall keep at most 1 request in flight (max concurrency 1 of 2), because parallel calls drew the provider's busy 429 on 2 of 10 projects.
- BSA-AC-63 [Event] When a request fails at the provider (HTTP 500 with one retry), the day ledger shall count 2 attempts, because the provider's day limit counts failed requests too.

## Retrieval and chatbot (bts_sbom_app/rag.py, chat.py)

- BSA-AC-38 [Event] When the 20-query golden set runs, the system shall reach Recall@5 of at least 0.85, MRR of at least 0.6 and nDCG@5 of at least 0.7.
- BSA-AC-39 [Unwanted] If a question is outside the corpus (5 out-of-domain queries), the system shall answer found=false for 5 of 5.
- BSA-AC-61 [Event] When valid questions are worded differently from the corpus (12-query untouched test set), the system shall answer at least 0.8 of them (found rate) and reject 4 of 4 out-of-domain questions, so a tighter gate cannot hide false rejections.
- BSA-AC-40 [Event] When the chatbot answers from project tools over 7 cases, the citation accuracy shall be 1.0 and a forged claim whose quote is not in its source shall be rejected (1 of 1).
- BSA-AC-41 [Unwanted] If a claim cites a source id that was not retrieved for the current question, the verifier shall reject it (1 of 1).
- BSA-AC-67 [Event] When an EXAONE chat answer cites a source id with brackets and a verbatim quote, the chatbot shall accept 2 of 2 such claims, and when a claim carries a translated quote it shall reject it (1 of 1) and fall back to the extractive answer.
- BSA-AC-91 [Unwanted] If a question names a project id that is not loaded, the chatbot shall answer found=false with 0 claims and 0 tools (1 of 1) instead of answering from the only loaded project, while a known id and a question without an id still answer (2 of 2).
- BSA-AC-92 [Unwanted] If an advisory summary contains instructions, the chatbot shall keep it as its own passage tagged untrusted-quote (1 of 1), keep it out of the 1 trusted tool claim, prefix it with "[untrusted quote]" in the extractive answer, set contains_untrusted, and never hand it to the model: the planning call and the answer call contain 0 of 1 such texts.
- BSA-AC-93 [Event] When an LLM client is available, the chatbot shall let the model plan its tool calls and route 5 of 5 paraphrased questions to the expected tool, where the regex router routes 0 of 5 (the measured baseline), with routing reported as llm for 5 of 5.
- BSA-AC-94 [Event] When asked what an upgrade does, the what_if_upgrade tool shall answer from the recorded plan only: the verified target reports 1 cleared advisory and its OSV verification (1 of 1), any other version reports no verified result and names the verified target (1 of 1), an unplanned component says no plan exists (1 of 1), and an unverified plan says not verified (1 of 1).
- BSA-AC-95 [Unwanted] If the model plans a tool outside the 12 read-only tools, an unknown argument, a component that is not in the project, a malformed advisory id or an unknown industry, the validator shall drop each (6 of 6 invalid entries), keep at most 4 calls (1 over the limit dropped) and drop 1 duplicate (a case variant of an earlier call counts as a duplicate), while sector industries and advisory ids are normalised to their canonical spelling (2 of 2).
- BSA-AC-96 [Unwanted] If the planning call is rate limited (HTTP 429), unparseable or has no valid tool call, the chatbot shall route with the regex router and state it in routing_note (3 of 3 cases) and still answer found=true, and with no LLM requested routing_note shall be empty (1 of 1).
- BSA-AC-97 [Event] When the model answer is accepted and the project holds 1 untrusted advisory text, that text shall be appended verbatim after the model answer with the "[untrusted quote]" prefix (1 of 1) and listed among the 2 claims with contains_untrusted true, and an advisory id repeated 3 times in one question (case variants included) shall run 1 tool call.

## Loop engineering (bts_sbom_app/loop.py)

- BSA-AC-42 [Event] When a candidate drops a blocking metric by more than 0.02, the gate shall return pass false, and pass true for identical metrics (2 of 2 cases).
- BSA-AC-43 [Event] When the last 3 accepted passes have identical metrics, the loop shall report plateau.
- BSA-AC-44 [Event] When EXAONE proposes 3 hypotheses of which 1 cites an unknown failure cluster, the system shall keep exactly 2.
- BSA-AC-88 [Unwanted] If a candidate keeps less than 50% of the baseline component or vulnerability count, the gate shall fail it (2 of 2 counts at 0, 1 of 1 at 49 of 100) and shall only warn for a 27% drop from merged duplicates (1 of 1), because a scanner that sees nothing had no metric left to regress.
- BSA-AC-89 [Unwanted] If a metric the baseline has is missing or None in the candidate, the gate shall report it as undecidable and fail (3 of 3 metrics, each in both forms), and a candidate with no comparable metric shall fail with 5 undecidable entries (1 of 1), because absent evidence is never a pass.
- BSA-AC-90 [Unwanted] If an evaluation set that the retrieval baseline measured vanishes from a candidate pass, the pass shall roll back with 5 undecidable entries (1 of 1) instead of being accepted on the remaining sets.
- BSA-AC-98 [Unwanted] If the retrieval baseline holds no comparable metric (no evaluation set at both passes), the pass shall roll back with 1 undecidable entry (1 of 1) instead of being accepted for comparing nothing.

## Pipeline (bts_sbom_app/pipeline.py)

- BSA-AC-45 [Event] When the pipeline runs on a 3-package fixture with approval, the re-scan shall show the findings reduced from 4 to 0 and the origin unchanged.

## Service and CLI (bts_sbom_app/server.py, cli.py)

- BSA-AC-55 [Unwanted] If the API receives an unsafe scan source or an empty question, the system shall answer HTTP 400 for 2 of 2 requests.
- BSA-AC-56 [Event] When a project has been analysed, the chat API shall answer a CVE question with found true, 1.0 citation accuracy and the vuln_lookup tool (1 of 1).
- BSA-AC-57 [Event] When the CLI runs evalrag on the shipped corpus, the process shall exit 0 and print recall, MRR, nDCG and citation accuracy (4 figures).

## Open-source security screen (bts_sbom_app/console.py, server.py, web/)

The screen reuses the BTS platform's page; `web/` holds 6 platform files copied unmodified (NOTICE.md) and 3 files written for BTS-SBOM.

- BSA-AC-69 [Event] When a project record with 2 findings (1 CRITICAL, 1 MEDIUM) is converted for the console, the report shall list 2 findings whose severity counts add up to 2, carry the CVE and the fixed version of each (2 of 2) and list 1 upgrade (requests to 2.31.0).
- BSA-AC-70 [Unwanted] If a value is not computed by BTS-SBOM (CISA KEV, EPSS, reachability, priority, VEX status), the report shall contain 0 of those 6 fields in each of the 2 findings, and the "deprecated" licence chip, which is never assessed, shall be absent, so the renderer shows absence instead of a made-up zero.
- BSA-AC-71 [Event] When the page is requested, the service shall serve it with a Content-Security-Policy limiting scripts to 'self' (1 of 1), serve sca_app.js byte for byte (1 of 1) and answer HTTP 404 for 4 of 4 paths outside the static allow-list (2 traversal forms, the page itself and an unknown name).
- BSA-AC-72 [Event] When the view of an analysed project is requested, the service shall return its report with 2 findings and list the project with 2 findings in the history (2 of 2), and shall answer HTTP 404 for an unknown project (1 of 1).
- BSA-AC-73 [Event] When a CycloneDX download is requested, the service shall answer a CycloneDX document as an attachment (1 of 1), and shall answer HTTP 400 for an unknown format and HTTP 404 for an unknown project (2 of 2).
- BSA-AC-74 [Event] When an ignore decision is posted, the service shall persist it and show it as triage_status on exactly 1 matching finding, and shall answer HTTP 400 for 3 of 3 invalid requests (unknown status, blank id, note of 501 characters).
- BSA-AC-75 [Unwanted] If one of the 6 copied platform files is edited, its sha256 shall differ from the recorded value: 6 of 6 copies match today and a copy with 1 added byte mismatches (1 of 1).
- BSA-AC-76 [Unwanted] If a scan asks for an approved patch without the digest of the reviewed plan, or for approval without a patch, the service shall answer HTTP 400 (2 of 2), and the work copy of a job that applied no patch shall already be removed when the job reports done, even when the clean-up takes 0.4 s (1 of 1), while the work copy of an applied patch shall be kept (1 of 1).
- BSA-AC-77 [Event] When a patch result carries its diff as an object {stat, patch} or as a bare string, the view shall expose both parts as strings (2 of 2), because the page printed "[object Object]" for the object form.
- BSA-AC-78 [Event] When the evidence folder holds one record under the current schema id, one under the earlier id and one under an unknown id, the loader shall list exactly the first 2 of the 3 (2 of 3), and a new analysis shall write the current id (1 of 1), so renaming the identifiers cannot make earlier evidence disappear.
- BSA-AC-79 [Ubiquitous] The system shall report one version everywhere: the package attribute, `--version`, the SBOM tool entries and both User-Agent headers all equal the distribution version in bts_sbom/_version.py (5 of 5 sites), because 0.2.0 shipped a stale 0.1.0 in all of them.
- BSA-AC-80 [Event] When a patch run ends with digest_mismatch, regression_reverted, blocked or error the command shall exit with code 1 (4 of 4), and when it ends with not_approved, applied, dry_run or nothing_applied it shall exit with code 0 (4 of 4).
- BSA-AC-81 [Ubiquitous] The console text shall keep every character the stdout encoding can show (Korean stays Korean on utf-8 and cp949, 2 of 2) and turn typographic punctuation into ASCII on ascii and cp1252 (2 of 2) without ever raising on write (4 of 4 encodings).
- BSA-AC-82 [Ubiquitous] The project and batch Markdown reports shall embed 0 Python dict or list representations: severity, licence-source, patch and proposal counts print as `key value` text (2 of 2 reports).
- BSA-AC-83 [Event] When the 6 vendored console files are hashed with CRLF normalised to LF, 6 of 6 shall match the recorded pins whatever the git autocrlf setting, `.gitattributes` shall pin the folder to LF (1 of 1), and the garbled footer word of the platform copy shall be gone (0 occurrences).
- BSA-AC-84 [Unwanted] If an approved patch finds every candidate blocked by a manifest constraint, the patch loop shall report the status blocked with an explanatory note (1 of 1) instead of nothing_applied, so the command exits 1.
- BSA-AC-85 [Event] When EXAONE is requested for a chat answer but no client is available, the answer shall state the reason in llm_note (names EXAONE_API_KEY, 1 of 1) and stay extractive, and with no request the note shall be empty (1 of 1).
- BSA-AC-86 [Event] When two metric vectors differ by exactly 0.02 on a blocking metric the regression gate shall pass (4 of 4 vectors) and shall fail for a drop of 0.0201 (1 of 1), because float noise had failed 4 of 5 boundary vectors.
- BSA-AC-87 [Event] When a batch source list holds a bare string it shall run as a source (1 of 1), and an entry without a source shall yield an error record instead of a traceback (1 of 1).

## License council (bts_sbom_app/council.py, evals/license_gold.json)

- BSA-AC-99 [Ubiquitous] The license gold set shall hold 44 cases with unique ids (34 answerable, 10 where the right answer is to abstain), every label shall be a canonical SPDX expression (34 of 34), and the deterministic baseline shall score 21 correct, 6 confident wrong, 10 missed and 7 correctly abstained, so the council has a measured number to beat.
- BSA-AC-100 [Unwanted] If a council member answers with an unknown or malformed SPDX expression, a quote that is not a verbatim substring of the evidence, a quote shorter than 3 characters, a quote that says nothing about licensing, an exception id that does not exist after WITH or a malformed object, the answer shall be invalid (7 of 7 invalid forms), while a known expression with a verbatim quote (2 of 2) and an explicit null (1 of 1) are accepted.
- BSA-AC-101 [Event] When 3 members propose the same license with a verbatim quote, all endorse it and the chairman picks it, the council shall agree with 7 calls (3 + 3 + 1), report the permissive category and mark applied false (1 of 1).
- BSA-AC-102 [Unwanted] If the members split 3 ways, a majority abstains, 1 of 3 abstains, nobody endorses the proposal, the chairman invents a label (1 of 1), declines (1 of 1) or picks a candidate that is not the top one (1 of 1), the council shall not agree (7 of 7 cases) and a majority of abstentions shall end as undetermined with 3 calls and no review round.
- BSA-AC-103 [Unwanted] If the council reading differs from the deterministic reading (0BSD against ISC), the council shall report needs_human with both readings (1 of 1) and apply neither, while an agreeing reading is accepted (1 of 1).
- BSA-AC-104 [Unwanted] If the council has fewer than 2 members, it shall make 0 calls and report needs_human (1 of 1), and if only 1 of 2 members gives a valid answer it shall not agree (1 of 1).
- BSA-AC-105 [Ubiquitous] The review and chairman payloads shall carry 0 member names (3 of 3 reviewers and 1 chairman), only the fields label, spdx, quote, proposed_by and endorsed_by, and the candidate order shall be identical for all 3 reviewers and when the member order is reversed (2 of 2).
- BSA-AC-106 [Event] When the same evidence is judged twice with the same members the second verdict shall come from the cache with 0 new calls (1 of 1), and a verdict that rests on 1 failed call shall not be cached (0 cache files), and 3 members of a different backend that share the model names shall not receive the cached verdict (0 of 3 cache hits).
- BSA-AC-107 [Event] When a project record holds 4 components (3 unresolved with 2 distinct raw strings, 1 resolved) and 2 license files (1 undetected), the council shall review 3 distinct items, cap the run at 2 items, list the 1 skipped item, make 14 calls, and leave the license of all 4 components unchanged.
- BSA-AC-108 [Event] When the council config lists 3 members of which 1 has no key, the council shall use the 2 keyed members, take the chairman by name (index 1 of 1), never put the key into the result (0 occurrences), and without a config it shall report that a council needs at least 2 members.
- BSA-AC-109 [Event] When the license tree is scanned, an undetected license file shall carry an excerpt of exactly 3000 characters (1 of 1) and a detected file shall carry 0 excerpts (1 of 1), so the council can review evidence after the work copy is gone.
- BSA-AC-110 [Unwanted] If a license string is a family nickname such as LGPLv2+, the normaliser shall map it to LGPL-2.0-or-later (1 of 1) or leave it unmapped (GPLv9, 1 of 1) instead of returning it verbatim as an SPDX id, which had counted it as resolved with category unknown.
- BSA-AC-111 [Unwanted] If the evidence tells the model to answer with a fixed license, the evidence shall reach the model only as the value of the JSON field text (3 of 3 calls) and an answer whose quote is not in the evidence shall make 3 of 3 members invalid, so the council ends needs_human with 0 license suggested.
- BSA-AC-112 [Event] When `evallicense` runs without a council config it shall print the baseline counts (21 / 6 / 10 / 7) and say the council was not run (2 of 2 lines), and `council` for an unknown project shall exit with code 2 (1 of 1).

## SBOM governance and vulnerability follow-up (bts_sbom_app/conformance.py, changes.py, triage.py, fleet.py, cli_ext.py)

Derived from the 6th FOSSLight Community Day (2026-10-28): changing SBOM regulations, Hub's strengthened vulnerability handling, Hub + Enterprise
operations. Everything here is deterministic and read-only; the LLM only narrates, and only figures present in the computed facts survive.

- BSA-AC-150 [Event] When a CycloneDX document of 2 components without supplier or hash is checked against the 5 regimes, the matrix shall report 5 verdicts, ntia-2021 as gaps with exactly 1 gap element (supplier), eu-cra-annex-i and vuln-ready as conformant (2 of 2), the supplier field first in the fix-once list with 3 blocked regimes, and the licence coverage as 50.0 percent partial because absent evidence is never a pass (1 of 1).
- BSA-AC-151 [Unwanted] If a document is not a JSON object, is neither CycloneDX nor SPDX, or lists 0 components, the matrix shall return NO_DATA with 0 elements and 0 regimes (3 of 3 inputs), and an unknown regime name shall raise an error (1 of 1).
- BSA-AC-152 [Event] When a complete CycloneDX document is checked, 5 of 5 regimes shall be conformant with 0 fix-once entries, and the equivalent SPDX 2.3 document shall be conformant for 4 of 5 regimes and miss only the generation context of the CISA 2025 draft (1 of 1); a hash entry with an empty value shall count 0.0 percent (1 of 1).
- BSA-AC-153 [Event] When a project is analysed from source, the record shall hold the matrix for 5 regimes and the CycloneDX shall declare the lifecycle phase pre-build (1 of 1) and stay valid (0 errors), and when every scanned source is a supplied SBOM no lifecycle shall be declared (0 of 1) and the generation-context element shall be a gap (1 of 1).
- BSA-AC-154 [Event] When a project is re-analysed after an upgrade that clears 1 advisory while 1 new HIGH finding without a fix and 1 GPL-3.0 component appear, the diff shall report 1 new, 1 resolved, 1 added component, 1 upgrade, the verdict mixed and exactly 2 alerts (new_at_or_above_threshold and copyleft_introduced), and an identical record shall report verdict same with 0 alerts (1 of 1).
- BSA-AC-155 [Event] When a finding rises from 6.5 to 7.5 across the threshold 7.0 and another falls from 8.0 to 5.0, the diff shall emit 1 threshold_crossed_up and 1 threshold_crossed_down alert with 2 rescored and 0 new (the mail-notification rule of Hub), and a finding without a score shall count as the lower bound of its label (HIGH is 7.0, 1 of 1) and UNKNOWN as no score (1 of 1).
- BSA-AC-156 [Event] When the same advisory is reported under a GHSA id before and under its CVE alias after a version change of the package, the diff shall count 1 persisting finding, 0 new and 0 resolved.
- BSA-AC-157 [Event] When 2 CycloneDX documents are compared, a vulnerability added to the second shall be reported as 1 new finding on the component its affects reference resolves to, and when 2 SPDX documents are compared only components and licences shall be compared (0 vulnerabilities, 1 copyleft alert), and an unrecognised document shall raise an error (1 of 1).
- BSA-AC-158 [Unwanted] If the model narrative of a change brief contains a number or an advisory id that is absent from the computed facts, the brief shall be rejected and the deterministic text returned (2 of 2 forged narratives), while a grounded narrative is accepted (1 of 1), and with no client the note shall name EXAONE_API_KEY (1 of 1).
- BSA-AC-159 [Event] When a project is analysed twice into the same evidence folder, the second record shall carry its changes (2 resolved, 1 new, 1 added component, 1 alert) and the first record shall be kept as the previous analysis without being listed as a project (1 project listed), while a first analysis carries no changes (1 of 1).
- BSA-AC-160 [Event] When a false-positive decision carries a VEX justification and a reason of at least 10 characters, the OpenVEX statement shall be not_affected with that justification and an impact statement (1 of 1), and when the justification is missing, invalid or the reason has 5 characters, the statement shall stay affected and explain why in status_notes (3 of 3), and a decision on an alias shall reach the finding (1 of 1).
- BSA-AC-161 [Unwanted] If a decision is past its expiry date, the finding shall be open again with the state expired and an affected statement (1 of 1), while a decision that expires today shall still apply (1 of 1).
- BSA-AC-162 [Event] When a risk acceptance carries a reason, an owner and an end date, the statement shall stay affected and name all 3 in its action statement (3 of 3) together with the upgrade hint (1 of 1), an acceptance with a 2-character reason shall be rejected (1 of 1), and a fixed claim for a finding that the scan still reports shall be rejected (1 of 1).
- BSA-AC-163 [Event] When a global decision and a decision scoped to one package exist for the same advisory, the scoped one shall win for its package and the global one shall apply to the other package (2 of 2), a purl-prefix scope shall match (1 of 1), and a decision that matches no finding shall be listed as stale (1 of 1).
- BSA-AC-164 [Event] When a record holds 1 finding without a confirming version range and 1 finding on a dev-only dependency, the review list shall hold exactly those 2 with their reasons and 0 suggested verdicts, omit a finding already decided not_affected (1 of 1), and the extra decision fields shall be validated (4 of 4 forms).
- BSA-AC-165 [Event] When a decision with justification, expiry, scope and owner is posted to the service, it shall persist all 4 fields (4 of 4) and answer HTTP 400 for 3 of 3 invalid extras, and the vex endpoint shall return an OpenVEX document with 2 statements, the decided one not_affected and the other affected (2 of 2), HTTP 404 for an unknown project (1 of 1), 5 regimes from the conformance endpoint (1 of 1) and a note from the changes endpoint of a project analysed once (1 of 1).
- BSA-AC-166 [Event] When an advisory affects 2 of 3 analysed projects, the lookup shall list exactly those 2 and name the third as not found (2 + 1), and match the id by a lower-case alias (1 of 1), find 0 projects when the advisory does not concern the named component (1 of 1) and raise an error for a query with neither id nor component (1 of 1).
- BSA-AC-167 [Event] When a component is looked up with the constraint below 2.20 and from 2.0, 2.19.1 shall match and 2.20.0 shall not (2 of 2) whatever the spelling case of the name, a component without a version shall be reported as version_unknown for a constrained query (1 of 1), and 3 of 3 junk constraints shall raise an error.
- BSA-AC-168 [Event] When a portfolio of 3 projects is rolled up, the projects shall be ranked by the weighted findings 15, 5 and 0 (CRITICAL 10, HIGH 5, MEDIUM 2, LOW 1, 3 of 3), the one advisory shared by 2 projects shall be listed with 2 projects (1 of 1), and the Markdown shall omit the shared-advisory section when no advisory is shared (1 of 1).
- BSA-AC-169 [Event] When the service receives the fleet and affected requests, it shall return the roll-up of 1 project with 2 findings and the 1 project hit by an advisory (2 of 2), answer 0 projects for a version constraint that excludes it (1 of 1) and HTTP 400 for 2 of 2 invalid queries (no parameter, junk constraint).
- BSA-AC-170 [Event] When several projects are loaded and a question names no project but asks which projects use or are hit by an item, the chatbot shall answer with the affected_projects tool and 1.0 citation accuracy for 4 of 4 phrasings in Korean and English (advisory ids, aliases and a component with a version), say that an advisory is in none of the 3 projects (1 of 1), keep declining an unrelated question (1 of 1), and run the fleet tool next to the advisory tool when a project is named (1 of 1).
- BSA-AC-171 [Event] When the model plans the 3 new read-only tools, the validator shall keep 4 of 4 valid calls and normalise the advisory id and the regime name (2 of 2), and shall drop 4 of 4 invalid calls (no id or component, malformed id, junk constraint, unknown regime).
- BSA-AC-172 [Event] When asked about NTIA conformance and about what changed, the router shall use sbom_conformance and what_changed (2 of 2) citing the recorded results with 1.0 citation accuracy and the not-a-legal-assessment line (1 of 1), shall say that no result or no earlier analysis was recorded when the record lacks it (2 of 2), and shall report 1 resolved vulnerability after a recorded upgrade (1 of 1).
- BSA-AC-173 [Event] When the CLI checks an SBOM with --require, the exit code shall be 1 for ntia-2021 with a missing supplier (1 of 1), 0 for vuln-ready (1 of 1) and 2 for an unreadable source (1 of 1), and --json shall print a parseable result (1 of 1).
- BSA-AC-174 [Event] When the CLI compares 2 records with --fail-on-alert, the exit code shall be 1 for a new high alert (1 of 1) and 0 when none exists (1 of 1) with verdict better, and 2 for a project without a previous analysis and for a missing file (2 of 2).
- BSA-AC-175 [Event] When the CLI exports the OpenVEX of a project with a decision store, the document shall hold 1 not_affected and 1 affected statement and stderr shall list the 1 rejected decision (3 of 3), an invalid date or an unknown project shall exit 2 (2 of 2), and the fleet command shall answer an advisory query, a roll-up and an empty evidence folder with exit codes 0, 0 and 2 (3 of 3).
- BSA-AC-200 [Unwanted] If a candidate loses the components or the vulnerabilities of the baseline, or lacks a metric the baseline has, the regression gate shall fail (3 of 3 vectors), because a run that detects nothing used to pass.
- BSA-AC-201 [Unwanted] If a marine-profile closing statement carries no justification, the MAR-05 verdict shall not be pass (3 of 3 unjustified statements) and shall report the count of unjustified statements.
- BSA-AC-202 [Unwanted] If a local-folder source contains 1 or more symlinks or junctions, the work copy shall contain 0 symlinks and the result shall report the skipped count.
- BSA-AC-203 [Unwanted] If a patch target does not resolve inside the work-copy root or crosses a symlink, apply() shall write 0 bytes to it and shall report that result as status blocked with detail "outside work copy" for both of the 2 escape forms (path traversal, symlink).
- BSA-AC-204 [Event] When a plan's target file list or verification outcome changes while its ecosystem, component and versions stay the same, approval_digest() shall return a different digest for 2 of 2 changed fields (files, verification).
- BSA-AC-205 [State] While EXAONE's daily call budget is exhausted, the chatbot shall stay extractive and make 0 further calls (never retries).
- BSA-AC-206 [Event] When the provider response's finish_reason equals 'length' on any ChatClient.complete() call, the system shall raise LLMError before the caller treats the content as valid JSON, making 100% of truncated completions fall back to deterministic() instead of 0% before this fix.
- BSA-AC-207 [Ubiquitous] The system shall maintain an AI_CALL_SITES registry entry resolving to a real, collectible fallback test for each of the 1 EXAONE call site in bts_sbom_app/ai.py, verified by static AST parse with 0 unregistered call sites.
- BSA-AC-208 [Event] When 2 or more license-resolution sources for the same component disagree after normalization, bts_sbom_app.licenses.resolve() shall append 1 entry to stats['conflicts'] naming both values and sources instead of silently discarding the disagreement (0 such entries exist today).
- BSA-AC-209 [Event] When patch.apply() returns an identical plan set across 2 consecutive rounds, pipeline.run_project() shall set status to "spinning_stopped" (1 new regression test, 0 existed before)
- BSA-AC-209 [Event] When patch.apply() returns an identical plan set across 2 consecutive rounds, pipeline.run_project() shall set status to "spinning_stopped" (1 new regression test, 0 existed before)
- BSA-AC-210 [Event] When any of the 3 critical-severity adversarial prompt-injection fixtures in knowledge/redteam/injection_fixtures.md is fed through Chatbot.ask()/verify_claims(), the system shall return zero verified claims sourced from the injected text (critical attack-success-rate 0%).
