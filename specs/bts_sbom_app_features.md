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

## Loop engineering (bts_sbom_app/loop.py)

- BSA-AC-42 [Event] When a candidate drops a blocking metric by more than 0.02, the gate shall return pass false, and pass true for identical metrics (2 of 2 cases).
- BSA-AC-43 [Event] When the last 3 accepted passes have identical metrics, the loop shall report plateau.
- BSA-AC-44 [Event] When EXAONE proposes 3 hypotheses of which 1 cites an unknown failure cluster, the system shall keep exactly 2.

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
