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
- BSA-AC-95 [Unwanted] If the model plans a tool outside the catalog of 21 tools (18 read-only or preview tools, 3 that change something), an unknown argument, a component that is not in the project, a malformed advisory id or an unknown industry, the validator shall drop each (6 of 6 invalid entries), keep at most 4 calls (1 over the limit dropped) and drop 1 duplicate (a case variant of an earlier call counts as a duplicate), while sector industries and advisory ids are normalised to their canonical spelling (2 of 2).
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
- BSA-AC-216 [Event] When an API key is posted to /api/llm, the status shall name the model with only the last 4 characters of the key (1 of 1) and the key itself shall appear in no server response and in exactly one file, the saved evidence/.llm_config.json (2 of 2); a chat question with use_llm shall be planned by the connected model (routing llm, 1 of 1), and a request without a key and without a localhost base shall be refused (1 of 1).
- BSA-AC-217 [Event] When a server is restarted on an evidence folder that holds the saved key and no startup configuration, it shall connect from the saved file (1 of 1), and POST /api/llm/clear shall disconnect and remove the saved file (2 of 2), after which the chat plans with the regex router again (1 of 1).
- BSA-AC-218 [Unwanted] If the process was started with a key in the environment, the saved file shall not replace it (1 of 1), and a clear shall fall back to that startup key and say that a saved file was removed (2 of 2), still masking the key to its last 4 characters (1 of 1).

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
- BSA-AC-219 [Event] When a record holds 5 advisories with 1 standing decision, 1 verified plan, 1 rejected and 1 expired decision and 1 with nothing recorded, the coverage shall report decided 1, planned 1, rejected 1, expired 1 and unhandled 1 (5 of 5 verdicts) with 40.0 percent handled, order the worklist nothing-recorded first and keep the decided advisory off it (2 of 2), and give every advisory the chain finding -> plan/decision -> outcome (2 of 2 shapes).
- BSA-AC-220 [Unwanted] If a false-positive lacks its VEX justification or its expiry date has passed, the coverage shall keep the finding on the worklist as rejected and expired (2 of 2) with the rule's reason in the issue, and shall anchor every applied decision to its advisory with key, state, owner and recorded time (4 of 4 fields), one anchor per applied decision (1 of 1).
- BSA-AC-221 [Event] When the CLI coverage command, GET /api/coverage/<project> and the chat coverage tool are asked about the same record and store, the three shall answer with the same verdict counts (3 of 3) and the same handled percentage (1 of 1), and the chat answer shall state its honest bounds (1 of 1).
- BSA-AC-222 [Unwanted] If a decision is scoped to another package, it shall not cover the advisory (1 of 1), a global decision shall cover it (1 of 1), and every chain shall start at finding and end at outcome (2 of 2).
- BSA-AC-223 [Event] When a folder holds an SPDX-tagged file, a file with a copyright line, a license-named file and a binary, the source scan shall record the SPDX identifier and the copyright line (2 of 2), also report the copyright lines of the license-named file (1 of 1), list the binary and the skipped dependency folder in the Scanner-Info exclusions (2 of 2), and its CSV shall lead with the FOSSLight-style columns (1 of 1); a missing folder exits 2 (1 of 1).
- BSA-AC-224 [Unwanted] When a binary carries license and copyright strings, the binary scan shall report them as string evidence with the no-database honesty note (2 of 2), keep text files out of the binary list and in the exclusions (1 of 1), and its CSV shall lead with the FOSSLight-style columns (1 of 1).
- BSA-AC-225 [Event] When the self-check sheet is produced from a record, the CSV shall hold one row per component under the FOSSLight self-check columns (2 of 2), leave unresolved licenses empty (1 of 1), be written by the CLI with --out (1 of 1), and be downloadable as text/csv from GET /api/selfcheck/<project> with a 404 for an unknown project (2 of 2).

## Repository context pack (bts_sbom_app/contextpack.py)

- BSA-AC-176 [Event] When a folder with 1 license file and 1 file importing the package is packed, the pack shall hold both (2 of 2 kinds), record the import at line 3 with its context lines (1 of 1), list 0 files that only mention the package in a comment or import a package with a longer name (2 of 2), report reachability unknown, repeat byte for byte on a second run (1 of 1) and leave the sha256 of all 8 files unchanged.
- BSA-AC-177 [Unwanted] If a path is a binary (2 of 2), a file over 200000 bytes (1 of 1), inside node_modules (1 of 1) or a symlink to a file or folder outside the root (2 of 2), the pack shall exclude it with its reason and carry 0 characters of the linked content.
- BSA-AC-178 [Event] When the pack exceeds max_chars (60 of 60 characters allowed) it shall drop whole items and list every dropped one (count equal to the difference, more than 0), never exceed the cap (1 of 1), and list at most max_sites import sites (2 of 2) while still reporting the total found.
- BSA-AC-179 [Unwanted] If a license file contains a closing tag and an instruction to ignore previous instructions, the pack shall flag it suspicious (1 of 1) without changing its text, and the CXML export shall escape it so the document has 1 closing documents tag and 2 matching content tags, and state that all documents are untrusted.
- BSA-AC-180 [Event] When a recorded import site is verified, it shall be confirmed only while the same line is at the same path:line (1 of 1) and rejected after the file changed (1 of 1), for a parent-folder path (1 of 1), an absolute path (1 of 1) and a non-integer line (1 of 1).
- BSA-AC-181 [Event] When the contextpack command runs it shall print a summary naming the listed import sites and the over-budget count (2 of 2 fields), print CXML starting with the documents tag with --cxml (1 of 1), and exit with code 2 for a missing folder (1 of 1).
- BSA-AC-211 [Event] When a package is searched, dotted imports of it shall match (2 lines of 2: from requests.adapters, import requests.auth) while a longer name, a submodule of another package, a relative path ending in the name and a scoped package of that name shall not (4 of 4), so an import site is a whole-name match.
- BSA-AC-212 [Unwanted] If a file is a binary that is not a license file (1 of 1), it shall be listed as excluded with its reason, at most 50 license-named files shall be read with the other 6 of 56 listed as over the cap, and a path that two scans meet shall be listed once (1 of 1), so no file is silently absent from the pack.
- BSA-AC-213 [Ubiquitous] The pack shall count import lines, merged sites, capped sites and listed sites separately: 3 adjacent import lines are 3 lines and 1 site with 0 capped (1 of 1), and 4 sites with max_sites 2 are 2 listed and 2 capped (1 of 1).
- BSA-AC-214 [Unwanted] If a folder is a Windows junction or any other link (2 of 2 simulated), or resolves to a directory already visited (1 of 1), the pack shall exclude it as symlink and carry 0 characters of its content, without needing permission to create symlinks.
- BSA-AC-215 [Unwanted] If a recorded path holds a NUL byte, verify_site shall return false instead of raising (1 of 1), while a valid path still verifies (1 of 1).

## Chat-driven analysis, patching and VEX decisions (bts_sbom_app/actions.py, chat.py, evals_chat.py)

The chat can analyse a source, apply an approved patch and record a VEX decision, but only in a session opened with actions, and every effect keeps its gate:
a token, a source, a confirm code or a decision reason has to be text the user typed, so the model can plan the call but never authorise it.

- BSA-AC-200 [Event] When a session with actions is asked to analyse a local source, the chat shall run the pipeline on an isolated work copy and answer with the counts (2 components, 3 vulnerabilities), the top findings and the approval token of the plan (3 of 3), record the project (1 of 1) and leave the origin tree hash unchanged (1 of 1), and a read-only session shall refuse (1 of 1) and analyse 0 sources.
- BSA-AC-201 [Unwanted] If a patch is requested with no token, with a wrong token or in a read-only session, the chat shall change 0 files (3 of 3 cases) and show the plan with the token or the refusal, and with the token of the plan it was shown it shall apply the 2 planned upgrades in a work copy with branch bts-sbom/auto-fix, report 3 advisories fixed and 0 introduced (3 of 3 figures), keep the origin unchanged (1 of 1) and record the patch result in the project record (1 of 1).
- BSA-AC-202 [Unwanted] If a token is used for another selection than the one it was shown for, the chat shall refuse it (1 of 1) and name the right token, and the approved subset of 1 component shall change only that component while the other pin stays (2 of 2), in exactly 1 patch round (1 of 1), so no follow-up plan runs that nobody approved.
- BSA-AC-203 [Unwanted] If a model plan carries an approval token, a source, a confirm code or a decision reason that the user did not type, or a justification the user did not name, the validator shall drop each (5 of 5 forged forms) and keep the same 4 calls when the user did type them (4 of 4), a plan with no project shall drop the patch (1 of 1), and a model-planned patch without a typed token shall change 0 files (1 of 1), with the 3 tools that change something absent from the catalog of a read-only session (3 of 3).
- BSA-AC-204 [Event] When a decision is previewed, the chat shall write 0 decisions and answer with its effect (VEX outcome not_affected, owner and expiry shown) and a confirm code of the decision content (3 of 3), a read-only session shall only preview (1 of 1), a wrong code shall record nothing (1 of 1), the right code shall record the decision with justification, owner, expiry and the mark via chat once (4 of 4) and not twice (1 of 1), and a staged decision whose content was changed or that is older than 24 hours shall not be recorded (2 of 2).
- BSA-AC-205 [Unwanted] If a decision would not stand under the triage rules, the preview shall say so before anything is recorded: a false-positive without a named justification or with a 3-character reason shall show the outcome rejected (2 of 2) and no justification shall be inferred for the user (1 of 1), a decision on an advisory that no finding has shall be called stale (1 of 1), and the exported OpenVEX shall hold 3 statements with the recorded acceptance affected and naming the reason (2 of 2), written only by a session with actions (1 of 1).
- BSA-AC-206 [Event] When license risks are asked for a distribution model, the view shall name the strong-copyleft component and its source-offer obligation for binary (2 of 2), drop it for internal (1 of 1), name the unresolved license (1 of 1) and accept 1 of 2 distribution names, and fix proposals written by the LLM shall be tagged untrusted-quote while deterministic ones are tagged tool (2 of 2).
- BSA-AC-207 [Event] When the service is started without chat actions, a patch approval through the chat API shall be refused as read-only (1 of 1) and the plan shall name the CLI route, and when started with them a wrong token shall be refused as not matching (1 of 1) and the plan shall show the token and the apply instruction (2 of 2).
- BSA-AC-208 [Event] When the chat command is run, it shall exit 2 without a question and without interactive mode (1 of 1), and in interactive mode it shall answer 2 lines in a session that reports actions off and stop at the empty line (3 of 3).
- BSA-AC-209 [Event] When 8 paraphrased governance and action questions are routed, the regex router shall reach the expected tool for 2 of 8 (the measured baseline), the LLM planner for 8 of 8 with routing llm for 8 of 8, and a planner whose decision reason is not the user's words shall score 7 of 8 (1 of 1 forged call not credited).
- BSA-AC-210 [Unwanted] If the regime table is 6 months or more past its review date, the conformance result, its Markdown, the persisted record and the chat answer shall say that a review is due (4 of 4), and a table 5 months old shall not (1 of 1), because a regulation moves faster than a table that was right once.

## Governance panes of the open-source security screen (web/bts_ui.js, web/bts_governance.js, web/bts_console.js)

The data of the SBOM-governance features (BSA-AC-150..175) as panes: SBOM conformance, what changed, OpenVEX with decisions and the decision form,
fleet and "who is affected". Render and form logic are pure functions that run under Node in the tests; the six copied platform files stay untouched (BSA-AC-75, BSA-AC-83).

- BSA-AC-226 [Ubiquitous] The page shall load 5 scripts in the order sca_app.js, bts_ui.js, bts_governance.js, bts_console.js, oss_scanner.js (the 3 governance ones served byte for byte, 3 of 3), keep script-src 'self' and form-action 'none', hold 0 inline scripts, 0 inline event handlers and 0 form elements, contain the 20 element ids the new panes and forms read (20 of 20), and no longer claim that decisions are "not yet written into the OpenVEX" file (0 occurrences).
- BSA-AC-227 [Event] When the conformance pane is rendered for a project analysed twice, it shall show the 5 verdicts the service returned (5 of 5), the DRAFT flag on exactly 1 regime (cisa-2025-draft, 1 of 5), the line "Not a legal assessment" once (1 of 1), one coverage row per element the service scored, and the fix-once ranking after the matrix (1 of 1).
- BSA-AC-228 [Unwanted] If the conformance result is NO_DATA, HTTP 404 or still loading, the pane shall show 0 verdicts and 0 coverage bars but still the "Not a legal assessment" line (3 of 3 states), and shall say that NO_DATA is not a pass (1 of 1).
- BSA-AC-229 [Event] When the changes of a project analysed twice are rendered, the 8 cards shall equal the 8 numbers of the record (1 new, 2 resolved, 0 rescored, 1 alert, 0 critical, 1 component added, 0 removed, 1 version change; 8 of 8), the new finding shall show its package, version, severity, CVSS 7.5 and fixed version 1.0 (5 of 5 cells), and the upgrade from 2.19.1 to 2.31.0 shall be listed (1 of 1).
- BSA-AC-230 [Unwanted] If a project has no earlier analysis or the change record lacks a field, the pane shall say that nothing is recorded and show 0 cards (1 of 1), show 7 of 7 absent numbers and a missing score as dashes, show a score that is only the floor of a severity label as "≥ 7.0 (label)" (1 of 1), and say "first 3 of 25" when a list was cut (1 of 1).
- BSA-AC-231 [Event] When 4 decisions are recorded (a false positive with justification, a false positive without one, an accepted risk with owner and end date, and an expired one), the VEX pane shall show 1 not_affected statement with its justification and owner, 2 affected statements of which 1 carries the reason its decision was not applied (1 of 1) and 1 the risk-acceptance text (1 of 1), and the decision table shall list 4 decisions with 1 marked expired (1 of 4).
- BSA-AC-232 [Ubiquitous] The decision form shall offer exactly the 5 OpenVEX justifications in the service's order and the 5 decision statuses with none preselected (5 of 5 each), state the minimum reason of 10 characters (1 of 1), and say, on the page and in the live outcome line (2 of 2), that without a justification and that reason a false positive stays affected.
- BSA-AC-233 [Event] When the form predicts the effect of a decision for 375 combinations (5 statuses x 3 justifications x 5 reasons x 5 end dates), its state and OpenVEX status shall equal the service's decision for 375 of 375, including a reason of 10 code points that is 20 UTF-16 units long and an end date that is not a calendar day.
- BSA-AC-234 [Event] When the form builds a request it shall trim the reason and the owner and send the justification only for a false positive (1 of 1), the service shall accept it and persist the 4 optional fields (4 of 4) so that the OpenVEX shows 1 not_affected statement, and 7 of 7 invalid inputs (no finding, no decision, 501 characters, a date that does not exist, a scope with a space, an 81-character owner, an unknown justification) shall be refused before any request is made.
- BSA-AC-235 [Event] When 2 projects are analysed, the fleet pane shall list them in the service's ranking order (2 of 2), show the time of each analysis (2 of 2), list the 1 advisory shared by 2 projects with both names, and say that each row is as of its last analysis and that the counts are a lower bound (2 of 2); an empty fleet shall say that no project has been analysed (1 of 1) and a response without a roll-up shall say so (1 of 1).
- BSA-AC-236 [Event] When an advisory held by 2 projects is searched, the result shall list 2 rows with the fixed version 1.0 (1 of 1), a constraint that matches 1 of 2 projects shall name the other as having no matching component (1 of 1), a project without the advisory shall be "not found among the findings of the last analysis" with "not proof they are unaffected" (1 of 1), an empty search shall send 0 requests (2 of 2), and a service error (HTTP 400) shall be shown with its message (1 of 1).
- BSA-AC-237 [Unwanted] If analysed data holds markup (an img element with onerror, a script element), the 6 renderers, the finding list and 3 error states shall output 0 injected elements (10 of 10 outputs) while the text stays visible, a JSON object with an html key shall render as text (1 of 1), and an unknown pill class shall fall back to the fixed muted class (1 of 1).
- BSA-AC-238 [Ubiquitous] The panes shall show an absent field as a dash and never as a default 0: 4 of 4 absent fleet cards, 0 coverage bars and 0 verdicts for a regime without data, "not recorded" for an unknown draft flag (1 of 1), and 7 of 7 absent cells of a ranking row.
- BSA-AC-239 [Ubiquitous] The page scripts shall define each of the 6 markup helpers (esc, table, pill, note, heading, kv) in exactly 1 file, bts_ui.js (6 of 6), and the pure governance module shall assign innerHTML 0 times.
- BSA-AC-240 [Unwanted] If the service reports its regime table as 6 months or more past its review date, the conformance pane shall show "Review due" with the service's note and 1 review-due flag (1 of 1) next to the review date and age in months, shall show a current table with its date and 0 flags (0 of 1), and shall show a dash instead of a claim when the field is absent (1 of 1).

## CVSS v4.0 (bts_sbom_app/cvss4.py, cvss4_data.py, cvss.py)

FOSSLight Hub scores with CVSS v4.0 first; the tables are FIRST's reference tables (BSD-2-Clause, notice retained in `cvss4_data.py`, downloaded 2026-11-20 with the user's permission).

- BSA-AC-250 [Ubiquitous] The system shall compute CVSS v4.0 scores equal to the published reference examples for 25 of 25 vectors (base, threat, environmental and combined, including 0.0 for no impact and 10.0 for the maximum) and name the vector group used (CVSS-B, CVSS-BT, CVSS-BE, CVSS-BTE, 4 of 4).
- BSA-AC-251 [Unwanted] If a vector has another prefix, lacks a base metric, repeats or invents a metric, carries an invalid value or is empty, the scorer shall return no score (12 of 12 inputs), and the optional groups shall default as specified: E:X equals E:A, requirement X equals H, a modified metric of X keeps the base metric and supplemental metrics never move the score (4 of 4).
- BSA-AC-252 [Ubiquitous] The system shall hold exactly the 270 valid macro vectors in its lookup table with every value between 0.0 and 10.0 (270 of 270), and every vector of a 1-in-64 sweep of the 104976 base vectors shall score between 0.0 and 10.0 with one decimal (1640 of 1640).
- BSA-AC-253 [Event] When an advisory has only a v4 vector, the finding shall carry its v4 score and severity CRITICAL for 9.3 with score_source cvss_v4_vector instead of UNKNOWN (1 of 1), when it has both the v3 score shall stay the default and the preference for v4 shall switch it (2 of 2), the scores of an alias group shall be kept per version (2 of 2), and an unscorable vector shall fall back to the advisory label or to UNKNOWN (2 of 2).
- BSA-AC-254 [Event] When a CycloneDX document is built for a finding with both versions, the vulnerability shall carry 2 ratings naming their methods CVSSv4 and CVSSv31 with the primary first (3 of 3 orders), an identical second score shall add no rating (1 of 1), and the document shall stay valid (4 of 4).

## Circuit breaker and honest no-answer outcomes (bts_sbom_app/resilience.py, bts_sbom_app/net.py)

A dead host used to be retried the same way as a slow one, and a 404 (no such resource) was indistinguishable from "could not reach the host" - both became `None`. A per-host circuit breaker now stops hammering a dead host, and `fetch_json`/`fetch_text` return the shape of what happened (success/empty_result/partial_result/access_failure) while `http_json`/`http_text` keep their original return value unchanged.

- BSA-AC-301 [Event] When a host answers 3 consecutive times with a retryable failure, the breaker for that host shall open (1 of 1 breaker opened, 3 of 3 failures counted, opens counter 1).
- BSA-AC-302 [State] While a breaker is open, 5 further calls to that host shall be short-circuited with 0 transport attempts made and the circuit_open reason on all 5.
- BSA-AC-303 [Event] When the open cooldown has elapsed, exactly 1 of 4 concurrent callers shall be let through as the half-open probe (1 of 4 allowed, 3 of 4 turned away).
- BSA-AC-304 [Event] When a half-open probe succeeds the breaker shall close (0 consecutive failures), and when a later probe fails it shall reopen with a new cooldown start time (2 of 2 opens recorded, cooldown timestamps differing by 1 of 1 comparison).
- BSA-AC-305 [Ubiquitous] The breaker registry shall keep 2 hosts isolated: 3 failures against host A shall open only host A's breaker while host B's stays closed (1 of 2 open, 1 of 2 closed).
- BSA-AC-306 [Unwanted] If a fetch gets HTTP 404, the system shall report empty_result, count 0 STATS failures and leave the breaker's consecutive-failure count at 0 across 5 such calls (5 of 5 neutral), and the legacy http_json wrapper shall still return None.
- BSA-AC-307 [Event] When a text body reaches the configured byte limit, fetch_text shall report partial_result carrying the truncated data (not None), and the legacy http_text wrapper shall still return that same truncated text (1 of 1 body kept), while a body under the limit shall report success.
- BSA-AC-308 [Event] When a retryable response carries a Retry-After header, the backoff sleep shall equal that value up to a cap of 30 seconds: Retry-After 7 shall sleep 7.0 seconds and Retry-After 99 shall sleep 30.0 seconds (2 of 2 capped correctly).
- BSA-AC-309 [Ubiquitous] The legacy http_json contract (parsed data, or None on 404/failure) shall stay unchanged across 4 of 4 response shapes (success, 404, exhausted 5xx, non-retryable 4xx).
- BSA-AC-310 [Unwanted] If a status is a non-retryable 4xx (e.g. 403), the fetch shall stop after 1 attempt; if it is retryable (429/5xx/timeout), the fetch shall retry up to the configured count (3 of 3 attempts for retries=2).
- BSA-AC-311 [Unwanted] If BTS_SBOM_BREAKER_THRESHOLD is 0, the breaker shall stay disabled and allow all 10 of 10 calls through regardless of failures, never opening.
- BSA-AC-312 [Event] When calls produce a short-circuit, an empty_result and a partial_result, STATS shall count each exactly once (3 of 3 counters), and reset_stats shall zero all 6 of 6 STATS fields.
- BSA-AC-313 [Ubiquitous] reset_breakers shall restore every registered breaker to a fresh closed state (0 consecutive failures, 0 opens) in 1 of 1 call.
- BSA-AC-314 [Event] When 8 concurrent calls against one host all fail, the breaker shall open exactly once (1 of 1 opens, not 8 of 8).
- BSA-AC-315 [Event] When a single fetch internally retries twice before exhausting retries, the breaker shall count exactly 1 failure for that call, not 3 (1 of 1 call-level failure for 3 of 3 attempts).

## Patch regression impact quadrants and independent review (bts_sbom_app/impact.py, bts_sbom_app/review.py, bts_sbom_app/pipeline.py)

The approval-gated patch loop used to judge regression only from the findings of the files it edited. The lecture's database regression quadrants (direct/upstream/downstream/shared) are translated to a dependency patch in `impact.classify()`, and `review.review()` is a deterministic, advisory-only reviewer that sees only the patch's artifacts (digest, changed files, diff size, impact result, plan summary), never the planner's internal state.

- BSA-AC-316 [Event] When pipeline._patch_loop reaches a final status, it shall add an "impact" and a "review" field to its result (2 of 2 fields added) while leaving every pre-existing field and status value unchanged (0 of 0 changes to existing fields).
- BSA-AC-317 [Event] When the components an upgrade plan targets are re-scanned, the direct quadrant shall count resolved, remaining and newly introduced findings separately (3 of 3 counts: 2 resolved, 1 remaining, 1 introduced) and report regression on any introduced finding.
- BSA-AC-318 [Unwanted] If no plan upgrades anything, the direct quadrant shall report n/a (checked true, 0 of 3 counts); if no post-patch re-scan is available, it shall report unverified (checked false) instead of a silent ok.
- BSA-AC-319 [Event] When an untouched component declared in the same manifest as an upgrade gains 1 new finding, the upstream quadrant shall report regression (1 of 1 new finding) and shall separately count 1 of 1 upgrade blocked by a manifest constraint.
- BSA-AC-320 [Unwanted] If no manifest was changed, or the changed manifest declares no other component, the upstream quadrant shall report n/a (2 of 2 such cases).
- BSA-AC-321 [State] While any of the 4 quadrants is unverified, the overall verdict shall never equal clean (0 of 1 clean verdicts across the unverified case).
- BSA-AC-322 [Event] When the same vulnerable component is declared in 2 manifests and only 1 is patched, the shared quadrant shall report regression naming 1 of 1 other unfixed manifest.
- BSA-AC-323 [Event] When a fleet registry is given, the shared quadrant shall count 2 of 2 other projects still on the patched component's vulnerable version and report regression.
- BSA-AC-324 [Unwanted] If no fleet registry is given, the shared quadrant shall report unverified (checked false) even when the project's own manifests are clean (1 of 1 case).
- BSA-AC-325 [Event] When a transitive dependency (relationship not direct) gains 1 new finding after the patch, the downstream quadrant shall report regression (1 of 1 new transitive finding).
- BSA-AC-326 [Unwanted] If 1 lockfile/manifest regeneration is still pending and no new transitive finding appeared, the downstream quadrant shall report unverified, not ok (1 of 1 pending item surfaced).
- BSA-AC-327 [Ubiquitous] The overall verdict shall equal clean only when all 4 of 4 quadrants are n/a or ok, as when nothing was upgraded.
- BSA-AC-328 [Event] When 1 of 4 quadrants regresses while the rest are ok, the overall verdict shall equal regression (1 of 1 override).
- BSA-AC-329 [Event] When no quadrant regresses but 1 of 4 is unverified, the overall verdict shall equal incomplete (1 of 1 case).
- BSA-AC-330 [Unwanted] If a changed file is not part of the planned manifests, review() shall reject with rule RV-SCOPE (1 of 1 out-of-scope file named).
- BSA-AC-331 [Unwanted] If a lockfile was edited directly, review() shall reject with rule RV-LOCKFILE (1 of 1 lockfile named).
- BSA-AC-332 [Event] When a plan summary carries 1 or more major-version bumps with no explicit confirmation, review() shall request changes (rule RV-MAJOR-BUMP); when major_bump_confirmed is true, that finding shall not appear (2 of 2 states).
- BSA-AC-333 [Event] When the impact verdict is regression, incomplete or clean, review() shall return reject, changes_requested or approve respectively (3 of 3 mappings).
- BSA-AC-334 [Unwanted] If the diff is over the configured line cap (400), review() shall request changes with rule RV-DIFF-SIZE (1 of 1 over-cap diff flagged); a diff under the cap shall approve.
- BSA-AC-335 [Ubiquitous] The review() function signature shall carry 0 parameters named rec (0 of 1 forbidden parameter present) and shall always report reviewer deterministic-v1 and independent true (2 of 2 fields).

## Scan progress events (SSE) and operational readiness (bts_sbom_app/events.py, server.py, Dockerfile.bts-sbom-app)

A scan job today only answers "running" or "done" on `GET /api/jobs/<id>`; this gives a client the per-stage progress
and the approval-gate state as they happen over `GET /api/jobs/<id>/events` (schema `bts-sbom.events.v1`), and gives
an operator two probes (`/healthz`, `/readyz`) and a policy-checked container image instead of none.

- BSA-AC-336 [Ubiquitous] The event schema bts-sbom.events.v1 shall define exactly 6 event types (job_start, step_start, step_end, patch_gate, final, error) each carrying schema, type, a seq, a timestamp and the job id (5 of 5 envelope fields), and EventBus.publish shall assign seq 1, 2 and 3 to the first 3 events published on a fresh bus (3 of 3).
- BSA-AC-337 [Event] When a scan job runs end to end against a fake 3-stage pipeline, GET /api/jobs/<id>/events shall deliver job_start first, one step_start/step_end pair per stage in the order the stages ran (3 of 3 stages) and final last, with seq strictly increasing across all 8 events (1 of 1 check) and exactly 1 final event at the end.
- BSA-AC-338 [Event] When a stage finishes, its step_end event shall carry ok true and a numeric seconds for a stage that did not raise (2 of 2 fields), and ok false with a non-empty error for a stage that raised (2 of 2 fields) matching rec["stage_errors"] for that stage name (1 of 1).
- BSA-AC-339 [Unwanted] If an event is missing its seq, names an unknown type, omits a type-specific required field (one of name, ok, seconds, state, error_type) or gives patch_gate a state outside its 3 allowed values, events.validate shall report at least 1 problem for each of 6 malformed inputs (6 of 6) and 0 problems for a well-formed event of each of the 6 types (6 of 6).
- BSA-AC-340 [Event] When a client reconnects to GET /api/jobs/<id>/events with Last-Event-ID set to the seq of the 2nd of 5 published events, the stream shall deliver only the remaining 3 events (3 of 3) and 0 of the first 2 again, and asking with ?after= instead of the header shall deliver the same 3 (3 of 3).
- BSA-AC-341 [Unwanted] If GET /api/jobs/<id>/events names a job id the service never created, the response shall be a plain 404 JSON object (1 of 1) with Content-Type application/json, never text/event-stream (0 of 1).
- BSA-AC-342 [State] While any one of the 3 readiness probes (evidence_writable, core_import, knowledge_corpus) is failing, GET /readyz shall answer 503 with ready false and only that probe's name in failed (1 of 1), tested for each of the 3 probes failing alone (3 of 3), and once every probe passes again it shall answer 200 with ready true and an empty failed list (1 of 1).
- BSA-AC-343 [Event] When a job requests a patch without an approval token, its patch_gate event shall carry state awaiting_approval and the plan digest (2 of 2 fields); when the request already carries an approved token, it shall carry state approved (1 of 1); when no patch is requested at all, 0 patch_gate events shall be published for that job (0 of 1).
- BSA-AC-344 [Unwanted] If the progress callback given to _Stages raises on each of 3 stages run through it, each stage's own return value and timing shall be recorded exactly as it would be without a callback (3 of 3 stages unaffected), and rec["stage_errors"]["progress_callback"] shall hold exactly 1 entry no matter how many of the 3 stages raised (1 of 1, not 3 of 3).
- BSA-AC-345 [Ubiquitous] run_project called with progress=None and with the progress argument omitted entirely shall return 2 records equal everywhere once the fields that vary on every call regardless of progress (timings, path, lineage, _docs at the top level, and every nested timestamp, created, elapsed_s or commit value) are scrubbed out (0 differing values among the rest), proving the new keyword changes nothing for every existing caller.
- BSA-AC-346 [Event] When pipeline.run_project raises an unhandled exception, the job's SSE stream shall end with exactly 1 error event carrying error_type equal to the exception's class name, severity high and retryable false (4 of 4 fields) and 0 final events (0 of 1); when it instead returns normally with rec["error"] set, the stream shall end with 1 error event whose recovery_hint contains that error text clipped to 200 characters (1 of 1) and likewise 0 final events.
- BSA-AC-347 [Unwanted] If a 5th concurrent GET /api/jobs/<id>/events is opened while 4 are already reading the same job, the 5th shall be refused with 503 (1 of 1) while the other 4 keep receiving events uninterrupted (4 of 4), and once one of the 4 disconnects a new 5th connection shall be accepted (1 of 1).
- BSA-AC-348 [Ubiquitous] GET /healthz shall answer 200 with ok true (1 of 1 field) in under 1 second (1 of 1), staying 200 even when the evidence folder and the core import are both made to fail (2 of 2 failures ignored).
- BSA-AC-349 [Event] When all 3 readiness probes pass (a writable evidence folder, an importable core, a non-empty knowledge folder), GET /readyz shall answer 200 with ready true and an empty failed list (2 of 2 fields), checked against all 3 conditions holding at once (3 of 3).
- BSA-AC-350 [Unwanted] If a readiness probe fails for any reason, the /readyz response body shall name only the failing check and contain 0 occurrences of the evidence path, the repository root path or the word Traceback (3 of 3 absent).
- BSA-AC-351 [Ubiquitous] While a job's event stream has no new event for the configured heartbeat interval, GET /api/jobs/<id>/events shall write at least 1 heartbeat comment line starting with ": " (1 of 1) without ending the connection, and a real event published afterward shall still arrive on the same connection (1 of 1).
- BSA-AC-352 [Unwanted] If a Dockerfile's USER instruction is root, nobody or absent, the container policy check shall fail it (3 of 3 rejected); the shipped Dockerfile.bts-sbom-app shall pass with exactly 1 numeric non-root USER instruction (1 of 1).
- BSA-AC-353 [Unwanted] If a Dockerfile's FROM line names the latest tag or carries no tag at all, the container policy check shall fail it (2 of 2 rejected); the shipped Dockerfile.bts-sbom-app shall pass with its FROM pinned to a specific major.minor Python tag (1 of 1) and 0 occurrences of the literal tag latest.
- BSA-AC-354 [Unwanted] If a Dockerfile has 0 HEALTHCHECK instructions or one that shells out to curl, the container policy check shall fail it (2 of 2 rejected); the shipped Dockerfile.bts-sbom-app shall pass with exactly 1 HEALTHCHECK calling /readyz through python (1 of 1) and 0 occurrences of curl.
- BSA-AC-355 [Unwanted] If any ENV or ARG line's name matches a secret-shaped pattern (KEY, TOKEN, SECRET or PASSWORD), the container policy check shall fail it (4 of 4 rejected patterns); the shipped Dockerfile.bts-sbom-app shall pass with 0 such lines among its ENV/ARG instructions.
- BSA-AC-356 [Ubiquitous] The container policy check shall compare the Dockerfile's EXPOSE port against the --port value in its CMD and fail when they differ (1 of 1 rejected); the shipped Dockerfile.bts-sbom-app shall pass with both equal to 8800 (1 of 1).
- BSA-AC-357 [Event] When 8 threads each publish 50 events to the same EventBus concurrently (400 of 400 calls), the bus shall end with exactly 400 events with 0 lost and 0 duplicated, whose seq values are the 400 integers from 1 to 400 with no gaps and no repeats (1 of 1 set equality).

## Design-rationale and governance doc pack + doc lint (bts_sbom_app/doclint.py)

ADRs (`docs/adr/ADR-0007..0010`), the AI impact assessment, model card, origin/lineage note and data contract
(`docs/governance/*.md`) and the enforcement map (`docs/ENFORCEMENT_MAP.md`) are checked by `doclint.py`: pure
functions (document text in, a list of problems out) so every rule below is exercised with hand-written strings, no
filesystem needed except where the enforcement map must confirm a referenced file/function/test actually exists.

- BSA-AC-361 [Ubiquitous] The doclint module shall classify a document's kind from its file name alone for all 7 kinds (adr, impact, modelcard, lineage, datacontract, runbook, enforcement) with 7 of 7 sample names matched and 0 kinds misclassified.
- BSA-AC-362 [Event] When an ADR is missing exactly one of its 5 required sections (Status, Context, Decision, Rejected alternatives, Consequences), doclint shall report exactly 1 missing-section problem for 5 of 5 single-section-missing documents, and 0 problems for the complete document.
- BSA-AC-363 [Unwanted] If an ADR's Rejected alternatives section holds 0 list items, doclint shall report exactly 1 problem for it, and 0 problems when the same section holds 1 list item (2 of 2 cases).
- BSA-AC-364 [Event] When an AI impact assessment document is linted, doclint shall report 0 problems for 8 of 8 required sections present and exactly 8 missing-section problems when all 8 are absent.
- BSA-AC-365 [Event] When a model card is missing exactly one of its 5 required sections, doclint shall report exactly 1 problem for 5 of 5 single-section-missing documents, and 0 problems for the complete document.
- BSA-AC-366 [Event] When an origin-lineage document is missing exactly one of its 5 required sections, doclint shall report exactly 1 problem for 5 of 5 single-section-missing documents, and 0 problems for the complete document.
- BSA-AC-367 [Event] When a data contract document is missing exactly one of its 4 required sections, doclint shall report exactly 1 problem for 4 of 4 single-section-missing documents, and 0 problems for the complete document.
- BSA-AC-368 [Event] When a runbook document is missing exactly one of its 4 delivery blocks, doclint shall report exactly 1 problem for 4 of 4 single-block-missing documents, and 0 problems for the complete document.
- BSA-AC-369 [Unwanted] If an enforcement-map table is missing one of its 4 required columns, doclint shall report exactly 1 column problem naming it for 4 of 4 single-column-missing tables.
- BSA-AC-370 [Unwanted] If an enforcement-map row's location cell names a file that does not exist on disk, doclint shall report exactly 1 dangling-location problem for it, and 0 problems when the file exists (2 of 2 cases).
- BSA-AC-371 [Unwanted] If an enforcement-map row's location cell names a file:function pair whose function is not defined in that file, doclint shall report exactly 1 problem for it, and 0 problems when the function is defined (2 of 2 cases).
- BSA-AC-372 [Unwanted] If an enforcement-map row's verifying-test cell names a test file or test function that does not exist, doclint shall report exactly 1 problem for each of 2 of 2 broken forms (missing file, missing function), and 0 when both exist.
- BSA-AC-373 [Event] When --strict is set, doclint shall report exactly 1 problem for each of 3 of 3 placeholder marker kinds (TODO, FIXME, a bracket placeholder) and 0 problems for the identical text without --strict.
- BSA-AC-374 [Event] When doclint discovers and lints this repository's own docs tree in --strict mode with no paths given, every document it finds shall report 0 problems (0 of N found documents with problems), and the only document group it may report as not present is the runbook (owned by another package).
- BSA-AC-375 [State] While a document's kind cannot be determined from its file name and no --kind override is given, doclint shall report exactly 1 problem naming the file instead of guessing a kind (1 of 1).
- BSA-AC-376 [Event] When lint_file is called with an explicit kind that differs from what the file name would imply, it shall lint the file as the given kind for 1 of 1 renamed-file cases.
- BSA-AC-377 [Unwanted] If a given document path does not exist, doclint shall report exactly 1 problem naming the path instead of raising an exception (1 of 1).
- BSA-AC-378 [Event] When the CLI is run against 2 explicit paths of which 1 has a problem, the process exit code shall be 1 (1 of 1), and exit code 0 when run against the same 2 paths with the problem fixed (1 of 1).
- BSA-AC-379 [Event] When discover() runs over a tree holding only 1 ADR file, it shall list that ADR as found and name the other 6 document groups (impact, model card, lineage, data contract, runbook, enforcement map) as not present (6 of 6 missing notes).
- BSA-AC-380 [Event] When the CI workflow file bts_sbom_app_ci.yml is parsed, it shall contain exactly 1 step invoking "python -m bts_sbom_app.doclint --strict" (1 of 1), positioned after the "Spec lint" step and before the "Retrieval + chatbot grounding eval" step (2 of 2 ordering checks).

## Traceability matrix and portfolio/proof evidence (bts_sbom_app/traceability.py, portfolio.py, cli_ext.py)

The spec's AC lines, its section headers' module lists and the tests' `AC:` references were never joined into one table, and the week-7
submission package had to be hand-assembled from scratch instead of pointed at the project's own canonical files. `trace` builds the
AC | pattern | section(module) | test table and its gaps; `portfolio export` points at the existing README / specs / ADRs / source / eval
reports / runbook / governance docs (never copying or inventing content, `missing` when an original is absent); `proof` runs the project's
own gates (pytest, speclint, doclint when present, evalrag) and records PASS/FAIL/NOT RUN, where NOT RUN is never counted as PASS.

- BSA-AC-381 [Ubiquitous] The trace command shall render byte-identical Markdown and byte-identical JSON across 2 of 2 runs over the same spec and tests tree, with every list sorted and 0 of 1 timestamp fields in either rendering.
- BSA-AC-382 [Event] When a fake spec of 2 AC lines has 1 with no referencing test, the traceability summary shall list exactly that 1 id under untested_acs (1 of 2) and keep the tested AC off that list (0 of 1).
- BSA-AC-383 [Event] When a fake tests tree references an AC id absent from a 1-AC fake spec, the traceability summary shall list that 1 unknown id under unknown_test_refs (1 of 1) without adding a row for it to the AC table (0 of 1).
- BSA-AC-384 [Event] When a fake bts_sbom_app folder of 2 modules has 1 named by a spec section and 1 named by none, the traceability summary shall list exactly that 1 module under undeclared_modules (1 of 2) and leave the declared module out of it (0 of 1).
- BSA-AC-385 [Unwanted] If a spec carries 0 State-pattern AC lines, the traceability summary shall carry a non-empty state_pattern_warning (1 of 1 case); a spec carrying 1 or more State AC lines shall carry an empty warning (0 of 1 case).
- BSA-AC-386 [Ubiquitous] The traceability summary's 5 pattern_counts (Ubiquitous, Event, State, Optional, Unwanted) shall sum to the AC count of a fake spec of 6 AC lines spread across 5 patterns (6 of 6).
- BSA-AC-387 [Event] When the CLI trace command is run with --format md --out FILE and again with --format json --out FILE over the same fake tree, each file shall be written and the command shall exit 0 for 2 of 2 formats, the Markdown file holding a header row and the JSON file parsing back with json.loads (2 of 2 checks).
- BSA-AC-388 [Event] When portfolio export runs over a fake root where every original file of packages 1 through 6 exists, the manifest shall report status found for 6 of 6 packages with path, size and sha256 recorded for every item (3 of 3 fields), and packages 7 and 8 shall report status human_required with a non-empty checklist (2 of 2).
- BSA-AC-389 [Unwanted] If an original file a portfolio package expects does not exist, export shall mark that item status missing (1 of 1) and leave its size and sha256 as the 2 of 2 fields that carry no fabricated value (null, not 0 or an invented digest).
- BSA-AC-390 [Event] When portfolio export runs twice over the same unchanged fake root, portfolio-manifest.json and README.md shall be byte-identical across 2 of 2 runs.
- BSA-AC-391 [Ubiquitous] The portfolio self_assessment shall carry 0 numeric rubric-score fields, 4 measured rows (ac_count, untested_ac_count, test_file_count, speclint_problem_count) and 3 of 3 judgment rows valued human_review.
- BSA-AC-392 [Event] When proof runs with a fake runner that exits 0 for pytest, speclint and evalrag while the doclint module is absent, the result shall classify 3 of 4 commands PASS and 1 of 4 NOT RUN (doclint, module not found), with overall status incomplete (1 of 1) although 3 of 4 commands passed.
- BSA-AC-393 [State] While the doclint module stays unavailable and the injected runner reports a timeout for evalrag, proof shall count 0 of those 2 NOT RUN commands toward PASS, keeping overall status incomplete rather than pass (1 of 1 status value) for as long as any command remains NOT RUN.
- BSA-AC-394 [Event] When proof runs with a fake runner that exits 0 for all 4 commands, the result shall report PASS 4, FAIL 0 and NOT RUN 0 (3 of 3 counters) and overall status pass (1 of 1).
- BSA-AC-395 [Unwanted] If at least 1 of the 4 commands exits non-zero under the injected runner, proof shall set overall status fail (1 of 1) even when the other 3 of 4 commands pass.
- BSA-AC-396 [Event] When proof runs twice into the same --out folder, proof-results.json shall hold only the latest run's counts after each call (1 of 1 file overwritten) while proof-runs/ shall accumulate 2 of 2 run files named by a UTC timestamp, with a numeric suffix appended if 2 runs land in the same second (0 of 2 files lost to a collision).
- BSA-AC-397 [Unwanted] If proof writes a command's sidecar entry, it shall carry exactly 6 fields (name, cmd, exit_code, status, reason, summary_lines) and 0 of those 6 holding raw stdout or stderr text, only a line count.
- BSA-AC-398 [Ubiquitous] The CLI proof command shall run exactly 1 of 4 named commands when --only is given and all 4 when it is not (2 of 2 modes), and shall exit 0 when overall status is pass and 1 otherwise (2 of 2 exit codes).
- BSA-AC-399 [Event] When the CLI portfolio export command is run with --out DIR over a fake root, it shall write 2 of 2 files (portfolio-manifest.json, README.md) naming all 8 of 8 package kinds and exit 0, and a second run into the same DIR shall leave portfolio-manifest.json byte-identical (1 of 1).
- BSA-AC-400 [Event] When the CLI trace command runs --format md and --format json over the real repository's spec and tests, each file shall include every AC id the real spec defines at least once (1 of 1 completeness check per format) and exit 0 for 2 of 2 formats, without asserting the changing total AC count.

## Review fixes: path containment and bounded event buses (bts_sbom_app/portfolio.py, bts_sbom_app/doclint.py, bts_sbom_app/server.py)

- BSA-AC-358 [Unwanted] If a portfolio pattern matches a symbolic link or a file whose real path lies outside the repository root, the system shall leave it out of the manifest (0 of 2 planted outside files listed).
- BSA-AC-359 [Unwanted] If an enforcement-map cell names a path that leaves the repository through a parent-directory segment or an absolute path, doclint shall report 1 problem per cell and open 0 files outside the root (2 of 2 escape forms).
- BSA-AC-360 [Unwanted] If more than 64 job event buses are registered, the system shall drop the oldest closed buses first and drop 0 of the 5 still-open buses.
- BSA-AC-441 [Unwanted] If the license lookups of 20 components all fail because a host is down or its circuit is open, the system shall write 0 of those 20 misses to the license cache and report 20 lookup_unavailable (a failed lookup is not a verified absence).
- BSA-AC-442 [State] While a half-open probe is in flight, the breaker shall ignore the late failure of 1 call that began before it opened, so the probe's success still closes the breaker (final state closed, 0 spurious reopens).

## Arch Intel: license verdict + AI architecture deep-dive (bts_sbom_app/arch_intel.py, bts_sbom_app/arch_api.py)

One input (a local folder or a git URL) is prepared into an isolated work copy (`workspace.prepare`), its project
license is categorized with obligations, a per-distribution verdict, a GPL/AGPL notice checklist and a pairwise
compatibility matrix; deterministic architecture facts (arch.analyze) plus entry-point detection and a bounded
key-file selection ground an EXAONE architecture lane that follows the ai.propose contract (prompt-hash cache,
four validation layers, honest deterministic fallback). Diagrams are generated deterministically from the
VALIDATED analysis, bounded highlighted snippets anchor the architecture in real files, and the result is served
under /api/arch/... for the Arch Intel pane. Clean-room guardrails are testable invariants: the LLM prompt
carries metadata only, code-shaped model output is dropped, the model never writes Mermaid, and the analysed
tree is never executed.

- BSA-AC-443 [Event] When entry_points runs over a fixture tree holding exactly one file of each of 5 kinds (a __main__.py, a python __main__-guard script, a package.json main, a package.json bin and a Go package-main file), it shall return exactly those 5 paths with their 5 kinds (5 of 5 detected, 0 false entries).
- BSA-AC-444 [Event] When a tree whose root LICENSE carries GPL-3.0 text is analysed, license_verdict shall report project_license GPL-3.0-only, category strong-copyleft and a checklist of at least 3 clauses (3 of 3 fields correct in 1 of 1 fixture).
- BSA-AC-445 [Event] When a tree whose root LICENSE carries AGPL-3.0 text is analysed, notice_checklist shall flag network_clause true, include 1 AGPL-13 clause and report 3 of 3 distribution verdicts (3 measured fields).
- BSA-AC-446 [Event] When compat_matrix runs for GPL-3.0-only, it shall return 6 of 6 candidate rows, mark the MIT row incompatible (1 of 1 verdict) and mark the GPL-3.0-only row compatible (1 of 1 verdict).
- BSA-AC-447 [Event] When prompt_evidence is built over a tree whose source carries a distinctive function-body string, the evidence JSON shall contain 0 occurrences of that string and at least 1 occurrence of a real file path (2 of 2 checks).
- BSA-AC-448 [Unwanted] If a model answer names a file that is not in the analysed tree, validate_arch shall drop that component into the semantic bucket (1 of 1 dropped) and return 0 components with ungrounded files (0 of N kept).
- BSA-AC-449 [Unwanted] If a model string contains a markdown code fence, validate_arch shall drop the item that carries it into the rule bucket (1 of 1 dropped) - the tool never echoes code on any of its 3 item kinds.
- BSA-AC-450 [State] While no LLM client is configured, propose_arch shall return source deterministic with at least 1 component built from measured clusters and 0 scenario steps beyond the static-inference entry flow (2 of 2 fields), with the cause recorded in llm_note (1 of 1 note).
- BSA-AC-451 [Event] When build_diagrams renders a scenario whose step target is "User", the sequence text shall use 1 -->> return arrow for that step (1 of 1), and mermaid_label shall sanitize a hostile label's quotes, newlines and -- sequence in 3 of 3 sanitizations.
- BSA-AC-452 [Event] When code_snippets runs over a 200-line key file with an anchor regex matching at line 100, it shall return at most 60 lines (1 bound) whose window includes line 100 (1 of 1 hit), with truncated true (1 of 1 flag).
- BSA-AC-453 [Event] When highlight renders a Python snippet holding 1 keyword, 1 string, 1 comment and 1 number, it shall wrap exactly those 4 tokens in tok-* spans (4 of 4), escape a raw <script payload (1 of 1) and emit 0 spans for an unknown language (0 of 4 spans).
- BSA-AC-454 [Event] When POST /api/arch/scan starts a run over a fixture tree, polling GET /api/arch/jobs/<id> shall observe state running then done, and the finished job's overview shall carry project_license, category and ai_source (3 of 3 fields).
- BSA-AC-455 [Event] When the SSE stream GET /api/arch/jobs/<id>/events is consumed for a finished run, every event shall pass events.validate with 0 problems and the stream shall end after exactly 1 terminal event (2 of 2 checks).
- BSA-AC-456 [Unwanted] If a request to /api/arch carries a Host header that is not the service's own address, the route shall answer 403 for 1 of 1 requests and serve 0 of 1 responses.
- BSA-AC-457 [Event] When GET /api/arch/report/<id>?format=md is fetched for a finished run, the body shall be markdown holding the project license string and at least 1 mermaid fence (2 of 2 checks) and format=xz shall be refused with 400 (1 of 1).
- BSA-AC-458 [Event] When a running scan job is cancelled, the job shall end in state cancelled with 1 cancellation recorded (2 of 2 fields) and a finished run shall appear in GET /api/arch/history with 1 row (1 of 1 rows).
- BSA-AC-459 [Event] When the Arch Intel renderer renders a result whose component name carries a <script> payload, the returned markup shall contain 0 unescaped occurrences (0 of 1 possible) and the model browser tree shall list exactly 7 openable items grouped into exactly 5 sections with exactly 1 view opened by default (7 of 7 items, 5 of 5 groups, 1 of 1 defaults).
- BSA-AC-460 [Event] When a diagram block holds non-empty Mermaid source, the renderer shall emit exactly 1 hidden pre.arc-mermaid-src per block (1 of 1) so the pane still shows the diagram source when the vendored renderer cannot load (0 empty panes).

## Arch Intel deterministic insights: flow blockers, bounded contexts, style hypothesis (bts_sbom_app/arch_flow.py, bts_sbom_app/arch_intel.py, bts_sbom_app/chat.py, bts_sbom_app/web/arch_intel_render.js)

Book-grounded, deterministic readings of the already-measured Arch Intel structure: what slows a change down
(flow blockers), where a seam to split along might be (bounded context candidates), which architecture style the
layout and manifests hint at (a hypothesis, never a verdict), big-ball-of-mud risk signals, and a modularity
fitness summary. Every insight cites the measurement it came from, every family carries an honesty note, and no
insight family runs anything, reaches the network or calls an LLM. The chat gains a `latest_arch` tool that
summarises the latest recorded run from the evidence folder.

- BSA-AC-461 [Event] When the measured import graph holds exactly 1 cycle of 2 modules, the flow blockers shall list exactly 1 cycle blocker naming both modules in edge order with the import-graph evidence cited (1 of 1 cycles).
- BSA-AC-462 [Event] When the graph holds 2 unstable hubs, one recorded as a name/instability pair and one as a bare name, the flow blockers shall name both, carry the instability figure for the pair form and the ? placeholder for the bare form (2 of 2 hub forms).
- BSA-AC-463 [Event] When change coupling holds 2 pairs of which exactly 1 is hidden, the flow blockers shall list exactly the hidden pair with its shared-change count and 0 blockers for the plain pair (1 of 2 pairs).
- BSA-AC-464 [Event] When 3 hotspots carry scores 12, 2 and 1, the flow blockers shall include 1 hotspot_concentration naming the top file and its commits (1 of 1), and both a 5/4/3 score spread and a 2-hotspot list shall produce 0 such blockers (2 of 2 negative cases).
- BSA-AC-465 [Event] When the graph carries tangle_ratio 0.3, the flow blockers shall include exactly 1 high_tangle blocker quoting the ratio (1 of 1), and tangle_ratio 0.2 shall produce 0 blockers (1 of 1 negative case).
- BSA-AC-466 [State] While the measured structure holds no cycles, no unstable hubs, no hidden coupling pairs, no concentrated hotspots and no tangle, the flow blocker report shall carry count 0 with an empty blocker list and the honesty note, and invent 0 blockers (2 of 2 fields plus 0 invented).
- BSA-AC-467 [Event] When 3 clusters exist of which 2 are extraction candidates with cohesions 0.9 and 0.7, the bounded context candidates shall list exactly those 2 ordered by cohesion descending, with at most 6 member files each (2 of 3 clusters, 1 of 1 orderings, 6 of 6 file caps).
- BSA-AC-468 [State] While no cluster is an extraction candidate, the bounded context report shall carry count 0 with an empty candidate list, name 0 domains and still carry its honesty note (0 named, 1 of 1 notes).
- BSA-AC-469 [Event] When the measured file list contains presentation, business and persistence layer names in 3 distinct groups, the style hypothesis shall read layered with exactly 1 signal per observed group (1 of 1 style, 3 of 3 signals).
- BSA-AC-470 [Event] When a compose manifest exists and no layer names do, the style hypothesis shall read distributed citing 1 manifest signal (1 of 1), and with no compose manifest but 1 entry point and 2 cohesive domains it shall read modular_monolith with the 2 signals named (1 of 1, 2 of 2 signals).
- BSA-AC-471 [State] While the structure shows no layer names, no entry points and no deployment manifests, the style hypothesis shall carry an empty style, an empty why and 0 signals, and name 0 styles (3 of 3 empty fields).
- BSA-AC-472 [Event] When tangle_ratio is 0.3 with 3 cycles and the mean cluster cohesion is 0.3 over 3 clusters, the antipattern signals shall be exactly big_ball_of_mud then low_cohesion, carrying the measured tangle, cycles and cohesion values (2 of 2 signals in order, 3 of 3 measured values).
- BSA-AC-473 [Event] When 8 of 20 files sit in the repository root, the antipattern signals shall include exactly 1 root_sprawl with measured root_share 0.4 (1 of 1), and 7 of 20 shall produce 0 root_sprawl signals (1 of 1 negative case).
- BSA-AC-474 [State] While the measured structure is clean, the antipattern report shall be an empty signal list with count 0 and a note that says the list is risk signals and never a verdict (2 of 2 fields, 1 of 1 notes).
- BSA-AC-475 [Event] When 3 clusters carry cohesions 0.9, 0.6 and 0.3 and the graph holds 10 nodes with 2 modules in cycles, the modularity summary shall report avg_cohesion 0.6, acyclic_percent 80.0 and a bounded-context flag on exactly the 2 candidate rows (2 of 2 numbers, 2 of 3 flags).
- BSA-AC-476 [Event] When build_insights runs over one measured structure it shall return the schema constant plus exactly the 5 insight families, each family carrying its honesty note, with the cycle count and the candidate member files taken from the structure (6 of 6 keys, 5 of 5 notes).
- BSA-AC-477 [Ubiquitous] The prompt evidence shall carry the insights as 1 flow-blocker count, at most 5 candidate names and 1 style string - 0 file paths from the insight pack (3 of 3 metadata kinds, 0 paths).
- BSA-AC-478 [Event] When a result carries the insight pack, the renderer shall add exactly 1 model browser item with id insights inside its own section, holding the style pill and the heuristic honesty note (1 of 1 items, 2 of 2 rendered marks).
- BSA-AC-479 [Event] When a finished result carries insights, report_md shall contain exactly 1 Insights section with 1 table row per flow blocker (1 of 1 sections, 1 of 1 rows), and a result without insights shall contain 0 such sections (1 of 1 negative case).
- BSA-AC-480 [Event] When the latest_arch chat tool runs with a reachable archintel store, it shall summarise the run with the latest finished stamp as exactly 7 lines covering run, license verdict, flow blockers, bounded contexts, style, antipatterns and the honesty note (7 of 7 lines), and with no store or no recorded run it shall say so honestly in 1 line (2 of 2 empty cases).

### TOP10 답변 품질 스코어카드 (`bts_sbom_app.quality`)

MetaNet 심화과정 별첨 「AI 에이전트 답변 품질 평가 TOP10」의 게이트를 오프라인 결정적 챗 세트 위에 얹은
점수카드. 판정 모델(LLM 심사기)을 쓰지 않는다 — 모든 지표는 이번 실행의 실측 산출물에서 코드로 계산한다:
근거성은 챗의 클레임 지지율과 같은 정의, 관련성은 질문-답변 토큰 코사인(코스의 0.80 게이트는 임베딩
역생성 방식으로, 측정 수단이 다르므로 이 코퍼스의 실측 하한을 기준으로 둔다), 완결성은 질문별 필수
요소 충족률, 툴 정확도는 결정적 라우터가 담당하는 범위 내 세트의 라우팅률(패러프레이즈 세트의 정규식
저조율은 계획기(플래너)가 존재하는 이유이므로 보고만 하고 게이트하지 않는다), 과잉 거절률은 정상 질문에
대한 오거절 비율이다. 쓰기 툴 1.0 규칙은 구조적으로 actions 게이트(chat.validate_calls)가 담당한다.

- BSA-AC-481 [Event] When top10_report runs over the offline chat set it shall return a scorecard holding exactly 5 gated metrics (faithfulness, relevance, completeness, tool_accuracy, over_refusal), each carrying value, threshold and pass, plus the paraphrase routing rate reported but not gated (5 of 5 metrics, 5 of 5 gates, 1 of 1 reported-only).
- BSA-AC-482 [Event] When apply_gates receives metrics that meet every threshold it shall return verdict pass with 0 failures, and with one metric below its threshold it shall return fail with exactly 1 failure naming that metric (2 of 2 verdicts, 1 of 1 named failure).
- BSA-AC-483 [Ubiquitous] The gates shall be faithfulness >= 0.90, relevance >= 0.25, completeness >= 0.90, tool_accuracy >= 0.95 and over_refusal <= 0.05, with over_refusal the only upper-bound gate (5 of 5 thresholds, 1 of 1 upper bound).
- BSA-AC-484 [Event] When a found answer is scored, completeness shall return the required-element ratio from the per-question element list and relevance shall return the question/answer token cosine bounded to 0..1 (2 of 2 per-case metrics).
- BSA-AC-485 [Event] When render_markdown formats a report it shall emit exactly 1 scorecard table with 1 row per gated metric plus the verdict line, and write_report shall write that markdown to the given path (5 of 5 rows, 2 of 2 actions).


## Lecture round 1 adoption (Metanet advanced weeks 1-2): precision observability, conflict annotation, case-level regression rate, requirement-kind map, trim accounting, chat answer renderer

The six week-1/2 decks are adopted by measurement, not by checklist: the lecture's re-ranker was measured as an
ordering change and REJECTED (ADR-0016 keeps the three variants and their numbers) - what ships is the precision
annotation; the conflict log (ADR-0017), the case-level regression rate (ADR-0018) and the requirement-kind map with
trim accounting (ADR-0019) ship as enforced behavior. The chat answer renderer (bts_ui.renderChatAnswer) shows
evidence chips, routing and the conflict annotations on the security screen.

- BSA-AC-486 [Event] When a question token matches a chunk's heading (patch/patching relaxed), that result shall carry a positive lex precision score (1 of 1 signals).
- BSA-AC-487 [Event] When no question token matches a chunk's heading, that result shall carry lex 0 with its rrf and bm25 scores intact (3 of 3 fields).
- BSA-AC-488 [State] While any result carries a positive lex score, the returned order shall stay exactly the reported rrf descending order (0 reorders over 3 results).
- BSA-AC-489 [Event] When a search returns n candidates of which m carry a heading match, the rerank block shall report pool n and lex_candidates m (2 of 2 counts).
- BSA-AC-490 [Event] When _relaxed compares patch with patching both ways it shall match, and patch with p2p or cv with cve shall not (2 of 2 stems, 2 of 2 exact-misses).
- BSA-AC-491 [Event] When the same measured label carries different numbers in two different top chunks, conflicts shall return exactly 1 entry with rule escalate and status unresolved (1 of 1 entries, 2 of 2 fields).
- BSA-AC-492 [Event] When the same label carries the same number in two different chunks, conflicts shall return 0 entries (0 of 1 candidate pairs).
- BSA-AC-493 [Event] When two different measured values sit inside one chunk, conflicts shall return 0 entries because both facts share 1 source (0 of 1 candidates).
- BSA-AC-494 [Event] When the chatbot answers from 2 knowledge chunks with 1 cross-source label conflict, the answer shall carry exactly 1 [conflict] line naming both values and the human-judgement note, and the result shall list 1 conflict (2 of 2 surfaces).
- BSA-AC-495 [Event] When an out-of-corpus question is rejected by the confidence gate, the result shall carry an empty conflicts list (0 of 1 entries, 1 of 1 empty lists).
- BSA-AC-496 [Event] When the candidate misses carry 1 query the baseline passed and 1 query the baseline missed, case_regressions shall list only the newly failing query and skip sets the baseline never measured (1 of 2 candidates, 0 of 1 skipped sets).
- BSA-AC-497 [Event] When aggregate metrics are flat but 1 query that passed at baseline now fails, the rag pass shall roll back with the case regression named in the gate failures (1 of 1 rollbacks, 1 of 1 failure lines).
- BSA-AC-498 [Event] When a query that failed at baseline passes now and no baseline-passing query fails, the pass shall be accepted with 0 case regressions (1 of 1 accepts, 0 regressions).
- BSA-AC-499 [Event] When an eval set vanishes the pass shall stay undecidable over its 5 baseline metrics and invent 0 case regressions from the missing set (5 of 5 undecidables, 0 regressions).
- BSA-AC-500 [Event] When a fresh loop runs its first rag pass, the decision shall be baseline with an empty case regression list (1 of 1 decisions, 0 regressions).
- BSA-AC-501 [Event] When an approval-token requirement and a first-token-within-2-seconds requirement are tagged, the kinds shall be exactly SECR and PER (2 of 2 kinds).
- BSA-AC-502 [Event] When a schema-version requirement and an /api/chat route requirement are tagged, the kinds shall be exactly DAR and SIR (2 of 2 kinds).
- BSA-AC-503 [Event] When a non-stdlib constraint and a plain 3-files functional requirement are tagged, the kinds shall be exactly CONR and SFR with defaults 1 (2 of 2 kinds, 1 of 1 defaults).
- BSA-AC-504 [Ubiquitous] The requirement map shall partition every parsed AC into exactly 1 kind, so the kind counts sum to the AC total and the id lists cover each id once (1 of 1 partitions, 0 unassigned).
- BSA-AC-505 [Event] When a project carries 20 vulnerabilities, 20 plans and 20 unresolved licenses, the evidence shall keep 12 of each and report 8 dropped in trimmed for all 3 lists (12 of 12 kept, 3 of 3 counts).
- BSA-AC-506 [State] While every evidence list stays within its cap, all 8 trimmed counts shall be 0 (8 of 8 zero counts).
- BSA-AC-507 [Event] When the answer, a heading and quoted values carry script tags, quotes and ampersands, the renderer shall escape all of them so 0 raw tags reach the markup (3 of 3 escapes, 0 raw).
- BSA-AC-508 [Event] When the answer contains untrusted quotes and 2 conflicts, the renderer shall draw exactly 1 untrusted warning and 2 conflict notes, and a clean answer 0 notes (3 of 3 notes, 0 of 0 notes).
- BSA-AC-509 [Event] When 2 retrieval hits and a routing note are present, the renderer shall draw exactly 2 evidence chips with their rrf titles and the routing note once, and omit the note when it is empty (2 of 2 chips, 1 of 1 notes, 1 of 1 omissions).

### NL2SQL 안전 레인 (`bts_sbom_app.nl2sql`)

로컬 OSV SQLite 미러 위의 Text-to-SQL 레인 (MetaNet 3주차 2차시). 안전은 3층이다 — (1) 토크나이저
검증기: 단일 문장, SELECT/WITH만(CTE 본문 포함 쓰기 토큰 전면 차단), LIMIT 강제(없으면 추가, 상한 초과는
축소), (2) 실행 연결은 읽기전용 URI + PRAGMA query_only — 검증기를 우회해도 DB 자체가 쓰기를 거부한다,
(3) 4상태 실행기(success/empty_result/partial_result/access_failure)는 정당한 0건을 오류로, 오류를 빈
결과로 바꾸지 않는다. 생성은 결정적 템플릿 라우터(오프라인 기본, EX 평가 대상)와 선택적 LLM 레인
(json_mode, 스키마 카탈로그, clarification_needed nullable)이며, 자기교정 루프는 원 질문+실패 SQL+구체적
오류를 재생성 프롬프트에 첨부하고 상한 3회, 동일 오류 반복 시 즉시 중단한다. EX는 작성된 기준 쿼리의
결과 집합과 후보의 결과 집합이 상태·행 단위로 일치하는지로 판정한다(정당한 빈 집합의 일치도 정답).

- BSA-AC-510 [Event] When validate receives a write or multi-statement SQL (INSERT, UPDATE, DELETE, DROP, PRAGMA, ATTACH, a DML inside a WITH, or a second statement) it shall raise an SqlError carrying errorCategory business or validation, and when the SQL lacks LIMIT or exceeds the cap it shall return the SQL with LIMIT enforced to the cap (6 of 6 refusals, 2 of 2 limit enforcements).
- BSA-AC-511 [Event] When run_readonly executes a query it shall return success with rows, empty_result for a valid 0-row answer, partial_result with truncated true when the row cap is reached, and access_failure with a retryable error for a failed query - and a write attempt reaching the connection shall come back as access_failure because the connection is read-only (4 of 4 states, 1 of 1 write refusal).
- BSA-AC-512 [Event] When the LLM lane's first SQL fails validation and the second succeeds, answer shall return the successful rows with attempts 2 and the regeneration prompt shall carry the previous attempt's concrete error message, and when the same error repeats it shall stop after 2 attempts with access_failure and the error (2 of 2 loop behaviours, 1 of 1 attached error).
- BSA-AC-513 [Event] When nl2sql_eval runs its 30-question golden set over the seeded local database the deterministic template lane shall reach execution accuracy EX >= 0.8 with equal result sets, and an out-of-scope question without a client shall return access_failure with an honest error instead of empty rows (1 of 1 sets, 1 of 1 honest miss).

### 공급망 게이트 (MetaNet 4주차 1차시)

scripts/supply_chain_gate.py 한 명령이 코스 파이프라인 전체를 실측한다 — Dockerfile 빌드 → Trivy
이미지 스캔(CRITICAL, --exit-code 1) → CycloneDX 이미지 SBOM → 자기 SBOM(bts-sbom이 자기 저장소를
스캔, --offline) → 서빙 벤치 스모크(/healthz 60회 p50/p95). 도구 부재는 계산된 계획(plan, 순수
함수)에서 미리 드러나며 모든 생략에는 이유가 붙는다 — 정직한 생략은 데이터, 조용한 생략은 거짓말.
게이트 판정(aggregate)은 실패 단계 하나면 fail, 스캔 성공 0이면 CRITICAL 0, 스캔 생략이면
critical_found null(정직한 미지), 도구 소실(127)은 취약점이 아니라 생략으로 기록한다. 산출물은
고정 경로 evidence/supply_chain/gate_<ts>.json + bench/bench_latest.json + bench 타임스탬프 사본에
기록된다(schema bts-sbom.supply-chain.v1).

- BSA-AC-514 [Event] When plan receives a tool-availability map it shall emit the ordered build/scan/sbom/self_sbom/bench steps with every unavailable tool as a skipped step carrying a reason, the Trivy CRITICAL scan with exit-code 1 through native trivy when present or through the aquasec/trivy container when only docker exists, and build skipped by flag when reuse is requested (5 of 5 step families, 3 of 3 tool layouts).
- BSA-AC-515 [Event] When aggregate receives the step entries it shall fail the gate on any failed step, record critical_found 0 for a passing scan and -1 for a failing scan, keep null when the scan was skipped, and treat a vanished tool (127) as a skip rather than a vulnerability (1 of 1 decisions, 4 of 4 code paths).
- BSA-AC-516 [Event] When the gate completes it shall write the report with schema bts-sbom.supply-chain.v1 to evidence/supply_chain/gate_<ts>.json and the bench summary to evidence/supply_chain/bench/bench_latest.json plus one timestamped bench copy, with per-step state and skip reasons preserved (2 of 2 artifact paths, 1 of 1 bench copy).

### 오류 봉투·핸드오프·챗 스트림·HITL (MetaNet 4주차 3차시)

실패를 숨기지 않는다. `handoff.py`는 4-3차시의 오류 봉투({error_type, severity warning/recoverable/fatal,
retry_budget, completed_steps, partialResult, coverage_gap})와 단계 간 명시 계약({schema_version, task,
context, constraints, not_passed})을 순수 함수로 제공하고, council 판정 어댑터는 멤버 실패가 없으면 봉투를
만들지 않는다(거짓 봉투 금지) — 부분 합의는 recoverable, needs_human 붕괴는 fatal. `chat_stream.py`의
StreamingChatbot은 Chatbot을 상속해 관찰만 추가한다(라우터·검증기·게이트 무손상): 7종 이벤트
step_start/tool_call/tool_result/awaiting_approval/handoff/final/error를 순서대로 내보내고, 도구 하나의
실패는 recoverable 봉투+다음 도구로 이어지는 부분 결과이며, plan_patch 결과는 승인 토큰과 함께
awaiting_approval을 내고 events.py의 PATCH_GATE 상태(awaiting_approval/approved/not_requested)를 그대로
쓴다 — 적용은 사용자만 닫는다(HITL). `POST /api/chat/stream`은 이 이벤트를 text/event-stream으로
실시간 송출하고, 웹 콘솔의 단계 스트림 패널이 타임라인·갭 배너·승인 배너를 렌더링한다.

- BSA-AC-517 [Event] When error_envelope is called it shall return exactly {error_type, severity, retry_budget, completed_steps, partialResult, coverage_gap} and refuse a severity outside warning/recoverable/fatal; the handoff shall carry schema_version bts-sbom.handoff.v1 with task/context/constraints/not_passed, council_envelope shall return None when no member failed, a recoverable envelope with the surviving partial verdict when members failed but a verdict was reached, and a fatal one when the verdict collapsed to needs_human (3 of 3 severities, 1 of 1 no-lie case).
- BSA-AC-518 [Event] When StreamingChatbot asks a patch-plan question it shall emit the ordered step_start, tool_call, tool_result, awaiting_approval, handoff, final timeline with dense seq numbers, the awaiting_approval carrying the 16-hex approval token and events.PATCH_GATE_STATES, the handoff carrying schema_version and no not_passed entries for a clean answer, and the /api/chat/stream route shall serve the same events as text/event-stream with id/event/data records (7 of 7 kinds, 1 of 1 token).
- BSA-AC-519 [Event] When a chat tool raises mid-turn StreamingChatbot shall emit an error event whose envelope is recoverable with retry_budget 1 and a coverage gap naming the failed tool, continue with the remaining tools, still return a found answer and still end the timeline with final (1 of 1 failures, 1 of 1 surviving turns).
- BSA-AC-520 [Event] When format_stream_sse renders an event it shall produce id/event headers plus a newline-safe multi-line data body terminated by a blank line, matching events.format_sse's wire discipline, and every streamed record shall parse back to one chat event with its seq preserved (2 of 2 wire rules, 1 of 1 round-trip).

### 벤치 3경로·kind 매니페스트 (브리프 5 G1 + 미측정 해소)

게이트의 벤치 단계는 /healthz(검사 없음) 하나만 재서는 실측을 늘리지 않는다 — 세 지연 등급을 함께 잰다:
/healthz(프로세스 생존), /readyz(검사 수행: 폴더 쓰기+import+코퍼스), /api/history(증거 폴더 읽기),
경로별 p50/p95/max를 `bench_latest.json`의 endpoints 블록에 기록하고 세 경로 전부 200일 때만 ok.
deploy/kind/는 단일 노드 kind 클러스터용 매니페스트를 산출만으로 제공한다(호스트에 kind 부재 — 미배포를
README가 명시): replicas 1 + Recreate(공유 상태는 evidence PVC 하나), readiness /readyz·liveness
/healthz 역할 분리, ClusterIP 고정(무인증 서비스의 노출 축 고정), 비루트 UID 10001, :latest 금지,
리소스 한도 선언. 검증은 kubectl client dry-run 파싱(4문서)과 정적 규칙 테스트이며, 클러스터 적용은
kind 설치 후 README 절차를 따른다(fsGroup 필요 여부는 적용 후 실측 항목으로 명시).

- BSA-AC-521 [Event] When the gate's bench step runs it shall request /healthz, /readyz and /api/history the same number of times and record per-path p50/p95/max with the HTTP status in bench_latest.json, marking ok only when all three returned 200 (3 of 3 latency classes, 1 of 1 ok rule).
- BSA-AC-522 [Event] The kind manifest set shall contain exactly Namespace, PersistentVolumeClaim, Deployment, Service with runAsNonRoot UID 10001, a pinned non-latest image, distinct /readyz readiness and /healthz liveness probes, ClusterIP-only exposure with no NodePort or LoadBalancer, the evidence PVC mount, replicas 1 with Recreate, declared resource limits - parseable by kubectl client dry-run - and the README shall state 산출만/미배포 with the port-forward procedure and the unverified fsGroup item (4 of 4 documents, 8 of 8 policy rules).

## Book KB (bts_sbom_app/books.py, bts_sbom_app/books_api.py)

### 아키텍처 도서 지식 베이스 (Book KB, 2026-11-22)

사용자가 소유한 로컬 PDF/EPUB 아키텍처 도서(실측 30권, 422MB)를 레거시 재구현 프로젝트의 지식 원으로 흡수한다.
계층 1은 결정론적 추출이다: `books.py`가 폴더를 순회해 EPUB은 표준 라이브러리만으로(zipfile+html.parser+xml.etree,
ADR-0007 유지), PDF는 외부 `pdftotext`로 텍스트를 뽑고, 책별 `sections.jsonl`/`book.md`/`stats.json`(페이지·문자·
정크비율)과 전역 `registry.json`(모든 파일에 ok/skipped/duplicate 명시 상태)을 `evidence/books/`(gitignored —
저작물 원문은 저장소에 넣지 않는다)에 쓴다. 계층 2는 정제 노트다: `knowledge_books/*.md`는 추출 원문을 읽고 우리
말로 종합한 것으로 각 노트가 "이 프로젝트 적용" 절을 가진다. 노트를 knowledge/ 평가 코퍼스에 넣었을 때
실측 회귀가 나왔다(dev recall 0.933→0.867, 게이트 허용폭 0.02 초과) — 따라서 노트도 serve-time 채팅 인덱스에만
적재되고 평가 코퍼스는 불변이다. 원문 청크(kind="books")는 State에 캐시되는 serve-time 전용 2차 인덱스로만 검색된다 — `State.bot()`이 요청마다 인덱스를 재구성하는 구조에서
수만 청크를 재구성에 끌어들이지 않고, RAG 평가 코퍼스(golden/dev/test 기준선)를 불변으로 지키기 위해서다. 채팅은
`book_search` 도구(프로젝트 불필요)로 이 2차 인덱스를 조회하고 모든 행에 `[book] 제목 (형식) - 절: "짧은 인용"`
속성을 단다. UI는 Book KB 탭에서 등록부·목차·검색·ingest 작업을 제공한다.

- BSA-AC-523 [Event] When the books builder runs over a source folder it shall attempt every .pdf/.epub file and record one registry entry per file with an explicit status ok, skipped or duplicate plus per-book stats (sections, chars, junk_ratio) and per-book artifacts sections.jsonl, book.md, stats.json under the output folder (2 of 2 synthetic files; 30 of 30 on the real folder 2026-11-22).
- BSA-AC-524 [Event] When two ingested files have identical SHA-256 the system shall index the first and record the second as duplicate with duplicate_of pointing at the first file (1 of 1 duplicate pair).
- BSA-AC-525 [Event] When an EPUB book is extracted the system shall parse it with the Python standard library only (zipfile, html.parser, xml.etree), honouring container.xml rootfile, OPF metadata title and spine order, and fall back to sorted xhtml members with spine_fallback recorded when the OPF cannot be honoured (0 new third-party dependencies, 1 of 1 fallback path).
- BSA-AC-526 [Event] When no PDF text extractor is on PATH or pdftotext fails or the PDF has no text layer the system shall record the PDF as skipped with a reason string and never silently drop or half-index it (3 of 3 skip reasons, 1 of 1 synthetic no-extractor case).
- BSA-AC-527 [Event] When a client searches the book library over GET /api/books/search the system shall return found plus top-k rows each carrying book, source id, heading and a snippet of at most 241 chars with took_ms, refuse an empty or oversized q with 400, and answer an empty library with an honest ingest hint (3 of 3 route cases, 1 of 1 snippet bound).
- BSA-AC-528 [Event] When a question names the book library the chatbot shall route to book_search without an analysed project, from both the regex router and the planner catalog, and answer with [book]-attributed lines or the honest no-library hint (3 of 3 routing questions: Korean fleet, English fleet, project-scoped).
- BSA-AC-529 [Event] When books are ingested the system shall keep the raw book chunks kind="books" in a serve-time-only index cached on State and invalidated by the registry signature, and load the distilled notes from knowledge_books into the chat index only, both excluded from evals.build_index so the RAG golden/dev/test baselines are unchanged by the book layer (3 of 3 eval sets identical pre/post; measured 2026-11-22).
- BSA-AC-530 [Event] When the distilled notes of the book library are stored in knowledge_books every note shall be our own synthesis carrying an "이 프로젝트 적용" section, no line over 400 chars so no book text is pasted, and every indexed book slug shall have one note (29 of 29 notes).
- BSA-AC-531 [Event] When an ingest is requested the system shall refuse a non-existing folder with 400, refuse a second concurrent ingest with 429, and report job state on /api/jobs/<id> with the same event bus wire as scan jobs, refusing cross-origin POSTs with 403 (3 of 3 refusals, 1 of 1 done job).
- BSA-AC-532 [Event] When book_search returns passages every line shall attribute the book title, format and section heading so the reader can locate the passage in their own copy, and the closing line shall state the copyright stays with the authors (1 of 1 synthetic book, 3 of 3 attributed lines).

### 스캔 진입점 통합 — Scan 랜딩 한 폼, Analyze 한 번에 OSS 성과물까지 (2026-11-22 화면 통합, ADR-0026)

메인 파이프라인(🌐)과 OSS 스캔 엔진(📜)은 엔진이 다르지만(파이프라인 vs oss_api), 진입점이 둘이어서 UX
불편이었다. 2026-11-22 사용자 지시("이 화면은 scan 부분에 싹다 통합")로 통합 폼이 🌐 Scan 랜딩 하나로
모인다: 대상 입력(git URL·로컬 폴더·아카이브) 한 줄에 branch/tag·offline·EXAONE(메인 파이프라인 옵션),
OSS 분석 유형(source/dependency/binary + sbom-info.yaml 보정), exclude 칩이 같은 상자에 있고 그 아래
Previous scans(OSS 이력, Open/Compare)가 붙는다(AC-565). 최상위 "📜 OSS Scanner" 사이드바 그룹은
흡수되어 Scan 섹션의 "📜 OSS 결과" 서브탭이 되고(진행 단계·결과 테이블·공개문·내보내기), 랜딩의
Open·배너 버튼은 bts:activate 커스텀 이벤트로 그 탭으로 점프한다. ▶ Analyze 한 번은 두 엔진을 모두
실행한다 — 메인 파이프라인이 대상을 읽지 못해도(아카이브 등) OSS 단계는 계속 실행되며, OSS 단계는
어떤 경우에도 조용히 건너뛰어지지 않는다(엔진 스크립트 미로드·분석 유형 미선택은 배너에 정직히 기록).
결과 배너는 성공 시 job id와 OSS 결과 탭 이동 버튼(addEventListener 방식 — CSP상 인라인 핸들러 금지),
실패 시 사유와 메인 결과의 상태를 명시한다. DOM 규칙은 콘솔과 동일: note()는 HTML 문자열이고 동적
값은 esc()로 감싼다.

- BSA-AC-533 [Event] When ▶ Analyze runs on the unified Scan landing the console shall read the OSS form values (modes, excludes, branch, sbom-info correction) through BtsOss.readForm, chain the same target into POST /api/oss/scan through BtsOss.start regardless of the main pipeline's outcome - including when the pipeline cannot read the target at all, so an archive target still gets its OSS scan - poll GET /api/oss/jobs/<id> until it leaves running, and never skip the OSS stage silently: a missing engine script or an empty mode selection renders an honest banner note naming the skip, and the scan banner then shows either the success note with the job id and a real button that activates the OSS 결과 tab, or a failure note naming the reason and stating what happened to the main result (1 of 1 chains, 2 of 2 honest skip paths, 2 of 2 banner outcomes).

### 책 라이브러리 기법 통합 — MCP 서버·Agent Card·컨텍스트 순서 (ai책모음 15권)

사용자 서재(ai책모음, 15권 12.02M자, junk_ratio<=0.03)에서 추론한 기법을 기능으로 통합한다 (정제 노트
30개는 knowledge_books/, AC-530 계약). (1) MCP 서버(mcp_server.py): stdio 위 JSON-RPC 2.0, initialize
핸드셰이크(프로토콜 2024-11-05)·tools/list·tools/call로 engine_status·book_search·project_overview·
chat_ask를 노출한다 — 도구는 기존 모듈 위임(이중 구현 없음), 도구 오류는 result.isError+메시지(4상태
철학), stdout은 프로토콜 전용(배너는 stderr), CLI 진입은 `python -m bts_sbom_app mcp`. (2) Agent Card
(/api/agent-card): A2A식 발견 문서로 7개 스킬(scan/patch/license_council/chat/book_search/nl2sql/
supply_chain_gate)의 게이트를 자기 서술하고 securitySchemes는 "none, localhost"로 정직히 선언하며
handoff 스키마와 MCP 표면을 함께 공개한다. (3) lost-in-the-middle 대책: LLM 경로에 넘길 신뢰 문서를
질문 토큰 겹침 순으로 재배열(최고 근거가 맨 앞, 동률은 id 결정론, 상한 6) — 추출 답변·검색·기준선에는
무영향이고 프롬프트 순서만 바뀐다.

- BSA-AC-534 [Event] When an MCP client speaks the line-delimited JSON-RPC 2.0 protocol to `python -m bts_sbom_app mcp` it shall complete the initialize handshake with protocolVersion 2024-11-05, list exactly the six tools (engine_status, book_search, project_overview, chat_ask, nl2sql, run_scan) with object input schemas, call each tool against the real modules (engine_status reads registry and LLM-config presence, book_search returns book-provenance passages capped at 240 chars or an honest miss note, project_overview returns the overview lines and isError+reason for an unknown project, chat_ask returns a grounded cited answer), keep stdout protocol-pure with the banner on stderr, and answer -32601/-32602 for unknown method and unknown tool (6 of 6 tools, 2 of 2 protocol errors).
- BSA-AC-535 [Event] When a client GETs /api/agent-card it shall receive a card named bts-sbom with version, streaming capability true, the handoff schema id, seven skills whose gate fields name the real gates (approval-token, deterministic-aggregation, citation-verification, 3-layer-safety, trivy-critical-0), a securitySchemes entry that states none-localhost outright, and an endpoints map that includes the MCP stdio entry (7 of 7 skills, 1 of 1 honest security declaration).
- BSA-AC-536 [Event] When the LLM lane assembles its prompt the trusted documents shall be reordered by token overlap with the question - most relevant first, ties broken deterministically by source id, capped at 6 - and the retrieval, extractive answer and evaluation baselines shall be untouched by the reordering (1 of 1 orderings, 3 of 3 untouched surfaces).

## Report screen shell (bts_sbom_app/web/index.html, bts_console.js, bts_report.js)

### 데스크탑 셸 + 리포트 별도 탭 (사용자 지시 "클로드 데스크탑 형태", 2026-11-22)

콘솔을 좌측 사이드바 내비게이션 + 콘텐츠 열의 데스크탑 앱 셸로 개편하고, Git 스캔 판에 파묻혀 있던 SCA 리포트를
**📊 Report 별도 탭**으로 승격한다. 리포트 탭은 ① 프로젝트 헤더(이름·출처·분석 시각·심각도 칩 5종·SBOM/OpenVEX/
리포트 다운로드 4종) ② 복제 플랫폼 렌더러(sca_app.js — 해시 고정 무수정) 본문 ③ 거버넌스 카드 3종(수정 계획 요약은
/api/view에서, VEX 커버리지·규제 적합도는 프로젝트당 1회 lazy fetch)으로 구성된다. 채팅도 💬 Chat 별도 탭이 된다.
사이드바 버튼은 기존 상단 탭 바와 동일한 `.rtab[data-sv]` 계약을 유지해 activate()/subnav()/GROUPS 로직을 무변경
으로 둔다. ScaApp 마운트는 #reportOut 하나뿐이며 탭 진입마다 재렌더한다(sca_app.js는 mount 스코프+1회 바인딩 가드).

- BSA-AC-538 [Event] When the console page loads it shall build the section navigation as a desktop-style sidebar from GROUPS/LABELS with the same .rtab[data-sv] contract as the old top bar, containing the Scan group that carries the OSS Scanner as a member since ADR-0026 plus the single-member report group whose sub-chip row stays hidden (1 of 1 Scan membership, 1 of 1 built-at-init call).
- BSA-AC-539 [Event] When the Report tab is opened the system shall render the selected project's header (name, source, analysed time, 5 severity chips, 4 document download buttons), the copied ScaApp report body into the single #reportOut mount, and re-render the whole screen on every entry of the tab (1 of 1 mount, 4 of 4 downloads, 5 of 5 chips, 1 of 1 entry hook).
- BSA-AC-540 [Event] When an analysis finishes with state done the system shall switch to the Report tab automatically and render the two honest data-status warnings (empty project, incomplete vulnerability data) in the report banner while the scan-time status stays on the Scan tab (2 of 2 warning cases, 1 of 1 auto-switch).
- BSA-AC-541 [Event] When the Report tab renders its governance cards it shall show the fix-plan summary from /api/view and fetch decision coverage and SBOM conformance once per project, rendering a loading line before the fetch, the measured numbers after it, and a not-loaded line carrying the error when the fetch fails (3 of 3 cards, 2 of 2 lazy fetches, 2 of 2 error lines).
- BSA-AC-542 [State] The copied platform renderer sca_app.js and the platform stylesheets shall stay byte-identical to their pinned hashes while the desktop shell, the Report tab and the Chat tab are added around them (6 of 6 pinned files unchanged, 1 of 1 ScaApp mount in the page).

### 책 재추론 개선 2차 — 답변 자기교정·절삭 보고·MCP 리소스 (BOOK_IMPROVEMENT_MAP)

docs/BOOK_IMPROVEMENT_MAP.md의 전수 갭 분석(15권, 구현/신규/부분/기각 4상태)에서 나온 미구현 고가치 3건.
(1) 답변 레인 자기교정: LLM 첫 답변이 인용 정확도 게이트 미달이거나 JSON 파싱 실패면, 거절 사유를 시스템
프롬프트에 그대로 첨부해 1회만 재시도한다(nl2sql 루프의 채팅 확장) — 재거절 시 기존과 동일한 추출 폴백+
정직 노트. (2) 절삭 보고: 신뢰 문서가 상한 6을 넘으면 "N of M passages (K trimmed)"를 llm_note로 보고한다
(조용한 손실 금지). (3) MCP resources: resources/list(3건: tools/catalog, agent/card, books/notes-index)와
resources/read 본문 반환, 미지 URI는 isError+known 목록 — "툴=행동, 리소스=카탈로그"(G2 잔여분).

- BSA-AC-543 [Event] When the LLM answer lane's first attempt is rejected for citation accuracy below the 0.8 gate or for unparseable JSON, ask shall retry exactly once with the concrete failure text embedded in the system prompt, accept a passing retry as the cited answer, and fall back to the extractive answer with the rejected note after a second failure - never more than one retry (2 of 2 failure kinds, 1 of 1 retry budget).
- BSA-AC-544 [Event] When more trusted passages exist than the prompt cap of 6 the LLM answer's llm_note shall report exactly "N of M trusted passages handed to the model (K trimmed by relevance, cap 6)" and report nothing when nothing was trimmed (1 of 1 notes, 1 of 1 quiet-loss prohibition).
- BSA-AC-545 [Event] When an MCP client lists resources it shall receive exactly the tool catalog, agent card, book-notes-index and nl2sql-catalog entries, and resources/read shall return each uri's typed text body - the catalog containing the chat tool contracts, the card matching /api/agent-card with 7 skills, the notes index enumerating the knowledge_books files, the nl2sql catalog describing the vulns/pkg_map tables - while an unknown uri returns isError with the known list (4 of 4 resources, 1 of 1 unknown-uri refusal).

### 챗봇·에이전트 고도화 — 다중 턴·복합질문·인젝션 가드 (2025-26 조사 라운드)

웹 조사(2026 multi-turn playbook, Rasa, Parlant, arXiv 2507.00355/2511.15759, Haystack/NVIDIA 쿼리
분해, Fiddler 가드레일 계층론)에서 도출한 3축을 결정론 우선 원칙으로 구현한다 (conversation.py; LLM은
규칙이 못 정할 때만). (1) 대화 기억: 서버 State가 소유한 ConversationMemory(최근 3턴의 질문·도구·결과)
가 요청을 넘어 살아있고, 후속형 질문(지시대명사 시작·그중/아까·필터만·주제어+조사 물음 "라이선스는?")은
이전 질문을 문맥으로 합쳐 라우팅한다 — 문자열 결합일 뿐 의도 추측은 없고, 완전한 질문은 재작성하지 않는다.
(2) 복합질문 분해: 명시 접속(그리고/및/쉼표/and)은 항상, 조사(와/과/랑)는 우변이 도구 의도로 시작할 때만
분해("CVE-X와 관련된 프로젝트"는 분해 금지) — 파트별 도구를 돌리고 소스로 중복 병합한다. (3) 컨텍스트
계층 인젝션 가드: 도구·검색 텍스트의 지시문 유사 패턴을 세어 결과에 attempts+주석으로 보고한다 — 구조적
방어(validate_calls·신뢰 문서만 프롬프트·비신뢰 인용 표기)는 그대로고, 시도는 조용히 흡수되지 않는다.

- BSA-AC-546 [Event] When a follow-up-shaped question arrives (demonstrative start, 그중/이중, bare severity filter, or topic+particle question like "라이선스는?") and the conversation memory holds a previous turn, the router shall see the previous question merged as context and the answer shall carry followup true, while a full standalone question is never rewritten and the memory window stays at 3 turns; the server's shared memory shall carry this across separate HTTP requests (4 of 4 follow-up shapes, 1 of 1 no-rewrite rule).
- BSA-AC-547 [Event] When a question contains explicit coordination (그리고/및/쉼표/and) or a particle split whose right side opens with a tool intent, ask shall decompose it into up to 4 parts, run the tool router per part, merge results deduplicated by source, and report the parts in decomposed - while "CVE-X와 관련된 프로젝트" stays a single question and single-intent questions pass through unchanged (2 of 2 split rules, 1 of 1 no-split rule).
- BSA-AC-548 [Event] When tool or retrieval text carries instruction-injection patterns (ignore previous instructions, system prompt, you are now, reveal prompt, system tags) the answer shall carry an injection guard annotation naming the attempt count and sources, and the result shall report attempts - the content stays quarantined by the existing structural defences and is never obeyed or silently dropped (6 of 6 pattern families, 1 of 1 visibility rule).

## Code Intel (bts_sbom_app/code_intel.py, arch.py, arch_flow.py)

### 함수 레벨 코드 이해 레인 (Understand 기능 자체 재구현, ADR-0023, 2026-11-22)

SciTools Understand(REA로 설치러 식별: Qt Installer Framework, ev_555081ae)의 핵심 기능 — 함수 콜그래프·순환
복잡도·데드코드·중복 코드 검출 — 을 설치·외부 의존 없이 표준 `ast`로 자체 재구현한다(사용자 결정). 커버리지는
정직하게 Python-first: 다른 언어는 기존 모듈 레벨 분석을 유지하고 그 한계를 notes로 명시한다. 결과는
`arch.analyze()["code"]`로 기록되고, 콘솔 🔎 Code Intel 판과 Arch Intel의 Code Intel 섹션(결정론 콜그래프
다이어그램 포함)으로 표시되며, LLM 프롬프트에는 이름·수치 메타데이터만 들어간다(소스 라인 금지 불변식 유지).

- BSA-AC-553 [Event] When Python sources are analysed the system shall build a function inventory with per-function cyclomatic complexity computed from the AST (1 + branches, loops, handlers, boolean alternatives, asserts, match cases, comprehensions), resolve against project-wide function names, and record the measured caps (functions, call edges) with an explicit truncation note in notes when hit (8 of 8 synthetic functions counted correctly, 2 of 2 cap cases).
- BSA-AC-554 [Event] When a call cannot be resolved the system shall count it as unknown instead of guessing, resolve the rest name-based across the project (cross-file too), and project the result into the view bounded to 15 functions and 40 call edges with an honest None when the lane is empty (2 of 2 projection cases, 2 of 2 bounds).
- BSA-AC-555 [Event] When a Python function has fan-in 0 the system shall report it as dead code except the explicitly listed exclusions (main/cli/run/setup/teardown, dunders, test_*, decorated functions) and list those rules in notes so the reader can disagree (2 of 2 exclusion classes verified on the synthetic tree).
- BSA-AC-556 [Event] When two function bodies normalize to the identical token sequence (identifiers and literals collapsed) with at least 24 tokens the system shall report one clone group with its members, and never group tiny getters (1 of 1 synthetic duplicate pair, 0 of 0 false groups on hot).
- BSA-AC-557 [Event] When the Arch Intel prompt is assembled the code lane shall contribute metadata only (counts, names, per-function max-complexity location) - never a source line - and the deterministic call-graph diagram plus the insights family code_smells (complexity outlier, high average, dead code, duplicates) shall be derived from the same measurements (0 of 0 source lines leaked in the invariant test, 1 of 1 diagram builder, 4 of 4 smell rules).

### VS Code Maps 수용 — DGML 내보내기·레이어 검증 (arch_map)

Visual Studio 모델링 도구(Code Maps, 의존성 다이어그램)의 두 기능을 이미 측정된 import 그래프
(arch.import_graph, Py/JS/Java/Go/C/Rust/Ruby) 위에 이식한다 (arch_map.py, 결정론·오프라인·LLM 없음).
(1) DGML 내보내기: 노드/링크를 DirectedGraph 8.0.0 XML(.dgml)로 렌더링해 Visual Studio Code Maps에서
바로 연다 — 셀프 루프는 지도에서 소음이므로 제외하고 노드 라벨 재정의를 허용한다. CLI: `arch --dgml
<out.dgml>`. (2) 레이어 검증: 의존성 다이어그램 검증과 동일한 선언 규칙 — fnmatch로 노드→레이어 매핑,
deny-by-default may_depend_on 허용목록, 위반은 VS의 두 범주(불법 참조 + 선언된 홉 우회)로 보고하고
미매핑 엣지는 unknown으로 세어 전부 미매핑이면 판정을 inconclusive로 명시한다 (조용한 vacuous pass 금지).
CLI: `arch --layers <rules.json>` — 결과는 레코드의 layer_validation으로 들어가 아키텍처 답변·화면에
나타난다. rules_example()이 형식 계약을 문서화한다.

- BSA-AC-558 [Event] When the arch CLI runs with --dgml it shall write a well-formed DirectedGraph DGML document in the VS namespace carrying every distinct node with its optional label overrides and every cross-node link with self-loops dropped, parseable by a standard XML reader (1 of 1 documents, 1 of 1 self-loop rule).
- BSA-AC-559 [Event] When the arch CLI runs with --layers it shall validate the measured import graph against the deny-by-default may_depend_on rules, reporting violations in the two dependency-diagram categories - illegal references (target layer not allowed for the source, including unknown layers) and bypassed intermediate layers (a direct edge skips an allowed neighbour that itself may reach the target) - counting unmapped edges as unknown, returning verdict fail on any violation, inconclusive when every checked edge is unmapped, pass otherwise, and storing the result as the record's layer_validation (2 of 2 violation categories, 3 of 3 verdict states).

### Code Intel v2 — 클래스 인지·Butterfly·메트릭 export (REA 채굴 어휘 반영, ADR-0023 후속, 2026-11-22)

설치러 문자열 채굴로 Understand의 그래프 어휘(Butterfly·Interaction·Dependencies·Essential 계열·Clone·Compare)와
`und` CLI를 확인했다. v2는 그 어휘를 우리 측정으로 흡수한다: ① 메서드를 `클래스.메서드` 엔티티로 수집하고
`self.method`·`Cls.method`·동일 파일 우선순위로 콜 해석을 정밀화(동명 함수가 여러 파일이어도 실제 호출 파일만
fan-in) ② 함수별 callers/callees 이웃(Butterfly 아날로그)을 /api/code-butterfly로 제공 ③ 함수 메트릭 전수를
CSV로 내보내는 /api/code-metrics(Understand metrics export 아날로그) ④ nesting depth 메트릭 추가.

- BSA-AC-560 [Event] When Python sources are analysed the system shall collect classes (name, bases, direct methods) and the enclosing class of every function, resolve calls with class context (self.method to the caller's own class, ClassName.method to that class, plain names with the caller's file first), and record a nesting-depth metric per function (2 of 2 self-method resolutions, 1 of 1 same-file precedence case, 1 of 1 class inventory).
- BSA-AC-561 [Event] When a function's neighbourhood is requested over GET /api/code-butterfly/<project>?function=<name> the system shall return the function with its measured callers and callees, return 404 for an unknown function, 400 for a missing function parameter, and include the top-complexity function's neighbourhood in the view projection (1 of 1 neighbourhood shapes, 2 of 2 error states).
- BSA-AC-562 [Event] When GET /api/code-metrics/<project> is served it shall return every analysed function as a text/csv attachment with the header name,file,line,complexity,nesting,loc,sloc,fan_in,fan_out, and answer 404 with an honest reason when the project has no function-level analysis (1 of 1 CSV shapes, 1 of 1 honest 404).

- BSA-AC-563 [Event] When to_dgml renders a code map it shall cluster nodes into directory Group nodes wired with Category="Contains" containment links (IsContainment true), mark hotspot nodes with the Hotspot category styled on the map's own background, categorise cycle edges as Cycle with red dashed stroke, set the Sugiyama layout flowing top-to-bottom, and drop self-loops - all four categories defined in the document's Categories block per the DGML reference (4 of 4 group members, 3 of 3 categories).
- BSA-AC-564 [Event] When to_layer_dgml renders the layer validation it shall create one Group node per declared layer (plus an unknown group only when unmapped nodes exist), contain each node in its layer, categorise every cross-node link as Legal, Illegal or Bypassed exactly as layer_validate judged it, style Illegal red and Bypassed amber dashed through the document's Categories block, and declare the verdict as a Property - so the validation opens as a visual map in Visual Studio or any DGML viewer (1 of 1 containment rule, 3 of 3 link categories).

### Scan 랜딩 통합 — OSS Scanner 화면 흡수 (사용자 지시 "이 화면은 scan 부분에 싹다 통합", 2026-11-22, ADR-0026)

스크린샷으로 지시된 OSS Scanner 화면(폴더/아카이브/git 통합 분석 폼 + Previous scans)을 🌐 Scan 섹션
안으로 통합한다. 랜딩 한 상자에 메인 파이프라인 입력(git/폴더/아카이브 + branch + offline·EXAONE)과 OSS
폼 조각(분석 유형 체크박스·sbom-info.yaml 보정·exclude 칩 — oss_scanner.js가 #scaOssModes/#scaOssExcludes
컨테이너에 채움)이 함께 있고, 그 아래 Previous scans(#ossHistoryLanding, Open/Compare)가 붙는다. 최상위
"📜 OSS Scanner" 그룹은 제거되어 최상위 그룹이 하나 줄어들고, OSS 스캔의 진행·결과(라이선스 리스크·소스·의존성·
바이너리·공개문·내보내기)는 Scan 섹션의 "📜 OSS 결과" 서브탭(#paneOss)이 담는다. 서브탭 전환은 pane
스크립트가 bts:activate 커스텀 이벤트를 발행하면 콘솔이 activate로 이어받는 방식(CSP상 인라인 핸들러 없음).

- BSA-AC-565 [Event] When the Scan landing renders it shall present one analyze box carrying the git/local/archive target input with its branch/tag field, the offline and EXAONE checkboxes, the OSS mode checkboxes with the sbom-info correction and the exclude chips, and the Previous scans list with Open and Compare buttons directly beneath - while the former top-level OSS Scanner group is absorbed into the Scan section as the OSS 결과 sub-tab that holds the progress stages and the results (license risk, source, dependency, binary, notice, export), and a history row's Open or the success banner's button lands on that sub-tab through the bts:activate event (1 of 1 unified forms, 3 of 3 landing containers, 1 of 1 Scan-section membership, 2 of 2 cross-tab jumps).

### 클린룸 재구현 워크벤치 (docs/GLM_IMPLEMENTATION_BRIEF_6.md, 시나리오 5번)

컴플라이언스 리스크(AGPL/GPLv3)로 소스 복제가 불가능한 컴포넌트를, 아키텍처·엔진 분석에 기반해 AI가
신규로 재구현하는 레인(reimpl.py, 브리프 6). 법적 핵심은 **클린룸 2중 장벽 + 측정 게이트**: (벽 1)
리더가 `ast`로 public 인터페이스(시그니처·docstring 계약)만 추출하고 구현 본문은 절대 내보내지 않는다,
(벽 2) 생성기는 명세 텍스트만 입력받는다 — 원본 소스는 이 함수의 매개변수가 아니므로 프롬프트 유출이
구조적으로 불가능, (게이트) 생성물과 원본의 행 shingle 대조 — docstring은 명세에서 온 것이므로 양쪽에서
제거한 뒤 구현 복제만 측정하고 임계(0.05) 초과 시 기각. 라이선스 게이트가 거부하면 생성 전에 중단.
테스트는 생성 코드가 비신뢰이므로 격리 서브프로세스(타임아웃·별도 work 폴더)로 실행되고, publish 기본은
folder이며 inplace는 명시 플래그 없으면 거부된다. 모든 단계는 이벤트로 스트리밍: CLI 실시간 출력,
POST /api/reimpl은 job+EventBus로 /api/jobs/<id>/events 스트림에 step_end/final을 흘린다. LLM 부재 시
결정론 스캐폴드(시그니처+생성 테스트)까지 가며, 본문 생성엔 LLM 필요함을 결과에 명시한다.

- BSA-AC-566 [Event] When extract_interface reads a component it shall export exactly the public functions and classes with their signatures and first-line docstring contracts plus the external import roots, and the exported structure shall contain no implementation body text - the reader never leaks bodies into the spec (2 of 2 surface kinds, 1 of 1 no-body rule).
- BSA-AC-567 [Event] When the lane runs it shall write the spec document and the dependency DGML (arch_map) to the artifact folder and emit spec_ready and diagram_ready events before any generation (2 of 2 artifacts, 2 of 2 events).
- BSA-AC-568 [Event] When the generator runs behind wall 2 its prompt shall be built from the spec text only, with the original source structurally absent from the generation function; with an LLM client it shall produce the new implementation, and without one it shall produce the deterministic scaffold marked "SCAFFOLD ONLY" so the missing bodies are stated, never implied (1 of 1 barrier, 2 of 2 generation modes).
- BSA-AC-569 [Event] When the copy gate compares the generated code against the original it shall strip docstrings from both sides (contracts come from the spec), measure line-shingle overlap, reject above the threshold and refuse when license strings appear - and a genuine independent implementation shall pass (1 of 1 measurement, 2 of 2 refusal causes).
- BSA-AC-570 [Event] When the generated contract tests run they shall execute in an isolated work folder under a subprocess timeout (generated code is untrusted), and the lane shall report tests_passed or tests_failed with the tail - partial results with reasons, never a silent outcome (1 of 1 isolation rule, 2 of 2 outcomes).
- BSA-AC-571 [Event] When every gate passes the lane shall publish by copying code and tests to the destination folder, refuse an inplace destination without the explicit flag, and stream published; the license gate shall refuse the whole lane before generation when it says no (2 of 2 publish rules, 1 of 1 license refusal).

### Book KB = 서비스 고도화 추론 소스 — 책 DB가 아니라 책→우리 서비스 적용의 화면 (사용자 지정 2026-11-22, ADR-0025)

사용자 지정: "book db는 kw db를 만들라는 게 아니라 우리 서비스를 고도화하는데 추론하라는 걸로 쓰이는 것" —
Book KB 화면의 주인공을 라이브러리(수집·검색·목록)에서 추론 산출물로 바꾼다. 새 두 읽기 API가 추론 층을
노출한다: GET /api/books/notes는 knowledge_books/ 정제 노트를 노트별 원저작 형태(제목·출처 책·핵심 원칙·
"이 프로젝트 적용" 불릿)로, GET /api/books/map은 docs/BOOK_IMPROVEMENT_MAP.md를 영역별 표(기법·상태·근거,
** 제거, 구분행 제외)로 돌려준다. 파서는 루트가 없을 때 절대 CWD로 폴백하지 않고 정직한 빈 값+힌트를
돌려준다(테스트 더블·잘못된 배치에서 실제 저장소를 몰래 읽는 일 금지). bts_books.js는 화면 상단을
"🧠 우리 서비스 고도화 추론" 상자(개선 지도 → 정제 노트 순)로 열고, 인제스트·검색은 "노트와 지도가 추론된
원문 소스"/"추론의 근거를 본문에서 확인"으로 재프레밍되어 그 아래에 둔다.

- BSA-AC-572 [Event] When the Book KB screen loads it shall render the service-upgrade inference output first - the improvement map (docs/BOOK_IMPROVEMENT_MAP.md parsed per area with each technique's adoption status and evidence) and then the distilled notes (knowledge_books/ parsed per note into title, source book, 핵심 원칙 and 이 프로젝트 적용 bullets) through GET /api/books/map and GET /api/books/notes - while ingest, full-text search and the library registry stay below them as the inference's source infrastructure, and a missing notes folder, a missing map doc or a state without a root returns the honest empty value with its hint instead of ever falling back to the process working directory (2 of 2 parsers, 2 of 2 api reads, 1 of 1 inference-first order, 3 of 3 honest empties).
### 다이어그램 카탈로그 + DMN식 추론 엔진 (EA 17.2 REA 재현)

REA 근거: `C:\firebaseprojects\REA\scitools\easetup_x64.msi` (Sparx Systems Enterprise Architect **Trial 17.2.1721.15**,
ProductCode {17C51F4B-53A6-4FD9-9E29-73F6394E9C1C}, 3,744파일 전수 추출·File 테이블과 1:1 대조). 폴더명은
"scitools"이지만 내용물은 EA이며, EA.exe 안에 New Diagram 레지스트리가 내장 기술 XML(`<Stereotype name=... notes=...>`
+ `<Apply type="Diagram_*">`)로, MDG 기술 파일(BPMN 1.0/1.1/2.0, ArchiMate 3.1/2, DFD, MindMapping, Kanban,
Executable State Machines, Wireframing, DMN-Sim 워크스페이스, BPSim/LSim 엔진 jar 등)이 설치 트리로 존재한다는
것을 설치본 자체에서 확인했다 (docs/EA_REA_FINDINGS.md). 우리 구현은 이 레지스트리를 우리 도구가 실제 측정하는
데이터 위에 재현한다: 종류는 카탈로그에 명시하고, 데이터가 없는 종류는 거짓 도식 대신 이유를 말한다.

- BSA-AC-573 [Event] When the diagram catalog is served it shall carry every kind mirrored from the EA 17.2 registry grouped under the extracted group names (UML Structural / UML Behavioral / SysML / Extended / Data & Process / Enterprise / Code Intel), keep one entry per kind with its EA name, Korean title and measured data source, mirror the SysML kinds the round-2 REA re-verification proved present (BDD / IBD / Parametric - the first-pass "SysML absent" claim was a UTF-16 extraction miss, corrected in docs/EA_REA_FINDINGS.md) plus the ICONIX Robustness diagram and the Timeline label on timing, expose the user-interface/wireframing kind with an honest "not derivable - no measured UI model" note instead of a fake builder, and keep catalog_doc/catalog_lines exactly consistent with the registry (7 of 7 groups pinned, 22 of 22 core UML kinds + 4 of 4 SysML-family kinds present, 1 of 1 honest-unavailable kind).
- BSA-AC-574 [Event] When a diagram kind is built it shall render only from the analysed record's measured data (recorded import edges, code-intel classes/calls, conformance regimes, changes, plans, runtime EOL dates), return the identical Mermaid text for the identical record, refuse kinds whose inputs are absent with the explicit reason (분석된 프로젝트 기록이 필요합니다 / 기록된 import 엣지가 없습니다), and distinguish an empty-edge record from an all-intra-domain one in the note (33 of 33 kinds draw-or-explain, 5 of 5 refusal kinds, 1 of 1 determinism pair, 2 of 2 edge-note cases).
- BSA-AC-575 [Event] When a question carries arrow chains the system shall parse them as the custom diagram's source - nodes in first-seen order with stable n1..nN ids, every `->`/`-->`/`→` pair preserved verbatim, comment lines ignored - and refuse prose without arrows with the exact parse-failure note instead of inventing nodes (3 of 3 chain cases, 3 of 3 stable-id checks, 1 of 1 prose rejection).
- BSA-AC-576 [Event] When the decision table is evaluated it shall run the DMN-style inference deterministically: severity labels compare by CVSS band rank (never alphabetically), the true/false cells are literals while only `*`/`-`/empty mean always, an absent input satisfies nothing and is named in the trace, hit policies collapse fired rules per their declared semantics (F first-declared, U conflict on 2+, A requires agreement, P best priority), and the catch-all rule of the shipped remediation-policy table yields the documented monitor verdict (8 of 8 policy rules, 3 of 3 hit policies, 2 of 2 literal-vs-always cases, 1 of 1 trace-missing case).
- BSA-AC-577 [Event] When the chatbot is asked to draw or to decide it shall route deterministically (trigger words -> catalog kind, arrows without a named kind -> custom, nothing recognisable -> the catalog listing), return draw_diagram results as lines plus a diagrams payload the UI renders inline, run decide over the measured facts with explicit caller overrides, drop unknown kinds at call validation, and carry the same diagrams payload in the streamed final event so the dock renders the turn from events alone (3 of 3 routing cases, 3 of 3 run_tool shapes, 1 of 1 unknown-kind drop, 1 of 1 stream payload).
- BSA-AC-578 [Event] When GET /api/diagrams is served it shall return the full catalog without a project, build one kind from the named project's record with optional target/spec arguments, answer 404 with a reason for an unknown kind and an unknown project, and render the same .arc-dwrap markup contract in the Diagrams pane and the chat dock with the vendored Mermaid falling back to source text (4 of 4 route cases, 1 of 1 markup-contract check).


- BSA-AC-579 [Event] When the layer validator runs it shall enforce the REAL Visual Studio layer-model semantics extracted by REA of the shipped Microsoft.VisualStudio.Layer 18.11 assembly (channel-manifest targeted payload download, provenance recorded in vs_alignment): per-layer forbidden deny-lists (ForbiddenNamespace / ForbiddenNamespaceDependencies) matching imported node paths, obsolete-layer findings for declared layers whose match patterns hit zero nodes (ValidateLayerHasNoOrObsoleteArtifacts), duplicate layer-name detection on trimmed display names (LayerNamesMustBeUnique), all three finding kinds failing the verdict - forbidden hits reported as their own category alongside illegal and bypassed (3 of 3 VS rules, 3 of 3 finding categories).

- BSA-AC-580 [Event] When the layer validator encounters a node path matching several layer patterns it shall report an ambiguous_monikers finding naming the node and all matched layers (validation proceeds on the first match - the ambiguity is a finding, never a silent choice), and when a layer declares exclude patterns the matching nodes shall be removed from validation entirely - not checked, not counted as unknown, named in excluded_nodes - the VS SupportsValidation participation semantics; ambiguous monikers fail the verdict while excluded nodes never do (1 of 1 ambiguity rule, 1 of 1 participation rule).

### Claude 클라이언트 셸 — 사이드바는 세션 목록, 패널은 접이식, 대화가 주 화면 (CCD 명세 기반, 사용자 지시 2026-11-22, ADR-0027)

CCD(Claude Code Desktop) 명세 8종(CC D×RFC API·인터페이스 명세서, Code 탭 화면 해부, IF-B04 Desktop 제어면
도구, IF-A04 슬래시 명령, 하네스·가드레일·생애주기·보안·플랫폼 덱)을 전수 분석한 결론을 화면에 적용한다:
Claude 클라이언트의 사이드바는 기능 메뉴가 아니라 **세션 목록**이고, 기능은 대화가 앱을 부르는 구조(IF-B04)다.
사용자 지시("여기 메뉴를 주요 기능으로 통합해 기능이 너무 많아")에 따라 레일을 재구성한다 — ① 맨 위 ＋ 새 분석
버튼(Scan 랜딩) ② 분석 세션 목록(/api/history 프로젝트 12건, 클릭=프로젝트 선택+리포트 패널, 선택 하이라이트)
③ 기존 12판을 전부 보존하는 5개 접이식 섹션(분석 스캔/결과와 우선순위/리포트와 구조/지식과 컴플라이언스/수정과
운영 — .rtab[data-sv] 계약은 섹션 헤더가 유지) ④ 하단 💬 어시스턴트 토글(챗 독 열기+포커스). 대화면(챗 독)은
접힘에서 **펼침 기본**으로 바뀌어 주 화면이 되고(초기 상태는 마크업이 결정 — bts_chat_panel.js는 root 클래스에서
읽는다), 메시지 영역은 44vh→52vh로 확대된다. 판 자체는 하나도 삭제하지 않는다 — 내비게이션만 Claude 클라이언트
모양으로 바뀐다.

- BSA-AC-583 [Event] When the console loads it shall build the rail as a Claude-client session list - a ＋ 새 분석 button that opens the Scan landing, an analysis-session list of the analysed projects (up to 12, click selects the project and opens its Report panel, the selected one highlighted) and five collapsed feature sections that keep all 26 panels reachable under their .rtab[data-sv] headers - with a 💬 어시스턴트 toggle that opens and focuses the conversation surface, while the conversation dock ships OPEN as the main window (its initial state decided by the markup class, message area enlarged to at least 50vh) (1 of 1 session lists, 5 of 5 sections, 26 of 26 panels preserved, 1 of 1 open-by-default surfaces).

- BSA-AC-591 [Event] When the layer validator reports findings it shall use the REAL Visual Studio message formats extracted verbatim from LayerDesigner.Dsl by REA - an empty layer reported as "Layer {name} has no artifacts or child layers." and an ambiguous moniker reported as "Ambiguous moniker '{node}' encountered. It is used for both '{layer1}' and '{layer2}'." - so users see the same wording Visual Studio shows (2 of 2 message formats, 1 of 1 verbatim rule).

### 대화가 앱을 부른다 — 슬래시 명령·다음 단계 상자·대화 영속화 (CCD IF-A04·IF-B04·CL-12, 사용자 지시 "계속", 2026-11-22, ADR-0028)

Claude 클라이언트 셸(AC-583)의 2차: 대화면이 앱의 실제 구동 계가 된다. ① **슬래시 명령(IF-A04)**: 대화 입력의
`/help·/scan·/oss·/report·/risk·/prioritize·/arch·/code·/diagrams·/books·/compliance·/vex·/fix·/history·/fleet`
은 모델 호출 없이 이 클라이언트를 구동한다 — 판 전환은 bts:activate 이벤트, `/scan <대상>`은 Scan 랜딩 입력을
채우고 ▶ Analyze(메인+OSS 통합, ADR-0026)까지 실행하며, 알 수 없는 명령은 조용히 모델로 넘어가지 않고 정직한
안내를 돌려준다. ② **다음 단계 상자(CCD zone 5)**: 턴이 실제로 실행한 도구만 근거로, 대응 판 보기 버튼
(예: top_vulns→📊 Findings, plan_patch→🔧 Patch, book_search→📚 Book KB)을 응답 아래에 제안한다 — 안 돌린
도구의 판은 제안하지 않는다. ③ **대화 영속화(CL-12 아날로그)**: 프로젝트별로 이 브라우저에만 대화를 저장하고
세션 전환 시 함께 교체된다. 저장 시 승인 버튼·다음 단계 버튼 같은 죽은 컨트롤은 잘라내고, 저장 실패(스토리지
불가)는 조용한 기능 상실이 아니라 "영속되지 않음"으로만 끝난다. 프로젝트별 지우기 버튼이 있다.

- BSA-AC-592 [Event] When a chat turn is sent the conversation surface shall first resolve app slash commands locally - the fifteen panel commands open their panel through the bts:activate event and /scan <target> additionally fills the Scan landing input and runs the unified Analyze - without any model call, reporting an unknown command with an honest hint instead of forwarding it; when a turn finishes the surface shall offer a next-steps row built only from the tools that turn actually executed, each button opening the matching panel; and the conversation shall persist per project in this browser only, stripped of approval and next-step controls on save, swapped on project change, clearable per project, with a failed storage write ending as a non-persistent conversation rather than an error (15 of 15 panel commands, 1 of 1 scan-with-target flow, 12 of 12 tool-to-panel suggestions, 1 of 1 per-project persistence).

### HITL 승인 체인 실측(--chat-actions)과 실측이 잡아낸 두 결함 수선 (사용자 지시 "계속", 2026-11-22)

남은 실측 항목(--chat-actions 승인 체인)을 8801 실측 서버로 전 구간 측정했다. 측정이 두 결함을 잡아냈다:
① "수정 계획을 세워줘"(계획 요청)가 plan_patch가 아니라 읽기 전용 상태 표시(patch)로 라우팅됐고 — _PLAN_ASK에
"수정 계획"이 없었다 ② _patch가 타임스탬프 없이 저장된 패치 상태를 현재형("Patch status: applied")으로 내보여
오래된 기록이 방금 일어난 일처럼 읽혔다. 수선: _PLAN_ASK에 수정·업그레이드 계획/remediation plan/계획을 세워를
추가하고, actions.patch_apply 결과에 at 타임스탬프를 남기며, _patch는 "Last recorded patch run of <시각> …
this question applied nothing; to apply, ask for the plan and approve its token"으로 역사 표시로 바꾼다.
실측 자체의 결과(양방향): **긍정** — plan_patch → awaiting_approval(토큰 f8d55f1d53c83755) → 사람이 승인 버튼
클릭("계획 적용 승인 <토큰>") → apply_patch가 격리 작업 사본에서 1컴포넌트 승급·재스캔 29개 조치/0 신규,
branch bts-sbom/auto-fix 커밋 d54d30c3e5, **원본 무변경·푸시 없음**; **부정** — 플래그 없는 서버는 같은 승인
문장에 read-only 정직 거부("This chat session is read-only, so the patch was not executed")로 끝난다.

- BSA-AC-593 [Event] When a plan-shaped question names the plan without the apply words ("수정 계획을 세워줘") the router shall route to plan_patch - never to the read-only status display - so the turn emits awaiting_approval with a token and changes nothing; when a patch run is approved and executed its record shall carry an "at" timestamp, and the read-only patch display shall present the stored status as history ("Last recorded patch run of <at> ... this question applied nothing; to apply, ask for the plan and approve its token") instead of a bare present-tense status that reads as if it had just happened (1 of 1 routing rules, 1 of 1 timestamp, 1 of 1 historical wording; the live chain measured both directions: approved apply in an isolated work copy with the origin untouched, and the flag-less server refusing read-only).

- BSA-AC-601 [Event] When read_dgml opens a Visual Studio code map (.dgml) it shall return the nodes, the cross-node edges (Contains containment links separated from dependency links), the group nodes and their membership, and whether styles are present - and a map produced by to_dgml shall survive the round trip with its edges intact so layer_validate can judge an imported VS map with the same deny-by-default rules (3 of 3 structure kinds, 1 of 1 round trip).

## NL2SQL 챗봇 통합 + DB 질의 판 (bts_sbom_app/nl2sql.py, chat.py, server.py)

### DB에게 묻는다 — nl2sql 챗 도구·DB 질의 판 (3주차 강의 기능 고도화, 2026-11-22, ADR-0023 후속)

고아 상태였던 nl2sql.py를 서비스 전면에 연결한다. ① **스키마 계약 통일**: 템플릿·카탈로그·golden이 쓰던
`pkg_map.name`을 실제 빌더(osv_local_db.py)의 `package_name`으로 정렬 — 실 DB 질의가 전부 실패하던 버그
수정. ② **챗 도구 `nl2sql`**: 프로젝트 불필요(NO_PROJECT_TOOLS), 4상태 응답(status/sql/rows/error)을 그대로
passage로, DB 부재는 정직 안내. LLM 라인은 run_tool에 client를 전달해 자기교정(self-correction) 활성화.
③ **API**: `POST /api/db/query`(자연어→SQL→rows), `GET /api/db/schema`(테이블·행 수). ④ **DB 질의 판**:
질문 입력→상태 pill·SQL·rows 표, 스키마 요약, dock 제안 칩.

- BSA-AC-602 [Event] When a natural-language question over the local OSV database reaches the chat the system shall resolve it through the nl2sql tool without an analysed project, running a read-only SELECT against BTS_SBOM_OSV_DB_PATH or the repo-root default and returning the 4-state result with SQL and up to 12 row lines (1 of 1 db paths resolved, 3 of 3 state fields surfaced).
- BSA-AC-603 [Event] When the OSV database file is absent or a query fails the system shall answer with the honest 4-state failure (access_failure with error envelope, or a not-present guide naming BTS_SBOM_OSV_DB_PATH and the scanner build path) and never an invented table (2 of 2 failure shapes).
- BSA-AC-604 [Event] When the service serves GET /api/db/schema it shall return the DB path with per-table row counts read through a read-only connection, and POST /api/db/query shall reject an empty q with 400 (2 of 2 routes, 1 of 1 schema shape).

## 품질 게이트(TOP-10) + HITL 액션 루프 + UI 상태 고도화 (2026-11-23, 브리프5 plan A 완결)

지난 라운드의 회귀와 미완을 한 번에 닫는 라운드. ① **db 판 복구**: 렌더러·바인딩·라벨은 있었지만 index.html에
rpane div가 없어 레일 클릭 시 콘텐츠 열 전체가 빈 화면이던 P0 버그 — 판 div 추가 + GROUPS↔페이지 대응 단정.
② **supply-chain 와이어**: 타이포스쿼팅·네임스페이스 혼동·의존성 혼동 탐지 코어(SupplyChainAnalyzer)가 앱에서
미와이어였던 것을 파이프라인 측정 → 뷰 투영 → 챗 도구 → 판 렌더러로 연결(nl2sql 고아 패턴의 반복 방지).
③ **TOP-10 품질 게이트**(evals_top10.py): 근거성 F(claim 지지율×출처 커버리지)·완결성·툴 호출 정확도(읽기는
라이브 스위트 게이트 로그에서, 쓰기는 위조 차단)·과잉 거절률 — 두 레인(결정론 floor/라이브)을 모두 문서화하고
loop.gate Δ≥−0.02 회귀 규칙을 지표별로 부착. ④ **HITL 액션 러너**: 승인 체인 전 구간(분석→계획·토큰→승인→적용→
기록→결정 preview→확정→triage→읽기전용 거부)을 재현 가능한 evidence/chat_actions/report.json으로.
⑤ **UI 상태**: dock 빈 대화 안내·생각 중 스켈레톤·스트림 실패 재시도 버튼, 거버넌스 카드 스켈레톤, 빈 프로젝트
리포트 안내.

- BSA-AC-605 [Event] When the rail renders its pane groups every pane id in GROUPS and every renderPanes target shall have its rpane div in index.html, so a chip can never blank the content column again (26 of 26 panes, 11 of 11 render targets).
- BSA-AC-606 [Event] When the pipeline analyses a project it shall measure supply-chain substitution risks (typosquatting, npm namespace confusion, dependency confusion) into the record, project them into the view, and answer the chat supply_chain tool with kind, resemblance, CWE and recommendation - or honestly that the checks ran clean (1 of 1 pipeline stages, 2 of 2 view/chat shapes).
- BSA-AC-607 [Event] When the quality scorecard runs it shall measure the grounding F per answer from claim support (verify_claims) and source coverage with the gate >= 0.90, and the completeness of procedure/policy answers against mandatory elements with the gate >= 0.90, without an LLM judge (2 of 2 gates, 1 of 1 deterministic lanes).
- BSA-AC-608 [Event] When the scorecard reports tool-call accuracy and over-refusal it shall gate read accuracy >= 0.95 and over-refusal <= 5% from the live suite artifact (planner lane) while documenting the regex floor beside them, prove the write lane 1.0 by dropping every forged authorising value with no write tool offered read-only, and render evals/top10_report.md with per-metric gates and loop.gate deltas (5 of 5 metrics, 1 of 1 report).
- BSA-AC-609 [Event] When the action runner walks the approval chain over real HTTP the positive direction shall apply the tokened plan in an isolated work copy with the record saved applied and the decision reaching .triage.json through its confirm code, and the flag-less server shall refuse the same sentence read-only - recorded replayably in evidence/chat_actions/report.json (7 of 7 steps).
- BSA-AC-610 [Event] When the console has nothing to show yet the chat dock shall explain a fresh conversation and animate thinking with skeletons, a failed stream shall offer a retry button resending the same question, the governance cards shall load as skeletons, and an empty report tab shall say what would fill it (4 of 4 states).

## u-boot 실전 E2E: 스캔 → 클린룸 워크벤치 UI → 발견 기반 고도화 (2026-11-23)

u-boot v2026.10(388MB, GPL-2.0-or-later)을 실제 표적으로 전 E2E를 실측하고, 드러난 격을 메운 라운드. 실측:
스캔 68 구성요소·43 취약점(CRITICAL 2: certifi/urllib3/jinja2 — docs·build Python 의존), 프로젝트 라이선스
GPL-2.0-or-later(SPDX 헤더 다수결), 정책 소견 3종. 재구현은 dtoc/src_scan.py(stdlib-only)로 실 LLM 생성
(copy gate 0.0, 계약 테스트 5/0), 원본 오라클은 u_boot_pylib의 pty 의존으로 Windows에서 임포트 실패 —
compatibility_failed로 정직 기록. 드러난 격: 재구현이 UI가 전무했다, 스캔 진행이 초 시계뿐이었다, 0구성요소에
녹색 통과 배너가 떴다, GPL 프로젝트 자신의 배포 의무가 어느 표면에도 없었다, setup.py가 침묵했다, adopted 테스트가
패키지 임포트+main 꼬리 없음+헬퍼 의존으로 실제로 안 돌았다.

- BSA-AC-611 [Event] When the user opens the Clean-Room pane and submits source and component the UI shall POST /api/reimpl, consume the job's SSE stream into a per-stage strip (interface, spec, diagram, code, copy gate, contract tests, adopted oracle) with failure names mapped onto their stage, and render the verdict record (copy overlap, contract tests, adopted oracle, compatibility) from the final job (9 of 9 stages, 1 of 1 verdict shape).
- BSA-AC-612 [Event] When a scan job runs the step bar shall consume the job's SSE stream and show the live stage name with a per-stage done count instead of only elapsed seconds, falling back to the ticker when no event has arrived (2 of 2 message owners, 1 of 1 fallback).
- BSA-AC-613 [Event] When the projected report has no authoritative pass (0 components or vulnerability presence not none) the pinned green pass banner shall be rewritten to "Unknown — not a pass" with the reason and restyled as a warning after render (2 of 2 non-authoritative shapes).
- BSA-AC-614 [Event] When a strong-copyleft PROJECT license is screened for a binary distribution the policy findings shall include the project's own source-offer duty regardless of the dependency list (absent for internal), and GET /api/policy/<project>?distribution= shall recompute the findings for binary|saas|internal and reject others with 400 (3 of 3 distributions, 1 of 1 rejection).
- BSA-AC-615 [Event] When a tree contains setup.py files the scanner roster shall disclose them as unsupported manifests in the completeness block instead of reporting empty_project, while a truly empty tree still reports empty_project (2 of 2 tree shapes).
- BSA-AC-616 [Event] When the adopted upstream suite runs in the isolated work folder the lane shall rebind the component's package-context import to the NEW flat module (never the origin), resolve the suite's own helper packages from the source tree, inject a main tail for a pytest-collected TestCase suite that has none, skip a file that would run zero tests as a recorded skip instead of a silent pass, and grade honestly (the same oracle fails the original behaviour) (5 of 5 reconciliations, 1 of 1 discrimination).

## Azure 아키텍처 센터 전 카탈로그 적용 (2026-11-23, AC-617~618)

Azure 아키텍처 센터의 세 축(아키텍처 스타일 6종·클라우드 디자인 패턴 44개·모범 사례 11문서 + WAF RE/PE 검사
목록)을 전수 조사해 채점하고, 카탈로그가 실제로 요구하는 최소 집합을 코드로 적용했다. 결론: 우리는 "웹-큐-작업자의
큐 제거판"이며 Retry·Circuit Breaker·Health Endpoint·Compute Consolidation은 이미 구현(resilience.py 호스트별
breaker 포함), 불채용 35개 패턴은 문서 자체의 미적용 사례로 정당화. 적용: ① **최상위 예외 가드** — 미처리 예외가
연결 절단(RemoteDisconnected, KeyError 라운드 실측) 대신 500 JSON(correlation_id 포함, traceback은 서버 로그에만)
② **잡 동시성 상한**(BTS_SBOM_MAX_JOBS 기본 1) — 초과 시 429+Retry-After, 드레인 중 503+Retry-After
③ **SIGTERM 드레인** — 새 잡 거절·진행 잡 완료 ④ **상관관계 ID** ⑤ **Cache-Control**(API no-store·파일 max-age)
⑥ timeout 전수 감사(누락 0건). 전수 매핑: docs/AZURE_ARCHITECTURE_CENTER_APPLIED.md.

- BSA-AC-617 [Event] When a handler raises an unexpected exception the response shall be a clean 500 JSON with a correlation id and no traceback while the full trace goes to the server log only, every response shall carry X-Correlation-ID, and dynamic API responses shall be Cache-Control no-store while served files get max-age (2 of 2 handler guards, 3 of 3 response surfaces).
- BSA-AC-618 [Event] When background jobs exceed the single-replica concurrency cap the service shall refuse 429 with Retry-After, refuse 503 with Retry-After while draining on SIGTERM, and let the running job finish inside the platform grace period - the bulkhead/throttling/load-leveling trio of the architecture-center patterns applied with one semaphore (2 of 2 refusal shapes, 1 of 1 drain path).

## 컴플라이언스 클린룸 재구현 — 책→AI 2단 패턴 추론 자동 주입 (2026-11-24, AC-619~620)

패치로 끝나지 않는 라이선스(GPL-3.0/AGPL 계열)의 정답 경로는 코드 교체다. 교체 구현에 아키텍처 패턴을
**2단으로 자동 추론해 명세에 주입**한다: Tier 1 = 로컬 책 KB(원문 청크+정제 노트 병합 인덱스, 인터페이스에서
파생한 쿼리로 검색 — 원본 소스는 이 단계에서도 consult되지 않는다), Tier 2 = 책이 도메인을 못 덮으면 배포
모델 지식 폴백. 패턴 섹션은 명세 채널만 흐르고 카피 게이트의 연산 대상이 아니며, 추론 실패는 tier=none으로
정직 강하한다. 표면: /api/reimpl body의 patterns 필드(기본 on), 워크벤치 판 체크박스+patterns_ready 단계+
판정 카드 표시, license_risks의 strong-copyleft 소견에 클린룸 안내 한 줄. 실물 E2E: u-boot 의존
concurrencytest(GPL, sdist 0.1.12) — tier=book(GoF 등 책 3건)·LLM 실생성·카피 게이트 0.0·계약 테스트 2/0·
판정 ok (evidence/copyleft_reimpl/).

- BSA-AC-619 [Event] When the clean-room lane runs with pattern inference enabled it shall infer patterns two-tier - the merged book/notes index first with interface-derived queries (tier book, book/section attribution on every pattern), falling back to the deployment model's own knowledge when the books do not cover the domain (tier model), and honestly tier none when neither yields - and the chosen pack shall ride the spec as a guidance section and be recorded on the result with its provenance (3 of 3 tiers, 1 of 1 spec channel, copy gate untouched).
- BSA-AC-620 [Event] When a strong-copyleft component is screened the license-risk view shall name the clean-room reimplementation path (a patch cannot fix a license) with the component names, the /api/reimpl route shall accept the patterns switch, and the workbench pane shall expose the switch, the patterns_ready stage and the inference provenance on the verdict card (2 of 2 surfaces, 1 of 1 route field, 1 of 1 pane stage).

## 패치 호환성 게이트 (2026-11-24, AC-630~636)

패치가 "취약점은 없애지만 프로젝트를 깨뜨리는" 일을 승인 전에 측정으로 막는 게이트. 이전에는 호환성 신호가 "메이저 버전이면
high" 한 비트뿐이었고, 매니페스트를 고친 뒤 설치도 테스트도 하지 않았다. 이제 ① 프로젝트가 실제로 쓰는 심볼(ast)을
② 현재·대상 릴리스의 공개 API(소스 ast, 실행·임포트 없음)와 비교하고 ③ 고정된 다른 패키지와의 Requires-Dist 충돌
(pip 리졸버 실패)을 검사해, 깨지는 업그레이드만 보류(hold)하고 나머지는 적용한다. 증거가 얇으면 compatible이 아니라
unverified/partial. 정적 분석이 못 보는 동작 변화는 옵트인 런타임 차등(프로젝트 자체 테스트 전/후)이 맡는다.
PyPI 한정(다른 생태계는 unverified + 메이저 prior). 전체 설명: docs/COMPAT_GATE.md.

- BSA-AC-630 [Event] When a patch plan upgrades a PyPI package the project imports, the gate shall extract the symbols the project's own code uses (imports, attribute chains, call sites with their positional/keyword shape, base classes) by ast, compare them with the public API of the current and the target release, report a removed symbol and a call site the target signature rejects as breaking and a newly deprecated symbol, a removed method the project calls by name and a subclass that lost methods as review, and report 0 findings for an identical release (4 of 4 breaking shapes, 3 of 3 review shapes, 6 of 6 call-shape rules, 1 of 1 negative control).
- BSA-AC-631 [Unwanted] If a release archive holds traversal or absolute member names, links, files over 1.5 MB or non-source files, then the gate shall ignore them and parse the rest in memory with ast without executing or importing anything, prefer a pure wheel over an sdist over a platform wheel, skip yanked or oversized files, and refuse a truncated download (3 of 3 unsafe member shapes, 4 of 4 file-choice rules, 1 of 1 truncation refusal, 1 of 1 sdist layout).
- BSA-AC-632 [Event] When the target release declares a Requires-Dist constraint the project's other pins violate, or another pinned package declares one the target violates, the gate shall report a breaking pin conflict in both directions, downgrade a marker-conditional constraint to review, and accept the conflict-free case when both packages are upgraded in the same patch (2 of 2 directions, 1 of 1 marker case, 1 of 1 joint upgrade, 9 of 9 specifier cases).
- BSA-AC-633 [Unwanted] If the evidence is thin - offline, a non-PyPI ecosystem, no readable archive, a dynamic module, an unresolvable C-extension symbol or an exhausted plan budget - then the gate shall report unverified or partial with the coverage fraction, never compatible, shall never hold the plan, and shall report not_direct for a package the project never imports (6 of 6 thin-evidence shapes, 2 of 2 further statuses).
- BSA-AC-634 [Event] When the patch loop runs in block mode (the default) the gate shall hold only the plans with a breaking finding while applying the rest under the approval digest computed over all plans, finish as compat_held with 0 files written when every plan is held, annotate the plan rows with the measured compatibility before approval, record an assessment failure without stopping the loop, make 0 provider calls in off mode, and let the review reject an applied breaking plan in warn mode (2 of 3 applied and 1 of 3 held, 3 of 3 all-held plans, 6 of 6 review rules).
- BSA-AC-635 [Optional] Where the caller opts in with compat_runtime, the gate shall run the project's own test suite on the original and on the patched pins in throw-away copies with a minimal environment and binary-only installs, report a regression for a test that passed before and fails after and revert the patch, and report unverified instead of ok when there is no runner, no requirements file or no collected test (2 of 2 verdicts, 3 of 3 unverified shapes, 2 of 2 withheld secrets, 4 of 4 result-line shapes).
- BSA-AC-636 [Event] When the patch pane renders a plan or a result it shall show the measured compatibility per plan with its coverage, the exact rule and call site behind a breaking or review verdict, the held count per round, the compat_held and compat_runtime_reverted outcomes and the runtime verdict (5 of 5 surfaces, 2 of 2 pure renderers executed).

## C/C++ 지원: 선언 리더 + 클린룸 재구현 + 호환성 게이트 (2026-11-24, AC-637~644)

오픈소스의 대부분은 C/C++다. 호환성 게이트와 클린룸 레인이 Python(ast)에만 묶여 있던 것을, 실제 도구 체인(gcc/nm/git)과
표준 라이브러리 전용 C/C++ 선언 리더(cparse) 위에 다시 세웠다. 실측(u-boot v2026.10, GPL-2.0+): 선언 리더는 헤더 625개에서
Universal Ctags 대비 recall 0.997 / precision 0.998 / 크래시 0. 클린룸: 실제 lib/crc8.c(함수 2 · 132케이스)와 lib/crc16.c(함수+256항목
테이블)가 원본을 이 호스트에서 독립 빌드한 차등 오라클로 불일치 0건 검증. 정직한 한계: u-boot lib 77개 파일 중 원본이 독립 빌드되는 것은 13개
(오라클 가능 11개) — 나머지는 verdict가 contract_only(동작 미검증)이며 ok가 아니다. 전체 설명: docs/CLEANROOM_C_CPP.md.

- BSA-AC-637 [Event] When a C or C++ header or source is read, the declaration reader shall return the functions (qualified names, prototypes, qualifiers, attributes, doc comments), types (structs, unions, classes, enums with evaluated values, typedefs), macros (object- and function-like with folded values) and variables, skip #if 0 regions and non-declarations, keep no function body, and agree with Universal Ctags on real u-boot code at recall and precision of at least 0.97 on a 100-file sample (measured 0.997 and 0.998 on 625 headers with 0 crashes) (8 of 8 constructs, 5 of 5 export-macro shapes, 11 of 11 C++ declarations, 100 of 100 files without a crash).
- BSA-AC-638 [Event] When a C or C++ component is reimplemented the lane shall export only the interface (prototypes, contracts, the types, macros and data the prototypes need) from the component and its paired headers, render a self-contained header deterministically, and gate the generated code with an identifier-normalised token overlap over function bodies plus a comment-stripped line overlap that ignore forced prototypes and numeric tables, flag bodies under 60 tokens as unreliable and reject a renamed copy (0 body statements in 5 of 5 artefacts, 4 of 4 header constructs, 5 of 5 gate behaviours, 2 of 2 table measures).
- BSA-AC-639 [Event] When generated C code passes the copy gate the lane shall compile it with the real compiler, prove with nm that every API symbol and published table is exported, verify behaviour with the upstream test mains and a generated differential driver that compares the original built here with the new code, regenerate once with the observed mismatches in the prompt, and report contract_only instead of ok when no oracle exists and toolchain_missing when no compiler exists (4 of 4 scenarios: pass, wrong constant, wrong table byte, scaffold; 2 of 2 honest degradations; 1 of 1 publish rule).
- BSA-AC-640 [Event] When the original component of a kernel-style code base cannot be compiled as written, the lane shall repair the host mismatch error by error - project include paths after the system headers, conflicting project headers replaced by empty stubs under their most specific include spelling, unknown typedef names defined, marker words and feature-test macros neutralised, the paired header shadowed by the rendered one - so the differential oracle can run on real GPL code, measured on u-boot (crc8 and crc16 verified ok; 13 of 77 lib files build standalone, 11 with a comparable function) (4 of 4 repair rules, 2 of 2 spellings, 1 of 1 freestanding fixture, 2 of 2 real GPL modules).
- BSA-AC-641 [Event] When a C or C++ library upgrade is assessed the gate shall compare the declarations of the current and the target headers on the symbols the project uses and report a removed function, macro, enumerator or variable, a call whose argument count the target rejects (functions and function-like macros) and a removed struct field the project reads as breaking, changed constant values, parameter types, return types and struct layouts as review, and nothing for identical or append-only headers (7 of 7 breaking kinds, 4 of 4 review kinds, 2 of 2 negative controls, 3 of 3 C++ overload cases).
- BSA-AC-642 [Event] When a compiler is available the gate shall syntax-check every project source that includes the library against the old and against the new headers and report only the errors that exist solely with the new headers, cancel errors common to both, and lift a header-diff partial result to compatible only when the project compiles cleanly against the target headers (at least 5 of 6 seeded breaks reproduced with the compiler's own message, 1 of 1 cancelled error, 1 of 1 confirmed upgrade).
- BSA-AC-643 [Unwanted] If a library has no header source, a release has no headers, the project uses no symbol of the library or the ecosystem is not covered, then the C and C++ gate shall report unverified or not_direct instead of compatible, shall never hold the plan, and shall route a plan to the C backend by ecosystem name or language field only (4 of 4 thin-evidence shapes, 3 of 3 ecosystem routes, 1 of 1 language route).
- BSA-AC-644 [Event] When headers are read from git release tags the provider shall clone each release shallowly without hooks or submodules, read public headers only, return the same result shape as the Python backend so the patch loop, the review and the console need nothing new, and return no headers for an unknown tag (3 of 3 provider behaviours, 1 of 1 result shape).

## 5·6주차 강의 적용: 커버리지 갭 공시 · 에스컬레이션 · 평가셋 무결성 · 프롬프트 레지스트리 (2026-11-26, AC-1000~1088)

5주차(에이전트 오류 처리·에스컬레이션·평가 설계)와 6주차(평가셋 무결성·프롬프트 형상관리) 강의에서 추론한 네 가지를 이 앱의 실제 구멍에 맞춰 구현했다.
(1) 스캔이 부분 결과였는데도 챗이 "취약점 없음"이라고 답하던 것을 커버리지 갭으로 공시한다. (2) 챗이 사람에게 넘겨야 할 때를 코드가 결정하고
구조화된 인계 페이로드와 추가 전용 로그, 해결 메모 환류, 모호할 땐 되묻기, 승인 요청 4요소를 갖춘다. (3) 평가 게이트에 세그먼트 하락 차단·평가셋 버전 핀·
유출/중복/구성 점검을 더한다. (4) 모든 프롬프트에 지문을 매기고 핀과 어긋나면 막는다. 실측: 실제 평가셋의 홀드아웃(rag_test)은 유출 0건이고
rag_dev에 코퍼스로 복사된 질의 1건(경고)이 있으며, 세 평가셋 모두 영어 in-domain 질의가 0건이다. 프롬프트 15개(상수 8 + 인라인 7)가 핀으로 고정됐다.

### 커버리지 갭 공시 (bts_sbom_app/gaps.py, chat.py, fleet.py)
- BSA-AC-1000 [Ubiquitous] The coverage-gap reader shall report no gap, the status complete, no summary note and no handoff envelope for an online scan whose core data status is complete and whose limits are all zero (4 of 4 empty results).
- BSA-AC-1001 [Event] When the core data status of a scan is one of the 7 non-complete values the reader shall record exactly one gap coded data_status:<value> sourced to engine.data_status, shall never invent a gap from an unknown or absent status (3 of 3 non-statuses), and shall record one presence_unknown gap for an unknown presence (7 of 7 statuses, 1 of 1 presence).
- BSA-AC-1002 [Event] When a run recorded an offline mode, network fallbacks, unqueried components, unresolved versions, unsupported files or stage errors, the reader shall name each as a gap with a detail and a source in the fixed order mode, fallback, unqueried, version, unsupported, stage errors (6 of 6 gaps in order, 6 of 6 with source and detail).
- BSA-AC-1003 [Unwanted] If a record is older and carries no engine facts (absent, or a null status and a null unsupported list), then the reader shall report no gap and the status complete (2 of 2 shapes).
- BSA-AC-1004 [Event] When a chat answer is built from a partial scan the answer shall carry the partial-coverage sentence, the coded gap line and a coverage object with the gap codes while its citation accuracy stays 1.0, and an answer about a complete scan shall carry neither (1 of 1 partial, 1 of 1 complete, citation accuracy 1.0).
- BSA-AC-1005 [Unwanted] If a partial scan found no vulnerability then the answer shall state that none were found and shall follow that statement with the gap exactly once even when two vulnerability tools ran (2 of 2 tools, 1 of 1 annotation).
- BSA-AC-1006 [Unwanted] If an advisory id is absent from the findings of a partial scan then the answer shall name the gap beside the not-present statement, whereas a complete scan shall state only the absence (1 of 1 partial, 1 of 1 complete).
- BSA-AC-1007 [Unwanted] If a fleet question finds no match in a project whose scan was partial then the project shall be listed as not verified with its gap codes instead of as not affected, and a complete project without a match shall not be listed so (1 of 1 partial, 1 of 1 complete, 1 of 1 fleet that is only partial).
- BSA-AC-1008 [Event] When a record is partial the handoff envelope shall be recoverable and carry the completed steps (timings minus stage errors), the coverage-gap sentence and the partial result counts, and a complete record shall yield no envelope (4 of 4 fields, 1 of 1 complete).
- BSA-AC-1009 [Unwanted] If the scan was complete, the project is absent, or no vulnerability tool ran then the annotation shall add no line, and of two vulnerability tool results only the first shall carry it (3 of 3 no-op cases, 1 of 1 first-result rule).
- BSA-AC-1010 [Event] When a new analysis is reported in chat the report shall name the gaps of a partial run and nothing for a complete run (1 of 1 partial, 1 of 1 complete).

### 에스컬레이션과 인계 루프 (bts_sbom_app/escalation.py, chat.py, server.py, cli_ext.py)
- BSA-AC-1020 [Event] When a user asks for a human (4 phrasings, 3 Korean and 1 English) the chatbot shall hand the question over as human_request to security-owner before any tool runs, with an empty attempted-action list and a payload that validates (4 of 4 phrasings, 0 tools run).
- BSA-AC-1021 [Event] When a user asks for a legal judgment (2 phrasings) or for a certification or guarantee (2 phrasings) the chatbot shall hand the question over as policy_gap to legal-review or oss-governance respectively, and shall still answer a definition question (4 of 4 handed over, 1 of 1 definition answered).
- BSA-AC-1022 [Unwanted] If a message is a patch approval, a confirm code, an angry sentence that asks for no person, or a sentence saying no person is needed, then no trigger shall fire, while an angry sentence that does ask for a person shall (4 of 4 negatives, 1 of 1 positive), and a mood-laden question shall still be answered by its tools (1 of 1).
- BSA-AC-1023 [Event] When the third consecutive question goes unanswered (MAX_FAIL 3) the chatbot shall hand the question over as no_progress naming the 3 misses and reset the miss count, and an answered question in between shall restart the count (2 of 2 earlier misses stay plain answers, 1 of 1 handoff on the third, 1 of 1 reset, 1 of 1 interrupted sequence).
- BSA-AC-1024 [Ubiquitous] The escalation payload shall carry the question verbatim marked as an untrusted quote, the attempted actions, the evidence references (project and advisory ids), an id derived from its content, and no sentiment or confidence field, and a payload with a missing field, an unknown trigger, a forbidden field or a malformed id shall fail validation (5 of 5 invalid shapes rejected, 1 of 1 valid payload accepted, 1 of 1 stable id).
- BSA-AC-1025 [Event] When an escalation is recorded the log shall append it once to escalations.jsonl and treat a repeated id as a duplicate, resolving it shall need a note of at least 8 characters, a resolver and an open item, and a damaged log line shall be skipped (1 of 1 append, 1 of 1 duplicate, 3 of 3 refused notes, 1 of 1 unknown id, 1 of 1 repeated resolution refused, 1 of 1 damaged line).
- BSA-AC-1026 [Event] When an escalation of a project is resolved the later answers about that project shall append the reviewer note as data after the answer and never as a verified claim, and answers about another project shall not receive it (1 of 1 note fed back, 1 of 1 other project unaffected, 0 claims carrying the note).
- BSA-AC-1027 [Unwanted] If a component name or an advisory id matches several analysed projects and the user named none then the chatbot shall ask which project with the candidate list and run no tool, and shall not ask when a project is named, when the question is about the fleet, or when only one project matches (2 of 2 ambiguous shapes asked, 3 of 3 unambiguous shapes not asked).
- BSA-AC-1028 [Event] When a patch plan or a VEX decision preview asks for approval the answer shall state the decision, what happens if approved, what happens if not approved and the deadline, and a read-only session shall request no approval for the decision preview (4 of 4 elements in 2 of 2 previews, 1 of 1 read-only case).
- BSA-AC-1029 [Event] When the service logs or resolves escalations the web API and the CLI shall list them by status, resolve one with a note and a name, and refuse a bad status or note with 400 or exit 2 and an unknown id with 404 or exit 2 (1 of 1 chat handoff logged, 2 of 2 status filters, 3 of 3 refusals, 1 of 1 CLI resolution).
- BSA-AC-1030 [Unwanted] If the chatbot has no evidence folder then the escalation shall be returned with logged false and no file shall be written (1 of 1 payload, 0 files).
- BSA-AC-1031 [Unwanted] If the log reaches its event cap then recording shall stop appending and report that the log is full (2 of 3 recorded at a cap of 2, 1 of 1 refused).

### 평가셋 무결성: 세그먼트 · 버전 핀 · 유출 점검 (bts_sbom_app/evalguard.py, rag.py, evals.py, loop.py)
- BSA-AC-1060 [Ubiquitous] Every eval item shall belong to segments by topic (its first expected source), by language (Hangul or not) and by the out-of-domain flag (5 of 5 item shapes).
- BSA-AC-1061 [Event] When a retrieval evaluation runs it shall report n, recall and MRR per segment (the rejection rate for out-of-domain), a single-language segment shall equal the totals and the topic segments shall partition the in-domain items (4 of 4 segments, 1 of 1 total equality, 1 of 1 empty set).
- BSA-AC-1062 [Unwanted] If one segment dropped by more than 0.10 while the totals stayed inside the 0.02 gate then the retrieval pass shall be rolled back naming the segment and flagged segment_only, and a drop inside the tolerance shall be accepted (1 of 1 hidden drop blocked, 1 of 1 tolerated drop accepted, 0.0 aggregate delta).
- BSA-AC-1063 [Unwanted] If a segment has fewer than 2 items then the gate shall report it as too thin and not gate it, and a baseline segment that is absent from the candidate or has an absent value shall be undecidable (1 of 1 thin segment, 1 of 1 vanished segment, 1 of 1 absent value).
- BSA-AC-1064 [Ubiquitous] The eval-set fingerprint shall be a 12-character hash of the queries, expectations and out-of-domain flags that ignores order, spacing and punctuation and changes with any content change (3 of 3 content changes detected, 1 of 1 order and spacing change ignored).
- BSA-AC-1065 [Unwanted] If the baseline was measured on another fingerprint of an eval set then the pass shall be undecidable and rolled back even when every metric is equal, and a set that is new since the baseline shall only warn (1 of 1 changed holdout blocked, 1 of 1 new set warned, 2 of 2 sets pinned).
- BSA-AC-1066 [State] While the baseline predates pinning and segment metrics the loop shall still compare the metrics, accept a pass that holds and warn of both gaps (2 of 2 warnings, 0 undecidable).
- BSA-AC-1067 [Unwanted] If a re-baseline is asked without a reason of at least 8 characters, without any baseline, or when no eval set changed since the baseline then the loop shall refuse it, and after a deliberate eval-set change it shall record a new baseline with the reason, the replaced pass and the changed sets (3 of 3 refusals, 1 of 1 recorded re-baseline).
- BSA-AC-1068 [Unwanted] If the holdout repeats or nearly repeats (character-trigram Jaccard of at least 0.8) a query of a tuned set then the leak check shall report a blocking finding, whereas a repeat between tuned sets or inside one set shall be a warning (2 of 2 blocking near-duplicates, 1 of 1 warning duplicate, 1 of 1 in-set warning, 1 of 1 clean pair).
- BSA-AC-1069 [Unwanted] If a query is copied verbatim into the corpus or expects a source that no chunk matches then the leak check shall report in_corpus (blocking for the holdout, a warning elsewhere) and dangling_expectation (blocking), and shall not flag a reachable expectation or an out-of-domain item (3 of 3 finding kinds, 2 of 2 reachable items unflagged).
- BSA-AC-1070 [Ubiquitous] The composition table shall give per set the size, the in-domain and out-of-domain counts, the out-of-domain share, the segment counts, the thin segments, the fingerprint and any language with no in-domain query (8 of 8 fields, 1 of 1 empty set).
- BSA-AC-1071 [Unwanted] If the holdout leaks then every later retrieval pass shall be undecidable and the evalsets command shall exit 1 naming the finding, and a clean folder shall exit 0 (1 of 1 blocked pass, 1 of 1 exit 1, 1 of 1 exit 0, 3 of 3 sets pinned).
- BSA-AC-1072 [Event] When ragloop is asked to re-baseline the command shall exit 2 while no eval set changed and shall record the new baseline after a change (1 of 1 refused, 1 of 1 recorded, 3 of 3 history decisions baseline, rollback, baseline).
- BSA-AC-1073 [Ubiquitous] The real eval sets shall carry no blocking leak finding and no finding at all about the holdout, shall be pinned with 3 of 3 fingerprints and shall each report their segments (3 of 3 sets).

### 프롬프트 레지스트리와 드리프트 게이트 (bts_sbom_app/promptreg.py, evals/prompt_registry.json)
- BSA-AC-1080 [Ubiquitous] The registry shall fingerprint every prompt constant (a name ending in SYSTEM or PROMPT with at least 40 characters) and every LLM call site whose system prompt is written inline, and shall register nothing else (4 of 4 prompts in the fixture, 4 of 4 exclusions: a short constant, a plural name, a parameter and a non-LLM call).
- BSA-AC-1081 [Event] When a prompt is built with operators or in several steps the registry shall pin its template source and every step (2 of 2 operator prompts registered, 1 of 1 interpolated-value change detected, 1 of 1 step change detected).
- BSA-AC-1082 [Unwanted] If a prompt is not pinned then the check shall fail, and re-pinning shall need a reason of at least 8 characters and shall record the reason, the changed ids, the eval-set pins and the digest in the history (4 of 4 unpinned prompts, 3 of 3 refused reasons, 1 of 1 history entry).
- BSA-AC-1083 [Event] When a prompt text changes the check shall report drift with the pinned and the current fingerprint, while re-wrapping the same words, adding a comment and editing unrelated code shall not (1 of 1 drift, 3 of 3 non-drift edits).
- BSA-AC-1084 [Unwanted] If a prompt changed while its module kept its PROMPT_VERSION then the check shall flag version_not_bumped and the re-pin shall be refused until the version is bumped (1 of 1 refused, 1 of 1 accepted after the bump).
- BSA-AC-1085 [Unwanted] If a pinned prompt no longer exists then the check shall report it as missing, and the history shall keep only its newest entries up to its cap (2 of 2 missing ids, 3 of 3 newest entries kept at a cap of 3).
- BSA-AC-1086 [Event] When a loop pass runs it shall record the digest of the prompts that produced it and warn when the digest differs from the baseline pass (1 of 1 digest recorded, 1 of 1 warning on a change, 0 warnings when equal).
- BSA-AC-1087 [Event] When the prompts command runs it shall exit 1 with the changed, unpinned and version lines on drift, exit 2 on a refused update and exit 0 on a match, and shall print the report as JSON on request (3 of 3 exit codes, 1 of 1 JSON report).
- BSA-AC-1088 [Ubiquitous] The prompts in the real code shall match their pins, and the registry shall hold the named constants and the inline prompts of the changes and reimpl modules (7 of 7 named constants, 2 of 2 inline families).

## 전 자료 재분석 후속 고도화 + Azure 재배포 준비 (2026-11-27, AC-1100~1240)

메타넷 과정 폴더 전체(PDF 23 · pptx 7 · xlsx 1 · zip 6)를 문서 그룹 27개로 다시 정독하고, 각 기법이 이미 앱에 있는지 코드를 검색해 확인한 뒤 남은 갭
116건을 87개 묶음으로 합쳐 3개 관점(제품 가치 · 과정 적합 · 구현 위험)으로 점수화했다. 상위 후보를 10개 묶음으로 구현하고 묶음마다 독립 검토 2명과
반박 검증으로 결함 24건을 확정해 고쳤다. 실측 새 발견: 인젝션 방어는 한국어 공격 0/8을 놓쳤고(재현율 0.48) 일반 패턴으로 다시 쓴 뒤 홀드아웃에서 재현율 1.0 ·
오탐 0.0, 영어 질문은 신뢰도 게이트가 절반을 거절했고(found 0.5) 번역 다리와 영어 게이트 바닥으로 0.812(홀드아웃 0.875)가 됐으며 한국어 지표는 한 자리도
바뀌지 않았다, NL2SQL 패키지별 템플릿은 존재하지 않는 컬럼을 조회해 항상 실패했는데 평가가 양쪽 실패를 일치로 세어 EX 1.0으로 가려져 있었다.
배포 쪽: 무인증 공개 ingress의 편차를 앱 자체 액세스 토큰 게이트와 소스 경계로 닫고, 클라우드 빌드가 evidence(저장된 LLM 키 포함)를 올리지 않도록 허용 목록
.dockerignore를 두었다.


### 배포 보안: 액세스 토큰 게이트 · 소스 경계 · 빌드 컨텍스트 (bts_sbom_app/access.py, workspace.py, .dockerignore)
- BSA-AC-1100 [Ubiquitous] The access-token gate shall read BTS_SBOM_ACCESS_TOKEN from the environment, treat an empty or blank value as gate off, refuse a token shorter than 16 characters, generate 256-bit URL-safe tokens that its own validator accepts, and exempt exactly the two probe paths (3 of 3 blank shapes read as off, 1 of 1 short token refused, 2 of 2 generated tokens distinct and accepted, 2 of 2 probe paths exempt, 3 of 3 look-alike paths gated).
- BSA-AC-1101 [Event] When a request carries the credential as a Basic password, a Bearer token or an X-BTS-Token header the gate shall accept it by constant-time comparison, and shall refuse an absent, altered, truncated, malformed-Basic, wrong-scheme or upper-cased credential, while a gate that is off accepts everything (5 of 5 accepted forms, 9 of 9 refused forms, 2 of 2 gate-off cases).
- BSA-AC-1102 [Unwanted] If BTS_SBOM_ACCESS_TOKEN is set and a request for any route other than /healthz and /readyz arrives without the token, then the service shall answer 401 with a Basic challenge and shall never echo the token (8 of 8 gated routes refused, 2 of 2 probes open, 3 of 3 credential forms accepted, 1 of 1 altered token refused).
- BSA-AC-1103 [Unwanted] If an unauthenticated POST arrives while the gate is on, then the service shall refuse it before reading the body and shall neither process nor log it, while the same chat and stream calls with the token are served (4 of 4 POST routes refused, 0 escalation records written, 2 of 2 authenticated calls served).
- BSA-AC-1104 [State] While the gate is off the service shall behave exactly as before and the agent card shall declare the none scheme, and while the gate is on the card shall declare the accessToken scheme without ever containing the token (1 of 1 off-state card, 1 of 1 on-state card, 0 occurrences of the token).
- BSA-AC-1105 [Unwanted] If the configured token is shorter than 16 characters then the service shall fail at start-up naming the minimum, and the access-token command shall print a fresh 256-bit token that passes the same validator (1 of 1 short token refused, 2 of 2 printed tokens valid and distinct).
- BSA-AC-1106 [Event] When BTS_SBOM_ALLOWED_ROOTS names one or more folders a local source or file:// URL outside every declared root, including through .., the parent folder or a symlink, shall be refused as outside the declared roots, a file or folder inside any root shall be accepted, and with the variable unset nothing shall change (6 of 6 escape forms refused, 2 of 2 roots honoured, 1 of 1 unset case unchanged).
- BSA-AC-1107 [Unwanted] If a git URL names a loopback, private, link-local (including the cloud metadata address), shared-address-space or IPv4-mapped IP literal, or a localhost, metadata or .internal host, then the source classifier shall refuse it unless BTS_OSS_ALLOW_PRIVATE_HOSTS=1 is set (10 of 10 non-public forms refused, 4 of 4 public hosts and 1 of 1 GitHub shorthand accepted, 1 of 1 opt-out honoured).
- BSA-AC-1108 [Unwanted] If a refused source, or a host name that resolves to a non-public address, reaches workspace.prepare then it shall create nothing under work_root and shall not start git, while a resolver failure shall not by itself be a refusal (1 of 1 refused local source writing 0 bytes, 1 of 1 internal resolution refused with 0 git calls, 3 of 3 pass-through cases: public, undecidable, opt-out).
- BSA-AC-1109 [Event] When the chat analyze action or the API classifies a source outside the boundary they shall report the boundary instead of analysing it (2 of 2 refusals reported, 0 of 1 analyses started).

### 챗 무결성: 도구 호출 격리 · 숫자 인용 · 가정 표시 · 버전 스탬프 (chat.py, chat_stream.py)
- BSA-AC-1110 [Event] When one tool call among up to 4 in a chat turn raises an unhandled exception, the system shall return the other calls' results plus one structured error passage without leaking the exception message or a path, and mark the turn status partial (0 of 4 results dropped across 4 of 4 injected failure positions; 1 of 1 ask() turns correctly marked status=partial with exactly 1 of 1 tool_errors entries).
- BSA-AC-1111 [Event] When the LLM's own answer text contains a number absent from every verified claim quote, the system shall demote the answer to the extractive source instead of accepting it (2 of 2 cases correctly classified: 1 of 1 fully-grounded answers accepted as exaone, 1 of 1 answers with an uncited number demoted to tools, naming the uncited number in the note).
- BSA-AC-1112 [Event] When license_risks is called with no distribution argument, the system shall label the resulting policy line as an assumed default rather than a confirmed fact (1 of 1 default calls labelled an assumption, 0 of 1 explicit-distribution calls mislabelled).
- BSA-AC-1113 [Unwanted] If 1 or more strong-copyleft components' only compliance path is clean-room reimplementation and no C/C++ compiler is on PATH, the system shall append one coverage line naming how many of them cannot be shown as a verified pass (0 of 1 such components silently presented as verifiable; 0 of 1 note lines shown once a compiler is detected on the same input).
- BSA-AC-1114 [Ubiquitous] The system shall include a 4-field versions object (app, model, prompt_digest, spec) in every chat answer's meta, with prompt_digest changing and the other 3 fields unchanged across 2 of 2 compared snapshots taken before and after a prompt re-pin (4 of 4 fields populated).
- BSA-AC-1115 [Event] When the chatbot hands a no_progress or policy_gap question to escalation.build with the analysed project record, the record's coverage gaps shall ride the payload's evidence_refs.root_cause, while a human_request handoff and a gap-free record shall carry no root_cause key (1 of 1 payload with root_cause, 1 of 1 human_request without, 1 of 1 gap-free record without).
- BSA-AC-1116 [Ubiquitous] The assembled chat answer shall be redacted for secret-shaped kinds only (private keys, AWS/GitHub keys, bearer tokens, key=value secret assignments) and the response shall report which kinds were masked, while an email and a phone number embedded in the same answer shall never be touched (1 of 1 secret masked and reported, 1 of 1 answer with no secret left unchanged, 2 of 2 non-secret kinds preserved).
- BSA-AC-1117 [Event] When the nl2sql tool answers with a result that exposes an as_of value the chat result shall append one line naming the imported-at date or "never imported" per referenced ecosystem, or "unknown" when no ecosystem is exposed, and a result with no as_of field shall add no line (2 of 2 freshness shapes rendered, 1 of 1 no-op case).

### 대화 사실 · 에스컬레이션 근거 · PII/비밀값 가림 · 모순 게이트 (conversation.py, escalation.py, pii_guard.py, quality.py)
- BSA-AC-1120 [Event] When a follow-up question implicitly references an identifier mentioned more than 3 turns earlier (already fallen out of the 3-turn deque), the system shall resolve it from the case-facts store instead of returning found=false (10 of 10 single-entity regression questions resolved, 0 of 2 existing no-history/full-question behaviours regressed).
- BSA-AC-1121 [Event] When a later turn records a different value for an already-known case-fact key, the system shall log both the old and new values together with their turn numbers in CaseFacts.conflicts instead of silently overwriting (2 of 2 conflicting-key scenarios recorded with both values and turn numbers).
- BSA-AC-1122 [Event] When escalation.build is called with kind no_progress or policy_gap and a project record with coverage gaps, the system shall copy gaps.of(rec) verbatim into evidence_refs['root_cause'] and omit the key when there are no gaps (2 of 2 kinds enriched, 1 of 1 empty-gap case with the key omitted).
- BSA-AC-1123 [Ubiquitous] The system shall mask every PII/secret-shaped substring (email, phone, Korean RRN-shaped number, AWS key, GitHub token, bearer token, private-key block, secret assignment) with [redacted:<kind>] while never altering a CVE/GHSA id, an SPDX license id, a version string or an ordinary number (8 of 8 seeded PII/secret shapes masked, 0 of 6 non-PII tokens altered).
- BSA-AC-1124 [Event] When an escalation's triggering question or a reviewer's resolution note contains PII, the system shall redact it before it is written to escalations.jsonl, and the escalation id shall still distinguish two genuinely different questions that happen to redact to the same text (the id is hashed from the original, pre-redaction text, not the redacted one) so neither is silently dropped as a duplicate (0 of 20 seeded PII substrings recoverable in the logged file; 2 of 2 distinct-PII-only escalations logged under distinct ids with 0 silently dropped, while a literal repeat of the same original question still dedupes as before).
- BSA-AC-1125 [State] While an answer's kept claims assign opposite status words to the same advisory id or license name - including when one claim uses natural negated phrasing such as 'not vulnerable' or 'no patch available' (or the Korean negations 미영향/패치 없음) rather than a bare antonym - the system shall flag a contradiction and gate the batch's contradiction rate at <=0.05 without changing the existing 5-gate report shape (1 of 1 contradiction scenario flagged, 4 of 4 negated phrasings classified by their negation rather than the positive substring they contain, 0 of 6 locked gate-shape assertions broken).
- BSA-AC-1126 [Ubiquitous] The system shall never record an email address as a CaseFacts component fact (the component@version extraction requires the version side to start with a digit and skips any span already matched as an email), while still recording a genuine component@version mention (5 of 5 email-only turns recorded 0 component facts, 5 of 5 genuine component@version turns still extracted correctly).
- BSA-AC-1127 [Ubiquitous] The system shall record a license case fact only when the turn also carries a license-context keyword (라이선스/license/spdx), so an SPDX id that collides with an ordinary English word or tool name (JSON, Ruby, curl, X11, PostgreSQL, MS-PL) is not misread as naming that license (6 of 6 ordinary-word turns recorded 0 license facts, 2 of 2 genuine license-context turns still extracted correctly).
- BSA-AC-1128 [State] While CaseFacts accumulates facts and conflicts over a long-running conversation, the system shall bound facts at MAX_CASE_FACTS=500 and conflicts at MAX_CASE_CONFLICTS=200, evicting the least-recently-seen entry first, with the process-wide single-tenant sharing limitation stated honestly in the class docstring (1 of 1 over-cap facts scenario bounded at exactly 500 with the oldest evicted, 1 of 1 over-cap conflicts scenario bounded at exactly 200 with the oldest dropped).
- BSA-AC-1129 [Ubiquitous] The system shall not log a CaseFacts conflict when two mentions of the same key differ only in letter case, while still logging a genuine value change regardless of case (2 of 2 case-only-difference scenarios recorded 0 false conflicts, 1 of 1 genuine case-different-value scenario still recorded as a real conflict).

### 송신 허용 가드(SSRF)와 소스 트리 비밀값 스캔 (net.py, secretscan.py)
- BSA-AC-1130 [Event] When net.py's shared fetch gateway is asked to reach a URL whose host is a literal loopback/link-local/private/CGNAT address (including the 169.254.169.254 cloud metadata address, IPv4 and IPv6), the system shall refuse it as resilience.ACCESS_FAILURE before opening a socket (6 of 6 blocked-address fixtures refused: 127.0.0.1, 169.254.169.254, 10.0.0.5, 192.168.1.1, ::1, fe80::1; 0 regressions).
- BSA-AC-1131 [Event] When net.py's shared fetch gateway is asked to reach a URL using a non-http(s) scheme, the system shall refuse it as resilience.ACCESS_FAILURE even when the private-host opt-out is set (2 of 2 scheme fixtures blocked in both opt-out states: file://, ftp://; 0 regressions).
- BSA-AC-1132 [Event] When a hostname resolves via DNS to a non-public address rather than being given as a literal IP, the system shall refuse the fetch the same as for a literal private IP (2 of 2 DNS-resolved-private fixtures blocked, 0 regressions).
- BSA-AC-1133 [Optional] Where the operator sets BTS_OSS_ALLOW_PRIVATE_HOSTS=1, the system shall let a private-address host through while still refusing a non-http(s) scheme (2 of 2 opt-out assertions: 1 host allowed, 1 scheme still blocked).
- BSA-AC-1134 [Ubiquitous] The egress guard shall never block a URL whose host resolves to a public address, and the existing TRANSPORT-stubbed callers shall be unaffected by the new guard (6 of 6 public-host fixtures passed: pypi.org, files.pythonhosted.org, registry.npmjs.org, repo1.maven.org, api.osv.dev, endoflife.date; 3 of 3 TRANSPORT-stub smoke calls succeeded with 0 DNS lookups; 0 regressions).
- BSA-AC-1135 [Event] When net.py's fetch_bytes (the package-archive path) is asked to reach a blocked URL, the system shall refuse it the same as fetch_json/fetch_text, and shall still allow a public host through to the (mocked) connection attempt (2 of 2 blocked-case fixtures refused, 1 of 1 public-host fixture allowed, 0 regressions).
- BSA-AC-1136 [Ubiquitous] secretscan.scan_tree shall flag at least one line for each of the 7 rule categories (aws-access-key, private-key-block, anthropic-api-key, openai-style-key, azure-storage-account-key, password-in-url, password-assignment), reporting only file+line+rule, never the matched text (7 of 7 categories detected, 0 secret values present in the returned findings).
- BSA-AC-1137 [Event] When the scanned tree contains a binary file and a file over the 2MB limit, the system shall skip both, count them under a named coverage limit, and shall not report the scan as clean when findings is 0 but files were skipped (2 of 2 skip fixtures counted exactly: 1 binary, 1 oversized; coverage_limited true; findings 0).
- BSA-AC-1138 [Unwanted] The tree walk shall not descend into .git or node_modules directories by name and shall not follow a symlink that would escape the scanned root (2 of 2 skip-by-name fixtures never visited, 1 of 1 symlink-escape fixture not followed: files_scanned 1, files_skipped_total 0).
- BSA-AC-1139 [Unwanted] The scanner shall not flag benign lines that merely resemble a secret pattern but fall short of it, avoiding false positives (3 of 3 benign fixtures produced 0 findings: short password value, password-free URL, too-short AWS-key-like string).

### 운영 한도: LLM 예산 단계 · 토큰 비용 장부 · Retry-After · 챗 속도/동시성 제한 · 질문 길이 (llm.py, server.py)
- BSA-AC-1140 [Event] When calls_today crosses the 50%/80%/100% thresholds of daily_budget, the system shall report ChatClient.budget_tier() as warn/critical/exhausted via describe()/GET /api/llm (3 of 3 thresholds, 8 of 8 measured data points), ok below 50%.
- BSA-AC-1141 [Event] When the LLM budget tier is degraded, the system shall thread a "LLM daily budget <tier> (<calls>/<budget> calls today)" note into the llm_note field of both /api/chat and /api/chat/stream (2 of 2 endpoints), leaving it unchanged at tier ok (1 of 1 case).
- BSA-AC-1142 [Event] When a completion returns usage tokens, the system shall add prompt_tokens/completion_tokens to today's ledger entry (2 of 2 fields) and compute estimated_cost_usd for a priced model (1 of 1 formula, measured 0.0075 USD), reporting null for an unpriced model only when no prior numeric cost_usd exists that day (1 of 1 fresh-day case), never overwriting a previously recorded numeric cost_usd when a later same-day call uses an unpriced model (1 of 1 mixed-model-day preserve case, measured 0.0075 USD preserved), while an old int-only ledger day shall still parse as its call count (1 of 1 migration case).
- BSA-AC-1143 [Event] When the provider answers HTTP 429 with a Retry-After header, the system shall sleep for its value capped at 30 seconds (1 of 1 present case, 1 of 1 cap case) instead of the fixed 3-second wait, falling back to the fixed wait when the header is absent or unparseable (2 of 2 fallback cases).
- BSA-AC-1144 [Event] When a completion's finish_reason is "length", the system shall raise LLMTruncated("truncated by token budget...") through the existing LLMError base class (1 of 1 case) while still recording the tokens actually consumed (2 of 2 counters).
- BSA-AC-1145 [Event] When concurrency on /api/chat or /api/chat/stream exceeds the configured cap, the system shall answer HTTP 429 with a Retry-After header and shall not invoke the chatbot (1 of 1 over-cap case, 0 chatbot calls measured), then shall admit the next request once a slot is released (1 of 1 recovery case).
- BSA-AC-1146 [Event] When one caller exceeds its sliding-window rate limit on /api/chat, the system shall answer that caller HTTP 429 with Retry-After without spending the daily LLM budget (1 of 1 over-rate case), while a different caller's request in the same window shall still succeed (1 of 1 other-caller-unaffected case).
- BSA-AC-1147 [Event] When the TCP peer is private or loopback, the system shall take the caller id from the last X-Forwarded-For entry (2 of 2 private/loopback-peer cases); otherwise it shall use the TCP peer address even when X-Forwarded-For is present (2 of 2 direct-peer cases).
- BSA-AC-1148 [Event] When a question exceeds MAX_QUESTION_CHARS (4000), the system shall answer HTTP 400 "question too long" on /api/chat and /api/chat/stream (2 of 2 endpoints), while exactly 4000 characters shall still be accepted (2 of 2 endpoints).
- BSA-AC-1149 [Event] When the number of distinct per-caller identities tracked by State._chat_hits would exceed MAX_CHAT_RATE_CALLERS (4096), the system shall prune already-expired caller entries first (1 of 1 expiry-pruning case), then the oldest-tracked remaining callers (1 of 1 oldest-fallback case), so the dict stays bounded across many distinct callers over the life of the process (1 of 1 bounded-after-500-distinct-callers case) instead of growing without bound.

### MCP 서버 고도화 (mcp_server.py)
- BSA-AC-1150 [Event] When an MCP tools/call for chat_ask requests use_llm=true and the operator has not set BTS_SBOM_MCP_ALLOW_LLM=1, the system shall answer deterministically and record the gate reason in llm_note, making 0 outbound LLM calls (1 of 1 gated call measured, 0 regressions).
- BSA-AC-1151 [Event] When an MCP tools/call for chat_ask requests use_llm=true and the operator has set BTS_SBOM_MCP_ALLOW_LLM=1, the system shall let the request reach the configured LLM client (1 of 1 call measured to reach the client, 0 regressions).
- BSA-AC-1152 [Ubiquitous] The MCP initialize response shall always declare both the tools and resources capability keys, and resources/list shall return all 4 of 4 declared resources (0 regressions).
- BSA-AC-1153 [Event] When an MCP client reads resources/read for uri bts://nl2sql/catalog, the system shall return the vulns and pkg_map tables (2 of 2 present, 0 regressions).
- BSA-AC-1154 [Event] When an MCP client calls the nl2sql tool with a counting question over a local OSV database, the system shall return a success status with the counted rows (1 of 1 case matched exactly, 0 regressions).
- BSA-AC-1155 [Event] When an MCP client calls prompts/list, the system shall return exactly 7 of 7 canned-question templates, each with an argument schema (0 regressions).
- BSA-AC-1156 [Event] When an MCP client calls prompts/get with a valid project argument, the system shall render exactly 1 message with the argument substituted and 0 unresolved placeholders remaining (0 regressions).
- BSA-AC-1157 [Unwanted] If an MCP client calls prompts/get without the required project argument, or names an unknown prompt, the system shall reject the call with JSON-RPC error code -32602 (2 of 2 cases rejected, 0 regressions).
- BSA-AC-1158 [Event] When an MCP tools/call for run_scan carries _meta.progressToken, the system shall emit exactly 1 notifications/progress line per completed pipeline stage (4 of 4 stages) before the final result line (0 regressions).
- BSA-AC-1159 [Event] When an MCP tools/call for run_scan carries no progressToken, the system shall emit 0 notifications/progress lines while still returning 1 of 1 unaffected final result (0 regressions).

### NL2SQL: 형식 검증 · 예시 · LLM 경로 평가 · 스냅샷 신선도 (nl2sql.py)
- BSA-AC-1160 [Event] When generate_sql's LLM-lane reply has a non-string sql, a non-list tables/assumptions, or an unrecognised key, the system shall raise SqlError(category='validation') into answer()'s existing capped self-correction loop (3 of 3 malformed-shape regression cases end in access_failure, attempts<=3, 0 uncaught exceptions).
- BSA-AC-1161 [Event] When a malformed generation shape is followed by a well-formed one on retry, the system shall self-correct to success instead of failing immediately (1 of 1 case: attempts=2, rows=[(6,)], the concrete shape error carried verbatim in the regeneration prompt).
- BSA-AC-1162 [Event] When select_examples ranks the curated few-shot pool by token overlap with a question, the system shall return the top-k examples (clamped to the 2-4 band) with the highest-overlap example first (3 of 3 requested k values (1,3,99) clamp to (2,3,4), 1 of 1 ranking case correct).
- BSA-AC-1163 [Event] When generate_sql builds the LLM-lane prompt for a question, the system shall fold every selected few-shot example's question and SQL text into the prompt sent to the client verbatim (3 of 3 selected examples found in the captured prompt).
- BSA-AC-1164 [Unwanted] While NL2SQL_EXAMPLES is checked against the golden set, the system shall contain 0 of 18 example questions that leak (exact-text match) into the 30-question golden set.
- BSA-AC-1165 [Event] When nl2sql_eval is given a client, the system shall run all 30 of 30 golden questions through the LLM lane and report ex_llm (measured 0.9) distinct from ex_template (measured 1.0, genuinely: a reference_sql execution failure is never counted as a hit even when the candidate also fails, and every miss states a `stage` of which side(s) failed), with 3 of 30 LLM misses and a per-status breakdown summing to 30; with no client (2 of 2 keys checked) it shall omit ex_llm and llm_misses entirely.
- BSA-AC-1166 [Event] When an nl2sql answer references a single ecosystem, the system shall attach that ecosystem's import_meta.imported_at date when known and None when the ecosystem was never imported (2 of 2 cases: 1 known date 2024-11-19, 1 explicit None).
- BSA-AC-1167 [Event] When an nl2sql answer references multiple ecosystems, the system shall attach the import_meta.imported_at date for each of the 2 of 2 referenced ecosystems (PyPI 2024-11-19, npm 2024-11-16).
- BSA-AC-1168 [Unwanted] While an nl2sql result exposes no ecosystem column, the system shall state the freshness as {'unknown': None} explicitly (1 of 1 case) rather than omitting the as_of field, which is present in every success/empty/partial return.
- BSA-AC-1169 [State] While determining which ecosystem(s) a result row set references, the system shall return the distinct ecosystem values when an ecosystem column is present (including an empty list for 0 matching rows) and None only when the column is absent (3 of 3 column-detection cases correct).

### 평가 정직성: 게이트 보정 · 인젝션 말뭉치 · 영어 검색 (calibrate.py, evals.py, evalguard.py, rag.py)
- BSA-AC-1170 [Event] When calibrate.reliability_table buckets the top-hit BM25 score of all 61 pinned golden+dev+test questions into 5 quantile buckets, the system shall report per-bucket accuracy and OOD false-accept rate (5 of 5 buckets measured: false-accept rates 0.917/0.25/0.0/0.0/0.0 across buckets 0-4, 0 regressions on the 3 pinned sets' fingerprints).
- BSA-AC-1171 [Event] When calibrate.check_threshold evaluates the committed min_bm25=12.0 (read live from rag.Index.search's own default), the system shall report both the coarse 5-bucket verdict and an exact per-item re-check (bucket [8.28,14.77] false-accept 0.25 => unsafe by the coarse method; exact per-item false-accept 0 of 14 OOD = 0.0 => safe, disagreement surfaced in the report, 0 regressions).
- BSA-AC-1172 [Event] When the injection-guard eval runs over evals/injection_samples.jsonl it shall report attack recall, benign precision and the benign false-positive rate without hiding misses; measured after the general-pattern guard rewrite (AC-1210..1213) at recall 1.0, precision 0.962 and false-positive rate 0.04 - up from the pre-fix 0.48 / 0.80 / 0.12, Korean-language recall 0.0 -> 1.0 - with the dev corpus itself unchanged (25 of 25 attacks, 25 of 25 benign, 1 of 25 remaining benign false positive).
- BSA-AC-1173 [Ubiquitous] evals.rag_en_eval shall report recall@5, MRR and OOD rejection separately from the confidence-gate found_rate over evals/rag_en.json (16 English questions, 5 OOD) without being a loop-gated RAG_SETS member (recall@5 1.000, MRR 0.906, OOD rejection 1.000, found_rate 0.812, 0 of 16 recall misses, measured after the BSA-AC-1175..1179 English bridge and gate-floor fix; was recall@5 0.875, MRR 0.705, found_rate 0.500, 2 misses before it).
- BSA-AC-1174 [Event] When evals.injection_samples parses evals/injection_samples.jsonl and one line contains an invalid-UTF-8 byte, the system shall not raise (open() uses errors="replace") and shall preserve every other record in the file, degrading the damaged line alone (recovered with a replacement character, or skipped if the corruption breaks JSON syntax) per its own "a damaged line is skipped, never fatal" contract; injection_guard_eval, which calls it directly, likewise does not crash on the same input (0 regressions on BSA-AC-1170..1173).
- BSA-AC-1175 [Ubiquitous] The retrieval tokenizer shall expand an English-only query (no Hangul character) with the Korean technical-term vocabulary the notes use (the reverse of SYNONYMS plus a hand-written EN_KR_BRIDGE derived from knowledge/*.md) and light English inflection folding, leaving any query containing a Hangul character completely unexpanded (recall@5 0.875 -> 1.000 and MRR 0.705 -> 0.906 on evals/rag_en.json; 3 of 3 pinned Korean sets' recall/MRR/OOD unchanged).
- BSA-AC-1176 [Ubiquitous] evals/rag_en_holdout.json shall hold a fresh, never-tuned-on English probe (16 in-domain questions across licences/vulnerabilities/SBOM-VEX/patching/architecture/AI-loop/SDD topics plus 6 out-of-domain questions, no wording shared with evals/rag_en.json) and shall measure recall@5 1.000, found_rate 0.875 and OOD rejection 1.000 (16 of 16 in-domain, 6 of 6 OOD questions, 0 misses).
- BSA-AC-1177 [Event] When an English-only query's caller leaves min_bm25 at its literal committed default (12.0) the confidence gate shall instead compare the top hit against a separately-measured EN_MIN_BM25 floor (10.0), while any caller-supplied min_bm25 other than that literal default shall still be honoured exactly, in any language (1 of 1 English in-domain question recovered at a measured top-hit BM25 of 11.28, strictly between the two thresholds; 0 of 11 measured English OOD probes - rag_en.json, rag_en_holdout.json and the three pinned sets' own English-only OOD items - accepted at the new floor, worst observed 9.70).
- BSA-AC-1178 [Ubiquitous] The three pinned Korean retrieval sets (rag_golden, rag_dev, rag_test), chat_eval, evals.rag_eval (golden, 20 queries) and calibrate.py's gate calibration (committed_min_bm25, reliability_table, check_threshold) shall report numbers identical to before the English retrieval fix (golden recall/MRR/found/OOD 1.000/0.950/0.850/1.000, dev 1.000/0.836/0.933/1.000, test 0.917/0.750/0.917/1.000; chat_eval found/tool_routing/citation 1.000/1.000/1.000; calibrate bucket [8.28, 14.77] at 0.25 false-accept, exact 0.0, committed_min_bm25 12.0).
- BSA-AC-1179 [Ubiquitous] rag._en_stem_variants and the EN_KR_BRIDGE/reverse-SYNONYMS lookup shall only ever add extra QUERY tokens for a Hangul-free query and shall never alter corpus-side tokenize() output (what Index.add indexes) or a mixed Korean+English query's expansion (2 of 2 stem-variant examples verified - hotspots->hotspot, dependencies->dependency -, 1 of 1 corpus-tokenize check showing no Korean bridge terms leak into indexed chunk tokens, 1 of 1 mixed-language query left unexpanded).

### 감사 표본 · 6게이트 거버넌스 · 프롬프트 재고정 근거 (audit.py, govgate.py, licenses.py, triage.py, promptreg.py)
- BSA-AC-1180 [Ubiquitous] The system shall compute sample_size(n, margin, confidence) as the finite-population-corrected Cochran sample size, capped at n and 0 for n<=0 (3 of 3 cases verified: n=100 margin=0.1 confidence=0.9 -> 41, n=0 -> 0, n=5 -> capped at 5).
- BSA-AC-1181 [Event] When licenses.audit_sample samples resolved components across 2+ distinct license_source values, the system shall deterministically draw at least 10% (minimum 1) of each source's resolved components into a review queue, with a source of 0 resolved components drawing 0 (3 of 3 cases verified: 2 of 20 drawn per source, identical queue for the same seed, 0 resolved -> empty queue).
- BSA-AC-1182 [Event] When triage.stratified_audit samples closed (not_affected/accepted) decisions across severity lanes, the system shall draw exactly ceil(sample_size(lane_size, margin, confidence)) decisions per lane, with a lane of 0 closed decisions drawing 0 (3 of 3 cases verified: CRITICAL 9 of 10, MEDIUM 9 of 10, HIGH/LOW lanes 0 of 0 since undecided).
- BSA-AC-1183 [State] While govgate.evaluate runs against any repository root, the system shall report exactly 6 named gates (Spec, AI-Review, Security, Compliance, Observability, Agent Access) in that fixed order (2 of 2 roots verified: an empty root and this repository).
- BSA-AC-1184 [Unwanted] If 1 or more of the 6 governance gates fails, govgate.main shall exit 1, and shall exit 0 only when all 6 gates pass (2 of 2 cases verified: 5 of 6 gates failing on an empty root exits 1, 6 of 6 gates passing on this repository exits 0).
- BSA-AC-1185 [Event] When promptreg.update is called with require_loop_evidence=True, the system shall refuse the re-pin unless a supplied loop_fingerprint or the latest evidence/loop/history.json pass's recorded prompts digest equals the current prompt digest (3 of 3 cases verified: fresh accepted, missing refused, mismatched refused).
- BSA-AC-1186 [Ubiquitous] The system shall leave promptreg.update's existing behaviour unchanged when require_loop_evidence is left at its default False (2 of 2 pre-existing-shaped callers verified: an initial re-pin with no evidence/loop directory, and a version-bumped re-pin).
- BSA-AC-1187 [Event] When a triage decision's free-text note contains a PII- or secret-shaped substring (an email address, a phone number, an API-key-shaped token) the decision shall mask each one with pii_guard.redact before it reaches the stored decision or a VEX impact/action statement built from it (3 of 3 masked kinds, 0 of 0 raw substrings surviving in the decision or the statement).
- BSA-AC-1188 [Unwanted] If a triage decision's note contains only a CVE id and a version then the note shall pass through byte-for-byte unchanged and the decision's advisory key shall stay untouched, since neither shape matches any redaction pattern (1 of 1 untouched note, 1 of 1 untouched key).
- BSA-AC-1189 [Event] When evaluate() and apply_to_statement() run end to end on a decision whose note mixes an SPDX license id and a CVE id with an email address, the email shall be masked while the SPDX id and the CVE id stay verbatim in both the stored finding and the exported VEX action statement (1 of 1 masked kind, 2 of 2 untouched ids).

### 재배포 준비: 프로브 · 거버넌스 태그/예산 · 라이브 스모크 (deploy/azure, scripts/)
- BSA-AC-1190 [Ubiquitous] deploy/azure/containerapp.yaml shall declare exactly 3 probes of distinct type (Startup on /readyz, Liveness on /healthz, Readiness on /readyz) with every probe's port equal to ingress.targetPort, and the static checker shall detect a probe removed or a port mismatch (3 of 3 probes correct, 2 of 2 induced-drift cases caught, 0 regressions).
- BSA-AC-1191 [Ubiquitous] The template shall wire BTS_SBOM_ACCESS_TOKEN from a secrets secretRef (never a literal value), and its backing secret shall hold only a bracketed placeholder, never a token-shaped string (1 of 1 env var via secretRef, 1 of 1 placeholder verified non-token-shaped, 0 literal secrets found).
- BSA-AC-1192 [Ubiquitous] The template shall carry a top-level tags: block with the 3 required governance keys team/week/owner non-empty, and scripts/azure_budget.py --dry-run shall print an `az consumption budget create` line using only flags verified against the installed az CLI's own --help (whitelisted in AZ_CONSUMPTION_BUDGET_CREATE_FLAGS), with the 3 notification thresholds 50/80/100 percent and the 3 tag keys surfaced as separate non-executable follow-up guidance rather than as unsupported flags on that line, while holding 0 subprocess/os.system call sites that could run az (3 of 3 tags present, 3 of 3 thresholds printed as non-executable guidance, 7 of 7 executable-line flags within the verified whitelist, 0 unverified flags found on the executable line, 1 of 1 run refused without --dry-run).
- BSA-AC-1193 [Event] When scripts/smoke_deployed.py runs against a local in-process server it shall report healthz 200 within its 2000ms budget, readyz 200, and the first SSE byte of an escalation-triggered chat turn timed honestly against its own configurable budget, and shall report failure rather than a silent pass against an unreachable URL and a deliberately slow stub (4 of 4 checks correctly passing on a healthy server, 2 of 2 induced-failure cases correctly failed, 0 regressions).
- BSA-AC-1194 [Event] When the deployed instance's access gate is configured the smoke script's auth_gate check shall report 401 without a credential and 200 once the correct token is supplied, shall name (never silently pass) a missing or wrong token, and shall report an open gate as a pass without ever echoing the token in its output (4 of 4 auth scenarios correctly classified, 0 token leaks).

### 배치 부분 상태와 실패분만 재시도 (batch.py)
- BSA-AC-1195 [Ubiquitous] The system shall derive a stable 8-hex-character id for every batch source from the sha256 of its src (and ref, if given), identical across repeated and separate calls (5 of 5 id-stability checks passed: repeatable, 8 hex chars, distinct sources differ, string/dict forms normalize alike, a ref changes the id).
- BSA-AC-1196 [Event] When a batch run finishes with a mix of successes and errors, the system shall set summary['status'] to partial_success and list every failed source under failed_sources (2 of 2 failed sources captured, 3 of 3 successes preserved; all-success and all-failure runs correctly reported as success/failure, 0 misclassifications).
- BSA-AC-1197 [Event] When retry_failed is given a prior run with K failed sources out of M, the system shall re-analyse exactly those K sources and leave the other M-K successes untouched (2 of 2 failed sources re-analysed, 0 of 3 successes re-run).
- BSA-AC-1198 [State] While merging a retry's fresh records into a prior run's records by id, the system shall produce 0 duplicate ids and recompute the aggregate from the merged set (5 of 5 merged ids unique, components recomputed to 25 from 3 rehydrated + 2 fresh records, status flips from partial_success to success).
- BSA-AC-1199 [Unwanted] If a failed source's id from the prior run has no matching entry in the sources given to retry_failed, the system shall keep it recorded as failed under missing_ids instead of dropping it (1 of 1 missing id reported, 0 of 3 records silently dropped, status remains partial_success).

### CLI 연결: 보정 · 재시도 · govgate · secretscan · audit · 프롬프트 재고정 플래그 · evalsets 게이트
- BSA-AC-1200 [Ubiquitous] The container build context shall be an allowlist that re-includes exactly the 7 paths the Dockerfile copies plus the Dockerfile itself and keeps the evidence, attic, downloads, tooling, git, test, docs, environment and local database paths out (7 of 7 copied paths included, 9 of 9 sensitive or irrelevant paths excluded).
- BSA-AC-1201 [Event] When evalrag is run with --calibrate the command shall print the bucket check and the exact per-item check of the committed min_bm25 side by side, write the reliability table, and exit 1 when the exact check fails (2 of 2 verdicts printed, 5 of 5 buckets written, 1 of 1 failing check exiting 1).
- BSA-AC-1202 [Event] When batch is run with --retry-failed the command shall call retry_failed with the prior run directory and otherwise run every source (1 of 1 retry-only call, 1 of 1 plain run covering 2 of 2 sources).
- BSA-AC-1203 [Event] When govgate is run the command shall print the six-gate table and exit 1 exactly when a gate fails (1 of 1 passing table exiting 0, 1 of 1 failing table exiting 1 and valid as JSON).
- BSA-AC-1204 [Unwanted] If secretscan finds a secret-shaped value or skipped any binary or oversized file then the command shall exit 1, print file, line and rule only and never the value or a prefix of it, and exit 2 for a missing folder (1 of 1 finding reported without its value, 1 of 1 partial scan exiting 1, 1 of 1 clean scan exiting 0, 1 of 1 missing folder exiting 2).
- BSA-AC-1205 [Event] When audit is run the command shall sample licence resolutions by resolution source and closed triage decisions by severity lane deterministically, with the same seed giving an identical queue, and shall exit 2 for an unknown project (2 of 2 sources sampled 1 each of 10, 2 of 2 lanes sampled of 20 closed decisions, 1 of 1 repeated seed identical).
- BSA-AC-1206 [Event] When prompts --update is run with --require-loop-evidence and no loop pass exists the command shall refuse with exit 2 while the default re-pin still works, and evalsets shall exit 1 when the injection holdout recall is below 0.90 or its false-positive rate above 0.05 and shall report the English retrieval probe (1 of 1 refusal, 1 of 1 default re-pin, 1 of 1 failing holdout exiting 1, 1 of 1 passing holdout exiting 0, 12 or more English in-domain queries reported).

### 인젝션 방어 한국어 일반화 (holdout 방식, conversation.py)
- BSA-AC-1210 [Ubiquitous] The injection guard shall be measured against a fresh held-out labelled corpus (evals/injection_holdout.jsonl, disjoint from the tuned dev corpus) covering English, Korean and mixed-language samples and the required attack categories - override, role/system-prompt impersonation, data exfiltration, command execution, hidden/quoted instructions, polite Korean forms - with benign samples that merely contain the trigger words harmlessly (46 of 46 samples, 22 of 22 attacks, 24 of 24 benign, 3 of 3 languages covered).
- BSA-AC-1211 [Event] When the injection guard is measured against the held-out corpus it shall reach attack recall of at least 0.90 and a benign false-positive rate of at most 0.05, and the pre-existing dev corpus's recall shall be reported alongside, never hidden (measured: holdout recall 1.0, holdout false-positive rate 0.0; dev recall 0.48 -> 1.0, dev false-positive rate 0.12 -> 0.04).
- BSA-AC-1212 [Ubiquitous] The injection guard shall detect override, role-reassignment, disclosure-request and command-execution phrasing by general verb-plus-object shape and common Korean conjugations/polite endings rather than literal sentences, and shall normalise zero-width characters and letter-spaced obfuscation before matching (3 of 3 unseen Korean conjugations caught, 2 of 2 obfuscation forms caught, 0 of 1 false trigger from the normalisation pass on ordinary abbreviations).
- BSA-AC-1213 [Unwanted] If the injection guard scans a 200,000-character benign string then it shall complete in under 1 second, and every English pattern the pre-fix guard already caught shall still be caught after the general-pattern rewrite (1 of 1 timing bound met at ~0.1s, 2 of 2 original patterns still caught).

### 챗 화면: 인계 · 되묻기 · 부분 커버리지 · 부분 턴 · 검토 메모 · 버전 스탬프 (web/bts_ui.js, bts_chat_panel.js)
- BSA-AC-1220 [Event] When a chat answer carries an escalation payload, a clarifying question or a reviewer note, both chat renderers shall show each as one text-marked note ([handoff], [which project?], [reviewer note]) naming the trigger, destination and id, the candidate projects or the note (3 of 3 markers shown once each, 3 of 3 notes produced by the shared helper the stream panel reuses).
- BSA-AC-1221 [Unwanted] If the coverage of an answer is partial or a tool call of its turn failed, then the renderer shall show a [partial coverage] note listing the gap codes and stating that an absent result is not verified clean plus a [partial turn] note listing the failed tools, and a complete turn shall add no note (2 of 2 notes shown, 0 of 1 notes on a complete turn, 2 of 2 empty inputs returning an empty string).
- BSA-AC-1222 [Ubiquitous] The renderer shall show the 4-field version stamp (app, model, prompts, spec) as one line and shall escape every dynamic value of the handoff, the reviewer note and the stamp (1 of 1 stamp line, 5 of 5 hostile strings escaped, 0 of 1 stamps for an empty versions object).
- BSA-AC-1223 [Ubiquitous] The answer region of both the chat API renderer and the stream renderer shall be a polite live region and the stream panel shall render the extras through the shared helper (2 of 2 renderers with aria-live polite, 1 of 1 shared-helper call).

### Azure 재배포 렌더링 (scripts/azure_render_app.py)
- BSA-AC-1224 [Ubiquitous] The deployment renderer shall fill the Container Apps template from the environment into a pure-ASCII file with no placeholder left, print none of the 3 secrets, keep each secret exactly once in the secrets block with the 2 secret-bearing environment variables read through a secretRef, and keep the 3 probes and the allowed-roots and OSV database settings (3 of 3 secrets once, 0 of 3 printed, 2 of 2 secretRefs, 3 of 3 probes, 0 placeholders, 0 non-ASCII bytes).
- BSA-AC-1225 [Unwanted] If a required secret is missing from the environment then the renderer shall stop with the variable named and write no file, and the replica floor, ISO week and owner tag shall be parameters (1 of 1 missing-secret run exiting non-zero with 0 files, 3 of 3 parameters honoured).

### 네트워크 파일 공유 위의 SQLite (server.py seed_local_osv_db)
- BSA-AC-1226 [Event] When BTS_SBOM_OSV_SEED_DB and BTS_SBOM_OSV_DB_PATH name different files and the local file is absent the service shall copy the OSV snapshot to the local path atomically at start-up and shall never overwrite a local file that already exists (1 of 1 atomic copy without a partial file left, 0 of 1 local caches overwritten).
- BSA-AC-1227 [Unwanted] If either setting is missing, both name the same file, the seed does not exist or the copy fails then the start-up step shall do nothing or report the failure and continue without raising (4 of 4 no-op shapes, 1 of 1 failed copy reported and non-fatal).

### 적대적 점검(레드팀)이 재현한 결함의 수선 (server.py, workspace.py, net.py, netaddr.py, promptreg.py)
- BSA-AC-1230 [Unwanted] If a client opens a connection and stalls while sending the request then the service shall drop it at the read timeout instead of holding a thread, and the Server header of every response, including a 401, shall name no interpreter or library version (1 of 1 stalled connection closed within 6 seconds, 2 of 2 responses with the neutral Server header).
- BSA-AC-1231 [Unwanted] If more connections arrive than the connection cap allows then the excess connection shall be answered 503 with Retry-After at once without a new thread, and the slots shall be reused after the held connections close (1 of 1 excess connection refused at a cap of 2, 1 of 1 recovery to 200).
- BSA-AC-1232 [Unwanted] If a request body is JSON nested 200000 levels deep then the service shall answer it like any malformed body with 400 and keep serving (1 of 1 deep body answered 400 without a traceback, 1 of 1 follow-up request served).
- BSA-AC-1233 [Unwanted] If a caller forges an X-Forwarded-For header then the service shall ignore it unless the operator declared a trusted proxy and the TCP peer is private or loopback (2 of 2 spoofs ignored by default, 1 of 1 trusted case honoured, 1 of 1 public peer never trusted, 1 of 1 explicit off).
- BSA-AC-1234 [Unwanted] If one caller presents a wrong access credential more often than the limit within the window then the service shall answer that caller 429 with Retry-After without checking the token, shall leave other callers and the probes unaffected, and shall bound the table of failures (3 of 3 failures answered 401, 1 of 1 guess refused unchecked, 1 of 1 locked-out valid token waiting, 1 of 1 other caller served, 1 of 1 bounded table).
- BSA-AC-1235 [Ubiquitous] The prompt digest shall be computed once per package signature (file names, modification times and sizes) and shall change when a module changes, so that a chat turn no longer re-parses the package (3 calls with 1 parse, 1 of 1 edit invalidating the cache, 1 of 1 missing package without a signature).
- BSA-AC-1236 [Unwanted] If a git URL or a fetch URL spells a loopback, metadata or private address in a legacy IPv4 form (decimal, hex, octal, short, trailing-dot localhost, mixed-case localhost, IPv4-mapped IPv6) then both guards shall refuse it, while the same spellings of a public address pass (10 of 10 spellings refused in each of 2 guards, 3 of 3 public spellings accepted).
- BSA-AC-1237 [Unwanted] If a file:// source names a host in its authority then the classifier shall refuse it so that the checked path is the executed one, while an empty or localhost authority is accepted (3 of 3 authorities refused, 2 of 2 local forms accepted).
- BSA-AC-1238 [Event] When a git host name is resolved for a clone the service shall pin the checked public address into the https clone through http.curloptResolve, shall refuse a name with any internal answer, and shall pin nothing for ssh or an IP literal (1 of 1 pinned command before the clone verb, 1 of 1 mixed-answer name refused, 2 of 2 unpinnable forms without a pin).
- BSA-AC-1239 [Ubiquitous] The deployment template shall declare BTS_SBOM_TRUST_FORWARDED=1 for the Container Apps ingress next to the allowed-roots setting (2 of 2 settings declared).
- BSA-AC-1240 [Event] When the Container Apps ingress connects from the shared address space 100.64.0.0/10 and the operator declared the trusted proxy, the service shall identify the caller by the forwarded client address, and the optional caller diagnosis header shall be sent only when switched on and only to a request that presented the token (2 of 2 ingress instances mapped to 1 caller, 2 of 2 further proxy peer forms honoured, 1 of 1 default-off response without it, 1 of 1 authenticated response with it, 0 of 2 unauthenticated or probe responses with it).

### 바이너리 구조 REA 레인 (morluto/rea 메커니즘 수용, AC-621~624)

github.com/morluto/rea의 핵심 메커니즘 — 결과는 증거와 한계를 함께 반환하고, capability를 정직하게
티어로 나눈다(엔진 프리 구조 분석 vs 엔진 백드 디컴파일) — 를 stdlib 전용 규칙 안에서 수용한다
(binary_rea.py). 엔진 프리 구조 티어만 구현: PE 임포트 테이블(DLL+함수 — 바이너리의 API 호환성
표면), ELF PT_DYNAMIC DT_NEEDED(DT_STRTAB 가상주소를 PT_LOAD 매핑으로 파일 오프셋 변환 후 이름
복원), ASAR(Electron 앱: JSON 인덱스 → package.json 이름·버전·의존성 → SBOM 컴포넌트 + JS 모듈
인벤토리), JAR(MANIFEST.MF 주요 속성 + 클래스 인벤토리). 파서는 매직으로 디스패치되고 모든 결과는
{tier: structural, evidence, error, limitations} 증거 기록 — 못 파싱한 형식은 추측하지 않고 기록한다.
binscan에 통합: 바이너리마다 구조 증거가 붙고 components_from이 외부 의존성을 SBOM 컴포넌트 행으로
집계(native-dll/shared-lib/npm-dependency/electron-app/java-jar), to_csv·to_md에 구조 컴포넌트
섹션이 나타나며 honesty에 티어 문구가 추가된다. 실행은 한 번도 하지 않는다(정적 REA).

- BSA-AC-621 [Event] When the structural tier parses a PE it shall walk DOS->PE->optional-header data directory 1->section table->import descriptors to return imported DLLs with their functions, and when it parses an ELF it shall resolve DT_STRTAB's virtual address through the PT_LOAD segments and return the DT_NEEDED shared-library names (2 of 2 formats, 2 of 2 address-conversion rules).
- BSA-AC-622 [Event] When the structural tier reads an ASAR archive it shall parse the header pickle JSON index, recover package.json (name, version, dependencies) and the JS module inventory, flag electron presence, and when it reads a JAR it shall return MANIFEST.MF main attributes and the class inventory count - both feeding components_from (2 of 2 formats, 4 of 4 evidence fields).
- BSA-AC-623 [Event] When inspect dispatches by magic it shall run the matching parser and return {kind, tier: structural, evidence, error, limitations}; an unparsed format is recorded as unknown with an explicit error and no invented evidence, and every record carries the limitations (1 of 1 dispatch, 1 of 1 honesty rule).
- BSA-AC-624 [Event] When binscan runs over a tree each binary shall carry its structural evidence (format, imports/needed/manifest) with the tier label, components_from shall aggregate the external dependencies into SBOM-ready component rows deduplicated by name+kind (native-dll, shared-lib, npm-dependency, electron-app, java-jar), and to_csv and to_md shall present the structural components section with the tier honesty note (1 of 1 per-binary rule, 5 of 5 component kinds).

### EU CRA compliance lane (Regulation (EU) 2024/2847, K-OSSC 실무 가이드 v1.0; ac-645-650 era, registered at ac-1241)

- BSA-AC-1241 [Event] When a project is viewed the CRA readiness scorecard shall score the automatable subset of the guide's annex-I checklist - machine-readable SBOM via the EU-CRA and BSI TR-03183-2 conformance regimes, security.txt deployment, the declared support period, the maintained EOL ledger, the OpenVEX disclosure, the Article 14 reporting process, the per-release SBOM refresh history and the recorded triage decisions - where every check carries its CRA article or guide section, a check whose data the scan does not produce is a gap with its fix and never a pass, and declaring support, recording an awareness entry or flagging the EOL ledger flips exactly those checks (8 of 8 checks, 3 of 3 gap-to-pass flips, 1 of 1 score increase).
- BSA-AC-1242 [Event] When security.txt is requested the service shall render the RFC 9116 file from the operator-configured contact (Contact plus Expires 90 days ahead and Preferred-Languages, with Policy and CSAF only when URLs are declared), refuse to invent a contact when none is configured, and answer the honest 404 with the fix in that case (2 of 2 mandatory fields always present, 2 of 2 optional fields conditional, 1 of 1 refusal, 1 of 1 honest 404).
- BSA-AC-1243 [Event] When a support period is declared the validator shall accept the year-month form of Annex II 7, refuse any other format with 400, and measure the shortfall in months against the 5-year floor of Article 13(8) - a declaration below the minimum is recorded and flagged, not rejected (1 of 1 passing form, 1 of 1 recorded below-minimum shortfall, 1 of 1 invalid format refusal, 1 of 1 clearing).
- BSA-AC-1244 [Event] When an awareness moment is recorded the Article 14 clock shall compute the 24-hour early warning and 72-hour notification deadlines from T0 and the final report from the mitigation moment plus 14 days for an actively exploited vulnerability or from the notification plus one month for an incident, flag deadlines overdue against the reading time, re-record the same id and kind as a replacement rather than a duplicate, and refuse unknown kinds (2 of 2 kinds, 2 of 2 final-report bases, 1 of 1 overdue flag, 1 of 1 replacement, 1 of 1 refusal).
- BSA-AC-1245 [Event] When the SBOM ledgers of guide annex J are built the service shall generate all five from the records - the product registry with format, tool, timestamp, generation context and retention, the vulnerability tracking ledger with the exploitation column marked not-assessed because KEV and EUVD are not wired, the EOL ledger listing every component with the upstream dates left to the team and the 4-band priority rule named, the update history with one row per recorded analysis run, and the submissions ledger honestly empty until a reasoned request arrives (5 of 5 ledgers, 1 of 1 not-assessed marker, 1 of 1 empty-ledger note).
- BSA-AC-1246 [Event] When the CRA screen is served the routes shall expose /.well-known/security.txt, the readiness view, the five ledger CSV downloads with attachment names, the awareness GET and POST, the support declaration POST and the EOL-maintained flag POST, with unknown projects answered 404 and unknown ledger numbers 400 (7 of 7 route groups, 1 of 1 attachment naming, 2 of 2 error codes).

### Overnight feature-loop round 1 (backlog C52+C43·C63·C27·C39, 2026-11-28; feature/aiagent)

- BSA-AC-1247 [Event] When the escalation roll-up is computed it shall aggregate the folded append-only event store into totals per status, rate tables per trigger, kind, destination and project, the open queue with its depth and the oldest wait in minutes, and the resolution-time mean and median from the recorded opened/resolved moments, answer an empty log as no_data instead of healthy-looking zeros, and count unparsable timestamps as skipped rather than inventing a duration (2 of 2 statuses in one log, 2 of 2 rate tables keyed, 1 of 1 oldest-wait measurement, 1 of 1 resolution distribution, 1 of 1 no_data, 1 of 1 skipped rule).
- BSA-AC-1248 [Event] When reverse traceability runs it shall collect every registered CLI subcommand and HTTP route literal from the source, normalise each route to its first distinguishing segment, match it against the spec text by literal or segment, name every working surface with zero mention (real repo measured: evalchat, looplog, srcscan of 70 surfaces), reproduce the report on a fabricated fixture with a never-registered command and route, and stay report-only - the gate decides, the report never guesses a fix (2 of 2 surface kinds, 2 of 2 match tiers, 3 of 3 real unmentioned named, 2 of 2 fixture detections, 1 of 1 report-only note).
- BSA-AC-1249 [Event] When any Mermaid source is linted the check shall be structural only - a known diagram header on the first line, per-line quote and paren/bracket balance with crow's-foot cardinality markers excluded, a document-scoped entity-block brace balance, and every arrow edge carrying text on both ends - so all 37 catalog builders' real output lints clean and a seeded break on each axis is named; a label truncation that leaves an unbalanced paren (the decision diagram's dotted-arrow defect this lint caught) is repaired at the escaping discipline (37 of 37 sampled kinds clean, 1 of 1 real producer defect found and fixed at source, 3 of 3 seeded breaks named).
- BSA-AC-1250 [Event] When the repository's Markdown is link-checked the checker shall resolve every relative link target, keep http/mailto/anchor targets out of scope, name each dead link with file, line and target (forward-slash paths), and exit 0 only on a clean tree (docs/ measured 0 dead, 1 of 1 dead-link detection, 1 of 1 fix verification).
- BSA-AC-1251 [Event] When the self-dogfood gate runs the product shall scan its own source tree offline, emit a machine-valid CycloneDX self-SBOM, record the NTIA-2021 verdict and its named gap elements as the drift baseline (the supplier gap that the never-invent rule produces is data, not a gate), parse the declared runtime dependencies from pyproject.toml (measured: empty - the stdlib-only claim), and exit 0 only when the document is valid and non-empty (1 of 1 valid self-SBOM, 1 of 1 baseline verdict recorded, 1 of 1 dependency parse, 2 of 2 exit conditions).
- BSA-AC-1252 [Event] When the nightly drift workflow is checked it shall parse as YAML, carry only schedule plus manual-dispatch triggers - decoupled from push/PR by design with no path filters - and name the offline battery it promises (regression suite, evalrag baseline, dogfood gate, escalation roll-up, markdown links, speclint) (1 of 1 trigger-shape check, 5 of 5 battery steps named).
- BSA-AC-1253 [Event] When claim support is classified the evidence layer shall grade every claim three-way - supported (quote in source), unsupported with the reason (no such source / quote not in source), and contradicted ONLY when the cited document contains the claim's own sentence with a documented antonym-pair polarity mirror-flipped as an exact normalised match - while the binary verify_claims gate stays unchanged, so a mirrored contradiction is named explicitly and mere absence of support never becomes proof of the opposite (3 of 3 states on the mirrored fixture, 1 of 1 unchanged gate, 1 of 1 no-heuristic note).
- BSA-AC-1254 [Event] When a chat turn carries a cancellation callable the tool loop shall check it BETWEEN calls, name every skipped call as an honest cancelled row (a two-tool turn whose callable fires after the first runs the first, cancels the second and reports status cancelled with cancelled=true - the plan still names both tools, the turn says it stopped early), never silently drop a planned call, and leave the no-callable path byte-identical (1 of 1 fired cancellation, 1 of 1 cancelled row shape, 1 of 1 unchanged default path).
- BSA-AC-1255 [Event] When an escalation is built with a trace id the payload shall carry it clipped to 64 characters and validate clean, omit the field entirely when no id was given (never an empty-string pretend id), and the stream's final event shall carry the same id as the turn's X-Correlation-ID response header so one id links the request, the SSE stream and the escalation handoff (1 of 1 stored-and-validated, 1 of 1 omission, 1 of 1 clipping, 1 of 1 header-equals-final-event linkage).
- BSA-AC-1256 [Event] When a chat SSE stream is served a heartbeat thread shall write SSE comment lines on the configured interval (default 15 s, env-tunable, socket writes serialised with the frame writer), a failed write shall set the reader-gone event that drives both the heartbeat stop and the turn cancellation, every scan and reimpl job record shall carry the request's correlation id as its trace field, and the stream response itself shall expose the same X-Correlation-ID header (measured live with a 1-second heartbeat: comment lines flowed, final trace_id equalled the header) (2 of 2 heartbeat behaviours, 1 of 1 gone-event coupling, 2 of 2 job kinds stamped, 1 of 1 stream header).
- BSA-AC-1257 [Event] When an effectful action is attempted the approval ledger shall append one JSONL line per attempt - patch_apply audited at nothing_to_patch, digest_mismatch (with the token-supplied flag) and the final outcome, decision_commit at committed and store_full - each carrying the actor the embedding supplied (the server passes its per-caller id; the default is the honest unattributed) and a timestamp, and a log failure never blocks the action itself (3 of 3 attempt outcomes audited, 1 of 1 actor propagation, 1 of 1 append-only shape).
- BSA-AC-1258 [Event] When an organisation documents remediation deviations in the overrides file named by BTS_SBOM_REMEDIATION_OVERRIDES the policy builder shall disable rules by id, change rule match priorities and action texts, and append new rules whose when-keys are declared inputs and then-keys declared outputs; an unknown rule id, a malformed file or a non-object document shall reject the WHOLE override set with the documented defaults standing and the status naming why - never a half-applied policy (2 of 2 applied-shape checks, 3 of 3 rejection causes, 1 of 1 status disclosure).
- BSA-AC-1259 [Event] When a license lookup is blocked the source call shall report the full fetch outcome's state and reason (e.g. circuit_open) into the caller's meta instead of collapsing 'we never asked' into plain None, and the resolve aggregation shall count lookup_unavailable with per-reason lookup_blocked_reasons while still leaving the component honestly without an invented licence (1 of 1 per-source reason, 1 of 1 reason aggregation, 1 of 1 no-invented-licence).
- BSA-AC-1260 [Event] When resolved escalations are read back as eval candidates the feed shall emit one row per resolved handoff whose resolution note carries at least the minimum substance (id, kind, project, the PII-redacted question and who resolved it), count thinner or missing notes as skipped rather than rows, and stay report-only - importing them into evals/ is a deliberate human step, never an automatic rewrite of the golden set (1 of 1 candidate shape, 1 of 1 thin-note skip, 1 of 1 report-only note).
### A2UI 스타일 UI 카드 (챗 도구 결과의 카탈로그 렌더)

분석 대상: https://github.com/a2ui-project/a2ui (Apache-2.0; 명세 수준 클린룸 채택, 코드 0줄 인용 — docs/A2UI_INTEGRATION.md).
채택한 4원칙: UI는 데이터(실행 코드 금지)·폐쇄 카탈로그+엄격 검증·카탈로그 협상·실행 경계(에이전트가 카드를 만들지 않는다;
클릭 액션 채널은 승인 게이트 우선으로 기각). 산문 라인은 항상 함께 전송되어 카드 폐기가 답을 잃지 않게 한다.

- BSA-AC-645 [Event] When a card payload is validated it shall enforce a closed catalog of 8 kinds with per-kind declared fields (additionalProperties false - one undeclared field drops the whole card and names it), scalar-only values (a dict that stringifies is not a scalar), hex-only approval codes, per-kind caps (4 cards/turn, 8 table rows, 6 list items, 90-char strings, 4000-char Mermaid), and drop any card that fails while the prose lines that always accompany cards carry the answer unchanged (2 of 2 unknown-kind/field drops, 2 of 2 scalar/clip cases, 1 of 1 cap case, 1 of 1 hex-gate case).
- BSA-AC-646 [Event] When a chat tool result is post-processed the system shall build cards ONLY deterministically from the measured record (the model never supplies card content), attach them to the tool result, collect at most 4 per turn into the JSON answer and the SSE final event, serve the catalog for negotiation at GET /api/ui/catalog, and render them natively in the chat dock and the non-stream answer with esc()/textContent only - an unknown kind on the renderer is skipped and the approval button stays exclusively on the awaiting_approval event path (1 of 1 _run attachment, 1 of 1 collection case, 1 of 1 negotiation route, 2 of 2 renderer surfaces).

### 침해사고 대응 레인 — KISA 침해사고 대응 RFP 매핑 (사용자 지시 "계획 수립 후 루프 방식 구현", 2026-11-28, docs/INCIDENT_RESPONSE_PLAN.md)

KISA 제안요청서(27년 침해사고 원인분석 및 대응조치 지원)를 전수 분석해 우리 공급망 보안 서비스에 접목 가능한
기능을 3루프로 구현했다. 루프1(AC-1261): incidents.py의 사고 레코드(접수→초동→증거수집→원인분석→보고서→종결,
전진 전용 상태기계)와 SLA 시계 — 접수 후 1일 내 담당자 미지정(assign_breach), 증거수집 완료 후 7일 내
보고서 단계 미도달(analysis_breach), 종결 아닌 사고 14일 경과(long_stalled) — 를 순수 함수로 산출하고
/api/incidents 목록 응답에 진척 롤업(단계별 건수·위반·미착수)을 함께 돌려준다. 루프2(AC-1262): 초동보고서·
원인분석 결과보고서·피해 대상별 증거수집 체크리스트(web/db/app/mobile-iot/other)·대응방안 모음집 4종 생성기 —
입력 없는 칸은 "미확인"으로, 모음집은 기록된 대응방안만 누적한다(지어내지 않음). 루프3(AC-1263): 사고에
IoC(해시/IP/C2/도메인/패키지)를 등록하고 스캔된 프로젝트 전체의 구성요소·알림과 교차조회(supply-chain 표면) —
패키지 IoC는 정규화 이름 대조+해당 advisory 나열, 해시는 스캔에 체크섬이 있을 때만 대조(없으면 대조 불가로
정직 응답), IP/C2/도메인은 SBOM 표면이 없음을 사실로 응답. 챗 도구 ioc_impact(읽기 전용)와 dock 다음 단계,
레일 🚨 사고 대응 섹션·판이 같은 API를 본다.

- BSA-AC-1261 [Event] When an incident is opened the lane shall create an IR-dated record with a forward-only stage machine (intake/interview/evidence/analysis/report/closed - one step per advance, skips and backwards refused), stamp every stage move, start the 7-day analysis clock when the evidence stage is left with collection_complete, and refuse a missing org/title, an unknown source and an env outside the closed set - while GET /api/incidents returns the summaries plus a roll-up counting stages, assign-SLA breaches (no assignee past 1 day), analysis-SLA breaches (due date passed before the report stage), long stalls (open past 14 days) and unstarted incidents (5 of 5 stage rules, 3 of 3 clocks, 3 of 3 refusals, 1 of 1 roll-up).
- BSA-AC-1262 [Event] When an incident report or checklist is requested the lane shall assemble it deterministically from the recorded fields only - the 초동보고서 (사고개요·주요 확인사항·초기 판단·증거수집 대상·향후 분석계획 with the target-env checklist), the 원인분석 결과보고서 (사고개요·침투경로·공격행위·피해범위·IoC·원인·대응방안·식별기준), the per-target evidence checklist and the 대응방안 모음집 (only incidents with a recorded response) - rendering every unfilled field as 미확인 and accumulating nothing that was never written (2 of 2 reports, 1 of 1 checklists over the closed env set, 1 of 1 playbook, 0 invented fields).
- BSA-AC-1263 [Event] When IoCs are attached to an incident the lane shall validate the type against the closed set (hash/ip/c2/domain/package), hashes against md5/sha1/sha256 hex, dedupe case-insensitively, and the sbom-impact cross-check shall match package IoCs canonically against every scanned project's components listing the component's advisories, answer a hash honestly as not comparable when no component checksum was recorded, and state that ip/c2/domain have no SBOM surface - while the same data is reachable from the chat through the read-only ioc_impact tool with values taken only from the user's question (5 of 5 IoC types, 1 of 1 hash policy, 1 of 1 canonical match with advisories, 2 of 2 honest non-matches, 1 of 1 read-only tool).
