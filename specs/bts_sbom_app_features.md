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


## Secret storage hygiene for the EXAONE key (.gitignore, bts_sbom_app/server.py, bts_sbom_app/llm.py)

- BSA-AC-425 [Ubiquitous] The system shall ship a .gitignore that lists evidence/.llm_config.json and evidence/.jobs/ (2 of 2 entries).
- BSA-AC-426 [Event] When a key is saved from the console on a POSIX host, the saved file shall be readable by its owner only (mode & 0o077 equals 0, 1 of 1 file).
- BSA-AC-427 [Unwanted] If any of 8 GET routes or the chat route is called after a key was set, the system shall return a body that contains the key 0 times.
- BSA-AC-428 [State] While a key is saved, GET /api/llm shall report storage plaintext-file, and after disconnect 0 files under the evidence folder shall contain the key.
- BSA-AC-429 [Unwanted] If a provider error string contains the key, the system shall raise a message and write an evidence record that contain the key 0 times.
- BSA-AC-430 [Event] When EXAONE_API_KEY_FILE names a file holding a key and a trailing newline, the client shall be available with the trimmed key (1 of 1) and write 0 copies to disk.
- BSA-AC-431 [Unwanted] If the key file is missing or unreadable, the client shall be unavailable with 1 recorded reason and 0 exceptions.
- BSA-AC-432 [Ubiquitous] The repository shall track 0 files named .llm_config.json.


## Security methods ported from the release branch (tools/secret_scan.py, .claude/hooks/, tests/)

- BSA-AC-433 [Event] When any of the 3 critical-severity adversarial prompt-injection fixtures in evals/redteam/injection_fixtures.md is fed through Chatbot.ask()/verify_claims(), the system shall return zero verified claims sourced from the injected text (critical attack-success-rate 0%).
- BSA-AC-440 [State] While the secret scanner runs over a tree that holds 1 planted fake AWS-style key, the system shall report 1 finding containing the file and line but 0 characters of the key value.


## Resilience: per-host circuit breaker and honest fetch outcomes (bts_sbom_app/resilience.py, bts_sbom_app/net.py)

- BSA-AC-301 [Event] When 3 consecutive calls to one host fail after their retries, the system shall open that host's circuit (1 of 1 hosts opened).
- BSA-AC-302 [State] While a host's circuit is open, the system shall send 0 requests to it across 5 further calls and report each as access_failure with reason circuit_open.
- BSA-AC-303 [Event] When the 60-second cooldown has elapsed and 4 calls arrive concurrently, the system shall let exactly 1 probe request through (1 probe of 4 calls).
- BSA-AC-304 [Event] When the probe succeeds, the system shall close the circuit and send the next 3 calls (3 of 3).
- BSA-AC-305 [Event] When the probe fails, the system shall reopen the circuit for a fresh cooldown and send 0 requests in the next 5 calls.
- BSA-AC-306 [Event] When 2 hosts are called and only the first fails 3 times, the system shall keep the second host's circuit closed (1 open of 2 hosts).
- BSA-AC-307 [Event] When a call returns HTTP 404, the system shall classify it empty_result and add 0 to the failure count and 0 to the consecutive-failure count.
- BSA-AC-308 [Event] When a text body reaches the byte limit, the system shall classify it partial_result and still return the truncated text (1 of 1).
- BSA-AC-309 [Event] When a 429 reply carries Retry-After 7, the system shall wait 7.0 seconds before the retry, and wait at most 30.0 seconds for Retry-After 90.
- BSA-AC-310 [Unwanted] If a non-retryable status such as 403 is returned, the system shall make 1 attempt and 0 retries.
- BSA-AC-311 [Ubiquitous] The system shall keep http_json and http_text returning the same values as before (data or None) for 6 of 6 representative cases.
- BSA-AC-312 [Event] When BTS_SBOM_BREAKER_THRESHOLD is 0, the system shall open 0 circuits across 10 consecutive failures.
- BSA-AC-313 [Event] When 5 calls were skipped by an open circuit, the system shall report short_circuited equal to 5 in the net statistics.


## Patch regression quadrants and independent review (bts_sbom_app/impact.py, bts_sbom_app/review.py, bts_sbom_app/pipeline.py)

- BSA-AC-316 [Event] When one component is declared in 2 manifests and only 1 manifest is edited, the shared quadrant shall be regression and list 1 unpatched manifest.
- BSA-AC-317 [Event] When the upgraded component clears 2 of its 2 advisories, the direct quadrant shall be ok with 2 cleared and 0 introduced.
- BSA-AC-318 [Event] When the upgrade introduces 1 new advisory on the same package, the direct quadrant shall be regression.
- BSA-AC-319 [Event] When an untouched sibling in an edited manifest gains 1 new advisory, the upstream quadrant shall be regression.
- BSA-AC-320 [Event] When a transitive component of an edited manifest gains 1 new advisory, the downstream quadrant shall be regression.
- BSA-AC-321 [Event] When an upgraded component is still pinned by 1 unedited lockfile, the downstream quadrant shall be unverified and list that 1 lockfile for regeneration.
- BSA-AC-322 [State] While any quadrant is unverified, the verdict shall be incomplete and never clean (1 of 1 unverified cases).
- BSA-AC-323 [Event] When all 4 quadrants are checked and ok, the verdict shall be clean (1 of 1 fully clean case).
- BSA-AC-324 [Event] When fleet records are supplied and 2 other projects use the upgraded component at the old version, the shared quadrant shall report other_projects checked true and count 2.
- BSA-AC-325 [Event] When no fleet records are supplied, the shared quadrant shall report other_projects checked false and count 0 and keep its own status unchanged.
- BSA-AC-326 [Event] When the impact verdict is regression, the review shall return reject with rule R4 (1 of 1).
- BSA-AC-327 [Event] When the impact verdict is incomplete, the review shall return changes_requested with rule R5 (1 of 1).
- BSA-AC-328 [Event] When a lockfile appears among the changed files, the review shall return changes_requested with rule R2 (1 of 1).
- BSA-AC-329 [Event] When a breaking-risk-high upgrade is applied without acknowledgement, the review shall return changes_requested with rule R3 (1 of 1).
- BSA-AC-330 [Event] When every rule passes, the review shall return approve with 0 findings (1 of 1).
- BSA-AC-331 [Ubiquitous] The review function shall take 0 parameters named rec, record or plans (signature check, 1 of 1).
- BSA-AC-332 [Event] When an approved patch is applied through the pipeline, the patch result shall carry impact and review and keep all of its earlier keys (0 keys lost).
- BSA-AC-333 [Unwanted] If computing the impact raises an exception, the patch result shall carry an impact error entry and keep its original status (1 of 1).


## Advisory-source conflicts shown, never hidden (bts_sbom_app/engine.py, bts_sbom_app/chat.py)

- BSA-AC-413 [Event] When 2 records of one advisory group name fixed versions 2.20.0 and 2.31.0, the system shall record 1 conflict with 2 values that each carry a source id and a date, and keep fixed_version 2.31.0.
- BSA-AC-414 [Event] When 3 records of one advisory group agree on the fixed version, the system shall record 0 conflicts and add 0 conflicts keys to the finding.
- BSA-AC-415 [Event] When 1 record carries no fix information and another names 2.20.0, the system shall record 0 conflicts (absence is not disagreement).
- BSA-AC-416 [Event] When 2 records carry CVSS v3 scores 9.8 and 7.5, the system shall record 1 cvss_v3 conflict marked material because the severity bands differ (CRITICAL vs HIGH).
- BSA-AC-417 [State] While a finding carries a conflict, the lookup answer shall state both values and both source ids (4 of 4 present in the answer text).
- BSA-AC-418 [Ubiquitous] The system shall attach a date to a lookup claim only when the advisory carries one (1 of 1 dated claims), and shall fabricate 0 dates.
- BSA-AC-419 [Event] When a conflict line is included in an answer, the claim verifier shall accept it verbatim (accuracy 1.0 over 1 of 1 claims).
- BSA-AC-420 [Unwanted] If conflict detection fails on 1 malformed record, the system shall finish the analysis with 0 conflicts and count 1 advisory_conflict_errors adjustment.
- BSA-AC-421 [Event] When 1 conflict is detected, the system shall report advisory_conflicts equal to 1 in the engine adjustments.
- BSA-AC-422 [Ubiquitous] The system shall leave every retrieval and grounding metric of the evalrag command unchanged (0 differences against the baseline).
- BSA-AC-423 [Event] When the same finding is reported by 2 manifests, the system shall list its conflicts once (1 entry, not 2).
- BSA-AC-424 [Event] When the persisted project record is reloaded, the system shall return the same conflicts entries (1 of 1 round trip).


## Scan-progress SSE events, readiness probes, container hardening and runbook (bts_sbom_app/events.py, bts_sbom_app/server.py, Dockerfile.bts-sbom-app, docs/RUNBOOK.md)

- BSA-AC-336 [Event] When a job runs, the event stream shall start with job_start and end with final with seq strictly increasing over at least 4 events.
- BSA-AC-337 [Event] When a client reconnects with Last-Event-ID 2, the stream shall send only events whose seq is above 2 (0 earlier events resent).
- BSA-AC-338 [Unwanted] If the job id is unknown, the events endpoint shall answer 404 with a JSON error and open 0 streams.
- BSA-AC-339 [Unwanted] If an event lacks a required field, the event bus shall refuse it and publish 0 events (1 problem reported).
- BSA-AC-340 [Event] When the progress callback raises, the analysis shall still finish with its normal result and record 1 progress_callback stage error.
- BSA-AC-341 [Ubiquitous] The pipeline shall return the same record keys with and without a progress callback (0 differences).
- BSA-AC-342 [Event] When an approved patch is requested, the stream shall contain 1 patch_gate event and 0 characters of the approval token.
- BSA-AC-343 [Unwanted] If 5 subscribers attach to one job, the system shall refuse the 5th with status 429 (4 accepted).
- BSA-AC-344 [Event] When no event arrives for one heartbeat interval, the stream shall send at least 1 comment line within 2 intervals.
- BSA-AC-345 [State] While a readiness check fails, GET /readyz shall return 503 listing only the failed check names and 0 filesystem paths.
- BSA-AC-346 [Event] When all 3 readiness checks pass, GET /readyz shall return 200.
- BSA-AC-347 [Ubiquitous] GET /healthz shall return 200 within 1 second even while a readiness check fails.
- BSA-AC-348 [Ubiquitous] The Dockerfile shall run as a numeric non-root USER (1 of 1).
- BSA-AC-349 [Ubiquitous] The Dockerfile shall declare 1 HEALTHCHECK that calls /readyz.
- BSA-AC-350 [Ubiquitous] The Dockerfile base image shall carry a pinned minor tag and not latest (1 of 1).
- BSA-AC-351 [Ubiquitous] The Dockerfile shall set 0 secret-looking ENV or ARG values.
- BSA-AC-352 [Ubiquitous] The Dockerfile EXPOSE port shall equal the server default port (1 of 1).
- BSA-AC-353 [Ubiquitous] docs/RUNBOOK.md shall contain the 4 blocks Delivery State, Deployment, Rollback and Monitoring.
- BSA-AC-354 [Event] When /api/health and /api/jobs/<id> are called, they shall return their earlier response shapes (2 of 2).


## Persistent scan-job records (bts_sbom_app/jobstore.py, bts_sbom_app/server.py)

- BSA-AC-401 [Event] When a scan job finishes, the system shall have written its record to <evidence>/.jobs/<id>.json that a new server state reads back with state done (1 of 1 jobs).
- BSA-AC-402 [State] While a job record is still queued or running when the server starts, the system shall mark it interrupted with reason server_restart (2 of 2 stale records).
- BSA-AC-403 [Unwanted] If a scan request carries an approval token, the system shall write that token into 0 job files.
- BSA-AC-404 [Unwanted] If a scan source contains user credentials, the system shall store the source with 0 credential characters (1 of 1 sources).
- BSA-AC-405 [Unwanted] If a job id is not 10 lowercase hex characters, the system shall answer 404 and open 0 files outside the jobs folder (3 of 3 malformed ids).
- BSA-AC-406 [Event] When 2 scan requests carry the same idempotency key within 24 hours and the first job is not failed, the system shall return the first job id and start 0 new threads.
- BSA-AC-407 [Event] When the earlier job of an idempotency key ended in error or interrupted, the system shall start 1 new job for the same key.
- BSA-AC-408 [Event] When 201 job records exist, the system shall delete the oldest finished records until 200 remain and delete 0 running records.
- BSA-AC-409 [Unwanted] If 1 job file holds corrupt JSON, the system shall skip it, count 1 corrupt record and still serve the other 2 records.
- BSA-AC-410 [Unwanted] If writing a job record fails midway, the system shall leave 0 partial files in the jobs folder.
- BSA-AC-411 [Event] When a job finished before a restart is requested after the restart, the system shall return its state and metrics (1 of 1 jobs) instead of unknown job.
- BSA-AC-412 [Optional] Where the events module is present, the events of an interrupted job shall contain exactly 1 error event of type interrupted.


## Cloud mode switch (bts_sbom_app/cloud.py, bts_sbom_app/server.py)

- BSA-AC-465 [State] While cloud mode is on, POST /api/llm shall answer 403 and write 0 files under the evidence folder.
- BSA-AC-466 [State] While cloud mode is on, chat actions shall stay off although the serve flag is given (1 of 1 refusals) unless BTS_SBOM_CLOUD_ALLOW_ACTIONS is 1.
- BSA-AC-467 [Event] When cloud mode is on and BTS_SBOM_CLOUD_LLM is unset, a scan request that asks for use_llm shall make 0 LLM calls (1 of 1 requests).
- BSA-AC-468 [Event] When GET /api/engine is called in cloud mode, the response shall report cloud enabled and the 4 policy flags and contain 0 secrets.
- BSA-AC-469 [Unwanted] If BTS_SBOM_CLOUD holds an unrecognised value, the system shall treat cloud mode as on (3 of 3 odd values).
- BSA-AC-470 [Ubiquitous] With cloud mode off, the system shall behave as before on 8 of 8 existing routes (0 differences).


## Cloud-mode source policy (bts_sbom_app/workspace.py, bts_sbom_app/server.py, bts_sbom_app/actions.py)

- BSA-AC-453 [State] While cloud mode is on, a local-path source shall be refused and 0 directories shall be read (3 of 3 paths).
- BSA-AC-454 [Unwanted] If a source uses ssh://, git@ or file:// in cloud mode, the system shall refuse it (3 of 3 forms).
- BSA-AC-455 [Unwanted] If the host resolves to 169.254.169.254, 127.0.0.1 or 10.0.0.5, the system shall refuse it and start 0 clones (3 of 3 addresses).
- BSA-AC-456 [Event] When a host is not in the allow list, the system shall refuse it (1 of 1), and when an allowed host resolves to public addresses only it shall accept it (1 of 1).
- BSA-AC-457 [Unwanted] If a URL carries user credentials in cloud mode, the system shall refuse it (1 of 1).
- BSA-AC-458 [Event] When cloud mode is off, the system shall accept the 6 earlier source forms exactly as before (0 differences).
- BSA-AC-459 [Event] When the chat analyze action receives a refused source in cloud mode, it shall refuse it with the same reason (1 of 1).
- BSA-AC-460 [Event] When /api/scan refuses a source, it shall answer 400 with a reason and create 0 jobs.


## Cloud-mode authentication, approver identity and audit log (bts_sbom_app/auth.py, bts_sbom_app/audit.py, bts_sbom_app/server.py)

- BSA-AC-441 [Unwanted] If a cloud-mode request to /api/scan carries no valid credentials, the system shall answer 401 and create 0 jobs.
- BSA-AC-442 [Event] When a request carries the correct bearer token, the system shall accept it (1 of 1), and a wrong token shall get the same 401 body as a missing token (2 of 2 identical bodies).
- BSA-AC-443 [State] While cloud mode is on and no authentication method is configured, every /api route except the probes shall answer 503 auth_not_configured (all listed routes).
- BSA-AC-444 [Event] When identity-header trust is on and the header is present, the system shall record that identity in the audit line (1 of 1).
- BSA-AC-445 [Unwanted] If identity-header trust is off, the system shall ignore the identity header and record 0 identities from it.
- BSA-AC-446 [Unwanted] If a patch approval or a VEX decision has no known identity in cloud mode, the system shall refuse it and change 0 files (2 of 2 actions).
- BSA-AC-447 [Event] When a patch is approved with a known identity, the patch result shall carry approved_by with that identity (1 of 1).
- BSA-AC-448 [Event] When a scan, an approval, a decision and an LLM connection happen, the system shall append 1 audit line for each (4 of 4) and write 0 token or key characters.
- BSA-AC-449 [Event] When the audit file holds 3 lines, verification shall pass, and after 1 line is altered it shall fail naming the first line whose integrity no longer matches (2 of 2 altered positions).
- BSA-AC-450 [Ubiquitous] The probes /healthz and /readyz shall need no credentials (2 of 2).
- BSA-AC-451 [Ubiquitous] With cloud mode off, the system shall behave as before (0 differences on 8 routes).


## Single-writer evidence lock and standby mode (bts_sbom_app/instance.py, bts_sbom_app/server.py)

- BSA-AC-473 [Event] When the first instance acquires the store, the system shall create 1 lock file holding host, pid and heartbeat.
- BSA-AC-474 [State] While a fresh lock is held by another instance, a second instance shall refuse to start (1 of 1) unless standby is allowed.
- BSA-AC-475 [State] While an instance runs in standby mode, every write request shall be answered 503 standby and write 0 files (3 of 3 write routes).
- BSA-AC-476 [Event] When the holder's heartbeat is older than 60 seconds, a second instance shall take over the lock (1 of 1) and switch from standby to active.
- BSA-AC-477 [Event] When the holder shuts down, the system shall remove its lock file (1 of 1).
- BSA-AC-478 [State] While the lock is lost, GET /readyz shall return 503 naming the evidence_lock check.
- BSA-AC-479 [Ubiquitous] The system shall create scan work copies outside the evidence folder (1 of 1 jobs).
- BSA-AC-480 [Ubiquitous] With a single instance and no lock file present, the system shall behave as before (0 differences on 8 routes).


## Resource limits and graceful shutdown (bts_sbom_app/limits.py, bts_sbom_app/server.py, bts_sbom_app/pipeline.py, bts_sbom_app/workspace.py)

- BSA-AC-483 [State] While 2 jobs run and the limit is 2, POST /api/scan shall answer 429 with a Retry-After header and start 0 new threads.
- BSA-AC-484 [Event] When a running job finishes, the next scan request shall be accepted (1 of 1).
- BSA-AC-485 [Unwanted] If a job runs past its deadline, the system shall stop it with state error and reason timeout and remove its work copy (1 of 1).
- BSA-AC-486 [Unwanted] If a work copy exceeds the size limit, the system shall abort the job and leave 0 bytes of it on disk.
- BSA-AC-487 [State] While the server is shutting down, GET /readyz shall return 503 with draining and POST /api/scan shall return 503 (2 of 2).
- BSA-AC-488 [Event] When the drain period ends with 1 job still running, the system shall record it as interrupted with reason sigterm (1 of 1).
- BSA-AC-489 [Unwanted] If a limit variable holds a non-integer or negative value, the system shall use its default (3 of 3 odd values).
- BSA-AC-490 [Event] When 3 jobs fail in a row, the gate shall hold 0 leaked permits.
- BSA-AC-491 [Ubiquitous] With cloud mode off and BTS_SBOM_MAX_JOBS unset, the system shall refuse 0 of 5 concurrent scan requests.


## Observability: JSON access log, request ids and /metrics (bts_sbom_app/obslog.py, bts_sbom_app/metrics.py, bts_sbom_app/server.py)

- BSA-AC-521 [Event] When any API route is called, the system shall write 1 access log line that parses as JSON and carries request_id, route_class, status and ms.
- BSA-AC-522 [Unwanted] If a request carries a bearer token, a credentialed source URL or an approval token, the system shall write 0 occurrences of those values into the log (3 of 3 planted values).
- BSA-AC-523 [Event] When a request carries an X-Request-Id of 64 safe characters, the response shall echo it, and an id with a newline or 65 characters shall be replaced (2 of 2 cases).
- BSA-AC-524 [Event] When 100 distinct URL paths are requested, the metrics text shall contain at most 12 route_class series.
- BSA-AC-525 [Event] When a job finishes in each of 2 states, the metrics shall count 1 job per state.
- BSA-AC-526 [State] While cloud mode is on, GET /metrics without credentials shall answer 401 and the probes shall answer 200.
- BSA-AC-527 [Ubiquitous] The existing response bodies and status codes shall stay unchanged on 8 of 8 routes (only the X-Request-Id header is added).
- BSA-AC-528 [Ubiquitous] docs/RUNBOOK.md shall contain an SLO table that marks every target as an assumption (4 of 4 targets).


## Infrastructure template (infra/main.bicep, infra/main.parameters.json, azure.yaml)

- BSA-AC-497 [Ubiquitous] The infrastructure template shall declare httpsOnly true, minTlsVersion 1.2, ftpsState Disabled and healthCheckPath /readyz for the web app (4 of 4 settings).
- BSA-AC-498 [Ubiquitous] The infrastructure template shall contain 0 secret-looking literals and 0 admin-enabled registries.
- BSA-AC-499 [Ubiquitous] The parameters file shall hold only ${...} placeholders and 0 real subscription identifiers.
- BSA-AC-500 [Ubiquitous] The template shall require the 3 tags team, week and owner with no default values.
- BSA-AC-501 [Ubiquitous] The template shall set the plan capacity to 1 and declare 0 autoscale rules.
- BSA-AC-502 [Event] When the template is read, it shall declare 1 budget with notifications at 50, 80 and 100 percent (3 of 3 thresholds).
- BSA-AC-503 [Ubiquitous] The template shall declare the managed identity role assignments AcrPull and Key Vault Secrets User (2 of 2).
- BSA-AC-504 [Ubiquitous] ADR-0016 shall name at least 3 rejected hosting alternatives with reasons.
- BSA-AC-505 [State] While the bicep tool is not installed, the infrastructure check shall report NOT RUN and count 0 passes for the build step.


## Deploy pipeline (static) (.github/workflows/deploy_azure.yml)

- BSA-AC-509 [Ubiquitous] The deploy workflow shall declare top-level read-only contents permission and grant id-token write only to the login job (2 of 2 permission rules).
- BSA-AC-510 [Ubiquitous] The deploy workflow shall contain 0 client secrets, 0 inline credentials JSON and 0 literal subscription identifiers.
- BSA-AC-511 [Ubiquitous] The deploy workflow shall run the Trivy step with severity CRITICAL and exit code 1 (1 of 1 step).
- BSA-AC-512 [Ubiquitous] The deploy workflow shall generate and upload the project's own SBOM before deploying (1 of 1 step, ordered before the deploy step).
- BSA-AC-513 [Ubiquitous] The swap step shall run in a job that names a protected environment (1 of 1).
- BSA-AC-514 [Ubiquitous] The workflow shall deploy to the staging slot and check /readyz before the swap (2 of 2 ordered steps).
- BSA-AC-515 [Ubiquitous] The workflow shall use 0 actions referenced by a moving branch name and 0 pull_request_target triggers.
- BSA-AC-516 [Event] When the swap or the post-swap check fails, the rollback job shall swap back (1 of 1 rollback job).
- BSA-AC-517 [State] While the workflow has not been run on GitHub, the report shall mark its execution NOT RUN and count 0 executed runs.


## Cost safety (tools/cost_estimate.py, docs/cost_assumptions.json, docs/COST.md)

- BSA-AC-533 [Ubiquitous] The cost assumptions file shall mark every input as assumed and hold 0 invented prices (all price fields null until filled).
- BSA-AC-534 [Event] When all price inputs are filled with 4 fake numbers, the estimate shall equal the documented formula result (1 of 1 exact match).
- BSA-AC-535 [State] While any price input is null, the estimate shall report the total as incomplete and list that input as unknown (1 of 1 null inputs).
- BSA-AC-536 [Ubiquitous] The estimate output shall state that it is an estimate and not a billed amount (1 of 1 outputs).
- BSA-AC-537 [Ubiquitous] docs/COST.md shall contain the cleanup procedure and the 50, 80 and 100 percent budget thresholds (2 of 2 items).


## LLM routing, outbound preview and the optional Azure OpenAI provider (bts_sbom_app/router.py, bts_sbom_app/llm.py, bts_sbom_app/ai.py, bts_sbom_app/server.py)

- BSA-AC-541 [Ubiquitous] The outbound preview shall contain 0 file contents, 0 absolute paths and 0 credentials for 1 of 1 sample projects.
- BSA-AC-542 [Event] When the preview is requested, the system shall send 0 requests to any LLM provider (0 transport calls).
- BSA-AC-543 [State] While cloud LLM use is not allowed, the router shall return deterministic for 4 of 4 input combinations.
- BSA-AC-544 [Event] When the data class is private, the router shall return deterministic even though a provider is configured (1 of 1).
- BSA-AC-545 [Event] When the daily budget ratio is 0.9 or more, the router shall return deterministic (2 of 2 values 0.9 and 1.0).
- BSA-AC-546 [Event] When the primary provider is throttled and a second provider is configured, the router shall return the second provider (1 of 1), and deterministic when none is configured (1 of 1).
- BSA-AC-547 [Event] When the router returns deterministic, the proposal shall record the reason (1 of 1 reasons).
- BSA-AC-548 [Unwanted] If an Azure OpenAI key is configured, the system shall write it into 0 log lines, 0 error messages and 0 status responses.
- BSA-AC-549 [Event] When the Azure OpenAI provider builds a request, the URL shall contain the deployment name and api-version (1 of 1, fake transport).


## Deterministic input guardrails (bts_sbom_app/guardrail.py, bts_sbom_app/chat.py, bts_sbom_app/server.py)

- BSA-AC-551 [Event] When any of the 3 critical injection fixtures is asked in cloud mode, the system shall block it and call 0 tools (3 of 3 blocked).
- BSA-AC-552 [Unwanted] If a question asks for an approval token, a confirmation code or an API key, the system shall refuse without repeating the request text (3 of 3 phrasings, English and Korean).
- BSA-AC-553 [Event] When 20 benign questions are asked in cloud mode, the system shall block 0 of them.
- BSA-AC-554 [Event] When an advisory text contains an instruction-override phrase, the system shall exclude that line from the model context and keep it in the deterministic view (1 of 1 lines).
- BSA-AC-555 [State] While cloud mode is off, the system shall apply no input filter and answer the 8 evalchat questions as before (0 differences).


## Tool groups behind a flag (bts_sbom_app/chat.py)

- BSA-AC-561 [Ubiquitous] Each tool group shall hold at most 5 tools and the groups shall cover all 21 tools with 0 orphans.
- BSA-AC-562 [Event] When the group flag is on and the question maps to a group, the planner shall be shown only that group's tools (at most 5 of 21).
- BSA-AC-563 [Event] When the group flag is on and no group matches, the planner shall be shown all 21 tools and the fallback counter shall read 1.
- BSA-AC-564 [Ubiquitous] With the group flag on, the evalchat accuracy shall be at least the flag-off accuracy (8 of 8 questions, 0 regressions).
- BSA-AC-565 [State] While the group flag is off, the planner shall be shown all 21 tools exactly as before (21 of 21 tools, 0 differences).


## Documentation lint, ADRs, governance documents and the enforcement map (bts_sbom_app/doclint.py, docs/adr/, docs/governance/, docs/ENFORCEMENT_MAP.md)

- BSA-AC-361 [Event] When an ADR has no item under its rejected alternatives section, doclint shall report 1 problem naming that file.
- BSA-AC-362 [Event] When every ADR in docs/adr carries the 5 required sections and at least 1 rejected alternative, doclint shall report 0 problems for all of them.
- BSA-AC-363 [Event] When an enforcement-map row cites a test that does not exist, doclint shall report 1 dangling reference.
- BSA-AC-364 [Event] When strict mode meets 1 TODO placeholder, doclint shall report 1 problem.
- BSA-AC-365 [State] While a document kind has no file in the repository, doclint shall print it as not present and count it as 0 passes.
- BSA-AC-366 [Ubiquitous] The repository documents shall pass doclint in strict mode with 0 problems.
- BSA-AC-367 [Event] When one required section is removed from a document of each of the 5 kinds impact, modelcard, lineage, datacontract and runbook, doclint shall report 1 problem per document (5 of 5).
- BSA-AC-368 [Ubiquitous] The enforcement map shall list at least 12 rows whose location and test both exist.
- BSA-AC-369 [Ubiquitous] The CI workflow shall contain exactly 1 doclint step.
- BSA-AC-370 [Event] When the impact assessment is linted, it shall carry all 8 required sections and state that it is a self-assessment and not legal advice (1 of 1).
- BSA-AC-371 [Event] When the model card quotes the README evaluation figures, it shall also state that they are in-sample (1 of 1 figures qualified).
- BSA-AC-372 [Event] When the lineage document is linted, every data source host named in the code shall appear in its sources table (0 missing hosts).


## Traceability matrix, portfolio export and the proof contract (bts_sbom_app/traceability.py, bts_sbom_app/portfolio.py, bts_sbom_app/proof.py, bts_sbom_app/cli_ext.py)

- BSA-AC-381 [Event] When the traceability matrix is generated twice from the same inputs, the system shall produce byte-identical output (2 of 2 runs).
- BSA-AC-382 [Event] When a spec holds 1 AC that no test cites, the summary shall report 1 AC without a test.
- BSA-AC-383 [Event] When a test cites 1 AC that the spec does not contain, the summary shall list that 1 reference.
- BSA-AC-384 [Event] When 1 module appears in no section's module list, the summary shall list that 1 module.
- BSA-AC-385 [State] While the spec holds 0 State-pattern ACs, the summary shall carry 1 warning about the missing pattern.
- BSA-AC-386 [Event] When the portfolio is exported, the manifest shall list 8 packages each with a status and a sources list.
- BSA-AC-387 [Event] When a package source file does not exist, the manifest shall mark it missing and fabricate 0 entries.
- BSA-AC-388 [Ubiquitous] The manifest shall mark packages 7 and 8 human_required with a checklist (2 of 2).
- BSA-AC-389 [Ubiquitous] The self-assessment shall contain 0 numeric rubric scores and mark judgement items human_review.
- BSA-AC-390 [State] While the runner cannot execute 1 command, the proof shall classify it NOT RUN and report an overall status of incomplete, never pass.
- BSA-AC-391 [Event] When 0 commands fail, at least 1 passes and 0 are NOT RUN, the proof shall report pass (1 of 1).
- BSA-AC-392 [Event] When the proof runs twice, the summary file shall be overwritten and the runs folder shall hold 2 files.
- BSA-AC-393 [Event] When the proof runs twice within one second, the system shall write 2 distinct run files (0 collisions).
- BSA-AC-394 [Ubiquitous] The command line shall offer the 3 sub-commands trace, portfolio and proof and leave every earlier sub-command unchanged.


## Post-deployment verification contract (.agentic-dev/contract.json, bts_sbom_app/verifydev.py)

- BSA-AC-567 [State] While DEV_BASE_URL is unset, verify-dev shall print NOT RUN and exit with code 2, never 0.
- BSA-AC-568 [Event] When both probes answer 200 and the unauthenticated API route answers 401, verify-dev shall report PASS (1 of 1).
- BSA-AC-569 [Event] When an unauthenticated API route answers 200 on a cloud-mode deployment, verify-dev shall report FAIL for the authentication check (1 of 1).
- BSA-AC-570 [Unwanted] If the URL uses plain http on a non-local host, verify-dev shall refuse it and send 0 requests carrying the token.
- BSA-AC-571 [Ubiquitous] verify-dev shall write 0 token characters to its output and to its sidecar files.
- BSA-AC-572 [Ubiquitous] The contract file shall hold the 5 blocks and 4 command verbs and name only commands whose modules exist (4 of 4 verbs).


## License obligations by component and scenario (bts_sbom_app/obligations.py)

- BSA-AC-601 [Event] When 4 components (MIT, LGPL-3.0-only, GPL-3.0-only, AGPL-3.0-only) are assessed for the binary scenario, the system shall report offer for exactly 3 of them with scopes library_only, combined_work and combined_work_incl_network (3 of 3 scopes).
- BSA-AC-602 [Unwanted] If a component license is unresolved, the system shall report verdict unknown in all 3 scenarios and count it as none in 0 scenarios.
- BSA-AC-603 [State] While at least 1 component is unresolved, the scenario status shall be incomplete or exposed and never clean (3 of 3 scenarios).
- BSA-AC-604 [Event] When the saas scenario meets a network-copyleft component, the system shall report scope combined_work_incl_network (1 of 1), and for a strong-copyleft component in saas it shall report scope none with a why text (1 of 1).
- BSA-AC-605 [Event] When the internal scenario meets a strong-copyleft component, the system shall report scope none and a why text that says redistribution changes the result (1 of 1).
- BSA-AC-606 [Event] When 5 reference license pairs are checked, the system shall return the expected 5 labels and return no_rule for 1 unlisted pair, and never return a label that says compatible (0 occurrences).
- BSA-AC-607 [Ubiquitous] The system shall attach the disclaimer text to 4 of 4 surfaces (assessment JSON, CLI output, API response, report section).
- BSA-AC-608 [Event] When a component has verdict offer, the system shall list exactly 5 mitigation options in the fixed order, each with needs_human true (5 of 5).
- BSA-AC-609 [Unwanted] If the obligations stage raises, the system shall keep the analysis result and record the failure in stage_errors (1 of 1).
- BSA-AC-610 [Event] When GET /api/obligations/<project> is called for an analysed project, the response shall hold 3 scenarios, and an unknown project shall get 404 (2 of 2 cases).
- BSA-AC-611 [Event] When the CLI runs with --distribution saas, it shall print only the saas scenario, exit 0 and make 0 network calls.
- BSA-AC-612 [State] While a stored record has no obligations key, the API shall compute the result on read and set computed_on_read to true (1 of 1 old records).
- BSA-AC-613 [Ubiquitous] The system shall leave the output of licenses.policy_findings unchanged (0 differences on the existing license policy tests).
- BSA-AC-614 [Event] When 0 components are assessed, every scenario status shall be no_data and not clean (3 of 3 scenarios).


## Legacy / EOL component assessment (bts_sbom_app/legacy.py)

- BSA-AC-616 [Event] When a mapped component version falls in a cycle that endoflife data marks as ended before today, the system shall report eol status with source endoflife.date and risk high (1 of 1).
- BSA-AC-617 [Event] When the cycle is still supported, the system shall report supported with the end date and risk low (1 of 1).
- BSA-AC-618 [Unwanted] If a component has no mapping or the lookup fails or the version cannot be parsed, the system shall report eol status unknown and never supported (3 of 3 cases).
- BSA-AC-619 [State] While online is off, the system shall make 0 network calls and shall keep UNVERIFIED in the source of any value taken from the embedded table (2 of 2 checks).
- BSA-AC-620 [Event] When a plan row has status no_fix with at least 1 advisory, the system shall set no_upstream_fix true, and risk shall be high for max severity HIGH and medium for MEDIUM (2 of 2 cases).
- BSA-AC-621 [Unwanted] If a plan row has status upgrade, the system shall set no_upstream_fix false (1 of 1).
- BSA-AC-622 [Ubiquitous] The system shall sort rows by risk and then by name and shall produce identical bytes on 2 runs of the same input.
- BSA-AC-623 [Unwanted] If a PRODUCTS entry lacks product or cycle_rule, the loader shall reject it and load 0 of 2 malformed entries.
- BSA-AC-624 [Event] When the legacy stage raises, the system shall keep the analysis and record the failure in stage_errors (1 of 1).
- BSA-AC-625 [State] While a stored record has no legacy key, the API shall compute it on read with computed_on_read true (1 of 1 old records).
- BSA-AC-626 [Event] When GET /api/legacy/<project> is called, the response shall carry the summary counts, and an unknown project shall get 404 (2 of 2 cases).
- BSA-AC-627 [Ubiquitous] The system shall leave arch.runtime_eol output unchanged (0 differences on the existing architecture tests).
- BSA-AC-628 [Ubiquitous] The system shall attach the disclaimer text to 3 of 3 surfaces (JSON, CLI output, report section).


## Replacement candidates: evidence table + verified AI candidates (bts_sbom_app/alternatives.py)

- BSA-AC-631 [Event] When a flagged component matches a table entry that has a source, the system shall return its options with origin table and the source text (1 of 1).
- BSA-AC-632 [Unwanted] If a table option has no source, the loader shall drop it and load 0 of 2 sourceless options.
- BSA-AC-633 [State] While no LLM client is available, the system shall return table results only and record ai used false with a reason (1 of 1).
- BSA-AC-634 [Event] When an AI candidate resolves to a strong-copyleft license, the system shall drop it with reason license_not_allowed (1 of 1) and keep 0 such candidates in the options.
- BSA-AC-635 [Event] When an AI candidate resolves to a permissive license, the system shall mark it ai_candidate_license_verified (1 of 1).
- BSA-AC-636 [State] While the resolver cannot answer (offline), every kept AI candidate shall be marked ai_candidate_unverified with license unknown (2 of 2 candidates).
- BSA-AC-637 [Unwanted] If a candidate name equals the original, has an invalid format or belongs to another ecosystem, the system shall drop it (3 of 3 cases).
- BSA-AC-638 [Ubiquitous] The system shall mark every option needs_human true and shall apply 0 changes to any manifest (0 files written).
- BSA-AC-639 [Unwanted] If the LLM call raises, the system shall fall back to table results and record the failure (1 of 1).
- BSA-AC-640 [Ubiquitous] The system shall ship alternatives.json with 0 entries and the loader shall ignore alternatives.example.json (2 of 2 checks).
- BSA-AC-641 [Event] When the API is called for a record without an alternatives key, it shall compute table-only results with computed_on_read true and make 0 LLM calls (1 of 1).
- BSA-AC-642 [Ubiquitous] The system shall attach the disclaimer text to 3 of 3 surfaces (JSON, CLI output, API response).


## Migration / upgrade impact plan with waves (bts_sbom_app/migration.py)

- BSA-AC-646 [Event] When a direct component has an upgrade plan with a minor jump and 3 import sites, the system shall place it in wave A (1 of 1).
- BSA-AC-647 [Event] When the plan is a major jump, or the import sites exceed 10, the system shall place it in wave B (2 of 2 cases).
- BSA-AC-648 [Event] When a plan has status no_fix, or the legacy row risk is high, the system shall place it in wave C with options from replace, accept_risk, pin and monitor (2 of 2 cases).
- BSA-AC-649 [State] While the source folder is not available, the system shall report code_sites available false with the note source not provided for 3 of 3 direct components and never report 0 sites (0 occurrences of a zero-site claim).
- BSA-AC-650 [Unwanted] If a direct component has 0 import sites in a given source, the system shall add the note that this does not prove no impact (1 of 1).
- BSA-AC-651 [Event] When the component is a transitive dependency, the system shall report available false with the transitive note (1 of 1).
- BSA-AC-652 [Ubiquitous] The system shall mark every item needs_human true and shall write 0 files into the analysed source (tree hash unchanged, 1 of 1).
- BSA-AC-653 [Ubiquitous] The system shall cap each component at the configured site limit and report bounded true when the cap was hit (1 of 1).
- BSA-AC-654 [Event] When the migration stage raises, the system shall keep the analysis and record the failure in stage_errors (1 of 1).
- BSA-AC-655 [Event] When GET /api/migration/<project> is called for a record without the key, it shall compute on read with source_available false (1 of 1).
- BSA-AC-656 [Event] When the CLI is run with --source on a local folder, the system shall read 0 files outside that folder and make 0 network calls (2 of 2 checks).
- BSA-AC-657 [Ubiquitous] The system shall produce identical bytes on 2 runs of the same input and attach the disclaimer text to 3 of 3 surfaces.


## Code-edit proposals, propose-only (bts_sbom_app/codeprop.py)

- BSA-AC-661 [Event] When the fake model returns a valid edit inside a shown site range, the system shall build a unified diff from the real file content and mark status proposed (1 of 1).
- BSA-AC-662 [Unwanted] If an edit names a file outside the import-site files, the system shall reject that edit and keep 0 such files in the diff (1 of 1).
- BSA-AC-663 [Unwanted] If an edit range lies outside the lines that were shown to the model, the system shall reject it (1 of 1).
- BSA-AC-664 [Unwanted] If a replacement adds an import that is neither in the file nor in the SBOM, the system shall reject it with reason adds_dependency (1 of 1).
- BSA-AC-665 [Unwanted] If a Python edit makes the file fail ast.parse, the system shall reject it and report validation V5 fail (1 of 1).
- BSA-AC-666 [Unwanted] If the edit count, edit lines or diff lines exceed the caps, the system shall reject the excess (3 of 3 caps).
- BSA-AC-667 [State] While no LLM client is available, the system shall return status llm_unavailable with the site list and the checklist and no diff (1 of 1).
- BSA-AC-668 [Unwanted] If the model call raises, the system shall return llm_unavailable and record the failure (1 of 1).
- BSA-AC-669 [Ubiquitous] The system shall execute 0 lines of the analysed repository and shall write 0 files into it while proposing (tree hash unchanged, 1 of 1).
- BSA-AC-670 [Event] When a code snippet contains an instruction aimed at the model, the system shall still apply only the 6 validations and shall not follow the instruction (1 of 1 injected snippets).
- BSA-AC-671 [Unwanted] If apply is called without a token, the system shall change 0 files and report not_approved (1 of 1).
- BSA-AC-672 [Unwanted] If the token does not match the diff digest, the system shall change 0 files and report digest_mismatch (1 of 1).
- BSA-AC-673 [Event] When apply is called with the matching token, the system shall change exactly the proposed files in a new work copy on branch bts-sbom/code-proposal and leave the origin tree hash unchanged (1 of 1).
- BSA-AC-674 [Unwanted] If git apply --check fails, the system shall change 0 files in the work copy and report apply_failed (1 of 1).
- BSA-AC-675 [Ubiquitous] The system shall record tests_run false and the not-built-or-tested note in 2 of 2 results (proposal and apply).
- BSA-AC-676 [Ubiquitous] The system shall expose 0 apply routes on the web API and 0 chat tools that apply a code proposal.
- BSA-AC-677 [State] While the proposal status is rejected or llm_unavailable, the system shall keep digest empty and refuse apply (2 of 2 statuses).
- BSA-AC-678 [Ubiquitous] The system shall attach the disclaimer text to 3 of 3 surfaces (JSON, CLI output, API response).


## Sector policy starter presets (bts_sbom_app/sector_policy.py)

- BSA-AC-686 [Ubiquitous] The system shall ship exactly 5 sector presets and each shall carry the starter-template basis text (5 of 5).
- BSA-AC-687 [Event] When --sector-policy defense is given, the effective policy shall deny strong-copyleft and carry eol_tolerance fail (2 of 2 fields).
- BSA-AC-688 [Unwanted] If an unknown preset name is given, the system shall exit with an error that lists the 5 known names and run 0 analyses (1 of 1).
- BSA-AC-689 [Unwanted] If --policy and --sector-policy are both given, the system shall refuse (1 of 1) and change 0 files.
- BSA-AC-690 [State] While no sector preset is selected, the system shall use the existing default policy and produce 0 differences on the existing license policy tests.
- BSA-AC-691 [Event] When a user presets file defines 1 valid and 1 invalid preset, the system shall load 1 and reject 1 with a reason (2 of 2 checks).
- BSA-AC-692 [Ubiquitous] The system shall print the effective policy and its basis text on 3 of 3 commands (scan, obligations, legacy).


## Chat tools for obligations / legacy / migration / proposals (bts_sbom_app/chat.py, bts_sbom_app/evals_chat.py, evals/obligations_gold.json)

- BSA-AC-696 [Ubiquitous] The system shall register 4 new read-only chat tools and keep WRITE_TOOLS unchanged at 3 tools (0 new write tools).
- BSA-AC-697 [Ubiquitous] The system shall expose 0 chat tools that apply a code proposal.
- BSA-AC-698 [Event] When a user asks about source disclosure duties for a project, the system shall answer from the obligations tool with the disclaimer line and a verified citation (1 of 1 questions, citation accuracy 1.0).
- BSA-AC-699 [Unwanted] If the project has no stored obligations and no components, the system shall answer that no data is available and never answer that the project is clean (1 of 1).
- BSA-AC-700 [State] While no code proposal is stored for a project, the propose_code tool shall answer with the CLI instructions and create 0 proposals (1 of 1).
- BSA-AC-701 [Ubiquitous] The system shall keep the routing of the existing 8 evalchat questions unchanged (8 of 8, 0 differences) after the new keywords are added.
- BSA-AC-702 [Event] When the 4 new evalchat questions are run through the regex router, the system shall report the measured routing count out of 4 and record each miss (4 of 4 questions reported).
- BSA-AC-703 [Ubiquitous] The system shall match 12 of 12 gold license expressions on category and binary scope.
- BSA-AC-704 [Ubiquitous] The system shall leave the evalrag metrics at or above the baseline after the new knowledge document is indexed (3 of 3 metrics, 0 regressions).
- BSA-AC-705 [Ubiquitous] The system shall keep each tool group at 5 or fewer tools with 0 orphans across 25 tools (only when the group feature exists).


## V&V evidence report (bts_sbom_app/vnv.py)

- BSA-AC-721 [Event] When an online project with no unresolved items is reported, the system shall grade it pass with the fixed existence-only scope statement (1 of 1).
- BSA-AC-722 [Unwanted] If the analysis ran offline, the system shall grade the report pass with restrictions and never pass (1 of 1).
- BSA-AC-723 [Unwanted] If any component license is unresolved, the system shall add a restriction and grade pass with restrictions (1 of 1).
- BSA-AC-724 [Unwanted] If the analysis failed, the system shall grade the report fail (1 of 1).
- BSA-AC-725 [Unwanted] If the project holds 0 components, the system shall grade the report pass with restrictions and never pass (1 of 1).
- BSA-AC-726 [Ubiquitous] The scope shall carry the fixed statement that exploitability was not demonstrated and only existence was checked (1 of 1 statement, every report).
- BSA-AC-727 [Event] When user plan and requirement references are given, the traceability shall carry them with the tool name, core version and online flag (4 of 4 fields).
- BSA-AC-728 [Ubiquitous] The report shall produce identical bytes for the same record and shall surface the disclaimer, results and conclusion in the markdown (2 of 2 surfaces).
- BSA-AC-729 [Event] When GET /api/vnv/<project> is called for an analysed project it shall answer with the report schema, and an unknown project shall get 404 (2 of 2 cases).
- BSA-AC-730 [Unwanted] If a pipeline stage raised, the report shall list it under deviations from plan (1 of 1 stage errors).


## Attack inputs, CWE aggregation and the evidence bundle (bts_sbom_app/evidence.py, bts_sbom_app/engine.py)

- BSA-AC-731 [Event] When a finding carries CVSS v3 and v4 vectors, the system shall decompose the v3 AV/AC/PR/UI and v4 AV/AC/AT/PR/UI metrics as attack inputs and note that no rating is computed (2 of 2 vector versions).
- BSA-AC-732 [Unwanted] If a finding carries no vector, the system shall report empty vectors and never fabricate metric values (1 of 1 findings).
- BSA-AC-733 [Event] When findings carry CWE ids, the aggregation shall rank them by count with a distinct-CWE total (1 of 1 distributions).
- BSA-AC-734 [Unwanted] If no finding carries a CWE id, the system shall report 0 distinct CWEs and 0 counts, never guessed ids (1 of 1 projects).
- BSA-AC-735 [Event] When the evidence bundle is written, it shall list the SBOM, VEX and record artifacts with SHA-256, byte size, tool and core versions (4 of 4 artifact kinds).
- BSA-AC-736 [Ubiquitous] The bundle manifest shall be deterministic apart from the timestamp (2 of 2 runs identical on the 4 content fields).
- BSA-AC-737 [Unwanted] If the OSV records carry no cwe_ids, the engine records shall hold no cwe field rather than an invented one (1 of 1 fake worlds).
- BSA-AC-738 [Ubiquitous] The attack-input output shall state that it is inputs only and no rating is computed (1 of 1 notes per finding).
- BSA-AC-739 [Ubiquitous] The bundle shall state that it provides content addressing only and that signatures are out of scope (1 of 1 manifests).
- BSA-AC-740 [Ubiquitous] Building attack inputs, the CWE aggregation and the bundle shall make 0 network calls (3 of 3 functions).


## Provider SBOM vs artifact reconciliation (bts_sbom_app/reconcile.py)

- BSA-AC-741 [Event] When the scan finds a component the provider SBOM does not declare, the system shall report it as an undeclared candidate (1 of 1 components).
- BSA-AC-742 [Unwanted] If the provider SBOM declares a component the scan cannot find, the system shall report it missing with the bundling/unused/renamed possibilities (1 of 1 components).
- BSA-AC-743 [Event] When a declared version differs from the scanned version, the system shall report the mismatch naming both versions (1 of 1 mismatches).
- BSA-AC-744 [Event] When the BOM-based findings differ from the scan-based findings, the system shall report the difference in both directions (2 of 2 directions).
- BSA-AC-745 [State] While binary string evidence is given, undeclared components shall be labelled candidates with the note that string evidence is not identification (1 of 1 components).
- BSA-AC-746 [Ubiquitous] The reconcile output shall state that it carries reconciliation findings only and issues no conformance verdict (1 of 1 outputs).
- BSA-AC-747 [Ubiquitous] The reconcile output shall carry the disclaimer, the declared and scanned component counts and its schema id (3 of 3 fields).
- BSA-AC-748 [Ubiquitous] The reconcile output shall produce identical bytes for the same inputs (2 of 2 runs).


## Frozen handover baseline, post-handover findings and the assumption register (bts_sbom_app/handover.py)

- BSA-AC-749 [Event] When a baseline is frozen, the system shall write it once with the component hash, declared components and the known finding ids, and never overwrite an existing baseline (1 of 1 overwrite attempts).
- BSA-AC-750 [Event] When a new advisory sits on a component declared in the frozen baseline, the system shall flag it as post-handover with the other-party note (1 of 1 advisories).
- BSA-AC-751 [Unwanted] If the component hash changed since the freeze, the post-handover report shall say it no longer matches (1 of 1 changes).
- BSA-AC-752 [State] While a false-positive decision's note carries no evidence reference, the assumption register shall keep it unverified and fail closed (2 of 2 decisions).
- BSA-AC-753 [Event] When the baseline is frozen from a record, its files section shall list the SBOM, VEX artifacts with SHA-256 (2 of 2 kinds).
- BSA-AC-754 [Unwanted] Even when the VEX export passes a justified not_affected, the assumption register shall keep the entry unverified while its note carries no evidence reference (1 of 1 decisions).
- BSA-AC-755 [Ubiquitous] The register evaluation shall produce identical bytes for the same input (2 of 2 runs).
- BSA-AC-756 [Ubiquitous] The freeze manifest, the post-handover report and the assumption register shall each carry the disclaimer text (3 of 3 outputs).


## End-to-end TR 8477 pipeline and security sweep (tests/bts_sbom_app/test_tr8477_e2e.py)

- BSA-AC-757 [Event] When one analysed git repo flows through the V&V report, attack inputs, evidence bundle, provider reconciliation and a frozen baseline, the origin tree hash shall stay unchanged and each stage shall answer with its schema (5 of 5 stages).
- BSA-AC-758 [Unwanted] If the analysis ran offline with an unresolved license, the report shall grade pass with restrictions and never emit a bare pass (1 of 1 reports).
- BSA-AC-759 [Unwanted] If a source URL carries credentials, the V&V report, the attack inputs, the CWE aggregation, the reconcile output and the assumption register shall contain 0 occurrences of the credential or the credentialed URL (5 of 5 outputs).
