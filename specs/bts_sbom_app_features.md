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

### 스캔 진입점 통합 — Analyze 한 번에 OSS 성과물까지 (UX 정리)

메인 Scan(🌐)과 OSS Scanner(📜)는 엔진이 다르다(파이프라인 vs oss_api) — 그래서 진입점이 두 개였다는
것이 UX 불편이므로, 메인 Analyze가 끝나면 체크박스(#scaOss "OSS 성과물")가 켜져 있을 때 같은 대상을
OSS Scanner 엔진(source+dependency+binary)으로 이어 스캔한다. 결과는 #scaBanner에 기록된다: 성공 시
job id와 OSS Scanner 탭 이동 버튼(addEventListener 방식 — CSP상 인라인 핸들러 금지), 실패 시 실패
이유와 "메인 분석 결과는 정상"임을 명시하는 정직한 노트. OSS 탭은 고급 옵션(exclude·브랜치·보정·내보내기
서식)용으로 유지된다. DOM 규칙은 콘솔과 동일: note()는 HTML 문자열이고 동적 값은 esc()로 감싼다.

- BSA-AC-533 [Event] When the main Analyze finishes and the OSS-deliverables checkbox is checked the console shall chain the same target into POST /api/oss/scan with all three modes, poll GET /api/oss/jobs/<id> until it leaves running, and then render in the scan banner either the success note with the job id and a real button that activates the OSS tab, or an honest failure note naming the reason and stating the main result is untouched - never a silent skip of the OSS stage (1 of 1 chains, 2 of 2 banner outcomes).

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

- BSA-AC-534 [Event] When an MCP client speaks the line-delimited JSON-RPC 2.0 protocol to `python -m bts_sbom_app mcp` it shall complete the initialize handshake with protocolVersion 2024-11-05, list exactly the four tools with object input schemas, call each tool against the real modules (engine_status reads registry and LLM-config presence, book_search returns book-provenance passages capped at 240 chars or an honest miss note, project_overview returns the overview lines and isError+reason for an unknown project, chat_ask returns a grounded cited answer), keep stdout protocol-pure with the banner on stderr, and answer -32601/-32602 for unknown method and unknown tool (4 of 4 tools, 2 of 2 protocol errors).
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

- BSA-AC-538 [Event] When the console page loads it shall build the section navigation as a desktop-style sidebar from GROUPS/LABELS with the same .rtab[data-sv] contract as the old top bar, containing 12 groups including the single-member report and chat groups whose sub-chip row stays hidden (12 of 12 groups, 1 of 1 built-at-init call).
- BSA-AC-539 [Event] When the Report tab is opened the system shall render the selected project's header (name, source, analysed time, 5 severity chips, 4 document download buttons), the copied ScaApp report body into the single #reportOut mount, and re-render the whole screen on every entry of the tab (1 of 1 mount, 4 of 4 downloads, 5 of 5 chips, 1 of 1 entry hook).
- BSA-AC-540 [Event] When an analysis finishes with state done the system shall switch to the Report tab automatically and render the two honest data-status warnings (empty project, incomplete vulnerability data) in the report banner while the scan-time status stays on the Scan tab (2 of 2 warning cases, 1 of 1 auto-switch).
- BSA-AC-541 [Event] When the Report tab renders its governance cards it shall show the fix-plan summary from /api/view and fetch decision coverage and SBOM conformance once per project, rendering a loading line before the fetch, the measured numbers after it, and a not-loaded line carrying the error when the fetch fails (3 of 3 cards, 2 of 2 lazy fetches, 2 of 2 error lines).
- BSA-AC-542 [State] The copied platform renderer sca_app.js and the platform stylesheets shall stay byte-identical to their pinned hashes while the desktop shell, the Report tab and the Chat tab are added around them (6 of 6 pinned files unchanged, 1 of 1 ScaApp mount in the page).
