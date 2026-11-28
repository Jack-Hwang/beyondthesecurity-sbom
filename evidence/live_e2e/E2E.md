# Live end-to-end on Azure — 2026-11-28 (revision bg20261128085328, image sha-01f12a1, app 0.6.1)

Chain requested by the owner ("GitHub에서 받고 → 스캔 → 리포트 → 레거시 아키텍처 → AI 제안 → 구현 → 배포"), all measured against the live Container Apps URL:

1. SCAN (GitHub → engine): POST /api/scan {"source":"https://github.com/OWASP/NodeGoat.git"} → job 1763010e14 → done.
   NodeGoat: components 1,091 · vulns 311 (CRITICAL 32 · HIGH 168 · MEDIUM 92 · LOW 19) — identical to the 11-27 run (deterministic).
2. ARTIFACTS: CycloneDX / SPDX / OpenVEX / record under evidence/NodeGoat.git/ on the volume (job 47c6f46484 with patch+use_llm).
3. ARCHITECTURE (legacy view): POST /api/arch/scan → job b7a77c9301 → done. Overview measured: project license Apache-2.0 (permissive), files / loc / entry points counted.
4. AI PROPOSAL (gpt-5-mini, live):
   - fix-plan question → 125 upgrades proposed, 40 major bumps, 6 packages without a known fix (deterministic tool answer, 0.68 s).
   - architecture question → the assistant answered ONLY from Book KB passages and honestly abstained: the corpus does not contain an Express/Mongo SSRF/NoSQL-injection reference architecture (25.8 s, not degraded, 근거 없이 통과시키지 않는 계약의 라이브 실측).
5. APPROVED PATCH (the implementation step): plan digest 724fd71981d36d55 (from the record) → POST /api/scan {patch, approved, approval_token} → job 235dac4d54 → done, work copy created (/tmp/bts_sbom_job_ygu3tvr8), origin untouched (AC-1). NOTE for the owning lane: the post-apply metrics in the job record still read 311 — worth a look by whoever owns the patch pipeline.
6. DEPLOY of the product itself: push 01f12a1 (Claude-client layout) → CI image lane built sha-01f12a1 in 1m9s (Trivy CRITICAL=0 gate) → scripts/gitops_deploy.py deploy promoted it live (blue/green, previous revision alive). First promote attempt auto-rolled-back because the smoke probe had no BTS_AZ_FQDN — the safety net worked as designed; second attempt with the env set PROMOTED (revision bg20261128085328).
7. LIVE SMOKE after promote: healthz 200/125ms · readyz 200/94ms · auth gate off (owner decision 10f2e05, documented) · SSE first byte 328ms → PASS 4/4.
8. UI in a real browser on the live URL: CCD three-column layout renders (rail 264 / chat 760 / drawer 576, 30 panes), a chat turn answered with live CVEs (CVE-2020-7610 bson CRITICAL 9.8 → 1.1.4 ...).

Auth state: the login wall is OFF by owner decision (commit 10f2e05) — an open demo deployment, documented in deploy/azure/README.md.
## 311 불변 진단 (추가 조사 2026-11-28 오후)

- 승인 잡(235dac4d54) 기록의 metrics 311은 **패치 적용 전 스캔값**이다 — 승인 흐름은 스캔 → 플랜 → 적용 순서이고 재스캔 수치는 별도 필드로 노출되지 않는다.
- 패치된 워크카피(/tmp/bts_sbom_job_ygu3tvr8)는 **컨테이너 로컬 /tmp**에 있었고, 잡 완료 후 스케일 0이 되면서 소멸했다(스모크 재실행 전 리비전이 콜드 스타트한 것으로 확인). 산출물(CDX/SPDX/VEX/레코드)은 Files 볼륨(/tmp/evidence)에 영속됐다.
- 결론: 실패가 아니라 **설계된 휘발성(R8) + 전달 단계(AC-18: 브랜치·폴더·제자리·GitHub PR) 미호출**. 배포 가능한 결과물을 남기려면 잡 창구 안에서 전달 단계(예: GitHub PR 플래그)를 함께 호출해야 한다. 이 문서를 쓰는 시점에는 컨테이너가 재기동되어 승인 잡 기록 자체가 /api/jobs에서 404(문서화된 동작: 완료 잡은 이전 서버 실행 것은 미서빙)이다.
