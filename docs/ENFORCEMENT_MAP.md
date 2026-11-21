# ENFORCEMENT MAP — 정직 계약이 코드 어디서, 어떤 테스트로 강제되는가

"근거가 없으면 통과가 아니다(없음 ≠ 안전)" 계약의 위험 → 강제 수단 → 위치 → 검증 테스트.
모든 위치와 테스트는 실제 존재하는 것만 적는다(doclint 가 dangling reference 를 검출한다).

| 위험 | 강제 수단 | 위치 | 검증 테스트 |
|---|---|---|---|
| 분석 대상 원본 변조 | 원본 트리 해시 불변 단정 + 워크 복사본 전용 | bts_sbom_app/pipeline.py | tests/bts_sbom_app/test_patch_delivery.py::test_pipeline_patch_flow_origin_untouched_and_findings_to_zero |
| 위험한 소스(ext::/http/옵션형) | normalize_source 거부 | bts_sbom_app/workspace.py | tests/bts_sbom_app/test_patch_delivery.py::test_unsafe_sources_are_refused |
| clone 이 훅·서브모듈·ext 전송을 끌어옴 | git 인자에 3가지 안전 설정 강제 | bts_sbom_app/workspace.py | tests/bts_sbom_app/test_patch_delivery.py::test_clone_command_carries_three_safety_settings |
| 승인 없는 패치 | approved=False 는 파일 변경 0 + 다이제스트만 산출 | bts_sbom_app/patch.py | tests/bts_sbom_app/test_patch_delivery.py::test_no_approval_changes_nothing |
| 승인 후 플랜이 바뀐 오적용 | 16자리 다이제스트 토큰 불일치 거부 | bts_sbom_app/patch.py | tests/bts_sbom_app/test_patch_delivery.py::test_digest_mismatch_applies_nothing |
| 상한 제약 무시하고 강제 업그레이드 | blocked 로 기록하고 요구 줄 보존 | bts_sbom_app/patch.py | tests/bts_sbom_app/test_patch_delivery.py::test_upper_bound_is_blocked_not_forced |
| 패치가 발견을 늘림 | 재스캔 회귀 감지 시 자동 revert | bts_sbom_app/pipeline.py | tests/bts_sbom_app/test_patch_delivery.py::test_regression_after_patch_is_reverted |
| 부분 수정(shared 분면) 누락 | 4분면 impact: 미수정 매니페스트를 regression 로 기록 | bts_sbom_app/impact.py | tests/bts_sbom_app/test_impact_review.py::test_shared_quadrant_catches_the_same_component_in_a_second_manifest |
| 죽은 호스트에 계속 호출 | 호스트별 서킷브레이커 + access_failure 정직 응답 | bts_sbom_app/net.py | tests/bts_sbom_app/test_resilience.py::test_open_circuit_sends_zero_requests_and_reports_circuit_open |
| OSV 질의 실패를 안전한 것처럼 보고 | verification unverified(null) 강제 | bts_sbom_app/remediate.py | tests/bts_sbom_app/test_engine_licenses.py::test_osv_failure_is_unverified_not_clean |
| 라이선스 철자 추측 | 정규화 실패는 unmapped 로 남김 | bts_sbom_app/licenses.py | tests/bts_sbom_app/test_engine_licenses.py::test_license_spellings_map_or_stay_unmapped |
| 정규화 캐시가 개선을 가림 | 원본 증거 캐시 + 재해석 | bts_sbom_app/licenses.py | tests/bts_sbom_app/test_engine_licenses.py::test_cached_raw_evidence_is_reinterpreted_without_network |
| EXAONE 429 를 성공처럼 보고 | 1회 호출 후 결정적 강등 + 사유 기록 | bts_sbom_app/ai.py | tests/bts_sbom_app/test_ai_rag_loop.py::test_http_429_day_limit_downgrades_after_one_call |
| LLM 환각 권고 유입 | 검증 4계층 후 dropped 계수 | bts_sbom_app/ai.py | tests/bts_sbom_app/test_ai_rag_loop.py::test_four_layer_validation_keeps_exactly_one |
| 챗봇이 근거 없는 출처를 인용 | claim-quote-source 검증(미검색 출처 거절) | bts_sbom_app/chat.py | tests/bts_sbom_app/test_ai_rag_loop.py::test_claim_pointing_to_unretrieved_source_is_rejected |
| 위조 인용 통과 | 인용이 문서 부분 문자열인지 검증 | bts_sbom_app/chat.py | tests/bts_sbom_app/test_ai_rag_loop.py::test_chat_answers_from_tools_with_perfect_citation_and_rejects_forgery |
| 읽기 전용 세션에서 패치 실행 | actions 없는 세션은 쓰기 도구 거부 | bts_sbom_app/chat.py | tests/bts_sbom_app/test_chat_actions.py::test_the_service_offers_actions_only_when_started_with_them |
| EXAONE 키가 응답에 노출 | 키 미반환·마지막 4자만 | bts_sbom_app/server.py | tests/bts_sbom_app/test_server_cli.py::test_api_llm_connects_masks_the_key_and_plans_with_the_llm |
| 저장된 키가 응답·증거에 유출 | 8개 GET 경로+챗 응답에서 키 0회 | bts_sbom_app/server.py | tests/bts_sbom_app/test_secret_hygiene.py::test_no_route_response_ever_contains_the_key |
| 작업 기록에 승인 토큰 저장 | 토큰 필드 자체를 저장하지 않음 | bts_sbom_app/jobstore.py | tests/bts_sbom_app/test_jobstore.py::test_an_approval_token_is_never_written_to_a_job_file |
| SSE 스트림에 승인 토큰 노출 | patch_gate 이벤트는 상태만, 토큰 0자 | bts_sbom_app/events.py | tests/bts_sbom_app/test_events_sse.py::test_an_approved_patch_stream_has_one_patch_gate_and_zero_token_characters |
| 클라우드에서 로컬 경로 접근 | 클라우드 소스 정책 거부(디렉터리 0회 읽기) | bts_sbom_app/workspace.py | tests/bts_sbom_app/test_source_policy.py::test_local_paths_are_refused_without_reading_anything |
| 클라우드에서 사설·메타데이터 주소 SSRF | 허용 목록 + 공개 주소 확인 | bts_sbom_app/workspace.py | tests/bts_sbom_app/test_source_policy.py::test_private_and_metadata_addresses_are_refused_and_start_no_clone |
| 인증 없는 클라우드 접근 | 클라우드 게이트 401, 미설정 시 503 fail-closed | bts_sbom_app/auth.py | tests/bts_sbom_app/test_auth_audit.py::test_an_unauthenticated_scan_is_401_and_creates_zero_jobs |
| 익명 승인·VEX 결정 | 신원 없는 쓰기 거부, approved_by 기록 | bts_sbom_app/server.py | tests/bts_sbom_app/test_auth_audit.py::test_writes_without_a_known_identity_are_refused_and_change_nothing |
| 감사 로그 변조 | 줄 단위 해시 체인(h=sha256(body), prev=앞 줄 h) | bts_sbom_app/audit.py | tests/bts_sbom_app/test_auth_audit.py::test_the_audit_hash_chain_verifies_and_names_the_altered_line |
| 무한 동시 스캔 | 작업 게이트 429 + Retry-After | bts_sbom_app/limits.py | tests/bts_sbom_app/test_limits_shutdown.py::test_a_full_gate_answers_429_with_retry_after_and_starts_no_threads |
| SIGTERM 뒤 "running"으로 남는 작업 | 드레인 후 interrupted(sigterm) 기록 | bts_sbom_app/server.py | tests/bts_sbom_app/test_limits_shutdown.py::test_the_drain_records_unfinished_jobs_as_interrupted_sigterm |
| 로그에 시크릿 기록 | 마스킹 + 구조적 필드만 기록 | bts_sbom_app/obslog.py | tests/bts_sbom_app/test_observability.py::test_the_log_never_carries_planted_secrets |
| 프롬프트 주입을 도구 실행으로 전환 | 결정적 입력 필터(도구 호출 0건) | bts_sbom_app/guardrail.py | tests/bts_sbom_app/test_guardrail.py::test_the_three_critical_injection_shapes_are_blocked_and_call_zero_tools |
| 미해결 라이선스를 안전으로 오인 | obligations 상태 계산에서 unknown 을 none 으로 세지 않음(모든 시나리오 unknown) | bts_sbom_app/obligations.py | tests/bts_sbom_app/test_obligations.py::test_unresolved_license_is_unknown_in_all_scenarios_and_never_none |
| 코드 수정 제안이 자동 적용됨 | 승인 다이제스트 토큰 + 적용 경로는 CLI 한정(웹·챗 0개) | bts_sbom_app/codeprop.py | tests/bts_sbom_app/test_codeprop.py::test_zero_apply_routes_on_the_web_api |
| LLM 후보가 라이선스 검증 없이 노출 | 결정적 검증 5단계 후 resolver 허용 카테고리만 통과, 미해결은 unverified 표기 | bts_sbom_app/alternatives.py | tests/bts_sbom_app/test_alternatives.py::test_unresolvable_candidates_stay_unverified_with_unknown_license |
| 법률 자문으로 오인 | DISCLAIMER 상수를 모든 출력 표면에 부착 | bts_sbom_app/obligations.py | tests/bts_sbom_app/test_obligations.py::test_the_disclaimer_is_on_all_four_surfaces |
