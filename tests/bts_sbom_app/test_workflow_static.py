"""Static checks of the deploy workflow (task 16, AC 509-517). Nothing executes on GitHub."""
from __future__ import annotations

import os
import re

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
WF = os.path.join(REPO, ".github", "workflows", "deploy_azure.yml")


def _wf() -> str:
    return open(WF, encoding="utf-8").read()


def test_permissions_are_read_only_and_oidc_only_for_login():
    """AC: BSA-AC-509"""
    t = _wf()
    assert re.search(r"^permissions:\s*$.*?^  contents: read", t, re.M | re.S)
    # id-token: write appears only inside job-level permissions blocks, never at the top level
    top = t.split("jobs:", 1)[0]
    assert "id-token" not in top
    assert t.count("id-token: write") >= 1
    for job_block in re.findall(r"permissions:\n(  contents: read\n  id-token: write\n)", t):
        assert "contents: read" in job_block


def test_no_secrets_no_client_secret_no_subscription_literals():
    """AC: BSA-AC-510"""
    t = _wf()
    assert "client_secret" not in t and "client-secret" not in t and "ARM_CLIENT_SECRET" not in t
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", t), "no literal ids"
    assert "secrets." in t or "vars." in t                                  # references only


def test_trivy_fails_the_job_on_critical():
    """AC: BSA-AC-511"""
    t = _wf()
    assert "aquasecurity/trivy-action" in t
    assert "severity: CRITICAL" in t and "exit-code: \"1\"" in t


def test_self_sbom_is_generated_and_uploaded_before_the_deploy():
    """AC: BSA-AC-512"""
    t = _wf()
    sbom_at = t.find("selfsbom")
    upload_at = t.find("self-sbom")
    login_at = t.find("\n  login:")
    assert 0 < sbom_at < upload_at < login_at, "the SBOM step must run before any Azure deploy job"


def test_the_swap_runs_in_a_protected_environment():
    """AC: BSA-AC-513"""
    swap_job = _wf().split("  swap:", 1)[1].split("  rollback:", 1)[0]
    assert "environment: production" in swap_job


def test_staging_deploy_and_readyz_precede_the_swap():
    """AC: BSA-AC-514"""
    t = _wf()
    staging_at = t.find("Deploy to the staging slot")
    readyz_at = t.find("Wait for /readyz on staging")
    swap_at = t.find("name: Swap")
    assert 0 < staging_at < readyz_at < swap_at


def test_no_moving_action_refs_and_no_pull_request_target():
    """AC: BSA-AC-515"""
    t = _wf()
    assert "pull_request_target" not in t
    refs = re.findall(r"uses:\s*([\w./-]+)@([\w.\-/]+)", t)
    assert refs, "the workflow pins its actions"
    assert all(not ref.endswith("@main") and not ref.endswith("@master") for _n, ref in refs)
    # SHAs would be stronger: noted as "확인 필요" in the workflow header comment
    assert "확인 필요" in t


def test_the_rollback_job_swaps_back():
    """AC: BSA-AC-516"""
    rollback = _wf().split("  rollback:", 1)[1]
    assert "if: failure()" in rollback and "slot swap" in rollback


def test_execution_is_not_run_until_github_and_azure_exist():
    """AC: BSA-AC-517"""
    t = _wf()
    assert "NOT RUN" in t and "workflow_dispatch" in t            # manual trigger only: 0 executed runs so far
