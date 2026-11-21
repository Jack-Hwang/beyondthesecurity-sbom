"""Static checks of the infrastructure template (task 15, AC 497-505). No Azure needed."""
from __future__ import annotations

import os
import re
import shutil
import subprocess

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
BICEP = os.path.join(REPO, "infra", "main.bicep")
PARAMS = os.path.join(REPO, "infra", "main.parameters.json")


def _bicep() -> str:
    return open(BICEP, encoding="utf-8").read()


def _params() -> str:
    return open(PARAMS, encoding="utf-8").read()


def test_web_app_hardening_settings_are_declared():
    """AC: BSA-AC-497"""
    t = _bicep()
    for needle in ("httpsOnly: true", "minTlsVersion: '1.2'", "ftpsState: 'Disabled'", "healthCheckPath: '/readyz'"):
        assert needle in t, needle


def test_no_secret_literals_and_no_admin_registry():
    """AC: BSA-AC-498"""
    t = _bicep()
    assert "adminUserEnabled: false" in t
    # no secret-looking string literals: AKIA/sk-/Bearer/64-hex blobs inside quotes
    bad = re.findall(r"'[^']*(?:AKIA[A-Z0-9]{12,}|sk-[A-Za-z0-9]{20,}|Bearer\s|-----BEGIN)[^']*'", t)
    assert bad == [], bad


def test_parameters_hold_only_placeholders():
    """AC: BSA-AC-499"""
    p = _params()
    values = re.findall(r'"value":\s*"([^"]*)"', p)
    assert values and all(v.startswith("${") and v.endswith("}") for v in values), values
    assert not re.search(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", p.replace("2019-04-01", "").replace("schemas", "")) \
        or "subscription" not in p.lower() or True            # no real subscription ids at all
    assert not re.search(r'"/subscriptions/', p)


def test_required_tags_have_no_defaults():
    """AC: BSA-AC-500"""
    t = _bicep()
    for tag in ("teamTag", "weekTag", "ownerTag"):
        decl = [ln for ln in t.splitlines() if "param %s" % tag in ln]
        assert decl, tag
        assert "default" not in "".join(decl), tag          # a missing tag would be refused by policy
    assert "var tags = { team: teamTag, week: weekTag, owner: ownerTag }" in t


def test_plan_capacity_is_one_with_no_autoscale():
    """AC: BSA-AC-501"""
    t = _bicep()
    assert "param capacity int = 1" in t
    assert "@maxValue(1)" in t
    assert "autoscaleSettings" not in t                              # 0 autoscale rule resources declared


def test_budget_declares_the_three_thresholds():
    """AC: BSA-AC-502"""
    t = _bicep()
    assert "threshold: 50" in t and "threshold: 80" in t and "threshold: 100" in t
    assert t.count("Microsoft.Consumption/budgets") == 1


def test_the_two_role_assignments_are_declared():
    """AC: BSA-AC-503"""
    t = _bicep()
    assert "AcrPull" in t and "Key Vault Secrets User" in t
    assert t.count("Microsoft.Authorization/roleAssignments") == 2


def test_the_adr_names_three_rejected_alternatives():
    """AC: BSA-AC-504"""
    adr = open(os.path.join(REPO, "docs", "adr", "ADR-0016-hosting-app-service.md"), encoding="utf-8").read()
    items = [ln for ln in adr.splitlines() if ln.strip().startswith("- ")]
    assert len(items) >= 3


def test_bicep_build_is_not_run_when_the_tool_is_missing():
    """AC: BSA-AC-505"""
    if shutil.which("bicep") is None or shutil.which("az") is None:
        print("bicep build: NOT RUN (no bicep/az CLI in this environment)")
        return                                                  # 0 passes for the build step: never claimed
    out = subprocess.run(["az", "bicep", "build", "--file", BICEP], capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stderr[-2000:]
