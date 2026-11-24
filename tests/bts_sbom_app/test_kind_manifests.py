"""kind manifest policy (brief 5 G1, 산출만): static checks over the YAML text - same discipline as
test_container_policy.py, plus a real kubectl client-side dry-run parse when kubectl is on PATH."""
from __future__ import annotations

import os
import re
import shutil
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
MANIFEST = os.path.join(ROOT, "deploy", "kind", "bts-sbom.yaml")
KUBECTL_CANDIDATES = [r"C:\Program Files\Docker\Docker\resources\bin\kubectl.exe", "kubectl"]


def _docs() -> list:
    with open(MANIFEST, encoding="utf-8") as fh:
        raw = fh.read()
    kinds = []
    for d in raw.split("\n---"):
        m = re.search(r"^kind:\s*(\S+)", d, re.M)
        if m:
            kinds.append(m.group(1))
    return kinds


def test_manifest_document_set_and_apply_safety_rules():
    """AC: BSA-AC-522"""
    assert _docs() == ["Namespace", "PersistentVolumeClaim", "Deployment", "Service"]
    text = open(MANIFEST, encoding="utf-8").read()
    assert "runAsNonRoot: true" in text and "runAsUser: 10001" in text       # the Dockerfile's numeric UID
    assert re.search(r"image:\s*bts-sbom-app:\S+", text) and ":latest" not in text   # pinned, never latest
    assert re.search(r"path:\s*/readyz", text) and re.search(r"path:\s*/healthz", text)  # ready vs live, distinct jobs
    assert "type: ClusterIP" in text and not re.search(r"type:\s*(NodePort|LoadBalancer)", text)  # no-auth exposure rule (comments may name them)
    assert "persistentVolumeClaim" in text and "claimName: evidence-pvc" in text
    assert "replicas: 1" in text and "type: Recreate" in text                # one process, one shared evidence volume
    assert "limits:" in text and "memory:" in text                           # resource ceiling declared


def test_manifest_parses_with_kubectl_dry_run():
    """AC: BSA-AC-522"""
    kubectl = next((k for k in KUBECTL_CANDIDATES if shutil.which(k) or os.path.exists(k)), None)
    if not kubectl:
        pytest.skip("kubectl not on this host")
    probe = subprocess.run([kubectl, "api-resources", "--request-timeout=5s"], capture_output=True, text=True, timeout=30)
    if probe.returncode != 0:                 # kubectl is installed (CI runners have it) but no cluster answers
        pytest.skip("no reachable cluster: `kubectl apply --dry-run=client` still needs API discovery")
    p = subprocess.run([kubectl, "apply", "--dry-run=client", "--validate=false", "-f", MANIFEST],
                       capture_output=True, text=True, timeout=60)
    assert p.returncode == 0, p.stderr
    assert "(dry run)" in p.stdout and p.stdout.count("(dry run)") == 4      # all four documents parse


def test_kind_readme_states_produced_not_deployed():
    """AC: BSA-AC-522"""
    readme = open(os.path.join(ROOT, "deploy", "kind", "README.md"), encoding="utf-8").read()
    assert "산출만" in readme and "미배포" in readme                          # the honest status is the contract
    assert "port-forward" in readme                                          # local-only exposure procedure
    assert "fsGroup" in readme                                               # the unverified-on-cluster item is named
