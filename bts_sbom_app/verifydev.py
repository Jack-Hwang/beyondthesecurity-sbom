"""verify-dev: post-deployment verification contract (task 22) - stdlib only.

The reference project's convention, adopted here: a deployment that does not exist is NOT RUN (exit 2), never a
pass. Checks (in order): GET /healthz 200, GET /readyz 200 (mode: standby counts as incomplete), and the NEGATIVE
probe - GET /api/projects WITHOUT credentials must answer 401 on a cloud-mode deployment (an open server would
be a FAIL). With a token, GET /api/engine must report cloud.enabled == true. Plain http on a non-local host is
refused BEFORE any request carrying the token is sent. The token is never written to output or sidecars.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

SIDECAR_SUMMARY = "proof-results.json"
SIDECAR_RUNS = "proof-runs"
LOCAL_HOSTS = ("127.0.0.1", "localhost", "::1", "0.0.0.0")


def run(base_url: str = "", token: str = "", opener: Optional[Callable[[str], Tuple[int, str]]] = None,
        out_dir: str = "") -> int:
    """Entry point. ``opener``: injectable GET (url) -> (status, body text) for tests; real urllib otherwise."""
    if not base_url:
        base_url = os.environ.get("DEV_BASE_URL", "")
    if not base_url:
        print("verify-dev: NOT RUN (DEV_BASE_URL is not set - there is no deployment to verify)")
        return 2
    if base_url.startswith("http://") and not any(h in base_url for h in LOCAL_HOSTS):
        print("verify-dev: refused (plain http to a non-local host would carry credentials in the clear)")
        return 2
    checks: List[Dict[str, Any]] = []
    get = opener if opener is not None else _urlopen(base_url, token)

    def probe(path: str) -> Tuple[str, Optional[str]]:
        try:
            status, body = get(path)
            return ("PASS" if status == 200 else "FAIL"), body
        except Exception as exc:                               # noqa: BLE001 - a network error is a FAIL, not a crash
            return "FAIL", type(exc).__name__

    st, _ = probe("/healthz")
    checks.append({"check": "healthz_200", "status": st})
    st, body = probe("/readyz")
    mode = ""
    if st == "PASS":
        try:
            mode = str((json.loads(body or "{}") or {}).get("mode") or "")
        except ValueError:
            mode = ""
        if mode == "standby":
            st = "NOT RUN"                                     # a standby instance verifies nothing about writes
            reason = "readyz reports standby"
            checks.append({"check": "readyz_200", "status": st, "reason": reason})
        else:
            checks.append({"check": "readyz_200", "status": st})
    else:
        checks.append({"check": "readyz_200", "status": st})
    try:
        status, _body = get("/api/projects")                   # deliberately WITHOUT credentials
        checks.append({"check": "unauthenticated_api_is_401", "status": "PASS" if status == 401 else "FAIL"})
    except Exception:                                          # noqa: BLE001
        checks.append({"check": "unauthenticated_api_is_401", "status": "FAIL"})
    if token:
        try:
            status, body = get("/api/engine")
            enabled = (json.loads(body or "{}").get("cloud") or {}).get("enabled") if status == 200 else None
            checks.append({"check": "cloud_enabled_with_token", "status": "PASS" if enabled is True else "FAIL"})
        except Exception:                                      # noqa: BLE001
            checks.append({"check": "cloud_enabled_with_token", "status": "FAIL"})
    overall = "pass"
    if any(c["status"] == "FAIL" for c in checks):
        overall = "fail"
    elif any(c["status"] == "NOT RUN" for c in checks):
        overall = "incomplete"
    _write_sidecar(out_dir or ".", checks, overall)
    print("verify-dev: %s (%s)" % (overall.upper(), ", ".join("%s=%s" % (c["check"], c["status"]) for c in checks)))
    return 0 if overall == "pass" else (1 if overall == "fail" else 2)


def _urlopen(base_url: str, token: str) -> Callable[[str], Tuple[int, str]]:
    headers = {"Authorization": "Bearer " + token} if token else {}

    def get(path: str) -> Tuple[int, str]:
        req = urllib.request.Request(base_url.rstrip("/") + path, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as r:
                return r.status, r.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode("utf-8", errors="replace")
    return get


def _write_sidecar(out_dir: str, checks: List[Dict[str, Any]], overall: str) -> None:
    """Same sidecar contract as the proof command: summary overwritten each run, per-run files accumulate."""
    record = {"tool": "verify-dev", "overall": overall, "checks": checks,
              "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())}
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, SIDECAR_SUMMARY), "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
    runs = os.path.join(out_dir, SIDECAR_RUNS)
    os.makedirs(runs, exist_ok=True)
    name = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    target = os.path.join(runs, name + ".json")
    seq = 0
    while os.path.exists(target):                              # two runs in the same second never collide
        seq += 1
        target = os.path.join(runs, "%s-%d.json" % (name, seq))
    with open(target, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(record, fh, ensure_ascii=False, indent=1)
        fh.write("\n")
