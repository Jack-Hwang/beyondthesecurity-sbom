"""Serving-image supply-chain gate (MetaNet 4주차 1차시): build -> scan -> SBOM -> bench, one command.

Order is the course pipeline: Dockerfile(비루트·pinned) -> docker build -> Trivy scan (CRITICAL 0 or fail) ->
CycloneDX SBOM 산출 -> self-SBOM(bts_sbom 이 자기 저장소를 분석) -> bench smoke -> evidence 고정 경로 요약 +
timestamp/ 원본 누적. Tools may be absent - the plan is computed first, so the report says exactly what ran,
what was skipped and why (an honest skip is data; a silent skip is a lie).

Usage:  python scripts/supply_chain_gate.py [--skip-build] [--max-critical 0]
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DOCKERFILE = os.path.join(ROOT, "Dockerfile.bts-sbom-app")
IMAGE = "bts-sbom-app:gate"
EVIDENCE = os.path.join(ROOT, "evidence", "supply_chain")


def _run(cmd: List[str], timeout: int = 900, full: bool = False) -> Dict[str, Any]:
    t0 = time.time()
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=ROOT)
        return {"cmd": " ".join(cmd), "code": p.returncode, "seconds": round(time.time() - t0, 2),
                "stdout_tail": (p.stdout or "") if full else (p.stdout or "")[-800:],
                "stderr_tail": (p.stderr or "")[-800:]}
    except FileNotFoundError:
        return {"cmd": " ".join(cmd), "code": 127, "seconds": 0.0, "stdout_tail": "", "stderr_tail": "tool not found"}
    except subprocess.TimeoutExpired:
        return {"cmd": " ".join(cmd), "code": 124, "seconds": round(time.time() - t0, 2),
                "stdout_tail": "", "stderr_tail": "timeout"}


def _have(tool: str) -> bool:
    return shutil.which(tool) is not None


def plan(tools: Dict[str, bool], skip_build: bool = False, trivy_via_docker: bool = True) -> List[Dict[str, Any]]:
    """The ordered step plan with honest skips - pure, so tests can pin it."""
    steps: List[Dict[str, Any]] = []
    if skip_build or not tools.get("docker"):
        steps.append({"name": "build", "state": "skipped", "why": "docker unavailable" if not skip_build else "skipped by flag"})
    else:
        steps.append({"name": "build", "state": "run", "cmd": ["docker", "build", "-f", DOCKERFILE, "-t", IMAGE, "."]})
    scan = {"name": "scan", "state": "run"}
    if tools.get("trivy"):
        scan["cmd"] = ["trivy", "image", "--severity", "CRITICAL", "--exit-code", "1", IMAGE]
    elif tools.get("docker") and trivy_via_docker:
        scan["cmd"] = ["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                       "aquasec/trivy:latest", "image", "--severity", "CRITICAL", "--exit-code", "1", IMAGE]
    else:
        scan.update(state="skipped", why="no trivy and no docker to host it")
    steps.append(scan)
    sbom = {"name": "sbom", "state": "run"}
    if tools.get("trivy"):
        sbom["cmd"] = ["trivy", "image", "--format", "cyclonedx", "--output", os.path.join(EVIDENCE, "image.cdx.json"), IMAGE]
    elif tools.get("docker") and trivy_via_docker:
        sbom["cmd"] = ["docker", "run", "--rm", "-v", "/var/run/docker.sock:/var/run/docker.sock",
                       "aquasec/trivy:latest", "image", "--format", "cyclonedx", "--output", "/dev/stdout", IMAGE]
        sbom["stdout_to"] = os.path.join(EVIDENCE, "image.cdx.json")
    else:
        sbom.update(state="skipped", why="no trivy and no docker to host it")
    steps.append(sbom)
    if tools.get("python"):
        steps.append({"name": "self_sbom", "state": "run",
                      "cmd": [sys.executable, "-X", "utf8", "-m", "bts_sbom_app", "--root", str(ROOT),
                              "scan", str(ROOT), "--out", EVIDENCE, "--offline", "--json"]})
    else:
        steps.append({"name": "self_sbom", "state": "skipped", "why": "python unavailable"})
    steps.append({"name": "bench", "state": "run" if tools.get("python") else "skipped",
                  "why": None if tools.get("python") else "python unavailable"})
    return steps


BENCH_PATHS = ("/healthz", "/readyz", "/api/history")   # no-check, probe, and file-reading: three latency classes


def _bench(server_cmd: List[str], port: int, requests_n: int = 60) -> Dict[str, Any]:
    """Start the container-free local server, hit each bench path N times, report per-path p50/p95.

    /healthz alone says nothing about real latency (it does no check); /readyz actually writes and imports,
    /api/history reads the evidence folder - capacity.md consumes all three."""
    import urllib.request
    proc = subprocess.Popen(server_cmd, cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    lat: Dict[str, List[float]] = {p: [] for p in BENCH_PATHS}
    code: Dict[str, int] = {p: 0 for p in BENCH_PATHS}
    try:
        time.sleep(2.5)
        for _ in range(requests_n):
            for path in BENCH_PATHS:
                t0 = time.time()
                try:
                    with urllib.request.urlopen("http://127.0.0.1:%d%s" % (port, path), timeout=3) as r:
                        code[path] = r.status
                except Exception:
                    code[path] = 0
                lat[path].append(round((time.time() - t0) * 1000, 2))
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
    endpoints = {}
    for path in BENCH_PATHS:
        s = sorted(lat[path])
        p = lambda q: s[min(len(s) - 1, int(len(s) * q))]
        endpoints[path] = {"requests": len(s), "http_status": code[path],
                           "p50_ms": p(0.50), "p95_ms": p(0.95), "max_ms": s[-1] if s else None}
    return {"requests_per_path": requests_n, "endpoints": endpoints,
            "ok": all(code[p2] == 200 for p2 in BENCH_PATHS)}


def aggregate(entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Pure gate decision from step entries: any failed step fails the gate; scan code reads criticals.

    127 is a missing tool (honest skip - the gate does not fail on it), 0 is CRITICAL-free, any other
    non-zero code means vulnerabilities or a broken pipeline and fails the gate."""
    verdict = "pass"
    critical_found = None
    for e in entries:
        if e.get("state") == "failed":
            verdict = "fail"
        code = (e.get("run") or {}).get("code")
        if e.get("name") == "scan" and code is not None and code != 127:
            critical_found = 0 if code == 0 else -1
    return {"verdict": verdict, "critical_found": critical_found}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-build", action="store_true", help="reuse the already-built image")
    ap.add_argument("--max-critical", type=int, default=0)
    ap.add_argument("--skip-bench", action="store_true")
    a = ap.parse_args(argv)
    os.makedirs(EVIDENCE, exist_ok=True)
    os.makedirs(os.path.join(EVIDENCE, "bench"), exist_ok=True)
    tools = {"docker": _have("docker"), "trivy": _have("trivy"), "python": True}
    report: Dict[str, Any] = {"schema": "bts-sbom.supply-chain.v1", "image": IMAGE, "tools": tools,
                              "steps": [], "critical_found": None, "verdict": "pass", "ts": time.strftime("%Y-%m-%dT%H:%M:%S")}
    plan_steps = plan(tools, skip_build=a.skip_build)
    for step in plan_steps:
        if step["state"] == "skipped":
            report["steps"].append({k: step[k] for k in ("name", "state", "why") if k in step})
            continue
        if step["name"] == "bench":
            if a.skip_bench:
                report["steps"].append({"name": "bench", "state": "skipped", "why": "skipped by flag"})
                continue
            res = _bench([sys.executable, "-X", "utf8", "-m", "bts_sbom_app", "--root", ROOT, "serve",
                          "--host", "127.0.0.1", "--port", "8899", "--evidence", os.path.join(ROOT, "evidence", "runs")], 8899)
            report["steps"].append({"name": "bench", "state": "done", "result": res})
            continue
        run = _run(step["cmd"], timeout=1200, full=step.get("stdout_to") is not None)  # SBOM stdout must not be tailed
        entry: Dict[str, Any] = {"name": step["name"], "run": run,
                                 "state": "done" if run["code"] == 0 else ("skipped" if run["code"] == 127 else "failed")}
        if entry["state"] == "skipped":
            entry["why"] = "tool vanished between planning and run"
        if step.get("stdout_to") and run["stdout_tail"]:
            with open(step["stdout_to"], "w", encoding="utf-8") as f:
                f.write(run["stdout_tail"])
        report["steps"].append(entry)
    decision = aggregate(report["steps"])
    report["verdict"] = decision["verdict"]
    report["critical_found"] = decision["critical_found"]
    stamp = time.strftime("%Y%m%d_%H%M%S")
    with open(os.path.join(EVIDENCE, "bench", "bench_latest.json"), "w", encoding="utf-8") as f:
        json.dump({s["name"]: s for s in report["steps"]}, f, indent=1, ensure_ascii=False)
    shutil.copyfile(os.path.join(EVIDENCE, "bench", "bench_latest.json"),
                    os.path.join(EVIDENCE, "bench", "bench_%s.json" % stamp))
    with open(os.path.join(EVIDENCE, "gate_%s.json" % stamp), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=1, ensure_ascii=False)
    print(json.dumps({"verdict": report["verdict"], "steps": [(s["name"], s["state"]) for s in report["steps"]]},
                     ensure_ascii=False))
    return 0 if report["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
