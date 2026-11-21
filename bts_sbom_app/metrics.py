"""Prometheus-text metrics with a fixed, low-cardinality label set (task 17) - stdlib only.

Counters: ``bts_sbom_requests_total{route_class,status_class}`` (route_class is one of the fixed families from
obslog.route_class, never a raw path; status_class is 2xx/4xx/5xx), ``bts_sbom_jobs_total{state}``,
``bts_sbom_jobs_running``, job duration ``bts_sbom_job_seconds_sum``/``_count``, and the outbound fetch honesty
counters from net.STATS (``bts_sbom_net_failures_total``, ``bts_sbom_net_short_circuited_total``). Auth: the
route is served through the standard /api gate (cloud mode requires credentials), /healthz and /readyz stay open.
"""
from __future__ import annotations

import threading
import time
from typing import Any, Dict, List

from . import obslog

_LOCK = threading.Lock()
REQUESTS: Dict[str, int] = {}
JOBS: Dict[str, int] = {}
JOB_SECONDS: Dict[str, float] = {"sum": 0.0, "count": 0.0}
JOB_RUNNING = 0
_started = time.time()

ROUTE_CLASSES = ("chat", "fleet", "jobs", "llm", "metrics", "other", "probe", "sbom", "scan", "view")
STATUS_CLASSES = ("2xx", "4xx", "5xx")
JOB_STATES = ("done", "error", "interrupted", "running")


def status_class(status: int) -> str:
    if status < 400:
        return "2xx"
    if status < 500:
        return "4xx"
    return "5xx"


def observe_request(route: str, status: int) -> None:
    with _LOCK:
        key = "%s,%s" % (obslog.route_class(route), status_class(status))
        REQUESTS[key] = REQUESTS.get(key, 0) + 1


def observe_job(state: str, seconds: float = 0.0) -> None:
    global JOB_RUNNING
    with _LOCK:
        if state == "running":
            JOB_RUNNING += 1
            return
        if state == "done" or state == "error" or state == "interrupted":
            JOB_RUNNING = max(0, JOB_RUNNING - 1)              # the gauge follows reality: the job left the running set
            if state != "interrupted":
                JOB_SECONDS["sum"] += max(0.0, float(seconds))
                JOB_SECONDS["count"] += 1
        JOBS[state] = JOBS.get(state, 0) + 1


def running() -> int:
    with _LOCK:
        return JOB_RUNNING


def render(stats: Dict[str, Any]) -> str:
    """The Prometheus text exposition. Deterministic ordering; labels stay inside the fixed sets."""
    lines: List[str] = []
    with _LOCK:
        req = dict(REQUESTS)
        jobs = dict(JOBS)
        secs = dict(JOB_SECONDS)
        running_now = JOB_RUNNING
    lines.append("# HELP bts_sbom_requests_total API requests by route class and status class.")
    lines.append("# TYPE bts_sbom_requests_total counter")
    for rc in ROUTE_CLASSES:
        for sc in STATUS_CLASSES:
            v = req.get("%s,%s" % (rc, sc), 0)
            lines.append('bts_sbom_requests_total{route_class="%s",status_class="%s"} %d' % (rc, sc, v))
    lines.append("# HELP bts_sbom_jobs_total scan jobs by final state.")
    lines.append("# TYPE bts_sbom_jobs_total counter")
    for st in JOB_STATES:
        lines.append('bts_sbom_jobs_total{state="%s"} %d' % (st, jobs.get(st, 0)))
    lines.append("# HELP bts_sbom_jobs_running scan jobs currently running.")
    lines.append("# TYPE bts_sbom_jobs_running gauge")
    lines.append("bts_sbom_jobs_running %d" % running_now)
    lines.append("# HELP bts_sbom_job_seconds_sum accumulated wall-clock seconds of finished jobs.")
    lines.append("# TYPE bts_sbom_job_seconds_sum counter")
    lines.append("bts_sbom_job_seconds_sum %s" % round(secs["sum"], 3))
    lines.append("# TYPE bts_sbom_job_seconds_count counter")
    lines.append("bts_sbom_job_seconds_count %d" % int(secs["count"]))
    lines.append("# HELP bts_sbom_net_failures_total outbound fetch failures (could-not-check answers).")
    lines.append("# TYPE bts_sbom_net_failures_total counter")
    lines.append("bts_sbom_net_failures_total %d" % int(stats.get("failures") or 0))
    lines.append("# HELP bts_sbom_net_short_circuited_total calls skipped by an open circuit breaker.")
    lines.append("# TYPE bts_sbom_net_short_circuited_total counter")
    lines.append("bts_sbom_net_short_circuited_total %d" % int(stats.get("short_circuited") or 0))
    return "\n".join(lines) + "\n"
