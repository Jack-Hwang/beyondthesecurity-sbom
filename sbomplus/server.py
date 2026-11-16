"""Small stdlib HTTP service: JSON API + single-page UI for scan jobs and the grounded chatbot.

POST /api/scan   {source, patch?, approved?, use_llm?}  -> {job}   (runs in a background thread; origin never modified)
GET  /api/jobs/<id>                                     -> status + metrics + artifact paths
POST /api/chat   {question, project?, use_llm?}         -> grounded answer with verified claims
GET  /api/projects                                      -> analysed projects (from the evidence folder)
GET  /api/health
Binds to 127.0.0.1 by default. There is no authentication: do not expose it beyond localhost without a reverse proxy.
Scan sources are restricted to https/ssh/file git URLs, owner/repo shorthands and EXISTING local folders.
"""
from __future__ import annotations

import json
import os
import tempfile
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, Optional

from . import chat as chatmod, evals, pipeline
from .cli import evidence_chunks, load_projects
from .llm import ChatClient

_PAGE = """<!doctype html><html lang="ko"><meta charset="utf-8"><title>SBOM+</title>
<style>body{font:14px system-ui;max-width:920px;margin:2rem auto;padding:0 1rem}input,button{font:inherit;padding:6px 10px}input{width:70%}
pre{background:#f5f5f5;padding:10px;overflow:auto;white-space:pre-wrap}.row{margin:12px 0}h2{margin-top:28px}</style>
<h1>SBOM+</h1>
<div class="row"><input id="src" placeholder="GitHub URL, owner/repo, or local folder"> <button onclick="scan()">Analyse</button>
<label><input type="checkbox" id="llm" style="width:auto"> EXAONE</label></div><pre id="job">idle</pre>
<h2>Ask</h2><div class="row"><input id="q" placeholder="e.g. CVE-2018-18074 ? / licenses ? / architecture ?"> <button onclick="ask()">Ask</button></div><pre id="ans"></pre>
<script>
async function j(u,b){const r=await fetch(u,b?{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}:{});return r.json()}
async function scan(){const s=document.getElementById('src').value;const r=await j('/api/scan',{source:s,use_llm:document.getElementById('llm').checked});
 if(r.error){document.getElementById('job').textContent=r.error;return}
 const id=r.job;for(;;){const st=await j('/api/jobs/'+id);document.getElementById('job').textContent=JSON.stringify(st,null,1);if(st.state!=='running')break;await new Promise(x=>setTimeout(x,1500))}}
async function ask(){const r=await j('/api/chat',{question:document.getElementById('q').value});
 document.getElementById('ans').textContent=(r.found?'':'[not found] ')+r.answer+'\\n\\nsource: '+r.answer_source+' | citation accuracy: '+r.citation_accuracy}
</script></html>"""


class State:
    def __init__(self, root: str, evidence: str, cfg: Optional[str]):
        self.root, self.evidence = root, evidence
        self.jobs: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        if cfg:
            os.environ["SBOMPLUS_LLM_CONFIG"] = cfg
        self.client = ChatClient.from_env(ledger=os.path.join(root, "evidence", ".llm_ledger.json"))

    def bot(self) -> chatmod.Chatbot:
        projs = load_projects(self.evidence)
        return chatmod.Chatbot(evals.build_index(self.root, evidence_chunks(projs)), projs, self.client if self.client.available else None)


def _safe_source(src: str) -> Optional[str]:
    from .workspace import normalize_source
    try:
        spec = normalize_source(src)
    except ValueError as exc:
        return str(exc)
    if spec["kind"] == "local" and not os.path.exists(spec["path"]):
        return "local path does not exist"
    return None


def make_handler(st: State):
    class H(BaseHTTPRequestHandler):
        def log_message(self, *a: Any) -> None:
            pass

        def _send(self, code: int, obj: Any, ctype: str = "application/json") -> None:
            body = (obj if isinstance(obj, str) else json.dumps(obj, ensure_ascii=False, default=str)).encode("utf-8")
            self.send_response(code)
            self.send_header("Content-Type", ctype + "; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self) -> Dict[str, Any]:
            n = min(int(self.headers.get("Content-Length") or 0), 1_000_000)
            try:
                return json.loads(self.rfile.read(n).decode("utf-8") or "{}")
            except ValueError:
                return {}

        def do_GET(self) -> None:                                    # noqa: N802
            if self.path in ("/", "/index.html"):
                return self._send(200, _PAGE, "text/html")
            if self.path == "/api/health":
                return self._send(200, {"ok": True, "llm": st.client.describe()})
            if self.path == "/api/projects":
                return self._send(200, {"projects": sorted(load_projects(st.evidence))})
            if self.path.startswith("/api/jobs/"):
                j = st.jobs.get(self.path.rsplit("/", 1)[-1])
                return self._send(200 if j else 404, j or {"error": "unknown job"})
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:                                   # noqa: N802
            b = self._body()
            if self.path == "/api/scan":
                src = str(b.get("source") or "")
                bad = _safe_source(src)
                if bad:
                    return self._send(400, {"error": bad})
                jid = uuid.uuid4().hex[:10]
                st.jobs[jid] = {"state": "running", "source": src}

                def work() -> None:
                    try:
                        rec = pipeline.run_project(src, work_root=tempfile.mkdtemp(prefix="sbomplus_job_"), out_dir=st.evidence,
                                                   patch=bool(b.get("patch")), approved=bool(b.get("approved")), use_llm=bool(b.get("use_llm")),
                                                   client=st.client if st.client.available else None,
                                                   cache_dir=os.path.join(st.root, "evidence", "cache"))
                        st.jobs[jid] = {"state": "error" if rec.get("error") else "done", "source": src, "error": rec.get("error"),
                                        "metrics": rec.get("metrics"), "artifacts": rec.get("artifacts"), "stage_errors": rec.get("stage_errors")}
                    except Exception as exc:                          # noqa: BLE001
                        st.jobs[jid] = {"state": "error", "source": src, "error": "%s: %s" % (type(exc).__name__, str(exc)[:200])}

                threading.Thread(target=work, daemon=True).start()
                return self._send(202, {"job": jid})
            if self.path == "/api/chat":
                q = str(b.get("question") or "").strip()
                if not q:
                    return self._send(400, {"error": "question required"})
                return self._send(200, st.bot().ask(q, project=b.get("project"), use_llm=bool(b.get("use_llm"))))
            self._send(404, {"error": "not found"})

    return H


def serve(root: str, host: str, port: int, evidence: str, cfg: Optional[str] = None) -> int:
    st = State(root, evidence, cfg)
    httpd = ThreadingHTTPServer((host, port), make_handler(st))
    print("SBOM+ serving on http://%s:%d (evidence: %s)" % (host, port, evidence), flush=True)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0
