/* bts_stream.js — chat-level SSE step stream (MetaNet 4주차 3차시, D3+D4).
 * Talks to POST /api/chat/stream: one SSE record per chat event
 * (step_start / tool_call / tool_result / awaiting_approval / handoff / final / error).
 * The timeline shows events in arrival order; an awaiting_approval banner renders the patch-gate
 * states server-side (events.PATCH_GATE_STATES) and reminds that only the user closes the loop.
 * Deliberately independent of bts_console.js (which another workstream owns). */
(function () {
  "use strict";

  var KIND_LABEL = {
    step_start: "시작",
    tool_call: "툴 호출",
    tool_result: "툴 결과",
    awaiting_approval: "승인 대기",
    handoff: "핸드오프",
    final: "최종",
    error: "오류"
  };
  var KIND_COLOR = {
    step_start: "#909399",
    tool_call: "#409eff",
    tool_result: "#67c23a",
    awaiting_approval: "#e6a23c",
    handoff: "#909399",
    final: "#67c23a",
    error: "#f56c6c"
  };

  function el(tag, text) {
    var n = document.createElement(tag);
    if (text != null) n.textContent = text;
    return n;
  }

  function row(ev) {
    var wrap = el("div");
    wrap.style.cssText = "display:flex;gap:8px;align-items:baseline;font-size:13px;padding:4px 8px;" +
      "border-left:3px solid " + (KIND_COLOR[ev.kind] || "#ccc") + ";background:#fafafa;border-radius:4px";
    var badge = el("span", "#" + ev.seq + " " + (KIND_LABEL[ev.kind] || ev.kind));
    badge.style.cssText = "font-weight:600;color:" + (KIND_COLOR[ev.kind] || "#333") + ";white-space:nowrap";
    wrap.appendChild(badge);
    var body = "";
    if (ev.kind === "tool_call") body = ev.tool + "(" + JSON.stringify(ev.args || {}) + ")";
    else if (ev.kind === "tool_result") body = ev.tool + " -> " + (ev.lines || 0) + "줄";
    else if (ev.kind === "final") body = "출처=" + ev.answer_source + " · 인용정확도=" + ev.citation_accuracy + (ev.llm_note ? " · " + ev.llm_note : "");
    else if (ev.kind === "error" && ev.envelope) {
      var e = ev.envelope;
      body = "[" + e.severity + "] " + e.error_type + " · 재시도예산=" + e.retry_budget +
        " · 완료된 단계=" + (e.completed_steps || []).join(",") + (e.coverage_gap ? " · 갭: " + e.coverage_gap : "");
    } else if (ev.kind === "handoff" && ev.handoff) {
      body = "스키마=" + ev.handoff.schema_version + " · 라우팅=" + (ev.handoff.context || {}).routing +
        " · 제약 " + (ev.handoff.constraints || []).length + "건" +
        ((ev.handoff.not_passed || []).length ? " · 미통과: " + ev.handoff.not_passed.join("; ") : "");
    } else if (ev.kind === "awaiting_approval") {
      body = "게이트=" + ev.gate + " · 상태=" + ev.state + (ev.token ? " · 토큰=" + ev.token : "") +
        (ev.note ? " · " + ev.note : "");
    } else if (ev.kind === "step_start") {
      body = ev.question || "";
    }
    wrap.appendChild(el("span", body));
    return wrap;
  }

  function gapBanner(msg) {
    var g = document.getElementById("streamGap");
    g.textContent = msg;
    g.style.display = "block";
  }

  function run() {
    var q = document.getElementById("streamQ").value.trim();
    if (!q) return;
    var tl = document.getElementById("streamTimeline");
    tl.textContent = "";
    document.getElementById("streamGap").style.display = "none";
    fetch("/api/chat/stream", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ question: q, use_llm: !!(window.chatLlm && window.chatLlm.checked) })
    }).then(function (res) {
      if (!res.ok || !res.body) throw new Error("HTTP " + res.status);
      var reader = res.body.getReader(), buf = "";
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) return;
          buf += new TextDecoder("utf-8").decode(chunk.value, { stream: true });
          var idx;
          while ((idx = buf.indexOf("\n\n")) >= 0) {           // one SSE record per blank line
            var rec = buf.slice(0, idx); buf = buf.slice(idx + 2);
            var data = rec.split("\n").filter(function (l) { return l.indexOf("data: ") === 0; })
              .map(function (l) { return l.slice(6); }).join("\n");
            if (!data) continue;
            var ev;
            try { ev = JSON.parse(data); } catch (e) { continue; }
            tl.appendChild(row(ev));
            if (ev.kind === "awaiting_approval") {
              gapBanner("승인 대기 (" + ev.gate + "): 아무것도 변경되지 않았습니다. 계획을 검토한 뒤 사용자가 직접 승인 토큰으로 답해야 적용됩니다." +
                (ev.token ? " 토큰: " + ev.token : ""));
            }
          }
          return pump();
        });
      }
      return pump();
    }).catch(function (err) {
      gapBanner("스트림 실패: " + err.message);
    });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var btn = document.getElementById("streamBtn");
    if (!btn) return;
    btn.addEventListener("click", run);
    document.getElementById("streamQ").addEventListener("keydown", function (e) {
      if (e.key === "Enter") run();
    });
  });
})();
