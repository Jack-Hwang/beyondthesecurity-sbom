/*!
 * bts_chat_panel.js - the bottom chat dock of the BTS-SBOM screen: a Claude-Code-desktop-style conversation
 * panel that stays docked at the bottom of the content column on every tab, so the SBOM service can be driven
 * conversationally from anywhere (scan, findings, report, code intel, books - the panel follows the project
 * selected in the title bar).
 *
 * A turn = POST /api/chat/stream, and the 7 chat events (chat_stream.py) are rendered the way a coding agent
 * renders tool activity: one collapsible activity card per turn (step -> tool_call/tool_result rows ->
 * awaiting_approval banner with an inline approve button -> handoff -> final with the rendered answer).
 * The final event carries the answer body (added 2026-11-22), so the whole turn renders from the stream alone -
 * the JSON answer endpoint is not called a second time (one LLM budget per turn).
 *
 * Rules (same as bts_console.js): every dynamic value goes through esc()/textContent; no inline event handlers
 * (strict CSP); stream failures show an honest error line and keep the panel usable.
 */
(function () {
  'use strict';
  var root = document.getElementById('chatDock');
  if (!root) { return; }
  var U = window.BtsUi;
  if (!U) { root.textContent = 'bts_ui.js did not load, so the chat dock cannot start.'; return; }
  var esc = U.esc, note = U.note, heading = U.heading, kv = U.kv, val = U.val;

  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') { e.textContent = attrs[k]; } else if (k === 'class') { e.className = attrs[k]; } else { e.setAttribute(k, attrs[k]); }
    });
    (kids || []).forEach(function (c) { if (c) { e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); } });
    return e;
  }

  var KIND_LABEL = { step_start: '시작', tool_call: '도구 호출', tool_result: '도구 결과', awaiting_approval: '승인 대기',
                     handoff: '핸드오프', final: '완료', error: '오류' };
  var KIND_COLOR = { step_start: '#8b949e', tool_call: '#4493f8', tool_result: '#3fb950', awaiting_approval: '#d4a72c',
                     handoff: '#a371f7', final: '#3fb950', error: '#f85149' };
  var CHIPS = [
    ['프로젝트 요약', '이 프로젝트 개요를 요약해줘'],
    ['취약점 top', '가장 심각한 취약점 3개와 수정 방법 알려줘'],
    ['리포트 발행', '리포트를 Markdown으로 발행해줘'],
    ['아키텍처', '아키텍처 분석 결과 보여줘'],
    ['Code Intel', '코드 인텔 결과에서 복잡도와 데드코드 요약해줘'],
    ['책 검색', '책에서 fitness function 찾아줘']
  ];

  /* ---------- IF-A04 slash commands + IF-B04 다음 단계 (CCD 명세, ADR-0028) ---------- */
  /* app commands typed in the box: they drive the client and NEVER reach the model - one LLM budget per turn stays reserved for real questions */
  var SLASH = [
    ['scan', '스캔 판 열기 (/scan <대상>은 입력까지 채워 ▶ Analyze까지 실행)'],
    ['oss', '📜 OSS 결과 판'], ['report', '📊 리포트 판'], ['risk', '📊 Findings 판'], ['prioritize', '🎯 SSVC 판'],
    ['arch', '🏛 Arch Intel 판'], ['code', '🔎 Code Intel 판'], ['diagrams', '🗺 Diagrams 판'], ['books', '📚 Book KB 판'],
    ['compliance', '✅ SBOM checks 판'], ['vex', '📋 VEX·결정 판'], ['fix', '🔧 Fix Plan 판'], ['history', '⚙️ CI/CD·이력 판'], ['fleet', '🗂 Fleet 판']
  ];
  var SLASH_GO = { scan: 'git', oss: 'oss', report: 'report', risk: 'risk', findings: 'risk', prioritize: 'ssvc',
                   arch: 'archintel', code: 'code', diagrams: 'diagrams', books: 'books', compliance: 'ntia',
                   vex: 'vex', fix: 'fix-plan', history: 'more', fleet: 'fleet' };
  function openPanel(sv, noteText) {
    document.dispatchEvent(new CustomEvent('bts:activate', { detail: sv }));
    if (noteText) {
      msgs.appendChild(el('div', { 'class': 'bts-cd-turn', text: '📦 ' + noteText }));
      scrollEnd();
    }
  }
  function runSlash(q) {
    var m = /^\/([a-z]+)\b\s*(.*)$/i.exec(q);
    if (!m) { return false; }
    var cmd = m[1].toLowerCase(), arg = (m[2] || '').trim();
    userLine(q);
    if (cmd === 'help') {
      var help = el('div', { 'class': 'bts-cd-turn' });
      help.appendChild(el('div', { 'class': 'sub', text: '앱 명령 - 모델 호출 없이 이 클라이언트를 구동한다 (IF-A04):' }));
      SLASH.forEach(function (s) { help.appendChild(el('div', { text: '/' + s[0] + ' - ' + s[1] })); });
      msgs.appendChild(help);
      scrollEnd();
      return true;
    }
    if (cmd === 'scan' && arg) {
      var run = document.getElementById('runScaReport'), inp = document.getElementById('scaGitUrl');
      if (!run || !inp) {
        msgs.appendChild(el('div', { 'class': 'bts-cd-turn', text: '스캔 폼을 찾지 못했다 - 🌐 Scan 판에서 직접 실행하라.' }));
        scrollEnd();
        return true;
      }
      openPanel('git');
      inp.value = arg;
      run.click();                                     // the unified Analyze: main pipeline + OSS scan (ADR-0026)
      msgs.appendChild(el('div', { 'class': 'bts-cd-turn', text: '▶ Analyze 실행: ' + arg + ' - 진행은 스캔 판의 단계 바, 결과는 📊 Report와 📜 OSS 결과에.' }));
      scrollEnd();
      return true;
    }
    var go = SLASH_GO[cmd];
    if (!go) {
      msgs.appendChild(el('div', { 'class': 'bts-cd-turn', text: "모르는 명령 '/" + cmd + "' - /help 로 목록을 볼 수 있다." }));
      scrollEnd();
      return true;
    }
    openPanel(go, go + ' 판을 열었다.');
    return true;
  }
  /* the zone-5 "다음 단계 상자": a finished turn offers the panel that matches the tools it actually used */
  var NEXT = {
    top_vulns: ['risk', '📊 Findings 판 보기'], vuln_lookup: ['risk', '📊 Findings 판 보기'],
    proposals: ['fix-plan', '🔧 Fix Plan 판 보기'], plan_patch: ['fix-pr', '🔧 Patch 판 보기'],
    latest_arch: ['archintel', '🏛 Arch Intel 판 보기'], book_search: ['books', '📚 Book KB 판 보기'],
    sbom_conformance: ['conformance', '📐 SBOM conformance 판 보기'], what_changed: ['changes', '🔔 What changed 판 보기'],
    coverage: ['ntia', '✅ SBOM checks 판 보기'], license_risks: ['license-risk', '⚖ License Risk 판 보기'],
    draw_diagram: ['diagrams', '🗺 Diagrams 판 보기'], overview: ['report', '📊 Report 판 보기']
  };

  /* ---------- DOM ---------- */
  var bar = el('button', { type: 'button', 'class': 'bts-cd-bar', id: 'chatDockBar' });
  var body = el('div', { 'class': 'bts-cd-body', id: 'chatDockBody' });
  var msgs = el('div', { 'class': 'bts-cd-msgs', id: 'chatDockMsgs' });
  var chipsRow = el('div', { 'class': 'bts-cd-chips' });
  CHIPS.forEach(function (c) {
    var ch = el('button', { type: 'button', 'class': 'bts-cd-chip', text: c[0] });
    ch.addEventListener('click', function () { input.value = c[1]; input.focus(); });
    chipsRow.appendChild(ch);
  });
  var input = el('input', { id: 'chatDockQ', placeholder: 'SBOM 어시스턴트에게 질문…  (예: django-nV 취약점 요약해줘 / 책에서 circuit breaker 찾아줘)', spellcheck: 'false' });
  var llmChk = el('input', { type: 'checkbox', id: 'chatDockLlm', title: 'EXAONE/Azure LLM 사용 (미연결 시 규칙 기반으로 정직하게 강등)' });
  var llmLab = el('label', { 'class': 'bts-cd-llm', title: llmChk.title }, [llmChk, document.createTextNode(' LLM')]);
  var sendBtn = el('button', { type: 'button', 'class': 'run', id: 'chatDockSend', text: '\u27A4 보내기' });
  var clearBtn = el('button', { type: 'button', 'class': 'bts-cd-clear', id: 'chatDockClear', title: '이 프로젝트의 대화를 지운다', text: '\u232B' });
  var inputRow = el('div', { 'class': 'bts-cd-input' }, [input, clearBtn, llmLab, sendBtn]);
  body.appendChild(msgs);
  body.appendChild(chipsRow);
  body.appendChild(inputRow);
  root.appendChild(bar);
  root.appendChild(body);

  var open = /\bopen\b/.test(root.className);   // the markup decides the initial state - it ships open as the main conversation surface
  var busy = false;
  function setBar() {
    bar.textContent = '';
    var mark = el('span', { 'class': 'bts-cd-mark', text: '\uD83D\uDCAC SBOM 어시스턴트' });
    var status = el('span', { 'class': 'bts-cd-status', text: busy ? '응답 생성 중…' : (open ? '' : '클릭해서 열기') });
    bar.appendChild(mark);
    bar.appendChild(status);
    bar.appendChild(el('span', { 'class': 'bts-cd-caret', text: open ? '\u25BC' : '\u25B2' }));
    body.style.display = open ? '' : 'none';
  }
  bar.addEventListener('click', function () { open = !open; root.className = 'bts-chatdock' + (open ? ' open' : ' collapsed'); setBar(); if (open) { input.focus(); scrollEnd(); } });
  setBar();

  function scrollEnd() { msgs.scrollTop = msgs.scrollHeight; }

  /* ---------- conversation memory (CCD CL-12 Local Data Store 아날로그): per-project, this browser only.
     The select is also moved PROGRAMMATICALLY (selectProject from the rail sessions and the history
     auto-pick - a value change fires no event), so the single sync point is the bts:project event that
     selectProject dispatches; the dock follows it instead of second-guessing the select. ---------- */
  var shownKey = null;                                       // the store key whose conversation msgs currently shows
  function keyFor(p) { return 'bts-chat-' + (p || '(no project)'); }
  function saveShown() {
    try {
      var out = [];
      Array.prototype.forEach.call(msgs.children, function (node) {
        if (node.classList.contains('bts-cd-turn-user')) { out.push({ t: 'u', text: node.textContent }); }
        else if (node.classList.contains('bts-cd-turn')) {
          var ans = node.querySelector('.bts-cd-answer');
          if (ans) {
            var clone = ans.cloneNode(true);                 // dead controls never persist
            Array.prototype.forEach.call(clone.querySelectorAll('.bts-cd-approve, .bts-cd-next'), function (x) { x.parentNode.removeChild(x); });
            out.push({ t: 'a', html: clone.innerHTML });     // our own escaped rendering, same origin only
          }
        }
      });
      localStorage.setItem(shownKey, JSON.stringify(out));
    } catch (e) { /* storage unavailable: the conversation simply does not persist */ }
  }
  function loadShown() {
    try {
      var raw = localStorage.getItem(shownKey);
      msgs.textContent = '';
      if (!raw) { return; }
      JSON.parse(raw).forEach(function (row) {
        if (row.t === 'u') { msgs.appendChild(el('div', { 'class': 'bts-cd-turn-user', text: row.text })); }
        else if (row.t === 'a') {
          var turn = el('div', { 'class': 'bts-cd-turn' });
          var box = el('div', { 'class': 'bts-cd-answer' });
          box.innerHTML = row.html;                          // saved from our own rendering; approve/next rows were stripped
          turn.appendChild(box);
          msgs.appendChild(turn);
        }
      });
    } catch (e) { msgs.textContent = ''; }
    scrollEnd();
  }
  function followProject(name) {
    var key = keyFor(name);
    if (shownKey === null) {                                 // first sync: keep any pre-project turns under their own key
      shownKey = keyFor('(no project)');
      if (msgs.childElementCount) { saveShown(); }
      shownKey = key;
      loadShown();
      return;
    }
    if (key === shownKey) { return; }
    saveShown();
    shownKey = key;
    loadShown();
  }
  clearBtn.addEventListener('click', function () {
    try { localStorage.removeItem(shownKey); } catch (e) { /* same as save */ }
    msgs.textContent = '';
  });
  document.addEventListener('bts:project', function (e) { followProject(e && e.detail); });

  /* ---------- rendering ---------- */
  function userLine(text) {
    msgs.appendChild(el('div', { 'class': 'bts-cd-turn-user', text: text }));
    scrollEnd();
  }
  function activityRow(kind, seq, summary) {
    var row = el('div', { 'class': 'bts-cd-act' });
    row.style.borderLeftColor = KIND_COLOR[kind] || '#8b949e';
    row.appendChild(el('span', { 'class': 'bts-cd-act-kind', text: '#' + seq + ' ' + (KIND_LABEL[kind] || kind) }));
    row.appendChild(el('span', { 'class': 'bts-cd-act-body' }));
    row.lastChild.textContent = summary || '';
    return row;
  }
  function answerHtml(fin) {
    // the final event carries the whole answer contract - render it like U.renderChatAnswer does for /api/chat
    var h = '<div class="bts-chat-out">' + esc((fin.found ? '' : '[not found] ') + (fin.answer || '')) + '</div>';
    h += '<div class="bts-chat-src">source: ' + esc(fin.answer_source) + ' · citation accuracy: ' + esc(fin.citation_accuracy) +
      ' · routing: ' + esc(fin.routing || 'n/a') + (fin.routing_note ? ' · ' + esc(fin.routing_note) : '') + '</div>';
    var tops = fin.retrieval_top || [];
    if (tops.length) {
      h += '<div class="bts-chat-chips">' + tops.map(function (t) {
        return '<span class="bts-chat-chip" title="rrf ' + esc(t.rrf) + '">' + esc(t.heading || t.source) +
          ' <span class="bts-chat-chip-src">' + esc(t.source) + '</span></span>';
      }).join('') + '</div>';
    }
    if (fin.contains_untrusted) {
      h += note('Contains untrusted third-party quotes - shown verbatim, never obeyed.', 'warn');
    }
    (fin.conflicts || []).forEach(function (c) {
      h += note('<b>[conflict]</b> ' + esc(c.label) + ': ' + esc(c.a.value) + ' (' + esc(c.a.source) + ') vs ' +
        esc(c.b.value) + ' (' + esc(c.b.source) + ') - the sources disagree; the judgement stays with you.', 'warn');
    });
    /* diagrams drawn mid-conversation (ADR-0024): same markup contract as the Diagrams tab - the Mermaid
       source rides in a hidden pre, renderDiagramsIn() below draws it (source text is the honest fallback). */
    (fin.diagrams || []).forEach(function (dg) {
      if (!dg || !dg.mermaid) { return; }
      h += '<div class="bts-diagram arc-dwrap"><div class="bts-diagram-title">' + esc(dg.name || 'diagram') + '</div>' +
        '<div class="arc-diagram"></div><pre class="arc-mermaid-src" hidden>' + esc(dg.mermaid) + '</pre>' +
        (dg.note ? '<div class="bts-diagram-note">' + esc(dg.note) + '</div>' : '') + '</div>';
    });
    return h;
  }

  /* ---------- mermaid (vendored, lazy; same contract as arch_intel.js) ---------- */
  var mermaidPromise = null;
  function ensureMermaid() {
    if (window.mermaid) { return Promise.resolve(window.mermaid); }
    if (!mermaidPromise) {
      mermaidPromise = new Promise(function (resolve, reject) {
        var s = document.createElement('script');
        s.src = '/static/vendor/mermaid.min.js';
        s.onload = function () {
          if (window.mermaid) {
            try { window.mermaid.initialize({ startOnLoad: false, securityLevel: 'strict' }); } catch (e) { /* keep defaults */ }
            resolve(window.mermaid);
          } else { reject(new Error('mermaid loaded but the global is missing')); }
        };
        s.onerror = function () { reject(new Error('cannot load /static/vendor/mermaid.min.js')); };
        document.head.appendChild(s);
      }).catch(function (e) { mermaidPromise = null; throw e; });
    }
    return mermaidPromise;
  }
  var diagramSeq = 0;
  function renderDiagramsIn(scope) {
    Array.prototype.forEach.call((scope || msgs).querySelectorAll('.arc-dwrap'), function (wrap) {
      var holder = wrap.querySelector('.arc-diagram');
      var src = wrap.querySelector('.arc-mermaid-src');
      if (!holder || !src || holder.childElementCount) { return; }
      var text = src.textContent || '';
      if (!text.trim()) { return; }
      ensureMermaid().then(function (m) {
        return m.render('btscd-' + Date.now() + '-' + diagramSeq++, text);
      }).then(function (out) {
        holder.innerHTML = out.svg;                     // mermaid strict mode; the source is server-sanitized
        src.hidden = true;
        scrollEnd();
      }).catch(function () {
        src.hidden = false;                             // fallback: show the Mermaid source, still the honest diagram
      });
    });
  }
  function approveRow(token) {
    var row = el('div', { 'class': 'bts-cd-approve' });
    row.appendChild(el('span', { text: '승인 대기 토큰: ' }));
    row.appendChild(el('code', { text: token }));
    var btn = el('button', { type: 'button', 'class': 'run', text: '\u2713 이 토큰으로 승인' });
    btn.addEventListener('click', function () { send('계획 적용 승인 ' + token); });
    row.appendChild(btn);
    row.appendChild(el('span', { 'class': 'sub', text: '승인은 사람이 - 서버가 --chat-actions로 열렸을 때만 실제 적용된다' }));
    return row;
  }

  /* ---------- the turn (SSE) ---------- */
  function send(text) {
    var q = (text !== undefined ? text : input.value).trim();
    if (!q || busy) { return; }
    input.value = '';
    if (runSlash(q)) { saveShown(); return; }         // app commands never reach the model (IF-A04)
    busy = true;
    setBar();
    userLine(q);
    var turnTools = [];                                      // the tools this turn actually ran -> 다음 단계 suggestions
    var projSel = document.getElementById('projSel');
    var project = projSel && projSel.value ? projSel.value : undefined;
    var turn = el('div', { 'class': 'bts-cd-turn' });
    var card = el('details', { 'class': 'bts-cd-card' });
    card.appendChild(el('summary', { text: '활동 보기' }));
    var actBox = el('div', { 'class': 'bts-cd-card-body' });
    card.appendChild(actBox);
    var answerBox = el('div', { 'class': 'bts-cd-answer' });
    answerBox.innerHTML = note('생각하고 도구를 돌리는 중…', 'warn');
    turn.appendChild(answerBox);
    turn.appendChild(card);
    msgs.appendChild(turn);
    scrollEnd();

    var fin = null;
    var done = false;
    var pendingToken = null;
    function finish() {
      if (done) { return; }
      done = true;
      busy = false;
      setBar();
      if (fin) {
        answerBox.innerHTML = answerHtml(fin);
        if (pendingToken) { answerBox.appendChild(approveRow(pendingToken)); }   // the approval outlives the final render
        renderDiagramsIn(answerBox);                    // draw the turn's diagrams (ADR-0024)
        var summ = el('summary', { text: '활동 보기 (' + actBox.querySelectorAll('.bts-cd-act').length + ')' });
        var old = card.querySelector('summary');
        if (old) { card.replaceChild(summ, old); }
        var seen = {}, next = el('div', { 'class': 'bts-cd-next' });
        turnTools.forEach(function (t) {                // zone-5 다음 단계 상자: only panels the turn actually touched
          var n = NEXT[t];
          if (!n || seen[n[0]]) { return; }
          seen[n[0]] = 1;
          var b = el('button', { type: 'button', 'class': 'bts-cd-next-b', text: n[1] });
          b.addEventListener('click', function () { openPanel(n[0]); });
          next.appendChild(b);
        });
        if (next.childElementCount) {
          next.insertBefore(el('span', { 'class': 'sub', text: '다음 단계: ' }), next.firstChild);
          answerBox.appendChild(next);
        }
      } else if (!answerBox.querySelector('.bts-note.bad')) {
        answerBox.innerHTML = note('스트림이 응답 없이 끝났다 - 다시 질문 가능.', 'warn');
      }
      saveShown();                                      // the turn (or its honest partial) persists for this project
      scrollEnd();
    }

    fetch('/api/chat/stream', { method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ question: q, project: project || undefined, use_llm: llmChk.checked }) }).then(function (res) {
      if (!res.ok || !res.body) { throw new Error('HTTP ' + res.status); }
      var reader = res.body.getReader(), dec = new TextDecoder(), buf = '';
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) { finish(); return; }
          buf += dec.decode(chunk.value, { stream: true });
          var parts = buf.split('\n\n');
          buf = parts.pop();
          parts.forEach(function (block) {
            var lines = block.split('\n'), ev = '';
            var datas = [];
            lines.forEach(function (ln) {
              if (ln.indexOf('event: ') === 0) { ev = ln.slice(7); }
              else if (ln.indexOf('data: ') === 0) { datas.push(ln.slice(6)); }
            });
            if (ev && datas.length) {
              try { handle(ev, JSON.parse(datas.join('\n'))); } catch (e) { /* malformed event: skip, keep the stream */ }
            }
          });
          return pump();
        });
      }
      return pump();
    }).catch(function (e) {
      answerBox.innerHTML = note('스트림 실패: ' + esc(String(e)) + ' - 대화 상태는 유지된다, 다시 시도 가능.', 'bad');
      finish();
    });
    function handle(ev, d) {
      if (ev === 'step_start') { actBox.appendChild(activityRow(ev, d.seq, '"' + (d.question || '') + '"')); }
      else if (ev === 'tool_call') {
        if (turnTools.indexOf(d.tool) < 0) { turnTools.push(d.tool); }
        actBox.appendChild(activityRow(ev, d.seq, d.tool + ' ' + JSON.stringify(d.args || {})));
      }
      else if (ev === 'tool_result') { actBox.appendChild(activityRow(ev, d.seq, d.tool + ' — ' + d.lines + '줄')); }
      else if (ev === 'handoff') {
        var h = d.handoff || {};
        actBox.appendChild(activityRow(ev, d.seq, 'routing ' + (h.context || {}).routing + ' · accuracy ' + (h.context || {}).citation_accuracy +
          ((h.not_passed || []).length ? ' · 미충족 ' + (h.not_passed || []).join(', ') : ' · 제약 3종 통과')));
      } else if (ev === 'awaiting_approval') {
        actBox.appendChild(activityRow(ev, d.seq, d.note || ''));
        if (d.token) { pendingToken = d.token; scrollEnd(); }   // the approve row survives the final render (finish re-appends it)
      } else if (ev === 'error') {
        var en = d.envelope || {};
        actBox.appendChild(activityRow(ev, d.seq, en.error_type + ' (' + en.severity + ') - ' + (en.coverage_gap || '')));
      } else if (ev === 'final') {
        fin = d;
      }
      scrollEnd();
    }
  }
  sendBtn.addEventListener('click', function () { send(); });
  input.addEventListener('keydown', function (e) { if (e.key === 'Enter') { send(); } });
})();
