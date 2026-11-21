/*!
 * arch_intel.js - the "Arch Intel" pane of the BTS-SBOM screen: license verdict + AI architecture deep-dive
 * (components, sequence, activity, live code excerpts, notice checklist) of one open-source source tree.
 * Written for BTS-SBOM. Rules (same as bts_console.js): every dynamic value is put into the page with
 * textContent / setAttribute or through ArchIntelRender/BtsUi (which escape); no inline event handlers (strict
 * Content-Security-Policy); a view says "not available" instead of showing a made-up value. The Mermaid renderer
 * is vendored under /static/vendor/mermaid.min.js (see NOTICE.md) and loaded lazily on first use; if it cannot
 * load, every diagram falls back to its Mermaid source text.
 */
(function () {
  'use strict';
  var root = document.getElementById('paneArchIntel');
  if (!root) { return; }
  var R = window.ArchIntelRender;

  var S = { job: null, timer: null, running: false };

  var STAGES = [['prepare', 'Prepare'], ['license', 'License'], ['structure', 'Structure'], ['ai', 'AI analysis'],
                ['anchors', 'Code anchors'], ['persist', 'Persist']];

  function el(tag, attrs, kids) {
    var e = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) {
      if (k === 'text') { e.textContent = attrs[k]; } else if (k === 'class') { e.className = attrs[k]; } else { e.setAttribute(k, attrs[k]); }
    });
    (kids || []).forEach(function (c) { if (c) { e.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); } });
    return e;
  }
  function api(url, body) {
    var opt = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    return fetch(url, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, data: d }; });
    }).catch(function (e) { return { ok: false, status: 0, data: { error: String(e) } }; });
  }

  /* ---------- layout ---------- */
  var form = el('div', { 'class': 'pathbox' });
  var source = el('input', { id: 'arcSource', placeholder: 'https://github.com/org/repo.git   -or-   owner/repo   -or-   D:\\path\\to\\project', spellcheck: 'false', style: 'flex:1;min-width:340px;font-family:ui-monospace,monospace' });
  var ref = el('input', { id: 'arcRef', placeholder: 'branch / tag (git)', spellcheck: 'false', style: 'width:150px' });
  var dist = el('select', { id: 'arcDist', title: 'How you intend to use this code - drives the license verdict' });
  [['binary', 'redistribute (binary)'], ['saas', 'serve as SaaS'], ['internal', 'internal use only']].forEach(function (d) {
    var o = el('option', { value: d[0], text: d[1] });
    dist.appendChild(o);
  });
  var lang = el('select', { id: 'arcLang', title: 'Language of the AI narrative' });
  [['ko', 'AI: Korean'], ['en', 'AI: English']].forEach(function (d) {
    lang.appendChild(el('option', { value: d[0], text: d[1] }));
  });
  var useLlm = el('input', { type: 'checkbox', checked: 'checked' });
  var useLlmLabel = el('label', { 'class': 'oss-chk', title: 'Ask LG EXAONE for the architecture analysis (needs a configured key; without one the deterministic view is used)' }, [useLlm, ' EXAONE']);
  var runBtn = el('button', { 'class': 'run', type: 'button', text: '\u25B6 Analyze' });
  var cancelBtn = el('button', { 'class': 'run', type: 'button', text: 'Cancel', style: 'background:#333;display:none' });

  form.appendChild(el('label', { text: 'Deep-dive one open-source tree: license verdict + AI architecture (components, sequence, activity) + live code anchors' }));
  var row1 = el('div', { 'class': 'oss-row' }, [source, ref, runBtn, cancelBtn]);
  var row2 = el('div', { 'class': 'oss-row' }, [el('span', { 'class': 'sub', text: 'Usage:' }), dist,
    el('span', { 'class': 'sub', text: 'Narrative:' }), lang, useLlmLabel]);
  form.appendChild(row1);
  form.appendChild(row2);
  form.appendChild(el('div', { 'class': 'ex', text: 'The tree is read in an isolated copy (git clone with hooks disabled) and never executed. The AI prompt carries metadata only - file paths, sizes, import edges - never source code. Excerpts shown under "Live code" are the original work: keep them inside this tool.' }));

  var banner = el('div', {});
  var progress = el('div', { 'class': 'oss-steps' });
  var result = el('div', {});
  var historyBox = el('div', { 'class': 'arc-history' });
  root.appendChild(form);
  root.appendChild(banner);
  root.appendChild(progress);
  root.appendChild(result);
  root.appendChild(el('details', { 'class': 'arc-histbox' }, [
    el('summary', { text: 'Past runs' }), historyBox]));

  /* ---------- progress ---------- */
  function chips(stage) {
    progress.textContent = '';
    if (!stage) { return; }
    STAGES.forEach(function (s) {
      var cls = 'oss-step';
      var idx = STAGES.map(function (x) { return x[0]; }).indexOf(stage);
      var mine = STAGES.map(function (x) { return x[0]; }).indexOf(s[0]);
      if (mine < idx) { cls += ' done'; } else if (mine === idx) { cls += ' on'; }
      progress.appendChild(el('span', { 'class': cls, text: s[1] }));
    });
  }

  /* ---------- mermaid (vendored, lazy) ---------- */
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

  function renderDiagrams(scope) {
    var wraps = (scope || result).querySelectorAll('.arc-dwrap');
    Array.prototype.forEach.call(wraps, function (wrap, i) {
      var holder = wrap.querySelector('.arc-diagram');
      var src = wrap.querySelector('.arc-mermaid-src');
      if (!holder || !src) { return; }
      var text = src.textContent || '';
      if (!text.trim()) { return; }
      ensureMermaid().then(function (m) {
        return m.render('arc-d-' + i + '-' + Date.now(), text);
      }).then(function (out) {
        holder.innerHTML = out.svg;                       // mermaid strict mode, source sanitized server-side
        src.hidden = true;
      }).catch(function () {
        src.hidden = false;                               // fallback: show the Mermaid source text
      });
    });
  }

  /* ---------- result tabs ---------- */
  function wireTabs() {
    result.addEventListener('click', function (ev) {
      var t = ev.target && ev.target.closest ? ev.target.closest('[data-arc-tab]') : null;
      if (!t) { return; }
      var name = t.getAttribute('data-arc-tab');
      Array.prototype.forEach.call(result.querySelectorAll('[data-arc-tab]'), function (b) {
        b.className = 'arc-tab' + (b === t ? ' on' : '');
      });
      Array.prototype.forEach.call(result.querySelectorAll('[data-arc-sec]'), function (sec) {
        sec.className = 'arc-sec' + (sec.getAttribute('data-arc-sec') === name ? ' on' : '');
      });
      renderDiagrams(result);
    });
  }

  function showResult(doc) {
    result.textContent = '';
    if (!R) {
      result.appendChild(el('div', { 'class': 'bts-note bad', text: 'renderer module missing' }));
      return;
    }
    var div = el('div', {});
    div.innerHTML = R.result(doc || {});
    result.appendChild(div);
    wireTabs();
    renderDiagrams(result);
  }

  function note_(text, cls) {
    banner.textContent = '';
    banner.appendChild(el('div', { 'class': 'bts-note ' + (cls || ''), text: text }));
  }

  /* ---------- job lifecycle ---------- */
  function setRunning(on) {
    S.running = on;
    runBtn.disabled = on;
    cancelBtn.style.display = on ? '' : 'none';
  }

  function poll() {
    api('/api/arch/jobs/' + S.job).then(function (r) {
      if (!r.ok) {
        setRunning(false);
        chips(null);
        note_('job state unavailable: ' + ((r.data && r.data.error) || ('HTTP ' + r.status)), 'bad');
        return;
      }
      chips(r.data.stage === 'queued' ? 'queued' : r.data.stage === 'done' ? null : r.data.stage);
      if (r.data.state === 'running') { S.timer = setTimeout(poll, 800); return; }
      setRunning(false);
      chips(null);
      if (r.data.state === 'cancelled') { note_('Analysis cancelled.', 'warn'); return; }
      if (r.data.state === 'error') { note_('Analysis failed: ' + (r.data.error || 'unknown error'), 'bad'); return; }
      api('/api/arch/result/' + S.job).then(function (r2) {
        if (!r2.ok) { note_('result unavailable: ' + ((r2.data && r2.data.error) || ('HTTP ' + r2.status)), 'bad'); return; }
        banner.textContent = '';
        showResult(r2.data);
        loadHistory();
      });
    });
  }

  function run() {
    var src = source.value.trim();
    if (!src) { note_('Give a local folder or a git URL first.', 'warn'); return; }
    setRunning(true);
    note_('Queued\u2026', '');
    result.textContent = '';
    chips('queued');
    api('/api/arch/scan', { source: src, ref: ref.value.trim(), use_llm: useLlm.checked,
                            lang: lang.value, distribution: dist.value }).then(function (r) {
      if (!r.ok) {
        setRunning(false);
        chips(null);
        note_(((r.data && r.data.error) || ('HTTP ' + r.status)), 'bad');
        return;
      }
      S.job = r.data.job;
      poll();
    });
  }

  function cancelJob() {
    if (!S.job) { return; }
    api('/api/arch/jobs/' + S.job + '/cancel', {}).then(function () { note_('Cancelling\u2026', 'warn'); });
  }

  function loadHistory() {
    api('/api/arch/history').then(function (r) {
      historyBox.textContent = '';
      if (!R) { return; }
      var div = el('div', {});
      div.innerHTML = R.history(r.ok ? (r.data && r.data.history) : []);
      historyBox.appendChild(div);
    });
  }

  runBtn.addEventListener('click', run);
  cancelBtn.addEventListener('click', cancelJob);
  loadHistory();
})();
