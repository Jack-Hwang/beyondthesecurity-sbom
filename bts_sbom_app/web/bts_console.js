/*!
 * bts_console.js - page logic of the BTS-SBOM open-source security screen.
 * Written for BTS-SBOM; the renderer it drives (sca_app.js) and the platform stylesheets are copied unmodified (see NOTICE.md).
 * Rules: every dynamic value goes through esc() (analysed data comes from untrusted repositories and registries); no inline
 * event handlers (the page is served with a strict Content-Security-Policy); a pane shows "not computed" instead of a made-up value.
 * The markup helpers live in bts_ui.js and the SBOM-governance renderers (conformance, what changed, VEX + decisions, fleet) in
 * bts_governance.js; both are loaded before this file. This file fetches the data and wires the page.
 */
(function () {
  'use strict';
  var U = window.BtsUi, G = window.BtsGovernance;
  if (!U || !G) {
    document.body.insertAdjacentHTML('afterbegin', '<div class="bts-note bad" style="margin:12px">The page scripts bts_ui.js / bts_governance.js did not load, so this screen cannot start.</div>');
    return;
  }

  var GROUPS = {
    'git': ['git', 'oss', 'lock', 'container'], 'risk': ['risk', 'changes'], 'prioritize': ['ssvc', 'epss', 'exploit-mat'],
    'graph-health': ['dep-graph', 'arch', 'code', 'db', 'supply-chain'], 'compliance': ['ntia', 'conformance', 'cra', 'vex', 'license-risk', 'sectors'],
    'fix': ['fix-plan', 'fix-pr', 'reimpl'], 'report': ['report'], 'archintel': ['archintel'], 'diagrams': ['diagrams'],
    'books': ['books'], 'more': ['more', 'fleet']
  };
  /* the Claude-client rail (CCD "Code 탭 화면 해부" + IF-B04): the sidebar is a SESSION list first and the
     feature panels live inside five collapsed sections - every pane stays reachable, but the menu no longer
     dominates the screen (사용자 지시 2026-11-22: "메뉴를 주요 기능으로 통합, claude client 기능으로 따라서"). */
  var SECTIONS = [
    { icon: '🔎', label: '분석 스캔', groups: ['git'] },
    { icon: '📊', label: '결과와 우선순위', groups: ['risk', 'prioritize'] },
    { icon: '🗄', label: '리포트와 구조', groups: ['report', 'archintel', 'diagrams', 'graph-health'] },
    { icon: '📚', label: '지식과 컴플라이언스', groups: ['books', 'compliance'] },
    { icon: '🔧', label: '수정과 운영', groups: ['fix', 'more'] }
  ];
  var LABELS = {
    'git': '🌐 Scan', 'lock': '📦 Lockfile / path', 'container': '🐳 Container', 'risk': '📊 Findings', 'changes': '🔔 What changed',
    'prioritize': '🎯 Prioritize', 'graph-health': '🕸 Graph & Health', 'compliance': '✅ Compliance', 'fix': '🔧 Fix',
    'ssvc': '🎯 SSVC', 'epss': '📡 EPSS', 'exploit-mat': '🔥 Exploit Mat.', 'dep-graph': '🕸 Dep Graph',
    'arch': '🏛 Architecture', 'code': '🔎 Code Intel', 'db': '🗄 DB 질의', 'supply-chain': '⛓ Supply Chain', 'ntia': '✅ SBOM checks', 'conformance': '📐 SBOM conformance',
    'vex': '📋 VEX · Decisions', 'license-risk': '⚖ License Risk', 'sectors': '🏭 Industry reports', 'fix-plan': '🔧 Fix Plan',
    'cra': '🇪🇺 CRA',
    'fix-pr': '🔧 Patch', 'reimpl': '🧬 Clean-Room', 'oss': '📜 OSS 결과', 'report': '📊 Report', 'archintel': '🏛 Arch Intel', 'diagrams': '🖼 Diagrams',
    'books': '📚 Book KB', 'more': '⚙️ CI/CD · History', 'fleet': '🗂 Fleet · Affected'
  };
  var SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  var SEV_COLOR = U.SEV_COLOR;
  var STEPS = ['Input', 'Configure', 'Analyze', 'Results'];
  // gov: the per-project API results of the selected project (null = still loading); seq drops answers for a project that is no longer selected.
  // fleet / affected: the portfolio roll-up and the last "who is affected" search (null = not asked yet).
  var S = { project: '', view: null, triage: {}, history: [], members: {}, lastJob: null, busy: false,
            gov: { seq: 0, conformance: null, changes: null, vex: null }, fleet: null, affected: null };

  /* ---------- helpers (markup helpers: bts_ui.js) ---------- */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  var esc = U.esc, H = U.H, table = U.table, sevBadge = U.sevBadge, pill = U.pill, note = U.note, heading = U.heading, kv = U.kv,
      unavailable = U.unavailable, when = U.when;
  function api(url, body) {
    var opt = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    return fetch(url, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, data: d }; });
    }).catch(function (e) { return { ok: false, status: 0, data: { error: String(e) } }; });
  }
  function needProject() {
    return note('No project is selected. Analyse a repository on the <b>Scan</b> tab, or pick an analysed project in the title bar.');
  }
  function fixedAt(f) { return f ? esc(f) : '—'; }
  function btn(label, act, extra, attrs) {
    return '<button type="button" class="run" data-act="' + esc(act) + '"' + (attrs || '') + (S.busy && extra === 'job' ? ' disabled' : '') + '>' + label + '</button>';
  }

  /* ---------- the Claude-client rail: sessions first, feature panels collapsed, assistant at the bottom ---------- */
  function buildSideNav() {
    var nav = $('#sideNav');
    if (!nav) { return; }
    var h = '<div class="bts-sidenav-brand">\u2699 BTS-SBOM</div>';
    h += '<button type="button" class="bts-rail-new" data-act="new">\uFF0B \uC0C8 \uBD84\uC11D</button>';
    h += '<div class="bts-rail-h">\u2699 \uBD84\uC11D \uC138\uC158</div><div id="railSessions" class="bts-rail-sessions"></div>';
    SECTIONS.forEach(function (s) {
      h += '<details class="bts-rail-grp"><summary class="rtab" data-sv="' + esc(s.groups[0]) + '" role="button" tabindex="0">' +
           s.icon + ' ' + esc(s.label) + '</summary>';
      s.groups.forEach(function (g) {
        (GROUPS[g] || []).forEach(function (m) {
          h += '<button type="button" class="bts-rail-chip" data-act="goto" data-sv="' + esc(m) + '">' + esc(LABELS[m] || m) + '</button>';
        });
      });
      h += '</details>';
    });
    h += '<button type="button" class="bts-rail-assist" data-act="assist">\uD83D\uDCAC \uC5B4\uC2DC\uC2A4\uD134\uD2B8</button>';
    nav.innerHTML = h;
    renderRailSessions();
  }
  function renderRailSessions() {
    var box = $('#railSessions');
    if (!box) { return; }
    if (!S.history.length) { box.innerHTML = '<div class="bts-rail-empty">\uBD84\uC11D \uAE30\uB85D\uC774 \uC5C6\uB2E4.</div>'; return; }
    box.innerHTML = S.history.slice(0, 12).map(function (h) {
      return '<button type="button" class="bts-rail-session' + (h.name === S.project ? ' on' : '') + '" data-act="session" data-name="' + esc(h.name) + '" title="' + esc(h.source || '') + '">' +
        '<span class="bts-rail-session-n">' + esc(h.name) + '</span>' +
        '<span class="bts-rail-session-t">' + esc(String(h.analysed_at || '').replace('T', ' ').slice(0, 16)) + '</span></button>';
    }).join('');
  }
  function focusAssistant() {
    var dock = $('#chatDock'), bar = $('#chatDockBar');
    if (dock && bar && dock.className.indexOf('open') < 0) { bar.click(); }
    var q = $('#chatDockQ');
    if (q) { q.focus(); if (q.scrollIntoView) { q.scrollIntoView({ block: 'center' }); } }
  }
  function groupOf(sv) {
    for (var g in GROUPS) { if (GROUPS[g].indexOf(sv) >= 0) { return g; } }
    return null;
  }
  function subnav(group, member) {
    var bar = $('#scanSubNav'), members = GROUPS[group] || [group];
    if (members.length <= 1) { bar.style.display = 'none'; bar.innerHTML = ''; return; }
    bar.style.display = 'flex';
    bar.innerHTML = members.map(function (m) {
      return '<button type="button" class="scan-subchip' + (m === member ? ' on' : '') + '" data-act="goto" data-sv="' + esc(m) + '">' + esc(LABELS[m] || m) + '</button>';
    }).join('');
  }
  /* exact=true: a sub-tab chip (or an explicit pane id) must open exactly that member; only the sidebar's
     GROUP button restores the member the user visited last (sv === group). Without the exact path the first
     member chip of a group can never reopen its own pane (e.g. the Scan landing after visiting OSS 결과). */
  function activate(sv, exact) {
    var group = sv, member = sv;
    if ($('#view-scan .rtab[data-sv="' + sv + '"]')) { member = (GROUPS[sv] && GROUPS[sv][0]) || sv; }
    else { group = groupOf(sv); if (!group) { return; } }
    if (!exact && sv === group && S.members[group] && GROUPS[group].indexOf(S.members[group]) >= 0) { member = S.members[group]; }
    S.members[group] = member;
    $$('#view-scan .rtab').forEach(function (x) { x.classList.toggle('active', x.getAttribute('data-sv') === group); });
    $$('#view-scan .rpane').forEach(function (p) { p.classList.toggle('on', p.getAttribute('data-sv') === member); });
    subnav(group, member);
    if (member === 'report') { renderConsole(); }     // the report tab owns the only ScaApp mount: re-render on entry
  }

  /* ---------- 1-4 step bar (same markup as the platform) ---------- */
  function setStep(step, msg, isError) {
    var row = $('#scaInputRow'), bar = $('#scaWorkflow');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'scaWorkflow';
      bar.className = 'analysis-workflow';
      bar.innerHTML = STEPS.map(function (l, i) { return '<div class="aw-step" data-step="' + (i + 1) + '">' + (i + 1) + '. ' + l + '</div>'; }).join('') +
        '<div class="aw-message"></div>';
      row.parentNode.insertBefore(bar, row);   // the bar sits ABOVE the unified input row: inside it the flex row would wrap apart
    }
    var failed = !!isError;           // toggle(name, undefined) would FLIP the class instead of clearing it
    $$('.aw-step', bar).forEach(function (el, i) {
      el.classList.toggle('done', i + 1 < step && !failed);
      el.classList.toggle('active', i + 1 === step && !failed);
      el.classList.toggle('error', i + 1 === step && failed);
    });
    $('.aw-message', bar).textContent = msg || '';
  }
  function setBusy(b) {
    S.busy = b;
    ['#runScaReport', '#scaDemoBtn', '#runLock'].forEach(function (s) { var e = $(s); if (e) { e.disabled = b; } });
    $$('[data-act="plan"],[data-act="apply"]').forEach(function (e) { e.disabled = b || (e.getAttribute('data-act') === 'apply' && !($('#ackPlan') || {}).checked); });
  }

  /* ---------- jobs ---------- */
  function runJob(body, label) {
    if (S.busy) { return Promise.resolve(); }
    setBusy(true);
    setStep(2, label + ': starting.');
    return api('/api/scan', body).then(function (r) {
      if (!r.ok) { setStep(1, (r.data && r.data.error) || ('HTTP ' + r.status), true); return null; }
      var id = r.data.job, t0 = Date.now();
      /* live stage progress (the job's SSE stream): the polling loop alone only ticks seconds, which reads as
         a hang on a big tree like u-boot (measured 2026-11-23: ~5 min of silent "running (N s)") */
      var seen = {};
      watchJobEvents(id, function (ev, d) {
        if (d && d.name && (ev === 'step_start' || ev === 'step_end')) {
          seen[d.name] = (ev === 'step_end') ? (d.ok === false ? 'fail' : 'ok') : 'run';
          var done = Object.keys(seen).filter(function (k) { return seen[k] !== 'run'; }).length;
          var cur = Object.keys(seen).filter(function (k) { return seen[k] === 'run'; }).pop();
          setStep(3, label + ': ' + (cur ? ('stage ' + cur) : 'warming up') + ' · ' + done + ' stage(s) done · ' +
            Math.round((Date.now() - t0) / 1000) + ' s');
        } else if (ev === 'patch_gate' && d.state === 'awaiting_approval') {
          setStep(3, label + ': patch plan awaits approval (digest ' + (d.digest || '') + ').');
        }
      });
      return new Promise(function (resolve) {
        (function poll() {
          api('/api/jobs/' + encodeURIComponent(id)).then(function (j) {
            var d = j.data || {};
            if (d.state === 'running') {
              if (!Object.keys(seen).length) {                   // SSE owns the message once events arrive
                setStep(3, label + ': analysis engines are running (' + Math.round((Date.now() - t0) / 1000) + ' s).');
              }
              setTimeout(poll, 1500);
              return;
            }
            resolve(d);
          });
        })();
      });
    }).then(function (job) {
      setBusy(false);
      if (!job) { return null; }
      S.lastJob = job;
      if (job.state !== 'done') { setStep(3, job.error || 'The analysis failed.', true); return null; }
      var m = job.metrics || {};
      setStep(4, 'Done: ' + (m.components || 0) + ' components, ' + (m.vulns || 0) + ' findings in ' + (m.elapsed_s || '?') + ' s.');
      return loadHistory().then(function () { return selectProject(job.name, true).then(function () { return job; }); });
    });
  }
  function analyse(src) {
    src = (src || '').trim();
    if (!src) { setStep(1, 'Enter a repository URL, a local path or an archive.', true); return; }
    var ossOpts = window.BtsOss ? window.BtsOss.readForm() : null;      // modes/excludes/branch from the unified landing form
    runJob({ source: src, offline: !!$('#scaOffline').checked, use_llm: !!$('#scaLlm').checked }, 'Analysis').then(function (job) {
      var ok = job && job.state === 'done';
      if (ok) { activate('report'); }                                    // the report has its own tab now
      runOssChain(src, ossOpts, ok);   // one Analyze, two engines: the OSS stage runs even when the main pipeline cannot read the target (archives)
    });
  }
  /* runOssChain: the same target through the OSS Scanner engine (source / dependency / binary chosen on the
     landing form), so the platform deliverables (OSS notice / spreadsheet) exist without a second manual entry
     point. The stage never skips silently: a missing engine script or an empty mode selection is reported, the
     stage runs even when the main pipeline failed on the same target (e.g. an archive the pipeline cannot read),
     and every failure note states what happened to the main result. Same DOM rules as renderConsole: note()
     returns an HTML string whose dynamic parts must be esc()ed, then a real button node is appended (the page
     CSP forbids inline handlers). */
  function runOssChain(src, opts, mainOk) {
    var banner = $('#scaBanner');
    if (!banner) { return; }
    if (!window.BtsOss) { banner.innerHTML = note('OSS 엔진 스크립트가 로드되지 않았다 — OSS 단계는 실행되지 않았다.', 'bad'); return; }
    if (!opts) { banner.innerHTML = note('OSS 분석 유형이 하나도 선택되지 않았다 — OSS 단계는 건너뛰었다.', 'warn'); return; }
    if (!mainOk) { banner.innerHTML = note('메인 파이프라인이 이 대상을 분석하지 못했다(사유는 단계 바에 있다) — OSS 스캔만 계속 실행한다.', 'warn'); }
    setStep(4, 'OSS Scanner: scanning the same target (' + opts.modes.join(' + ') + ')…');
    window.BtsOss.start(src, opts).then(function (r) {
      if (r && r.superseded) { return; }                                 // a newer Analyze took over the OSS stage
      if (!r || !r.ok) {
        banner.innerHTML = note('OSS 성과물 생성 실패: ' + esc((r && r.error) || 'unknown') + ' — ' + (mainOk ? '메인 분석 결과는 정상이다.' : '메인 파이프라인도 이 대상은 분석하지 못했다.'), 'bad');
        return;
      }
      banner.innerHTML = note('OSS 성과물 완료 (job ' + esc(r.id) + ') — 공개문·엑셀·바이너리 목록은 📜 OSS 결과 탭에 있다.', 'ok');
      var view = document.createElement('button');
      view.type = 'button';
      view.className = 'bts-mini';
      view.textContent = '📜 OSS 결과에서 보기';
      view.addEventListener('click', function () { activate('oss'); });
      banner.appendChild(view);
    });
  }

  /* ---------- engine, history, project ---------- */
  function loadEngine() {
    return api('/api/engine').then(function (r) {
      var e = r.data || {}, core = e.core || {};
      var c = core.version ? 'bts_sbom ' + core.version : 'bts_sbom unavailable (' + (core.error || 'unknown') + ')';
      var l = (e.llm && e.llm.key_configured) ? 'EXAONE configured' : 'EXAONE not configured (rule-based proposals and answers)';
      $('#engineTxt').textContent = c + ' · ' + l + ' · ' + (e.projects || 0) + ' project(s) in the evidence folder';
      $('#statusTxt').textContent = 'BTS-SBOM workflow ' + (e.workflow_version || '') + ' · evidence: ' + (e.evidence || '');
    });
  }
  function fillSelect() {
    var sel = $('#projSel');
    sel.innerHTML = S.history.length ? S.history.map(function (h) { return '<option value="' + esc(h.name) + '">' + esc(h.name) + '</option>'; }).join('')
                                     : '<option value="">(none analysed yet)</option>';
    if (S.project) { sel.value = S.project; }
  }
  /* ---------- EXAONE connection (key typed in the page; the server never sends the key back, only its masked tail) ---------- */
  function loadLlm() {
    return api('/api/llm').then(function (r) {
      var d = (r && r.data) || {};
      $('#llmStatus').textContent = d.key_configured
        ? 'connected: ' + (d.model || '') + (d.key_tail ? ' (key …' + d.key_tail + ')' : '') + (d.saved ? ' · saved in the evidence folder' : '')
        : 'not connected (rule-based proposals and answers)';
      $('#llmKey').value = '';                       // the key is never echoed back into the page
      return d;
    });
  }
  function connectLlm() {
    var body = { api_key: ($('#llmKey').value || '').trim(), model: ($('#llmModel').value || '').trim(), remember: !!$('#llmSave').checked };
    if (!body.api_key) { $('#llmStatus').textContent = 'Enter an API key first.'; return; }
    api('/api/llm', body).then(function (r) {
      if (!r.ok) { $('#llmStatus').textContent = (r.data && r.data.error) || 'Connection failed.'; return; }
      $('#llmKey').value = '';
      loadEngine();                                  // the engine line reflects key_configured
      return loadLlm();
    });
  }
  function clearLlm() {
    api('/api/llm/clear', {}).then(function () { loadEngine(); return loadLlm(); });
  }
  function loadHistory() {
    return api('/api/history').then(function (r) {
      S.history = (r.data && r.data.history) || [];
      fillSelect(); renderHistory(); renderRailSessions();           // the rail session list refreshes with the history
      loadFleet();                                                     // the roll-up covers the same evidence folder: refresh it with the list
    });
  }
  function selectProject(name, keepStep) {
    if (!name) { S.project = ''; S.view = null; resetGovernance(); renderAll();
      document.dispatchEvent(new CustomEvent('bts:project', { detail: '' }));   // the dock swaps its conversation
      return Promise.resolve(); }
    S.project = name;
    $('#projSel').value = name;
    document.dispatchEvent(new CustomEvent('bts:project', { detail: name }));   // the dock swaps its conversation
    return Promise.all([api('/api/view/' + encodeURIComponent(name)), api('/api/triage')]).then(function (rs) {
      if (!rs[0].ok) {
        S.view = null;
        resetGovernance();
        $('#reportOut').innerHTML = note(esc((rs[0].data && rs[0].data.error) || 'The project could not be loaded.'), 'bad');
        renderPanes();
        return;
      }
      S.view = rs[0].data;
      S.triage = (rs[1].data && rs[1].data.triage) || {};
      renderAll();
      loadGovernance(name);
      if (!keepStep) { setStep(4, 'Showing ' + name + ' (analysed ' + when(S.view.analysed_at) + ').'); }
    });
  }

  /* ---------- SBOM governance data: conformance, what changed, OpenVEX with decisions, fleet ---------- */
  function resetGovernance() {
    S.gov = { seq: S.gov.seq + 1, conformance: null, changes: null, vex: null, cra: null };
  }
  function loadGovernance(name) {
    resetGovernance();
    var seq = S.gov.seq, n = encodeURIComponent(name);
    renderGovernance();
    [['conformance', '/api/conformance/'], ['changes', '/api/changes/'], ['vex', '/api/vex/'], ['cra', '/api/cra/']].forEach(function (p) {
      api(p[1] + n).then(function (r) {
        if (S.gov.seq !== seq || S.project !== name) { return; }      // another project was selected meanwhile
        S.gov[p[0]] = r;
        renderGovernance();
      });
    });
  }
  function loadFleet() {
    return api('/api/fleet').then(function (r) { S.fleet = r; renderGovernance(); });
  }

  /* ---------- EU CRA (Regulation (EU) 2024/2847): readiness, security.txt, support period, Article 14 clock, annex-J ledgers ---------- */
  var CRA_ST = { pass: 'ok', partial: 'warn', gap: 'bad' };
  function craClockLine(e) {
    var c = e.clock || {}, f = function (s) { return s && s.due ? esc(s.due) + ' <span class="bts-pill ' + (s.status === 'overdue' ? 'bad' : 'ok') + '">' + esc(s.status) + '</span>' : '<span class="sub">—</span>'; };
    return '<b>' + esc(e.id) + '</b> (' + esc(e.kind) + ') T0 ' + esc(e.aware_at) +
      '<br>24h 조기 경보: ' + f(c.early_warning) + ' · 72h 통보: ' + f(c.notification) + ' · 최종 보고: ' + f(c.final_report);
  }
  function craPane(p) {
    if (!p) { return heading('EU CRA') + note('readiness 데이터를 불러오는 중…'); }
    var r = p.readiness || {}, sc = r.score || {}, n = encodeURIComponent(p.project);
    var out = heading('EU CRA compliance', 'Regulation (EU) 2024/2847 · K-OSSC 실무 가이드 v1.0');
    out += kv([['Readiness', (sc.pass || 0) + ' pass · ' + (sc.partial || 0) + ' partial · ' + (sc.gap || 0) + ' gap → ' + (sc.pct || 0) + '%'],
               ['security.txt', p.security_txt && p.security_txt.deployed ? pill('deployed', 'ok') : pill('not deployed', 'bad')],
               ['지원 기간', p.support && p.support.declared ? esc(p.support.declared_end || p.support.declared) + ' · ' + esc(p.support.status) : '미선언']]);
    (r.checks || []).forEach(function (c) {
      out += note('<b>' + esc(c.title) + '</b> ' + pill(c.status, CRA_ST[c.status] || 'muted') + ' <span class="sub">' + esc(c.ref) + '</span><br>' +
        esc(c.basis) + (c.fix ? '<br><span class="sub">→ ' + esc(c.fix) + '</span>' : ''), c.status === 'gap' ? 'bad' : '');
    });
    out += heading('security.txt', 'RFC 9116 · CRA Annex I Part II (5)/(6)');
    out += (p.security_txt && p.security_txt.preview) ? H('<pre>' + esc(p.security_txt.preview) + '</pre>')
      : note(esc((p.security_txt && p.security_txt.note) || '미배포'), 'warn');
    out += heading('지원 기간 선언', 'Article 13(8): 최소 5년 · Annex II 7: 최소 연·월');
    out += '<div class="bts-actions"><input id="craSupportEnd" placeholder="YYYY-MM (예: 2032-06)" size="16">' +
      btn('선언 저장', 'cra-support') +
      btn('EOL 대장 유지 플래그 ' + (p.eol_maintained ? '끄기' : '켜기'), 'cra-eol') + '</div>';
    out += heading('Article 14 보고 시계', '2026-09-11부터 적용 중 · 24h → 72h → 14일(취약점)/1개월(사고)');
    out += '<div class="bts-actions"><input id="craAevId" placeholder="CVE-… / 사고 ID" size="16">' +
      '<select id="craAevKind"><option value="aev">악용 취약점</option><option value="incident">심각한 사고</option></select>' +
      '<input id="craAevAware" placeholder="T0 인지 시각(비우면 지금)" size="18">' + btn('인지 기록', 'cra-aev') + '</div>';
    (p.awareness || []).forEach(function (e) { out += note(craClockLine(e), 'warn'); });
    out += heading('SBOM 관리 5종 대장', 'guide annex J');
    out += '<div class="bts-actions">' + [1, 2, 3, 4, 5].map(function (i) {
      return btn('⬇ 대장 ' + i, 'dl', '', ' data-url="/api/cra/' + n + '/ledgers?which=' + i + '"');
    }).join('') + '</div>';
    return out + note(esc(r.note || ''), 'warn');
  }
  function craReload() {
    return api('/api/cra/' + encodeURIComponent(S.project)).then(function (r) {
      if (r.ok) { S.gov.cra = r.data; renderGovernance(); }
    });
  }
  function bindCraPane() {
    var pane = $('#paneCra');
    if (!pane || pane.dataset.craBound) { return; }
    pane.dataset.craBound = '1';
    /* delegated on the persistent container: renderGovernance rewrites this pane's innerHTML (the db-pane lesson) */
    pane.addEventListener('click', function (e) {
      var t = e.target;
      if (!t || !t.getAttribute) { return; }
      var act = t.getAttribute('data-act'), n = encodeURIComponent(S.project || '');
      if (act === 'cra-support') {
        api('/api/cra/' + n + '/support', { support_end: ($('#craSupportEnd') ? $('#craSupportEnd').value : '').trim() }).then(function (r) {
          toolNote(r.ok ? '지원 기간 저장됨: ' + esc((((r.data || {}).validation || {}).status) || '?') : ('실패: ' + esc((r.data || {}).error || r.status)));
          return craReload();
        });
      } else if (act === 'cra-eol') {
        api('/api/cra/' + n + '/eol-maintained', { maintained: !((S.gov.cra || {}).eol_maintained) }).then(function (r) {
          toolNote(r.ok ? 'EOL 대장 유지 플래그 갱신됨' : ('실패: ' + esc((r.data || {}).error || r.status)));
          return craReload();
        });
      } else if (act === 'cra-aev') {
        var id = ($('#craAevId') ? $('#craAevId').value : '').trim();
        if (!id) { toolNote('CVE id 또는 사고 ID를 입력하라.'); return; }
        var body = { id: id, kind: $('#craAevKind') ? $('#craAevKind').value : 'aev' };
        var aware = ($('#craAevAware') ? $('#craAevAware').value : '').trim();
        if (aware) { body.aware_at = aware; }
        api('/api/cra/' + n + '/article14', body).then(function (r) {
          toolNote(r.ok ? '인지 기록됨 - 24h 조기 경보 시한이 이 팬에 표시된다' : ('실패: ' + esc((r.data || {}).error || r.status)));
          return craReload();
        });
      }
    });
  }
  function analysedMap() {
    var m = Object.create(null);
    S.history.forEach(function (h) { m[h.name] = h.analysed_at; });
    return m;
  }

  /* ---------- console (sca_app.js) ---------- */
  // sca_app.js hard-codes the platform label "AutoGuard" in two places (organisation badge, breadcrumb) and has no option for it.
  // The file must stay a byte-for-byte copy, so the product name is corrected here, after every (re)render.
  function rebrand(mount) {
    $$('.sx-org', mount).forEach(function (e) { if (e.textContent.indexOf('AutoGuard') >= 0) { e.textContent = '▣ BTS-SBOM ▾'; } });
    $$('.sx-crumb', mount).forEach(function (e) {
      var n = e.firstChild;
      if (n && n.nodeType === 3 && n.nodeValue.indexOf('AutoGuard') >= 0) { n.nodeValue = n.nodeValue.replace('AutoGuard', 'BTS-SBOM'); }
    });
    /* honest pass banner: a green "No known vulnerabilities detected" under a 0-component or unknown-presence
       projection contradicts the warn banner above it (measured on a manifest-less C tree, 2026-11-23) */
    var pass = $('.sx-banner.pass .sx-banner-msg', mount);
    if (pass && S.view) {
      var eng = S.view.engine || {};
      var comp = ((S.view.report || {}).components) || 0;
      if (eng.vulnerability_presence !== 'none' || comp === 0) {
        var why = comp === 0 ? '구성요소 0 — 쿼리할 매니페스트 구성요소가 없다(결과는 unknown, 통과가 아니다)'
                             : '쿼리 상태 ' + (eng.vulnerability_presence || 'unknown') + ' — 모든 구성요소가 답을 받은 것이 아니다';
        pass.innerHTML = 'Unknown — not a pass: ' + esc(why);
        var box = pass.closest('.sx-banner');
        if (box) { box.classList.remove('pass'); box.classList.add('warn'); }
      }
    }
  }
  function watchBrand() {
    var mount = $('#reportOut');
    new MutationObserver(function () { rebrand(mount); }).observe(mount, { childList: true, subtree: true });
  }
  function download(url, fname) {
    var a = document.createElement('a');
    a.href = url; a.download = fname || '';
    document.body.appendChild(a); a.click(); a.remove();
  }
  function toolNote(text) {
    if (window.ScaApp && window.ScaApp.setToolOutput) {
      var d = document.createElement('div'); d.className = 'sx-note'; d.textContent = text; window.ScaApp.setToolOutput(d);
    }
  }
  function proxy(btnId) {
    if (!S.project) { return; }
    var n = encodeURIComponent(S.project);
    if (btnId === 'dlSbomFmt') {
      var sel = $('#sxSbomFmt'), f = sel ? sel.value : 'cdx';
      if (f === 'cdx' || f === 'spdx') { download('/api/sbom/' + n + '?format=' + f); }
      else { toolNote('SPDX tag-value output is not produced by BTS-SBOM; use the CycloneDX or SPDX JSON download.'); }
    } else if (btnId === 'dlReport') { download('/api/doc/' + n); }
    else { toolNote('This export is not available in BTS-SBOM; use the CycloneDX / SPDX / Markdown downloads.'); }
  }
  function triage(id, status, noteText) {
    return api('/api/triage', { check_id: id, status: status, note: noteText || '' }).then(function (r) {
      if (!r.ok) { throw new Error((r.data && r.data.error) || ('HTTP ' + r.status)); }
      return selectProject(S.project).then(function () { return true; });
    });
  }
  function renderConsole() {
    var mount = $('#reportOut'), banner = $('#reportBanner'), head = $('#reportHead');
    if (!mount) { return; }
    banner.innerHTML = '';
    if (!window.BtsReport) { head.innerHTML = ''; }
    else { head.innerHTML = BtsReport.renderHead(S.view); }
    if (!S.view) {
      mount.innerHTML = note('아직 연 프로젝트가 없다 — 왼쪽 레일에서 세션을 고르거나 <b>+ 새 분석</b>으로 스캔하면 이 리포트가 채워진다. (스캔 전까지 이 화면은 비어 있는 게 아니라 "알 수 없음"이다.)', 'warn');
      $('#govCards').innerHTML = '';
      return;
    }
    var rep = S.view.report, b = rep.bts || {};
    if (b.empty_project) {
      banner.innerHTML = note('<b>No supported manifest or lockfile was found in this source.</b> The result is <b>unknown</b>, not "no vulnerabilities".', 'warn');
    } else if (b.data_status && b.data_status !== 'complete') {
      banner.innerHTML = note('<b>Vulnerability data is "' + esc(b.data_status) + '".</b> Some packages were not authoritatively queried, so the counts are a lower bound.', 'warn');
    }
    if (!window.ScaApp) { mount.innerHTML = note('The console renderer (sca_app.js) did not load.', 'bad'); return; }
    window.ScaApp.render(mount, rep, {
      proxy: proxy, triage: triage, triageCached: function () { return S.triage; },
      testedLabel: S.view.analysed_at ? 'Analysed ' + when(S.view.analysed_at) : ''
    });
    renderGovCards();
  }
  /* The three governance cards of the Report tab. Coverage and conformance are fetched lazily, once per
     project; a failed fetch shows an honest "not loaded" line in the card instead of a made-up number. */
  function renderGovCards() {
    var box = $('#govCards');
    if (!box || !window.BtsReport || !S.project) { return; }
    var gc = S.govReport;
    if (!gc || gc.name !== S.project) { gc = S.govReport = { name: S.project, coverage: null, conformance: null, fetched: false }; }
    box.innerHTML = BtsReport.renderGovCards({ view: S.view, coverage: gc.coverage, conformance: gc.conformance });
    if (gc.fetched) { return; }
    gc.fetched = true;
    var n = encodeURIComponent(S.project);
    api('/api/coverage/' + n).then(function (r) {
      gc.coverage = r.ok ? r.data : { error: (r.data && r.data.error) || ('HTTP ' + r.status) };
      renderGovCards();
    });
    api('/api/conformance/' + n).then(function (r) {
      gc.conformance = r.ok ? r.data : { error: (r.data && r.data.error) || ('HTTP ' + r.status) };
      renderGovCards();
    });
  }

  /* ---------- DB 인텔: 로컬 OSV DB에 자연어 질문 (nl2sql, 3주차 강의 기능) ---------- */
  function dbIntel(v) {
    var out = heading('DB 질의 (NL2SQL)', '로컬 OSV 데이터베이스에 자연어로 묻는다 — 읽기 전용 SELECT, 행 수 제한, 4상태 응답');
    out += '<div class="bts-formbox"><div class="bts-fields"><label for="dbQ">질문</label>' +
      '<input id="dbQ" placeholder="예: 생태계별 취약점 수 알려줘 / django의 취약점 목록 / 전체 취약점 개수" spellcheck="false"></div>' +
      '<div class="bts-actions"><button type="button" class="run" id="dbQBtn">▶ 질의</button>' +
      '<button type="button" class="bts-mini" id="dbSchemaBtn">스키마 보기</button></div>' +
      '<div class="bts-small">NL2SQL(3주차 강의 기능): 질문이 SQL로 변환되어 로컬 OSV DB(읽기 전용)에서 실행된다. ' +
      'DB가 없으면 정직하게 안내한다. 쓰기·여러 문장은 검증기가 차단한다.</div></div>';
    out += '<div id="paneDbOut"></div>';
    return out;
  }
  function dbStatusPill(s) {
    var cls = s === 'success' ? 'ok' : (s === 'empty_result' ? 'muted' : (s === 'partial_result' ? 'warn' : 'bad'));
    return pill(s || '—', cls);
  }
  function bindDbPane() {
    var pane = $('#paneDb');
    if (!pane || pane.dataset.dbBound) { return; }
    pane.dataset.dbBound = '1';
    /* delegated clicks: renderPanes rewrites this pane's innerHTML on every project switch, so the buttons are
       bound on the persistent container, never on the per-render elements (a null querySelector here used to
       kill the whole init chain before loadHistory ran - measured 2026-11-23). */
    pane.addEventListener('click', function (e) {
      var out = $('#paneDbOut');
      if (e.target && e.target.id === 'dbQBtn') {
        var q = $('#dbQ') ? $('#dbQ').value.trim() : '';
        if (!q) { out.innerHTML = note('질문을 입력하라.', 'warn'); return; }
        out.innerHTML = note('질의 실행 중…', 'warn');
        api('/api/db/query', { q: q }).then(function (r) {
          var d = r.data || {};
          if (!r.ok) { out.innerHTML = note('<b>질의 실패.</b> ' + esc(d.error || ('HTTP ' + r.status)), 'bad'); return; }
          var h = heading('질의 결과', 'status: ' + (d.status || '?') + (d.truncated ? ' · 잘림' : '') +
            ' · source: ' + esc(d.source || '?') + ' · attempts: ' + esc(d.attempts));
          h += kv([['SQL', H('<code>' + esc(d.sql || '—') + '</code>')]]);
          var rows = d.rows || [];
          if (rows.length) {
            var cols = Object.keys(rows[0]);
            h += table(cols, rows.slice(0, 50).map(function (row) { return cols.map(function (k) { return row[k]; }); }),
              '행 없음.');
            if (rows.length > 50) { h += note('앞 50행만 표시 (전체 ' + rows.length + '행).', 'warn'); }
          } else if (d.status === 'empty_result') {
            h += note('조건에 맞는 행이 없다 — 빈 결과는 오류가 아니다.', 'warn');
          }
          if (d.error) { h += note('<b>질의 오류.</b> ' + esc(d.error.message || ''), 'bad'); }
          if (d.clarification_needed) { h += note('명확화 필요: ' + esc(d.clarification_needed), 'warn'); }
          out.innerHTML = h;
        });
      } else if (e.target && e.target.id === 'dbSchemaBtn') {
        api('/api/db/schema').then(function (r) {
          var d = r.data || {};
          if (!r.ok) { out.innerHTML = note(esc(d.error || '조회 실패'), 'bad'); return; }
          var rows = Object.keys(d.tables || {}).map(function (k) { return [k, d.tables[k]]; });
          out.innerHTML = heading('스키마 요약', esc(d.db || '')) +
            table(['테이블', '행 수'], rows, '테이블 없음.');
        });
      }
    });
  }

  /* ---------- panes ---------- */
  /* ---------- 클린룸 재구현 워크벤치 (brief 6, /api/reimpl): 두 개의 벽 — 명세만 생성기로, 카피 게이트+원본 오라클 ---------- */
  var REIMPL_STAGES = ['interface_ready', 'patterns_ready', 'spec_ready', 'diagram_ready', 'code_ready', 'copy_gate', 'tests_running', 'tests_passed', 'adopted_tests_running', 'adopted_tests_passed'];
  var REIMPL_LABEL = { interface_ready: '인터페이스', patterns_ready: '패턴 추론', spec_ready: '명세', diagram_ready: 'DGML', code_ready: '코드 생성', copy_gate: '카피 게이트', tests_running: '계약 테스트', tests_passed: '계약 통과', adopted_tests_running: '원본 오라클', adopted_tests_passed: '원본 통과' };
  var REIMPL_FAIL_AT = { copy_gate_failed: 'copy_gate', tests_failed: 'tests_running', adopted_tests_failed: 'adopted_tests_running', refused: 'interface_ready' };
  /* job SSE consumer shared by the reimpl pane and the scan step bar: the server streams bts-sbom.events.v1 frames */
  function watchJobEvents(jid, onEvent) {
    fetch('/api/jobs/' + encodeURIComponent(jid) + '/events').then(function (res) {
      if (!res.ok || !res.body) { throw new Error('HTTP ' + res.status); }
      var reader = res.body.getReader(), dec = new TextDecoder(), buf = '';
      function pump() {
        return reader.read().then(function (chunk) {
          if (chunk.done) { return; }
          buf += dec.decode(chunk.value, { stream: true });
          var parts = buf.split('\n\n');
          buf = parts.pop();
          parts.forEach(function (block) {
            var lines = block.split('\n'), ev = '', datas = [];
            lines.forEach(function (ln) {
              if (ln.indexOf('event: ') === 0) { ev = ln.slice(7); }
              else if (ln.indexOf('data: ') === 0) { datas.push(ln.slice(6)); }
            });
            if (ev && datas.length) { try { onEvent(ev, JSON.parse(datas.join('\n'))); } catch (e) { /* malformed frame: skip, keep the stream */ } }
          });
          return pump();
        });
      }
      return pump();
    }).catch(function () { /* the stream ends when the job ends */ });
  }
  function reimplPane(v) {
    var src = (v && v.source) || '';
    var out = heading('클린룸 재구현 (Clean-Room)', '두 개의 벽: 본문은 절대 생성기로 가지 않는다 — 카피 게이트(4행 shingle ≤5%) + 원본 테스트 오라클');
    out += '<div class="bts-formbox"><div class="bts-fields"><label for="riSource">소스 (로컬 경로 / git URL)</label>' +
      '<input id="riSource" placeholder="C:/path/to/repo 또는 https://github.com/owner/repo" spellcheck="false" value="' + esc(src) + '"></div>' +
      '<div class="bts-fields"><label for="riComponent">컴포넌트 (소스 안의 모듈 상대경로)</label>' +
      '<input id="riComponent" placeholder="예: tools/dtoc/src_scan.py" spellcheck="false"></div>' +
      '<div class="bts-actions"><label class="bts-cd-llm"><input type="checkbox" id="riLlm" checked> LLM 생성 (끄면 스캐폴드)</label>' +
      '<label class="bts-cd-llm"><input type="checkbox" id="riPatterns" checked> 책·AI 패턴 주입 (책 KB 먼저, 없으면 모델)</label>' +
      '<button type="button" class="run" id="riRun">▶ 재구현 실행</button></div>' +
      '<div class="bts-small">벽 1에서 인터페이스(함수·클래스 시그니처+docstring)만 명세가 된다. 벽 2는 명세만 본다. ' +
      '생성 코드가 원본과 4행 shingle 5%를 넘게 겹치면 기각되고, 원본 테스트 오라클이 통과해야 발행 자격이 생긴다. 산출물: evidence/reimpl/&lt;jid&gt;/.</div></div>';
    out += '<div id="riStages" class="bts-stages"></div>';
    out += '<div id="riOut"></div>';
    return out;
  }
  function reimplVerdict(d) {
    var v = d.verdict || '?';
    var cls = v === 'ok' ? 'ok' : (v === 'refused' || v === 'rejected' || v === 'contract_only' || v === 'toolchain_missing' ? 'warn' : 'bad');
    var h = heading('판정', esc(d.component || '') + ' · ' + esc(d.started || ''));
    var cg = d.copy_gate || {};
    var pt = d.patterns;
    h += kv([['verdict', pill(v, cls)],
             ['copy overlap', (cg.overlap !== undefined ? cg.overlap : '—') + ' (게이트 ' + (cg.threshold !== undefined ? cg.threshold : (d.copy_threshold !== undefined ? d.copy_threshold : '—')) + ')'],
             ['생성 테스트', d.tests ? (d.tests.ok ? '통과' : '실패') : '—'],
             ['원본 오라클', d.adopted_tests ? (d.adopted_tests.ok ? '통과 (' + (d.adopted_tests.files || []).length + '개 파일)' : '실패') : '—'],
             ['호환성', d.compatibility || '—'],
             ['언어 / 컴파일', d.language ? (String(d.language).toUpperCase() + (d.compile ? (d.compile.ok ? ' · 컴파일 통과 (경고 ' + (d.compile.warnings || 0) + ')' : ' · 컴파일 실패') : '')) : '—'],
             ['차등 오라클', (d.oracle && d.oracle.differential) ? (d.oracle.differential.ran ? ((d.oracle.differential.ok ? '일치 ' : '불일치 ') + (d.oracle.differential.functions || 0) + '개 항목 · ' + (d.oracle.differential.total_cases || 0) + '케이스 · 불일치 ' + (d.oracle.differential.mismatches === null || d.oracle.differential.mismatches === undefined ? '?' : d.oracle.differential.mismatches)) : ('없음 — ' + (d.oracle.differential.reason || ''))) : '—'],
             ['패턴 주입', pt ? ('tier ' + pt.tier + ' · ' + (pt.patterns || []).map(function (p) { return p.name; }).join(', ')) : '—']]);
    if (d.reason) { h += note('<b>이유:</b> ' + esc(d.reason), v === 'ok' ? 'ok' : 'warn'); }
    if (d.published_to) { h += note('발행: <code>' + esc(d.published_to) + '</code>'); }
    return h;
  }
  function bindReimplPane() {
    var pane = $('#paneReimpl');
    if (!pane || pane.dataset.riBound) { return; }
    pane.dataset.riBound = '1';
    /* delegated like bindDbPane: the pane's innerHTML is rewritten on project switches, the binding is not */
    pane.addEventListener('click', function (e) {
      if (!e.target || e.target.id !== 'riRun') { return; }
      var src = $('#riSource').value.trim(), comp = $('#riComponent').value.trim();
      var out = $('#riOut'), stages = $('#riStages');
      if (!src || !comp) { out.innerHTML = note('소스와 컴포넌트 경로를 입력하라.', 'warn'); return; }
      out.innerHTML = '<div class="bts-skel" style="width:70%"></div><div class="bts-skel" style="width:50%"></div>' + note('레인 실행 중 — 두 개의 벽을 통과하는 중…', 'warn');
      stages.innerHTML = REIMPL_STAGES.map(function (s) {
        return '<span class="bts-stage" id="ri-st-' + s + '">' + esc(REIMPL_LABEL[s] || s) + '</span>';
      }).join('');
      api('/api/reimpl', { source: src, component: comp, use_llm: $('#riLlm').checked, patterns: $('#riPatterns').checked }).then(function (r) {
        if (!r.ok || !(r.data || {}).job) { out.innerHTML = note('<b>실행 거부.</b> ' + esc((r.data || {}).error || ('HTTP ' + r.status)), 'bad'); return; }
        var jid = r.data.job;
        watchJobEvents(jid, function (ev, d) {
          if (ev === 'step_end' && d.name) {
            var at = REIMPL_FAIL_AT[d.name] || d.name;
            var el = document.getElementById('ri-st-' + at);
            if (el) { el.classList.add(d.ok === false ? 'fail' : 'ok'); }
          } else if (ev === 'final') {
            api('/api/jobs/' + encodeURIComponent(jid)).then(function (jr) {
              var d = jr.data || {};
              out.innerHTML = reimplVerdict(d);
              if (d.verdict === 'ok') {
                REIMPL_STAGES.forEach(function (s) {
                  var e = document.getElementById('ri-st-' + s);
                  if (e && !e.classList.contains('fail')) { e.classList.add('ok'); }
                });
              }
            });
          }
        });
      });
    });
  }

  /* ---------- panes ---------- */
  function risk(v) {
    var rep = v.report, s = rep.severity, f = rep.findings.slice();
    var cards = [['Findings', s.total, '#e6edf3'], ['Critical', s.CRITICAL, SEV_COLOR.CRITICAL], ['High', s.HIGH, SEV_COLOR.HIGH],
                 ['Medium', s.MEDIUM, SEV_COLOR.MEDIUM], ['Low', s.LOW, SEV_COLOR.LOW], ['Unknown', s.UNKNOWN, SEV_COLOR.UNKNOWN],
                 ['Vulnerable packages', s.vulnerable_packages, '#e6edf3'], ['Components', rep.components, '#e6edf3']];
    var out = heading('Risk overview', v.project + ' · analysed ' + when(v.analysed_at));
    out += '<div class="bts-cards">' + cards.map(function (c) {
      return '<div class="bts-card"><div class="v" style="color:' + c[2] + '">' + esc(c[1]) + '</div><div class="l">' + esc(c[0]) + '</div></div>';
    }).join('') + '</div>';
    var max = Math.max(1, s.total);
    out += '<div class="bts-bars">' + SEVS.map(function (k) {
      return '<div class="bts-bar-row"><span>' + k + '</span><span class="bts-bar-track"><span class="bts-bar-fill" style="display:block;width:' +
        Math.round(100 * (s[k] || 0) / max) + '%;background:' + SEV_COLOR[k] + '"></span></span><span>' + esc(s[k] || 0) + '</span></div>';
    }).join('') + '</div>';
    f.sort(function (a, b) { return (SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity)) || ((b.score || 0) - (a.score || 0)); });
    out += heading('Top findings', 'by severity, then CVSS');
    out += table(['Advisory', 'Package', 'Version', 'Severity', 'CVSS', 'Fixed in'], f.slice(0, 10).map(function (x) {
      return [x.cve || x.id, x.name, x.version, sevBadge(x.severity), x.score === undefined ? '—' : x.score, H(fixedAt(x.fixed))];
    }), 'No findings.');
    out += note('<b>CISA KEV and EPSS</b> are not computed by BTS-SBOM, so they are absent here (see <b>Prioritize</b>). The full list, with filters and the "ignore with reason" action, is under <b>Scan &rarr; Git repo</b>.');
    return out;
  }
  function depGraph(v) {
    var ms = (v.report.dep_tree || {}).manifests || [];
    var out = heading('Dependencies by manifest', ms.length + ' manifest(s)');
    out += table(['Manifest', 'Ecosystems', 'Total', 'Direct', 'Transitive', 'Vulnerable', 'Max depth'], ms.map(function (m) {
      return [m.path, (m.ecosystems || []).join(', '), m.total, m.direct, m.transitive, m.vulnerable, m.max_depth];
    }), 'No manifest was found.');
    var comps = [];
    ms.forEach(function (m) { (m.children || []).forEach(function (c) { if (c.vuln_count) { comps.push(c); } }); });
    comps.sort(function (a, b) { return b.vuln_count - a.vuln_count; });
    out += heading('Most vulnerable components', 'top 15');
    out += table(['Component', 'Version', 'Findings', 'Worst', 'Relationship', 'Fixed in (plan)'], comps.slice(0, 15).map(function (c) {
      return [c.name, c.version, c.vuln_count, sevBadge(c.worst_severity), c.relationship, H(fixedAt(c.fixed_latest))];
    }), 'No vulnerable component.');
    return out + note('The graph is a flat list per manifest: BTS-SBOM records which manifest a component comes from, not its parent edges.');
  }
  /* Code Intel (Understand-like function-level lane, Python-only - honest about it): metrics, complexity top,
     dead code, clones. Data comes from arch.code in the view projection (bts_sbom_app/code_intel.py). */
  function codeIntel(v) {
    var c = (v.arch || {}).code;
    if (!c) {
      return heading('Code Intel') + note('No function-level analysis was recorded for this project - it has no Python functions, or it was analysed before this lane existed. Other languages stay at module-level analysis.');
    }
    var m = c.metrics || {}, mx = m.max_complexity || {};
    var out = heading('Code Intel', 'function-level facts (Python) - call graph, complexity, dead code, clones');
    out += kv([['Functions analysed', m.functions], ['Avg complexity', m.avg_complexity],
               ['Max complexity', (mx.name ? mx.name + ' (' + mx.file + ') — ' + mx.cc : '—')],
               ['Dead functions (fan-in 0)', m.dead_count], ['Clone groups', m.clone_groups],
               ['Resolved / unknown calls', (m.resolved_calls || 0) + ' / ' + (m.unknown_calls || 0)],
               ['Language', c.language || '—']]);
    out += '<div class="bts-actions">' +
      '<button type="button" class="bts-mini" data-act="dl" data-url="/api/code-metrics/' + esc(encodeURIComponent(v.project)) + '">⬇ Metrics CSV (functions)</button></div>';
    out += heading('Complexity top', 'cyclomatic = 1 + decisions (branches, loops, handlers, booleans)');
    out += table(['Function', 'File', 'CC', 'nesting', 'fan-in', 'fan-out', 'sLOC'], (c.functions || []).map(function (f) {
      return [f.name, f.file, f.complexity >= 9 ? H('<span class="bts-pill bad">' + esc(f.complexity) + '</span>') : f.complexity,
              f.nesting === undefined ? '—' : f.nesting, f.fan_in, f.fan_out, f.sloc];
    }), 'No functions were analysed.');
    var bf = c.butterfly;
    if (bf) {
      out += heading('Butterfly: ' + bf.name, 'immediate neighbourhood (callers / callees, measured)');
      out += table(['Direction', 'Function', 'File'], (bf.callers || []).map(function (x) {
        return ['caller', x.name, x.file];
      }).concat((bf.callees || []).map(function (x) {
        return ['callee', x.name, x.file];
      })), 'No resolved callers or callees for the top function (the resolver is name-based and Python-only).');
    }
    out += heading('Classes', 'name, bases and direct method count');
    out += table(['Class', 'File', 'line', 'Bases', 'methods'], (c.classes || []).map(function (k) {
      return [k.name, k.file, k.line, (k.bases || []).join(', ') || '—', k.methods];
    }), 'No classes were analysed.');
    out += heading('Dead code', 'never called in the analysed tree — remove or wire in, the judgement is yours');
    out += table(['Function', 'File', 'line', 'sLOC'], (c.dead_code || []).map(function (d) {
      return [d.name, d.file, d.line, d.sloc];
    }), 'No dead function above the exclusions.');
    out += heading('Clone groups', 'identical normalized bodies (identifiers and literals collapsed)');
    out += table(['Group', 'Members'], (c.clones || []).map(function (g) {
      return [g.hash, g.members.map(function (mm) { return mm.name + ' (' + mm.file + ':' + mm.line + ')'; }).join(', ')];
    }), 'No clone group above the token threshold.');
    (c.notes || []).forEach(function (n) { out += note(esc(n), 'warn'); });
    return out;
  }
  function arch(v) {
    var a = v.arch || {}, g = a.graph || {}, lang = ((a.stack || {}).languages) || {};
    if (!g.modules && !(a.hotspots || []).length && !(a.runtime_eol || []).length) {
      return heading('Architecture') + note('No architecture data was produced for this project (not a source tree, or the stage did not run).');
    }
    var out = heading('Legacy architecture', 'import graph, change history, runtime end-of-life');
    out += kv([['Modules', g.modules], ['Import edges', g.import_edges], ['Import cycles', g.cycle_count], ['Modules in cycles', g.modules_in_cycles],
               ['Tangle ratio', g.tangle_ratio], ['Max layer depth', g.max_depth],
               ['Languages', Object.keys(lang).map(function (k) { return k + ' (' + lang[k].files + ' files, ' + lang[k].loc + ' loc)'; }).join(', ') || '—'],
               ['History', a.history ? (a.history.commits + ' commits' + (a.history.shallow ? ' (shallow clone)' : '')) : '—']]);
    (a.notes || []).forEach(function (n) { out += note(esc(n), 'warn'); });
    out += heading('Hotspots', 'churn × complexity');
    out += table(['File', 'Commits', 'Churn', 'LOC', 'Complexity', 'Score'], (a.hotspots || []).map(function (h) { return [h.file, h.commits, h.churn, h.loc, h.complexity, h.score]; }), 'No hotspots.');
    out += heading('Change coupling', 'files that change together');
    out += table(['A', 'B', 'Shared commits', 'Jaccard', 'No import link'], (a.coupling || []).map(function (c) { return [c.a, c.b, c.shared, c.jaccard, c.hidden ? 'yes' : 'no']; }), 'No coupled pairs.');
    out += heading('Import cycles');
    out += (a.cycles || []).length ? table(['Cycle'], a.cycles.map(function (c) { return [Array.isArray(c) ? c.join(' → ') : String(c)]; })) : note('No import cycle was found.', 'ok');
    out += heading('Runtime end-of-life');
    out += table(['Product', 'Cycle', 'Declared in', 'Status', 'EOL date', 'Source'], (a.runtime_eol || []).map(function (r) {
      return [r.product, r.cycle, r.declared_in, pill(r.status, r.status === 'eol' ? 'bad' : r.status === 'supported' ? 'ok' : 'warn'), r.eol_date, r.source];
    }), 'No runtime declaration was found.');
    out += heading('Modernisation candidates');
    out += table(['Kind', 'Priority', 'Target', 'Why'], (a.modernization || []).map(function (m) { return [m.kind, m.priority, m.target, m.why]; }), 'None.');
    return out;
  }
  function sbomChecks(v) {
    var c = v.sbom_check || {}, ri = c.ref_integrity || {}, n = encodeURIComponent(v.project);
    var out = heading('SBOM documents', 'built from the same findings');
    out += kv([['CycloneDX 1.5', pill(c.cyclonedx_valid ? 'valid' : 'invalid', c.cyclonedx_valid ? 'ok' : 'bad')], ['SPDX 2.3', pill(c.spdx_valid ? 'valid' : 'invalid', c.spdx_valid ? 'ok' : 'bad')],
               ['Components / vulnerabilities', (c.components || 0) + ' / ' + (c.vulnerabilities || 0)],
               ['Vulnerability references resolved', ri.affects ? (ri.resolved + ' of ' + ri.affects + ' (' + ri.rate + ')') : '—']]);
    (c.cyclonedx_errors || []).concat(c.spdx_errors || []).forEach(function (e) { out += note(esc(e), 'bad'); });
    out += '<div class="bts-actions">' + btn('⬇ CycloneDX JSON', 'dl', '', ' data-url="/api/sbom/' + n + '?format=cdx"') +
      btn('⬇ SPDX JSON', 'dl', '', ' data-url="/api/sbom/' + n + '?format=spdx"') +
      btn('⬇ OpenVEX JSON (as analysed)', 'dl', '', ' data-url="/api/sbom/' + n + '?format=vex"') +
      btn('⬇ Report (Markdown)', 'dl', '', ' data-url="/api/doc/' + n + '"') + '</div>';
    return out + note('The OpenVEX file above is the one written when the project was analysed, <b>without</b> later decisions; the <b>VEX &middot; Decisions</b> tab downloads it with them applied. ' +
      'NTIA 2021 and three more regimes are checked per element on the <button type="button" class="bts-link" data-act="goto" data-sv="conformance">SBOM conformance</button> tab.');
  }
  /* FOSSLight-report-style license risk colors: red = strong/network copyleft, orange = weak copyleft / proprietary, green = permissive, gray = unknown. */
  var LIC_COLOR = { strong_copyleft: '#c0392b', network_copyleft: '#c0392b', weak_copyleft: '#d97a09',
                    proprietary: '#d97a09', permissive: '#2e7d32', public_domain: '#2e7d32', unknown: '#6e7681' };
  function licBadge(cat) {
    cat = String(cat || 'unknown');
    var label = cat.replace(/_/g, ' ');
    var color = LIC_COLOR[cat] || LIC_COLOR.unknown;
    return H('<span class="bts-pill" style="background:' + color + '">' + esc(label) + '</span>');
  }
  function progressBar(pct) {   // FOSSLight-report-style resolved bar
    if (pct === null || pct === undefined || isNaN(pct)) { return '<span class="sub">—</span>'; }
    var w = Math.max(0, Math.min(100, Math.round(pct)));
    return H('<div style="display:flex;align-items:center;gap:8px;min-width:220px">' +
      '<div style="flex:1;height:10px;border-radius:5px;background:var(--line,rgba(127,127,127,.25));overflow:hidden">' +
      '<div style="width:' + w + '%;height:100%;background:' + (w >= 90 ? '#2e7d32' : w >= 60 ? '#d97a09' : '#c0392b') + '"></div></div>' +
      '<span class="sub" style="min-width:52px">' + w + '%</span></div>');
  }
  function licences(v) {
    var l = v.license || {}, st = l.stats || {}, cats = (v.report.licenses || {}).summary || {}, cc = cats.category_counts || {};
    var out = heading('License risk', 'resolved from lockfile, deps.dev or the registry; the source is recorded per component · sheet style after the FOSSLight report');
    out += kv([['Project license', (l.project_license || '—') + (l.project_license_source ? ' (' + l.project_license_source + ')' : '')],
               ['Resolved', progressBar(st.resolved !== undefined && st.total ? Math.round(100 * st.resolved / st.total) : null)],
               ['Count', (st.resolved || 0) + ' of ' + (st.total || 0)],
               ['By source', Object.keys(st.by_source || {}).map(function (k) { return k + ': ' + st.by_source[k]; }).join(', ') || '—']]);
    out += '<div style="display:flex;gap:8px;align-items:center;margin:4px 0 10px;flex-wrap:wrap">' +
      '<a class="bts-mini" id="selfcheckBtn" href="/api/selfcheck/' + encodeURIComponent(S.project || '') + '" download' + (S.project ? '' : ' style="pointer-events:none;opacity:.5"') +
      ' title="FOSSLight-style self-check sheet (CSV): OSS name / version / license per component, unresolved left empty">⬇ Self-check sheet (CSV)</a>' +
      '<span class="sub">folder scans run from the CLI: <code>bts-sbom-app srcscan &lt;folder&gt;</code> · <code>bts-sbom-app binscan &lt;folder&gt;</code></span></div>';
    if ((l.components || []).length) {
      out += heading('Components', 'risk color: red strong/network copyleft · orange weak copyleft, proprietary · green permissive · gray unknown');
      out += table(['Component', 'Version', 'License', 'Risk', 'Source'], l.components.slice(0, 40).map(function (c) {
        return [c.name, c.version, c.license || '<span class="sub">(unresolved)</span>', licBadge(c.category), c.source || '—'];
      }), 'No component was recorded.');
    }
    out += '<div style="display:flex;gap:8px;align-items:center;margin:10px 0 2px;flex-wrap:wrap">' +
      '<b style="font-size:12.5px">Policy findings</b>' +
      '<select id="distSel" title="배포 모델을 바꾸면 정책 소견이 다시 계산된다" style="background:var(--dcard-bg,#161b22);border:1px solid #30363d;border-radius:6px;color:#e6edf3;font:inherit;font-size:12px;padding:3px 8px">' +
      '<option value="binary">배포: binary</option><option value="saas">배포: saas</option><option value="internal">배포: internal</option></select>' +
      '<span class="sub">기본값 binary — 소견은 /api/policy 로 재계산된다</span></div>';
    out += '<div id="policyOut">' + policyBlock(l.policy || []) + '</div>';
    if ((l.unresolved || []).length) { out += heading('Unresolved', 'left unresolved on purpose, never guessed'); out += note(esc(l.unresolved.join(', '))); }
    return out;
  }
  function policyBlock(fs) {
    if (!fs.length) { return note('No license policy finding.'); }
    var h = table(['Category', 'Severity', 'Count', 'Affected / 의무'], fs.map(function (p) {
      var right = (p.components || []).length ? (p.components.slice(0, 6).join(', ') + ((p.components || []).length > 6 ? ' …' : ''))
                                              : (p.obligations || []).join('; ');
      return [p.category, sevBadge(p.severity), p.count, right];
    }));
    h += fs.filter(function (p) { return p.detail; }).map(function (p) {
      return note('<b>' + esc(p.category) + ':</b> ' + esc(p.detail));
    }).join('');
    return h;
  }
  function bindLicPane() {
    var pane = document.querySelector('.rpane[data-sv="license-risk"]');
    if (!pane || pane.dataset.licBound) { return; }
    pane.dataset.licBound = '1';
    pane.addEventListener('change', function (e) {
      if (!e.target || e.target.id !== 'distSel' || !S.project) { return; }
      var out = pane.querySelector('#policyOut');
      if (out) { out.innerHTML = note('재계산 중…', 'warn'); }
      api('/api/policy/' + encodeURIComponent(S.project) + '?distribution=' + encodeURIComponent(e.target.value)).then(function (r) {
        var d = r.data || {};
        if (!r.ok) { if (out) { out.innerHTML = note('<b>재계산 실패.</b> ' + esc(d.error || ('HTTP ' + r.status)), 'bad'); } return; }
        if (out) { out.innerHTML = policyBlock(d.findings || []); }
      });
    });
  }
  function sectors(v) {
    var s = v.sectors || {}, keys = Object.keys(s);
    if (!keys.length) { return heading('Industry reports') + note('No industry report was produced for this project.'); }
    var out = heading('Industry reports', 'verdicts are computed from the SBOM and VEX documents; a requirement without evidence is "not_evidence", never a pass');
    out += table(['Industry', 'Title', 'Verdict', 'Pass', 'Gap', 'No evidence'], keys.map(function (k) {
      var x = s[k], sm = x.summary || {};
      return [k, x.title, pill(x.verdict, x.verdict === 'pass' || x.verdict === 'ready' ? 'ok' : x.verdict === 'gaps' ? 'bad' : 'warn'), sm.pass, sm.gap, sm.not_evidence];
    }));
    keys.forEach(function (k) {
      var x = s[k];
      out += '<details style="margin:6px 0"><summary style="cursor:pointer;font-weight:600">' + esc(k) + ' — ' + esc(x.title || '') + '</summary>' +
        (x.honesty ? note(esc(x.honesty)) : '') +
        table(['Requirement', 'Title', 'Verdict', 'Detail'], (x.requirements || []).map(function (r) {
          return [r.id, r.title, pill(r.verdict, r.verdict === 'pass' ? 'pass' : r.verdict === 'gap' ? 'gap' : 'not_evidence'), r.detail]; })) + '</details>';
    });
    return out;
  }
  /* measured compatibility (compat.py): the gate's verdict per plan; "partial" carries the coverage of the used API */
  function compatPill(c) {
    if (!c) { return '—'; }
    var kind = { compatible: 'ok', partial: 'warn', review: 'warn', breaking: 'bad', unverified: 'muted', not_direct: 'muted' };
    return pill(c.status + (c.coverage !== null && c.coverage !== undefined ? ' ' + Math.round(c.coverage * 100) + '%' : ''), kind[c.status] || 'muted');
  }
  /* items: [{component, compat: {findings}}] - the exact symbols and call sites behind a breaking/review verdict */
  function compatEvidence(items) {
    var rows = [];
    (items || []).forEach(function (x) {
      ((x.compat || {}).findings || []).slice(0, 6).forEach(function (f) { rows.push([x.component, pill(f.level, f.level === 'breaking' ? 'bad' : 'warn'), f.rule, f.detail]); });
    });
    if (!rows.length) { return ''; }
    return heading('Compatibility findings', 'the project\'s own call sites against the target release') + table(['Component', 'Level', 'Rule', 'Detail'], rows, '') +
      note('Static check: a behaviour change behind an unchanged signature is not detected. <b>Breaking</b> upgrades are held back when the patch is applied; unverified ones are not blocked and not claimed compatible.');
  }
  function fixPlan(v) {
    var ps = (v.plans || []).filter(function (p) { return p.status === 'upgrade'; }), pr = v.proposals || {};
    var out = heading('Upgrade plan', 'lowest version that clears every advisory, re-checked against OSV');
    out += table(['Component', 'From', 'To', 'Clears', 'Worst', 'Breaking risk', 'Compat (measured)', 'Verified clean'], ps.map(function (p) {
      var ver = p.verification || {};
      return [p.component, p.current_version, p.safe_version, p.cve_count, sevBadge(p.max_severity), p.major_bump ? pill(p.breaking_risk || 'major bump', 'warn') : '—', compatPill(p.compat),
              ver.clean === true ? pill('yes', 'ok') : ver.clean === false ? pill('no', 'bad') : pill('not verified', 'muted')];
    }), 'No upgrade is needed or possible (see the findings for entries without a fixed version).');
    out += heading('Proposals', 'source: ' + (pr.source || 'none') + (pr.model ? ' (' + pr.model + ')' : ''));
    if (pr.llm_note) { out += note(esc(pr.llm_note), 'warn'); }
    out += table(['Action', 'Risk', 'Proposal', 'Why'], (pr.items || []).map(function (i) { return [i.action, i.risk, i.title, i.rationale]; }), 'No proposal was produced.');
    return out + note('Proposals are checked against the analysis (unknown versions or advisories are dropped). A person has not reviewed them.');
  }
  function fixPr(v) {
    var p = v.patch || {}, st = p.status || 'not_requested';
    var out = heading('Patch', 'approval-gated; the origin is never modified');
    out += note('<b>How it works.</b> 1) Preview the plan: nothing is changed. 2) Review it and approve with its digest. 3) Manifests are edited in a temporary work copy, ' +
      'the project is re-scanned, and the edit is reverted if the findings in the edited files increase. Lockfiles are never edited; regeneration commands are listed instead. ' +
      'Before editing, each upgrade is checked against the API the project actually uses (breaking ones are held back). <b>The patched code has not been built; its tests are run only when explicitly requested.</b>');
    out += '<div class="bts-actions">' + btn('1 · Preview plan (changes nothing)', 'plan', 'job', S.busy ? ' disabled' : '') + '</div>';
    if (st === 'not_requested') { return out + note('No patch has been requested for this analysis yet.'); }
    if (st === 'not_approved') {
      out += heading('Plan to review', 'digest ' + (p.digest || ''));
      out += table(['Component', 'From', 'To', 'Breaking risk', 'Compat (measured)'], (p.plans || []).map(function (x) { return [x.component, x.current_version, x.safe_version, x.breaking_risk || '—', compatPill(x.compat)]; }), 'The plan is empty.');
      out += compatEvidence(p.plans);
      if ((p.plans || []).length) {
        out += '<label style="font-size:12px;display:block;margin:8px 0"><input type="checkbox" id="ackPlan"> I reviewed this plan (digest <code>' + esc(p.digest) + '</code>)</label>' +
          '<div class="bts-actions">' + btn('2 · Approve and apply on a work copy', 'apply', 'job', ' disabled') + '</div>';
      }
      return out;
    }
    var rounds = p.rounds || [];
    out += heading('Result', st);
    out += kv([['Status', pill(st, st === 'applied' ? 'ok' : st === 'regression_reverted' || st === 'compat_runtime_reverted' || st === 'digest_mismatch' ? 'bad' : 'warn')], ['Components edited', p.applied_components],
               ['Findings before', (p.before || {}).vulns], ['After re-scan', (p.after || {}).vulns_rescan], ['Estimated after (plan)', (p.after || {}).vulns_estimated],
               ['Fixed, confirmed by re-scan', p.rescan_fixed_total], ['Branch / commit', (p.branch || '—') + ' / ' + String(p.commit || '—').slice(0, 10)],
               ['Work copy', (S.lastJob && S.lastJob.work_copy) || '—']]);
    if (p.note) { out += note(esc(p.note), 'warn'); }
    if (st === 'regression_reverted') { out += note('The edit made things worse in the edited files, so it was <b>reverted</b>.', 'bad'); }
    if (st === 'digest_mismatch') { out += note('The plan changed since it was reviewed. Preview it again.', 'bad'); }
    if (st === 'compat_runtime_reverted') { out += note('The project\'s own tests regressed on the patched versions, so the patch was <b>reverted</b>.', 'bad'); }
    if (p.compat && (p.compat.summary || {}).held) {
      out += note('<b>' + p.compat.summary.held + ' upgrade(s) were held back</b> by the compatibility gate and stay vulnerable until the call sites or pins are adapted. The rest were applied.', 'warn');
    }
    if (p.compat_runtime) {
      var rt = p.compat_runtime, ra = rt.after || {}, rb = rt.baseline || {};
      out += kv([['Runtime differential', pill(ra.status || rb.status || 'unverified', ra.status === 'ok' ? 'ok' : ra.status === 'regression' ? 'bad' : 'muted')], ['Detail', ra.reason || rb.reason || '—']]);
    }
    if (p.compat) { out += compatEvidence((p.compat.plans || []).map(function (x) { return { component: x.component, compat: x }; })); }
    if ((p.regenerate || []).length) { out += heading('Regenerate lockfiles'); out += note('<code>' + (p.regenerate || []).map(esc).join('</code><br><code>') + '</code>'); }
    out += table(['Round', 'Status', 'Applied', 'Held', 'Blocked', 'Manual', 'Before', 'After'], rounds.map(function (r) { return [r.round, r.status, r.applied, r.held || 0, r.blocked, r.manual, r.vulns_before, r.vulns_after]; }), 'No round ran.');
    var d = p.diff || {};
    if (d.stat || d.patch) {
      out += heading('Changed files', 'work copy against the base commit');
      if (d.stat) { out += '<pre class="bts-diff">' + esc(d.stat) + '</pre>'; }
      if (d.patch) { out += heading('Diff'); out += '<pre class="bts-diff">' + esc(d.patch) + '</pre>'; }
    }
    return out;
  }
  function renderHistory() {
    var out = heading('Analysed projects', 'from the evidence folder; one row per project, the latest analysis');
    out += table(['Project', 'Source', 'Analysed', 'Components', 'Findings', 'License resolved', 'Patch', 'Proposals', ''], S.history.map(function (h) {
      return [h.name, h.source, when(h.analysed_at), h.components, h.vulns, h.license_resolved_rate === null || h.license_resolved_rate === undefined ? '—' : h.license_resolved_rate,
              h.patch_status || '—', h.proposal_source || '—', H('<button type="button" class="bts-link" data-act="open" data-name="' + esc(h.name) + '">Open</button>')];
    }), 'Nothing has been analysed yet.');
    out += note('<b>CI gate:</b> the policy gate with CI exit codes is a command of the core (<code>bts-sbom policy</code>); this screen does not run it. ' +
      'The history shows only the latest analysis per project, not a time series.');
    $('#paneHistory').innerHTML = out;
  }
  /* Supply-chain substitution risks (bts_sbom/supply_chain.py, measured into the record by the pipeline):
     typosquatting, npm namespace confusion and dependency confusion. */
  function supplyChain(v) {
    var fs = v.supply_chain || [];
    var out = heading('Supply chain', 'substitution risks measured on the components - typosquatting, namespace confusion, dependency confusion');
    if (!fs.length) {
      return out + note('No substitution risk was measured on the ' + ((v.metrics || {}).components || (v.report || {}).components || 0) +
        ' components: every name passed the typosquatting, namespace-confusion and dependency-confusion checks. ' +
        'The checks compare each component name against a popular-package list (edit distance 1) and internal-name declarations.');
    }
    out += table(['Component', 'Ecosystem', 'Kind', 'Resembles', 'CWE', 'Confidence'], fs.map(function (f) {
      return [f.package, f.ecosystem || '—', esc(f.kind), f.resembles || '—', f.cwe || '—', esc(f.confidence || '—')];
    }));
    out += fs.slice(0, 6).map(function (f) {
      return '<div class="bts-note"><b>' + esc(f.kind) + ' — ' + esc(f.package) + '</b><br>' + esc(f.description || '') +
        (f.recommendation ? '<br><b>권고:</b> ' + esc(f.recommendation) : '') + '</div>';
    }).join('');
    return out + note('Findings are name-based risk signals, not proof of compromise: verify the publisher and the intended package before acting.');
  }
  function renderPanes() {
    var v = S.view;
    $('#paneContainer').innerHTML = '<b>Container image scanning is not supported by BTS-SBOM.</b> Analyse the repository or lockfile the image is built from instead.';
    $('#paneSsvc').innerHTML = unavailable('SSVC', 'CISA SSVC decisions need exploitation, automatable and mission-impact inputs that this workflow does not collect.');
    $('#paneEpss').innerHTML = unavailable('EPSS', 'No EPSS feed is wired into this workflow, so a finding has no score (it is absent, not zero).');
    $('#paneExploit').innerHTML = unavailable('Exploit maturity', 'It needs exploit-database and CISA KEV matching, which this workflow does not do.');
    var map = { paneRisk: risk, paneDep: depGraph, paneArch: arch, paneCode: codeIntel, paneDb: dbIntel, paneSupply: supplyChain, paneSbom: sbomChecks, paneLic: licences, paneSectors: sectors, paneFixPlan: fixPlan, paneFixPr: fixPr, paneReimpl: reimplPane };
    Object.keys(map).forEach(function (id) { $('#' + id).innerHTML = v ? map[id](v) : needProject(); });
    renderHistory();
    renderGovernance();
    bindDbPane();
    bindCraPane();
    bindReimplPane();
    bindLicPane();
  }
  function renderAll() {
    renderConsole();
    renderPanes();
    renderRailSessions();                                            // the rail session list follows the selected project
    var ack = $('#ackPlan');
    if (ack) { ack.addEventListener('change', function () { var b = $('[data-act="apply"]'); if (b) { b.disabled = !ack.checked || S.busy; } }); }
  }

  /* ---------- governance panes: conformance, what changed, VEX + decisions, fleet ---------- */
  function renderGovernance() {
    var v = S.view, g = S.gov, ages = analysedMap();
    $('#paneConformance').innerHTML = v ? G.renderConformance(g.conformance)
      : heading('SBOM conformance') + note(G.LEGAL_NOTE, 'warn') + needProject();
    $('#paneCra').innerHTML = v ? craPane(g.cra) : needProject();
    $('#paneChanges').innerHTML = v ? G.renderChanges(g.changes) : needProject();
    renderVexPane();
    $('#paneFleet').innerHTML = G.renderFleet(S.fleet, ages);
    $('#paneAffected').innerHTML = G.renderAffected(S.affected, ages);
  }
  function renderVexPane() {
    var v = S.view, form = $('#paneTriage');
    form.style.display = v ? '' : 'none';
    if (!v) { $('#paneVex').innerHTML = needProject(); return; }
    $('#paneVex').innerHTML = '<div class="bts-actions">' +
      btn('⬇ OpenVEX with decisions applied', 'dl', '', ' data-url="/api/vex/' + encodeURIComponent(v.project) + '" data-fname="' + esc(v.project) + '.vex.json"') + '</div>' +
      G.renderVex(S.gov.vex) + G.renderDecisions(S.triage);
    var sel = $('#tfFinding');
    sel.innerHTML = G.findingOptions(v.report.findings, sel.value);          // the chosen finding survives a re-render
    updateTriageHint();
  }
  function triageValues() {
    return { finding: $('#tfFinding').value, status: $('#tfStatus').value, justification: $('#tfJust').value, reason: $('#tfReason').value,
             expires: $('#tfExpires').value, scope: $('#tfScope').value, by: $('#tfBy').value };
  }
  function updateTriageHint() {
    var f = triageValues(), fp = f.status === 'false-positive', n = Array.from(f.reason.trim()).length, o = f.status ? G.triageOutcome(f) : null;
    $('#tfJust').disabled = !fp;                                              // a justification only means something for a false positive
    $('#tfStatusHint').textContent = G.statusHint(f.status);
    $('#tfCount').textContent = n + ' / 500 characters; at least ' + G.MIN_REASON + ' are needed to make a false positive or an accepted risk count';
    $('#tfOutcome').innerHTML = o ? note('<b>Effect on the OpenVEX statement:</b> ' + esc(o.text), o.tone) : note('Choose a decision to see what it does to the OpenVEX statement.');
  }
  function saveDecision() {
    var out = $('#tfResult'), vals = triageValues(), r = G.triageRequest(vals);
    if (r.error) { out.innerHTML = note(esc(r.error), 'bad'); return; }
    var o = G.triageOutcome(vals), key = r.body.check_id;
    out.innerHTML = note('Saving…');
    api('/api/triage', r.body).then(function (res) {
      if (!res.ok) { out.innerHTML = note('<b>Not saved.</b> ' + esc((res.data && res.data.error) || ('HTTP ' + res.status)), 'bad'); return; }
      ['#tfReason', '#tfExpires', '#tfScope', '#tfJust', '#tfStatus'].forEach(function (id) { $(id).value = ''; });      // finding and owner stay for the next one
      return selectProject(S.project, true).then(function () {
        out.innerHTML = note('<b>Saved</b> the decision for <code>' + esc(key) + '</code>. ' + esc(o.text) + ' The OpenVEX below was regenerated from the stored decisions.', o.tone === 'bad' ? 'warn' : o.tone);
      });
    });
  }
  function searchAffected() {
    var q = G.affectedQuery({ cve: $('#afCve').value, component: $('#afComp').value, version: $('#afVer').value }), box = $('#paneAffected');
    if (q.error) { S.affected = { ok: false, status: 0, data: { error: q.error } }; box.innerHTML = G.renderAffected(S.affected, analysedMap()); return; }
    box.innerHTML = note('Searching…');
    api(q.url).then(function (r) { S.affected = r; box.innerHTML = G.renderAffected(r, analysedMap()); });
  }

  /* ---------- chat: the bottom dock (bts_chat_panel.js) owns the conversation UX; ask() and the chat-tab
     bindings were removed together with the 💬 Chat tab. The dock reads the current project from #projSel. ---------- */

  /* ---------- diagrams pane: the EA-17.2 catalog (ADR-0024), drawn from the measured record ----------
     Same markup contract as the chat dock (.arc-dwrap > .arc-diagram + hidden .arc-mermaid-src), its own lazy
     mermaid loader, and an honest note line when a kind has no measured source. */
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
    Array.prototype.forEach.call((scope || document).querySelectorAll('.arc-dwrap'), function (wrap) {
      var holder = wrap.querySelector('.arc-diagram');
      var src = wrap.querySelector('.arc-mermaid-src');
      if (!holder || !src || holder.childElementCount) { return; }   // already rendered (or empty)
      var text = src.textContent || '';
      if (!text.trim()) { return; }
      ensureMermaid().then(function (m) {
        return m.render('btsd-' + Date.now() + '-' + diagramSeq++, text);
      }).then(function (out) {
        holder.innerHTML = out.svg;                     // mermaid strict mode; the source is server-sanitized
        src.hidden = true;
      }).catch(function () {
        src.hidden = false;                             // fallback: the Mermaid source, still the honest diagram
      });
    });
  }
  var dgCatalog = null;
  function fillDiagramKindSelect() {
    if ($('#dgKind') && $('#dgKind').childElementCount) { return Promise.resolve(); }
    return api('/api/diagrams').then(function (r) {
      dgCatalog = (r.data && r.data.catalog) || [];
      var sel = $('#dgKind');
      if (!sel) { return; }
      var groups = {};
      dgCatalog.forEach(function (c) { (groups[c.group] = groups[c.group] || []).push(c); });
      sel.innerHTML = Object.keys(groups).map(function (g) {
        return '<optgroup label="' + esc(g) + '">' + groups[g].map(function (c) {
          return '<option value="' + esc(c.kind) + '">' + esc(c.title) + (c.needs_target ? ' (target)' : (c.needs_spec ? ' (spec)' : '')) + '</option>';
        }).join('') + '</optgroup>';
      }).join('');
    });
  }
  function drawDiagram() {
    var out = $('#paneDiagrams');
    if (!out) { return; }
    var kind = ($('#dgKind') || {}).value || '';
    var p = encodeURIComponent(S.project || '');
    var url = '/api/diagrams/' + encodeURIComponent(kind) +
      (p ? '?project=' + p : '') +
      ($('#dgTarget') && $('#dgTarget').value.trim() ? '&target=' + encodeURIComponent($('#dgTarget').value.trim()) : '') +
      ($('#dgSpec') && $('#dgSpec').value.trim() ? '&spec=' + encodeURIComponent($('#dgSpec').value.trim()) : '');
    out.innerHTML = note('Drawing…');
    api(url).then(function (r) {
      var d = r.data || {};
      if (!r.ok) { out.innerHTML = note(esc(d.error || ('HTTP ' + r.status)), 'bad'); return; }
      if (!d.mermaid) {
        out.innerHTML = heading(d.title || kind, (d.group || '') + ' · ' + (d.ea || '')) + note(esc(d.note || '그릴 데이터가 없습니다.'), 'warn');
        return;
      }
      var noteText = String(d.note || '').split('\n')[0];
      out.innerHTML = heading(d.title || kind, (d.group || '') + ' · ' + (d.ea || '')) +
        '<div class="bts-diagram arc-dwrap"><div class="arc-diagram"></div><pre class="arc-mermaid-src" hidden>' + esc(d.mermaid) + '</pre>' +
        (noteText ? '<div class="bts-diagram-note">' + esc(noteText) + '</div>' : '') + '</div>' +
        (d.lines && d.lines.length ? '<pre class="bts-diagram-lines">' + esc(d.lines.join('\n')) + '</pre>' : '');
      renderDiagramsIn(out);
    });
  }

  /* ---------- events ---------- */
  document.addEventListener('click', function (e) {
    var t = e.target.closest ? e.target.closest('[data-act],.rtab,.egchip') : null;
    if (!t) { return; }
    if (t.classList.contains('rtab')) { activate(t.getAttribute('data-sv')); return; }
    if (t.classList.contains('egchip')) { $('#scaGitUrl').value = t.getAttribute('data-url'); $('#scaGitUrl').focus(); return; }
    var act = t.getAttribute('data-act');
    if (act === 'goto') { activate(t.getAttribute('data-sv'), t.classList.contains('scan-subchip')); }   // a sub-tab chip opens exactly that member
    else if (act === 'dl') { download(t.getAttribute('data-url'), t.getAttribute('data-fname')); }
    else if (act === 'triage-save') { saveDecision(); }
    else if (act === 'affected') { searchAffected(); }
    else if (act === 'open') { selectProject(t.getAttribute('data-name')).then(function () { activate('risk'); }); }
    else if (act === 'session') { selectProject(t.getAttribute('data-name')).then(function () { activate('report', true); }); }   // a rail session opens its report
    else if (act === 'new') { activate('git', true); }                             // ＋ 새 분석: the Scan landing
    else if (act === 'assist') { focusAssistant(); }                               // 💬 어시스턴트: the main conversation surface
    else if (act === 'plan' && S.view) { runJob({ source: S.view.source, patch: true, approved: false, offline: !!$('#scaOffline').checked }, 'Plan preview').then(function () { activate('fix-pr'); }); }
    else if (act === 'apply' && S.view && S.view.patch && S.view.patch.digest && ($('#ackPlan') || {}).checked) {
      runJob({ source: S.view.source, patch: true, approved: true, approval_token: S.view.patch.digest, offline: !!$('#scaOffline').checked }, 'Approved patch').then(function () { activate('fix-pr'); });
    }
  });
  function init() {
    buildSideNav();
    activate('git');
    setStep(1, 'Choose an input source.');
    document.addEventListener('bts:activate', function (e) { if (e && e.detail) { activate(String(e.detail), true); } });   // pane scripts (oss_scanner.js) request an exact pane
    $('#runScaReport').addEventListener('click', function () { activate('git'); analyse($('#scaGitUrl').value); });
    $('#scaGitUrl').addEventListener('keydown', function (e) { if (e.key === 'Enter') { analyse($('#scaGitUrl').value); } });
    $('#scaDemoBtn').addEventListener('click', function () { $('#scaGitUrl').value = 'https://github.com/adeyosemanputra/pygoat.git'; analyse($('#scaGitUrl').value); });
    $('#runLock').addEventListener('click', function () { var p = $('#lockPath').value.trim(); $('#scaGitUrl').value = p; activate('git'); analyse(p); });
    $('#projSel').addEventListener('change', function () { selectProject($('#projSel').value); });
    $('#engineRefresh').addEventListener('click', function () { loadEngine(); loadHistory(); loadLlm(); });
    $('#llmConnect').addEventListener('click', connectLlm);
    $('#llmKey').addEventListener('keydown', function (e) { if (e.key === 'Enter') { connectLlm(); } });
    $('#llmClear').addEventListener('click', clearLlm);
    $('#tfStatus').innerHTML = G.statusOptions();
    $('#tfJust').innerHTML = G.justificationOptions();
    ['#tfFinding', '#tfStatus', '#tfJust', '#tfReason', '#tfExpires', '#tfScope', '#tfBy'].forEach(function (id) {
      $(id).addEventListener('input', updateTriageHint);
      $(id).addEventListener('change', updateTriageHint);
    });
    ['#afCve', '#afComp', '#afVer'].forEach(function (id) { $(id).addEventListener('keydown', function (e) { if (e.key === 'Enter') { searchAffected(); } }); });
    fillDiagramKindSelect();                                        // the Diagrams pane (ADR-0024); Draw uses the selected project
    if ($('#dgDraw')) { $('#dgDraw').addEventListener('click', drawDiagram); }
    watchBrand();
    renderPanes();
    loadEngine();
    loadLlm();
    loadHistory().then(function () {
      if (S.history.length && !S.project) { selectProject(S.history[0].name); }
    });
  }
  init();
})();
