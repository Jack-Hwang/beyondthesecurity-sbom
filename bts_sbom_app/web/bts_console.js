/*!
 * bts_console.js - page logic of the BTS-SBOM open-source security screen.
 * Written for BTS-SBOM; the renderer it drives (sca_app.js) and the platform stylesheets are copied unmodified (see NOTICE.md).
 * Rules: every dynamic value goes through esc() (analysed data comes from untrusted repositories and registries); no inline
 * event handlers (the page is served with a strict Content-Security-Policy); a pane shows "not computed" instead of a made-up value.
 */
(function () {
  'use strict';

  var GROUPS = {
    'git': ['git', 'lock', 'container'], 'risk': ['risk'], 'prioritize': ['ssvc', 'epss', 'exploit-mat'],
    'graph-health': ['dep-graph', 'arch', 'supply-chain'], 'compliance': ['ntia', 'vex', 'license-risk', 'sectors'],
    'fix': ['fix-plan', 'fix-pr'], 'more': ['more']
  };
  var LABELS = {
    'git': '🌐 Git repo', 'lock': '📦 Lockfile / path', 'container': '🐳 Container', 'risk': '📊 Overview',
    'ssvc': '🎯 SSVC', 'epss': '📡 EPSS', 'exploit-mat': '🔥 Exploit Mat.', 'dep-graph': '🕸 Dep Graph',
    'arch': '🏛 Architecture', 'supply-chain': '⛓ Supply Chain', 'ntia': '✅ SBOM checks', 'vex': '📋 VEX',
    'license-risk': '⚖ License Risk', 'sectors': '🏭 Industry reports', 'fix-plan': '🔧 Fix Plan',
    'fix-pr': '🔧 Patch', 'more': '⚙️ CI/CD · History'
  };
  var SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  var STEPS = ['Input', 'Configure', 'Analyze', 'Results'];
  var S = { project: '', view: null, triage: {}, history: [], members: {}, lastJob: null, busy: false, intelBusy: false, doneMsg: '' };

  /* ---------- helpers ---------- */
  function $(sel, root) { return (root || document).querySelector(sel); }
  function $$(sel, root) { return Array.prototype.slice.call((root || document).querySelectorAll(sel)); }
  function esc(v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function H(html) { return { html: html }; }                       // markup built here from escaped parts
  function cell(c) { return (c && c.html !== undefined) ? c.html : esc(c); }
  function api(url, body) {
    var opt = body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) };
    return fetch(url, opt).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (d) { return { ok: r.ok, status: r.status, data: d }; });
    }).catch(function (e) { return { ok: false, status: 0, data: { error: String(e) } }; });
  }
  function pill(text, cls) { return H('<span class="bts-pill ' + esc(cls) + '">' + esc(text) + '</span>'); }
  function note(html, cls) { return '<div class="bts-note ' + (cls || '') + '">' + html + '</div>'; }   // html: already escaped by the caller
  function kv(pairs) {
    return '<dl class="bts-kv">' + pairs.map(function (p) { return '<dt>' + esc(p[0]) + '</dt><dd>' + cell(p[1]) + '</dd>'; }).join('') + '</dl>';
  }
  function when(iso) { return iso ? String(iso).replace('T', ' ').slice(0, 16) : '—'; }

  /* ---------- tabs (same grouping as the platform screen) ---------- */
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
  function activate(sv) {
    var group = sv, member = sv;
    if ($('#view-scan .rtab[data-sv="' + sv + '"]')) { member = (GROUPS[sv] && GROUPS[sv][0]) || sv; }
    else { group = groupOf(sv); if (!group) { return; } }
    if (sv === group && S.members[group] && GROUPS[group].indexOf(S.members[group]) >= 0) { member = S.members[group]; }
    S.members[group] = member;
    $$('#view-scan .rtab').forEach(function (x) { x.classList.toggle('active', x.getAttribute('data-sv') === group); });
    $$('#view-scan .rpane').forEach(function (p) { p.classList.toggle('on', p.getAttribute('data-sv') === member); });
    subnav(group, member);
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
      row.insertBefore(bar, row.firstChild);
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
      return new Promise(function (resolve) {
        (function poll() {
          api('/api/jobs/' + encodeURIComponent(id)).then(function (j) {
            var d = j.data || {};
            if (d.state === 'running') {
              setStep(3, label + ': analysis engines are running (' + Math.round((Date.now() - t0) / 1000) + ' s).');
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
      S.doneMsg = 'Done: ' + (m.components || 0) + ' components, ' + (m.vulns || 0) + ' findings in ' + (m.elapsed_s || '?') + ' s.' +
                  (job.work_copy ? ' Download kept at ' + job.work_copy : '');
      setStep(4, S.doneMsg);
      // EPSS and CISA KEV are looked up right after the analysis (offline: the curated table only); a failure shows as a status, never as zero
      return loadHistory().then(function () { return selectProject(job.name, true); }).then(function () { return runIntel(); });
    });
  }
  function saveInternal() {
    var el = $('#supplyInternal');
    if (!el || !S.project) { return; }
    var names = el.value.split(/[\r\n,]+/).map(function (x) { return x.trim(); }).filter(Boolean);
    api('/api/supply-policy', { internal_names: names }).then(function (r) {
      if (!r.ok) { window.alert((r.data && r.data.error) || ('HTTP ' + r.status)); return; }
      selectProject(S.project, true);
    });
  }
  function reviewSupply(key, status) {
    var why = '';
    if (status !== 'open') {
      why = window.prompt('Why? The reason is kept with the decision.', '');
      if (why === null) { return; }
    }
    triage(key, status, why).catch(function (e) { window.alert(String(e && e.message || e)); });
  }
  function setIntelBusy(b) {
    S.intelBusy = b;
    $$('[data-act="intel"],#scaRiskRefresh').forEach(function (e) { e.disabled = b; });
  }
  function intelMessage(r) {
    var i = r.intel, e = i.epss, k = i.kev;
    if (!i.asked) { return 'EPSS · KEV: this project has no CVE ids to look up.'; }
    function part(name, s, ok) {
      return name + ' ' + (s.status === 'unavailable' ? 'unavailable (' + (s.error || 'no answer') + ')' : s.status === 'partial' ? 'partial' : s.status === 'table' ? 'offline table only' : 'ok' + ok);
    }
    return 'EPSS · KEV: ' + part('EPSS', e, ' (' + e.scored + ' of ' + i.asked + ' scored)') + ' · ' + part('KEV', k, ' (' + k.listed + ' listed)') +
      (r.kept_previous ? ' — the earlier stored result is kept.' : '.');
  }
  function runIntel() {
    if (!S.project || S.intelBusy) { return Promise.resolve(); }
    var name = S.project;
    setIntelBusy(true);
    setStep(4, 'Looking up EPSS (FIRST.org) and the CISA KEV catalog…');
    return api('/api/intel', { project: name, offline: !!$('#scaOffline').checked }).then(function (r) {
      setIntelBusy(false);
      if (!r.ok) { setStep(4, 'EPSS · KEV lookup failed: ' + ((r.data && r.data.error) || ('HTTP ' + r.status)), true); return null; }
      var i = r.data.intel, dead = i.asked && i.epss.status === 'unavailable' && i.kev.status === 'unavailable';
      var done = function () { setStep(4, (S.doneMsg ? S.doneMsg + ' ' : '') + intelMessage(r.data), !!dead); };
      return S.project === name ? selectProject(name, true).then(done) : done();
    });
  }
  function analyse(src) {
    src = (src || '').trim();
    if (!src) { setStep(1, 'Enter a repository URL or a local path.', true); return; }
    runJob({ source: src, offline: !!$('#scaOffline').checked, use_llm: !!$('#scaLlm').checked, keep: !!$('#scaKeep').checked }, 'Analysis');
  }

  /* ---------- local data bar (the platform's "Intel DB" bar), history, project ---------- */
  function chipPart(color, text) { return '<span style="color:' + color + '">' + esc(text) + '</span>'; }
  function loadEngine() {
    return Promise.all([api('/api/engine'), api('/api/db/status')]).then(function (rs) {
      var e = rs[0].data || {}, core = e.core || {}, db = rs[1].data || {}, parts = [];
      parts.push(core.version ? chipPart('var(--dcard-ok)', 'bts_sbom ' + core.version) : chipPart('var(--dcard-err)', 'bts_sbom unavailable (' + (core.error || 'unknown') + ')'));
      if (db.error) { parts.push(chipPart('var(--dcard-err)', 'OSV DB status unavailable')); }
      else if (db.exists) {
        var eco = (db.imported_ecosystems || []).length;
        parts.push(chipPart('var(--dcard-ok)', 'OSV cache ' + (db.exact_entries || 0) + ' · ' + eco + ' dump(s)'));
      } else { parts.push(chipPart('var(--dcard-warn)', 'OSV: online, no local DB')); }
      parts.push((e.llm && e.llm.key_configured) ? chipPart('var(--dcard-ok)', 'EXAONE on') : chipPart('var(--dcard-warn)', 'EXAONE off'));
      parts.push(chipPart('#858585', (e.projects || 0) + ' analysed'));
      $('#scaIntelChipTxt').innerHTML = parts.join('<span style="color:#444"> · </span>');
      if (db.path) { $('#scaIntelChipTxt').title = 'Local OSV database: ' + db.path; }
      $('#statusTxt').textContent = 'BTS-SBOM workflow ' + (e.workflow_version || '') + ' · evidence: ' + (e.evidence || '');
    });
  }
  function fillSelect() {
    var sel = $('#projSel');
    sel.innerHTML = S.history.length ? S.history.map(function (h) { return '<option value="' + esc(h.name) + '">' + esc(h.name) + '</option>'; }).join('')
                                     : '<option value="">(none analysed yet)</option>';
    if (S.project) { sel.value = S.project; }
  }
  function loadHistory() {
    return api('/api/history').then(function (r) { S.history = (r.data && r.data.history) || []; fillSelect(); renderHistory(); });
  }
  function selectProject(name, keepStep) {
    if (!name) { S.project = ''; S.view = null; renderAll(); return Promise.resolve(); }
    S.project = name;
    $('#projSel').value = name;
    return Promise.all([api('/api/view/' + encodeURIComponent(name)), api('/api/triage')]).then(function (rs) {
      if (!rs[0].ok) {
        S.view = null;
        $('#scaReportOut').innerHTML = note(esc((rs[0].data && rs[0].data.error) || 'The project could not be loaded.'), 'bad');
        renderPanes();
        return;
      }
      S.view = rs[0].data;
      S.triage = (rs[1].data && rs[1].data.triage) || {};
      renderAll();
      if (!keepStep) { S.doneMsg = ''; setStep(4, 'Showing ' + name + '.'); }
    });
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
  }
  // The copied renderer prints "No known exploit" / "no score available" for every finding that has no epss / kev field. That is true only
  // where a lookup answered; for the others the label is changed to "not looked up" (only the text of the chip changes).
  function relabelExploit(mount) {
    var known = {}, i = S.view && S.view.intel;
    ((i && i.known) || []).forEach(function (c) { known[c] = 1; });
    $$('.sx-issue', mount).forEach(function (row) {
      if (known[String(row.getAttribute('data-sx-trikey') || '').toUpperCase()]) { return; }
      var chip = $('.sx-chip-exp', row), lab = $('.sx-epss-label', row);
      if (chip && chip.textContent === 'No known exploit') { chip.textContent = 'Exploit data not looked up'; chip.title = 'EPSS and CISA KEV have no answer for this finding'; }
      if (lab && lab.textContent.indexOf('no score available') >= 0) { lab.textContent = 'EPSS — not looked up'; }
    });
  }
  function watchBrand() {
    var mount = $('#scaReportOut');
    new MutationObserver(function () { rebrand(mount); relabelExploit(mount); }).observe(mount, { childList: true, subtree: true });
  }
  function download(url) {
    var a = document.createElement('a');
    a.href = url; a.download = '';
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
    var mount = $('#scaReportOut'), banner = $('#scaBanner');
    banner.innerHTML = '';
    if (!S.view) { mount.innerHTML = ''; return; }
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
  }

  /* ---------- panes ---------- */
  // Findings = the platform's "SCA risk dashboard". The markup (cards, distribution panel, KEV and EPSS tables) is static in
  // index.html; this fills it. KEV, EPSS and the risk grade are not computed by this service: they stay "—" and the tables say so.
  var DASH_SEV = [['CRITICAL', 'var(--dcard-err)'], ['HIGH', '#fb923c'], ['MEDIUM', 'var(--dcard-warn)'], ['LOW', 'var(--dcard-ok)'], ['UNKNOWN', '#4b5563']];
  function emptyRow(text) { return '<tr><td colspan="4" style="padding:8px;text-align:center;color:var(--dcard-muted);font-size:11px">' + esc(text) + '</td></tr>'; }
  /* ---- EPSS / CISA KEV: a lookup the service stored next to the evidence (intel.py). Without one, or when a source failed, nothing is shown. ---- */
  function hasNum(x) { return typeof x === 'number' && isFinite(x); }
  function findingsOf(v) { return v ? v.report.findings : []; }
  function epssPct(e) { return (e >= 0.1 ? (e * 100).toFixed(1) : (e * 100).toFixed(2)) + '%'; }
  function intelWhy(v, which) {                  // why the value of one source is missing, or '' when that source answered
    var name = which === 'kev' ? 'KEV' : 'EPSS', i = v && v.intel;
    if (!v) { return NOPROJ; }
    if (!i) { return name + ' 조회 안 함 — Refresh 또는 Load 버튼으로 조회하세요. 조회하기 전에는 값을 만들지 않습니다'; }
    if (!i.asked) { return '조회할 CVE 번호가 없습니다 — 이 프로젝트의 취약점에는 CVE 번호가 없습니다'; }
    var s = i[which];
    return s.status === 'unavailable' ? name + ' 조회 실패 — ' + (s.error || '응답 없음') + ' (' + when(i.fetched_at) + '). 점수가 없는 것이지 0 이 아닙니다' : '';
  }
  function intelLine(v) {
    var i = v && v.intel;
    if (!v) { return ''; }
    if (!i) { return 'EPSS · KEV: 조회 안 함'; }
    if (!i.asked) { return 'EPSS · KEV: 조회할 CVE 없음'; }
    if (i.mode === 'offline-table') { return 'EPSS · KEV: ' + when(i.fetched_at) + ' offline 표(일부 데이터)'; }
    return 'EPSS · KEV: ' + when(i.fetched_at) + ' 조회 — EPSS ' + (i.epss.status === 'unavailable' ? '실패' : i.epss.status === 'partial' ? '일부' : (i.epss.date || 'ok')) +
      ' · KEV ' + (i.kev.status === 'unavailable' ? '실패' : (i.kev.catalog_version || 'ok'));
  }
  function sourceNote(i) {
    if (!i || !i.asked) { return ''; }
    var e = i.epss, k = i.kev;
    return pRef(esc('EPSS: ' + e.source + (e.date ? ' (모델 날짜 ' + e.date + ')' : '') + ' · CVE ' + i.asked + '개 중 ' + e.scored + '개에 점수 · KEV: ' + k.source + (k.catalog_version ? ' ' + k.catalog_version : '') +
      ' · 조회 ' + when(i.fetched_at) + (i.truncated ? ' · CVE 가 많아 일부만 조회했습니다' : '')));
  }
  function dataRow(cells) { return '<tr style="border-bottom:1px solid #1e293b">' + cells.join('') + '</tr>'; }
  function td(html, align) { return '<td style="padding:5px 8px;text-align:' + (align || 'left') + '">' + html + '</td>'; }
  function kevTitle(f) {
    var k = f.kev_info || {};
    return 'CISA KEV' + (k.added ? ' — 등재 ' + k.added : '') + (k.due ? ' · 조치 기한 ' + k.due : '') + (k.ransomware ? ' · 랜섬웨어 사용: ' + k.ransomware : '');
  }
  function fillRisk(v) {
    var s = v ? v.report.severity : null, total = s ? Math.max(1, s.total) : 1, fs = findingsOf(v), i = v && v.intel;
    $('#scaRiskWhich').textContent = v ? v.project + ' · analysed ' + when(v.analysed_at) + ' · ' + intelLine(v) : 'no project selected';
    $('#scaRiskTotal').textContent = s ? s.total : '—';
    $('#scaRiskCritical').textContent = s ? s.CRITICAL : '—';
    $('#scaRiskHigh').textContent = s ? s.HIGH : '—';
    // a KEV count needs a source that can say "not listed" (the full catalog) - or, offline, at least one listed CVE (a lower bound)
    var kev = fs.filter(function (f) { return f.kev === true; }).sort(function (a, b) { return (b.score || 0) - (a.score || 0); });
    var count = i && (i.kev.status === 'ok' || (i.kev.status === 'table' && kev.length)) ? kev.length : null;
    $('#scaRiskKev').textContent = count === null ? '—' : count;
    $('#scaRiskKev').parentNode.title = count === null ? intelWhy(v, 'kev') || 'KEV 값을 확인할 수 없습니다'
      : i.kev.status === 'table' ? 'offline 표에서 일치한 항목 수 — 하한값입니다' : 'CISA KEV 에 등재된 취약점 수 (카탈로그 ' + (i.kev.catalog_version || '?') + ')';
    $('#scaRiskGrade').textContent = '—';
    $('#scaRiskScore').textContent = '';
    $('#scaSevBars').innerHTML = DASH_SEV.map(function (c) {
      var n = s ? (s[c[0]] || 0) : 0, pct = Math.min(n / total * 100, 100).toFixed(1);
      return '<div style="display:flex;align-items:center;gap:8px"><span style="font-size:10px;color:#94a3b8;width:60px;flex-shrink:0">' + c[0] + '</span>' +
        '<div style="flex:1;height:14px;background:#1e293b;border-radius:3px;overflow:hidden"><div style="height:100%;width:' + pct + '%;background:' + c[1] + ';border-radius:3px"></div></div>' +
        '<span style="font-size:11px;font-weight:700;color:' + c[1] + ';width:28px;text-align:right">' + n + '</span></div>';
    }).join('');
    var kevWhy = intelWhy(v, 'kev');
    $('#scaKevBody').innerHTML = kev.length ? kev.map(function (f) {
      return dataRow([td('<span title="' + esc(kevTitle(f)) + '" style="font-family:monospace;color:#0969da">' + esc(f.cve) + '</span>'), td(esc(f.name + ' ' + f.version)),
        td(cell(sevTint(f.severity))), td(hasNum(f.score) ? f.score.toFixed(1) : '—', 'right')]);
    }).join('') : emptyRow(kevWhy || (i.kev.status === 'table' ? 'offline 표에서는 일치하는 항목이 없습니다 — 표는 일부만 담고 있어 "등재되지 않음"을 뜻하지 않습니다'
      : 'CISA KEV 에 등재된 취약점이 없습니다 (카탈로그 ' + (i.kev.catalog_version || '?') + ' 기준)'));
    var top = fs.filter(function (f) { return hasNum(f.epss); }).sort(function (a, b) { return b.epss - a.epss; }).slice(0, 5);
    $('#scaEpssBody').innerHTML = top.length ? top.map(function (f) {
      return dataRow([td('<span style="font-family:monospace;color:#0969da">' + esc(f.cve) + '</span>'), td(esc(f.name + ' ' + f.version)),
        td('<span title="percentile ' + esc(hasNum(f.epss_percentile) ? f.epss_percentile.toFixed(2) : '?') + '">' + epssPct(f.epss) + '</span>', 'right'), td(cell(sevTint(f.severity)))]);
    }).join('') : emptyRow(intelWhy(v, 'epss') || 'EPSS 점수가 공개된 취약점이 없습니다');
  }

  /* The other panes follow the platform's pane layout: a title row with a coloured action button, a grey description, dark summary cards and a
     flat table. Panes whose numbers BTS-SBOM does not compute keep the same layout with dashes and say why in the empty row. */
  var NOPROJ = '프로젝트를 선택하세요 — 상단 Project 목록에서 고르거나 Scan 탭에서 분석하세요';
  var TINT = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', UNKNOWN: '#94a3b8' };
  var CARD = {                                   // [background, border, value colour, label colour] (the platform's dark cards)
    red: ['#1f0a0a', '#b91c1c', '#ef4444', 'var(--dcard-err)'], orange: ['#1a0f00', '#9a3412', '#f97316', '#fb923c'],
    lime: ['#111700', '#3f6212', '#84cc16', '#a3e635'], green: ['#001a10', '#059669', '#34d399', 'var(--dcard-muted)'],
    blue: ['#0f172a', '#1e3a5f', '#60a5fa', 'var(--dcard-muted)'], grey: ['#0f0f0f', '#374151', '#9ca3af', 'var(--dcard-muted)'],
    pink: ['#1f0020', '#86198f', '#e879f9', '#f0abfc'], violet: ['#1a0020', '#7e22ce', '#c084fc', '#d8b4fe'],
    slate: ['#161b22', '#2a3040', '#e6edf3', 'var(--dcard-muted)']
  };
  var BTN_DL = 'background:#0a1020;border-color:#0e7490;color:#22d3ee;font-size:12px';
  function dash(x) { return (x === undefined || x === null || x === '') ? '—' : x; }
  function pCard(kind, val, label, valColor) {
    var c = CARD[kind];
    return '<div class="bts-pcard" style="background:' + c[0] + ';border-color:' + c[1] + '"><div class="v" style="color:' + (valColor || c[2]) + '">' + esc(dash(val)) +
      '</div><div class="l" style="color:' + c[3] + '">' + esc(label) + '</div></div>';
  }
  function tCard(val, label, color) {            // tinted card (platform: license risk summary)
    return '<div class="bts-pcard" style="background:' + color + '22;border-color:' + color + '55"><div class="v" style="color:' + color + '">' + esc(dash(val)) +
      '</div><div class="l" style="color:var(--dcard-muted)">' + esc(label) + '</div></div>';
  }
  function pCards(list) { return '<div class="bts-pcards">' + list.join('') + '</div>'; }
  function pHead(color, title, btns) { return '<div class="bts-ph"><div class="bts-pt" style="color:' + color + '">' + title + '</div>' + (btns || '') + '</div>'; }
  function pBtn(label, act, style, o) {          // label/style are literals of this file; o.off = reason the button cannot work (it is shown disabled)
    o = o || {};
    return '<button type="button" class="run" data-act="' + esc(act) + '" style="' + style + '"' + (o.off ? ' disabled title="' + esc(o.off) + '"' : '') +
      (o.job && S.busy ? ' disabled' : '') + (o.intel && S.intelBusy ? ' disabled' : '') + (o.attrs || '') + '>' + label + '</button>';
  }
  function pDesc(t) { return '<div class="bts-pd">' + esc(t) + '</div>'; }
  function pSub(color, t, sub) { return '<div class="bts-ps" style="color:' + color + '">' + esc(t) + (sub ? '<small>' + esc(sub) + '</small>' : '') + '</div>'; }
  function pRef(html) { return '<div class="bts-ref">' + html + '</div>'; }          // html: already escaped by the caller
  function tint(text, color) { return H('<span class="bts-tint" style="background:' + color + '22;color:' + color + ';border-color:' + color + '55">' + esc(text) + '</span>'); }
  function sevTint(s) { s = String(s || 'UNKNOWN').toUpperCase(); return tint(s, TINT[s] || TINT.UNKNOWN); }
  function pTab(heads, rows, empty, left) {
    left = left || [0];
    var cls = function (i) { return left.indexOf(i) >= 0 ? ' class="l"' : ''; };
    return '<div class="bts-wrap"><table class="pt"><thead><tr>' + heads.map(function (h, i) { return '<th' + cls(i) + '>' + esc(h) + '</th>'; }).join('') + '</tr></thead><tbody>' +
      (rows.length ? rows.map(function (r) { return '<tr>' + r.map(function (c, i) { return '<td' + cls(i) + '>' + cell(c) + '</td>'; }).join('') + '</tr>'; }).join('')
        : '<tr><td class="empty" colspan="' + heads.length + '">' + esc(empty || '데이터 없음') + '</td></tr>') + '</tbody></table></div>';
  }
  function sevRank(s) { var i = SEVS.indexOf(String(s || '').toUpperCase()); return i < 0 ? 9 : i; }

  /* ---- Prioritize / supply chain: not computed here ---- */
  function paneSsvc(v) {
    var off = 'SSVC 입력(악용 여부, 자동화 가능성, 미션 영향)을 이 서비스는 수집하지 않아 판정하지 않습니다';
    return pHead('#f59e0b', '&#127919; SSVC 의사결정 트리', pBtn('&#127919; Score CVEs', 'na', 'background:#1a1000;border-color:#92400e;color:#f59e0b', { off: off })) +
      pDesc('SSVC(Stakeholder-Specific Vulnerability Categorization) — Exploitation·Automatable·Technical Impact → ACT/ATTEND/TRACK 결정.') +
      pCards([pCard('red', '—', 'ACT 즉시 패치'), pCard('orange', '—', 'ATTEND 단기 처리'), pCard('lime', '—', 'TRACK 추적 관리')]) +
      pTab(['CVE', 'Package', 'Exploit', 'Auto', 'Impact', 'EPSS', 'Decision'], [], v ? 'SSVC 판정 안 함 — ' + off + '. 값을 만들어 내지 않습니다' : NOPROJ);
  }
  var BANDS = [['≥ 50%', 0.5, 2, '#ef4444'], ['10 – 50%', 0.1, 0.5, '#f97316'], ['1 – 10%', 0.01, 0.1, '#eab308'], ['< 1%', 0, 0.01, '#22c55e']];
  function epssBar(f) {
    var pct = Math.max(0, Math.min(100, f.epss * 100)).toFixed(1);
    return H('<div title="percentile ' + esc(hasNum(f.epss_percentile) ? f.epss_percentile.toFixed(2) : '?') + '" style="display:flex;align-items:center;gap:6px;justify-content:center">' +
      '<div style="width:50px;height:6px;border-radius:3px;background:#cbd5e1"><div style="width:' + pct + '%;height:6px;border-radius:3px;background:#818cf8"></div></div>' +
      '<span style="font-size:11px;color:#4f46e5">' + epssPct(f.epss) + '</span></div>');
  }
  function paneEpss(v) {
    var i = v && v.intel, why = intelWhy(v, 'epss'), all = findingsOf(v), shown = !!v && !!i && !why;
    var scored = all.filter(function (f) { return hasNum(f.epss); }).sort(function (a, b) { return b.epss - a.epss || sevRank(a.severity) - sevRank(b.severity); });
    var out = pHead('#818cf8', '&#128225; EPSS Priority Queue', pBtn('&#128225; Load EPSS', 'intel', 'background:#0d0a2a;border-color:#3730a3;color:#818cf8', { off: v ? '' : NOPROJ, intel: true })) +
      pDesc('FIRST.org EPSS 점수 기반 CVE 우선순위 큐 — 앞으로 30일 안에 악용될 확률이 높은 취약점부터 보여 줍니다. 점수는 CVE 번호가 있는 취약점에만 있고, 점수를 받지 못한 항목은 0 이 아니라 점수 없음입니다.');
    out += pCards(BANDS.map(function (b) {
      return tCard(shown ? scored.filter(function (f) { return f.epss >= b[1] && f.epss < b[2]; }).length : '—', 'EPSS ' + b[0], b[3]);
    }).concat([tCard(shown ? all.length - scored.length : '—', shown && i.epss.status === 'ok' ? 'No score' : 'No score / not covered', '#94a3b8')]));
    out += pTab(['CVE ID', 'Component', 'Severity', 'EPSS', 'KEV', 'Fixed in'], scored.slice(0, 300).map(function (f) {
      return [f.cve, f.name + ' ' + f.version, sevTint(f.severity), epssBar(f), f.kev === true ? tint('KEV', '#ef4444') : '—', f.fixed || '—'];
    }), why || (v ? 'EPSS 점수가 공개된 취약점이 없습니다' : NOPROJ), [0, 1]);
    return out + (i ? sourceNote(i) : '');
  }
  // Maturity from the two measured sources only (the same order as the console's exploit chip): KEV > EPSS >= 50% > any EPSS score > nothing known.
  var TIERS = [['IN_THE_WILD', 'In the wild (KEV)', '#ef4444'], ['HIGH_EPSS', 'High EPSS (≥ 50%)', '#f97316'], ['EPSS_OBSERVED', 'EPSS observed', '#eab308'], ['NO_KNOWN', 'No known', '#22c55e']];
  function tierOf(f, i) {
    if (!i) { return ''; }
    if (f.kev === true) { return 'IN_THE_WILD'; }
    if (hasNum(f.epss)) { return f.epss >= 0.5 ? 'HIGH_EPSS' : 'EPSS_OBSERVED'; }
    return f.kev === false && i.epss.status === 'ok' ? 'NO_KNOWN' : '';
  }
  function paneExploit(v) {
    var i = v && v.intel, why = intelWhy(v, 'kev') && intelWhy(v, 'epss'), all = findingsOf(v), rank = {};
    TIERS.forEach(function (t, n) { rank[t[0]] = n; });
    var rows = all.map(function (f) { return { f: f, t: tierOf(f, i) }; }).filter(function (r) { return r.t; })
      .sort(function (a, b) { return rank[a.t] - rank[b.t] || (b.f.epss || 0) - (a.f.epss || 0); });
    var out = pHead('#f97316', '&#128293; Exploit Maturity Dashboard', pBtn('&#128293; Load', 'intel', 'background:#1a0f00;border-color:#9a3412;color:#f97316', { off: v ? '' : NOPROJ, intel: true })) +
      pDesc('EPSS + CISA KEV → 단계: KEV 등재 = IN_THE_WILD, EPSS ≥ 50% = HIGH_EPSS, 그 밖의 EPSS 점수 = EPSS_OBSERVED, 두 소스 모두 없음 = NO_KNOWN. 공개 익스플로잇 참조를 따지는 FUNCTIONAL · POC 단계는 판정하지 않습니다.');
    out += pCards(TIERS.map(function (t) { return pCard('slate', i ? rows.filter(function (r) { return r.t === t[0]; }).length : '—', t[1], t[2]); })
      .concat([pCard('slate', i ? all.length - rows.length : '—', 'Not determined', '#94a3b8')]));
    out += pTab(['CVE', 'Component', 'Version', 'CVSS', 'EPSS', 'KEV', 'Maturity'], rows.slice(0, 300).map(function (r) {
      var f = r.f, t = TIERS[rank[r.t]];
      return [f.cve, f.name, f.version, hasNum(f.score) ? f.score.toFixed(1) : '—', hasNum(f.epss) ? epssPct(f.epss) : '—', f.kev === true ? tint('KEV', '#ef4444') : f.kev === false ? 'no' : '—', tint(t[0], t[2])];
    }), why || (v && !i ? intelWhy(v, 'kev') : v ? '단계를 판정할 수 있는 취약점이 없습니다' : NOPROJ), [0, 1]);
    return out + (i ? sourceNote(i) : '');
  }
  /* ---- Supply chain: the core's name-based checks (supply.py). A finding is a name resemblance, never proof; "no finding" is never "safe". ---- */
  var SC_KIND = { 'typosquat': 'Typosquat', 'homoglyph': 'Homoglyph', 'namespace-confusion': 'Namespace confusion', 'dependency-confusion': 'Dependency confusion' };
  var SC_CONF = { high: '#e879f9', medium: '#c084fc', low: '#94a3b8' };
  var SC_REVIEW = { 'false-positive': 'False positive', accepted: 'Accepted', wontfix: "Won't fix", fixed: 'Fixed' };
  function scAction(f, status, label) {
    return '<button type="button" class="bts-link" data-act="supply-review" data-key="' + esc(f.key) + '" data-status="' + status + '">' + label + '</button>';
  }
  function scReview(f) {
    if (!f.key) { return '—'; }
    if (f.review) {
      return H(tint(SC_REVIEW[f.review.status] || f.review.status, '#94a3b8').html + ' ' + scAction(f, 'open', 'reopen') +
        (f.review.note ? '<div style="font-size:10px;color:#6b7280">' + esc(f.review.note) + '</div>' : ''));
    }
    return H(scAction(f, 'false-positive', 'false positive') + ' · ' + scAction(f, 'accepted', 'accept'));
  }
  function scDetail(f) {
    return f.description + ' → ' + f.recommendation + (f.note ? ' [' + f.note + ']' : '') + ' (' + f.cwe + ')';
  }
  function paneSupply(v) {
    var d = v ? v.supply : null, head = pHead('#e879f9', '&#9939; 공급망 공격 대시보드', pBtn('&#9939; Load Dashboard', 'reload', 'background:#1a0020;border-color:#86198f;color:#e879f9', { off: v ? '' : NOPROJ })) +
      pDesc('타이포스쿼팅 · 동형 문자 · 스코프 이름 가로채기 · 의존성 혼동 — 패키지 이름만 널리 쓰이는 패키지 목록과 비교합니다. 결과는 "이름이 비슷하다"는 경고이며 악성이라는 증거가 아닙니다(패키지 내용과 게시자는 보지 않습니다).');
    var heads = ['Package', 'Version', 'Risk Type', 'Confidence', 'Detail', 'Review'];
    if (!d) {
      return head + pCards([pCard('pink', '—', 'High confidence'), pCard('violet', '—', 'Medium confidence'), pCard('grey', '—', 'Open findings')]) + pTab(heads, [], NOPROJ, [0, 4]);
    }
    if (d.status === 'failed') {
      return head + note('<b>공급망 검사가 실패했습니다.</b> ' + esc(d.error) + ' — 이것은 "안전함"이 아니라 결과가 없다는 뜻입니다.', 'bad');
    }
    var c = d.counts || {}, out = head;
    out += pCards([pCard('pink', c.high, 'High confidence'), pCard('violet', c.medium, 'Medium confidence'), pCard('grey', c.open, 'Open findings')]);
    if (d.status === 'partial') { out += note('<b>' + esc(d.errors) + '개 패키지는 검사하지 못했습니다</b> (' + esc(d.error) + '). 아래는 나머지 패키지의 결과입니다.', 'warn'); }
    var seed = d.ecosystems.filter(function (e) { return e.covered; }).map(function (e) { return e.seed; }).reduce(function (a, b) { return a + b; }, 0);
    out += pTab(heads, d.findings.slice(0, 300).map(function (f) {
      return [f.package, (f.versions || []).slice(0, 4).join(', ') || '—', SC_KIND[f.kind] || f.kind, tint(f.confidence, SC_CONF[f.confidence] || '#94a3b8'), scDetail(f), scReview(f)];
    }), '탐지된 항목 없음 — 검사한 ' + d.checked + '개 패키지(이름 비교 목록 ' + seed + '개 이름)에서 비슷한 이름을 찾지 못했습니다. 이것이 안전하다는 뜻은 아닙니다', [0, 4]);
    out += pSub('#e879f9', 'Coverage', '어떤 생태계를 검사했는가 — 이름 비교 목록이 없는 생태계는 검사하지 않습니다');
    out += pTab(['Ecosystem', 'Packages', 'Popular-name list', 'Checked'], d.ecosystems.map(function (e) {
      return [e.ecosystem, e.packages, e.seed ? e.seed + ' names' : '—', e.covered ? pill('yes', 'ok') : pill('no list', 'warn')];
    }), '컴포넌트가 없습니다');
    out += pSub('#e879f9', 'Internal package names', '의존성 혼동은 여기 적은 이름에 대해서만 판정합니다 (한 줄에 하나)');
    out += '<textarea id="supplyInternal" class="bts-ta" rows="3" style="max-width:420px" placeholder="acme-billing&#10;@acme/core">' + esc((d.internal || []).join('\n')) + '</textarea>' +
      '<div class="bts-actions">' + pBtn('Apply', 'supply-policy', BTN_DL) + '</div>';
    return out + pRef('검사 대상 ' + esc(d.packages) + '개 패키지 중 ' + esc(d.checked) + '개가 이름 비교 목록이 있는 생태계입니다 · 코어 ' + esc(d.core) + ' · 탐지가 없다고 안전한 것은 아니며, 이 검사는 목록에 있는 이름과의 유사성만 봅니다. ' +
      '내부 이름이 공개 레지스트리에서 받아지는지는 확인하지 않습니다(그 이름이 의존성에 있다는 사실만 알려 줍니다). 검토 결과(오탐/수용)는 모든 프로젝트에 적용됩니다.');
  }

  /* ---- Graph & Health ---- */
  // The platform draws a force-directed graph of parent -> child edges. BTS-SBOM records which manifest a component comes from, not its parents,
  // so the graph is manifest -> component: one cluster per manifest, worst findings nearest the centre, filled dot = has findings.
  function graphSvg(ms, flagged) {
    var W = 900, H = 480, k = ms.length, edges = '', dots = '', labels = '', shown = 0, total = 0, vuln = 0;
    var cols = Math.max(1, Math.ceil(Math.sqrt(k * W / H))), rows = Math.ceil(k / cols), cw = W / cols, ch = H / rows;
    var R = Math.max(30, Math.min(cw, ch) / 2 - 16);
    function key(c) { return String(c.ecosystem || '').toLowerCase() + '|' + String(c.name || '').toLowerCase(); }
    function rk(c) { return flagged[key(c)] ? -1 : c.vuln_count ? sevRank(c.worst_severity) : 8; }
    ms.forEach(function (m, i) {
      var cx = cw * (i % cols) + cw / 2, cy = ch * Math.floor(i / cols) + ch / 2, ring = 0, idx = 0;
      var comps = (m.children || []).slice().sort(function (a, b) { return rk(a) - rk(b) || (b.vuln_count || 0) - (a.vuln_count || 0) || String(a.name).localeCompare(String(b.name)); });
      total += comps.length;
      while (idx < comps.length) {
        var r = 24 + ring * 14;
        if (r > R) { break; }
        var cap = Math.max(6, Math.floor(2 * Math.PI * r / 14));
        for (var s = 0; s < cap && idx < comps.length; s++, idx++) {
          var c = comps[idx], a = 2 * Math.PI * s / cap + ring * 0.6, x = (cx + r * Math.cos(a)).toFixed(1), y = (cy + r * Math.sin(a)).toFixed(1);
          var col = c.vuln_count ? (TINT[String(c.worst_severity).toUpperCase()] || TINT.UNKNOWN) : TINT.LOW;
          vuln += c.vuln_count ? 1 : 0;
          var sc = flagged[key(c)];
          edges += '<line x1="' + cx.toFixed(1) + '" y1="' + cy.toFixed(1) + '" x2="' + x + '" y2="' + y + '" stroke="#21262d" stroke-width="1"/>';
          dots += '<circle cx="' + x + '" cy="' + y + '" r="' + (c.vuln_count ? 5.5 : 4.5) + '" fill="' + (c.vuln_count ? col : col + '22') + '" stroke="' + col + '" stroke-width="1.5"><title>' +
            esc(c.name + ' ' + (c.version || '') + (c.vuln_count ? ' — ' + c.vuln_count + ' finding(s), worst ' + c.worst_severity : ' — no known vulnerability') +
              (sc ? ' — name resembles ' + sc.resembles + ' (' + sc.kind + ')' : '')) + '</title></circle>' +
            (sc ? '<circle cx="' + x + '" cy="' + y + '" r="9" fill="none" stroke="#e879f9" stroke-width="2"/>' : '');
        }
        ring++;
      }
      shown += idx;
      var base = String(m.path || '').split('/').slice(-2).join('/') || String(m.path || ''), lab = base.length > 26 ? '…' + base.slice(-25) : base;   // last two segments: many manifests share a file name
      dots += '<circle cx="' + cx.toFixed(1) + '" cy="' + cy.toFixed(1) + '" r="11" fill="#1f2937" stroke="#818cf8" stroke-width="2"><title>' + esc(m.path) + '</title></circle>';
      labels += '<text x="' + cx.toFixed(1) + '" y="' + Math.max(12, cy - Math.min(R, 24 + ring * 14) - 6).toFixed(1) + '" text-anchor="middle" font-size="10" fill="#9ca3af">' + esc(lab) + '</text>';
    });
    return { svg: edges + dots + labels, shown: shown, total: total, vuln: vuln };
  }
  function depGraph(v) {
    var C = '#818cf8', ms = v ? ((v.report.dep_tree || {}).manifests || []) : [], flagged = {};
    ((v && v.supply && v.supply.findings) || []).forEach(function (f) {
      if (!f.review) { flagged[String(f.ecosystem || '').toLowerCase() + '|' + String(f.package || '').toLowerCase()] = f; }
    });
    var g = ms.length ? graphSvg(ms, flagged) : null;
    var out = pHead(C, '&#128376; 의존성 그래프', pBtn('&#128257; Load Graph', 'reload', 'background:#0f0f2a;border-color:#4338ca;color:#818cf8', { off: v ? '' : NOPROJ })) +
      pDesc('매니페스트별 컴포넌트를 그래프로 보여 줍니다. 노드 색상 = CVE 심각도(채운 점 = 취약점 있음, 빈 점 = 알려진 취약점 없음). 간선은 매니페스트 → 컴포넌트이며 컴포넌트 사이의 부모 관계는 BTS-SBOM 이 기록하지 않습니다.');
    out += '<div class="bts-gcanvas">' + (g ? '<svg viewBox="0 0 900 480" preserveAspectRatio="xMidYMid meet" role="img" aria-label="manifest to component graph">' + g.svg + '</svg>'
      : '<div class="ph">' + esc(v ? '매니페스트를 찾지 못했습니다' : '▶ ' + NOPROJ) + '</div>') + '</div>';
    out += '<div class="bts-glegend"><span style="color:#ef4444">● CRITICAL</span><span style="color:#f97316">● HIGH</span><span style="color:#eab308">● MEDIUM</span>' +
      '<span style="color:#22c55e">● LOW</span><span style="color:#22c55e">○ 취약점 없음</span><span style="color:#818cf8">◉ 매니페스트</span><span style="color:#e879f9">◎ 이름이 유사한 패키지(공급망)</span></div>';
    out += '<div class="bts-ginfo">' + (g ? esc(ms.length + '개 매니페스트 · ' + g.total + '개 컴포넌트 중 ' + g.shown + '개 표시(취약 ' + g.vuln + '개) · 점에 마우스를 올리면 이름이 보입니다' +
      (g.shown < g.total ? ' · 나머지는 아래 표를 보세요' : '')) : '') + '</div>';
    out += pSub(C, 'Dependencies by manifest', ms.length + ' manifest(s)');
    out += pTab(['Manifest', 'Ecosystems', 'Total', 'Direct', 'Transitive', 'Vulnerable', 'Max depth'], ms.map(function (m) {
      return [m.path, (m.ecosystems || []).join(', '), m.total, m.direct, m.transitive, m.vulnerable, m.max_depth];
    }), v ? 'No manifest was found.' : NOPROJ);
    var comps = [];
    ms.forEach(function (m) { (m.children || []).forEach(function (c) { if (c.vuln_count) { comps.push(c); } }); });
    comps.sort(function (a, b) { return b.vuln_count - a.vuln_count; });
    out += pSub(C, 'Most vulnerable components', 'top 15');
    out += pTab(['Component', 'Version', 'Findings', 'Worst', 'Relationship', 'Fixed in (plan)'], comps.slice(0, 15).map(function (c) {
      return [c.name, c.version, c.vuln_count, sevTint(c.worst_severity), c.relationship, dash(c.fixed_latest)];
    }), v ? 'No vulnerable component.' : NOPROJ);
    return out;
  }
  function arch(v) {
    var C = '#818cf8', a = v ? (v.arch || {}) : {}, g = a.graph || {}, lang = (a.stack || {}).languages || {};
    var out = pHead(C, '&#127963; Legacy architecture') +
      pDesc('import 그래프 · 변경 이력(hotspot, change coupling) · 런타임 end-of-life · 현대화 후보 — 소스 트리를 분석한 결과입니다.');
    if (!v) { return out + pTab(['Module'], [], NOPROJ); }
    if (!g.modules && !(a.hotspots || []).length && !(a.runtime_eol || []).length) {
      return out + note('No architecture data was produced for this project (not a source tree, or the stage did not run).');
    }
    out += pCards([pCard('blue', g.modules, 'Modules'), pCard('blue', g.import_edges, 'Import edges'), pCard(g.cycle_count > 0 ? 'red' : 'green', g.cycle_count, 'Import cycles'),
      pCard('blue', g.tangle_ratio, 'Tangle ratio'), pCard('blue', g.max_depth, 'Max layer depth')]);
    out += kv([['Languages', Object.keys(lang).map(function (k) { return k + ' (' + lang[k].files + ' files, ' + lang[k].loc + ' loc)'; }).join(', ') || '—'],
               ['History', a.history ? (a.history.commits + ' commits' + (a.history.shallow ? ' (shallow clone)' : '')) : '—'],
               ['Modules in cycles', dash(g.modules_in_cycles)]]);
    (a.notes || []).forEach(function (n) { out += note(esc(n), 'warn'); });
    out += pSub(C, 'Hotspots', 'churn × complexity');
    out += pTab(['File', 'Commits', 'Churn', 'LOC', 'Complexity', 'Score'], (a.hotspots || []).map(function (h) { return [h.file, h.commits, h.churn, h.loc, h.complexity, h.score]; }), 'No hotspots.');
    out += pSub(C, 'Change coupling', 'files that change together');
    out += pTab(['A', 'B', 'Shared commits', 'Jaccard', 'No import link'], (a.coupling || []).map(function (c) { return [c.a, c.b, c.shared, c.jaccard, c.hidden ? 'yes' : 'no']; }), 'No coupled pairs.', [0, 1]);
    out += pSub(C, 'Import cycles');
    out += pTab(['Cycle'], (a.cycles || []).map(function (c) { return [Array.isArray(c) ? c.join(' → ') : String(c)]; }), 'No import cycle was found.');
    out += pSub(C, 'Runtime end-of-life');
    out += pTab(['Product', 'Cycle', 'Declared in', 'Status', 'EOL date', 'Source'], (a.runtime_eol || []).map(function (r) {
      return [r.product, r.cycle, r.declared_in, pill(r.status, r.status === 'eol' ? 'bad' : r.status === 'supported' ? 'ok' : 'warn'), r.eol_date, r.source];
    }), 'No runtime declaration was found.', [0, 2, 5]);
    out += pSub(C, 'Modernisation candidates');
    out += pTab(['Kind', 'Priority', 'Target', 'Why'], (a.modernization || []).map(function (m) { return [m.kind, m.priority, m.target, m.why]; }), 'None.', [0, 2, 3]);
    return out;
  }

  /* ---- Compliance ---- */
  function sbomChecks(v) {
    var G = '#34d399', c = v ? (v.sbom_check || {}) : {}, ri = c.ref_integrity || {}, n = v ? encodeURIComponent(v.project) : '', off = v ? '' : NOPROJ;
    function ok(flag) { return flag === undefined ? '—' : flag ? 'valid' : 'invalid'; }
    var out = pHead(G, '&#9989; SBOM checks', pBtn('&#8635; Reload', 'reload', 'background:#001a10;border-color:#059669;color:#34d399', { off: off })) +
      pDesc('같은 findings 로 만든 CycloneDX 1.5 / SPDX 2.3 문서를 스키마와 참조 무결성으로 검사한 결과입니다.');
    out += pCards([pCard(c.cyclonedx_valid === undefined ? 'grey' : c.cyclonedx_valid ? 'green' : 'red', ok(c.cyclonedx_valid), 'CycloneDX 1.5'),
      pCard(c.spdx_valid === undefined ? 'grey' : c.spdx_valid ? 'green' : 'red', ok(c.spdx_valid), 'SPDX 2.3'),
      pCard('blue', c.components, 'Components'), pCard('blue', c.vulnerabilities, 'Vulnerabilities')]);
    out += pTab(['Check', 'Result', 'Detail'], v ? [
      ['CycloneDX 1.5 schema', pill(ok(c.cyclonedx_valid), c.cyclonedx_valid ? 'ok' : 'bad'), (c.cyclonedx_errors || []).length + ' error(s)'],
      ['SPDX 2.3 schema', pill(ok(c.spdx_valid), c.spdx_valid ? 'ok' : 'bad'), (c.spdx_errors || []).length + ' error(s)'],
      ['Vulnerability references resolved', ri.affects ? pill(ri.resolved === ri.affects ? 'all' : 'partial', ri.resolved === ri.affects ? 'ok' : 'warn') : '—',
       ri.affects ? (ri.resolved + ' of ' + ri.affects + ' (' + ri.rate + ')') : '—']] : [], NOPROJ, [0, 2]);
    (c.cyclonedx_errors || []).concat(c.spdx_errors || []).forEach(function (e) { out += note(esc(e), 'bad'); });
    if (v) {
      out += '<div class="bts-actions">' + pBtn('&#128196; CycloneDX JSON', 'dl', BTN_DL, { attrs: ' data-url="/api/sbom/' + n + '?format=cdx"' }) +
        pBtn('&#128196; SPDX JSON', 'dl', BTN_DL, { attrs: ' data-url="/api/sbom/' + n + '?format=spdx"' }) +
        pBtn('&#128196; OpenVEX JSON', 'dl', BTN_DL, { attrs: ' data-url="/api/sbom/' + n + '?format=vex"' }) +
        pBtn('&#128196; Report (Markdown)', 'dl', BTN_DL, { attrs: ' data-url="/api/doc/' + n + '"' }) + '</div>';
    }
    return out + pRef('NTIA 최소 요소 점수는 이 워크플로에서 계산하지 않아 점수와 등급을 표시하지 않습니다.');
  }
  var DECISION_COLOR = { open: '#f59e0b', accepted: '#60a5fa', fixed: '#22c55e', wontfix: '#94a3b8', false_positive: '#94a3b8' };
  function vex(v) {
    var O = '#fb923c', fs = v ? v.report.findings : [], n = v ? encodeURIComponent(v.project) : '', off = v ? '' : NOPROJ;
    var marked = fs.filter(function (f) { return f.triage_status && f.triage_status !== 'open'; });
    var out = pHead(O, '&#128203; VEX Report',
      pBtn('&#128203; Load VEX', 'reload', 'background:#1a0a00;border-color:#c2410c;color:#fb923c', { off: off }) +
      pBtn('&#128228; OpenVEX 내보내기', 'dl', 'background:#1a0a00;border-color:#7c2d12;color:#fed7aa;font-size:12px', { off: off, attrs: v ? ' data-url="/api/sbom/' + n + '?format=vex"' : '' })) +
      pDesc('OpenVEX 문서는 findings 에서 생성됩니다. 콘솔에서 내린 무시 결정(accepted · fixed · wont fix · false positive)은 증거 폴더에 저장되지만 아직 OpenVEX 파일에는 반영되지 않습니다.');
    out += pCards([pCard('blue', v ? fs.length : '—', 'Findings'), pCard('slate', v ? marked.length : '—', 'Decisions recorded'), pCard('slate', v ? fs.length - marked.length : '—', 'Open', '#f59e0b')]);
    out += pTab(['Advisory', 'Component', 'Version', 'Severity', 'Decision', 'KEV'], fs.slice(0, 200).map(function (f) {
      var st = f.triage_status || 'open';
      return [f.cve || f.id, f.name, f.version, sevTint(f.severity), tint(st, DECISION_COLOR[st] || '#94a3b8'), '—'];
    }), v ? 'CVE 없음 — 이 프로젝트에서 취약점이 발견되지 않았습니다(분석 범위 안에서).' : NOPROJ);
    return out + pRef((fs.length > 200 ? esc((fs.length - 200) + '개 항목은 Findings 탭에서 보세요. ') : '') + 'KEV 열은 CISA KEV 를 조회하지 않아 비어 있습니다. 결정(Decision)은 콘솔 값이며 OpenVEX status 가 아닙니다.');
  }
  var RISK_COLOR = { CRITICAL: '#ef4444', HIGH: '#f97316', MEDIUM: '#eab308', LOW: '#22c55e', OK: '#22c55e', UNRESOLVED: '#94a3b8' };
  function licences(v) {
    var L = '#65a30d', l = v ? (v.license || {}) : {}, pk = v ? (v.report.packages || []) : [], st = l.stats || {}, cats = ((v ? v.report.licenses : {}) || {}).summary || {}, cc = cats.category_counts || {};
    var sevOf = {};
    (l.policy || []).forEach(function (p) { sevOf[p.category] = String(p.severity || '').toUpperCase(); });
    var by = { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, OK: 0, UNRESOLVED: 0 }, copyleft = 0;
    var rows = pk.map(function (p) {
      var risk = !p.license ? 'UNRESOLVED' : (sevOf[p.category] || 'OK');
      by[risk] = (by[risk] || 0) + 1;
      copyleft += (p.obligations || {}).gpl_warning ? 1 : 0;
      return { p: p, risk: risk };
    });
    rows.sort(function (a, b) { return sevRank(a.risk) - sevRank(b.risk) || String(a.p.name).localeCompare(String(b.p.name)); });
    var out = pHead(L, '&#9878; License Risk Matrix', pBtn('&#9878; Load License Risk', 'reload', 'background:#0f1a00;border-color:#4d7c0f;color:#a3e635', { off: v ? '' : NOPROJ })) +
      pDesc('저작권 오염 위험 매트릭스 — 컴포넌트마다 라이선스(lockfile → deps.dev → 레지스트리)와 출처를 기록하고, 기본 정책(배포 = binary)으로 위험을 판정합니다. 해석하지 못한 라이선스는 추측하지 않고 Unresolved 로 둡니다.');
    var cardList = ['CRITICAL', 'HIGH', 'MEDIUM'].map(function (k) { return tCard(v ? by[k] : '—', k, RISK_COLOR[k]); });
    if (by.LOW) { cardList.push(tCard(by.LOW, 'LOW', RISK_COLOR.LOW)); }
    cardList.push(tCard(v ? by.OK : '—', 'OK', RISK_COLOR.OK), tCard(v ? by.UNRESOLVED : '—', 'Unresolved', RISK_COLOR.UNRESOLVED), tCard(v ? copyleft : '—', 'Copyleft', '#c084fc'));
    out += pCards(cardList);
    out += pTab(['Package', 'Version', 'License', 'Category', 'Risk'], rows.slice(0, 300).map(function (r) {
      return [r.p.name, r.p.version, r.p.license || '—', r.p.category || '—', tint(r.risk === 'UNRESOLVED' ? 'unresolved' : r.risk, RISK_COLOR[r.risk] || '#94a3b8')];
    }), v ? '컴포넌트가 없습니다' : NOPROJ);
    if (rows.length > 300) { out += pRef(esc((rows.length - 300) + '개 컴포넌트는 표시하지 않았습니다(위험도 순 정렬).')); }
    if (!v) { return out; }
    out += pSub(L, 'Resolution', 'where each license came from');
    out += kv([['Project license', (l.project_license || '—') + (l.project_license_source ? ' (' + l.project_license_source + ')' : '')],
               ['Resolved', (st.resolved || 0) + ' of ' + (st.total || 0) + (st.resolved_rate !== undefined && st.resolved_rate !== null ? ' (' + st.resolved_rate + ')' : '')],
               ['By source', Object.keys(st.by_source || {}).map(function (k) { return k + ': ' + st.by_source[k]; }).join(', ') || '—'],
               ['Categories', Object.keys(cc).map(function (k) { return k + ': ' + cc[k]; }).join(', ') || '—']]);
    out += pSub(L, 'Policy findings', 'default policy: distribution = binary');
    out += pTab(['Category', 'Severity', 'Components', 'Affected'], (l.policy || []).map(function (p) {
      return [p.category, sevTint(p.severity), p.count, (p.components || []).slice(0, 6).join(', ') + ((p.components || []).length > 6 ? ' …' : '')];
    }), 'No license policy finding.', [0, 3]);
    if ((l.unresolved || []).length) { out += pSub(L, 'Unresolved', 'left unresolved on purpose, never guessed'); out += note(esc(l.unresolved.join(', '))); }
    return out;
  }
  function sectors(v) {
    var G = '#34d399', s = v ? (v.sectors || {}) : {}, keys = Object.keys(s);
    var out = pHead(G, '&#127981; Industry reports') +
      pDesc('판정은 SBOM · VEX 문서에서 계산합니다. 근거가 없는 요구사항은 not_evidence 로 표시하며 통과로 처리하지 않습니다.');
    if (!keys.length) { return out + pTab(['Industry', 'Title', 'Verdict', 'Pass', 'Gap', 'No evidence'], [], v ? 'No industry report was produced for this project.' : NOPROJ, [0, 1]); }
    out += pTab(['Industry', 'Title', 'Verdict', 'Pass', 'Gap', 'No evidence'], keys.map(function (k) {
      var x = s[k], sm = x.summary || {};
      return [k, x.title, pill(x.verdict, x.verdict === 'pass' || x.verdict === 'ready' ? 'ok' : x.verdict === 'gaps' ? 'bad' : 'warn'), sm.pass, sm.gap, sm.not_evidence];
    }), '', [0, 1]);
    keys.forEach(function (k) {
      var x = s[k];
      out += '<details style="margin:8px 0"><summary style="cursor:pointer;font-weight:600">' + esc(k) + ' — ' + esc(x.title || '') + '</summary>' +
        (x.honesty ? note(esc(x.honesty)) : '') +
        pTab(['Requirement', 'Title', 'Verdict', 'Detail'], (x.requirements || []).map(function (r) {
          return [r.id, r.title, pill(r.verdict, r.verdict === 'pass' ? 'pass' : r.verdict === 'gap' ? 'gap' : 'not_evidence'), r.detail]; }), '', [0, 1, 3]) + '</details>';
    });
    return out;
  }

  /* ---- Fix ---- */
  function fixPlan(v) {
    var P = '#a78bfa', ps = v ? (v.plans || []).filter(function (p) { return p.status === 'upgrade'; }) : [], pr = v ? (v.proposals || {}) : {};
    var clears = ps.reduce(function (n, p) { return n + (p.cve_count || 0); }, 0);
    var out = pHead(P, '&#128295; Fix Plan Priority Queue') +
      pDesc('컴포넌트마다 모든 advisory 를 해소하는 가장 낮은 버전과 major bump 경고를 보여 줍니다(OSV 로 재확인). KEV · 도달 가능성 기반 우선순위는 계산하지 않습니다.');
    out += pCards([pCard('slate', v ? ps.length : '—', 'Upgradeable', 'var(--dcard-ok)'), pCard('slate', v ? ps.filter(function (p) { return p.major_bump; }).length : '—', 'Major Bumps', '#f97316'),
      pCard('slate', v ? clears : '—', 'Advisories cleared', '#e6edf3'), pCard('slate', v ? ps.filter(function (p) { return (p.verification || {}).clean === true; }).length : '—', 'Verified clean', 'var(--dcard-ok)')]);
    out += pTab(['Component', 'From', 'To', 'Clears', 'Worst', 'Breaking risk', 'Verified clean'], ps.map(function (p) {
      var ver = p.verification || {};
      return [p.component, p.current_version, p.safe_version, p.cve_count, sevTint(p.max_severity), p.major_bump ? pill(p.breaking_risk || 'major bump', 'warn') : '—',
              ver.clean === true ? pill('yes', 'ok') : ver.clean === false ? pill('no', 'bad') : pill('not verified', 'muted')];
    }), v ? 'No upgrade is needed or possible (see the findings for entries without a fixed version).' : NOPROJ);
    if (!v) { return out; }
    out += pSub(P, 'Proposals', 'source: ' + (pr.source || 'none') + (pr.model ? ' (' + pr.model + ')' : ''));
    if (pr.llm_note) { out += note(esc(pr.llm_note), 'warn'); }
    out += pTab(['Action', 'Risk', 'Proposal', 'Why'], (pr.items || []).map(function (i) { return [i.action, i.risk, i.title, i.rationale]; }), 'No proposal was produced.', [0, 2, 3]);
    return out + pRef('제안은 분석 결과와 대조해 검증합니다(모르는 버전이나 advisory 는 버림). 사람이 검토한 것은 아닙니다.');
  }
  var BTN_GREEN = 'background:#14532d;border-color:#16a34a;color:#86efac';
  function fixPr(v) {
    var Gn = '#16a34a', p = v ? (v.patch || {}) : {}, st = p.status || 'not_requested';
    var out = pHead(Gn, '&#128295; Fix PR — 승인 후 패치') +
      pDesc('권고된 fixed 버전으로 매니페스트를 임시 작업 사본에서 고치고, 다시 스캔해 검증하며, 악화되면 되돌립니다. 원본(origin)은 수정하지 않고, fixed 버전이 없는 패키지는 추측하지 않고 그대로 둡니다.');
    if (!v) { return out + pTab(['Component', 'From', 'To', 'Breaking risk'], [], NOPROJ); }
    out += note('<b>절차.</b> 1) 계획 미리보기: 아무것도 바꾸지 않습니다. 2) 계획을 검토하고 digest 로 승인합니다. 3) 임시 작업 사본의 매니페스트를 수정하고 다시 스캔하며, 수정한 파일의 findings 가 늘면 되돌립니다. ' +
      'Lockfile 은 수정하지 않고 재생성 명령만 보여 줍니다. <b>패치된 코드는 빌드·테스트하지 않았습니다.</b>');
    out += '<div class="bts-actions">' + pBtn('1 · Preview plan (changes nothing)', 'plan', BTN_GREEN, { job: true }) + '</div>';
    if (st === 'not_requested') { return out + pRef('이 분석에 대해 패치를 요청한 적이 없습니다.'); }
    if (st === 'not_approved') {
      out += pSub(Gn, 'Plan to review', 'digest ' + (p.digest || ''));
      out += pTab(['Component', 'From', 'To', 'Breaking risk'], (p.plans || []).map(function (x) { return [x.component, x.current_version, x.safe_version, x.breaking_risk || '—']; }), 'The plan is empty.');
      if ((p.plans || []).length) {
        out += '<label style="font-size:12px;display:block;margin:8px 0"><input type="checkbox" id="ackPlan"> I reviewed this plan (digest <code>' + esc(p.digest) + '</code>)</label>' +
          '<div class="bts-actions">' + pBtn('2 · Approve and apply on a work copy', 'apply', BTN_GREEN, { attrs: ' disabled' }) + '</div>';
      }
      return out;
    }
    var rounds = p.rounds || [];
    out += pSub(Gn, 'Result', st);
    out += kv([['Status', pill(st, st === 'applied' ? 'ok' : st === 'regression_reverted' || st === 'digest_mismatch' ? 'bad' : 'warn')], ['Components edited', p.applied_components],
               ['Findings before', (p.before || {}).vulns], ['After re-scan', (p.after || {}).vulns_rescan], ['Estimated after (plan)', (p.after || {}).vulns_estimated],
               ['Fixed, confirmed by re-scan', p.rescan_fixed_total], ['Branch / commit', (p.branch || '—') + ' / ' + String(p.commit || '—').slice(0, 10)],
               ['Work copy', (S.lastJob && S.lastJob.work_copy) || '—']]);
    if (p.note) { out += note(esc(p.note), 'warn'); }
    if (st === 'regression_reverted') { out += note('The edit made things worse in the edited files, so it was <b>reverted</b>.', 'bad'); }
    if (st === 'digest_mismatch') { out += note('The plan changed since it was reviewed. Preview it again.', 'bad'); }
    if ((p.regenerate || []).length) { out += pSub(Gn, 'Regenerate lockfiles'); out += note('<code>' + (p.regenerate || []).map(esc).join('</code><br><code>') + '</code>'); }
    out += pTab(['Round', 'Status', 'Applied', 'Blocked', 'Manual', 'Before', 'After'], rounds.map(function (r) { return [r.round, r.status, r.applied, r.blocked, r.manual, r.vulns_before, r.vulns_after]; }), 'No round ran.');
    var d = p.diff || {};
    if (d.stat || d.patch) {
      out += pSub(Gn, 'Changed files', 'work copy against the base commit');
      if (d.stat) { out += '<pre class="bts-diff">' + esc(d.stat) + '</pre>'; }
      if (d.patch) { out += pSub(Gn, 'Diff'); out += '<pre class="bts-diff">' + esc(d.patch) + '</pre>'; }
    }
    return out;
  }

  /* ---- CI/CD · History: the platform's two panels ---- */
  function renderHistory() {
    var off = 'BTS-SBOM 은 아직 파이프라인 파일을 만들지 않습니다';
    var out = '<div class="pathbox"><label>&#9881;&#65039; CI/CD pipeline generator — run the policy gate in your pipeline</label>' +
      '<div style="display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap"><label style="font-size:12px;margin:0">Platform</label>' +
      '<select disabled style="width:auto"><option>GitHub Actions</option><option>GitLab CI</option></select>' +
      '<label style="font-size:12px"><input type="checkbox" disabled checked> Policy gate</label>' +
      '<input disabled value="." title="source path" style="width:110px">' +
      '<button class="run" type="button" disabled title="' + esc(off) + '" style="margin-left:auto">▶ Generate</button></div>' +
      '<div class="ex">' + esc(off + '. CI 에서는 코어 명령 bts-sbom policy 의 종료 코드(통과 0 · 위반 1 · 입력 오류 2)를 게이트로 사용하세요. 이 화면은 정책 게이트를 실행하지 않습니다.') + '</div></div>';
    out += '<div class="pathbox"><label>&#128200; History / Trends — analysed projects</label>' +
      '<div style="display:flex;gap:10px;align-items:center;margin-top:10px;flex-wrap:wrap"><label style="font-size:12px;margin:0">Kind</label>' +
      '<select disabled style="width:auto"><option>SCA</option></select>' +
      '<button class="run" type="button" data-act="reloadHist" style="margin-left:auto">&#8635; Load</button></div>' +
      '<div class="ex">' + esc('증거 폴더에 저장된 분석을 프로젝트마다 최신 한 건씩 보여 줍니다. 시계열 추이와 baseline ↔ compare 비교는 아직 없습니다.') + '</div>' +
      '<div style="margin-top:10px">' + pTab(['Project', 'Source', 'Analysed', 'Components', 'Findings', 'License resolved', 'Patch', 'Proposals', ''], S.history.map(function (h) {
        return [h.name, h.source, when(h.analysed_at), h.components, h.vulns, h.license_resolved_rate === null || h.license_resolved_rate === undefined ? '—' : h.license_resolved_rate,
                h.patch_status || '—', h.proposal_source || '—', H('<button type="button" class="bts-link" data-act="open" data-name="' + esc(h.name) + '">Open</button>')];
      }), '아직 분석한 프로젝트가 없습니다 — Scan 탭에서 분석하세요', [0, 1]) + '</div></div>';
    $('#paneHistory').innerHTML = out;
  }
  function renderPanes() {
    var v = S.view;
    var map = { paneSsvc: paneSsvc, paneEpss: paneEpss, paneExploit: paneExploit, paneSupply: paneSupply, paneDep: depGraph, paneArch: arch, paneSbom: sbomChecks,
                paneVex: vex, paneLic: licences, paneSectors: sectors, paneFixPlan: fixPlan, paneFixPr: fixPr };
    Object.keys(map).forEach(function (id) { $('#' + id).innerHTML = map[id](v); });
    fillRisk(v);
    renderHistory();
  }

  /* ---------- menu bar (same DOM contract as the platform's: .menubar > .mb-item, .mb-drop > .mb-row / .mb-sep / .mb-head) ---------- */
  function mountMenubar(barSel, menus) {
    var bar = $(barSel);
    if (!bar) { return; }
    bar.innerHTML = menus.map(function (m, i) { return '<div class="mb-item" data-idx="' + i + '">' + esc(m.name) + '</div>'; }).join('') + '<div class="mb-drop" style="display:none"></div>';
    var dd = $('.mb-drop', bar), open = -1;
    function closeM() { open = -1; dd.style.display = 'none'; $$('.mb-item', bar).forEach(function (x) { x.classList.remove('active'); }); }
    function openM(i) {
      open = i;
      $$('.mb-item', bar).forEach(function (x, k) { x.classList.toggle('active', k === i); });
      dd.innerHTML = menus[i].items.map(function (it, k) {
        if (it.sep) { return '<div class="mb-sep"></div>'; }
        if (it.head) { return '<div class="mb-head">' + esc(it.head) + '</div>'; }
        var off = it.enabled && !it.enabled();
        return '<div class="mb-row' + (off ? ' disabled' : '') + '" data-i="' + k + '">' + ((it.check && it.check()) ? '✓ ' : '') + esc(it.label) + '</div>';
      }).join('');
      dd.style.left = $$('.mb-item', bar)[i].offsetLeft + 'px';
      dd.style.display = 'block';
    }
    bar.addEventListener('click', function (e) {
      var row = e.target.closest('.mb-row'), it = e.target.closest('.mb-item');
      if (row) {
        var item = menus[open] && menus[open].items[+row.getAttribute('data-i')];
        if (!item || (item.enabled && !item.enabled())) { return; }
        closeM();
        if (item.act) { item.act(); }
      } else if (it) { var i = +it.getAttribute('data-idx'); if (open === i) { closeM(); } else { openM(i); } }
    });
    bar.addEventListener('mouseover', function (e) {
      var it = e.target.closest('.mb-item');
      if (open >= 0 && it && +it.getAttribute('data-idx') !== open) { openM(+it.getAttribute('data-idx')); }
    });
    document.addEventListener('click', function (e) { if (!e.target.closest(barSel)) { closeM(); } });
    document.addEventListener('keydown', function (e) { if (e.key === 'Escape') { closeM(); } });
  }
  var ABOUT = 'OSV.dev - open-source vulnerability database, queried online (the core can also use a local OSV database). deps.dev and the PyPI / npm / Maven registries - ' +
    'licenses, with the source recorded for every component. FIRST.org EPSS scores and the CISA KEV catalog - looked up after an analysis and on Refresh ' +
    '(Offline: only a small curated table). The supply-chain check compares package names with a small list of popular packages. SBOMs are written as CycloneDX 1.5, SPDX 2.3 and OpenVEX.';
  var HONESTY = 'Nothing is made up: a package that was not queried stays flagged, a license that could not be resolved stays unresolved, an empty result is reported as empty ' +
    '(never as a pass), EPSS and KEV are shown only where a lookup really answered (a failed or missing lookup is never a score of 0 or "not exploited"), ' +
    'supply-chain findings are name resemblances (never proof, and "none" is never "safe"), and values this service does not compute (SSVC, risk grade) are shown as a dash.';
  function hasProject() { return !!S.project; }
  function curGroup() { var t = $('#view-scan .rtab.active'); return t ? t.getAttribute('data-sv') : 'git'; }
  function exportDoc(kind) { if (S.project) { download('/api/sbom/' + encodeURIComponent(S.project) + '?format=' + kind); } }
  var MENUS = [
    { name: 'Scan', items: [
      { label: 'Analyze Git repo…', act: function () { activate('git'); $('#scaGitUrl').focus(); } },
      { label: 'Analyze local path…', act: function () { activate('git'); $('#scaGitUrl').focus(); } },
      { sep: 1 },
      { label: 'Lockfile / path', act: function () { activate('lock'); } },
      { sep: 1 },
      { label: 'Run demo repo', act: function () { $('#scaDemoBtn').click(); } }] },
    { name: 'Export', items: [
      { head: 'Last report' },
      { label: 'CycloneDX SBOM', enabled: hasProject, act: function () { exportDoc('cdx'); } },
      { label: 'SPDX 2.3 SBOM', enabled: hasProject, act: function () { exportDoc('spdx'); } },
      { label: 'OpenVEX', enabled: hasProject, act: function () { exportDoc('vex'); } },
      { label: 'Markdown report', enabled: hasProject, act: function () { if (S.project) { download('/api/doc/' + encodeURIComponent(S.project)); } } }] },
    { name: 'View', items: [
      { label: 'Git repo — OSS vuln · license · SBOM', check: function () { return curGroup() === 'git'; }, act: function () { activate('git'); } },
      { label: 'Lockfile / path', check: function () { return S.members.git === 'lock' && curGroup() === 'git'; }, act: function () { activate('lock'); } },
      { label: 'CI/CD · History', check: function () { return curGroup() === 'more'; }, act: function () { activate('more'); } }] },
    { name: 'Help', items: [
      { label: 'About the data sources', act: function () { window.alert(ABOUT); } },
      { label: 'Honesty model', act: function () { window.alert(HONESTY); } }] }
  ];
  function renderAll() {
    renderConsole();
    renderPanes();
    var ack = $('#ackPlan');
    if (ack) { ack.addEventListener('change', function () { var b = $('[data-act="apply"]'); if (b) { b.disabled = !ack.checked || S.busy; } }); }
  }

  /* ---------- chat ---------- */
  function ask() {
    var q = $('#chatQ').value.trim(), out = $('#chatOut');
    if (!q) { return; }
    out.textContent = 'Thinking…';
    api('/api/chat', { question: q, project: S.project || undefined, use_llm: !!$('#chatLlm').checked }).then(function (r) {
      var d = r.data || {};
      if (!r.ok) { out.textContent = d.error || ('HTTP ' + r.status); return; }
      var srcs = {};
      (d.claims || []).forEach(function (c) { srcs[c.source] = 1; });
      out.innerHTML = '<div>' + esc((d.found ? '' : '[not found] ') + (d.answer || '')) + '</div><div class="bts-chat-src">source: ' + esc(d.answer_source) +
        ' · citation accuracy: ' + esc(d.citation_accuracy) + (Object.keys(srcs).length ? ' · evidence: ' + esc(Object.keys(srcs).join(', ')) : '') + '</div>';
    });
  }

  /* ---------- events ---------- */
  document.addEventListener('click', function (e) {
    var t = e.target.closest ? e.target.closest('[data-act],.rtab,.egchip') : null;
    if (!t) { return; }
    if (t.classList.contains('rtab')) { activate(t.getAttribute('data-sv')); return; }
    if (t.classList.contains('egchip')) { $('#scaGitUrl').value = t.getAttribute('data-url'); $('#scaGitUrl').focus(); return; }
    var act = t.getAttribute('data-act');
    if (act === 'goto') { activate(t.getAttribute('data-sv')); }
    else if (act === 'dl') { download(t.getAttribute('data-url')); }
    else if (act === 'reload') { if (S.project) { selectProject(S.project, true); } }
    else if (act === 'intel') { runIntel(); }
    else if (act === 'supply-policy') { saveInternal(); }
    else if (act === 'supply-review') { reviewSupply(t.getAttribute('data-key'), t.getAttribute('data-status')); }
    else if (act === 'reloadHist') { loadHistory(); }
    else if (act === 'open') { selectProject(t.getAttribute('data-name')).then(function () { activate('risk'); }); }
    else if (act === 'plan' && S.view) { runJob({ source: S.view.source, patch: true, approved: false, offline: !!$('#scaOffline').checked }, 'Plan preview').then(function () { activate('fix-pr'); }); }
    else if (act === 'apply' && S.view && S.view.patch && S.view.patch.digest && ($('#ackPlan') || {}).checked) {
      runJob({ source: S.view.source, patch: true, approved: true, approval_token: S.view.patch.digest, offline: !!$('#scaOffline').checked }, 'Approved patch').then(function () { activate('fix-pr'); });
    }
  });
  function init() {
    activate('git');
    setStep(1, 'Choose an input source.');
    $('#runScaReport').addEventListener('click', function () { activate('git'); analyse($('#scaGitUrl').value); });
    $('#scaGitUrl').addEventListener('keydown', function (e) { if (e.key === 'Enter') { analyse($('#scaGitUrl').value); } });
    $('#scaDemoBtn').addEventListener('click', function () { $('#scaGitUrl').value = 'https://github.com/adeyosemanputra/pygoat.git'; analyse($('#scaGitUrl').value); });
    $('#runLock').addEventListener('click', function () { var p = $('#lockPath').value.trim(); $('#scaGitUrl').value = p; activate('git'); analyse(p); });
    $('#projSel').addEventListener('change', function () { selectProject($('#projSel').value); });
    $('#scaIntelRefreshBtn').addEventListener('click', function () { loadEngine(); loadHistory(); });
    $('#scaRiskRefresh').addEventListener('click', function () { runIntel(); });
    $('#helpBtn').addEventListener('click', function () { window.alert(ABOUT + '\n\n' + HONESTY); });
    mountMenubar('#scanMenubar', MENUS);
    $('#chatBtn').addEventListener('click', ask);
    $('#chatQ').addEventListener('keydown', function (e) { if (e.key === 'Enter') { ask(); } });
    watchBrand();
    renderPanes();
    loadEngine();
    loadHistory().then(function () {
      if (S.history.length && !S.project) { selectProject(S.history[0].name); }
    });
  }
  init();
})();
