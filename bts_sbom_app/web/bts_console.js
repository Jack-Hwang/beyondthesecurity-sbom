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
    'git': ['git', 'lock', 'container'], 'risk': ['risk', 'changes'], 'prioritize': ['ssvc', 'epss', 'exploit-mat'],
    'graph-health': ['dep-graph', 'arch', 'supply-chain'], 'compliance': ['ntia', 'conformance', 'vex', 'license-risk', 'sectors'],
    'fix': ['fix-plan', 'fix-pr'], 'oss': ['oss'], 'more': ['more', 'fleet']
  };
  var LABELS = {
    'git': '🌐 Git repo', 'lock': '📦 Lockfile / path', 'container': '🐳 Container', 'risk': '📊 Overview', 'changes': '🔔 What changed',
    'ssvc': '🎯 SSVC', 'epss': '📡 EPSS', 'exploit-mat': '🔥 Exploit Mat.', 'dep-graph': '🕸 Dep Graph',
    'arch': '🏛 Architecture', 'supply-chain': '⛓ Supply Chain', 'ntia': '✅ SBOM checks', 'conformance': '📐 SBOM conformance',
    'vex': '📋 VEX · Decisions', 'license-risk': '⚖ License Risk', 'sectors': '🏭 Industry reports', 'fix-plan': '🔧 Fix Plan',
    'fix-pr': '🔧 Patch', 'oss': '📜 OSS Scanner', 'more': '⚙️ CI/CD · History', 'fleet': '🗂 Fleet · Affected'
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
      setStep(4, 'Done: ' + (m.components || 0) + ' components, ' + (m.vulns || 0) + ' findings in ' + (m.elapsed_s || '?') + ' s.');
      return loadHistory().then(function () { return selectProject(job.name, true); });
    });
  }
  function analyse(src) {
    src = (src || '').trim();
    if (!src) { setStep(1, 'Enter a repository URL or a local path.', true); return; }
    runJob({ source: src, offline: !!$('#scaOffline').checked, use_llm: !!$('#scaLlm').checked }, 'Analysis');
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
      fillSelect(); renderHistory();
      loadFleet();                                                     // the roll-up covers the same evidence folder: refresh it with the list
    });
  }
  function selectProject(name, keepStep) {
    if (!name) { S.project = ''; S.view = null; resetGovernance(); renderAll(); return Promise.resolve(); }
    S.project = name;
    $('#projSel').value = name;
    return Promise.all([api('/api/view/' + encodeURIComponent(name)), api('/api/triage')]).then(function (rs) {
      if (!rs[0].ok) {
        S.view = null;
        resetGovernance();
        $('#scaReportOut').innerHTML = note(esc((rs[0].data && rs[0].data.error) || 'The project could not be loaded.'), 'bad');
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
    S.gov = { seq: S.gov.seq + 1, conformance: null, changes: null, vex: null };
  }
  function loadGovernance(name) {
    resetGovernance();
    var seq = S.gov.seq, n = encodeURIComponent(name);
    renderGovernance();
    [['conformance', '/api/conformance/'], ['changes', '/api/changes/'], ['vex', '/api/vex/']].forEach(function (p) {
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
  }
  function watchBrand() {
    var mount = $('#scaReportOut');
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
    out += heading('Policy findings', 'default policy: distribution = binary');
    out += table(['Category', 'Severity', 'Components', 'Affected'], (l.policy || []).map(function (p) {
      return [p.category, sevBadge(p.severity), p.count, (p.components || []).slice(0, 6).join(', ') + ((p.components || []).length > 6 ? ' …' : '')];
    }), 'No license policy finding.');
    if ((l.unresolved || []).length) { out += heading('Unresolved', 'left unresolved on purpose, never guessed'); out += note(esc(l.unresolved.join(', '))); }
    return out;
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
  function fixPlan(v) {
    var ps = (v.plans || []).filter(function (p) { return p.status === 'upgrade'; }), pr = v.proposals || {};
    var out = heading('Upgrade plan', 'lowest version that clears every advisory, re-checked against OSV');
    out += table(['Component', 'From', 'To', 'Clears', 'Worst', 'Breaking risk', 'Verified clean'], ps.map(function (p) {
      var ver = p.verification || {};
      return [p.component, p.current_version, p.safe_version, p.cve_count, sevBadge(p.max_severity), p.major_bump ? pill(p.breaking_risk || 'major bump', 'warn') : '—',
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
      '<b>The patched code has not been built or tested.</b>');
    out += '<div class="bts-actions">' + btn('1 · Preview plan (changes nothing)', 'plan', 'job', S.busy ? ' disabled' : '') + '</div>';
    if (st === 'not_requested') { return out + note('No patch has been requested for this analysis yet.'); }
    if (st === 'not_approved') {
      out += heading('Plan to review', 'digest ' + (p.digest || ''));
      out += table(['Component', 'From', 'To', 'Breaking risk'], (p.plans || []).map(function (x) { return [x.component, x.current_version, x.safe_version, x.breaking_risk || '—']; }), 'The plan is empty.');
      if ((p.plans || []).length) {
        out += '<label style="font-size:12px;display:block;margin:8px 0"><input type="checkbox" id="ackPlan"> I reviewed this plan (digest <code>' + esc(p.digest) + '</code>)</label>' +
          '<div class="bts-actions">' + btn('2 · Approve and apply on a work copy', 'apply', 'job', ' disabled') + '</div>';
      }
      return out;
    }
    var rounds = p.rounds || [];
    out += heading('Result', st);
    out += kv([['Status', pill(st, st === 'applied' ? 'ok' : st === 'regression_reverted' || st === 'digest_mismatch' ? 'bad' : 'warn')], ['Components edited', p.applied_components],
               ['Findings before', (p.before || {}).vulns], ['After re-scan', (p.after || {}).vulns_rescan], ['Estimated after (plan)', (p.after || {}).vulns_estimated],
               ['Fixed, confirmed by re-scan', p.rescan_fixed_total], ['Branch / commit', (p.branch || '—') + ' / ' + String(p.commit || '—').slice(0, 10)],
               ['Work copy', (S.lastJob && S.lastJob.work_copy) || '—']]);
    if (p.note) { out += note(esc(p.note), 'warn'); }
    if (st === 'regression_reverted') { out += note('The edit made things worse in the edited files, so it was <b>reverted</b>.', 'bad'); }
    if (st === 'digest_mismatch') { out += note('The plan changed since it was reviewed. Preview it again.', 'bad'); }
    if ((p.regenerate || []).length) { out += heading('Regenerate lockfiles'); out += note('<code>' + (p.regenerate || []).map(esc).join('</code><br><code>') + '</code>'); }
    out += table(['Round', 'Status', 'Applied', 'Blocked', 'Manual', 'Before', 'After'], rounds.map(function (r) { return [r.round, r.status, r.applied, r.blocked, r.manual, r.vulns_before, r.vulns_after]; }), 'No round ran.');
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
  function renderPanes() {
    var v = S.view;
    $('#paneContainer').innerHTML = '<b>Container image scanning is not supported by BTS-SBOM.</b> Analyse the repository or lockfile the image is built from instead.';
    $('#paneSsvc').innerHTML = unavailable('SSVC', 'CISA SSVC decisions need exploitation, automatable and mission-impact inputs that this workflow does not collect.');
    $('#paneEpss').innerHTML = unavailable('EPSS', 'No EPSS feed is wired into this workflow, so a finding has no score (it is absent, not zero).');
    $('#paneExploit').innerHTML = unavailable('Exploit maturity', 'It needs exploit-database and CISA KEV matching, which this workflow does not do.');
    $('#paneSupply').innerHTML = unavailable('Supply chain', 'Typosquatting and dependency-confusion detection exists in the core (bts_sbom.supply_chain) but is not wired into this workflow yet.');
    var map = { paneRisk: risk, paneDep: depGraph, paneArch: arch, paneSbom: sbomChecks, paneLic: licences, paneSectors: sectors, paneFixPlan: fixPlan, paneFixPr: fixPr };
    Object.keys(map).forEach(function (id) { $('#' + id).innerHTML = v ? map[id](v) : needProject(); });
    renderHistory();
    renderGovernance();
  }
  function renderAll() {
    renderConsole();
    renderPanes();
    var ack = $('#ackPlan');
    if (ack) { ack.addEventListener('change', function () { var b = $('[data-act="apply"]'); if (b) { b.disabled = !ack.checked || S.busy; } }); }
  }

  /* ---------- governance panes: conformance, what changed, VEX + decisions, fleet ---------- */
  function renderGovernance() {
    var v = S.view, g = S.gov, ages = analysedMap();
    $('#paneConformance').innerHTML = v ? G.renderConformance(g.conformance)
      : heading('SBOM conformance') + note(G.LEGAL_NOTE, 'warn') + needProject();
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
    else if (act === 'dl') { download(t.getAttribute('data-url'), t.getAttribute('data-fname')); }
    else if (act === 'triage-save') { saveDecision(); }
    else if (act === 'affected') { searchAffected(); }
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
    $('#chatBtn').addEventListener('click', ask);
    $('#chatQ').addEventListener('keydown', function (e) { if (e.key === 'Enter') { ask(); } });
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
