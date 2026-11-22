/*!
 * oss_scanner.js - the OSS scan engine of the BTS-SBOM screen (source / dependency / binary scan, results, licenses, notice).
 * Since the scan-entry unification the FORM pieces (analysis modes, exclude globs) and the "Previous scans" list live on
 * the 🌐 Scan landing pane, in the index.html containers #scaOssModes / #scaOssExcludes / #ossHistoryLanding next to the
 * main input row; THIS pane (#paneOss, the 📜 OSS 결과 sub-tab of the Scan section) renders the progress and the results
 * (license risk / source / dependency / binary / OSS notice / export). bts_console.js starts the scan through
 * window.BtsOss.start() - one ▶ Analyze on the landing runs the main pipeline and this engine on the same target.
 * Written for BTS-SBOM. Rules (same as bts_console.js): every dynamic value is put into the page with textContent /
 * setAttribute (analysed data comes from untrusted repositories); no HTML-string writes, no inline event handlers
 * (strict Content-Security-Policy); a view says "not available" instead of showing a made-up value.
 */
(function () {
  'use strict';
  var root = document.getElementById('paneOss');
  var modesBox = document.getElementById('scaOssModes');
  var exBox = document.getElementById('scaOssExcludes');
  var histBox = document.getElementById('ossHistoryLanding');
  if (!root || !modesBox || !exBox || !histBox) { return; }

  var S = { job: null, epoch: 0, kind: 'src', q: '', sort: 'path', dir: 'asc', offset: 0, limit: 50, total: 0, excludes: [], overview: null };
  var KINDS = { src: 'Source', dep: 'Dependency', bin: 'Binary' };
  var PATHLABEL = { src: 'Source Path', dep: 'Package URL', bin: 'Binary Path' };
  var STAGES = [['prepare', 'Prepare (download / extract)'], ['analyze', 'Analyze'], ['normalize', 'Normalize results']];
  var FORMATS = ['xlsx', 'csv', 'json', 'yaml', 'spdx-json', 'spdx-tag', 'cyclonedx-json', 'cyclonedx-xml'];

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
    });
  }
  function note(text, cls) { return el('div', { 'class': 'oss-note ' + (cls || ''), text: text }); }

  /* ---------- landing form pieces: analysis modes + exclude globs (the target row itself is index.html markup) ---------- */
  var modes = {};
  var modeRow = el('div', { 'class': 'oss-row' }, [el('span', { 'class': 'sub', text: 'Analysis:' })]);
  [['source', 'Source code'], ['dependency', 'Dependency'], ['binary', 'Binary']].forEach(function (m) {
    var cb = el('input', { type: 'checkbox', checked: 'checked' });
    modes[m[0]] = cb;
    modeRow.appendChild(el('label', { 'class': 'oss-chk' }, [cb, ' ' + m[1]]));
  });
  var corr = el('input', { type: 'checkbox', checked: 'checked' });
  modeRow.appendChild(el('label', { 'class': 'oss-chk', title: 'Apply sbom-info.yaml from the project root (corrections / exclusions)' }, [corr, ' apply sbom-info.yaml']));
  modesBox.appendChild(modeRow);

  var exIn = el('input', { placeholder: 'exclude path or glob (e.g. node_modules, test/*) - Enter to add', spellcheck: 'false', style: 'flex:1;min-width:240px' });
  var exChips = el('span', { 'class': 'oss-chips' });
  exBox.appendChild(el('div', { 'class': 'oss-row' }, [exIn, exChips]));

  function renderChips() {
    exChips.textContent = '';
    S.excludes.forEach(function (x, i) {
      var b = el('button', { type: 'button', 'class': 'oss-chip', title: 'remove', text: x + ' \u00D7' });
      b.addEventListener('click', function () { S.excludes.splice(i, 1); renderChips(); });
      exChips.appendChild(b);
    });
  }
  exIn.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && exIn.value.trim()) { S.excludes.push(exIn.value.trim()); exIn.value = ''; renderChips(); }
  });

  /* the form the console reads on every ▶ Analyze; null means "no analysis type selected" (the console reports that honestly) */
  function readForm() {
    var m = Object.keys(modes).filter(function (k) { return modes[k].checked; });
    if (!m.length) { return null; }
    var br = document.getElementById('ossBranch');
    return { modes: m, excludes: S.excludes.slice(), branch: br ? br.value.trim() : '', correction: corr.checked };
  }

  /* ---------- results pane (#paneOss): progress + result, with an honest empty state ---------- */
  var progress = el('div', { 'class': 'oss-steps' });
  var idle = note('No scan is open yet. One \u25B6 Analyze on the \uD83C\uDF10 Scan landing runs this engine together with the main pipeline; finished scans are listed under "Previous scans" there.');
  var result = el('div', {});
  root.appendChild(progress);
  root.appendChild(idle);
  root.appendChild(result);

  function renderProgress(job) {
    progress.textContent = '';
    if (!job) { return; }
    var idx = -1;
    STAGES.forEach(function (s, i) { if (s[0] === job.stage) { idx = i; } });
    STAGES.forEach(function (s, i) {
      var done = job.state === 'done' || i < idx;
      progress.appendChild(el('span', { 'class': 'oss-step' + (done ? ' done' : (i === idx && job.state === 'running' ? ' on' : '')), text: (i + 1) + '. ' + s[1] }));
    });
  }
  function showResult(jid) {
    S.job = jid; S.offset = 0; S.q = '';
    api('/api/oss/overview/' + jid).then(function (r) {
      if (!r.ok) { result.textContent = ''; result.appendChild(note(r.data.error || 'result not found', 'bad')); return; }
      S.overview = r.data;
      renderResult();
    });
  }
  function card(title, value) { return el('div', { 'class': 'oss-card' }, [el('div', { 'class': 'oss-card-n', text: String(value) }), el('div', { 'class': 'sub', text: title })]); }

  function renderResult() {
    var ov = S.overview || {}, c = ov.counts || {};
    result.textContent = '';
    var cards = el('div', { 'class': 'oss-cards' }, [card('Source', c.src || 0), card('Dependency', c.dep || 0), card('Binary', c.bin || 0), card('Excluded', ov.excluded || 0), card('No license', ov.without_license || 0)]);
    result.appendChild(cards);
    (ov.warnings || []).slice(0, 8).forEach(function (w) { result.appendChild(note(w, 'warn')); });

    var tabs = el('div', { 'class': 'oss-tabs' });
    [['overview', 'License risk'], ['src', 'Source'], ['dep', 'Dependency'], ['bin', 'Binary'], ['notice', 'OSS Notice'], ['export', 'Export']].forEach(function (t) {
      var b = el('button', { type: 'button', 'class': 'oss-tab' + (t[0] === (S.tab || 'overview') ? ' on' : ''), text: t[1] });
      b.addEventListener('click', function () { S.tab = t[0]; S.offset = 0; renderResult(); });
      tabs.appendChild(b);
    });
    result.appendChild(tabs);
    var pane = el('div', {});
    result.appendChild(pane);
    var tab = S.tab || 'overview';
    if (tab === 'overview') { renderLicenses(pane, ov); }
    else if (tab === 'notice') { renderNotice(pane); }
    else if (tab === 'export') { renderExport(pane); }
    else { S.kind = tab; renderTable(pane); }
  }

  function renderLicenses(pane, ov) {
    var tiers = ov.license_tiers || {};
    var desc = { 'High': 'strong / network copyleft - source disclosure obligations', 'Medium': 'weak copyleft', 'Low': 'permissive', 'Needs review': 'unclassified - check by hand' };
    Object.keys(desc).forEach(function (t) {
      var rows = tiers[t] || [];
      var box = el('div', { 'class': 'oss-tier oss-tier-' + t.replace(' ', '') }, [el('h4', { text: t + ' risk (' + rows.length + ') - ' + desc[t] })]);
      if (!rows.length) { box.appendChild(el('div', { 'class': 'sub', text: 'none' })); }
      rows.forEach(function (r) {
        box.appendChild(el('div', { 'class': 'oss-lic' }, [el('b', { text: r.license }), ' x' + r.components, el('span', { 'class': 'sub', text: '  ' + (r.obligations || []).join(', ') })]));
      });
      pane.appendChild(box);
    });
    var sc = ov.scanners || {};
    Object.keys(sc).forEach(function (k) {
      pane.appendChild(el('div', { 'class': 'sub', text: k + ': ' + (typeof sc[k] === 'string' ? sc[k] : JSON.stringify(sc[k])) }));
    });
  }

  function renderTable(pane) {
    var bar = el('div', { 'class': 'oss-row' });
    var q = el('input', { placeholder: 'search path, OSS name, license', value: S.q, spellcheck: 'false', style: 'flex:1;min-width:240px' });
    q.addEventListener('keydown', function (e) { if (e.key === 'Enter') { S.q = q.value.trim(); S.offset = 0; renderResult(); } });
    bar.appendChild(q);
    pane.appendChild(bar);
    var holder = el('div', { 'class': 'oss-tablewrap' }, [note('loading\u2026')]);
    pane.appendChild(holder);
    var url = '/api/oss/items/' + S.job + '?kind=' + S.kind + '&q=' + encodeURIComponent(S.q) + '&sort=' + S.sort + '&dir=' + S.dir + '&limit=' + S.limit + '&offset=' + S.offset;
    api(url).then(function (r) {
      holder.textContent = '';
      if (!r.ok) { holder.appendChild(note(r.data.error || 'failed', 'bad')); return; }
      var d = r.data;
      S.total = d.total;
      var tbl = el('table', { 'class': 'oss-table' });
      var head = el('tr', {});
      [['path', PATHLABEL[S.kind]], ['oss_name', 'OSS Name'], ['version', 'Version'], ['license', 'License']].forEach(function (h) {
        var th = el('th', { text: h[1] + (S.sort === h[0] ? (S.dir === 'asc' ? ' \u25B2' : ' \u25BC') : ''), style: 'cursor:pointer' });
        th.addEventListener('click', function () { if (S.sort === h[0]) { S.dir = S.dir === 'asc' ? 'desc' : 'asc'; } else { S.sort = h[0]; S.dir = 'asc'; } S.offset = 0; renderResult(); });
        head.appendChild(th);
      });
      tbl.appendChild(head);
      if (!d.rows.length) { tbl.appendChild(el('tr', {}, [el('td', { colspan: '4', text: 'No rows' + (S.q ? ' match the search.' : ' - this scanner found nothing (that is not proof that nothing is there).') })])); }
      d.rows.forEach(function (row) {
        var tr = el('tr', { 'class': row.exclude ? 'oss-excluded' : '' }, [el('td', { text: row.path || '' }), el('td', { text: row.oss_name || '' }), el('td', { text: row.version || '' }), el('td', { text: row.license || '' })]);
        var detail = el('tr', { 'class': 'oss-detail', style: 'display:none' });
        var dtd = el('td', { colspan: '4' });
        [['Download Location', row.download_location], ['Homepage', row.homepage], ['Copyright', row.copyright], ['Comment', row.comment], ['Checksum', row.checksum], ['Found by', (row.evidence || []).join(' | ')]].forEach(function (kv) {
          if (kv[1]) { dtd.appendChild(el('div', {}, [el('b', { text: kv[0] + ': ' }), el('span', { text: kv[1] })])); }
        });
        if (!dtd.firstChild) { dtd.appendChild(el('span', { 'class': 'sub', text: 'no further details recorded' })); }
        detail.appendChild(dtd);
        tr.style.cursor = 'pointer';
        tr.addEventListener('click', function () { detail.style.display = detail.style.display === 'none' ? '' : 'none'; });
        tbl.appendChild(tr); tbl.appendChild(detail);
      });
      holder.appendChild(tbl);
      var pager = el('div', { 'class': 'oss-row' });
      var prev = el('button', { type: 'button', 'class': 'bts-mini', text: '\u2039 Prev' });
      var next = el('button', { type: 'button', 'class': 'bts-mini', text: 'Next \u203A' });
      prev.disabled = S.offset <= 0; next.disabled = S.offset + S.limit >= d.total;
      prev.addEventListener('click', function () { S.offset = Math.max(0, S.offset - S.limit); renderResult(); });
      next.addEventListener('click', function () { S.offset += S.limit; renderResult(); });
      pager.appendChild(prev);
      pager.appendChild(el('span', { 'class': 'sub', text: (d.total ? (d.offset + 1) : 0) + '-' + Math.min(d.offset + d.limit, d.total) + ' of ' + d.total }));
      pager.appendChild(next);
      holder.appendChild(pager);
    });
  }

  function renderExport(pane) {
    pane.appendChild(el('div', { 'class': 'sub', text: 'Download the report (FOSSLight-Report-style columns) or an SBOM rendering of the same data.' }));
    var row = el('div', { 'class': 'oss-row' });
    FORMATS.forEach(function (f) {
      row.appendChild(el('a', { 'class': 'run oss-dl', href: '/api/oss/report/' + S.job + '?format=' + f, download: '', text: f }));
    });
    pane.appendChild(row);
  }

  function renderNotice(pane) {
    pane.appendChild(el('div', { 'class': 'sub', text: 'Generates the OSS notice from the scan. It lists what was found; license texts are taken from the components\' own license files, and anything missing is reported - never made up. The written-offer text is a template: have it reviewed.' }));
    var fmt = el('select', {}, ['html', 'text', 'simple-html', 'simple-text'].map(function (f) { return el('option', { value: f, text: f }); }));
    var lang = el('select', {}, [el('option', { value: 'en', text: 'English' }), el('option', { value: 'ko', text: '\uD55C\uAD6D\uC5B4' })]);
    var product = el('input', { placeholder: 'product name', style: 'width:200px' });
    var contact = el('input', { placeholder: 'contact for the written source offer (e.g. oss@example.com)', style: 'flex:1;min-width:260px' });
    var fetchCb = el('input', { type: 'checkbox' });
    var go = el('button', { type: 'button', 'class': 'run', text: 'Generate notice' });
    pane.appendChild(el('div', { 'class': 'oss-row' }, [fmt, lang, product, contact]));
    pane.appendChild(el('div', { 'class': 'oss-row' }, [el('label', { 'class': 'oss-chk', title: 'Network: fetches missing texts from the SPDX license list' }, [fetchCb, ' fetch missing license texts from the SPDX list (network)']), go]));
    var out = el('div', {});
    pane.appendChild(out);
    go.addEventListener('click', function () {
      out.textContent = ''; out.appendChild(note('generating\u2026'));
      api('/api/oss/notice', { job: S.job, format: fmt.value, lang: lang.value, product: product.value.trim(), contact: contact.value.trim(), fetch_license_texts: fetchCb.checked }).then(function (r) {
        out.textContent = '';
        if (!r.ok) { out.appendChild(note(r.data.error || 'failed', 'bad')); return; }
        var a = r.data.audit || {};
        out.appendChild(note(a.complete ? 'Notice complete: ' + a.components + ' component(s), ' + (a.licenses || []).length + ' license(s).' : 'Notice INCOMPLETE: ' + (a.problems || []).join('; '), a.complete ? 'ok' : 'warn'));
        [['License text missing', a.missing_license_text], ['Components without a license', a.components_without_license], ['Components without copyright', a.components_without_copyright], ['OR choice not recorded', a.components_with_OR_choice_not_recorded]].forEach(function (kv) {
          if (kv[1] && kv[1].length) { out.appendChild(el('div', { 'class': 'sub', text: kv[0] + ': ' + kv[1].slice(0, 20).join(', ') + (kv[1].length > 20 ? ' \u2026' : '') })); }
        });
        out.appendChild(el('div', { 'class': 'sub', text: 'Written offer: ' + (a.written_offer || '') }));
        var blob = new Blob([r.data.notice], { type: fmt.value.indexOf('html') >= 0 ? 'text/html' : 'text/plain' });
        var dl = el('a', { 'class': 'run oss-dl', href: URL.createObjectURL(blob), download: 'bts_notice_' + fmt.value.replace('-', '_') + (fmt.value.indexOf('html') >= 0 ? '.html' : '.txt'), text: 'Download notice' });
        out.appendChild(dl);
      });
    });
  }

  /* ---------- history: the "Previous scans" list on the landing pane ---------- */
  function loadHistory() {
    api('/api/oss/history').then(function (r) {
      histBox.textContent = '';
      var rows = (r.data && r.data.history) || [];
      if (!rows.length) { histBox.appendChild(el('div', { 'class': 'sub', text: 'No scans yet.' })); return; }
      rows.slice(0, 20).forEach(function (h) {
        var c = h.counts || {};
        var open = el('button', { type: 'button', 'class': 'bts-mini', text: 'Open' });
        open.addEventListener('click', function () { openJob(h.id); });
        var cmp = el('button', { type: 'button', 'class': 'bts-mini', text: 'Compare with open scan' });
        cmp.addEventListener('click', function () {
          if (!S.job || S.job === h.id) { return; }
          api('/api/oss/compare?a=' + h.id + '&b=' + S.job).then(function (cr) {
            if (!cr.ok) { return; }
            var s = cr.data.summary;
            histBox.textContent = '';
            histBox.appendChild(note('Compared with ' + (h.target || h.id) + ': +' + s.added + ' added, -' + s.deleted + ' deleted, ~' + s.changed + ' changed.', 'ok'));
            loadHistory();
          });
        });
        histBox.appendChild(el('div', { 'class': 'oss-hrow' }, [el('span', { text: (h.finished || '') + '  ' + (h.target || '') }), el('span', { 'class': 'sub', text: '  src ' + (c.src || 0) + ' / dep ' + (c.dep || 0) + ' / bin ' + (c.bin || 0) + '  ' }), open, cmp]));
      });
    });
  }

  /* ---------- job start + polling: bts_console.js calls BtsOss.start on every ▶ Analyze ---------- */
  function start(target, opts) {
    opts = opts || {};
    return new Promise(function (resolve) {
      var epoch = ++S.epoch;                       // a newer start supersedes an older poll loop
      idle.style.display = 'none';
      result.textContent = '';
      renderProgress({ stage: 'prepare', state: 'running' });
      api('/api/oss/scan', { target: target, modes: opts.modes, excludes: opts.excludes || [], branch: opts.branch || '', correction: !!opts.correction }).then(function (r) {
        if (epoch !== S.epoch) { resolve({ ok: false, superseded: true, error: 'superseded by a newer scan' }); return; }
        if (!r.ok) { renderProgress(null); resolve({ ok: false, error: (r.data && r.data.error) || ('HTTP ' + r.status) }); return; }
        poll(r.data.job, epoch, resolve);
      });
    });
  }
  function poll(id, epoch, resolve) {
    if (epoch !== S.epoch) { resolve({ ok: false, superseded: true, error: 'superseded by a newer scan' }); return; }
    api('/api/oss/jobs/' + encodeURIComponent(id)).then(function (r) {
      if (epoch !== S.epoch) { resolve({ ok: false, superseded: true, error: 'superseded by a newer scan' }); return; }
      if (!r.ok) { renderProgress(null); resolve({ ok: false, error: (r.data && r.data.error) || 'lookup failed' }); return; }
      var job = r.data;
      renderProgress(job);
      if (job.state === 'running') { setTimeout(function () { poll(id, epoch, resolve); }, 800); return; }
      if (job.state === 'error' || job.state === 'cancelled') { resolve({ ok: false, error: (job.state === 'cancelled' ? 'Cancelled. ' : 'The scan failed: ') + (job.error || '') }); return; }
      showResult(job.id);
      loadHistory();
      resolve({ ok: true, id: job.id });
    });
  }
  /* history "Open": render the scan here and jump to this sub-tab (the landing and this pane are different tabs now) */
  function openJob(jid) {
    idle.style.display = 'none';
    S.tab = 'overview';
    showResult(jid);
    document.dispatchEvent(new CustomEvent('bts:activate', { detail: 'oss' }));
  }

  window.BtsOss = { readForm: readForm, start: start, open: openJob };
  loadHistory();
})();
