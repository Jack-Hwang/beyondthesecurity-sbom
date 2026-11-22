/*!
 * bts_report.js - pure builders of the dedicated Report tab: the project header (identity, severity chips,
 * document downloads) and the three governance cards (fix-plan summary, VEX/decision coverage, SBOM
 * conformance). Written for BTS-SBOM; UMD like bts_ui.js so the Node render harness (tests/js/render_harness.js)
 * can execute these functions without a browser. The ScaApp report body itself is rendered by the copied
 * platform renderer (sca_app.js, byte-pinned - see NOTICE.md); this file only draws AROUND it.
 *
 * Rules (same as bts_ui.js): every dynamic value goes through esc() before it reaches innerHTML; absent data is
 * shown as a dash or an honest "not loaded" line, never as a made-up number. No inline event handlers - the
 * buttons carry data-act/data-sv attributes that bts_console.js's delegated click handler understands.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  if (root) { root.BtsReport = api; }
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';

  var SEV_COLOR = { CRITICAL: '#9F4BDD', HIGH: '#BC5F04', MEDIUM: '#EDAB00', LOW: '#4A76AA', UNKNOWN: '#6e7681' };
  var SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];

  function esc(v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function when(iso) { return iso ? String(iso).replace('T', ' ').slice(0, 16) : '\u2014'; }
  function pct(x) { return (typeof x === 'number' && isFinite(x)) ? Math.round(100 * x) + '%' : '\u2014'; }
  function dlBtn(label, url, fname) {
    return '<button type="button" class="bts-mini" data-act="dl" data-url="' + esc(url) + '"' +
           (fname ? ' data-fname="' + esc(fname) + '"' : '') + '>' + esc(label) + '</button>';
  }
  function gotoBtn(label, sv) {
    return '<button type="button" class="bts-mini" data-act="goto" data-sv="' + esc(sv) + '">' + esc(label) + '</button>';
  }

  /* ---------- header: identity + severity chips + document downloads ---------- */
  function renderHead(view) {
    if (!view || !view.project) {
      return '<div class="bts-note">No project is selected. Analyse a repository on the <b>Scan</b> tab, or pick one in the title bar.</div>';
    }
    var s = ((view.report || {}).severity) || {}, n = encodeURIComponent(view.project);
    var chips = SEVS.map(function (k) {
      return '<span class="bts-sev" style="background:' + SEV_COLOR[k] + '">' + k + ' ' + esc(s[k] || 0) + '</span>';
    }).join(' ');
    var src = view.source ? String(view.source) : '\u2014';
    var downloads = dlBtn('\u2B07 CycloneDX JSON', '/api/sbom/' + n + '?format=cdx') +
      dlBtn('\u2B07 SPDX JSON', '/api/sbom/' + n + '?format=spdx') +
      dlBtn('\u2B07 OpenVEX JSON', '/api/sbom/' + n + '?format=vex') +
      dlBtn('\u2B07 Report (Markdown)', '/api/doc/' + n, view.project + '.md');
    return '<div class="bts-reporthead">' +
      '<div class="bts-reporthead-title"><span class="bts-rh-name">' + esc(view.project) + '</span>' +
      '<span class="bts-rh-meta">' + esc(src.length > 90 ? src.slice(0, 90) + '\u2026' : src) + ' &middot; analysed ' + esc(when(view.analysed_at)) + '</span></div>' +
      '<div class="bts-rh-chips">' + chips + '</div>' +
      '<div class="bts-rh-actions">' + downloads + '</div>' +
      '</div>';
  }

  /* ---------- governance cards: fix plan summary, decision coverage, SBOM conformance ----------
     p.coverage / p.conformance are the raw responses of GET /api/coverage/<p> and GET /api/conformance/<p>
     (fetched lazily by bts_console.js); null/undefined = not loaded yet, {error} = the fetch failed. */
  function govCard(title, sub, body, goto_) {
    return '<div class="bts-govcard"><div class="bts-gc-title">' + esc(title) + '</div>' +
      '<div class="bts-gc-sub">' + esc(sub) + '</div>' + body +
      (goto_ ? '<div class="bts-gc-actions">' + gotoBtn('\u2192 ' + goto_[1], goto_[0]) + '</div>' : '') + '</div>';
  }
  function renderGovCards(p) {
    p = p || {};
    var v = p.view;
    /* 1 - fix plan summary (from /api/view, always present when a project is selected) */
    var ps = (v && v.plan_summary) || {}, planBody;
    if (!v) {
      planBody = '<div class="bts-gc-line">No project is selected.</div>';
    } else if (!ps.plans) {
      planBody = '<div class="bts-gc-line">\u2014</div><div class="bts-gc-line">No remediation plan was recorded for this analysis.</div>';
    } else {
      planBody = '<div class="bts-gc-big">' + esc(ps.upgrade || 0) + '<span class="bts-gc-unit">safe upgrades</span></div>' +
        '<div class="bts-gc-line">plans ' + esc(ps.plans) + ' &middot; no-fix ' + esc(ps.no_fix || 0) + ' &middot; major bumps ' + esc(ps.major_bumps || 0) + '</div>' +
        '<div class="bts-gc-line">verified: clean ' + esc(ps.verified_clean || 0) + ' &middot; dirty(reverted) ' + esc(ps.verified_dirty || 0) + ' &middot; unverified ' + esc(ps.unverified || 0) + '</div>';
    }
    var cards = govCard('Fix plan', 'the verified safe-upgrade plan', planBody, ['fix-plan', 'Fix Plan']);
    /* 2 - decision coverage */
    var c = p.coverage, covBody;
    if (c && c.error) {
      covBody = '<div class="bts-gc-line">Not loaded: ' + esc(c.error) + '</div>';
    } else if (!c) {
      covBody = '<div class="bts-gc-line">loading\u2026</div>';
    } else {
      var wl = (c.worklist || []).length;
      covBody = '<div class="bts-gc-big">' + pct(c.handled_pct) + '<span class="bts-gc-unit">handled by decisions + plans</span></div>' +
        '<div class="bts-gc-line">advisories ' + esc(c.advisories || 0) + ' &middot; open worklist ' + esc(wl) + '</div>' +
        '<div class="bts-gc-line">verdict status: ' + esc(c.status || '\u2014') + '</div>';
    }
    cards += govCard('Decision coverage', 'VEX decisions + verified plans vs open advisories', covBody, ['vex', 'VEX \u00B7 Decisions']);
    /* 3 - SBOM conformance */
    var f = p.conformance, confBody;
    if (f && f.error) {
      confBody = '<div class="bts-gc-line">Not loaded: ' + esc(f.error) + '</div>';
    } else if (!f) {
      confBody = '<div class="bts-gc-line">loading\u2026</div>';
    } else {
      var regimes = Object.keys(f.regimes || {});
      var failed = regimes.filter(function (k) { return (f.regimes[k] || {}).status === 'FAIL'; }).length;
      confBody = '<div class="bts-gc-big">' + esc(f.status || '\u2014') + '<span class="bts-gc-unit">document conformance</span></div>' +
        '<div class="bts-gc-line">components ' + esc(f.components || 0) + ' &middot; regimes checked ' + esc(regimes.length) + (regimes.length ? ' (fail ' + esc(failed) + ')' : '') + '</div>' +
        (f.reason ? '<div class="bts-gc-line">' + esc(f.reason) + '</div>' : '');
    }
    cards += govCard('SBOM conformance', 'NTIA 2021 \u00B7 CISA 2025 draft \u00B7 EU CRA \u00B7 BSI TR-03183-2', confBody, ['conformance', 'SBOM conformance']);
    return '<div class="bts-govcards">' + cards + '</div>';
  }

  return { renderHead: renderHead, renderGovCards: renderGovCards, SEV_COLOR: SEV_COLOR };
});
