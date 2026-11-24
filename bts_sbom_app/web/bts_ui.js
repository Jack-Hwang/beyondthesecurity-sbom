/*!
 * bts_ui.js - markup helpers shared by the BTS-SBOM page scripts (bts_console.js and bts_governance.js).
 * Written for BTS-SBOM (not one of the six copied platform files, see NOTICE.md).
 *
 * This is the ONE place that escapes. Everything the page shows that came from analysed data (project names, advisory ids, package
 * names, summaries, licence strings, SBOM fields) is untrusted text: it goes through esc() before it reaches innerHTML, either directly
 * or through cell()/kv()/table(), which escape every value that was not built here with H(). H() returns an instance of a private
 * class, so a value parsed from JSON - even an object with an "html" key - can never be mistaken for trusted markup.
 * Absent data is shown as an em dash (val()), never as a default 0.
 */
(function (root, factory) {
  var api = factory();
  if (typeof module === 'object' && module.exports) { module.exports = api; }
  if (root) { root.BtsUi = api; }
})(typeof window !== 'undefined' ? window : null, function () {
  'use strict';

  var SEV_COLOR = { CRITICAL: '#9F4BDD', HIGH: '#BC5F04', MEDIUM: '#EDAB00', LOW: '#4A76AA', UNKNOWN: '#6e7681' };

  function esc(v) {
    return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) {
      return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c];
    });
  }
  function Safe(html) { this.html = html; }                           // markup built here from escaped parts
  function H(html) { return new Safe(html); }
  function cell(c) { return (c instanceof Safe) ? c.html : esc(c); }
  function absent(v) { return v === null || v === undefined || v === '' || (typeof v === 'number' && !isFinite(v)); }
  function val(v) { return absent(v) ? '—' : v; }                  // "not recorded" is a dash, never a default 0
  function when(iso) { return iso ? String(iso).replace('T', ' ').slice(0, 16) : '—'; }

  function table(heads, rows, empty) {
    if (!rows.length) { return '<div class="bts-note">' + esc(empty || 'Nothing to show.') + '</div>'; }
    return '<div class="bts-wrap"><table class="bts-table"><thead><tr>' + heads.map(function (h) { return '<th>' + esc(h) + '</th>'; }).join('') +
      '</tr></thead><tbody>' + rows.map(function (r) { return '<tr>' + r.map(function (c) { return '<td>' + cell(c) + '</td>'; }).join('') + '</tr>'; }).join('') +
      '</tbody></table></div>';
  }
  function sevBadge(s) {
    s = String(s || 'UNKNOWN').toUpperCase();
    return H('<span class="bts-sev" style="background:' + (SEV_COLOR.hasOwnProperty(s) ? SEV_COLOR[s] : SEV_COLOR.UNKNOWN) + '">' + esc(s) + '</span>');
  }
  var PILL_CLASSES = ['ok', 'bad', 'warn', 'muted', 'pass', 'gap', 'not_evidence'];
  function pill(text, cls) { return H('<span class="bts-pill ' + (PILL_CLASSES.indexOf(cls) >= 0 ? cls : 'muted') + '">' + esc(text) + '</span>'); }
  function note(html, cls) { return '<div class="bts-note ' + (cls || '') + '">' + html + '</div>'; }   // html: already escaped by the caller
  function heading(t, sub) { return '<div class="bts-h">' + esc(t) + (sub ? ' <span class="sub">' + esc(sub) + '</span>' : '') + '</div>'; }
  function kv(pairs) {
    return '<dl class="bts-kv">' + pairs.map(function (p) { return '<dt>' + esc(p[0]) + '</dt><dd>' + cell(p[1]) + '</dd>'; }).join('') + '</dl>';
  }
  function unavailable(title, why) {
    return heading(title) + note('<b>Not computed by BTS-SBOM.</b> ' + esc(why) + ' Nothing is shown rather than a made-up value.', 'warn');
  }
  /* Chat answer renderer (pure, harness-tested): answer text, source/citation/routing line, retrieval evidence chips,
     untrusted-quote warning and conflict annotations. Every dynamic value is escaped - analysed data and knowledge
     chunks come from untrusted repositories. No inline event handlers (strict CSP). */
  function renderChatAnswer(d) {
    d = d || {};
    var h = '<div class="bts-chat-out">' + esc((d.found ? '' : '[not found] ') + (d.answer || '')) + '</div>';
    h += '<div class="bts-chat-src">source: ' + esc(d.answer_source) + ' · citation accuracy: ' + esc(d.citation_accuracy) +
         ' · routing: ' + esc(d.routing || 'n/a') + (d.routing_note ? ' · ' + esc(d.routing_note) : '') + '</div>';
    var tops = (d.retrieval && d.retrieval.top) || [];
    if (tops.length) {
      h += '<div class="bts-chat-chips">' + tops.map(function (t) {
        return '<span class="bts-chat-chip" title="rrf ' + esc(t.rrf) + '">' + esc(t.heading || t.source) +
               ' <span class="bts-chat-chip-src">' + esc(t.source) + '</span></span>';
      }).join('') + '</div>';
    }
    if (d.contains_untrusted) {
      h += note('Contains untrusted third-party quotes - shown verbatim, never obeyed.', 'warn');
    }
    (d.conflicts || []).forEach(function (c) {
      h += note('<b>[conflict]</b> ' + esc(c.label) + ': ' + esc(c.a.value) + ' (' + esc(c.a.source) + ') vs ' +
                esc(c.b.value) + ' (' + esc(c.b.source) + ') - the sources disagree; the judgement stays with you.', 'warn');
    });
    /* diagrams drawn mid-conversation (ADR-0024): Mermaid source stays in a hidden pre; bts_console.js renders
       it with the vendored mermaid and falls back to showing the source when rendering fails. */
    (d.diagrams || []).forEach(function (dg) {
      if (!dg || !dg.mermaid) { return; }
      h += '<div class="bts-diagram arc-dwrap"><div class="bts-diagram-title">' + esc(dg.name || 'diagram') + '</div>' +
           '<div class="arc-diagram"></div><pre class="arc-mermaid-src" hidden>' + esc(dg.mermaid) + '</pre>' +
           (dg.note ? '<div class="bts-diagram-note">' + esc(dg.note) + '</div>' : '') + '</div>';
    });
    return h;
  }

  return { SEV_COLOR: SEV_COLOR, esc: esc, H: H, cell: cell, absent: absent, val: val, when: when, table: table, sevBadge: sevBadge, pill: pill,
           note: note, heading: heading, kv: kv, unavailable: unavailable, renderChatAnswer: renderChatAnswer };
});
