/*!
 * bts_governance.js - renderers and form logic for the SBOM-governance panes of the BTS-SBOM open-source security screen:
 * SBOM conformance, what changed, OpenVEX with decisions, the decision form, the fleet roll-up and the "who is affected" search.
 * Written for BTS-SBOM (not one of the six copied platform files, see NOTICE.md).
 *
 * Everything here is a pure function of the JSON the service returned (no DOM, no network), so it runs unchanged under Node for
 * the tests; bts_console.js fetches the data and puts the returned markup on the page. Rules, as everywhere on this screen:
 *  - every value from analysed data goes through BtsUi.esc() (cell()/kv()/table() do it for table cells);
 *  - absent data is an em dash (BtsUi.val), never a default 0; NO_DATA / "no earlier analysis" / an API error each get their own message;
 *  - the conformance pane always says it is not a legal assessment and flags draft regimes;
 *  - the decision form never promises more than the service will write: see triageOutcome(), which mirrors bts_sbom_app/triage.py.
 */
(function (root, factory) {
  var isNode = typeof module === 'object' && module.exports;
  var api = factory(isNode ? require('./bts_ui.js') : root.BtsUi);
  if (isNode) { module.exports = api; }
  if (root) { root.BtsGovernance = api; }
})(typeof window !== 'undefined' ? window : null, function (U) {
  'use strict';

  var esc = U.esc, H = U.H, val = U.val, note = U.note, heading = U.heading, table = U.table, pill = U.pill, kv = U.kv, when = U.when;

  /* ---------- constants (triage.py is the source of truth; a test compares them) ---------- */
  var MIN_REASON = 10;
  var MAX_REASON = 500, MAX_KEY = 200, MAX_SCOPE = 200, MAX_BY = 80;
  var JUSTIFICATIONS = [
    { id: 'component_not_present', text: 'The vulnerable component is not part of the product.' },
    { id: 'vulnerable_code_not_present', text: 'The component is there, but the vulnerable code is not (removed, not compiled in).' },
    { id: 'vulnerable_code_not_in_execute_path', text: 'The vulnerable code is present but is never executed.' },
    { id: 'vulnerable_code_cannot_be_controlled_by_adversary', text: 'The vulnerable code runs, but an attacker cannot influence its input.' },
    { id: 'inline_mitigations_already_exist', text: 'Mitigations in the product already prevent exploitation.' }
  ];
  var STATUSES = [
    { id: 'false-positive', label: 'False positive',
      hint: 'The finding is wrong for this product. Only this decision can turn the OpenVEX statement into not_affected, and only with a justification and a reason.' },
    { id: 'accepted', label: 'Accept the risk',
      hint: 'The statement stays affected (OpenVEX has no accepted-risk status); the reason, owner and end date go into its action statement.' },
    { id: 'wontfix', label: "Won't fix", hint: 'Handled like an accepted risk: the statement stays affected and carries the reason.' },
    { id: 'fixed', label: 'Fixed (confirm by re-scan)', hint: 'Believed only once the next analysis no longer reports the finding; while it is still reported the statement stays affected.' },
    { id: 'open', label: 'Open (no exemption)', hint: 'Records that the finding is open. Nothing is exempted.' }
  ];
  var SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  var ALERT_KIND = {
    threshold_crossed_up: 'Score rose across the threshold', threshold_crossed_down: 'Score fell below the threshold',
    new_at_or_above_threshold: 'New finding at or above the threshold', new_malicious_package: 'New malicious-package advisory',
    copyleft_introduced: 'Copyleft licence introduced'
  };
  var ALERT_TONE = { critical: 'bad', high: 'bad', medium: 'warn', info: 'muted' };
  var VERDICT_TONE = { conformant: 'ok', partial: 'warn', gaps: 'bad' };
  var CHANGE_TONE = { worse: 'bad', better: 'ok', mixed: 'warn', same: 'muted' };
  var CHANGE_TEXT = { worse: 'new findings', better: 'fewer open findings', mixed: 'new and resolved findings', same: 'no change in the findings' };
  var LEGAL_NOTE = '<b>Not a legal assessment.</b> The regimes below are a checked subset of data fields, each with the date it was last reviewed. ' +
    'This is evidence-gathering support: confirm against the official text of each regime.';

  /* ---------- small helpers ---------- */
  function isNum(v) { return typeof v === 'number' && isFinite(v); }
  function pick(map, key) { return Object.prototype.hasOwnProperty.call(map, key) ? map[key] : undefined; }   // data-supplied keys never reach Object.prototype
  function list(v) { return Array.isArray(v) ? v : []; }
  function obj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
  function loading(title) { return heading(title) + note('Loading…'); }
  function failure(title, res) {
    var d = obj(res && res.data), msg = d.error ? String(d.error) : ('HTTP ' + (res ? res.status : '?'));
    return heading(title) + note('<b>The service could not provide this.</b> ' + esc(msg), 'bad');
  }
  function fmtScore(n) { return isNum(n) ? Number(n).toFixed(1) : null; }
  function scoreCell(score, basis) {
    var s = fmtScore(score);
    if (s === null) { return '—'; }
    return basis === 'label-floor' ? H('<span title="No CVSS score is recorded; this is the lower bound of the severity label.">≥ ' + esc(s) + ' (label)</span>') : s;
  }
  function fixedCell(v) { return v ? String(v) : H('<span class="bts-muted">no fix known</span>'); }
  function chips(ids) { return H(list(ids).map(function (i) { return pill(i, 'muted').html; }).join(' ') || '—'); }
  function ageOf(map, name) { return when(pick(obj(map), name)); }
  function isoDay(d) {
    var p = function (n) { return (n < 10 ? '0' : '') + n; };
    return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate());
  }
  function today(t) { return typeof t === 'string' ? t : isoDay(t || new Date()); }
  function parseDay(v) {                                              // 'YYYY-MM-DD' (a longer ISO string is cut), real calendar day, else null
    var m = /^(\d{4})-(\d{2})-(\d{2})/.exec(String(v === null || v === undefined ? '' : v).trim());
    if (!m) { return null; }
    var d = new Date(Date.UTC(+m[1], +m[2] - 1, +m[3]));
    return (d.getUTCFullYear() === +m[1] && d.getUTCMonth() === +m[2] - 1 && d.getUTCDate() === +m[3]) ? m[0] : null;
  }
  function chars(s) { return Array.from(String(s === null || s === undefined ? '' : s)).length; }   // code points, like the service
  function barCell(pct) {
    if (!isNum(pct)) { return '—'; }
    var w = Math.max(0, Math.min(100, pct));
    return H('<span class="bts-cov"><span class="bts-bar-track"><span class="bts-bar-fill" style="display:block;width:' + Math.round(w) + '%;background:' +
      (pct >= 100 ? '#1a7f37' : pct >= 50 ? '#9a6700' : '#cf222e') + '"></span></span> ' + esc(pct) + '%</span>');
  }
  function truncated(items, total, what, why) {
    return (Array.isArray(items) && isNum(total) && items.length < total)
      ? note('Showing the first ' + esc(items.length) + ' of ' + esc(total) + ' ' + esc(what) + '; ' + esc(why || 'the project record keeps only that many') + '.', 'warn') : '';
  }

  /* ---------- SBOM conformance ---------- */
  function renderConformance(res) {
    var T = 'SBOM conformance', out = heading(T, 'one SBOM checked against several regimes at once') + note(LEGAL_NOTE, 'warn');
    if (!res) { return out + note('Loading…'); }
    var d = obj(res.data);
    if (!res.ok) {
      return out + note('<b>No conformance result.</b> ' + esc(d.error || ('HTTP ' + res.status)) + ' No verdict is shown rather than a made-up one.', 'bad');
    }
    if (d.status !== 'OK') {
      return out + note('<b>NO_DATA.</b> ' + esc(d.reason || 'The document could not be scored.') + ' This is not a pass: no regime was checked.', 'warn');
    }
    var regimes = obj(d.regimes), rids = Object.keys(regimes), els = obj(d.elements), eids = Object.keys(els);
    var tb = obj(d.table), stale = tb.stale === true;                  // how old the regime table is: an old table must read as "review due", never as current
    out += stale ? note('<b>Review due.</b> ' + esc(tb.note || ('The regime table was last reviewed ' + val(tb.reviewed))) + '. Regulations move, so the verdicts below may not match the current official texts.', 'bad') : '';
    out += kv([['Document format', val(d.format)], ['Components checked', val(d.components)],
               ['Regime table reviewed', !tb.reviewed ? '—' : H(esc(tb.reviewed) + (isNum(tb.age_months) ? ' (' + esc(tb.age_months) + ' month(s) ago) ' : ' ') +
                 (stale ? pill('review due', 'bad').html : ''))]]);
    out += heading('Regimes', 'a regime is conformant only when every element it names is met by every component');
    out += table(['Regime', 'Authority', 'Stage', 'Reviewed', 'Draft', 'Verdict', 'Elements met / partial / gap'], rids.map(function (rid) {
      var r = obj(regimes[rid]), draft = r.draft === true ? pill('draft', 'warn') : (r.draft === false ? 'no' : 'not recorded');
      return [H('<b>' + esc(r.title || rid) + '</b><br><code>' + esc(rid) + '</code>' + (r.draft === true ? ' ' + pill('DRAFT', 'warn').html : '')),
              val(r.authority), val(r.stage), val(r.as_of), draft,
              r.verdict ? pill(r.verdict, pick(VERDICT_TONE, r.verdict) || 'muted') : '—',
              [val(r.pass), val(r.partial), val(r.gap)].join(' / ') + ' of ' + val(r.total)];
    }), 'No regime was returned.');
    if (rids.some(function (rid) { return obj(regimes[rid]).draft === true; })) {
      out += note('<b>DRAFT</b> regimes are published for comment: their final text may differ from what is checked here.');
    }
    out += heading('Elements', 'coverage across the components (document-level elements are met or not)');
    out += table(['Element', 'Scope', 'Coverage', 'Basis'].concat(rids), eids.map(function (eid) {
      var e = obj(els[eid]);
      return [H('<b>' + esc(e.title || eid) + '</b><br><code>' + esc(eid) + '</code>'), H('<span class="bts-nowrap">' + esc(val(e.scope)) + '</span>'), barCell(e.pct), val(e.basis)].concat(rids.map(function (rid) {
        var s = obj(regimes[rid]).elements && obj(regimes[rid].elements)[eid];
        return s ? pill(s, s === 'pass' ? 'ok' : s === 'partial' ? 'warn' : s === 'gap' ? 'bad' : 'muted') : H('<span class="bts-muted" title="not required by this regime">·</span>');
      }));
    }), 'No element was scored.');
    var fix = list(d.fix_once);
    out += heading('Fix once, satisfy many', 'the same missing field often blocks several regimes; most regimes unblocked first');
    out += fix.length ? table(['#', 'Element', 'Status', 'Coverage', 'Missing', 'Blocks', 'How to fix'], fix.map(function (f, i) {
      return [i + 1, H('<b>' + esc(f.title || f.element) + '</b><br><code>' + esc(f.element) + '</code>'), f.status ? pill(f.status, f.status === 'gap' ? 'bad' : 'warn') : '—',
              barCell(f.pct), val(f.missing), chips(f.regimes), val(f.hint)];
    })) : (Array.isArray(d.fix_once) ? note('Nothing to fix: every checked element is met by every component.', 'ok') : note('No fix list was returned.'));
    return out + (d.honesty ? '<div class="bts-small">' + esc(d.honesty) + '</div>' : '');
  }

  /* ---------- what changed ---------- */
  function renderChanges(res) {
    var T = 'What changed since the previous analysis';
    if (!res) { return loading(T); }
    if (!res.ok) { return failure(T, res); }
    var d = obj(res.data), s = d.summary;
    if (!s || typeof s !== 'object') {
      var why = String(d.note || 'The service returned no change data for this project');
      return heading(T) + note('<b>Nothing to compare.</b> ' + esc(why) + (/[.!?]$/.test(why) ? '' : '.') +
        ' Analyse the project again after a change to see new and resolved findings, version changes and alerts.', 'warn');
    }
    var cards = [['New findings', s.vulns_new, U.SEV_COLOR.HIGH], ['Resolved', s.vulns_resolved, '#1a7f37'], ['Rescored', s.vulns_rescored], ['Alerts', s.alerts],
                 ['Critical alerts', s.alerts_critical, U.SEV_COLOR.CRITICAL], ['Components added', s.components_added], ['Components removed', s.components_removed],
                 ['Version changes', s.components_changed]];                                     // the colour only shows for a computed number above 0
    var out = heading(T, 'compared when the project was analysed again');
    out += '<div class="bts-cards">' + cards.map(function (c) {
      return '<div class="bts-card"><div class="v"' + (c[2] && isNum(c[1]) && c[1] > 0 ? ' style="color:' + c[2] + '"' : '') + '>' + esc(val(c[1])) + '</div><div class="l">' + esc(c[0]) + '</div></div>';
    }).join('') + '</div>';
    var b = obj(d.before);
    out += kv([['Verdict', d.verdict ? H(pill(d.verdict, pick(CHANGE_TONE, d.verdict) || 'muted').html + ' ' + esc(pick(CHANGE_TEXT, d.verdict) || '')) : '—'],
               ['Alert threshold', isNum(d.threshold) ? 'CVSS ≥ ' + fmtScore(d.threshold) : '—'], ['Compared at', when(d.compared_at)],
               ['Previous analysis', (b.components === undefined && b.vulns === undefined) ? '—' : val(b.components) + ' components, ' + val(b.vulns) + ' findings']]);
    out += note('Scores are CVSS base scores. <b>≥ x (label)</b> marks a finding without a CVSS score: x is the lower bound its severity label proves, not an estimate.');
    var alerts = list(d.alerts);
    out += heading('Alerts', 'what a security owner should look at first');
    out += table(['Severity', 'Alert', 'Package', 'Advisory', 'Detail'], alerts.map(function (a) {
      return [pill(a.severity || 'unknown', pick(ALERT_TONE, a.severity) || 'muted'), pick(ALERT_KIND, a.kind) || val(a.kind), val(a.package) + (a.version ? ' ' + a.version : ''), val(a.id), val(a.detail)];
    }), 'No alert.') + truncated(alerts, s.alerts, 'alerts');
    var nw = list(d.new);
    out += heading('New findings');
    out += table(['Advisory', 'Package', 'Version', 'Severity', 'Score', 'Fixed in'], nw.map(function (x) {
      return [val(x.id), val(x.package), val(x.version), U.sevBadge(x.severity), scoreCell(x.score, x.score_basis), fixedCell(x.fixed_version)];
    }), 'No new finding.') + truncated(nw, s.vulns_new, 'new findings');
    var rs = list(d.resolved);
    out += heading('Resolved findings', 'no longer reported by the latest analysis');
    out += table(['Advisory', 'Package', 'Version (before)', 'Severity'], rs.map(function (x) { return [val(x.id), val(x.package), val(x.version), U.sevBadge(x.severity)]; }),
                 'No finding was resolved.') + truncated(rs, s.vulns_resolved, 'resolved findings');
    var rc = list(d.rescored);
    out += heading('Rescored findings', 'same advisory, different score');
    out += table(['Advisory', 'Package', 'Severity', 'Score before', 'Score now', 'Threshold'], rc.map(function (x) {
      return [val(x.id), val(x.package), U.sevBadge(x.severity), val(fmtScore(x.previous_score)), scoreCell(x.score, x.score_basis),
              x.crossing === 'up' ? pill('crossed up', 'bad') : x.crossing === 'down' ? pill('fell below', 'ok') : '—'];
    }), 'No finding changed its score.') + truncated(rc, s.vulns_rescored, 'rescored findings');
    var c = obj(d.components), ch = list(c.changed);
    out += heading('Version changes');
    out += table(['Package', 'Ecosystem', 'From', 'To', 'Direction'], ch.map(function (x) {
      return [val(x.name), val(x.ecosystem), list(x.from).join(', ') || '—', list(x.to).join(', ') || '—', x.direction ? pill(x.direction, x.direction === 'downgrade' ? 'bad' : 'muted') : '—'];
    }), 'No component changed its version.') + truncated(ch, s.components_changed, 'version changes');
    var add = list(c.added), rem = list(c.removed);
    out += heading('Components added and removed');
    out += table(['Change', 'Package', 'Version', 'Ecosystem'], add.map(function (x) { return [pill('added', 'ok'), val(x.name), val(x.version), val(x.ecosystem)]; })
      .concat(rem.map(function (x) { return [pill('removed', 'muted'), val(x.name), val(x.version), val(x.ecosystem)]; })), 'No component was added or removed.') +
      truncated(add, s.components_added, 'added components') + truncated(rem, s.components_removed, 'removed components');
    var lc = list(c.license_changed), cl = list(c.copyleft_introduced);
    if (lc.length || cl.length) {
      out += heading('Licence changes');
      out += table(['Package', 'Version', 'From', 'To'], lc.map(function (x) { return [val(x.name), val(x.version), val(x.from), val(x.to)]; }), 'No licence changed.');
      out += table(['Copyleft introduced', 'Version', 'Licence', 'Category', 'Why'], cl.map(function (x) { return [val(x.name), val(x.version), val(x.license), val(x.category), val(x.reason)]; }), 'None.');
    }
    return out;
  }

  /* ---------- OpenVEX with decisions ---------- */
  function stmtDetail(st) {
    var p = [];
    if (st.impact_statement) { p.push('<b>Impact:</b> ' + esc(st.impact_statement)); }
    if (st.status_notes) { p.push(pill('decision not applied', 'warn').html + ' ' + esc(st.status_notes)); }
    if (st.action_statement) { p.push('<b>Action:</b> ' + esc(st.action_statement)); }
    return p.length ? H(p.join('<br>')) : '—';
  }
  function renderVex(res) {
    var T = 'OpenVEX', MAX = 200;
    if (!res) { return loading(T); }
    if (!res.ok) { return failure(T, res); }
    var d = obj(res.data), sts = list(d.statements), by = {}, notApplied = 0, accepted = 0;
    sts.forEach(function (s) {
      by[s.status] = (by[s.status] || 0) + 1;
      if (s.status_notes) { notApplied++; }
      if (/^Risk accepted/.test(String(s.action_statement || ''))) { accepted++; }
    });
    var out = heading(T, sts.length + ' statement(s), generated now from the findings and the recorded decisions');
    out += kv([['Statements by status', Object.keys(by).sort().map(function (k) { return k + ': ' + by[k]; }).join(', ') || '—'],
               ['Risk acceptances (stay affected)', accepted], ['Decisions that did not change a statement', notApplied],
               ['Document', val(d['@id'])], ['Generated', when(d.timestamp)]]);
    out += note('<b>Fail-closed.</b> A decision changes a statement only when it carries what OpenVEX needs. A false positive becomes <b>not_affected</b> only with one of the five VEX justifications ' +
      'and a reason of at least ' + MIN_REASON + ' characters; a risk acceptance needs a reason; an expired decision no longer applies. In every other case the finding <b>stays affected</b>, ' +
      'and the statement says why.');
    out += table(['Advisory', 'Product', 'Status', 'Justification', 'Detail'], sts.slice(0, MAX).map(function (s) {
      var prod = list(s.products)[0];
      return [val(obj(s.vulnerability).name), val(prod && prod['@id']),
              s.status ? pill(s.status, s.status === 'affected' ? 'bad' : s.status === 'not_affected' || s.status === 'fixed' ? 'ok' : 'muted') : '—',
              val(s.justification), stmtDetail(s)];
    }), 'The project has no findings, so the document has no statements.') + truncated(sts.slice(0, MAX), sts.length, 'statements', 'download the OpenVEX file for the rest');
    return out;
  }
  function isExpired(expires, t) { var e = parseDay(expires); return !!e && e < today(t); }
  function renderDecisions(triage, t) {
    var store = obj(triage), keys = Object.keys(store).sort(), out = heading('Recorded decisions', 'one store per evidence folder: a decision applies to every analysed project that reports the advisory, unless its scope limits it');
    return out + table(['Advisory', 'Decision', 'Justification', 'Reason', 'Owner', 'Ends', 'Scope', 'Recorded'], keys.map(function (k) {
      var e = obj(store[k]);
      return [H('<code>' + esc(k) + '</code>'), val(e.status), val(e.justification), val(e.note),
              val(e.by), H(esc(val(e.expires)) + (isExpired(e.expires, t) ? ' ' + pill('expired', 'bad').html : '')), val(e.scope), when(e.ts)];
    }), 'No decision has been recorded yet.');
  }

  /* ---------- the decision form ---------- */
  function triageOutcome(f, t) {
    var status = String(f && f.status || ''), just = String(f && f.justification || ''), n = chars(String(f && f.reason || '').trim());
    var known = JUSTIFICATIONS.some(function (j) { return j.id === just; }), exp = parseDay(f && f.expires);
    var short = 'needs a reason of at least ' + MIN_REASON + ' characters (now ' + n + ')';
    if (exp && exp < today(t)) {
      return { state: 'expired', vex: 'affected', tone: 'bad', text: 'This decision ended on ' + exp + ', so it would not apply: the finding is open again and stays affected.' };
    }
    if (status === 'false-positive') {
      if (known && n >= MIN_REASON) { return { state: 'not_affected', vex: 'not_affected', tone: 'ok', text: 'Will be written as not_affected with the justification ' + just + '.' }; }
      return { state: 'rejected', vex: 'affected', tone: 'bad',
               text: 'Without a VEX justification and a reason of at least ' + MIN_REASON + ' characters (now ' + n + ') this finding STAYS AFFECTED: it is recorded, but the OpenVEX statement does not change.' };
    }
    if (status === 'accepted' || status === 'wontfix') {
      if (n >= MIN_REASON) { return { state: 'accepted', vex: 'affected', tone: 'warn', text: 'The statement stays affected; the reason, owner and end date are written into its action statement.' }; }
      return { state: 'rejected', vex: 'affected', tone: 'bad', text: 'A risk acceptance ' + short + '; until then the finding STAYS AFFECTED.' };
    }
    if (status === 'fixed') {
      return { state: 'rejected', vex: 'affected', tone: 'warn', text: 'The scan still reports this finding, so it stays affected until the next analysis confirms the fix.' };
    }
    return { state: 'open', vex: 'affected', tone: 'warn', text: 'No exemption: the finding stays affected.' };
  }
  function triageRequest(f) {
    f = f || {};
    var key = String(f.finding || '').trim(), status = String(f.status || ''), reason = String(f.reason || '').trim(), just = String(f.justification || ''), by = String(f.by || '').trim();
    var scope = String(f.scope || '').trim(), exp = String(f.expires || '').trim();
    if (!key) { return { error: 'Choose the finding this decision is about.' }; }
    if (chars(key) > MAX_KEY) { return { error: 'The advisory id is longer than ' + MAX_KEY + ' characters.' }; }
    if (!STATUSES.some(function (s) { return s.id === status; })) { return { error: 'Choose a decision.' }; }
    if (chars(reason) > MAX_REASON) { return { error: 'The reason is longer than ' + MAX_REASON + ' characters.' }; }
    if (status === 'false-positive' && just && !JUSTIFICATIONS.some(function (j) { return j.id === just; })) { return { error: 'The justification is not one of the five OpenVEX justifications.' }; }
    if (exp && !(/^\d{4}-\d{2}-\d{2}$/.test(exp) && parseDay(exp))) { return { error: 'The end date must be a real date, YYYY-MM-DD.' }; }
    if (scope && (chars(scope) > MAX_SCOPE || /\s/.test(scope))) { return { error: 'The scope is a package name or purl prefix without spaces, at most ' + MAX_SCOPE + ' characters.' }; }
    if (chars(by) > MAX_BY) { return { error: 'The owner is longer than ' + MAX_BY + ' characters.' }; }
    var body = { check_id: key, status: status, note: reason };
    if (status === 'false-positive' && just) { body.justification = just; }          // a justification only means something for a false positive
    if (exp) { body.expires = exp; }
    if (scope) { body.scope = scope; }
    if (by) { body.by = by; }
    return { body: body };
  }
  function justificationOptions() {
    return '<option value="">(none: the finding stays affected)</option>' + JUSTIFICATIONS.map(function (j) {
      return '<option value="' + esc(j.id) + '">' + esc(j.id) + ' — ' + esc(j.text) + '</option>';
    }).join('');
  }
  function statusOptions() {
    return '<option value="">(choose a decision)</option>' + STATUSES.map(function (s) { return '<option value="' + esc(s.id) + '">' + esc(s.label) + '</option>'; }).join('');
  }
  function statusHint(id) {
    var s = STATUSES.filter(function (x) { return x.id === id; })[0];
    return s ? s.hint : '';
  }
  function findingKey(f) { return String(f && (f.cve || f.id) || ''); }
  function findingOptions(findings, selected) {
    var rows = list(findings).filter(function (f) { return findingKey(f); });
    if (!rows.length) { return '<option value="">(this project has no findings)</option>'; }
    return '<option value="">(choose a finding)</option>' + rows.map(function (f) {
      var k = findingKey(f), label = k + ' — ' + val(f.name) + ' ' + val(f.version) + ' (' + val(f.severity) + ')' +
        (f.triage_status && f.triage_status !== 'open' ? ' · decision recorded: ' + f.triage_status : '');
      return '<option value="' + esc(k) + '"' + (k === selected ? ' selected' : '') + '>' + esc(label) + '</option>';
    }).join('');
  }

  /* ---------- fleet and "who is affected" ---------- */
  function renderFleet(res, analysedAt) {
    var T = 'Fleet', out;
    if (!res) { return loading(T); }
    if (!res.ok) { return failure(T, res); }
    var d = obj(res.data);
    if (!isNum(d.projects)) { return heading(T) + note('The service returned no roll-up.', 'warn'); }
    if (d.projects === 0) { return heading(T) + note('No project has been analysed yet, so there is nothing to roll up. Analyse a repository on the <b>Scan</b> tab.'); }
    var sev = obj(d.severity), cards = [['Projects', d.projects], ['Components', d.components], ['Findings', d.vulns], ['Without a known fix', d.unfixed_findings],
                                        ['With a malicious package', Array.isArray(d.projects_with_malicious) ? d.projects_with_malicious.length : undefined]];
    out = heading(T, 'portfolio roll-up over every analysed project');
    out += '<div class="bts-cards">' + cards.map(function (c) { return '<div class="bts-card"><div class="v">' + esc(val(c[1])) + '</div><div class="l">' + esc(c[0]) + '</div></div>'; }).join('') + '</div>';
    out += kv([['Findings by severity', H(SEVS.filter(function (k) { return sev.hasOwnProperty(k); }).map(function (k) { return U.sevBadge(k).html + ' ' + esc(sev[k]); }).join(' &nbsp; ') || '—')],
               ['Licence categories', Object.keys(obj(d.license_categories)).sort().map(function (k) { return k + ': ' + d.license_categories[k]; }).join(', ') || '—']]);
    if (list(d.projects_with_malicious).length) {
      out += note('<b>Malicious-package advisory in:</b> ' + list(d.projects_with_malicious).map(esc).join(', '), 'bad');
    }
    out += note('Each project is shown as of its <b>last analysis</b> (see the Analysed column). A project analysed offline, or with unqueried packages, can lack findings, so these counts are a lower bound.');
    out += heading('Projects', 'ranked by weighted findings');
    out += table(['#', 'Project', 'Analysed', 'Components', 'Findings', 'Worst', 'Weighted', 'No fix', 'Malicious', ''], list(d.ranking).map(function (r, i) {
      return [i + 1, r.project, ageOf(analysedAt, r.project), val(r.components), val(r.vulns), r.worst ? U.sevBadge(r.worst) : '—', val(r.weighted), val(r.unfixed), val(r.malicious),
              H('<button type="button" class="bts-link" data-act="open" data-name="' + esc(r.project) + '">Open</button>')];
    }), 'No project was ranked.');
    if (d.ranking_basis) { out += '<div class="bts-small">' + esc(d.ranking_basis) + '</div>'; }
    var sa = list(d.shared_advisories).filter(function (e) { return isNum(e.project_count) && e.project_count > 1; });
    out += heading('Advisories reported by several projects');
    out += table(['Advisory', 'Package', 'Worst', 'Fixed in', 'Projects', 'Which'], sa.map(function (e) {
      return [val(e.id), val(e.package), e.worst ? U.sevBadge(e.worst) : '—', fixedCell(e.fixed_version), val(e.project_count), list(e.projects).join(', ')];
    }), 'No advisory is reported by more than one project.');
    var sc = list(d.shared_components);
    out += heading('Components used by several projects');
    out += table(['Component', 'Version', 'Projects', 'Findings (most in one project)', 'Which'], sc.map(function (e) {
      return [val(e.name), val(e.version), val(e.project_count), val(e.vulns), list(e.projects).join(', ')];
    }), 'No component is shared by more than one project.');
    return out;
  }
  function affectedQuery(f) {
    f = f || {};
    var cve = String(f.cve || '').trim(), comp = String(f.component || '').trim(), ver = String(f.version || '').trim(), q = [];
    if (!cve && !comp) { return { error: 'Give an advisory id (CVE, GHSA, ...) and/or a component name.' }; }
    if (cve) { q.push('cve=' + encodeURIComponent(cve)); }
    if (comp) { q.push('component=' + encodeURIComponent(comp)); }
    if (ver) { q.push('version=' + encodeURIComponent(ver)); }
    return { url: '/api/affected?' + q.join('&') };
  }
  function matchRow(project, age, m, q) {
    if (m.kind === 'finding') {
      return [project, age, H('finding <code>' + esc(m.id) + '</code>'), val(m.package), val(m.version), H(U.sevBadge(m.severity).html + ' ' + (m.fixed_version ? 'fixed in ' + esc(m.fixed_version) : 'no fix known'))];
    }
    if (m.kind === 'version_unknown') {
      return [project, age, pill('version unknown', 'warn'), val(m.package), '—', 'The component has no recorded version, so it cannot be checked against ' + (q.version || 'the constraint') + '.'];
    }
    return [project, age, 'component', val(m.package), val(m.version), val(m.relationship) + ' · ' + val(m.vulns) + ' known finding(s)'];
  }
  function renderAffected(res, analysedAt) {
    if (!res) { return ''; }
    if (!res.ok) { return note('<b>The search did not run.</b> ' + esc(obj(res.data).error || ('HTTP ' + res.status)), 'bad'); }
    var d = obj(res.data), q = obj(d.query), what = [q.id, q.component, q.version].filter(function (x) { return x; }).join(' · ') || '—', rows = [];
    list(d.projects).forEach(function (p) { list(p.matches).forEach(function (m) { rows.push(matchRow(p.project, ageOf(analysedAt, p.project), m, q)); }); });
    var out = heading('Search result', what);
    out += kv([['Projects that match', val(d.project_count) + ' of ' + val(d.analysed_projects) + ' analysed'], ['Matches', val(d.match_count)]]);
    out += table(['Project', 'Analysed', 'What', 'Package', 'Version', 'Detail'], rows, q.id ? 'No analysed project reports this advisory.' : 'No analysed project uses this component.');
    var nf = list(d.not_found_in), names = nf.map(function (n) { return esc(n) + ' (' + esc(ageOf(analysedAt, n)) + ')'; }).join(', ');
    if (nf.length && q.id) {
      out += note('<b>Not found among the findings of the last analysis in:</b> ' + names +
        '. That is not proof they are unaffected: a project analysed offline, or with unqueried packages, can lack findings.');
    } else if (nf.length) {
      out += note('<b>No matching component' + (q.version ? ' within the constraint' : '') + ' in:</b> ' + names + ', as of their last analysis.');
    }
    return out + (d.note ? '<div class="bts-small">' + esc(d.note) + '</div>' : '');
  }

  return {
    JUSTIFICATIONS: JUSTIFICATIONS, STATUSES: STATUSES, MIN_REASON: MIN_REASON, LEGAL_NOTE: LEGAL_NOTE,
    renderConformance: renderConformance, renderChanges: renderChanges, renderVex: renderVex, renderDecisions: renderDecisions,
    renderFleet: renderFleet, renderAffected: renderAffected,
    triageOutcome: triageOutcome, triageRequest: triageRequest, justificationOptions: justificationOptions, statusOptions: statusOptions,
    statusHint: statusHint, findingOptions: findingOptions, findingKey: findingKey, affectedQuery: affectedQuery, isExpired: isExpired
  };
});
