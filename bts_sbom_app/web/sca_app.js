/*!
 * sca_app.js — SCA console renderer for the OSS security view.
 * Vanilla JS, no dependencies (no jQuery); IIFE, single global window.ScaApp,
 * all state in closure variables, reset on every render().
 * PUBLIC API:
 *   ScaApp.render(mountEl, report, opts) — draw the report into mountEl.innerHTML
 *   ScaApp.setToolOutput(htmlOrNode)     — fill the Tools output area (#sxToolOut)
 *   ScaApp.notify(label)                 — show "label — running…" in that area
 *   ScaApp.version = '1.1.0'
 * opts (all optional, safe defaults):
 *   proxy(btnId)  hidden classic button runner 'dlXlsx'|'dlSbomFmt'|'dlReport'; missing -> warn + no-op.
 *   setMode(mode) 'classic' switch callback (Classic toggle / sidebar Settings).
 *   runTool(name) 'checkUpdates'|'vulnTrend'|'vulnAge'; missing -> buttons disabled + "skip".
 *   history()     [{label,total,critical,high,medium,low,ts}]; missing/empty -> honest empty state.
 *   testedLabel   e.g. 'Tested just now'; missing -> '—'.
 *   triage(checkId, status, note) -> Promise<boolean>; set triage for one issue
 *                 (status: 'open'|'accepted'|'wontfix'|'false-positive'|'fixed').
 *                 Missing -> Ignore form hidden; false/rejection -> honest error inside the card.
 *   triageCached() -> map { cveOrId: {status, note} }; current triage state at render time.
 *   retest(path)   -> boolean; start a re-scan of one history target; missing -> disabled + "skip".
 *   scanDiff()     -> Promise<{ok, message?, new_cves[], resolved_cves[], new_pkgs[],
 *                 removed_pkgs[], new_high}>; missing -> disabled; ok:false -> message verbatim.
 *   advisory(query, ecosystem) -> Promise<{ok, source, advisory|advisories, count?, note?, error?}>;
 *                 missing -> Lookup disabled; result rendered defensively into the Tools output.
 * Severity colors = sca_app.css sx vars: CRITICAL #9F4BDD · HIGH #BC5F04 · MEDIUM #EDAB00 ·
 *   LOW #4A76AA · UNKNOWN #6e7681. Sort rank: CRITICAL=0, HIGH=1, MEDIUM=2, LOW=3, UNKNOWN=4.
 * Priority score: report-computed 0-1000 with levels P0 #fb2c36 / P1 #ff8904 / P2 #ffb224 /
 *   P3 #52a8ff / P4 #7e838c; ring and chip follow the level. Sort: severity rank asc, then
 *   priority score desc (falling back to CVSS when priority is absent).
 * Report schema (every field optional, all access defensive):
 *   source; severity{total,CRITICAL..UNKNOWN,vulnerable_packages}; scan_status{mode,unqueried,offline_no_data};
 *   findings[]{cve,id,aliases[],name,version,severity,score,summary,vector,ecosystem,ref(purl),location,url,
 *     fixed,kev,reachability_status,epss,epss_percentile,vex_status,
 *     priority{score(0-1000),level(P0..P4),factors{cvss,exploit,reach,fix,kev(0-100)}},
 *     triage_status,triage_note};
 *   remediation[]{component,current_version,safe_version};
 *   packages[]{name,version,license,dep_license,dependency_type,ecosystem,source_file,obligations{gpl_warning},
 *     health{grade,reason}}; licenses.summary.category_counts{};
 *   license_verification.summary{ok,deprecated,invalid,none};
 *   source_licenses{source: licenseStrOrObj, policy, policy_findings[](unstructured -> escaped table)};
 *   dep_tree{manifests[]{path,ecosystems[],total,direct,transitive,unknown,vulnerable,max_depth,
 *     children[]{name,version,ecosystem,relationship,depth,parents[],license,location,
 *       health{score,grade},vuln_count,severities{CRITICAL..UNKNOWN},worst_severity,fixed_latest,
 *       children[...]}}}.
 * Honest degradation: dep_tree absent/empty -> Tree toggle hidden; no triage backend -> no Ignore
 *   form; ignored issues hidden by default ("Show ignored" filter), reflected in the tab count.
 * Markup emits exactly the agreed sx-* class names for sca_app.css. Inline styles only where JS computes
 *   values (severity colors, donut conic-gradient, score ring --sc/--sp, EPSS bar --ep, factor bar --fv)
 *   + pane visibility. Every dynamic string passes esc()/escAttr(); hrefs restricted to http(s). SBOM
 *   selects carry the format label as value; the glue's proxy('dlSbomFmt') handler syncs hidden #sbomFmtSel.
 */
(function () {
  'use strict';

  /* constants */
  var SEVS = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'];
  var SEV_COLOR = { CRITICAL: '#9F4BDD', HIGH: '#BC5F04', MEDIUM: '#EDAB00', LOW: '#4A76AA', UNKNOWN: '#6e7681' };
  var SEV_RANK = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, UNKNOWN: 4 };
  var TABS = ['overview', 'issues', 'deps', 'licenses', 'history', 'tools'];
  // Honest sidebar delegation: Console nav items map onto tabs we really have.
  var NAV_TO_TAB = { projects: 'overview', issues: 'issues', reporting: 'history', integrations: 'tools' };
  var SUM_TRUNC = 150;                    // issue subtitle truncation length
  var TOOL_OUT_EMPTY = 'Run a tool to see output here.';
  var ESC_MAP = { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' };
  // Priority levels (ring/chip colors) and the score factor weights (must sum to 100).
  var P_LEVEL_COLOR = { P0: '#fb2c36', P1: '#ff8904', P2: '#ffb224', P3: '#52a8ff', P4: '#7e838c' };
  var PRIOR_FACTORS = [
    ['cvss', 'CVSS', 30], ['exploit', 'Exploit maturity', 25], ['reach', 'Reachability', 20],
    ['fix', 'Fix available', 10], ['kev', 'CISA KEV', 15]
  ];
  var TRIAGE_STATUSES = ['open', 'accepted', 'wontfix', 'false-positive', 'fixed'];
  var TRIAGE_LABELS = {
    open: 'Open', accepted: 'Accepted risk', wontfix: 'Won\u2019t fix',
    'false-positive': 'False positive', fixed: 'Fixed'
  };
  var ADV_ECOSYSTEMS = ['', 'PyPI', 'npm', 'Maven', 'Hex', 'Cargo', 'Go', 'crates.io', 'NuGet', 'RubyGems'];
  var ADV_FIELDS = [['id', 'ID'], ['identifier', 'ID'], ['cve', 'CVE'], ['aliases', 'Aliases'],
    ['severity', 'Severity'], ['severity_score', 'Severity score'], ['cvss_score', 'CVSS'],
    ['cvss_vector', 'CVSS vector'], ['summary', 'Summary'], ['title', 'Title'],
    ['description', 'Description'], ['affected', 'Affected'], ['fixed_versions', 'Fixed versions'],
    ['published', 'Published'], ['modified', 'Modified'], ['source_name', 'Source']];

  /* closure state */
  var mount = null, R = {}, O = {}, activeTab = 'overview';
  var F = null, DF = null;                // issue / dependency filters
  var openMap = {}, remapCache = null;    // open issues, component->safe_version
  var depView = 'table';                  // deps pane: 'table' | 'tree'
  var triageCache = null;                 // opts.triageCached() map (cveOrId -> {status, note})
  var pendingToolOut = null;              // setToolOutput() before render / after unmount

  /* helpers */
  // Escape for text content and quoted attribute values alike.
  function esc(v) { return String(v === null || v === undefined ? '' : v).replace(/[&<>"']/g, function (c) { return ESC_MAP[c]; }); }
  function escAttr(v) { return esc(v); }  // separate name for attribute call sites
  // Strict numeric coercion: finite number or null (never NaN).
  function numv(v) {
    if (typeof v === 'number' && isFinite(v)) return v;
    return (typeof v === 'string' && v.trim() !== '' && isFinite(Number(v))) ? Number(v) : null;
  }
  function txt(v) { return (v === null || v === undefined) ? '' : String(v); }
  function trunc(s, n) { s = txt(s); return s.length > n ? s.slice(0, n - 1) + '\u2026' : s; }
  function clamp(v, lo, hi) { return Math.max(lo, Math.min(hi, v)); }
  // Normalized severity of a finding; anything unexpected becomes UNKNOWN.
  function sevOf(f) { var s = txt(f && f.severity).toUpperCase(); return SEV_COLOR.hasOwnProperty(s) ? s : 'UNKNOWN'; }
  function fmtTs(ts) {
    var n = numv(ts);
    if (n === null) return txt(ts) || '\u2014';
    try { return new Date(n).toLocaleString(); } catch (e) { return txt(ts) || '\u2014'; }
  }
  // Walk up from el to (excluding) mount; delegation never escapes the app root.
  function closest(el, sel) {
    while (el && el !== mount) { if (el.matches && el.matches(sel)) return el; el = el.parentNode; }
    return null;
  }
  // Only allow http(s) URLs into href attributes.
  function safeUrl(u) { var s = txt(u).trim(); return /^https?:\/\//i.test(s) ? s : ''; }

  /* report accessors (defensive) */
  function findings() { return Array.isArray(R.findings) ? R.findings : []; }
  function packagesList() { return Array.isArray(R.packages) ? R.packages : []; }
  function remediationList() { return Array.isArray(R.remediation) ? R.remediation : []; }
  // component name -> safe_version
  function remap() {
    if (remapCache) return remapCache;
    remapCache = {};
    remediationList().forEach(function (r) { if (r && txt(r.component) && txt(r.safe_version)) remapCache[txt(r.component)] = { safe: txt(r.safe_version), cur: txt(r.current_version) }; });
    return remapCache;
  }
  function hasFix(f) { return !!(f && (txt(f.fixed) || remap()[txt(f.name)])); }
  function sevCounts() {
    var out = { total: 0, CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0, vulnerable_packages: 0 };
    var fs = findings();
    var s = (R.severity && typeof R.severity === 'object') ? R.severity : null;
    if (s) {
      SEVS.forEach(function (k) { var n = numv(s[k]); if (n !== null) out[k] = n; });
      var t = numv(s.total); if (t !== null) out.total = t;
      var vp = numv(s.vulnerable_packages); if (vp !== null) out.vulnerable_packages = vp;
    } else {
      fs.forEach(function (f) { out[sevOf(f)]++; }); // honest fallback from findings
    }
    if (!out.total) { var sum = 0; SEVS.forEach(function (k) { sum += out[k]; }); out.total = sum || fs.length; }
    if (!out.vulnerable_packages) {
      var names = {};
      fs.forEach(function (f) { if (f && txt(f.name)) names[txt(f.name)] = 1; });
      out.vulnerable_packages = Object.keys(names).length;
    }
    return out;
  }
  function unverifiedCount() { var ss = R.scan_status; return (ss && typeof ss === 'object') ? (numv(ss.unqueried) || 0) + (numv(ss.offline_no_data) || 0) : 0; }
  // Issues tab count: hides triaged-away (ignored) issues while "Show ignored" is off.
  function issueTabCount(sc) {
    var fs = findings(), ignored = 0;
    fs.forEach(function (f) { if (isIgnored(f)) ignored++; });
    return ignored ? Math.max(sc.total - ignored, 0) : sc.total;
  }
  function issueKey(f) { return txt(f.cve || f.id) + '|' + txt(f.name) + '|' + txt(f.version); }
  // Identifier the triage backend keys on (cve || id).
  function triageKey(f) { return txt(f && (f.cve || f.id)); }
  // priority{score,level,factors} — null when absent (honest fallback to the CVSS ring).
  function prioOf(f) {
    var p = (f && f.priority && typeof f.priority === 'object') ? f.priority : null;
    if (!p) return null;
    var score = numv(p.score), lvl = txt(p.level).toUpperCase();
    return {
      score: score === null ? null : clamp(Math.round(score), 0, 1000),
      level: P_LEVEL_COLOR.hasOwnProperty(lvl) ? lvl : null,
      factors: (p.factors && typeof p.factors === 'object') ? p.factors : null
    };
  }
  // Triage state: when the glue supplies triageCached() it is authoritative (missing
  // key = open); only without a cache do the finding's own fields apply. null = open.
  function triageOf(f) {
    var k = triageKey(f);
    if (triageCache !== null) {
      var c = triageCache[k];
      return (c && typeof c === 'object') ? { status: txt(c.status).toLowerCase(), note: txt(c.note) } : null;
    }
    var st = txt(f && f.triage_status).toLowerCase();
    return st ? { status: st, note: txt(f && f.triage_note) } : null;
  }
  function isIgnored(f) {
    var t = triageOf(f);
    return !!(t && t.status && t.status !== 'open');
  }
  function errMsg(e) { return (e && e.message) ? String(e.message) : String(e); }

  /* filtering / sorting — severity rank asc, then priority score (else CVSS) desc */
  function cmpIssue(a, b) {
    var d = SEV_RANK[sevOf(a)] - SEV_RANK[sevOf(b)];
    if (d) return d;
    var pa = prioOf(a), pb = prioOf(b);
    if (pa && pa.score !== null && pb && pb.score !== null) return pb.score - pa.score;
    var sa = numv(a.score), sb = numv(b.score);
    return (sb === null ? -1 : sb) - (sa === null ? -1 : sa);
  }
  function filteredFindings() {
    var q = txt(F.search).trim().toLowerCase();
    return findings().filter(function (f) {
      if (!f) return false;
      if (!F.sev[sevOf(f)]) return false;
      if (F.fixOnly && !hasFix(f)) return false;
      if (F.kevOnly && f.kev !== true) return false;
      if (F.reachOnly && txt(f.reachability_status).toLowerCase() !== 'reachable') return false;
      if (!F.showIgnored && isIgnored(f)) return false;
      if (q) {
        var hay = txt(f.cve) + ' ' + txt(f.id) + ' ' + txt(f.name) + ' ' + txt(f.summary) + ' ' + (Array.isArray(f.aliases) ? f.aliases.join(' ') : '');
        if (hay.toLowerCase().indexOf(q) === -1) return false;
      }
      return true;
    }).sort(cmpIssue);
  }
  function filteredPackages() {
    var q = txt(DF.search).trim().toLowerCase();
    return packagesList().filter(function (p) {
      if (!p) return false;
      if (DF.type !== 'all' && txt(p.dependency_type).toLowerCase() !== DF.type) return false;
      if (q) {
        var hay = txt(p.name) + ' ' + txt(p.ecosystem) + ' ' + txt(p.source_file) + ' ' + txt(p.license) + ' ' + txt(p.dep_license);
        if (hay.toLowerCase().indexOf(q) === -1) return false;
      }
      return true;
    });
  }
  // package name -> { SEVERITY: count }
  function vulnIndex() {
    var idx = {};
    findings().forEach(function (f) {
      if (!f || !txt(f.name)) return;
      var n = txt(f.name); if (!idx[n]) idx[n] = {};
      idx[n][sevOf(f)] = (idx[n][sevOf(f)] || 0) + 1;
    });
    return idx;
  }

  /* shell builders */
  function html(sc) { return '<div class="sx-app">' + sideHtml(sc) + mainHtml(sc) + '</div>'; }

  function sideHtml(sc) {
    var badge = sc.total > 0 ? ' <span class="sx-nav-badge">' + sc.total + '</span>' : '';
    return '<aside class="sx-side">' +
      '<div class="sx-side-logo">BTS<span class="sx-logo-dot"></span></div>' +
      '<div class="sx-org">\u25A3 AutoGuard \u25BE</div>' +
      '<nav class="sx-nav">' +
        '<button type="button" class="sx-nav-item on" data-sx-nav="projects">\u229E Projects</button>' +
        '<button type="button" class="sx-nav-item" data-sx-nav="issues">\u26A0 Issues' + badge + '</button>' +
        '<button type="button" class="sx-nav-item" data-sx-nav="reporting">\u25A4 Reporting</button>' +
        '<button type="button" class="sx-nav-item" data-sx-nav="integrations">\u21C4 Integrations</button>' +
        '<button type="button" class="sx-nav-item" data-sx-nav="settings">\u2699 Settings</button>' +
      '</nav><div class="sx-side-foot">SCA engine: OSV.dev + deps.dev</div></aside>';
  }

  function mainHtml(sc) {
    var panes = [['overview', paneOverview(sc)], ['issues', paneIssues(sc)], ['deps', paneDeps()],
      ['licenses', paneLicenses()], ['history', paneHistory()], ['tools', paneTools()]];
    return '<div class="sx-main">' + topbarHtml() + bannerHtml(sc) + tabsHtml(sc) +
      panes.map(function (p) {
        return '<div class="sx-pane" data-sx-pane="' + p[0] + '"' + (p[0] === 'overview' ? '' : ' style="display:none"') + '>' + p[1] + '</div>';
      }).join('') + footHtml() + '</div>';
  }

  function topbarHtml() {
    return '<div class="sx-topbar">' +
      '<div class="sx-crumb">AutoGuard <span>\u203A</span> SCA <span>\u203A</span> <b>' + esc(txt(R.source) || 'project') + '</b></div>' +
      '<div class="sx-actions">' +
        '<button type="button" class="sx-btn" data-sx-proxy="dlXlsx" title="Download findings as Excel">\u2B07 Excel</button>' +
        '<select id="sxSbomFmt" class="sx-select" title="SBOM format">' +
          '<option value="cdx">CycloneDX JSON</option><option value="spdx">SPDX JSON</option>' +
          '<option value="SPDX TV">SPDX TV</option></select>' +
        '<button type="button" class="sx-btn" data-sx-proxy="dlSbomFmt" title="Download SBOM">\u2B07 SBOM</button>' +
        '<button type="button" class="sx-btn" data-sx-proxy="dlReport" title="Download full report">\u2B07 Report</button>' +
        '<button type="button" class="sx-btn sx-btn-ghost" data-sx-classic title="Switch to the classic view">Classic</button>' +
      '</div></div>';
  }

  function bannerHtml(sc) {
    var chips = SEVS.filter(function (sv) { return sc[sv] > 0; }).map(function (sv) {
      return '<b style="color:' + SEV_COLOR[sv] + '">' + sc[sv] + ' ' + sv + '</b>';
    }).join(' <span class="sx-sep">\u00B7</span> ');
    var tested = '<span class="sx-tested">' + esc(O.testedLabel || '\u2014') + '</span>', unv = unverifiedCount();
    var note = unv > 0 ? ' <span class="sx-note">' + unv + ' checks unverified (offline/DB \uC5C6\uC74C)</span>' : '';
    var side = '<div class="sx-banner-side">' + tested + note + '</div>';
    if (sc.total > 0) {
      var depN = packagesList().length || sc.vulnerable_packages || 0;
      return '<div class="sx-banner fail"><div class="sx-banner-msg">Found <b>' + sc.total + '</b> issues in <b>' + depN +
        '</b> dependencies' + (chips ? ' \u00B7 ' + chips : '') + '</div>' + side + '</div>';
    }
    return '<div class="sx-banner pass"><div class="sx-banner-msg">No known vulnerabilities detected</div>' + side + '</div>';
  }

  function tabsHtml(sc) {
    function tab(id, label) {
      return '<button type="button" class="sx-tab' + (id === activeTab ? ' on' : '') + '" data-sx-tab="' + id + '">' + label + '</button>';
    }
    return '<div class="sx-tabs">' + tab('overview', 'Overview') + tab('issues', 'Issues (' + issueTabCount(sc) + ')') +
      tab('deps', 'Dependencies (' + packagesList().length + ')') + tab('licenses', 'Licenses') +
      tab('history', 'History') + tab('tools', 'Tools') + '</div>';
  }

  function footHtml() {
    var s = 'Data: OSV.dev + deps.dev \u00B7 decisionmatic offline matching';
    if (typeof O.proxy !== 'function' || typeof O.runTool !== 'function') s += ' \u00B7 unavailable tools: skip';
    return '<div class="sx-foot">' + esc(s) + '</div>';
  }

  /* overview pane */
  function paneOverview(sc) {
    var cards = SEVS.map(function (sv) {
      return '<button type="button" class="sx-ov-card" data-sx-sevjump="' + sv + '" title="Show issues">' +
        '<span class="sx-ov-num" style="color:' + SEV_COLOR[sv] + '">' + sc[sv] + '</span><span class="sx-ov-label">' + sv + '</span></button>';
    }).join('');
    return '<div class="sx-ov-grid">' + cards + '</div><div class="sx-ov-row">' + donutHtml(sc) + mostVulnHtml() + '</div>' +
      '<div class="sx-sum-row"><span><b>' + sc.total + '</b> total issues</span>' +
      '<span><b>' + sc.vulnerable_packages + '</b> vulnerable packages</span>' +
      '<span><b>' + packagesList().length + '</b> packages scanned</span></div>';
  }

  // Severity donut: conic-gradient stops computed here, applied inline.
  function donutHtml(sc) {
    var total = sc.total || 0, stops = [], acc = 0;
    if (total > 0) {
      SEVS.forEach(function (sv) {
        if (!sc[sv]) return;
        var from = (acc / total) * 100;
        acc += sc[sv];
        stops.push(SEV_COLOR[sv] + ' ' + from.toFixed(2) + '% ' + ((acc / total) * 100).toFixed(2) + '%');
      });
    } else {
      stops.push(SEV_COLOR.UNKNOWN + ' 0% 100%');
    }
    var legend = SEVS.map(function (sv) {
      return '<span class="sx-legend-item"><i style="background:' + SEV_COLOR[sv] + '"></i>' + sv + ' (' + sc[sv] + ')</span>';
    }).join('');
    return '<div class="sx-ov-block"><h3 class="sx-ov-h">Severity distribution</h3>' +
      '<div class="sx-donut" style="background:conic-gradient(' + stops.join(',') + ')"><b class="sx-donut-total">' + total + '</b></div>' +
      '<div class="sx-legend">' + legend + '</div></div>';
  }

  function mostVulnHtml() {
    var byPkg = {};
    findings().forEach(function (f) {
      if (!f) return;
      var n = txt(f.name) || '(unknown)';
      var e = byPkg[n] || (byPkg[n] = { count: 0, worst: 'UNKNOWN' });
      e.count++;
      if (SEV_RANK[sevOf(f)] < SEV_RANK[e.worst]) e.worst = sevOf(f);
    });
    var rows = Object.keys(byPkg).map(function (n) { return { name: n, d: byPkg[n] }; })
      .sort(function (a, b) { return (b.d.count - a.d.count) || (SEV_RANK[a.d.worst] - SEV_RANK[b.d.worst]); }).slice(0, 5);
    var body = rows.length ? rows.map(function (r) {
      return '<tr><td><b>' + esc(r.name) + '</b></td><td>' + r.d.count + '</td><td><span class="sx-sev-pill" style="background:' +
        SEV_COLOR[r.d.worst] + ';color:#fff">' + r.d.worst + '</span></td></tr>';
    }).join('') : '<tr><td colspan="3" class="sx-empty">No vulnerable dependencies.</td></tr>';
    return '<div class="sx-ov-block"><h3 class="sx-ov-h">Most vulnerable dependencies</h3>' +
      '<div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>Package</th><th>Issues</th><th>Worst</th></tr></thead>' +
      '<tbody>' + body + '</tbody></table></div></div>';
  }

  /* issues pane */
  function paneIssues(sc) {
    var rail = '<div class="sx-filter-rail">' +
      '<input class="sx-input" type="search" placeholder="Search CVE, package, summary\u2026" data-sx-filter="search" />' +
      '<div class="sx-rail-group">' + sevChecks(sc) + '</div>' +
      '<div class="sx-rail-group">' +
        '<label class="sx-check"><input type="checkbox" data-sx-flag="fix" /> Fix available</label>' +
        '<label class="sx-check"><input type="checkbox" data-sx-flag="kev" /> KEV only</label>' +
        '<label class="sx-check"><input type="checkbox" data-sx-flag="reach" /> Reachable only</label>' +
        '<label class="sx-check"><input type="checkbox" data-sx-flag="ignored" /> Show ignored</label>' +
      '</div><div class="sx-rail-note">Click a severity to include/exclude</div></div>';
    return '<div class="sx-layout">' + rail + '<div class="sx-issue-list" data-sx-issuelist>' + issueListHtml() + '</div></div>';
  }

  function sevChecks(sc) {
    return SEVS.map(function (sv) {
      return '<label class="sx-check"><input type="checkbox" data-sx-sev="' + sv + '" checked /> <span style="color:' +
        SEV_COLOR[sv] + ';font-weight:600">' + sv + ' (' + sc[sv] + ')</span></label>';
    }).join('');
  }

  // Re-rendered in place on filter change (rail keeps focus and state).
  function issueListHtml() {
    if (sevCounts().total === 0 && findings().length === 0) {
      return '<div class="sx-empty">\uD83C\uDF89 No known vulnerabilities found.</div>';
    }
    var list = filteredFindings();
    if (!list.length) return '<div class="sx-empty">No issues match the current filters.</div>';
    return list.map(issueHtml).join('');
  }

  function issueHtml(f) {
    var sv = sevOf(f), key = issueKey(f), open = !!openMap[key];
    var ignored = isIgnored(f);
    return '<div class="sx-issue sev-' + sv.toLowerCase() + (open ? ' open' : '') + (ignored ? ' ignored' : '') +
      '" data-sx-issue="' + escAttr(key) + '" data-sx-trikey="' + escAttr(triageKey(f)) + '">' +
      (ignored ? ignoredBarHtml(f) : '') +
      '<div class="sx-issue-h" aria-expanded="' + (open ? 'true' : 'false') + '">' +
        '<span class="sx-sev-pill" style="background:' + SEV_COLOR[sv] + ';color:#fff">' + sv + '</span>' +
        '<div class="sx-issue-text"><div class="sx-issue-title">' + esc(txt(f.cve || f.id) || 'Unknown issue') +
        ' <span class="sx-issue-pkg">' + esc(txt(f.name)) + '</span></div>' +
        '<div class="sx-issue-sub">' + esc(trunc(f.summary, SUM_TRUNC)) + '</div></div>' +
        '<div class="sx-issue-chips">' + issueChips(f) + '</div>' + prioRingHtml(f, sv) +
        '<span class="sx-chev">\u25B8</span></div>' +
      issueDetail(f) + '</div>';
  }

  // Priority ring (score/1000 conic arc, colored by P level); falls back to the CVSS ring.
  function prioRingHtml(f, sv) {
    var pr = prioOf(f), chip = '';
    if (pr && pr.level) chip = '<span class="sx-pchip" style="background:' + P_LEVEL_COLOR[pr.level] +
      '" title="Priority level ' + esc(pr.level) + '">' + esc(pr.level) + '</span>';
    var ring;
    if (pr && pr.score !== null) {
      var color = pr.level ? P_LEVEL_COLOR[pr.level] : '#7e838c';
      ring = '<div class="sx-score-ring" style="--sc:' + color + ';--sp:' + ((pr.score / 1000) * 100).toFixed(1) +
        '%" title="Priority score ' + pr.score + ' / 1000"><span>' + pr.score + '</span></div>';
    } else {
      var score = numv(f.score);
      ring = '<div class="sx-score-ring" style="--sc:' + (score === null ? SEV_COLOR.UNKNOWN : SEV_COLOR[sv]) + ';--sp:' +
        (score === null ? 0 : clamp(score * 10, 0, 100).toFixed(1)) + '%" title="CVSS ' +
        (score === null ? '\u2014' : score.toFixed(1)) + '"><span>' + (score === null ? '\u2014' : score.toFixed(1)) + '</span></div>';
    }
    return '<span class="sx-issue-meta">' + chip + ring + '</span>';
  }

  // Gray banner on top of triaged-away issues; note kept verbatim (escaped).
  function ignoredBarHtml(f) {
    var t = triageOf(f) || {};
    var st = (t.status || 'ignored').replace(/_/g, ' ');
    var note = txt(t.note);
    return '<div class="sx-tri-bar"><span class="sx-chip-tri" title="Triaged: ' + escAttr(st) + '">Ignored \u2014 ' +
      esc(st) + '</span>' + (note ? '<span class="sx-tri-note" title="' + escAttr(note) + '">' + esc(trunc(note, 90)) + '</span>' : '') +
      '</div>';
  }

  function issueChips(f) {
    var out = [exploitChipHtml(f)]; // one exploit-maturity chip (replaces the bare KEV chip)
    if (hasFix(f)) out.push('<span class="sx-chip-fix" title="Fixed version available">Fix available</span>');
    var vex = txt(f.vex_status).toLowerCase();
    if (vex) out.push('<span class="sx-chip-vex-' + escAttr(vex) + '" title="VEX status">VEX \u00B7 ' + esc(vex.replace(/_/g, ' ')) + '</span>');
    var reach = txt(f.reachability_status).toLowerCase();
    if (reach) out.push('<span class="sx-chip-reach" data-reach="' + escAttr(reach) + '" title="Reachability">' + esc(reach.charAt(0).toUpperCase() + reach.slice(1)) + '</span>');
    return out.join('');
  }

  // Exploit maturity chip: KEV > EPSS >= 0.5 > EPSS observed > none.
  function exploitChipHtml(f) {
    var e = numv(f.epss), cls, label, title;
    if (f.kev === true) { cls = 'kev'; label = 'Known exploited (CISA KEV)'; title = 'Listed in CISA KEV'; }
    else if (e !== null && e >= 0.5) { cls = 'high'; label = 'High exploitation probability (EPSS)'; title = 'EPSS ' + (e * 100).toFixed(1) + '%'; }
    else if (e !== null && e > 0) { cls = 'low'; label = 'EPSS observed'; title = 'EPSS ' + (e * 100).toFixed(1) + '%'; }
    else { cls = 'low'; label = 'No known exploit'; title = 'No exploit evidence available'; }
    return '<span class="sx-chip-exp ' + cls + '" title="' + escAttr(title) + '">' + esc(label) + '</span>';
  }

  function issueDetail(f) {
    var pr = prioOf(f), score = numv(f.score);
    var aliases = Array.isArray(f.aliases) ? f.aliases.filter(function (a) { return txt(a); }) : [];
    var kvs = '';
    if (pr && pr.score !== null) kvs += kv('Priority score', '<b>' + pr.score + '</b> / 1000' + (pr.level ? ' (' + esc(pr.level) + ')' : ''));
    if (score !== null) kvs += kv('CVSS score', score.toFixed(1));
    if (aliases.length) kvs += kv('Aliases', aliases.map(function (a) { return '<code>' + esc(a) + '</code>'; }).join(' '));
    if (txt(f.vector)) kvs += kv('CVSS vector', '<code>' + esc(f.vector) + '</code>');
    if (txt(f.ecosystem)) kvs += kv('Ecosystem', esc(f.ecosystem));
    if (txt(f.ref)) kvs += kv('PURL', '<code>' + esc(f.ref) + '</code>');
    if (txt(f.location)) kvs += kv('Location', '<code>' + esc(f.location) + '</code>');
    kvs += kv('Version', esc(txt(f.version)) || '\u2014');
    var url = safeUrl(f.url);
    if (url) kvs += kv('Advisory', '<a href="' + escAttr(url) + '" target="_blank" rel="noopener noreferrer">View advisory \u2197</a>');
    var summary = txt(f.summary) || 'No summary provided by the advisory source.';
    return '<div class="sx-detail"><div class="sx-detail-l"><div class="sx-detail-sum">' + esc(summary) + '</div>' + factorsHtml(pr) + kvs +
      '</div><div class="sx-side-box">' + epssHtml(f) + remediationHtml(f) + triageFormHtml(f, triageOf(f)) + '</div></div>';
  }

  // Priority score factor breakdown; hidden entirely when the report omits factors.
  function factorsHtml(pr) {
    if (!pr || !pr.factors) return '';
    var rows = PRIOR_FACTORS.map(function (w) {
      var v = numv(pr.factors[w[0]]);
      if (v === null) return '';
      return '<div class="sx-factor"><span class="sx-factor-k">' + esc(w[1]) + '</span>' +
        '<span class="sx-factor-bar"><i style="--fv:' + clamp(v, 0, 100).toFixed(1) + '%"></i></span>' +
        '<span class="sx-factor-w">' + clamp(v, 0, 100) + ' \u00B7 ' + w[2] + '%</span></div>';
    }).join('');
    return rows ? '<div class="sx-factors"><div class="sx-factors-h">Priority score factors</div>' + rows + '</div>' : '';
  }

  // Ignore form; only rendered when the glue provides opts.triage (honest degradation).
  function triageFormHtml(f, t) {
    if (typeof O.triage !== 'function') return '';
    var st = (t && t.status) || 'open';
    if (TRIAGE_STATUSES.indexOf(st) === -1) st = 'open';
    var opts = TRIAGE_STATUSES.map(function (s) {
      return '<option value="' + s + '"' + (s === st ? ' selected' : '') + '>' + esc(TRIAGE_LABELS[s]) + '</option>';
    }).join('');
    return '<div class="sx-tri-form" data-sx-triform>' +
      '<div class="sx-tri-form-h">Triage \u00B7 Ignore</div>' +
      '<select class="sx-select" data-sx-tri-status>' + opts + '</select>' +
      '<input class="sx-input" data-sx-tri-note placeholder="Reason (optional)" value="' + escAttr(t && t.note) + '" />' +
      '<button type="button" class="sx-btn" data-sx-tri-apply>Apply</button>' +
      '<div class="sx-tri-msg" data-sx-trimsg style="display:none"></div></div>';
  }

  function showTriMsg(scope, text, isErr) {
    var box = scope ? scope.querySelector('[data-sx-trimsg]') : null;
    if (!box) return;
    box.textContent = text;
    box.className = isErr ? 'sx-tri-msg sx-tri-err' : 'sx-tri-msg';
    box.style.display = '';
  }

  // Apply one triage change; the glue re-renders on success, failures surface in-card (honest).
  function applyTriage(btn) {
    var scope = closest(btn, '.sx-tri-form'), card = closest(btn, '.sx-issue');
    var sel = scope ? scope.querySelector('[data-sx-tri-status]') : null;
    if (!scope || !sel || typeof O.triage !== 'function') return;
    var id = card ? txt(card.getAttribute('data-sx-trikey')) : '';
    var status = txt(sel.value).toLowerCase();
    var noteEl = scope.querySelector('[data-sx-tri-note]');
    var note = noteEl ? txt(noteEl.value) : '';
    if (!id) { showTriMsg(scope, 'This issue carries no identifier to triage against.', true); return; }
    if (TRIAGE_STATUSES.indexOf(status) === -1) { showTriMsg(scope, 'Unknown triage status \u201C' + status + '\u201D.', true); return; }
    showTriMsg(scope, 'Saving triage\u2026', false);
    var res;
    try { res = O.triage(id, status, note); }
    catch (e) { showTriMsg(scope, 'Triage failed: ' + errMsg(e), true); return; }
    if (res && typeof res.then === 'function') {
      res.then(function (ok) {
        if (ok === false) showTriMsg(scope, 'Not applied \u2014 the triage backend reported failure.', true);
        // ok === true: the glue re-renders the report with fresh triage state.
      }, function (e2) { showTriMsg(scope, 'Triage failed: ' + errMsg(e2), true); });
    } else if (res === false) {
      showTriMsg(scope, 'Not applied \u2014 the triage backend reported failure.', true);
    }
  }

  function kv(k, vHtml) {
    return '<div class="sx-kv"><span class="sx-kv-k">' + esc(k) + '</span><span class="sx-kv-v">' + vHtml + '</span></div>';
  }

  function epssHtml(f) {
    var e = numv(f.epss), p = numv(f.epss_percentile);
    var label = e === null ? 'EPSS \u2014 no score available'
      : 'EPSS ' + (e * 100).toFixed(1) + '%' + (p !== null ? ' \u00B7 percentile ' + p.toFixed(2) : '');
    return '<div class="sx-epss"><div class="sx-epss-bar" style="--ep:' + (e === null ? 0 : clamp(e * 100, 0, 100).toFixed(1)) + '%"></div><div class="sx-epss-label">' + esc(label) + '</div></div>';
  }

  function remediationHtml(f) {
    var head = '<div class="sx-remediation-h">How to fix?</div>';
    var e = remap()[txt(f.name)]; // { safe, cur } | undefined
    if (e) {
      return '<div class="sx-remediation">' + head + '<div class="sx-remediation-body">Upgrade ' + esc(txt(f.name)) + ' ' +
        esc(e.cur || txt(f.version)) + ' \u2192 <b>' + esc(e.safe) + '</b></div></div>';
    }
    if (txt(f.fixed)) {
      return '<div class="sx-remediation">' + head + '<div class="sx-remediation-body">Fixed in ' + esc(f.fixed) + '</div></div>';
    }
    var url = safeUrl(f.url);
    return '<div class="sx-remediation none">' + head + '<div class="sx-remediation-body">No fixed version identified \u2014 review the advisory' +
      (url ? ' (<a href="' + escAttr(url) + '" target="_blank" rel="noopener noreferrer">link</a>)' : '.') + '</div></div>';
  }

  /* dependencies pane */
  function paneDeps() {
    var canRun = typeof O.runTool === 'function';
    var ms = depManifests();
    // Table/Tree toggle only when the report actually carries a dependency tree (honest).
    var toggle = ms.length ? '<div class="sx-viewtoggle" role="group" aria-label="Dependency view">' +
      '<button type="button" class="sx-tbtn' + (depView === 'table' ? ' on' : '') + '" data-sx-depview="table">Table</button>' +
      '<button type="button" class="sx-tbtn' + (depView === 'tree' ? ' on' : '') + '" data-sx-depview="tree">Tree</button></div>' : '';
    return '<div class="sx-dep-toolbar">' +
      '<span class="sx-dep-filters" data-sx-depfilters>' +
        '<input class="sx-input" type="search" placeholder="Filter packages\u2026" data-sx-depsearch />' +
        '<select class="sx-select" data-sx-deptype><option value="all">All dependencies</option><option value="direct">Direct only</option><option value="transitive">Transitive only</option></select>' +
      '</span>' + toggle +
      '<button type="button" class="sx-btn-ghost" data-sx-tool="checkUpdates"' +
      (canRun ? '' : ' disabled title="Unavailable \u2014 no tool runner provided"') + '>\u21BB Check Updates' + (canRun ? '' : skipTag()) + '</button></div>' +
      '<div data-sx-depbody>' + depsBodyHtml() + '</div>';
  }

  function depManifests() {
    var dt = (R.dep_tree && typeof R.dep_tree === 'object') ? R.dep_tree : null;
    return (dt && Array.isArray(dt.manifests)) ? dt.manifests.filter(function (m) { return m && typeof m === 'object'; }) : [];
  }

  function depsBodyHtml() {
    return depView === 'tree'
      ? depTreeHtml()
      : '<div class="sx-table-wrap">' + depsTableHtml() + '</div>';
  }

  function depsTableHtml() {
    if (!packagesList().length) return '<div class="sx-empty">No dependency data in this report.</div>';
    var pkgs = filteredPackages();
    if (!pkgs.length) return '<div class="sx-empty">No packages match the current filters.</div>';
    var vIdx = vulnIndex();
    var rows = pkgs.map(function (p) {
      var name = txt(p.name) || '(unknown)';
      var meta = [txt(p.ecosystem), txt(p.source_file)].filter(Boolean).join(' \u00B7 ');
      var gpl = (p.obligations && p.obligations.gpl_warning) ? ' <span class="sx-chip-gpl" title="GPL obligation warning">GPL</span>' : '';
      var v = vIdx[name];
      var vcell = v ? Object.keys(v).sort(function (a, b) { return SEV_RANK[a] - SEV_RANK[b]; }).map(function (sv) {
        return '<span class="sx-sev-pill" style="background:' + SEV_COLOR[sv] + ';color:#fff">' + v[sv] + ' ' + sv + '</span>';
      }).join(' ') : '<span class="sx-dim">0</span>';
      var h = (p.health && typeof p.health === 'object') ? p.health : {};
      var g = txt(h.grade).toUpperCase();
      var hcell = g ? '<span class="sx-grade" style="background:' + gradeColor(g) + ';color:#fff">' + esc(g) + '</span>' +
        (txt(h.reason) ? ' <span class="sx-dim">' + esc(h.reason) + '</span>' : '') : '<span class="sx-dim">\u2014</span>';
      var dtype = txt(p.dependency_type).toLowerCase();
      return '<tr><td><b>' + esc(name) + '</b>' + gpl + (meta ? '<div class="sx-pkg-meta">' + esc(meta) + '</div>' : '') + '</td>' +
        '<td>' + esc(txt(p.version) || '\u2014') + '</td><td>' + (dtype ? '<span class="sx-chip-type">' + esc(dtype) + '</span>' : '\u2014') + '</td>' +
        '<td>' + esc(txt(p.license) || txt(p.dep_license) || '\u2014') + '</td>' +
        '<td>' + vcell + '</td><td>' + hcell + '</td></tr>';
    }).join('');
    return '<table class="sx-table" id="scaSbomTable"><thead><tr><th>Package</th><th>Version</th><th>Type</th>' +
      '<th>License</th><th>Vulnerabilities</th><th>Health</th></tr></thead><tbody>' + rows + '</tbody></table>';
  }

  function gradeColor(g) {
    if (g === 'A' || g === 'B') return '#2f9e44';
    if (g === 'C') return SEV_COLOR.MEDIUM;
    if (g === 'D') return SEV_COLOR.HIGH;
    if (g === 'F') return '#c0392b';
    return SEV_COLOR.UNKNOWN;
  }

  /* dependency tree view (recursive children, honest empty states) */
  function depTreeHtml() {
    var ms = depManifests();
    if (!ms.length) return '<div class="sx-empty">No dependency tree data in this report.</div>';
    return '<div class="sx-tree">' + ms.map(depTreeManifestHtml).join('') + '</div>';
  }

  function depTreeManifestHtml(m) {
    var sums = [['total', 'total'], ['direct', 'direct'], ['transitive', 'transitive'], ['vulnerable', 'vulnerable']]
      .map(function (p) {
        var n = numv(m[p[0]]);
        if (n === null) return '';
        return '<span' + (p[0] === 'vulnerable' && n > 0 ? ' class="bad"' : '') + '>' + esc(p[1]) + ' <b>' + n + '</b></span>';
      }).filter(Boolean).join('');
    var kids = Array.isArray(m.children) ? m.children.filter(Boolean) : [];
    var head = '<div class="sx-tree-head"><code class="sx-tree-path">' + esc(txt(m.path) || '(manifest)') + '</code>' +
      (sums ? '<span class="sx-tree-sums">' + sums + '</span>' : '') + '</div>';
    var body = kids.length
      ? '<div class="sx-tree-kids">' + kids.map(function (c) { return depTreeNodeHtml(c); }).join('') + '</div>'
      : '<div class="sx-empty sx-tree-empty">No dependency entries recorded for this manifest.</div>';
    return '<div class="sx-tree-manifest">' + head + body + '</div>';
  }

  function depTreeNodeHtml(n) {
    if (!n || typeof n !== 'object') return '';
    var ver = txt(n.version);
    var label = '<span class="sx-tree-label"><code class="sx-tree-pkg">' + esc(txt(n.name) || '(unknown)') +
      (ver ? '@' + esc(ver) : '') + '</code></span>';
    var rel = txt(n.relationship).toLowerCase();
    var row = '<div class="sx-tree-node">' + label +
      (rel ? '<span class="sx-chip sx-chip-rel" title="Relationship">' + esc(rel) + '</span>' : '') +
      depTreeVulnHtml(n) +
      (txt(n.fixed_latest) ? '<span class="sx-chip sx-chip-fix" title="Fixed in the latest version">fix: ' + esc(n.fixed_latest) + '</span>' : '') +
      (txt(n.location) ? '<span class="sx-tree-loc" title="' + escAttr(n.location) + '">' + esc(n.location) + '</span>' : '') +
      '</div>';
    var kids = Array.isArray(n.children) ? n.children.filter(Boolean) : [];
    if (kids.length) row += '<div class="sx-tree-kids">' + kids.map(function (c) { return depTreeNodeHtml(c); }).join('') + '</div>';
    return '<div class="sx-tree-item">' + row + '</div>';
  }

  function depTreeVulnHtml(n) {
    var vc = numv(n.vuln_count);
    if (vc === null || vc <= 0) return '';
    var worst = txt(n.worst_severity).toUpperCase();
    if (!SEV_COLOR.hasOwnProperty(worst)) {
      var sev = (n.severities && typeof n.severities === 'object') ? n.severities : {};
      for (var i = 0; i < SEVS.length; i++) {
        var c = numv(sev[SEVS[i]]);
        if (c !== null && c > 0) { worst = SEVS[i]; break; }
      }
    }
    var color = SEV_COLOR.hasOwnProperty(worst) ? SEV_COLOR[worst] : SEV_COLOR.UNKNOWN;
    return '<span class="sx-tree-vuln" style="color:' + color + '" title="' + esc(worst) + ' \u00B7 ' + vc +
      ' known issue(s)"><i style="background:' + color + '"></i>' + vc + '</span>';
  }

  /* licenses pane */
  function paneLicenses() {
    var lv = (R.license_verification && typeof R.license_verification === 'object') ? R.license_verification : {};
    var ls = (lv.summary && typeof lv.summary === 'object') ? lv.summary : {};
    var chips = licChip('OK', ls.ok, '#2f9e44') + licChip('Deprecated', ls.deprecated, SEV_COLOR.MEDIUM) +
      licChip('Invalid', ls.invalid, SEV_COLOR.HIGH) + licChip('No license', ls.none, SEV_COLOR.UNKNOWN);
    var lic = (R.licenses && typeof R.licenses === 'object') ? R.licenses : {};
    var cc = (lic.summary && typeof lic.summary === 'object') ? lic.summary.category_counts : null;
    var catChips = (cc && typeof cc === 'object') ? Object.keys(cc).map(function (k) {
      return '<span class="sx-lic-cat">' + esc(k) + ': <b>' + esc(cc[k]) + '</b></span>';
    }).join('') : '';
    var sl = (R.source_licenses && typeof R.source_licenses === 'object') ? R.source_licenses : {};
    var sll = Array.isArray(sl.licenses) ? sl.licenses : [];
    var ev = Array.isArray(sl.findings) ? sl.findings : [];
    var cps = Array.isArray(sl.copyrights) ? sl.copyrights : [];
    var notes = Array.isArray(sl.notes) ? sl.notes : [];
    var polNote = (typeof sl.policy === 'string' && sl.policy) ? '<div class="sx-note">License policy in effect: ' + esc(sl.policy) + '</div>' : '';
    var policyHtml = licPolicyHtml(sl);
    var srcHtml = '<div style="font-size:12px;font-weight:700;margin:14px 0 8px">Source-file licenses' +
      '<span style="font-weight:400;color:var(--sx-text-muted,#555463);font-size:11px;margin-left:6px">detected in ' +
      esc(numv(sl.files_scanned) === null ? '0' : String(numv(sl.files_scanned))) + ' files \u2014 evidence-grounded (SPDX tags + license notice text), not registry metadata</span></div>';
    if (sll.length) {
      srcHtml += '<div class="sx-table-wrap"><table class="sx-table"><thead><tr><th>License</th><th>Category</th><th>Files</th><th>Confidence</th></tr></thead><tbody>' +
        sll.slice(0, 60).map(function (e2) {
          return '<tr><td><b>' + esc(txt(e2 && e2.license)) + '</b></td><td>' + esc(txt(e2 && e2.category)) + '</td><td>' +
            esc(txt(e2 && e2.count)) + '</td><td>' + esc(txt(e2 && e2.best_confidence)) + '</td></tr>';
        }).join('') + '</tbody></table></div>';
      if (ev.length) {
        srcHtml += '<details style="margin:6px 0"><summary style="cursor:pointer;font-size:11.5px;color:#555463">Evidence \u2014 file:line (' + ev.length + ')</summary>' +
          '<ul style="margin:4px 0 0 16px;padding:0;font-size:11px;line-height:1.6">' +
          ev.slice(0, 20).map(function (fe) {
            return '<li><code>' + esc(txt(fe && fe.file)) + ':' + esc(txt(fe && fe.line)) + '</code> \u2014 <b>' + esc(txt(fe && fe.license)) + '</b> <span style="color:#7e838c">(' + esc(txt(fe && fe.kind)) + ', ' + esc(txt(fe && fe.confidence)) + ')</span></li>';
          }).join('') + '</ul></details>';
      }
      if (cps.length) {
        srcHtml += '<details style="margin:4px 0"><summary style="cursor:pointer;font-size:11.5px;color:#555463">Copyright holders (' + cps.length + ')</summary>' +
          '<ul style="margin:4px 0 0 16px;padding:0;font-size:11px;line-height:1.6">' +
          cps.slice(0, 15).map(function (c) {
            return '<li>' + esc(txt(c && c.holder)) + ' \u2014 <code>' + esc(txt(c && c.file)) + ':' + esc(txt(c && c.line)) + '</code></li>';
          }).join('') + '</ul></details>';
      }
    } else {
      srcHtml += '<div class="sx-empty">No license text or SPDX tag detected in the scanned files (reported honestly \u2014 not treated as \u201Cno obligations\u201D).</div>';
    }
    notes.forEach(function (n) { srcHtml += '<div class="sx-note">' + esc(txt(n)) + '</div>'; });
    if (!chips && !catChips && !sll.length && !ev.length && !cps.length && !notes.length &&
        !policyHtml && !polNote && numv(sl.files_scanned) === null) {
      return '<div class="sx-empty">No license information available in this report.</div>';
    }
    return polNote + policyHtml + '<div class="sx-lic-chips">' + chips + '</div>' +
      (catChips ? '<div class="sx-lic-cats">' + catChips + '</div>' : '') + srcHtml;
  }

  function licChip(label, n, color) {
    var v = numv(n);
    return v === null ? '' : '<span class="sx-lic-chip" style="border-color:' + color + ';color:' + color + '">' +
      esc(label) + ': <b>' + v + '</b></span>';
  }

  // License policy violations: unstructured finding objects -> escaped table (max 6 columns).
  function licPolicyHtml(sl) {
    var pf = Array.isArray(sl.policy_findings)
      ? sl.policy_findings.filter(function (x) { return x && typeof x === 'object'; }) : [];
    if (!pf.length) return '';
    var keys = [], seen = {};
    pf.forEach(function (it) {
      Object.keys(it).forEach(function (k) {
        if (!seen[k] && keys.length < 6) { seen[k] = 1; keys.push(k); }
      });
    });
    if (!keys.length) return '';
    var rows = pf.slice(0, 60).map(function (it) {
      return '<tr>' + keys.map(function (k) { return '<td>' + policyCell(it[k]) + '</td>'; }).join('') + '</tr>';
    }).join('');
    return '<div class="sx-lic-policy"><h3 class="sx-lic-policy-h">\u26A0 License policy violations (' + pf.length + ')</h3>' +
      '<div class="sx-table-wrap"><table class="sx-table"><thead><tr>' +
      keys.map(function (k) { return '<th>' + esc(k) + '</th>'; }).join('') +
      '</tr></thead><tbody>' + rows + '</tbody></table></div></div>';
  }

  function policyCell(v) {
    if (v === null || v === undefined || v === '') return '\u2014';
    if (typeof v === 'object') {
      try { return '<code>' + esc(trunc(JSON.stringify(v), 80)) + '</code>'; } catch (e) { return '\u2014'; }
    }
    return esc(txt(v));
  }

  /* history pane */
  function paneHistory() {
    var canRun = typeof O.runTool === 'function';
    var canRetest = typeof O.retest === 'function';
    var canDiff = typeof O.scanDiff === 'function';
    var hist = [];
    if (typeof O.history === 'function') {
      try {
        var h = O.history();
        if (Array.isArray(h)) hist = h;
        else console.warn('[ScaApp] opts.history() did not return an array \u2014 ignoring');
      } catch (e) { console.warn('[ScaApp] opts.history() threw', e); }
    }
    var body;
    if (!hist.length) {
      body = '<div class="sx-empty">No scan history yet \u2014 run a test to build history.</div>';
    } else {
      body = hist.map(function (h) {
        if (!h || typeof h !== 'object') return '';
        var parts = [['critical', 'CRITICAL'], ['high', 'HIGH'], ['medium', 'MEDIUM'], ['low', 'LOW']]
          .filter(function (pr) { return (numv(h[pr[0]]) || 0) > 0; })
          .map(function (pr) { return '<b style="color:' + SEV_COLOR[pr[1]] + '">' + numv(h[pr[0]]) + ' ' + pr[1] + '</b>'; });
        var tot = numv(h.total);
        var counts = (tot !== null ? '<b>' + tot + '</b> total' + (parts.length ? ' \u00B7 ' : '') : '') + parts.join(' \u00B7 ');
        return '<div class="sx-history-row"><span class="sx-history-label">' + esc(txt(h.label) || '(unlabeled scan)') + '</span>' +
          '<span class="sx-history-counts">' + (counts || '\u2014') + '</span>' +
          '<span class="sx-history-ts">' + esc(fmtTs(h.ts)) + '</span>' +
          '<button type="button" class="sx-btn-ghost sx-btn-sm" data-sx-retest="' + escAttr(txt(h.label)) + '"' +
          (canRetest ? ' title="Re-scan this target"' : ' disabled title="Unavailable \u2014 no retest handler provided"') +
          '>\u21BB Retest' + (canRetest ? '' : skipTag()) + '</button></div>';
      }).join('');
    }
    return '<div class="sx-history-actions">' + toolBtn('vulnTrend', '\uD83D\uDCC8 Vulnerability trend', canRun) +
      toolBtn('vulnAge', '\uD83D\uDCC8 Age', canRun) +
      '<button type="button" class="sx-btn-ghost" data-sx-scandiff' +
      (canDiff ? ' title="Compare the two most recent scans"' : ' disabled title="Unavailable \u2014 no scan-diff handler provided"') +
      '>\u21C4 Compare last 2' + (canDiff ? '' : skipTag()) + '</button></div>' +
      '<div class="sx-history-list">' + body + '</div>' +
      '<div class="sx-tool-out sx-scan-out" data-sx-scanout>Run \u201CCompare last 2\u201D to compare the two most recent scans.</div>';
  }

  function runRetest(btn) {
    if (btn.disabled || typeof O.retest !== 'function') return;
    var label = txt(btn.getAttribute('data-sx-retest'));
    var out = mount ? mount.querySelector('[data-sx-scanout]') : null;
    var ok;
    try { ok = O.retest(label); }
    catch (e) { ok = false; console.warn('[ScaApp] opts.retest threw', e); }
    // true: the glue takes over (re-scan + re-render). Any other result stays honest.
    if (ok !== true && out) {
      out.innerHTML = '<div class="sx-note sx-note-err">Retest could not be started for \u201C' + esc(label) +
        '\u201D \u2014 the backend refused the request.</div>';
    }
  }

  function runScanDiff() {
    if (typeof O.scanDiff !== 'function') return;
    var out = mount ? mount.querySelector('[data-sx-scanout]') : null;
    if (!out) return;
    out.innerHTML = '<div class="sx-note">Comparing the two most recent scans\u2026</div>';
    var res;
    try { res = O.scanDiff(); }
    catch (e) { out.innerHTML = '<div class="sx-note sx-note-err">Scan comparison failed: ' + esc(errMsg(e)) + '</div>'; return; }
    if (res && typeof res.then === 'function') {
      res.then(function (r) { renderScanDiff(r, out); }, function (e) {
        out.innerHTML = '<div class="sx-note sx-note-err">Scan comparison failed: ' + esc(errMsg(e)) + '</div>';
      });
    } else renderScanDiff(res, out);
  }

  function renderScanDiff(r, out) {
    if (!r || typeof r !== 'object') {
      out.innerHTML = '<div class="sx-note sx-note-err">Scan comparison returned no result.</div>';
      return;
    }
    if (r.ok === false) {
      out.innerHTML = '<div class="sx-note sx-note-err">' +
        esc(txt(r.message) || txt(r.error) || txt(r.note) || 'Scan comparison is not available for these scans.') + '</div>';
      return;
    }
    var nc = Array.isArray(r.new_cves) ? r.new_cves : [];
    var rc = Array.isArray(r.resolved_cves) ? r.resolved_cves : [];
    var np = Array.isArray(r.new_pkgs) ? r.new_pkgs : [];
    var rp = Array.isArray(r.removed_pkgs) ? r.removed_pkgs : [];
    var items = [['New CVEs', nc.length, '#fb2c36'], ['Resolved', rc.length, '#2f9e44'],
      ['New packages', np.length, '#ff8904'], ['Removed', rp.length, '#7e838c']];
    var s = '<div class="sx-sdiff">' + items.map(function (it) {
      return '<span class="sx-sdiff-item"><b class="sx-sdiff-n" style="color:' + it[2] + '">' + it[1] +
        '</b><span class="sx-sdiff-l">' + it[0] + '</span></span>';
    }).join('') + '</div>';
    var nh = numv(r.new_high);
    if (nh !== null && nh > 0) s += '<div class="sx-note sx-note-err">\u26A0 ' + nh + ' new high-severity issue(s) since the previous scan.</div>';
    if (txt(r.note)) s += '<div class="sx-note">' + esc(r.note) + '</div>';
    out.innerHTML = s;
  }

  /* tools pane */
  function paneTools() {
    var hasProxy = typeof O.proxy === 'function', hasRun = typeof O.runTool === 'function';
    function pbtn(id, label) {
      return '<button type="button" class="sx-btn" data-sx-proxy="' + id + '"' +
        (hasProxy ? '' : ' disabled title="Unavailable \u2014 no proxy handler provided"') + '>' +
        label + (hasProxy ? '' : skipTag()) + '</button>';
    }
    return '<div class="sx-tool-grid">' +
      '<div class="sx-tool-group"><h4 class="sx-tool-group-h">Downloads</h4>' + pbtn('dlXlsx', '\u2B07 Excel') +
      pbtn('dlReport', '\u2B07 Report') +
      '<span class="sx-tool-sbom"><select class="sx-select" data-sx-sbomsel>' +
        '<option value="cdx">CycloneDX JSON</option><option value="spdx">SPDX JSON</option>' +
        '<option value="tv">SPDX TV</option></select>' + pbtn('dlSbomFmt', '\u2B07 SBOM') + '</span></div>' +
      '<div class="sx-tool-group"><h4 class="sx-tool-group-h">Analysis</h4>' +
      toolBtn('checkUpdates', '\u21BB Check Updates', hasRun) +
      toolBtn('vulnTrend', '\uD83D\uDCC8 Vulnerability trend', hasRun) +
      toolBtn('vulnAge', '\uD83D\uDCC8 Age', hasRun) + '</div>' +
      advisoryGroupHtml() + '</div>' +
      '<div class="sx-tool-out" id="sxToolOut">' + TOOL_OUT_EMPTY + '</div>';
  }

  function toolBtn(name, label, enabled) {
    return '<button type="button" class="sx-btn-ghost" data-sx-tool="' + escAttr(name) + '"' +
      (enabled ? '' : ' disabled title="Unavailable \u2014 no tool runner provided"') + '>' + label + (enabled ? '' : skipTag()) + '</button>';
  }
  function skipTag() { return ' <span class="sx-skip">skip</span>'; }

  function advisoryGroupHtml() {
    var has = typeof O.advisory === 'function';
    var opts = ADV_ECOSYSTEMS.map(function (e) {
      return '<option value="' + escAttr(e) + '">' + (e ? esc(e) : 'All ecosystems') + '</option>';
    }).join('');
    return '<div class="sx-tool-group"><h4 class="sx-tool-group-h">Advisory lookup</h4>' +
      '<input class="sx-input" data-sx-advq placeholder="CVE-2024-1234, GHSA-\u2026 or name@version" />' +
      '<select class="sx-select" data-sx-adveco>' + opts + '</select>' +
      '<button type="button" class="sx-btn" data-sx-adv' +
      (has ? '' : ' disabled title="Unavailable \u2014 no advisory handler provided"') + '>Lookup' + (has ? '' : skipTag()) + '</button>' +
      '<span class="sx-tool-hint">Unavailable in a local install: notifications, SCM fix PRs, team/org management.</span></div>';
  }

  function runAdvisory(btn) {
    if (typeof O.advisory !== 'function') return;
    var scope = closest(btn, '.sx-tool-group');
    var qEl = scope ? scope.querySelector('[data-sx-advq]') : null;
    var ecoEl = scope ? scope.querySelector('[data-sx-adveco]') : null;
    var q = qEl ? txt(qEl.value).trim() : '';
    if (!q) {
      setToolOutput('<div class="sx-note sx-note-err">Enter a CVE/GHSA id or package name to look up.</div>');
      if (qEl) qEl.focus();
      return;
    }
    var eco = ecoEl ? txt(ecoEl.value) : '';
    setToolOutput('<div class="sx-note">Looking up \u201C' + esc(q) + '\u201D\u2026</div>');
    var res;
    try { res = O.advisory(q, eco); }
    catch (e) { setToolOutput('<div class="sx-note sx-note-err">Advisory lookup failed: ' + esc(errMsg(e)) + '</div>'); return; }
    if (res && typeof res.then === 'function') {
      res.then(renderAdvisoryOut, function (e) {
        setToolOutput('<div class="sx-note sx-note-err">Advisory lookup failed: ' + esc(errMsg(e)) + '</div>');
      });
    } else renderAdvisoryOut(res);
  }

  // Advisory result: ok:false -> verbatim note/error; single advisory -> defensive field
  // table; list -> count + id/summary rows. Unknown shapes stay honest.
  function renderAdvisoryOut(r) {
    if (!r || typeof r !== 'object') {
      setToolOutput('<div class="sx-note sx-note-err">Advisory lookup returned no result.</div>');
      return;
    }
    if (r.ok === false) {
      setToolOutput('<div class="sx-note sx-note-err">' +
        esc(txt(r.error) || txt(r.note) || txt(r.message) || 'Advisory lookup is unavailable.') + '</div>');
      return;
    }
    var srcLine = txt(r.source) ? ' \u00B7 source: ' + esc(r.source) : '';
    if (Array.isArray(r.advisories)) {
      var list = r.advisories.filter(function (a) { return a && typeof a === 'object'; });
      var cnt = numv(r.count);
      var head = '<div class="sx-note">' + (cnt === null ? list.length : cnt) + ' advisories found' + srcLine + '</div>';
      if (!list.length) { setToolOutput(head + '<div class="sx-note">The result contained no advisory entries.</div>'); return; }
      var rows = list.slice(0, 40).map(function (a) {
        var id = txt(a.id || a.identifier || a.cve || a.name) || '(no id)';
        var sum = trunc(txt(a.summary || a.title || a.details || a.description), 160);
        return '<tr><td><b>' + esc(id) + '</b></td><td>' + (sum ? esc(sum) : '\u2014') + '</td></tr>';
      }).join('');
      setToolOutput(head + '<table><thead><tr><th>ID</th><th>Summary</th></tr></thead><tbody>' + rows + '</tbody></table>');
      return;
    }
    var a = (r.advisory && typeof r.advisory === 'object') ? r.advisory : null;
    if (!a) {
      setToolOutput('<div class="sx-note">' + (txt(r.note) ? esc(r.note) : 'The lookup succeeded but returned no advisory object.') + srcLine + '</div>');
      return;
    }
    var out = '<div class="sx-note">Advisory' + srcLine + '</div><table><tbody>';
    ADV_FIELDS.forEach(function (fd) {
      var v = a[fd[0]];
      if (v === null || v === undefined || v === '') return;
      var cell;
      if (Array.isArray(v)) {
        cell = v.map(function (x) {
          if (x === null || x === undefined) return '';
          if (typeof x === 'object') { try { return esc(trunc(JSON.stringify(x), 80)); } catch (e2) { return ''; } }
          return esc(txt(x));
        }).filter(Boolean).join(', ');
        if (!cell) return;
      } else if (typeof v === 'object') {
        try { cell = esc(trunc(JSON.stringify(v), 160)); } catch (e2) { return; }
      } else cell = esc(txt(v));
      out += '<tr><th>' + esc(fd[1]) + '</th><td>' + cell + '</td></tr>';
    });
    out += '</tbody></table>';
    setToolOutput(out);
  }

  /* rendering entry points */
  function render(mountEl, reportObj, userOpts) {
    if (!mountEl || typeof mountEl.appendChild !== 'function') {
      console.warn('[ScaApp] render() requires a mount element');
      return;
    }
    mount = mountEl;
    R = (reportObj && typeof reportObj === 'object') ? reportObj : {};
    O = (userOpts && typeof userOpts === 'object') ? userOpts : {};
    activeTab = 'overview';
    F = { search: '', sev: { CRITICAL: true, HIGH: true, MEDIUM: true, LOW: true, UNKNOWN: true }, fixOnly: false, kevOnly: false, reachOnly: false, showIgnored: false };
    DF = { search: '', type: 'all' };
    depView = 'table';
    triageCache = null;
    openMap = {};
    remapCache = null;
    if (typeof O.triageCached === 'function') {
      try {
        var tc = O.triageCached();
        if (tc && typeof tc === 'object') triageCache = tc;
        else console.warn('[ScaApp] opts.triageCached() did not return an object \u2014 ignoring');
      } catch (e) { console.warn('[ScaApp] opts.triageCached() threw', e); }
    }
    mount.innerHTML = html(sevCounts());
    applyTab();
    bindEvents();
    if (pendingToolOut !== null) {
      var box = mount.querySelector('#sxToolOut');
      if (box) { fillToolBox(box, pendingToolOut); pendingToolOut = null; }
    }
  }

  // Toggle tab buttons + pane visibility. Inline display keeps this robust even
  // if the stylesheet has no pane-active rule; .sx-on is a bonus hook for CSS.
  function applyTab() {
    if (!mount) return;
    var tabs = mount.querySelectorAll('.sx-tab');
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].classList.toggle('on', tabs[i].getAttribute('data-sx-tab') === activeTab);
    }
    var panes = mount.querySelectorAll('.sx-pane');
    for (var j = 0; j < panes.length; j++) {
      var on = panes[j].getAttribute('data-sx-pane') === activeTab;
      panes[j].classList.toggle('sx-on', on);
      panes[j].style.display = on ? '' : 'none';
    }
  }

  function switchTab(name) {
    if (TABS.indexOf(name) === -1) return;
    activeTab = name;
    applyTab();
  }

  // Partial re-render: only the issue list region (filter rail untouched).
  function renderIssueList() {
    if (!mount) return;
    var box = mount.querySelector('[data-sx-issuelist]');
    if (box) box.innerHTML = issueListHtml();
    updateIssueTabCount();
  }

  // Keep the Issues tab count in sync with the ignored filter.
  function updateIssueTabCount() {
    if (!mount) return;
    var tab = mount.querySelector('[data-sx-tab="issues"]');
    if (tab) tab.textContent = 'Issues (' + issueTabCount(sevCounts()) + ')';
  }

  // Partial re-render: only the dependency body region (toolbar untouched).
  function renderDepsView() {
    if (!mount) return;
    var box = mount.querySelector('[data-sx-depbody]');
    if (box) box.innerHTML = depsBodyHtml();
    syncDepFilters();
  }

  // The package filters only apply to the Table view — hide them in Tree view (honest UI).
  function syncDepFilters() {
    if (!mount) return;
    var fl = mount.querySelector('[data-sx-depfilters]');
    if (fl) fl.style.display = depView === 'tree' ? 'none' : '';
  }

  function syncDepToggle() {
    if (!mount) return;
    var btns = mount.querySelectorAll('[data-sx-depview]');
    for (var i = 0; i < btns.length; i++) {
      btns[i].classList.toggle('on', btns[i].getAttribute('data-sx-depview') === depView);
    }
  }

  /* callback bridges (honest degradation) */
  function callProxy(btnId) {
    if (typeof O.proxy !== 'function') {
      console.warn('[ScaApp] opts.proxy not provided \u2014 "' + btnId + '" click ignored');
      return;
    }
    try { O.proxy(btnId); } catch (e) { console.warn('[ScaApp] opts.proxy("' + btnId + '") threw', e); }
  }
  function callRunTool(name) {
    if (typeof O.runTool !== 'function') {
      console.warn('[ScaApp] opts.runTool not provided \u2014 "' + name + '" ignored');
      return;
    }
    try { O.runTool(name); } catch (e) { console.warn('[ScaApp] opts.runTool("' + name + '") threw', e); }
  }
  function callSetMode(mode) {
    if (typeof O.setMode !== 'function') {
      console.warn('[ScaApp] opts.setMode not provided \u2014 cannot switch to "' + mode + '"');
      return;
    }
    try { O.setMode(mode); } catch (e) { console.warn('[ScaApp] opts.setMode threw', e); }
  }

  /* events (delegated on mountEl; bound once per element) */
  function bindEvents() {
    if (!mount || mount.__scaAppBound) return;
    mount.__scaAppBound = true;
    mount.addEventListener('click', onClick);
    mount.addEventListener('change', onChange);
    mount.addEventListener('input', onInput);
    mount.addEventListener('keydown', onKeydown);
  }

  function onClick(e) {
    var el;
    if ((el = closest(e.target, '[data-sx-proxy]'))) {
      if (el.disabled) return;
      var btnId = el.getAttribute('data-sx-proxy');
      if (btnId === 'dlSbomFmt') syncSbomSel(el);
      callProxy(btnId);
      return;
    }
    if ((el = closest(e.target, '[data-sx-classic]'))) { callSetMode('classic'); return; }
    if ((el = closest(e.target, '[data-sx-nav]'))) { onNav(el); return; }
    if ((el = closest(e.target, '[data-sx-tab]'))) { switchTab(el.getAttribute('data-sx-tab')); return; }
    if ((el = closest(e.target, '[data-sx-depview]'))) {
      var dv = el.getAttribute('data-sx-depview');
      if ((dv === 'table' || dv === 'tree') && depView !== dv) { depView = dv; syncDepToggle(); renderDepsView(); }
      return;
    }
    if ((el = closest(e.target, '[data-sx-tri-apply]'))) { applyTriage(el); return; }
    if ((el = closest(e.target, '[data-sx-retest]'))) { runRetest(el); return; }
    if ((el = closest(e.target, '[data-sx-scandiff]'))) { runScanDiff(); return; }
    if ((el = closest(e.target, '[data-sx-adv]'))) { runAdvisory(el); return; }
    if ((el = closest(e.target, '.sx-issue-h'))) {
      var issue = closest(el, '.sx-issue');
      if (issue) {
        issue.classList.toggle('open');
        el.setAttribute('aria-expanded', issue.classList.contains('open') ? 'true' : 'false');
        var k = issue.getAttribute('data-sx-issue');
        if (k) openMap[k] = issue.classList.contains('open');
      }
      return;
    }
    if ((el = closest(e.target, '[data-sx-sevjump]'))) { switchTab('issues'); return; }
  }

  // Tools-tab SBOM button: copy its sibling select's value into the topbar
  // select (#sxSbomFmt) so the glue's proxy handler reads the right format.
  function syncSbomSel(btn) {
    var scope = closest(btn, '.sx-tool-sbom');
    if (!scope) return;
    var sel = scope.querySelector('[data-sx-sbomsel]');
    var top = mount ? mount.querySelector('#sxSbomFmt') : null;
    if (sel && top) top.value = sel.value;
  }

  function onNav(btn) {
    var nav = btn.getAttribute('data-sx-nav');
    var items = mount.querySelectorAll('.sx-nav-item');
    for (var i = 0; i < items.length; i++) items[i].classList.remove('on');
    btn.classList.add('on');
    if (nav === 'settings') { callSetMode('classic'); return; }
    var tab = NAV_TO_TAB[nav];
    if (tab) switchTab(tab);
  }

  function onChange(e) {
    var el;
    if ((el = closest(e.target, '[data-sx-sev]'))) {
      var sv = el.getAttribute('data-sx-sev');
      if (F.sev.hasOwnProperty(sv)) { F.sev[sv] = !!el.checked; renderIssueList(); }
      return;
    }
    if ((el = closest(e.target, '[data-sx-flag]'))) {
      var flag = el.getAttribute('data-sx-flag');
      if (flag === 'fix') F.fixOnly = !!el.checked;
      else if (flag === 'kev') F.kevOnly = !!el.checked;
      else if (flag === 'reach') F.reachOnly = !!el.checked;
      else if (flag === 'ignored') F.showIgnored = !!el.checked;
      renderIssueList();
      return;
    }
    if ((el = closest(e.target, '[data-sx-deptype]'))) {
      DF.type = txt(el.value).toLowerCase() || 'all';
      renderDepsView();
    }
  }

  function onInput(e) {
    var el;
    if ((el = closest(e.target, '[data-sx-filter="search"]'))) { F.search = txt(el.value); renderIssueList(); return; }
    if ((el = closest(e.target, '[data-sx-depsearch]'))) { DF.search = txt(el.value); renderDepsView(); }
  }

  // Enter inside the advisory query box triggers Lookup.
  function onKeydown(e) {
    if (!e || e.key !== 'Enter' || !closest(e.target, '[data-sx-advq]')) return;
    e.preventDefault();
    var group = closest(e.target, '.sx-tool-group');
    var btn = group ? group.querySelector('[data-sx-adv]') : null;
    if (btn && !btn.disabled) runAdvisory(btn);
  }

  /* tools output API */
  function fillToolBox(box, v) {
    if (v && typeof v === 'object' && v.nodeType === 1) { box.innerHTML = ''; box.appendChild(v); }
    else box.innerHTML = String(v === null || v === undefined ? '' : v);
  }

  function setToolOutput(htmlOrNode) {
    var box = mount ? mount.querySelector('#sxToolOut') : null;
    if (!box) { pendingToolOut = htmlOrNode; return; } // buffered until next render()
    fillToolBox(box, htmlOrNode);
  }

  function notify(label) {
    setToolOutput('<div class="sx-note">' + esc(label) + ' \u2014 running\u2026</div>');
  }

  /* export (single global) */
  window.ScaApp = { render: render, setToolOutput: setToolOutput, notify: notify, version: '1.1.0' };

})();

/* changelog 1.1.0 — priority score ring (0-1000, P0..P4 colors) + P-level chip + factor
 * breakdown bars (CVSS 30 / exploit 25 / reach 20 / fix 10 / KEV 15); exploit maturity
 * chip (KEV / EPSS >= 0.5 / EPSS observed / none — replaces the bare KEV chip); issue
 * triage (ignore) with cached state, gray banner, in-card form and honest failure
 * messages, "Show ignored" filter reflected in the tab count; Dependencies table/tree
 * toggle with recursive tree view; History per-target Retest + "Compare last 2" scan
 * diff output; Licenses policy-violation table + policy note; Tools advisory lookup
 * group (query + ecosystem + result table) with an honest local-install note. */
