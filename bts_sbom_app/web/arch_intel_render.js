/*!
 * arch_intel_render.js - pure renderers for the "Arch Intel" pane (license verdict + AI architecture deep-dive).
 * Written for BTS-SBOM (not one of the six copied platform files, see NOTICE.md).
 *
 * Everything here is a pure function of the JSON the service returned (no DOM, no network), so it runs unchanged
 * under Node for the tests; arch_intel.js fetches the data, puts the markup on the page and renders the Mermaid
 * diagrams. Rules, as everywhere on this screen:
 *  - every value from analysed data goes through BtsUi.esc() (cell()/kv()/table() do it for table cells);
 *  - the ONLY unescaped HTML is the server-side highlighted code (arch_intel.highlight escapes every character
 *    before wrapping tokens) and the diagram placeholders built here from escaped parts;
 *  - absent data is an em dash (BtsUi.val), never a default 0; each diagram keeps its Mermaid source in a hidden
 *    <pre class="arc-mermaid-src"> so the pane still shows something when the renderer cannot load;
 *  - the license card says this is evidence, not a legal assessment.
 */
(function (root, factory) {
  var isNode = typeof module === 'object' && module.exports;
  var api = factory(isNode ? require('./bts_ui.js') : root.BtsUi);
  if (isNode) { module.exports = api; }
  if (root) { root.ArchIntelRender = api; }
})(typeof window !== 'undefined' ? window : null, function (U) {
  'use strict';

  var esc = U.esc, H = U.H, val = U.val, note = U.note, heading = U.heading, table = U.table, pill = U.pill, kv = U.kv;

  var CATEGORY = {
    'permissive': { label: 'Permissive', pill: 'ok' },
    'public-domain': { label: 'Public domain', pill: 'ok' },
    'weak-copyleft': { label: 'Weak copyleft', pill: 'warn' },
    'strong-copyleft': { label: 'Strong copyleft (GPL)', pill: 'warn' },
    'network-copyleft': { label: 'Network copyleft (AGPL/SSPL)', pill: 'bad' },
    'restricted': { label: 'Restricted', pill: 'bad' },
    'unknown': { label: 'Unknown', pill: 'muted' }
  };
  var COMPAT_PILL = { compatible: 'ok', conditional: 'warn', incompatible: 'bad', unknown: 'muted' };
  var DIST_PILL = { ok: 'ok', review: 'warn', deny: 'bad' };
  var TABS = [
    ['verdict', 'License verdict'],
    ['overview', 'Overview'],
    ['components', 'Components'],
    ['sequence', 'Sequence'],
    ['activity', 'Activity'],
    ['code', 'Live code'],
    ['notice', 'Notice']
  ];

  function obj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
  function list(v) { return Array.isArray(v) ? v : []; }
  function cat(c) { return obj(CATEGORY[String(c)]); }

  /* ---------- diagram placeholder: wiring reads the hidden pre and renders the sibling div ---------- */
  function diagramBlock(src, emptyNote) {
    if (!src) { return note(esc(emptyNote || 'No diagram for this item.'), 'warn'); }
    return '<div class="arc-dwrap"><div class="arc-diagram" data-arc-diagram></div>' +
      '<pre class="arc-mermaid-src" hidden>' + esc(src) + '</pre></div>';
  }

  /* ---------- tabs ---------- */
  function nav(active) {
    return '<div class="arc-tabs">' + TABS.map(function (t) {
      return '<button type="button" class="arc-tab' + (t[0] === active ? ' on' : '') + '" data-arc-tab="' + t[0] + '">' + esc(t[1]) + '</button>';
    }).join('') + '</div>';
  }

  /* ---------- license verdict ---------- */
  function licenseVerdict(license) {
    var d = obj(license);
    var c = cat(d.category);
    var src = d.project_license_source || '';
    var obligations = list(d.obligations);
    var nv = obj(d.notice);
    var cm = obj(d.compat);
    var rows = list(cm.rows);
    var verdicts = list(nv.verdicts);
    var out = heading('License verdict', 'detected from the source tree');
    out += '<div class="bts-cards">' +
      '<div class="bts-card"><div class="v">' + pill(d.project_license || 'unknown', c.pill || 'muted').html + '</div><div class="l">' + esc(c.label || 'Unknown') + '</div></div>' +
      '<div class="bts-card"><div class="v">' + esc(val(d.project_license)) + '</div><div class="l">SPDX expression' + (src ? ' (' + esc(src) + ')' : '') + '</div></div>' +
      '</div>';
    if (obligations.length) {
      out += note('<b>Obligations:</b> ' + obligations.map(function (o) { return esc(o); }).join(' · '));
    }
    if (verdicts.length) {
      out += table(['If you', 'Verdict', 'Why'], verdicts.map(function (v) {
        return [v.distribution, pill(String(v.verdict || 'review'), DIST_PILL[v.verdict] || 'muted'), v.why || '—'];
      }), 'No distribution verdicts.');
    }
    if (rows.length) {
      out += heading('Compatibility matrix', 'pairwise verdicts against common product licenses');
      out += table(['This package', 'Your product license', 'Verdict', 'Why'], rows.map(function (r) {
        return [r.their, r.your, pill(String(r.status), COMPAT_PILL[r.status] || 'muted'), r.reason || '—'];
      }), 'No compatibility rows.');
    } else if (cm.note) {
      out += note('<b>Compatibility:</b> ' + esc(cm.note), 'warn');
    }
    if (list(d.license_files).length) {
      out += table(['License file', 'Detected license'], list(d.license_files).slice(0, 12).map(function (f) {
        return [f.file, f.detected ? pill(String(f.license || '?'), 'pass') : H('<span class="bts-muted">not detected</span>')];
      }), 'No license files.');
    }
    out += note('<b>Evidence, not a legal assessment.</b> Confirm against the official license text before you ship.', 'warn');
    return out;
  }

  /* ---------- notice checklist (GPL/AGPL clauses + clean-room guidance) ---------- */
  function notice(license) {
    var d = obj(license);
    var nv = obj(d.notice);
    var cl = list(nv.checklist);
    var out = heading('Notice checklist', 'what this license demands when the code ships');
    if (cl.length) {
      out += table(['Clause', 'Requirement'], cl.map(function (c) {
        return [pill(String(c.clause || '—'), nv.network_clause && String(c.clause).indexOf('13') >= 0 ? 'bad' : 'pass'), c.req || '—'];
      }), 'No checklist items.');
    }
    if (nv.network_clause) {
      out += note('<b>AGPL §13 is live.</b> If this code (or a modified derivative) runs behind a network service, ' +
        'every network user can demand the corresponding source — distributing nothing is not enough.', 'bad');
    }
    var verdicts = list(nv.verdicts);
    if (verdicts.length) {
      out += heading('Distribution verdicts', 'per usage mode');
      out += table(['Mode', 'Verdict', 'Why'], verdicts.map(function (v) {
        return [v.distribution, pill(String(v.verdict || 'review'), DIST_PILL[v.verdict] || 'muted'), v.why || '—'];
      }), 'No distribution verdicts.');
    }
    out += heading('Clean-room guidance', 'if you plan to reimplement, not to reuse');
    out += note('<b>Architecture facts on this screen are ideas — ideas are not copyrighted.</b> The code excerpts are ' +
      'expressions of the original work under ' + esc(d.project_license || 'the detected license') + ': keep them inside this tool. ' +
      'A reimplementation should be written from a specification (behaviour, interfaces, formats) — never from the ' +
      'excerpts or from decompiler output — and the process documented. Redistributing this screen\'s report or the ' +
      'excerpts triggers the license\'s obligations.', 'warn');
    if (nv.note) { out += note(esc(nv.note)); }
    return out;
  }

  /* ---------- overview (static view) ---------- */
  function overview(structure, meta) {
    var st = obj(structure);
    var stack = obj(st.stack);
    var languages = obj(stack.languages);
    var g = obj(st.graph);
    var entries = list(st.entry_points);
    var hot = list(st.hotspots);
    var eol = list(st.runtime_eol);
    var out = heading('Architecture overview', 'deterministic facts (never executed, nothing inferred here)');
    var eolCount = eol.filter(function (r) { return r.status === 'eol'; }).length;
    out += '<div class="bts-cards">' +
      '<div class="bts-card"><div class="v">' + esc(val(st.files_count)) + '</div><div class="l">files</div></div>' +
      '<div class="bts-card"><div class="v">' + esc(val(st.total_loc)) + '</div><div class="l">lines of code</div></div>' +
      '<div class="bts-card"><div class="v">' + esc(val(g.import_edges)) + '</div><div class="l">import edges</div></div>' +
      '<div class="bts-card"><div class="v">' + esc(val(g.cycle_count)) + '</div><div class="l">dependency cycles</div></div>' +
      '<div class="bts-card"><div class="v">' + esc(val(entries.length)) + '</div><div class="l">entry points</div></div>' +
      (eolCount ? '<div class="bts-card"><div class="v" style="color:var(--dcard-err)">' + eolCount + '</div><div class="l">runtimes past EOL</div></div>' : '') +
      '</div>';
    if (Object.keys(languages).length) {
      out += table(['Language', 'Files', 'LOC'], Object.keys(languages).map(function (k) {
        return [k, val(languages[k].files), val(languages[k].loc)];
      }), 'No language data.');
    }
    if (entries.length) {
      out += heading('Entry points', 'where execution can start (declared or content-detected)');
      out += table(['File', 'Kind', 'Note'], entries.map(function (e) {
        return [e.path, pill(String(e.kind || '?'), 'pass'), e.note || '—'];
      }), 'No entry points detected.');
    }
    if (hot.length) {
      out += heading('Hotspots', 'changed most often (git history)');
      out += table(['File', 'Commits', 'Score'], hot.slice(0, 8).map(function (h) {
        return [h.file, val(h.commits), val(h.score)];
      }), 'No hotspots.');
    }
    if (list(g.cycles).length) {
      out += heading('Dependency cycles', 'strongly connected components of the import graph');
      out += note(list(g.cycles).map(function (c) { return esc(list(c).join(' → ')); }).join('<br>') || '—', 'warn');
    }
    if (eol.length) {
      out += heading('Runtime EOL', 'endoflife.date, offline table when offline');
      out += table(['Runtime', 'Cycle', 'Status', 'EOL date'], eol.map(function (r) {
        return [r.product, r.cycle, r.status === 'eol' ? pill('eol', 'bad') : pill(String(r.status || '?'), 'muted'), val(r.eol)];
      }), 'No runtime data.');
    }
    if (list(st.notes).length) {
      out += note('<b>Measurement notes:</b> ' + list(st.notes).map(function (n) { return esc(n); }).join(' · '), 'warn');
    }
    if (meta && meta.ai_note) {
      out += note('<b>AI lane:</b> ' + esc(meta.ai_note));
    }
    return out;
  }

  /* ---------- components (AI) ---------- */
  function components(analysis, diagrams) {
    var an = obj(analysis);
    var dg = obj(diagrams);
    var comp = obj(dg.components);
    var items = list(an.components);
    var out = heading('Component diagram', an.overview ? undefined : 'no AI analysis available');
    if (an.overview) { out += note(esc(an.overview)); }
    out += diagramBlock(comp.mermaid, comp.note || 'No component diagram (the analysis found no components).');
    if (items.length) {
      out += table(['Component', 'Role', 'Files (verified in tree)'], items.map(function (c) {
        return [c.name, val(c.role), list(c.files).join(', ') || '—'];
      }), 'No components.');
    }
    if (list(an.scenarios).length === 0 && list(an.activity).length === 0) {
      out += note('<b>No AI scenario analysis.</b> ' + esc('Connect an EXAONE key (top bar) and re-run for scenario-level sequence and activity flows. The deterministic view above is measured, not invented.'), 'warn');
    }
    return out;
  }

  /* ---------- sequence diagrams (dynamic view, static inference) ---------- */
  function sequence(diagrams) {
    var items = list(obj(diagrams).sequence);
    var out = heading('Sequence diagrams', 'dynamic view — static inference, the tree was never executed');
    if (!items.length) {
      out += note('<b>Not computed.</b> Scenario-level sequence flows need the AI lane (an EXAONE key). ' +
        'Nothing is invented rather than shown.', 'warn');
      return out;
    }
    out += items.map(function (s, i) {
      var d = obj(s);
      var steps = list(d.steps);
      var inner = diagramBlock(d.mermaid, 'No diagram for this scenario.') +
        table(['#', 'Actor', 'Action', 'Target'], steps.map(function (st, j) {
          return [String(j + 1), st.actor, st.action, st.target];
        }), 'No steps.');
      return '<details class="arc-scenario"' + (i === 0 ? ' open' : '') + '><summary>' + esc(d.name || 'Scenario') +
        (d.inferred ? ' <span class="bts-pill muted">static inference</span>' : '') + '</summary>' + inner + '</details>';
    }).join('');
    return out;
  }

  /* ---------- activity flows ---------- */
  function activity(diagrams) {
    var items = list(obj(diagrams).activity);
    var out = heading('Activity diagrams', 'control flow — static inference, the tree was never executed');
    if (!items.length) {
      out += note('<b>Not computed.</b> Activity flows need the AI lane (an EXAONE key). Nothing is invented rather than shown.', 'warn');
      return out;
    }
    out += items.map(function (f, i) {
      var d = obj(f);
      var steps = list(d.steps);
      var inner = diagramBlock(d.mermaid, d.note || 'No diagram for this flow.') +
        (steps.length ? note(steps.map(function (s, j) { return (j + 1) + '. ' + esc(s); }).join('<br>')) : '');
      return '<details class="arc-scenario"' + (i === 0 ? ' open' : '') + '><summary>' + esc(d.name || 'Activity flow') +
        '</summary>' + inner + '</details>';
    }).join('');
    return out;
  }

  /* ---------- live code (excerpts) ---------- */
  function code(codeItems, projectLicense) {
    var items = list(codeItems);
    var out = heading('Live code', 'the architecture elements above, as they actually read');
    out += note('<b>These excerpts are the original work</b> (license: ' + esc(projectLicense || 'unknown') + '). ' +
      'They stay inside this analysis; copying them out or redistributing the report triggers the license\'s obligations. ' +
      'A reimplementation must be written from a specification, not from these excerpts (clean-room).', 'warn');
    if (!items.length) {
      out += note('No key files were selected (empty tree or unreadable files).');
      return out;
    }
    out += items.map(function (c) {
      var d = obj(c);
      var meta = esc(d.path) + ' · ' + esc(d.role || '') + ' · lines ' + esc(val(d.start_line)) + '–' + esc(val(d.end_line)) +
        ' of ' + esc(val(d.total_lines));
      return '<details class="arc-scenario"><summary>' + esc(d.path) + '</summary>' +
        '<div class="arc-codemeta">' + meta + '</div>' +
        '<pre class="arc-code">' + H(String(d.html || '')).html + '</pre>' +
        (d.truncated ? '<div class="bts-small">excerpt — open the file for the full text</div>' : '') +
        '</details>';
    }).join('');
    return out;
  }

  /* ---------- the whole result ---------- */
  function result(doc) {
    var d = obj(doc);
    var meta = obj(d.meta);
    var lic = obj(d.license);
    var an = obj(d.analysis);
    var secs = {
      verdict: licenseVerdict(lic),
      overview: overview(d.structure, { ai_note: d.ai_note }),
      components: components(an, d.diagrams),
      sequence: sequence(d.diagrams),
      activity: activity(d.diagrams),
      code: code(d.code, lic.project_license),
      notice: notice(lic)
    };
    var src = (meta.source ? String(meta.source) : '') + (meta.distribution ? ' · distribution: ' + meta.distribution : '') +
      (meta.lang ? ' · AI language: ' + meta.lang : '') + (d.ai_source ? ' · AI: ' + d.ai_source : '');
    var head = heading('Arch Intel result', src ? esc(src) : undefined);
    if (an.license_note) {
      head += note(esc(an.license_note));
    }
    return head + nav('verdict') + TABS.map(function (t, i) {
      return '<div class="arc-sec' + (i === 0 ? ' on' : '') + '" data-arc-sec="' + t[0] + '">' + (secs[t[0]] || '') + '</div>';
    }).join('');
  }

  function failure(msg) {
    return heading('Arch Intel') + note('<b>The analysis could not be retrieved.</b> ' + esc(String(msg || 'unknown error')), 'bad');
  }

  function history(rows) {
    var items = list(rows);
    if (!items.length) { return note('No Arch Intel runs yet.'); }
    return table(['Finished', 'Source', 'License', 'Category', 'AI'], items.map(function (r) {
      var ov = obj(r.overview);
      var c = cat(ov.category);
      return [U.when(r.finished), r.source || '—',
        ov.project_license || '—', pill(String(ov.category || 'unknown'), c.pill || 'muted'), ov.ai_source || '—'];
    }), 'No runs.');
  }

  return { CATEGORY: CATEGORY, TABS: TABS, result: result, licenseVerdict: licenseVerdict, notice: notice,
           overview: overview, components: components, sequence: sequence, activity: activity, code: code,
           history: history, failure: failure, diagramBlock: diagramBlock, nav: nav };
});
