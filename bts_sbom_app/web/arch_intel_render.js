/*!
 * arch_intel_render.js - pure renderers for the "Arch Intel" pane, laid out like a modelling tool
 * (Enterprise-Advisor style): a model browser tree on the left, an openable canvas in the middle and a
 * properties panel on the right. Written for BTS-SBOM (not one of the six copied platform files, see NOTICE.md).
 *
 * Everything here is a pure function of the JSON the service returned (no DOM, no network), so it runs unchanged
 * under Node for the tests; arch_intel.js fetches the data, mounts the shell and moves a view into the canvas when
 * its tree node is clicked. Rules, as everywhere on this screen:
 *  - every value from analysed data goes through BtsUi.esc() (cell()/kv()/table() do it for table cells);
 *  - the ONLY unescaped HTML is the server-side highlighted code (arch_intel.highlight escapes every character)
 *    and markup built here from escaped parts;
 *  - the model browser lists EVERY modelled item - the live code excerpts are their own section in the tree, not a
 *    stack below the diagrams;
 *  - each diagram keeps its Mermaid source in a hidden pre.arc-mermaid-src inside its view, so a view still shows
 *    the diagram source when the vendored renderer cannot load;
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
  var BLOCK_PILL = { cycle: 'bad', unstable_hub: 'bad', hidden_change_coupling: 'warn', hotspot_concentration: 'warn', high_tangle: 'bad' };

  function obj(v) { return (v && typeof v === 'object' && !Array.isArray(v)) ? v : {}; }
  function list(v) { return Array.isArray(v) ? v : []; }
  function cat(c) { return obj(CATEGORY[String(c)]); }

  /* ---------- diagram placeholder: wiring reads the hidden pre and renders the sibling div ---------- */
  function diagramBlock(src, emptyNote) {
    if (!src) { return note(esc(emptyNote || 'No diagram for this item.'), 'warn'); }
    return '<div class="arc-dwrap"><div class="arc-diagram" data-arc-diagram></div>' +
      '<pre class="arc-mermaid-src" hidden>' + esc(src) + '</pre></div>';
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

  /* ---------- notice checklist ---------- */
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
    out += heading('Clean-room guidance', 'if you plan to reimplement, not to reuse');
    out += note('<b>Architecture facts on this screen are ideas — ideas are not copyrighted.</b> The code excerpts are ' +
      'expressions of the original work under ' + esc(d.project_license || 'the detected license') + ': keep them inside this tool. ' +
      'A reimplementation should be written from a specification (behaviour, interfaces, formats) — never from the ' +
      'excerpts or from decompiler output — and the process documented.', 'warn');
    if (nv.note) { out += note(esc(nv.note)); }
    return out;
  }

  /* ---------- overview (static view) ---------- */
  function overview(structure, aiNote) {
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
    if (aiNote) { out += note('<b>AI lane:</b> ' + esc(aiNote)); }
    return out;
  }

  /* ---------- insights (book-grounded heuristics) ---------- */
  function insights(ins) {
    var d = obj(ins);
    var fb = obj(d.flow_blockers);
    var bcc = obj(d.bounded_context_candidates);
    var sh = obj(d.style_hypothesis);
    var ap = obj(d.antipattern_signals);
    var mod = obj(d.modularity);
    var out = heading('Insights', 'measured facts + architecture heuristics — never a verdict');
    var blockers = list(fb.blockers);
    if (blockers.length) {
      out += heading('Flow blockers', 'what slows a change down (fix the biggest first)');
      out += table(['Signal', 'Where', 'Why it blocks'], blockers.map(function (b) {
        return [pill(String(b.kind || '?'), BLOCK_PILL[b.kind] || 'warn'), esc(b.what || '—'), esc(b.why || '—')];
      }), 'No flow blockers measured.');
    } else {
      out += note('No flow blockers measured (no cycles, no unstable hubs, no hidden change coupling).');
    }
    var cands = list(bcc.candidates);
    out += heading('Bounded context candidates', 'cohesive, weakly-inbound modules — seams worth considering');
    if (cands.length) {
      out += table(['Candidate', 'Cohesion', 'In/out', 'Modules', 'Files'], cands.map(function (c) {
        return [pill(String(c.name || '?'), 'pass'), esc(val(c.cohesion)), esc(val(c.inbound)) + ' / ' + esc(val(c.outbound)),
          esc(val(c.modules)), esc(list(c.files).join(', ') || '—')];
      }), 'No candidates.');
    } else {
      out += note('No bounded context candidates above the threshold (cohesion ≥ 0.6 with low inbound).');
    }
    if (sh.style) {
      out += heading('Style hypothesis', 'signals, not a verdict');
      out += '<div class="bts-cards"><div class="bts-card"><div class="v">' + pill(String(sh.style), 'pass').html +
        '</div><div class="l">' + esc(sh.why || '') + '</div></div></div>';
      if (list(sh.signals).length) { out += note(list(sh.signals).map(function (s) { return esc(s); }).join(' · ')); }
    }
    var signals = list(ap.signals);
    if (signals.length) {
      out += heading('Antipattern signals', 'risk signals, not a verdict');
      out += table(['Signal', 'Why', 'Measured'], signals.map(function (s) {
        return [pill(String(s.code || '?'), 'bad'), esc(s.why || '—'), esc(JSON.stringify(s.measured || {}))];
      }), 'No antipattern signals.');
    }
    if (mod && mod.avg_cohesion !== undefined && mod.avg_cohesion !== null) {
      out += heading('Modularity', 'fitness numbers over the measured clusters');
      out += kv([['avg cohesion', esc(val(mod.avg_cohesion))], ['acyclic', esc(val(mod.acyclic_percent)) + '%'],
        ['tangle ratio', esc(val(mod.tangle_ratio))]]);
      if (list(mod.clusters).length) {
        out += table(['Domain', 'Modules', 'Cohesion', 'In', 'Out', 'BC candidate'], list(mod.clusters).map(function (r) {
          return [r.domain, esc(val(r.modules)), esc(val(r.cohesion)), esc(val(r.inbound)), esc(val(r.outbound)),
            r.bounded_context_candidate ? pill('yes', 'pass') : '—'];
        }), 'No clusters.');
      }
    }
    out += note('<b>Heuristic readings of measured facts.</b> An insight names its signals and never claims certainty — ' +
      'the build/buy and team-boundary judgement stays with the architect.', 'warn');
    return out;
  }

  /* ---------- component views ---------- */
  function componentView(c) {
    var d = obj(c);
    var out = heading('Component — ' + esc(d.name), esc(val(d.role)));
    out += kv([['role', esc(val(d.role))], ['verified files', esc(list(d.files).join(', ') || '—')]]);
    out += note('Every file above was verified to exist in the analysed tree (grounding).');
    return out;
  }

  function componentProps(c) {
    var d = obj(c);
    return kv([['name', esc(d.name || '—')], ['role', esc(val(d.role))],
      ['verified files', esc(list(d.files).length)], ['kind', esc('component')]]);
  }

  function componentsTable(analysis) {
    var an = obj(analysis);
    var items = list(an.components);
    var out = '';
    if (an.overview) { out += note(esc(an.overview)); }
    if (items.length) {
      out += table(['Component', 'Role', 'Files (verified in tree)'], items.map(function (c) {
        return [c.name, val(c.role), list(c.files).join(', ') || '—'];
      }), 'No components.');
    }
    if (list(an.scenarios).length === 0 && list(an.activity).length === 0) {
      out += note('<b>No AI scenario analysis.</b> ' + esc('Connect an EXAONE key (top bar) and re-run for scenario-level sequence and activity flows. The deterministic view is measured, not invented.'), 'warn');
    }
    return out;
  }

  /* ---------- sequence / activity views ---------- */
  function sequenceView(s) {
    var d = obj(s);
    var steps = list(d.steps);
    var out = heading('Sequence — ' + esc(d.name || 'Scenario'),
      d.inferred ? 'static inference — the tree was never executed' : undefined);
    out += diagramBlock(d.mermaid, 'No diagram for this scenario.');
    out += table(['#', 'Actor', 'Action', 'Target'], steps.map(function (st, j) {
      return [String(j + 1), st.actor, st.action, st.target];
    }), 'No steps.');
    return out;
  }

  function sequenceProps(s) {
    var d = obj(s);
    return kv([['name', esc(d.name || '—')], ['steps', esc(list(d.steps).length)],
      ['inferred', esc(d.inferred ? 'yes (static)' : 'no')], ['kind', esc('sequence diagram')]]);
  }

  function activityView(f) {
    var d = obj(f);
    var steps = list(d.steps);
    var out = heading('Activity — ' + esc(d.name || 'Flow'), 'control flow — static inference');
    out += diagramBlock(d.mermaid, d.note || 'No diagram for this flow.');
    if (steps.length) { out += note(steps.map(function (s, j) { return (j + 1) + '. ' + esc(s); }).join('<br>')); }
    return out;
  }

  function activityProps(f) {
    var d = obj(f);
    return kv([['name', esc(d.name || '—')], ['steps', esc(list(d.steps).length)], ['kind', esc('activity diagram')]]);
  }

  /* ---------- code view (live code excerpts) ---------- */
  function codeView(c) {
    var d = obj(c);
    var meta = esc(d.path) + ' · ' + esc(d.role || '') + ' · lines ' + esc(val(d.start_line)) + '–' + esc(val(d.end_line)) +
      ' of ' + esc(val(d.total_lines));
    return heading('Code — ' + esc(d.path), esc(d.role || '')) +
      note('<b>This excerpt is the original work</b> (license: ' + esc(d.license || 'unknown') + '). Keep it inside this ' +
        'analysis; a reimplementation must be written from a specification, not from these excerpts (clean-room).', 'warn') +
      '<div class="arc-codemeta">' + meta + '</div>' +
      '<pre class="arc-code">' + H(String(d.html || '')).html + '</pre>' +
      (d.truncated ? '<div class="bts-small">excerpt — open the file for the full text</div>' : '');
  }

  function codeProps(c) {
    var d = obj(c);
    return kv([['path', esc(d.path || '—')], ['role', esc(val(d.role))], ['language', esc(val(d.lang))],
      ['lines shown', esc(val(d.start_line)) + '–' + esc(val(d.end_line)) + ' of ' + esc(val(d.total_lines))],
      ['license', esc(val(d.license))], ['kind', esc('source excerpt')]]);
  }

  /* ---------- the model ---------- */
  function model(doc) {
    /* Every modelled item as {id, section, label, title, html, props}. The tree mirrors this. */
    var d = obj(doc);
    var meta = obj(d.meta);
    var lic = obj(d.license);
    var an = obj(d.analysis);
    var dg = obj(d.diagrams);
    var items = [];
    var licCat = cat(lic.category);
    items.push({ id: 'license', section: 'License', label: 'License verdict', title: 'License verdict',
      html: licenseVerdict(lic), props: kv([['license', esc(lic.project_license || '—')], ['category', esc(lic.category || '—')],
        ['source', esc(val(lic.project_license_source))], ['kind', esc('license verdict')]]) });
    items.push({ id: 'notice', section: 'License', label: 'Notice & clean-room', title: 'Notice checklist',
      html: notice(lic), props: kv([['checklist items', esc(list(obj(lic.notice).checklist).length)],
        ['network clause', esc(obj(lic.notice).network_clause ? 'yes (AGPL §13)' : 'no')], ['kind', esc('notice')]]) });
    items.push({ id: 'overview', section: 'Overview', label: 'Overview (static view)', title: 'Overview',
      html: overview(d.structure, d.ai_note), props: kv([['files', esc(val(obj(d.structure).files_count))],
        ['loc', esc(val(obj(d.structure).total_loc))], ['kind', esc('overview')]]) });
    if (d.insights) {
      var fb = obj(obj(d.insights).flow_blockers);
      items.push({ id: 'insights', section: 'Insights', label: 'Insights (' + esc(list(fb.blockers).length) + ' blockers)',
        title: 'Insights', html: insights(d.insights),
        props: kv([['flow blockers', esc(list(fb.blockers).length)],
          ['bounded context candidates', esc(list(obj(obj(d.insights).bounded_context_candidates).candidates).length)],
          ['style hypothesis', esc(obj(obj(d.insights).style_hypothesis).style || '—')],
          ['antipattern signals', esc(list(obj(obj(d.insights).antipattern_signals).signals).length)],
          ['kind', esc('insights')]]) });
    }
    var comp = obj(dg.components);
    if (comp.mermaid || list(an.components).length) {
      items.push({ id: 'diagram_components', section: 'Diagrams', label: 'Component diagram', title: 'Component diagram',
        html: heading('Component diagram', 'components and their measured edges') +
          diagramBlock(comp.mermaid, comp.note || 'No component diagram (the analysis found no components).') +
          componentsTable(an),
        props: kv([['components', esc(list(an.components).length)], ['kind', esc('diagram')]]) });
    }
    list(dg.sequence).forEach(function (s, i) {
      items.push({ id: 'seq_' + i, section: 'Diagrams', label: 'Sequence — ' + String(obj(s).name || ('#' + (i + 1))),
        title: 'Sequence — ' + String(obj(s).name || (i + 1)), html: sequenceView(s), props: sequenceProps(s) });
    });
    list(dg.activity).forEach(function (f, i) {
      items.push({ id: 'act_' + i, section: 'Diagrams', label: 'Activity — ' + String(obj(f).name || ('#' + (i + 1))),
        title: 'Activity — ' + String(obj(f).name || (i + 1)), html: activityView(f), props: activityProps(f) });
    });
    list(an.components).forEach(function (c, i) {
      items.push({ id: 'comp_' + i, section: 'Components', label: String(obj(c).name || ('#' + (i + 1))),
        title: 'Component — ' + String(obj(c).name || i), html: componentView(c), props: componentProps(c) });
    });
    list(d.code).forEach(function (c, i) {
      items.push({ id: 'code_' + i, section: 'Code', label: String(obj(c).path || ('file #' + (i + 1))),
        title: 'Code — ' + String(obj(c).path || i), html: codeView(c), props: codeProps(c) });
    });
    /* Code Intel: the deterministic function-level lane (call graph, complexity, dead code, clones - Python only).
       The call graph comes from the same deterministic builder as every other diagram - the model never writes Mermaid. */
    var codeL = obj(obj(d.structure).code);
    if (codeL.metrics && codeL.metrics.functions) {
      var cgm = obj(dg.callgraph);
      var mx = obj(codeL.metrics.max_complexity);
      var dead = list(codeL.dead_code);
      var clones = list(codeL.clones);
      var ciHtml = heading('Code Intel', 'function-level facts (Python, deterministic)') +
        kv([['functions', esc(val(codeL.metrics.functions))], ['avg complexity', esc(val(codeL.metrics.avg_complexity))],
            ['max complexity', esc(mx.name ? mx.name + ' (' + val(mx.file) + ') — cc ' + val(mx.cc) : '—')],
            ['dead functions', esc(val(codeL.metrics.dead_count))], ['clone groups', esc(val(codeL.metrics.clone_groups))],
            ['resolved / unknown calls', esc(val(codeL.metrics.resolved_calls)) + ' / ' + esc(val(codeL.metrics.unknown_calls))]]) +
        (cgm.mermaid ? heading('Call graph', esc(cgm.note || 'measured function-level calls')) +
          diagramBlock(cgm.mermaid, 'No call graph for this tree.')
                     : note('No resolved function-level call in this tree - the call resolver is name-based and Python-only.', 'warn')) +
        (dead.length ? heading('Dead functions (fan-in 0)', esc(dead.length) + ' listed of ' + esc(val(codeL.metrics.dead_count))) +
          kv(dead.slice(0, 10).map(function (x) { return [val(x.name), val(x.file) + ':' + val(x.line) + ' (' + val(x.sloc) + ' sloc)']; })) : '') +
        (clones.length ? heading('Clone groups', esc(clones.length) + ' groups of identical normalized bodies') +
          kv(clones.slice(0, 6).map(function (g) { return [val(g.hash) + ' ×' + val(g.count),
            list(g.members).map(function (mm) { return val(mm.name) + ' (' + val(mm.file) + ':' + val(mm.line) + ')'; }).join(', ')]; })) : '') +
        list(codeL.notes).map(function (x) { return note(esc(x), 'warn'); }).join('');
      items.push({ id: 'code_intel', section: 'Code Intel', label: 'Code Intel', title: 'Code Intel (function level)',
        html: ciHtml, props: kv([['language', esc(val(codeL.language))], ['functions', esc(val(codeL.metrics.functions))],
          ['dead', esc(val(codeL.metrics.dead_count))], ['clone groups', esc(val(codeL.metrics.clone_groups))],
          ['kind', esc('code intel')]]) });
    }
    return { items: items, meta: meta, licCat: licCat, license: lic, analysis: an };
  }

  var SECTION_ORDER = ['License', 'Overview', 'Insights', 'Diagrams', 'Components', 'Code', 'Code Intel'];

  /* ---------- the shell ---------- */
  function result(doc) {
    var m = model(doc);
    var meta = m.meta;
    var src = (meta.source ? String(meta.source) : '') + (meta.distribution ? ' · distribution: ' + meta.distribution : '') +
      (meta.lang ? ' · AI: ' + meta.lang : '') + (doc.ai_source ? ' · AI: ' + doc.ai_source : '');
    var head = heading('Arch Intel model', src ? esc(src) : undefined);
    if (obj(m.analysis).license_note) { head += note(esc(obj(m.analysis).license_note)); }
    var defaultId = 'diagram_components';
    var hasDefault = m.items.some(function (it) { return it.id === defaultId; });
    if (!hasDefault && m.items.length) { defaultId = m.items[0].id; }
    /* model browser: section groups in fixed order, tree nodes under each */
    var tree = '<div class="arc-tree">';
    SECTION_ORDER.forEach(function (sec) {
      var inSec = m.items.filter(function (it) { return it.section === sec; });
      if (!inSec.length) { return; }
      tree += '<details class="arc-tgroup" open><summary>' + esc(sec) + '</summary>';
      inSec.forEach(function (it) {
        tree += '<button type="button" class="arc-node' + (it.id === defaultId ? ' on' : '') + '" data-arc-open="' +
          esc(it.id) + '">' + esc(it.label) + '</button>';
      });
      tree += '</details>';
    });
    tree += '</div>';
    /* hidden store: one view pane + one props pane per item */
    var store = '<div class="arc-store" hidden>';
    m.items.forEach(function (it) {
      store += '<div class="arc-viewpane" data-arc-view="' + esc(it.id) + '" data-arc-title="' + esc(it.title || it.label) + '">' + it.html + '</div>';
      store += '<div class="arc-viewprops" data-arc-props="' + esc(it.id) + '" hidden>' + (it.props || '') + '</div>';
    });
    store += '</div>';
    var shell = '<div class="arc-shell">' +
      '<div class="arc-browser"><div class="arc-browser-h">Model browser</div>' + tree + '</div>' +
      '<div class="arc-main"><div class="arc-canvas-tabs"></div><div class="arc-canvas-body"></div></div>' +
      '<div class="arc-props"><div class="arc-browser-h">Properties</div><div class="arc-props-body"></div></div>' +
      '</div>';
    return head + shell + store + '<div data-arc-default="' + esc(defaultId) + '" hidden></div>' +
      '<div data-arc-verdict="' + esc(m.license.project_license || '') + '" hidden></div>';
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

  return { CATEGORY: CATEGORY, SECTION_ORDER: SECTION_ORDER, result: result, model: model, licenseVerdict: licenseVerdict,
           notice: notice, overview: overview, insights: insights, componentsTable: componentsTable,
           sequenceView: sequenceView, activityView: activityView, codeView: codeView,
           history: history, failure: failure, diagramBlock: diagramBlock };
});
