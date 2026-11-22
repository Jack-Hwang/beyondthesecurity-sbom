/*!
 * bts_books.js - the "Book KB" pane of the BTS-SBOM screen: the local architecture-book knowledge base.
 * Shows the ingest registry (one row per book, each with its explicit status), the chapter outline of a book and
 * full-text search over the ingested books; an ingest job reads a local folder of PDF/EPUB files in the
 * background (books are read, never fetched). Written for BTS-SBOM, laid out like arch_intel.js.
 * Rules (same as bts_console.js): every dynamic value goes through textContent or BtsUi helpers (which escape);
 * no inline event handlers (strict Content-Security-Policy); book text appears only as short snippets with the
 * book and section it came from - the copyright stays with the authors.
 */
(function () {
  'use strict';
  var root = document.getElementById('paneBooks');
  if (!root) { return; }
  var U = window.BtsUi;
  if (!U) { root.textContent = 'bts_ui.js did not load, so this screen cannot start.'; return; }
  var esc = U.esc, H = U.H, table = U.table, note = U.note, heading = U.heading;

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
    }).catch(function (e) { return { ok: false, status: 0, data: { error: String(e) } }; });
  }

  /* ---------- layout ---------- */
  var ingestPath = el('input', { id: 'booksIngestPath', placeholder: 'D:\\path\\to\\book folder  (read-only; artifacts go to evidence/books/)', spellcheck: 'false', style: 'flex:1;min-width:340px;font-family:ui-monospace,monospace' });
  var ingestBtn = el('button', { 'class': 'run', type: 'button', id: 'booksIngestBtn', text: '\u25B6 Ingest folder' });
  var ingestOut = el('div', {});
  var searchQ = el('input', { id: 'booksSearchQ', placeholder: 'e.g. fitness function / circuit breaker / refactoring move / 29119 test process', spellcheck: 'false', style: 'flex:1;min-width:340px' });
  var searchBtn = el('button', { 'class': 'run', type: 'button', id: 'booksSearchBtn', text: '\uD83D\uDD0D Search books' });
  var searchOut = el('div', {});
  var listBox = el('div', { id: 'booksList' });
  var outlineBox = el('div', { id: 'booksOutline' });
  root.appendChild(el('div', { 'class': 'pathbox' }, [
    el('label', { text: 'Ingest a local folder of PDF/EPUB books into the knowledge base' }),
    el('div', { style: 'display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap' }, [ingestPath, ingestBtn]),
    el('div', { 'class': 'ex', text: 'Extraction: EPUB via the standard library, PDF via pdftotext when it is on PATH (otherwise the PDF is recorded as skipped - nothing is silently dropped). Identical files are indexed once (SHA-256). Extracted text stays in evidence/books/ (gitignored); only our own distilled notes live in the repository.' }),
    ingestOut
  ]));
  root.appendChild(el('div', { 'class': 'pathbox' }, [
    el('label', { text: 'Search the ingested books' }),
    el('div', { style: 'display:flex;gap:8px;align-items:center;margin-top:8px;flex-wrap:wrap' }, [searchQ, searchBtn]),
    searchOut
  ]));
  var libHead = el('div', {});
  libHead.innerHTML = heading('Library');
  root.appendChild(libHead);
  root.appendChild(listBox);
  root.appendChild(el('div', {}, [outlineBox]));

  /* ---------- registry ---------- */
  function loadRegistry() {
    api('/api/books').then(function (r) {
      var d = r.data || {};
      if (!d.built) {
        listBox.innerHTML = note('No book knowledge base has been built yet. ' + esc(d.hint || 'Ingest a folder above, or run bts-sbom-app books --src <folder>.'));
        return;
      }
      var t = d.totals || {};
      var rows = (d.books || []).map(function (b) {
        return [esc(b.title || b.file || ''), esc(b.format || ''), esc(b.status || ''),
                b.sections === undefined ? '' : String(b.sections), b.chars === undefined ? '' : String(b.chars),
                b.pages === undefined ? '' : String(b.pages),
                b.status === 'ok' ? H('<button type="button" class="bts-mini" data-book="' + esc(b.slug) + '">outline</button>')
                                   : esc(b.reason || (b.duplicate_of ? 'of ' + b.duplicate_of : ''))];
      });
      listBox.innerHTML = heading('Library', t.files + ' files: ' + t.ok + ' ok, ' + t.skipped + ' skipped, ' + t.duplicates + ' duplicates - ' + t.sections + ' sections, ' + t.chars + ' chars') +
        table(['Book', 'Format', 'Status', 'Sections', 'Chars', 'Pages', ''], rows, 'Nothing indexed.');
      var meta = el('div', { 'class': 'sub', text: 'built ' + (d.built_at || '') + ' - pdftotext: ' + (d.pdftotext || 'not on PATH (PDFs skipped)') + ' - src: ' + (d.src || '') });
      listBox.appendChild(meta);
    });
  }

  function loadOutline(slug) {
    api('/api/books/' + encodeURIComponent(slug)).then(function (r) {
      var d = r.data || {};
      if (!r.ok) { outlineBox.innerHTML = note(esc(d.error || 'unknown book'), 'warn'); return; }
      var rows = (d.outline || []).map(function (s) { return [esc(s.heading || ''), s.chars === undefined ? '' : String(s.chars)]; });
      outlineBox.innerHTML = heading('Outline: ' + (d.title || slug), (d.sections || 0) + ' sections - ' + (d.chars || 0) + ' chars' + (d.pages ? ' - ' + d.pages + ' pages' : '')) +
        table(['Section', 'Chars'], rows, 'No sections recorded.');
    });
  }

  function runSearch() {
    var q = searchQ.value.trim();
    if (!q) { searchOut.innerHTML = note('Type what to look up in the books.', 'warn'); return; }
    searchOut.innerHTML = note('Searching...');
    api('/api/books/search?q=' + encodeURIComponent(q) + '&k=8').then(function (r) {
      var d = r.data || {};
      if (r.status === 400) { searchOut.innerHTML = note(esc(d.error || 'bad request'), 'warn'); return; }
      if (!d.found) { searchOut.innerHTML = note(esc(d.reason || 'No matching passage in the book library.'), 'warn'); return; }
      var rows = (d.results || []).map(function (x) {
        return [esc(x.book || ''), esc(x.heading || ''), esc(x.snippet || ''), esc(String(x.rrf))];
      });
      searchOut.innerHTML = heading('Matches', (d.results || []).length + ' passages - ' + d.took_ms + ' ms') +
        table(['Book', 'Section', 'Snippet (short quote)', 'rrf'], rows, 'Nothing found.');
      searchOut.appendChild(el('div', { 'class': 'sub', text: 'Snippets are short quotes from books on this machine; the copyright stays with the authors. The chat answers from the same library via the book_search tool.' }));
    });
  }

  /* ---------- ingest job (same wire as /api/scan jobs) ---------- */
  var pollTimer = null;
  function pollJob(jid) {
    api('/api/jobs/' + encodeURIComponent(jid)).then(function (r) {
      var d = r.data || {};
      if (d.state === 'running') {
        ingestOut.innerHTML = note('Ingesting... current file: ' + esc(d.stage || d.source || ''), 'warn');
        pollTimer = setTimeout(function () { pollJob(jid); }, 1200);
        return;
      }
      if (d.state === 'done') {
        var t = d.totals || {};
        ingestOut.innerHTML = note('Done: ' + t.files + ' files - ' + t.ok + ' ok, ' + t.skipped + ' skipped, ' + t.duplicates + ' duplicates (' + t.sections + ' sections, ' + t.chars + ' chars).');
      } else {
        ingestOut.innerHTML = note('Ingest failed: ' + esc(d.error || d.state || 'unknown'), 'bad');
      }
      loadRegistry();
    });
  }
  ingestBtn.addEventListener('click', function () {
    var src = ingestPath.value.trim();
    if (!src) { ingestOut.innerHTML = note('Type the local folder that holds the PDF/EPUB books.', 'warn'); return; }
    api('/api/books/ingest', { src: src }).then(function (r) {
      var d = r.data || {};
      if (r.status === 202 && d.job) {
        ingestOut.innerHTML = note('Ingest job ' + esc(d.job) + ' started.');
        pollJob(d.job);
      } else {
        ingestOut.innerHTML = note(esc(d.error || ('HTTP ' + r.status)), 'bad');
      }
    });
  });
  searchBtn.addEventListener('click', runSearch);
  searchQ.addEventListener('keydown', function (e) { if (e.key === 'Enter') { runSearch(); } });
  listBox.addEventListener('click', function (e) {
    var b = e.target.closest('[data-book]');
    if (b) { loadOutline(b.getAttribute('data-book')); }
  });

  loadRegistry();
})();
