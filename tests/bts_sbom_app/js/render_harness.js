// Test harness: runs the page's pure render / form functions (bts_ui.js, bts_governance.js) under Node, without a DOM or a network.
// stdin: JSON [{"mod": "gov"|"ui", "fn": "renderChanges", "args": [...]}, ...]   stdout: JSON list with one result per call.
'use strict';
const path = require('path');
const web = path.join(__dirname, '..', '..', '..', 'bts_sbom_app', 'web');
const mods = { ui: require(path.join(web, 'bts_ui.js')), gov: require(path.join(web, 'bts_governance.js')) };
let raw = '';
process.stdin.setEncoding('utf8');
process.stdin.on('data', (c) => { raw += c; });
process.stdin.on('end', () => {
  const out = JSON.parse(raw).map((c) => {
    const f = mods[c.mod][c.fn];
    if (typeof f === 'function') { return f.apply(null, c.args || []); }
    return f;                                                    // a constant (JUSTIFICATIONS, STATUSES, ...)
  });
  process.stdout.write(JSON.stringify(out));
});
