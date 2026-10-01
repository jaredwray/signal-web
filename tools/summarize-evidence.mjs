#!/usr/bin/env node
// Builds the markdown tables used in VALIDATION_REPORT.md from evidence JSON,
// so reported numbers are generated, not transcribed.
//   node tools/summarize-evidence.mjs evidence/ci/local evidence/ci/live
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const load = (dir) => {
  try {
    return readdirSync(dir).filter((f) => f.endsWith('.json')).map((f) => ({ f, d: JSON.parse(readFileSync(join(dir, f), 'utf8')) }));
  } catch {
    return [];
  }
};
const [localDir, liveDir] = process.argv.slice(2);
const local = load(localDir);
const live = load(liveDir);

const LABEL = {
  'pw:chromium': 'Chromium (Playwright build)',
  'pw-channel:chrome': 'Google Chrome',
  'pw-channel:msedge': 'Microsoft Edge',
  'pw:firefox': 'Firefox (Playwright build)',
  'pw:webkit': 'WebKit (Playwright build, not Safari)',
  'wd:firefox': 'Firefox (installed, geckodriver)',
  'wd:safari': 'Safari (installed, safaridriver)',
};
const specOf = (f) => {
  const m = f.match(/-(pw-channel-chrome|pw-channel-msedge|pw-chromium|pw-firefox|pw-webkit|wd-firefox|wd-safari)(?:-|\.json)/);
  if (!m) return f;
  return m[1].startsWith('pw-channel-') ? m[1].replace('pw-channel-', 'pw-channel:') : m[1].replace(/^(pw|wd)-/, '$1:');
};
const order = Object.keys(LABEL);
const sortBySpec = (a, b) => order.indexOf(specOf(a.f)) - order.indexOf(specOf(b.f));
const row = (cells) => `| ${cells.join(' | ')} |`;

// --- G1
const out = [];
out.push('#### G1 table', '', row(['Browser', 'Version', 'Self-test (protocol + provisioning)', 'Upstream libsignal tests (incl. ignored)']), row(['---', '---', '---', '---']));
for (const { f, d } of local.filter((x) => x.f.startsWith('crypto-selftest-')).sort(sortBySpec)) {
  const spec = specOf(f);
  const up = local.find((x) => x.f.startsWith('upstream-tests-including-ignored-') && specOf(x.f) === spec);
  const upCell = up ? `${up.d.counts.ok ?? 0}/${Object.values(up.d.counts).reduce((a, b) => a + b, 0)} ok` : 'not run';
  out.push(row([LABEL[spec] ?? spec, d.browser, `${d.passed}/${d.passed + d.failed} pass`, upCell]));
}

// --- G5
out.push('', '#### G5 table', '', row(['Browser', 'Restart mode', 'Phase 1 (setup)', 'Phase 2 (after restart)', 'persist() granted']), row(['---', '---', '---', '---', '---']));
for (const { f, d } of local.filter((x) => x.f.startsWith('storage-test-')).sort(sortBySpec)) {
  const spec = specOf(f);
  const p1 = d.phase_setup ?? {};
  const p2 = d.phase_resume_after_restart ?? {};
  out.push(row([LABEL[spec] ?? spec, d.restart, `${p1.passed ?? 0}/${(p1.passed ?? 0) + (p1.failed ?? 0)}`,
    `${p2.passed ?? 0}/${(p2.passed ?? 0) + (p2.failed ?? 0)}`, String(p1.storage_persist_granted)]));
}

// --- G2
const SIGNAL = ['chat.signal.org', 'grpc.chat.signal.org', 'storage.signal.org', 'cdn.signal.org', 'cdn2.signal.org', 'cdn3.signal.org', 'cdsi.signal.org', 'svr2.signal.org'];
out.push('', '#### G2 table', '', row(['Browser', 'Version', 'Control `updates.signal.org` (CORS fetch / no-cors / WS)', 'Signal hosts: readable CORS fetch', 'Signal hosts: no-cors reachable', 'Provisioning WebSocket', 'Browser\'s own TLS verdict (navigation / DevTools)', 'Verdict']), row(Array(8).fill('---')));
for (const { f, d } of live.filter((x) => x.f.startsWith('probe-') && !x.f.includes('cloud-container')).sort(sortBySpec)) {
  const spec = specOf(f);
  const res = d.page_report.results;
  const find = (kind, host) => res.find((r) => r.kind === kind && new URL(r.url).host === host);
  const ctl = ['fetch/cors', 'fetch/no-cors', 'websocket'].map((k) => {
    const r = find(k, 'updates.signal.org');
    if (!r) return '-';
    if (k === 'websocket') return r.events.at(-1).replace(/, wasClean.*$/, ')');
    return r.ok ? `${r.type} ${r.status}` : 'failed';
  }).join(' / ');
  const cors = SIGNAL.filter((h) => find('fetch/cors', h)?.ok).length;
  const corsTotal = SIGNAL.filter((h) => find('fetch/cors', h)).length;
  const nc = SIGNAL.filter((h) => find('fetch/no-cors', h)?.ok).length;
  const ws = [...new Set(res.filter((r) => r.kind === 'websocket' && r.url.includes('provisioning') && !r.url.includes('updates')).map((r) => r.events.at(-1).replace(/, wasClean.*$/, ')')))].join(', ');
  const hosts = d.verdict.hosts ?? {};
  const navErr = [...new Set(SIGNAL.map((h) => hosts[h]?.navigation).filter((n) => n && !n.ok).map((n) => n.error.replace(/ at https?:\/\/\S+/, '').replace(/^page\.goto: /, '')))];
  const dt = [...new Set(SIGNAL.flatMap((h) => hosts[h]?.devtools_errors ?? []))].filter((e) => /CERT/.test(e)).map((e) => e.replace('Error in connection establishment: ', 'WS: '));
  const rejected = SIGNAL.filter((h) => hosts[h]?.certificate_rejected_by_browser).length;
  out.push(row([LABEL[spec] ?? spec, d.browser, ctl, `${cors}/${corsTotal}`, `${nc}/${SIGNAL.length}`, ws,
    `${rejected}/${SIGNAL.length} rejected: ${[...navErr, ...dt].join('; ') || '-'}`, d.verdict.validity]));
}
console.log(out.join('\n'));
