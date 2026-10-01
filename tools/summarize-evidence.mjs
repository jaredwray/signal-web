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
  'pw:chromium': 'Chromium (Playwright headless shell build)',
  'pw-channel:chrome': 'Google Chrome (installed)',
  'pw-channel:msedge': 'Microsoft Edge (installed)',
  'pw:firefox': 'Firefox (Playwright\'s patched build)',
  'pw:webkit': 'WebKit (Playwright\'s Linux build; not Safari)',
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
const tally = (r) => {
  if (!r) return 'not run';
  const extra = [r.aborted && `aborted: ${r.aborted}`, r.crashed && `crashed: ${r.crashed}`].filter(Boolean);
  return `${r.passed ?? 0}/${(r.passed ?? 0) + (r.failed ?? 0)} pass${extra.length ? ` (${extra.join('; ')})` : ''}`;
};

// --- G1
const out = [];
out.push('#### G1 table', '', row(['Browser', 'Version', 'Self-test (protocol + provisioning)', 'Upstream libsignal tests (incl. ignored)']), row(['---', '---', '---', '---']));
for (const { f, d } of local.filter((x) => x.f.startsWith('crypto-selftest-')).sort(sortBySpec)) {
  const spec = specOf(f);
  const up = local.find((x) => x.f.startsWith('upstream-tests-including-ignored-') && specOf(x.f) === spec);
  const upCell = up ? `${up.d.counts.ok ?? 0}/${Object.values(up.d.counts).reduce((a, b) => a + b, 0)} ok` : 'not run';
  out.push(row([LABEL[spec] ?? spec, d.browser, tally(d), upCell]));
}

// --- G5
out.push('', '#### G5 table', '', row(['Browser', 'Restart mode', 'Phase 1 (setup)', 'Phase 2 (after restart)', 'persist() granted']), row(['---', '---', '---', '---', '---']));
for (const { f, d } of local.filter((x) => x.f.startsWith('storage-test-')).sort(sortBySpec)) {
  const spec = specOf(f);
  const p1 = d.phase_setup ?? {};
  const p2 = d.phase_resume_after_restart ?? {};
  // A phase whose report names another phase did not run (see run-local-tests).
  const phaseCell = (p, want) => (p.phase && p.phase !== want ? `INVALID (report from phase "${p.phase}")` : tally(p));
  out.push(row([LABEL[spec] ?? spec, d.restart, phaseCell(p1, 'setup'), phaseCell(p2, 'resume'), String(p1.storage_persist_granted)]));
}

// --- G2
const SIGNAL = ['chat.signal.org', 'grpc.chat.signal.org', 'storage.signal.org', 'cdn.signal.org', 'cdn2.signal.org', 'cdn3.signal.org', 'cdsi.signal.org', 'svr2.signal.org'];
const CONTROL = 'updates.signal.org';
const probes = live.filter((x) => x.f.startsWith('probe-') && !x.f.includes('cloud-container')).sort(sortBySpec);
const isReadable = (r) => Boolean(r && (r.readable ?? (r.ok && (r.type === 'cors' || r.type === 'basic'))));
const wsOutcome = (r) => r.events.at(-1).replace(/, wasClean.*$/, ')');
out.push('', '#### G2 table', '', row(['Browser', 'Version', `Control \`${CONTROL}\`: CORS fetch / no-cors / navigation`, 'Signal hosts: readable CORS fetch', 'Signal hosts: no-cors reachable', 'Provisioning WebSocket', 'Browser named a certificate problem', 'Browser\'s own error', 'Verdict']), row(Array(9).fill('---')));
for (const { f, d } of probes) {
  const spec = specOf(f);
  const res = d.page_report.results;
  const find = (kind, host) => res.find((r) => r.kind === kind && new URL(r.url).host === host);
  const hosts = d.verdict.hosts ?? {};
  const ctlFetch = ['fetch/cors', 'fetch/no-cors'].map((k) => {
    const r = find(k, CONTROL);
    if (!r) return '-';
    return r.ok ? `${r.type} ${r.status}` : 'failed';
  });
  const ctlNav = hosts[CONTROL]?.navigation;
  const ctl = [...ctlFetch, ctlNav ? (ctlNav.ok ? `reached${ctlNav.status ? ` (${ctlNav.status})` : ''}` : 'failed') : '-'].join(' / ');
  const cors = SIGNAL.filter((h) => isReadable(find('fetch/cors', h))).length;
  const corsTotal = SIGNAL.filter((h) => find('fetch/cors', h)).length;
  const nc = SIGNAL.filter((h) => find('fetch/no-cors', h)?.ok).length;
  const ws = [...new Set(res.filter((r) => r.kind === 'websocket' && new URL(r.url).host !== CONTROL).map(wsOutcome))].join(', ');
  const navErr = [...new Set(SIGNAL.map((h) => hosts[h]?.navigation).filter((n) => n && !n.ok)
    .map((n) => n.error.replace(/ at https?:\/\/\S+/, '').replace(/^page\.goto: /, '').replace(/:\s*$/, '')))];
  const dt = [...new Set(SIGNAL.flatMap((h) => hosts[h]?.devtools_errors ?? []))].filter((e) => /CERT/.test(e))
    .map((e) => e.replace('Error in connection establishment: ', 'WebSocket: '));
  const rejected = SIGNAL.filter((h) => hosts[h]?.certificate_rejected_by_browser).length;
  const tls = SIGNAL.filter((h) => hosts[h]?.tls_handshake_failed_unspecified).length;
  out.push(row([LABEL[spec] ?? spec, d.browser, ctl, `${cors}/${corsTotal}`, `${nc}/${SIGNAL.length}`, ws,
    `${rejected}/${SIGNAL.length}${tls ? ` (+ WebSocket close 1015 on ${tls})` : ''}`,
    [...new Set([...navErr, ...dt])].join('; ') || '-', d.verdict.validity]));
}

// --- G2 NetLog: the certificate chains Chromium-family browsers received.
out.push('', '#### G2 NetLog table', '', row(['Browser', 'Signal-host chains received', 'Leaf issuer', 'Signal root sent in chain', 'Interception check']), row(Array(5).fill('---')));
for (const { f, d } of probes.filter((x) => x.d.netlog)) {
  const spec = specOf(f);
  const chains = (d.netlog.certificate_chains_received ?? []).filter((c) =>
    SIGNAL.some((h) => (c.names ?? [c.host]).some((n) => n === h || (n.startsWith('*.') && h.endsWith(n.slice(1))))));
  const short = (c) => (c.names?.[0] ?? c.host).replace('.signal.org', '');
  const issuers = [...new Set(chains.map((c) => (c.leaf_issuer.match(/CN=([^,]+)/) ?? [])[1] ?? c.leaf_issuer))];
  const withRoot = [...new Set(chains.filter((c) => c.includes_signal_root).map(short))];
  out.push(row([LABEL[spec] ?? spec, [...new Set(chains.map(short))].join(', ') || 'none', issuers.join('; ') || '-',
    withRoot.length ? withRoot.join(', ') : 'none', d.verdict.interception_check ?? '-']));
}
// --- G3: the real app's linking attempt on the same clean network.
out.push('', '#### G3 app table', '', row(['Browser', 'WASM loaded', 'QR shown', 'Status shown to the user']), row(Array(4).fill('---')));
for (const { f, d } of probes) {
  const spec = specOf(f);
  const a = d.app_link_attempt ?? {};
  const wasm = (d.static_origin_requests ?? []).some((r) => r.path.endsWith('.wasm') && r.status === 200);
  const text = (a.status_text ?? a.error ?? '-').replace(/\|/g, '/');
  out.push(row([LABEL[spec] ?? spec, wasm ? 'yes' : 'no', String(a.qr_shown ?? false), text.length > 140 ? `${text.slice(0, 140)}…` : text]));
}

// --- Versions of everything around the browsers, grouped by environment.
out.push('', '#### Versions table', '', row(['Runner image', 'OS', 'Node', 'Playwright', 'Browsers', 'Evidence files']), row(Array(6).fill('---')));
const envs = new Map();
for (const { f, d } of [...local, ...live].filter((x) => x.d.tools && !x.f.includes('cloud-container'))) {
  const t = d.tools;
  const k = [t.runner_image ?? 'not a GitHub runner', t.os, t.node, t.playwright].join('|');
  const e = envs.get(k) ?? envs.set(k, { t, browsers: new Set(), files: 0 }).get(k);
  e.browsers.add(specOf(f));
  e.files += 1;
}
for (const { t, browsers, files } of envs.values()) {
  out.push(row([t.runner_image ?? 'not a GitHub runner', t.os, t.node, t.playwright, [...browsers].sort((a, b) => order.indexOf(a) - order.indexOf(b)).map((x) => LABEL[x] ?? x).join('; '), String(files)]));
}
console.log(out.join('\n'));
