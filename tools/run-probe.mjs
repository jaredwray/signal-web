#!/usr/bin/env node
// LIVE (opt-in) direct-networking probe: loads web/probe.html in a browser and
// lets it contact Signal's public hosts. No Signal account and no credentials
// are involved; one attempt is made per target.
//
//   SIGNAL_WEB_LIVE=1 node tools/run-probe.mjs [--browser <spec>]... [--proxy-from-env]
//
// Browser specs: see tools/browsers.mjs (default pw:chromium).
// The runner only OBSERVES: page results, console messages and, for
// Chromium-family browsers, DevTools Network events plus a NetLog that shows
// the certificate chain the browser actually received. It registers no
// request interception and changes no browser security setting. Raw NetLogs
// stay outside the repository; a sanitized summary goes to evidence/live/.
//
// --proxy-from-env routes the browser through $HTTPS_PROXY (only for machines
// whose internet access requires a CONNECT proxy). The verdict flags any
// network that re-terminates TLS, so such a network cannot be mistaken for a
// Signal result.

import { X509Certificate } from 'node:crypto';
import { mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { browserArgs, openBrowser, parseSpec, specSlug } from './browsers.mjs';
import { readServerLog, startServer } from './run-local-tests.mjs';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
const SIGNAL_ROOT_SHA256 =
  'DD:B0:F9:2B:B9:5C:8D:6F:D2:02:EA:6E:8C:C5:CC:D1:82:B5:44:F8:CD:69:6F:47:D5:80:65:9D:DC:9D:F6:5A';

if (process.env.SIGNAL_WEB_LIVE !== '1') {
  console.error('This probe contacts Signal servers. Re-run with SIGNAL_WEB_LIVE=1 to opt in.');
  process.exit(2);
}

const outDir = join(repo, 'evidence', 'live');
const scratch = process.env.PROBE_SCRATCH_DIR ?? join(tmpdir(), 'signal-web-probe');

function summarizeNetLog(path) {
  let log;
  try {
    log = JSON.parse(readFileSync(path, 'utf8'));
  } catch (err) {
    return { error: `could not parse NetLog: ${err.message}` };
  }
  const typeName = Object.fromEntries(Object.entries(log.constants.logEventTypes).map(([k, v]) => [v, k]));
  const chains = new Map();
  const proxies = new Set();
  for (const ev of log.events) {
    const type = typeName[ev.type];
    if (type === 'PROXY_RESOLUTION_SERVICE_RESOLVED_PROXY_LIST') proxies.add(ev.params?.proxy_info);
    if (type === 'SSL_CERTIFICATES_RECEIVED' && ev.params?.certificates) {
      const certs = ev.params.certificates.map((pem) => new X509Certificate(pem));
      const leaf = certs[0];
      const host = (leaf.subjectAltName ?? '').replace(/^DNS:/, '').split(',')[0];
      chains.set(host, {
        host,
        leaf_issuer: leaf.issuer.replace(/\n/g, ', '),
        leaf_valid: `${leaf.validFrom} -> ${leaf.validTo}`,
        chain_length: certs.length,
        chain_sha256: certs.map((c) => c.fingerprint256),
        includes_signal_root: certs.some((c) => c.fingerprint256 === SIGNAL_ROOT_SHA256),
      });
    }
  }
  return { proxy_resolution: [...proxies], certificate_chains_received: [...chains.values()] };
}

function verdict(report, netlog) {
  const byUrl = (kind, url) => report.results.find((r) => r.kind === kind && r.url === url);
  const control = byUrl('fetch/no-cors', 'https://updates.signal.org/desktop/latest.yml');
  const signalTargets = report.results.filter((r) => r.kind === 'fetch/no-cors' && !r.label.startsWith('CONTROL'));
  const v = {
    control_public_ca_host_reachable: Boolean(control?.ok),
    signal_hosts_reachable_no_cors: signalTargets.filter((r) => r.ok).map((r) => r.url),
    signal_hosts_unreachable_no_cors: signalTargets.filter((r) => !r.ok).map((r) => r.url),
    cors_readable_responses: report.results.filter((r) => r.kind === 'fetch/cors' && r.ok).map((r) => r.url),
    websockets_opened: report.results.filter((r) => r.kind === 'websocket' && r.events.includes('open')).map((r) => r.url),
  };
  const chains = netlog?.certificate_chains_received ?? [];
  const foreign = chains.filter((c) => c.host.endsWith('signal.org') && c.host !== 'updates.signal.org' && !c.includes_signal_root && !/Signal Messenger/.test(c.leaf_issuer));
  const controlChain = chains.find((c) => c.host === 'updates.signal.org');
  if (foreign.length || (controlChain && /interception|proxy/i.test(controlChain.leaf_issuer))) {
    v.validity = 'INVALID_FOR_SIGNAL_CONCLUSIONS';
    v.reason = `the network re-terminated TLS (issuer seen: ${(foreign[0] ?? controlChain).leaf_issuer})`;
  } else if (!v.control_public_ca_host_reachable) {
    v.validity = 'INCONCLUSIVE';
    v.reason = 'even the publicly trusted control host was unreachable from this browser';
  } else {
    v.validity = 'VALID';
    v.reason = chains.length
      ? 'control reachable; browser received Signal\'s own certificate chains (see netlog)'
      : 'control reachable; certificate chains not observable in this browser';
  }
  return v;
}

async function probeOne(spec, origin, serverLog) {
  const s = parseSpec(spec);
  const chromiumFamily = s.driver === 'playwright' && s.engine === 'chromium';
  const netlogPath = join(scratch, `netlog-${specSlug(spec)}.json`);
  rmSync(netlogPath, { force: true });
  const proxyServer = process.argv.includes('--proxy-from-env') ? (process.env.HTTPS_PROXY ?? process.env.https_proxy) : undefined;
  const browser = await openBrowser(spec, {
    launchArgs: chromiumFamily ? [`--log-net-log=${netlogPath}`, '--net-log-capture-mode=Default'] : [],
    proxy: proxyServer ? { server: proxyServer, bypass: 'localhost,127.0.0.1' } : undefined,
  });
  const net = new Map();
  let report;
  try {
    const entry = (id) => net.get(id) ?? net.set(id, { id }).get(id);
    if (chromiumFamily) {
      // Attach DevTools before navigation so every request is observed.
      const page = await browser.context.newPage();
      const cdp = await browser.context.newCDPSession(page);
      await cdp.send('Network.enable');
      cdp.on('Network.requestWillBeSent', (e) => Object.assign(entry(e.requestId), { url: e.request.url, type: e.type }));
      cdp.on('Network.responseReceived', (e) => Object.assign(entry(e.requestId), {
        status: e.response.status,
        protocol: e.response.protocol,
        access_control_allow_origin: e.response.headers['access-control-allow-origin'] ?? null,
      }));
      cdp.on('Network.loadingFailed', (e) => Object.assign(entry(e.requestId), {
        error_text: e.errorText, cors_error: e.corsErrorStatus?.corsError ?? null,
      }));
      cdp.on('Network.webSocketCreated', (e) => Object.assign(entry(e.requestId), { url: e.url, type: 'WebSocket' }));
      cdp.on('Network.webSocketHandshakeResponseReceived', (e) => Object.assign(entry(e.requestId), { ws_handshake_status: e.response.status }));
      cdp.on('Network.webSocketFrameError', (e) => Object.assign(entry(e.requestId), { ws_error: e.errorMessage }));
      const consoleLines = [];
      page.on('console', (m) => consoleLines.push({ type: m.type(), text: m.text() }));
      await page.goto(`${origin}/probe.html?auto`);
      await page.waitForFunction(() => window.__probe !== undefined, null, { timeout: 300_000, polling: 500 });
      report = await page.evaluate(() => window.__probe);
      report.console = consoleLines.filter((l) => /signal\.org/.test(l.text));
    } else {
      const page = await browser.open(`${origin}/probe.html?auto`);
      await page.waitFor('window.__probe !== undefined', 300_000);
      report = await page.evaluate('window.__probe');
      report.console = page.console.filter((l) => /signal\.org/.test(l.text));
    }
  } finally {
    await browser.close();
  }
  const netlog = chromiumFamily ? summarizeNetLog(netlogPath) : null;
  return {
    kind: 'live-browser-network-probe',
    label: 'LIVE network test from an ordinary browser origin; no Signal account or credentials used',
    generated_at: new Date().toISOString(),
    browser_spec: spec,
    browser: browser.version,
    origin: `${origin} (static files only)`,
    request_interception: 'none',
    network_path: proxyServer ? 'explicit HTTPS CONNECT proxy from environment' : 'browser default',
    verdict: verdict(report, netlog),
    page_report: report,
    devtools_network: [...net.values()].filter((r) => r.url && !r.url.startsWith(origin)),
    netlog,
    static_origin_requests: readServerLog(serverLog).map(({ method, path, status }) => ({ method, path, status })),
  };
}

async function main() {
  mkdirSync(outDir, { recursive: true });
  mkdirSync(scratch, { recursive: true });
  const port = Number(process.env.STATIC_PORT ?? 8182);
  const origin = `http://localhost:${port}`;
  const serverLog = join(scratch, 'server-requests.jsonl');
  const server = await startServer(port, serverLog);
  const tag = process.env.PROBE_TAG ? `-${process.env.PROBE_TAG}` : '';
  try {
    for (const spec of browserArgs(process.argv, ['pw:chromium'])) {
      const ev = await probeOne(spec, origin, serverLog);
      const file = join(outDir, `probe-${specSlug(spec)}${tag}.json`);
      writeFileSync(file, JSON.stringify(ev, null, 2) + '\n');
      console.log(`\n=== ${spec} (${ev.browser}) -> ${file}`);
      for (const r of ev.page_report.results) {
        const outcome = r.kind === 'websocket' ? r.events.join(' -> ') : r.ok ? `type=${r.type} status=${r.status}` : r.error;
        console.log(`  ${r.kind.padEnd(13)} ${r.url}\n      page sees: ${outcome}`);
      }
      for (const r of ev.devtools_network) {
        console.log(`  devtools: ${r.url} status=${r.status ?? '-'} error=${r.error_text ?? r.ws_error ?? '-'} cors=${r.cors_error ?? '-'}`);
      }
      for (const c of ev.netlog?.certificate_chains_received ?? []) {
        console.log(`  netlog: ${c.host} leaf issuer="${c.leaf_issuer}" signal_root=${c.includes_signal_root}`);
      }
      console.log(`  VERDICT: ${ev.verdict.validity} - ${ev.verdict.reason}`);
      // Machine-readable copy for CI logs (no secrets: no credentials are used).
      console.log(`PROBE_EVIDENCE_JSON ${JSON.stringify(ev)}`);
    }
  } finally {
    server.kill();
  }
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
