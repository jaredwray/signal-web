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

import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { browserArgs, openBrowser, parseSpec, specSlug, toolVersions } from './browsers.mjs';
import { NAV_HOSTS, navUrl, summarizeNetLog, verdict } from './probe-verdict.mjs';
import { readServerLog, startServer } from './run-local-tests.mjs';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');

if (process.env.SIGNAL_WEB_LIVE !== '1') {
  console.error('This probe contacts Signal servers. Re-run with SIGNAL_WEB_LIVE=1 to opt in.');
  process.exit(2);
}

// CI points EVIDENCE_OUT at a fresh per-job directory so only this run's
// results are printed, never evidence files committed earlier.
const ciRun = process.env.GITHUB_RUN_ID
  ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
  : null;
const outDir = process.env.EVIDENCE_OUT ?? join(repo, 'evidence', 'live');
const scratch = process.env.PROBE_SCRATCH_DIR ?? join(tmpdir(), 'signal-web-probe');

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
  const navigation = {};
  let appLink = null;
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
      await page.waitFor(() => window.__probe !== undefined, undefined, 300_000);
      report = await page.evaluate(() => window.__probe);
      report.console = page.console.filter((l) => /signal\.org/.test(l.text));
    }
    // The real app's linking attempt, as a user would start it. Failures here
    // are recorded (with the page's own status text) rather than aborting.
    const app = await browser.open(`${origin}/index.html`);
    const text = (sel) => app.evaluate((s) => document.querySelector(s)?.textContent ?? null, sel).catch(() => null);
    try {
      await app.waitFor(() => { const el = document.querySelector('#link'); return !!el && !el.disabled; }, undefined, 60_000);
      await app.evaluate(() => document.querySelector('#link').click());
      await app.waitFor(() => /Could not|Scan|approved|closed/.test(document.querySelector('#link-status')?.textContent ?? ''), undefined, 60_000);
      appLink = {
        status_text: await text('#link-status'),
        qr_shown: await app.evaluate(() => !document.querySelector('#qr').hidden),
      };
    } catch (err) {
      appLink = {
        error: String(err.message ?? err).split('\n')[0],
        env_text: await text('#env'),
        status_text: await text('#link-status'),
      };
    }
    // Then the browser's own TLS verdict per host via top-level navigation
    // (last, because certificate-warning pages can disturb later automation).
    for (const host of NAV_HOSTS) {
      navigation[host] = await browser.navigate(navUrl(host));
    }
  } finally {
    await browser.close();
  }
  const netlog = chromiumFamily ? summarizeNetLog(netlogPath) : null;
  return {
    kind: 'live-browser-network-probe',
    label: 'LIVE network test from an ordinary browser origin; no Signal account or credentials used',
    generated_at: new Date().toISOString(),
    ci_run: ciRun,
    browser_spec: spec,
    browser: browser.version,
    tools: toolVersions(),
    origin: `${origin} (static files only)`,
    request_interception: 'none',
    network_path: proxyServer ? 'explicit HTTPS CONNECT proxy from environment' : 'browser default',
    verdict: verdict(report, netlog, navigation, [...net.values()], { chromiumFamily }),
    navigation,
    app_link_attempt: appLink,
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
      let ev;
      try {
        ev = await probeOne(spec, origin, serverLog);
      } catch (err) {
        process.exitCode = 1;
        console.log(`\n=== ${spec}: ERROR ${String(err.message ?? err).split('\n')[0]}`);
        continue;
      }
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
      for (const [host, nav] of Object.entries(ev.navigation)) {
        console.log(`  navigate ${navUrl(host)} -> ${nav.ok ? `ok ${nav.status ?? ''}` : nav.error}`);
      }
      console.log(`  app link attempt: QR shown=${ev.app_link_attempt?.qr_shown} status="${ev.app_link_attempt?.status_text?.slice(0, 90)}..."`);
      console.log(`  VERDICT: ${ev.verdict.validity} - ${ev.verdict.reason} [interception check: ${ev.verdict.interception_check}]`);
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
