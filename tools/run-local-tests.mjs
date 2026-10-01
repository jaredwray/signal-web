#!/usr/bin/env node
// Local tests that need NO Signal account and NO network access to Signal:
//   1. libsignal-protocol self-test inside browser WASM (web/selftest.html)
//   2. encrypted IndexedDB persistence across a full browser restart
//      (web/storage-test.html), when the browser can keep a profile directory
//
//   node tools/run-local-tests.mjs [--browser <spec>]...   (default: pw:chromium)
//
// Browser specs are documented in tools/browsers.mjs. The runner only observes
// pages; it registers no request interception. Results: evidence/local/*.json.

import { spawn } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { browserArgs, openBrowser, specSlug, toolVersions } from './browsers.mjs';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
// CI points EVIDENCE_OUT at a fresh per-job directory so only this run's
// results are printed, never evidence files committed earlier.
const ciRun = process.env.GITHUB_RUN_ID
  ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
  : null;
const outDir = process.env.EVIDENCE_OUT ?? join(repo, 'evidence', 'local');

export async function startServer(port, logFile) {
  if (logFile) rmSync(logFile, { force: true });
  const proc = spawn(
    process.execPath,
    [join(repo, 'tools/static-server.mjs'), '--root', join(repo, 'web'), '--port', String(port),
      ...(logFile ? ['--log', logFile] : [])],
    { stdio: ['ignore', 'pipe', 'inherit'] },
  );
  await new Promise((resolve, reject) => {
    proc.stdout.on('data', (d) => d.toString().includes('serving') && resolve());
    proc.on('exit', (code) => reject(new Error(`static server exited ${code}`)));
  });
  return proc;
}

export function readServerLog(logFile) {
  if (!existsSync(logFile)) return [];
  return readFileSync(logFile, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
}

function print(title, result) {
  console.log(`${title}: ${result.passed} passed, ${result.failed} failed` +
    (result.aborted ? ` (aborted: ${result.aborted})` : '') + (result.crashed ? ` (crashed: ${result.crashed})` : ''));
  for (const c of result.checks ?? []) {
    console.log(`  ${c.ok ? 'PASS' : 'FAIL'} ${c.name}${c.ms !== undefined ? ` (${c.ms.toFixed(1)} ms)` : ''} ${c.ok ? '' : c.detail}`);
  }
}

async function runOnce(spec, url, globalName, opts = {}) {
  const browser = await openBrowser(spec, opts);
  try {
    const page = await browser.open(url);
    await page.waitFor(`window.${globalName} !== undefined`, 300_000);
    const result = await page.evaluate(`window.${globalName}`);
    const userAgent = await page.evaluate('navigator.userAgent');
    return { result, console: page.console, version: browser.version, userAgent };
  } finally {
    await browser.close();
  }
}

async function runSameSession(spec, urls) {
  const browser = await openBrowser(spec);
  try {
    const results = [];
    let userAgent = null;
    for (const url of urls) {
      // The phases differ only in the URL fragment, and a fragment-only change
      // is a same-document navigation; load about:blank first so every phase
      // runs in a fresh document.
      await browser.open('about:blank');
      const page = await browser.open(url);
      await page.waitFor('window.__storagetest !== undefined', 300_000);
      results.push({ result: await page.evaluate('window.__storagetest'), console: page.console });
      userAgent = await page.evaluate('navigator.userAgent');
    }
    return { ...results[0], version: browser.version, userAgent, second: results[1] };
  } finally {
    await browser.close();
  }
}

async function selftest(spec, origin, meta) {
  const r = await runOnce(spec, `${origin}/selftest.html`, '__selftest');
  const evidence = { ...meta, browser: r.version, user_agent: r.userAgent, ...r.result, console: r.console };
  writeFileSync(join(outDir, `crypto-selftest-${specSlug(spec)}.json`), JSON.stringify(evidence, null, 2) + '\n');
  print(`[${spec}] crypto self-test`, r.result);
  // An abort outside a named check can leave failed == 0; it is still a failure.
  return r.result.failed + (r.result.crashed ? 1 : 0) + (r.result.aborted ? 1 : 0);
}

async function storage(spec, origin, meta) {
  if (!existsSync(join(repo, 'web/storage-test.html'))) {
    throw new Error('web/storage-test.html is missing: the persistence test cannot be skipped');
  }
  // Two separate browser processes sharing one profile directory: phase 1
  // writes encrypted state, the browser is shut down completely, and phase 2
  // starts a fresh browser that must unlock and resume from disk.
  const supportsProfile = !spec.startsWith('wd:safari');
  const profile = supportsProfile ? mkdtempSync(join(tmpdir(), 'signal-web-profile-')) : undefined;
  const passphrase = `test-only-${Math.random().toString(36).slice(2)}`;
  const q = `pass=${encodeURIComponent(passphrase)}`;
  try {
    let p1 = await runOnce(spec, `${origin}/storage-test.html#phase=setup&${q}`, '__storagetest', { userDataDir: profile });
    let p2;
    if (supportsProfile) {
      p2 = await runOnce(spec, `${origin}/storage-test.html#phase=resume&${q}`, '__storagetest', { userDataDir: profile });
    } else {
      // safaridriver sessions do not keep website data between sessions, so a
      // real restart cannot be automated; fall back to a fresh page load in
      // the same session (weaker: same browser process).
      p1 = await runSameSession(spec, [
        `${origin}/storage-test.html#phase=setup&${q}`,
        `${origin}/storage-test.html#phase=resume&${q}`,
      ]);
      p2 = p1.second;
    }
    const evidence = {
      ...meta,
      browser: p1.version,
      user_agent: p1.userAgent,
      restart: supportsProfile
        ? 'separate browser processes sharing one profile directory'
        : 'NOT a browser restart: fresh page load within one automation session (driver limitation)',
      phase_setup: p1.result,
      phase_resume_after_restart: p2.result,
      console: [...(p1.console ?? []), ...(p2.console ?? [])],
    };
    writeFileSync(join(outDir, `storage-test-${specSlug(spec)}.json`), JSON.stringify(evidence, null, 2) + '\n');
    print(`[${spec}] storage phase 1 (setup)`, p1.result);
    print(`[${spec}] storage phase 2 (after browser restart)`, p2.result);
    // Each phase must report the phase that was requested; anything else means
    // a phase did not actually run (e.g. a stale report was read back).
    let mismatch = 0;
    for (const [want, got] of [['setup', p1.result], ['resume', p2.result]]) {
      if (got.skipped) continue;
      if (got.phase !== want) {
        mismatch += 1;
        console.log(`[${spec}] storage ${want}: ERROR report came from phase "${got.phase}"`);
      }
    }
    return mismatch + p1.result.failed + p2.result.failed + (p1.result.crashed ? 1 : 0) + (p2.result.crashed ? 1 : 0);
  } finally {
    if (profile) rmSync(profile, { recursive: true, force: true });
  }
}

async function main() {
  const wasm = join(repo, 'web/pkg/signal_web_core_bg.wasm');
  if (!existsSync(wasm)) {
    console.error('web/pkg/ is missing: build it first with `npm run build:wasm` (see README).');
    process.exit(2);
  }
  mkdirSync(outDir, { recursive: true });
  const specs = browserArgs(process.argv, ['pw:chromium']);
  const port = Number(process.env.STATIC_PORT ?? 8181);
  const logFile = join(tmpdir(), `signal-web-local-${port}.jsonl`);
  const server = await startServer(port, logFile);
  const origin = `http://localhost:${port}`;
  const meta = {
    generated_at: new Date().toISOString(),
    ci_run: ciRun,
    origin,
    request_interception: 'none (pages are only observed)',
    tools: toolVersions(),
    wasm_bytes: readFileSync(join(repo, 'web/pkg/signal_web_core_bg.wasm')).length,
  };
  let failed = 0;
  try {
    for (const spec of specs) {
      // One browser's failure (e.g. a timeout) must not hide the others' results.
      for (const [name, fn] of [['crypto self-test', selftest], ['storage test', storage]]) {
        try {
          failed += await fn(spec, origin, meta);
        } catch (err) {
          failed += 1;
          console.log(`[${spec}] ${name}: ERROR ${String(err.message ?? err).split('\n')[0]}`);
        }
      }
    }
  } finally {
    server.kill();
  }
  const requests = readServerLog(logFile);
  const nonGet = requests.filter((r) => r.method !== 'GET' && r.method !== 'HEAD');
  console.log(`static origin served ${requests.length} requests; non-GET/HEAD: ${nonGet.length}`);
  if (nonGet.length) failed += 1;
  process.exit(failed ? 1 : 0);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  main().catch((err) => {
    console.error(err);
    process.exit(1);
  });
}
