#!/usr/bin/env node
// Runs libsignal's own rust/protocol/tests (prepared by
// scripts/prepare-upstream-tests.sh) inside Chromium.
//
// wasm-bindgen-test-runner is started in its interactive mode (NO_HEADLESS=1),
// where it only serves a page that runs the tests; a browser (see
// tools/browsers.mjs, default pw:chromium) opens that page and the runner's own
// output is read back. No request interception is used.
//
//   node tools/run-upstream-tests.mjs [--browser <spec>]... [--include-ignored]
//
// Results go to evidence/local/upstream-tests-<browser>.json.

import { execFileSync, spawn } from 'node:child_process';
import { mkdirSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { browserArgs, openBrowser, specSlug, toolVersions } from './browsers.mjs';

const repo = join(dirname(fileURLToPath(import.meta.url)), '..');
// CI points EVIDENCE_OUT at a fresh per-job directory so only this run's
// results are printed, never evidence files committed earlier.
const ciRun = process.env.GITHUB_RUN_ID
  ? `${process.env.GITHUB_SERVER_URL}/${process.env.GITHUB_REPOSITORY}/actions/runs/${process.env.GITHUB_RUN_ID}`
  : null;
const outDir = process.env.EVIDENCE_OUT ?? join(repo, 'evidence', 'local');
mkdirSync(outDir, { recursive: true });

function buildTests() {
  const out = execFileSync('cargo', [
    'test', '--release', '--target', 'wasm32-unknown-unknown',
    '-p', 'upstream-protocol-tests', '--no-run', '--message-format=json',
  ], { cwd: repo, encoding: 'utf8', maxBuffer: 1 << 28, stdio: ['ignore', 'pipe', 'inherit'] });
  return out.split('\n').filter(Boolean).map((l) => JSON.parse(l))
    .filter((m) => m.reason === 'compiler-artifact' && m.executable && m.target.kind.includes('test'))
    .map((m) => ({ name: m.target.name, wasm: m.executable }));
}

async function runOne(spec, test, port) {
  const extra = process.argv.includes('--include-ignored') ? ['--include-ignored'] : [];
  const runner = spawn('wasm-bindgen-test-runner', [test.wasm, ...extra], {
    env: { ...process.env, NO_HEADLESS: '1', WASM_BINDGEN_TEST_ADDRESS: `127.0.0.1:${port}` },
    stdio: ['ignore', 'pipe', 'pipe'],
  });
  let browser;
  try {
    await new Promise((resolve, reject) => {
      runner.stdout.on('data', (d) => d.toString().includes('available at') && resolve());
      runner.on('exit', (code) => reject(new Error(`runner exited ${code}`)));
    });
    browser = await openBrowser(spec);
    const started = Date.now();
    const page = await browser.open(`http://127.0.0.1:${port}/`);
    await page.waitFor(
      () => /test result: (ok|FAILED)/.test(document.getElementById('output')?.textContent ?? ''),
      undefined,
      30 * 60_000,
    );
    const output = await page.evaluate(() => document.getElementById('output').textContent);
    const tests = [...output.matchAll(/^test (\S+) \.\.\. (ok|FAIL|FAILED|ignored)/gm)]
      .map(([, name, status]) => ({ name, status }));
    const summary = output.match(/test result: .*/)?.[0] ?? 'missing summary';
    return { binary: test.name, wasm: basename(test.wasm), browser: browser.version, seconds: (Date.now() - started) / 1000, summary, tests, output };
  } finally {
    await browser?.close();
    runner.kill();
  }
}

async function main() {
  const tests = buildTests().filter((t) => t.name !== 'upstream_protocol_tests');
  const includeIgnored = process.argv.includes('--include-ignored');
  let anyBad = false;
  let port = Number(process.env.UPSTREAM_TEST_PORT ?? 8300);
  for (const spec of browserArgs(process.argv, ['pw:chromium'])) {
    const results = [];
    for (const t of tests) {
      let r;
      try {
        r = await runOne(spec, t, port++);
      } catch (err) {
        r = { binary: t.name, summary: `ERROR ${String(err.message ?? err).split('\n')[0]}`, tests: [], seconds: 0 };
      }
      console.log(`[${spec}] ${r.binary}: ${r.summary} (${r.seconds.toFixed(1)} s)`);
      for (const x of r.tests.filter((x) => x.status !== 'ok')) console.log(`  ${x.status} ${x.name}`);
      results.push(r);
    }
    const counts = results.flatMap((r) => r.tests).reduce((acc, t) => {
      acc[t.status] = (acc[t.status] ?? 0) + 1;
      return acc;
    }, {});
    const file = `upstream-tests-${includeIgnored ? 'including-ignored-' : ''}${specSlug(spec)}.json`;
    writeFileSync(join(outDir, file), JSON.stringify({
      kind: 'upstream-libsignal-protocol-tests-in-browser',
      label: 'LOCAL tests from libsignal rust/protocol/tests; not a live Signal test',
      libsignal_rev: 'e8cc2dddd578859b4a029c9c94670b24ce2b616a',
      transforms: 'scripts/wasmify_upstream_tests.py (#[test] attribute + SystemTime::now() shim only)',
      generated_at: new Date().toISOString(),
      ci_run: ciRun,
      browser_spec: spec,
      browser: results[0]?.browser,
      tools: toolVersions(),
      request_interception: 'none',
      include_ignored: includeIgnored,
      counts,
      results,
    }, null, 2) + '\n');
    console.log(`[${spec}] totals:`, counts);
    anyBad ||= results.some((r) => !r.summary.startsWith('test result: ok'));
  }
  process.exit(anyBad ? 1 : 0);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
