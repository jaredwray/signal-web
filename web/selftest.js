// Runs the Rust/WASM self-test (crates/signal-web-core/src/selftest.rs) and
// renders the report. The report is also exposed as window.__selftest so the
// Playwright runner can collect it.
import init, { libsignalVersion, runProtocolSelftest, runProvisioningSelftest } from './pkg/signal_web_core.js';

const $ = (sel) => document.querySelector(sel);

async function main() {
  const t0 = performance.now();
  await init();
  const loadMs = performance.now() - t0;
  $('#env').textContent =
    `libsignal ${libsignalVersion()} · WASM instantiated in ${loadMs.toFixed(1)} ms · ` +
    `crossOriginIsolated=${self.crossOriginIsolated} · ${navigator.userAgent}`;

  const report = JSON.parse(await runProtocolSelftest());
  // Linked-device provisioning crypto/framing, checked against an independent
  // test vector produced by scripts/make_provisioning_vector.py.
  const vector = await (await fetch('testdata/provisioning-vector.json')).text();
  const prov = JSON.parse(await runProvisioningSelftest(vector));
  report.checks.push(...prov.checks);
  report.passed += prov.passed;
  report.failed += prov.failed;
  if (prov.aborted) report.aborted = [report.aborted, prov.aborted].filter(Boolean).join('; ');
  report.wasm_instantiate_ms = loadMs;
  report.user_agent = navigator.userAgent;

  const body = $('#results tbody');
  for (const c of report.checks) {
    const tr = document.createElement('tr');
    tr.className = c.ok ? 'pass' : 'fail';
    for (const v of [c.name, c.ok ? 'PASS' : 'FAIL', c.ms.toFixed(1), c.detail]) {
      const td = document.createElement('td');
      td.textContent = v;
      tr.append(td);
    }
    body.append(tr);
  }
  $('#summary').textContent =
    `${report.passed} passed, ${report.failed} failed` +
    (report.aborted ? ` (stopped: ${report.aborted})` : '');
  window.__selftest = report;
}

main().catch((err) => {
  $('#summary').textContent = `Self-test crashed: ${err}`;
  window.__selftest = { crashed: String(err), passed: 0, failed: 1, checks: [] };
});
