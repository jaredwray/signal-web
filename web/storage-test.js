// Two-phase persistence test (see storage-test.html). Phase 1 ("setup") and
// phase 2 ("resume") run in separate browser processes that share a profile.
import init, { LocalConversation } from './pkg/signal_web_core.js';
import { acquireTabLock } from './lib/tablock.js';
import { Vault, VaultError, rawStore } from './lib/vault.js';

const enc = new TextEncoder();
const dec = new TextDecoder();
const report = { kind: 'local-storage-test', passed: 0, failed: 0, checks: [] };

async function check(name, fn) {
  try {
    const detail = await fn();
    report.passed += 1;
    report.checks.push({ name, ok: true, detail: detail ?? '' });
    return true;
  } catch (err) {
    report.failed += 1;
    report.checks.push({ name, ok: false, detail: String(err?.message ?? err) });
    return false;
  }
}

function assert(cond, msg) {
  if (!cond) throw new Error(msg);
}

async function expectVaultError(code, fn) {
  try {
    await fn();
  } catch (err) {
    if (err instanceof VaultError && err.code === code) return `rejected with ${code}`;
    throw new Error(`expected ${code}, got ${err?.code ?? err}`);
  }
  throw new Error(`expected ${code}, but the operation succeeded`);
}

function exchange(conv, label, n) {
  for (let i = 0; i < n; i++) {
    const a = `${label} a->b ${i} ${crypto.randomUUID()}`;
    assert(conv.aliceToBob(a) === a, `a->b mismatch at ${i}`);
    const b = `${label} b->a ${i} ${crypto.randomUUID()}`;
    assert(conv.bobToAlice(b) === b, `b->a mismatch at ${i}`);
  }
  return `${2 * n} messages decrypted correctly`;
}

function frameLockProbe(timeoutMs = 15000) {
  return new Promise((resolve, reject) => {
    setTimeout(() => reject(new Error('lock probe frame did not report')), timeoutMs);
    const frame = document.createElement('iframe');
    frame.hidden = true;
    window.addEventListener('message', function on(e) {
      if (e.origin !== location.origin || !('tablockAcquired' in e.data)) return;
      window.removeEventListener('message', on);
      frame.remove();
      resolve(e.data.tablockAcquired);
    });
    frame.src = 'tablock-probe.html';
    document.body.append(frame);
  });
}

async function setup(pass) {
  // Firefox asks the user before granting persistent storage, so persist()
  // may never settle under automation; record the outcome without blocking.
  report.storage_persist_granted = await Promise.race([
    navigator.storage?.persist?.().catch(() => null) ?? Promise.resolve(null),
    new Promise((resolve) => setTimeout(() => resolve('no answer within 3 s (permission prompt?)'), 3000)),
  ]);
  await Vault.destroy();
  let vault;
  await check('tablock.this_tab_acquires_lock', async () => {
    assert(await acquireTabLock(), 'could not acquire the tab lock');
    return 'Web Locks lock held by this page';
  });
  await check('tablock.second_context_refused', async () => {
    assert((await frameLockProbe()) === false, 'a second same-origin context acquired the lock');
    return 'a second same-origin context was refused while this page holds the lock';
  });
  await check('vault.create', async () => {
    vault = await Vault.create(pass);
    return 'PBKDF2-SHA256 (600k) -> non-extractable AES-256-GCM key';
  });
  const conv = LocalConversation.create();
  await check('conversation.messages_before_restart', async () => exchange(conv, 'before restart', 5));
  const digest = conv.aliceSessionDigest();
  await check('vault.atomic_commit_and_read_back', async () => {
    const snap = conv.snapshot();
    await vault.commit({ conversation: snap, expect: enc.encode(JSON.stringify({ digest })) });
    const back = await vault.get('conversation');
    assert(back.length === snap.length && back.every((b, i) => b === snap[i]), 'read-back differs');
    return `${snap.length}-byte libsignal state snapshot committed with its expectation record in one transaction`;
  });
  await check('vault.stored_bytes_are_ciphertext', async () => {
    const raw = await rawStore('records', 'conversation');
    const asText = dec.decode(raw.ct);
    assert(!asText.includes('session_hex') && !asText.includes('identity_hex'), 'plaintext structure visible in storage');
    const meta = await rawStore('meta', 'vault');
    assert(JSON.stringify(Object.keys(meta).sort()) === '["check","kdf","v"]', 'unexpected meta fields');
    return 'IndexedDB holds only iv+ciphertext per record and {v, kdf params+salt, key check}; no key';
  });
  await check('vault.reject_wrong_passphrase', async () => expectVaultError('WRONG_PASSPHRASE', () => Vault.unlock(`${pass}x`)));
  vault.close();
  report.expected_session_digest = digest;
}

async function resume(pass) {
  let vault;
  let conv;
  await check('vault.present_after_restart', async () => {
    assert(await Vault.exists(), 'stored state missing after restart');
    return 'IndexedDB state survived the browser restart';
  });
  await check('vault.reject_wrong_passphrase_after_restart', async () =>
    expectVaultError('WRONG_PASSPHRASE', () => Vault.unlock(`${pass}x`)));
  await check('vault.unlock_after_restart', async () => {
    vault = await Vault.unlock(pass);
    return 'unlocked with the passphrase; key re-derived, never stored';
  });
  await check('conversation.restored_state_matches_commit', async () => {
    conv = LocalConversation.fromSnapshot(await vault.get('conversation'));
    const { digest } = JSON.parse(dec.decode(await vault.get('expect')));
    assert(conv.aliceSessionDigest() === digest, 'restored session differs from the committed one');
    return `restored session digest ${digest}`;
  });
  await check('conversation.resume_messaging_after_restart', async () => exchange(conv, 'after restart', 5));
  await check('vault.commit_after_resume', async () => {
    await vault.commit({ conversation: conv.snapshot() });
    LocalConversation.fromSnapshot(await vault.get('conversation'));
    return 'advanced ratchet state committed and reloadable';
  });
  await check('vault.reject_corrupted_record', async () => {
    const raw = await rawStore('records', 'conversation');
    const bad = { ...raw, ct: raw.ct.slice() };
    bad.ct[Math.floor(bad.ct.length / 2)] ^= 0x01;
    await rawStore('records', 'conversation', bad);
    const outcome = await expectVaultError('CORRUPT_RECORD', () => vault.get('conversation'));
    await rawStore('records', 'conversation', raw);
    return `${outcome}; nothing was loaded`;
  });
  await check('vault.reject_swapped_record', async () => {
    const other = await rawStore('records', 'expect');
    const raw = await rawStore('records', 'conversation');
    await rawStore('records', 'conversation', other);
    const outcome = await expectVaultError('CORRUPT_RECORD', () => vault.get('conversation'));
    await rawStore('records', 'conversation', raw);
    return `${outcome} (record id is bound as AES-GCM additional data)`;
  });
  vault.close();
  await check('vault.deleted_storage_detected', async () => {
    await Vault.destroy();
    assert(!(await Vault.exists()), 'state still present');
    await expectVaultError('NO_VAULT', () => Vault.unlock(pass));
    return 'after deletion the client reports NO_VAULT (it must be linked again)';
  });
}

async function run(phase, pass) {
  const started = performance.now();
  await init();
  if (phase === 'setup') await setup(pass);
  else await resume(pass);
  report.phase = phase;
  report.ms = Math.round(performance.now() - started);
  const body = document.querySelector('#results tbody');
  for (const c of report.checks) {
    const tr = document.createElement('tr');
    tr.className = c.ok ? 'pass' : 'fail';
    for (const v of [c.name, c.ok ? 'PASS' : 'FAIL', c.detail]) {
      const td = document.createElement('td');
      td.textContent = v;
      tr.append(td);
    }
    body.append(tr);
  }
  document.querySelector('#summary').textContent = `${phase}: ${report.passed} passed, ${report.failed} failed`;
  window.__storagetest = report;
}

// The test passphrase arrives in the URL fragment, which browsers never send
// to the server, so even this test keeps it away from the hosting origin.
const params = new URLSearchParams(location.hash.slice(1));
if (params.has('phase')) {
  run(params.get('phase'), params.get('pass') ?? '').catch((err) => {
    window.__storagetest = { crashed: String(err), passed: 0, failed: 1, checks: [] };
  });
}
document.querySelector('#manual').addEventListener('submit', (e) => {
  e.preventDefault();
  run(e.submitter.value, document.querySelector('#pass').value);
});
