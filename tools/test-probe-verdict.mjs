#!/usr/bin/env node
// Offline tests for the live-probe verdict (tools/probe-verdict.mjs). The
// inputs mirror what real runs recorded; no network access is involved.
//   node tools/test-probe-verdict.mjs
import assert from 'node:assert/strict';
import { CERT_ERROR, CONTROL_HOST, SIGNAL_HOSTS, coversHost, isReadable, verdict } from './probe-verdict.mjs';

const SIGNAL_ISSUER = 'C=US, ST=California, L=Mountain View, O=Signal Messenger\\, LLC, CN=Signal Messenger';
const chain = (host, issuer) => ({ host, names: [host], leaf_issuer: issuer, includes_signal_root: false });
const signalChains = SIGNAL_HOSTS.map((h) => chain(h, SIGNAL_ISSUER));
const controlChain = chain(CONTROL_HOST, 'C=US, O=Google Trust Services, CN=WE1');
const controlOk = [
  { kind: 'fetch/cors', url: `https://${CONTROL_HOST}/desktop/latest.yml`, ok: true, type: 'cors', status: 200, readable: true },
  { kind: 'websocket', url: `wss://${CONTROL_HOST}/v1/websocket/provisioning/`, events: ['error', 'close(code=1006, wasClean=false, reason="")'] },
];
const signalFetchFailed = SIGNAL_HOSTS.map((h) => ({ kind: 'fetch/cors', url: `https://${h}/`, ok: false, readable: false, error: 'TypeError: Failed to fetch' }));
const nav = (error) => Object.fromEntries([
  ...SIGNAL_HOSTS.map((h) => [h, { ok: false, error }]),
  [CONTROL_HOST, { ok: true, status: 404 }],
]);
const run = (results, netlog, navigation, devtools = [], chromiumFamily = true) =>
  verdict({ results }, netlog, navigation, devtools, { chromiumFamily });

const cases = {
  // Edge's own background traffic is issued by Microsoft CAs; it must not be
  // mistaken for interception of Signal traffic.
  'edge background chains are ignored'() {
    const v = run([...controlOk, ...signalFetchFailed], {
      certificate_chains_received: [
        chain('edge.microsoft.com', 'C=US, O=Microsoft Corporation, CN=Microsoft TLS G2 RSA CA OCSP 16'),
        chain('*.bing.com', 'C=US, O=Microsoft Corporation, CN=Microsoft TLS G2 ECC CA OCSP 02'),
        ...signalChains, controlChain,
      ],
    }, nav('page.goto: net::ERR_CERT_AUTHORITY_INVALID at https://chat.signal.org/'));
    assert.equal(v.validity, 'VALID', v.reason);
    assert.equal(v.signal_hosts_certificate_rejected.length, SIGNAL_HOSTS.length);
  },
  'a Signal host chain from a foreign issuer means interception'() {
    const v = run([...controlOk, ...signalFetchFailed], {
      certificate_chains_received: [...SIGNAL_HOSTS.map((h) => chain(h, 'CN=Some Proxy CA')), controlChain],
    }, nav('page.goto: net::ERR_CERT_AUTHORITY_INVALID'));
    assert.equal(v.validity, 'INVALID_FOR_SIGNAL_CONCLUSIONS');
  },
  'a rejected control means the network is not usable for conclusions'() {
    const navigation = nav('page.goto: net::ERR_CERT_AUTHORITY_INVALID');
    navigation[CONTROL_HOST] = { ok: false, error: 'page.goto: net::ERR_CERT_AUTHORITY_INVALID' };
    const v = run(signalFetchFailed, { certificate_chains_received: signalChains }, navigation);
    assert.equal(v.validity, 'INVALID_FOR_SIGNAL_CONCLUSIONS');
  },
  'a Chromium run without Signal chains in the NetLog is inconclusive'() {
    const v = run([...controlOk, ...signalFetchFailed], { error: 'could not parse NetLog: ENOENT' },
      nav('page.goto: net::ERR_CERT_AUTHORITY_INVALID'));
    assert.equal(v.validity, 'INCONCLUSIVE');
  },
  'Safari: certificate warning page counts as a named certificate problem'() {
    const v = run([...controlOk, ...signalFetchFailed], null,
      nav('browser certificate warning page: "This Connection Is Not Private"'), [], false);
    assert.equal(v.validity, 'VALID');
    assert.equal(v.signal_hosts_certificate_rejected.length, SIGNAL_HOSTS.length);
    assert.match(v.interception_check, /no NetLog/);
  },
  'WebSocket close 1015 alone is an unspecified TLS failure, not a certificate rejection'() {
    const ws = SIGNAL_HOSTS.slice(0, 2).map((h) => ({
      kind: 'websocket', url: `wss://${h}/v1/websocket/provisioning/`, events: ['error', 'close(code=1015, wasClean=false, reason="")'],
    }));
    const navigation = nav('page.goto: NS_ERROR_NET_RESET');
    const v = run([...controlOk, ...signalFetchFailed, ...ws], null, navigation, [], false);
    assert.equal(v.validity, 'VALID');
    assert.equal(v.signal_hosts_certificate_rejected.length, 0);
    assert.equal(v.signal_hosts_tls_handshake_failed_unspecified.length, 2);
    assert.equal(v.signal_hosts_navigation_failed.length, SIGNAL_HOSTS.length);
  },
  'certificate-specific error names only'() {
    for (const e of ['net::ERR_CERT_AUTHORITY_INVALID', 'SEC_ERROR_UNKNOWN_ISSUER', 'insecure certificate: x',
      'Unacceptable TLS certificate', 'MOZILLA_PKIX_ERROR_SELF_SIGNED_CERT']) assert.ok(CERT_ERROR.test(e), e);
    for (const e of ['SSL_ERROR_NO_CYPHER_OVERLAP', 'net::ERR_SSL_PROTOCOL_ERROR', 'NS_ERROR_NET_RESET',
      'navigation did not reach chat.signal.org']) assert.ok(!CERT_ERROR.test(e), e);
  },
  'only cors/basic responses are readable'() {
    assert.ok(isReadable({ ok: true, type: 'cors', status: 200 }));
    assert.ok(!isReadable({ ok: true, type: 'opaque', status: 0 }));
    assert.ok(!isReadable({ ok: true, type: 'opaqueredirect', status: 0 }));
    assert.ok(!isReadable({ ok: false }));
  },
  'wildcard names cover exactly one label'() {
    assert.ok(coversHost('*.signal.org', 'cdn.signal.org'));
    assert.ok(!coversHost('*.signal.org', 'grpc.chat.signal.org'));
    assert.ok(coversHost('chat.signal.org', 'chat.signal.org'));
  },
};

let failed = 0;
for (const [name, fn] of Object.entries(cases)) {
  try {
    fn();
    console.log(`PASS ${name}`);
  } catch (err) {
    failed += 1;
    console.log(`FAIL ${name}: ${err.message}`);
  }
}
console.log(`${Object.keys(cases).length - failed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
