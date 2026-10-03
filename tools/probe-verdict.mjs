// Verdict logic for tools/run-probe.mjs, kept separate so it can be tested
// offline (tools/test-probe-verdict.mjs) against fixed inputs.
import { X509Certificate } from 'node:crypto';
import { readFileSync } from 'node:fs';

export const SIGNAL_ROOT_SHA256 =
  'DD:B0:F9:2B:B9:5C:8D:6F:D2:02:EA:6E:8C:C5:CC:D1:82:B5:44:F8:CD:69:6F:47:D5:80:65:9D:DC:9D:F6:5A';

// Top-level navigation targets: the browser's own TLS verdict per host.
export const CONTROL_HOST = 'updates.signal.org'; // publicly trusted certificate
export const SIGNAL_HOSTS = [
  'chat.signal.org', 'grpc.chat.signal.org', 'storage.signal.org', 'cdn.signal.org',
  'cdn2.signal.org', 'cdn3.signal.org', 'cdsi.signal.org', 'svr2.signal.org',
];
export const NAV_HOSTS = [...SIGNAL_HOSTS, CONTROL_HOST];
// The control's root URL is served as a download, which never commits a page;
// a missing path returns an ordinary HTML 404 page from the same host.
export const navUrl = (host) => (host === CONTROL_HOST ? `https://${host}/probe-nonexistent` : `https://${host}/`);
// Errors that name a certificate problem specifically: Chromium net errors,
// NSS/mozilla::pkix codes, WebKit's wording, the W3C WebDriver error code, and
// a browser certificate warning page detected by tools/browsers.mjs. Other TLS
// failures (e.g. WebSocket close 1015) are recorded separately.
export const CERT_ERROR = new RegExp([
  'ERR_CERT_', 'SEC_ERROR_UNKNOWN_ISSUER', 'SEC_ERROR_UNTRUSTED_ISSUER', 'MOZILLA_PKIX_ERROR_',
  'SSL_ERROR_BAD_CERT_DOMAIN', 'insecure certificate', 'Unacceptable TLS certificate',
  'certificate for this server is invalid', 'browser certificate warning page',
].join('|'));
export const coversHost = (name, host) => name === host ||
  (name.startsWith('*.') && host.endsWith(name.slice(1)) && host.split('.').length === name.split('.').length);
export function summarizeNetLog(path) {
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
      const names = (leaf.subjectAltName ?? '').split(',').map((n) => n.trim())
        .filter((n) => n.startsWith('DNS:')).map((n) => n.slice(4));
      // One entry per (names, issuer): repeated connections add nothing, but
      // a different issuer for the same host must stay visible.
      chains.set(`${names.join(',')}|${leaf.issuer}`, {
        host: names[0] ?? null,
        names,
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

// A CORS response the page can actually read (not opaque, not a redirect).
export const isReadable = (r) => Boolean(r && (r.readable ?? (r.ok && (r.type === 'cors' || r.type === 'basic'))));

export function verdict(report, netlog, navigation, devtools, { chromiumFamily }) {
  const chains = netlog?.certificate_chains_received ?? [];
  const pageCors = (host) => report.results.find((r) => r.kind === 'fetch/cors' && new URL(r.url).host === host);
  const ws = (host) => report.results.find((r) => r.kind === 'websocket' && new URL(r.url).host === host);
  const chainFor = (host) => chains.find((c) => (c.names ?? [c.host]).some((n) => coversHost(n, host)));
  const hosts = {};
  for (const host of NAV_HOSTS) {
    const nav = navigation[host];
    const dt = devtools.filter((d) => d.url && new URL(d.url).host === host)
      .map((d) => d.error_text || d.ws_error).filter(Boolean);
    const wsr = ws(host);
    hosts[host] = {
      page_cors_fetch_readable: pageCors(host) ? isReadable(pageCors(host)) : null,
      page_websocket: wsr ? wsr.events.join(' -> ') : null,
      navigation: nav,
      netlog_leaf_issuer: chainFor(host)?.leaf_issuer ?? null,
      devtools_errors: [...new Set(dt)],
      // The browser itself named a certificate problem (navigation error,
      // certificate warning page, or a DevTools net error).
      certificate_rejected_by_browser:
        Boolean(nav && !nav.ok && CERT_ERROR.test(nav.error)) || dt.some((e) => CERT_ERROR.test(e)),
      // A TLS handshake failure with no stated cause (WebSocket close 1015).
      tls_handshake_failed_unspecified: Boolean(wsr?.events.some((e) => e.startsWith('close(code=1015'))),
      // Weakest: a top-level navigation did not reach the host.
      navigation_failed: Boolean(nav && !nav.ok),
    };
  }
  const v = { hosts };
  const control = hosts[CONTROL_HOST];
  // Interception check (Chromium family only, from the NetLog): every chain
  // received for a Signal service host must be issued by Signal's own CA.
  // Chains for unrelated hosts (browser background traffic) are ignored.
  const signalChains = chains.filter((c) => SIGNAL_HOSTS.some((h) => (c.names ?? [c.host]).some((n) => coversHost(n, h))));
  const foreign = signalChains.filter((c) => !/Signal Messenger/.test(c.leaf_issuer));
  v.interception_check = chromiumFamily
    ? `NetLog: ${signalChains.length} certificate chain(s) received for Signal service hosts, ${foreign.length} not issued by Signal Messenger`
    : 'no NetLog in this browser; relies on the control host being accepted while Signal hosts were not';
  if (foreign.length || control.certificate_rejected_by_browser) {
    v.validity = 'INVALID_FOR_SIGNAL_CONCLUSIONS';
    v.reason = 'the network re-terminated TLS (a Signal host chain from a foreign issuer, or the publicly trusted control was rejected)';
  } else if (chromiumFamily && !signalChains.length) {
    v.validity = 'INCONCLUSIVE';
    v.reason = `no certificate chain for a Signal host in the NetLog${netlog?.error ? ` (${netlog.error})` : ''}; interception cannot be ruled out`;
  } else if (!control.page_cors_fetch_readable && !(control.navigation?.ok)) {
    v.validity = 'INCONCLUSIVE';
    v.reason = 'the publicly trusted control host was unreachable from this browser';
  } else {
    v.validity = 'VALID';
    const rejected = SIGNAL_HOSTS.filter((h) => hosts[h].certificate_rejected_by_browser);
    const tlsFailed = SIGNAL_HOSTS.filter((h) => hosts[h].tls_handshake_failed_unspecified);
    const navFailed = SIGNAL_HOSTS.filter((h) => hosts[h].navigation_failed);
    const pageReadable = SIGNAL_HOSTS.filter((h) => hosts[h].page_cors_fetch_readable);
    v.reason = `control reachable; browser named a certificate problem for ${rejected.length}/${SIGNAL_HOSTS.length} Signal service hosts` +
      `; top-level navigation failed for ${navFailed.length}/${SIGNAL_HOSTS.length}; page-readable Signal responses: ${pageReadable.length}`;
    v.signal_hosts_certificate_rejected = rejected;
    v.signal_hosts_tls_handshake_failed_unspecified = tlsFailed;
    v.signal_hosts_navigation_failed = navFailed;
    v.signal_hosts_page_readable = pageReadable;
  }
  return v;
}
