// Direct-from-browser probes of Signal's service hosts. Endpoints and paths
// come from Signal-Desktop config/production.json and libsignal
// rust/net/src/env.rs (see VALIDATION_REPORT.md). No credentials are sent.
//
// Page JavaScript cannot see *why* a request failed (TLS, DNS, CORS all look
// like "TypeError: Failed to fetch" / WebSocket close 1006 by design), so the
// test runner additionally records Chrome's own console messages, DevTools
// network events and NetLog. This page only reports what it can observe.

export const HTTP_TARGETS = [
  // [label, url, purpose]
  ['chat REST', 'https://chat.signal.org/v1/certificate/delivery', 'core: sender certificate (auth required)'],
  ['chat (grpc host)', 'https://grpc.chat.signal.org/', 'core: libsignal-net chat host'],
  ['storage', 'https://storage.signal.org/v1/storage/manifest', 'storage service (auth required)'],
  ['cdn0', 'https://cdn.signal.org/attachments/probe-nonexistent', 'attachment download path'],
  ['cdn2', 'https://cdn2.signal.org/attachments/probe-nonexistent', 'attachment download path'],
  ['cdn3', 'https://cdn3.signal.org/attachments/probe-nonexistent', 'attachment download path'],
  ['cdsi', 'https://cdsi.signal.org/', 'contact discovery (enclave)'],
  ['svr2', 'https://svr2.signal.org/', 'secure value recovery (enclave)'],
  ['CONTROL updates', 'https://updates.signal.org/desktop/latest.yml', 'control: Signal host with a publicly trusted certificate'],
];

export const WS_TARGETS = [
  ['provisioning (chat)', 'wss://chat.signal.org/v1/websocket/provisioning/', 'core: linking'],
  ['provisioning (grpc host)', 'wss://grpc.chat.signal.org/v1/websocket/provisioning/', 'core: linking via libsignal-net host'],
  ['CONTROL updates', 'wss://updates.signal.org/v1/websocket/provisioning/', 'control: publicly trusted certificate, not a WebSocket endpoint'],
];

async function probeFetch(url, mode, timeoutMs = 20000) {
  const started = performance.now();
  const out = { kind: `fetch/${mode}`, url };
  const abort = new AbortController();
  const timer = setTimeout(() => abort.abort(), timeoutMs);
  try {
    // The Fetch Standard rejects mode "no-cors" unless redirect is "follow".
    const res = await fetch(url, {
      mode, credentials: 'omit', cache: 'no-store', redirect: mode === 'no-cors' ? 'follow' : 'manual', signal: abort.signal,
    });
    out.ok = true; // the promise resolved; see `readable` for a usable response
    out.type = res.type;
    out.status = res.status;
    // Usable only if the page can read it: an "opaque" (no-cors) or
    // "opaqueredirect" response exposes neither status nor body.
    out.readable = res.type === 'cors' || res.type === 'basic';
    // Only headers exposed by CORS are readable from page JS.
    out.readable_headers = [...res.headers.keys()];
    if (mode === 'cors') out.body_bytes = (await res.arrayBuffer()).byteLength;
  } catch (err) {
    out.ok = false;
    out.readable = false;
    out.error = abort.signal.aborted ? `timeout after ${timeoutMs} ms` : `${err.name}: ${err.message}`;
  } finally {
    clearTimeout(timer);
  }
  out.ms = Math.round(performance.now() - started);
  return out;
}

function probeWebSocket(url, timeoutMs = 15000) {
  return new Promise((resolve) => {
    const started = performance.now();
    const out = { kind: 'websocket', url, events: [] };
    let ws;
    const finish = () => {
      out.ms = Math.round(performance.now() - started);
      try { ws?.close(); } catch {}
      resolve(out);
    };
    const timer = setTimeout(() => { out.events.push('timeout'); finish(); }, timeoutMs);
    try {
      ws = new WebSocket(url);
      ws.binaryType = 'arraybuffer';
    } catch (err) {
      out.events.push(`constructor threw ${err.name}: ${err.message}`);
      clearTimeout(timer);
      return finish();
    }
    ws.onopen = () => out.events.push('open');
    ws.onerror = () => out.events.push('error');
    ws.onmessage = (e) => {
      // Never record contents; size and type only.
      const size = typeof e.data === 'string' ? e.data.length : e.data.byteLength;
      out.events.push(`message(${typeof e.data === 'string' ? 'text' : 'binary'}, ${size} bytes)`);
      clearTimeout(timer);
      finish();
    };
    ws.onclose = (e) => {
      out.events.push(`close(code=${e.code}, wasClean=${e.wasClean}, reason=${JSON.stringify(e.reason)})`);
      clearTimeout(timer);
      finish();
    };
  });
}

export async function runProbe() {
  const results = [];
  for (const [label, url, purpose] of HTTP_TARGETS) {
    // A CORS request is what a real client needs: the page must read the response.
    results.push({ label, purpose, ...(await probeFetch(url, 'cors')) });
    // A no-cors request yields an unreadable "opaque" response when the TLS
    // connection and HTTP exchange succeed, and a TypeError when they do not.
    // It is used ONLY as a reachability diagnostic, never as a usable response.
    results.push({ label, purpose: `${purpose} [reachability diagnostic only]`, ...(await probeFetch(url, 'no-cors')) });
  }
  for (const [label, url, purpose] of WS_TARGETS) {
    results.push({ label, purpose, ...(await probeWebSocket(url)) });
  }
  return {
    kind: 'browser-network-probe',
    origin: location.origin,
    user_agent: navigator.userAgent,
    secure_context: isSecureContext,
    at: new Date().toISOString(),
    results,
  };
}

function render(report) {
  const body = document.querySelector('#results tbody');
  body.textContent = '';
  for (const r of report.results) {
    const tr = document.createElement('tr');
    const outcome = r.kind === 'websocket'
      ? r.events.join(' → ')
      : r.ok ? `response type=${r.type} status=${r.status}` : r.error;
    for (const v of [`${r.label}: ${r.url}`, r.kind, outcome]) {
      const td = document.createElement('td');
      td.textContent = v;
      tr.append(td);
    }
    body.append(tr);
  }
  document.querySelector('#raw').textContent = JSON.stringify(report, null, 2);
  document.querySelector('#summary').textContent = `done at ${report.at}`;
}

document.querySelector('#run').addEventListener('click', async () => {
  document.querySelector('#summary').textContent = 'running…';
  const report = await runProbe();
  render(report);
  window.__probe = report;
});

if (new URLSearchParams(location.search).has('auto')) {
  document.querySelector('#run').click();
}
