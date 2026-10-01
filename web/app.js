// Minimal UI for the linking step. All Signal traffic goes directly from this
// page to Signal's servers; this origin only serves static files.
import init, { libsignalVersion, ProvisioningSession } from './pkg/signal_web_core.js';
import { acquireTabLock } from './lib/tablock.js';

const PROVISIONING_URL = 'wss://chat.signal.org/v1/websocket/provisioning/';
const $ = (s) => document.querySelector(s);

function status(text, ok) {
  const el = $('#link-status');
  el.textContent = text;
  el.className = ok === undefined ? '' : ok ? 'status-ok' : 'status-bad';
}

function bytesFromB64(b64) {
  return Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
}

function startLinking() {
  $('#link').disabled = true;
  $('#qr').hidden = true;
  const session = new ProvisioningSession();
  let gotAddress = false;
  let done = false;
  status(`Connecting to ${PROVISIONING_URL} …`);

  const ws = new WebSocket(PROVISIONING_URL);
  ws.binaryType = 'arraybuffer';
  ws.onopen = () => status('Connected. Waiting for a provisioning address from Signal…');
  ws.onmessage = (e) => {
    if (typeof e.data === 'string') return status('Unexpected text frame; aborting.', false);
    let event;
    try {
      event = JSON.parse(session.handleFrame(new Uint8Array(e.data)));
    } catch (err) {
      ws.close();
      return status(`Rejected a provisioning frame: ${err.message ?? err}`, false);
    }
    if (event.ack_b64) ws.send(bytesFromB64(event.ack_b64));
    if (event.event === 'address') {
      gotAddress = true;
      const svg = session.linkQrSvg();
      if (!svg) {
        done = true;
        ws.close();
        return status('Could not render the link as a QR code.', false);
      }
      $('#qr-img').src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(svg)}`;
      $('#qr').hidden = false;
      status('Scan the QR code with the phone to approve this device.');
    } else if (event.event === 'provisioned') {
      done = true;
      ws.close();
      $('#qr').hidden = true;
      status(
        `Phone approved and the provisioning message decrypted (ACI ${event.summary.aci}). ` +
        'Registering the device (PUT /v1/devices/link) is NOT implemented in this spike; ' +
        'see VALIDATION_REPORT.md.', true);
    }
  };
  ws.onclose = (e) => {
    $('#link').disabled = false;
    if (done) return;
    if (!gotAddress) {
      status(
        `Could not establish the provisioning connection (WebSocket closed, code ${e.code}, ` +
        'before any data arrived). Browsers do not reveal the reason to pages; the developer ' +
        'console shows the network error. In our tests the browser rejected the server ' +
        'certificate: chat.signal.org uses a certificate from Signal\'s private root CA, which ' +
        'browsers do not trust. See VALIDATION_REPORT.md.', false);
    } else {
      $('#qr').hidden = true;
      status(`Provisioning connection closed (code ${e.code}) before approval. Start again.`, false);
    }
  };
}

async function main() {
  // One active tab per browser profile: protocol state must have one writer.
  const lock = await acquireTabLock();
  if (lock !== 'acquired') {
    $('#env').textContent = lock === 'held-elsewhere'
      ? 'signal-web is already open in another tab of this browser. Close it first.'
      : `Cannot guarantee a single active tab (Web Locks ${lock}); refusing to start.`;
    return;
  }
  await init();
  $('#env').textContent = `libsignal ${libsignalVersion()} loaded in WebAssembly.`;
  $('#link').disabled = false;
  $('#link').addEventListener('click', startLinking);
}

main().catch((err) => {
  $('#env').textContent = `Failed to start: ${err}`;
});
