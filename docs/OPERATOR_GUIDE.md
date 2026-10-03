# Operator guide

This guide is for a person who wants to reproduce the browser results on their own computer,
and for the phone-side steps the linking test would need. Nothing here asks you to share keys,
verification codes, or passwords with anyone, including an AI agent.

## 0. Ground rules

- Use an **authorized test account** on a test phone, never a personal Signal installation.
- Do not import data from Signal Desktop or any other client.
- Never click through a browser certificate warning for a `signal.org` host. That disables the
  very check this experiment is testing, and it is outside the project's constraints.
- Send no unsolicited messages. Do not retry failures in a loop.

## 1. Build and serve the static site

```sh
cargo install wasm-bindgen-cli --version 0.2.129 --locked
npm ci
npm run build:wasm
npm run serve        # http://localhost:8080/
```

The server only answers GET/HEAD for files under `web/`. Any page served from `localhost`
is a secure context, so WebCrypto, IndexedDB, and Web Locks behave as they would over HTTPS.

## 2. Reproduce the network result in your own browsers (no account needed)

1. Open `http://localhost:8080/probe.html` in Chrome, Edge, Firefox, and Safari.
2. Open the developer tools console (Safari: enable the Develop menu first).
3. Click **Run probe** and wait about 30 seconds.

What to expect (from the clean-network CI runs in `evidence/ci/`):

| Target | Page sees | Browser console / devtools |
|---|---|---|
| `https://updates.signal.org/...` (control: public certificate) | `response type=cors status=200` | normal request |
| `https://chat.signal.org/...` and every other Signal service host | `TypeError` (fetch) | Chrome/Edge: `net::ERR_CERT_AUTHORITY_INVALID` |
| `wss://chat.signal.org/v1/websocket/provisioning/` | `error → close(code=1006)`; Firefox reports **1015** (TLS handshake failure) | Chrome/Edge: `Error in connection establishment: net::ERR_CERT_AUTHORITY_INVALID` |

You can also visit `https://chat.signal.org/` in each browser's address bar. You should get
the browser's untrusted-certificate interstitial (Chrome/Edge: `NET::ERR_CERT_AUTHORITY_INVALID`;
Firefox: `SEC_ERROR_UNKNOWN_ISSUER`; Safari: "This Connection Is Not Private"); again, do not
proceed past it. Firefox's console may also print "Cross-Origin Request Blocked" for these
requests; that is a side effect of the failed connection, not a CORS result.

If the control row also fails, your network intercepts or blocks TLS (a corporate proxy, for
example). Then the run says nothing about Signal. `tools/run-probe.mjs` reports this as
`INVALID_FOR_SIGNAL_CONCLUSIONS` or `INCONCLUSIVE`.

## 3. The linking step (phone operator)

1. Open `http://localhost:8080/` and click **Start linking**.
2. Expected today: the page reports that the provisioning connection could not be
   established, and **no QR code is shown**. The flow ends here. There is nothing to approve
   on the phone and nothing to unlink afterwards.
3. Only if a future change on Signal's side lets the connection succeed: the page shows a QR
   code that it generated from the address Signal's server sent. On the **test** phone, open
   Signal → Settings → Linked devices → Link new device and scan it.
   - The page then decrypts the provisioning message and stops. That message contains the
     account's identity private key and account secrets, which this spike keeps only in WASM
     memory and drops on reload. Device registration (`PUT /v1/devices/link`) is deliberately
     not implemented, so no device will appear in the phone's linked-device list.
   - To confirm, check Settings → Linked devices on the phone. A device that does appear must
     be removed there.

## 4. Messaging, persistence, and attachments

The live versions of these steps (two-way messages with an official client, a browser restart
followed by resumed messaging, and attachments) cannot be reached: they all need the
connections that step 2 shows failing. The local, account-free versions run with `npm test`:

- WASM crypto, plus libsignal's own tests, in your browser: open
  `http://localhost:8080/selftest.html`.
- Encrypted persistence across a real browser restart: open
  `http://localhost:8080/storage-test.html`. Enter a throwaway passphrase and run phase 1.
  Then quit the browser completely, reopen the page, and run phase 2 with the same passphrase.
