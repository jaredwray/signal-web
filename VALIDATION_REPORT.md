# Validation report: a browser-only Signal client in Rust/WebAssembly

Date of inspection and testing: **2026-10-01**. Everything below separates **source
observations** (read in pinned source), **live results** (executed, with evidence files), and
**hypotheses** (not executed).

## 1. Outcome and scope

**Overall outcome: `BLOCKED_UNDER_CURRENT_CONSTRAINTS`.**

The blocking operation is mandatory and comes first: a browser page opening **any** connection
to Signal's service hosts. That includes the provisioning WebSocket that starts device linking,
the chat WebSocket, the REST API, the storage service, and the attachment CDNs. Every one of
these hosts presents a TLS certificate that chains only to Signal's private root CA
("Signal Messenger", SHA-256 `DD:B0:F9:2B:…:9D:F6:5A`, 2022-01-26 → 2032-01-24). The evidence:

- That root is in none of the Apple, Google Chrome, Microsoft, or Mozilla root programs.
- No publicly trusted certificate for these names exists in Certificate Transparency.
- Signal's own clients pin this root.
- Web pages have no API to add trust anchors.

Real browsers on an ordinary network (GitHub-hosted runners, no TLS interception) refuse these
connections. That holds for Chromium, Google Chrome, Microsoft Edge, Firefox (real and
Playwright builds), Playwright WebKit, and **real Safari**. A Signal host with a publicly
trusted certificate (`updates.signal.org`) works from the same pages, which rules out the
network or the test page as the cause.

What the evidence does and does not cover:

| Question from the brief | Answer | Gate |
|---|---|---|
| 1. Signal client crypto in Rust → WASM | **Yes.** Current libsignal-protocol (PQXDH + Kyber1024, mandatory SPQR, sealed sender) builds for `wasm32-unknown-unknown` with **no source patches**. It passes a 32-check self-test in all seven browser builds tested, and libsignal's own 55 protocol tests in six of them (all but Edge, where the upstream suite was not run). | G1 PASS |
| 2. Link via phone-approved QR | **No.** The provisioning WebSocket cannot be opened (TLS). The client-side linking crypto works locally. | G3 BLOCKED |
| 3. Connect directly to Signal | **No.** TLS trust failure on every service host, in every tested browser. | G2 FAIL |
| 4. Real E2EE messages with official clients | **No.** It depends on 3. A second, independent blocker for *receiving* follows from source and spec (§8.2). | G4 BLOCKED |
| 5–6. Persist and resume after browser restart | **The mechanism works locally.** Real libsignal state survives a full browser restart in encrypted IndexedDB, and messaging resumes. The live version depends on 3. | G5 BLOCKED (live); local PASS |
| 7. Attachments | **No.** The CDNs use the same private CA. The CDN responses a non-browser diagnostic could see (404s) carry no CORS headers. | G6 BLOCKED |

Scope of the conclusion: desktop browsers that use the public root programs (all major ones),
against Signal's production service as deployed on 2026-10-01. Staging was not tested. The
conclusion would change only if Signal served publicly trusted certificates. That is a
Signal-side change, and even then §8.2 applies to receiving messages. No client-only fix was
found (§8).

Security readiness is reported separately in §9. Nothing here is a security audit, and the
prototype must not be used for real conversations.

## 2. Gate results

| Gate | Status | Evidence |
|---|---|---|
| **G1** Current crypto runs correctly in browser WASM | **PASS** | §2.1 |
| **G2** Mandatory service operations work via direct browser networking | **FAIL** (reproducible incompatibility) | §2.2 |
| **G3** Fresh phone-approved browser linking | **BLOCKED** by G2 (provisioning socket cannot open). Local crypto/framing PASS. Phone approval NOT RUN. | §2.3 |
| **G4** Two-way text with an official client on another account | **BLOCKED** by G2. Receiving has a further blocker (§8.2). NOT RUN. | §5, §8 |
| **G5** Encrypted state survives restart; messaging resumes | **BLOCKED** (live, needs G3/G4). Local mechanism PASS (§2.4). | §2.4 |
| **G6** Direct encrypted attachment upload/download | **BLOCKED** by G2. NOT RUN. | §5 |

### 2.1 G1: cryptography in browser WebAssembly (LOCAL tests, synthetic identities)

These are local cryptographic tests. They never contact Signal and are not live Signal tests.

- **Build.** `libsignal-protocol` and `libsignal-core` at `signalapp/libsignal@e8cc2dd`, with
  SPQR `v1.6.0` (`06959b47`) and `libcrux-ml-kem 0.0.10`, compile for `wasm32-unknown-unknown`
  with Rust 1.97.0 and wasm-bindgen 0.2.129. **No libsignal source changes.** Portability notes:
  - `getrandom` appears twice in the tree: 0.3 via `rand` 0.9, and 0.4 via RustCrypto
    `crypto-common` 0.2. Each needs its `wasm_js` feature, and 0.3 also needs
    `--cfg getrandom_backend="wasm_js"` (`.cargo/config.toml`). Randomness then comes from
    `crypto.getRandomValues()`.
  - `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown`. libsignal's session APIs
    take `now` as a parameter, so the crate passes browser time (`src/clock.rs`).
    `KyberPreKeyRecord::generate()` calls `SystemTime::now()` internally
    ([kyber_prekey.rs:63][ls-kyber-now]); the crate builds the record with the public
    `GenericSignedPreKey::new()` instead. A real client must avoid that helper, or upstream
    should take a timestamp.
  - Threads: `sealed_sender_multi_recipient_encrypt` asks for `available_parallelism()`, which
    fails on wasm, so it falls back to one thread ([sealed_sender.rs:1570][ls-ss-par]). `rayon`
    compiles but is never used for threads.
  - The host build needs `protoc` (SPQR's build script). This has no effect on the browser.
  - Sizes: the self-test module (libsignal-protocol + provisioning + QR + test code) is
    **1,334,830 bytes raw, 398,450 bytes gzip -9** (§3). The protocol-only build measured
    1,082,535 / 314,410 bytes.
- **Custom self-test** (`crates/signal-web-core/src/selftest.rs`, `web/selftest.html`): 22
  protocol checks plus 10 provisioning checks.
  - Protocol: Curve25519 key generation and signatures; a Kyber1024 KEM round trip; PQXDH bundle
    with a Kyber prekey; PreKeySignalMessage → SignalMessage. Both sessions verified as
    **version 4, `EstablishedWithPqxdh` + `Spqr`**.
  - Session evolution: 40 alternating messages, plus out-of-order delivery (order
    [3,0,5,1,4,2]).
  - Serialization: both stores rebuilt from serialized bytes, then 10 more messages.
  - Rejection: a flipped MAC bit, a flipped body bit, truncation, an unknown version, replay
    (`old counter`), and a tampered PreKey message. The untouched original still decrypts
    afterwards, so state is intact.
  - Sealed sender: round trip, rejection of an untrusted root, an expired certificate, and a
    tampered envelope.
  - Identity: `UntrustedIdentity` on an identity-key change.
  - Provisioning (linking) crypto and framing. The decryption is checked against an
    **independent Python implementation** of the phone side
    (`scripts/make_provisioning_vector.py`, using `cryptography` 49.0.0). Six tamper cases are
    rejected for the expected reason: MAC, ciphertext, version, truncation, substituted sender
    key, and wrong recipient.
- **Upstream tests in browsers**: libsignal's own `rust/protocol/tests` (`session.rs`,
  `sealed_sender.rs`, `groups.rs`, `ratchet.rs`) run under wasm-bindgen-test. The only
  transforms are mechanical and counted: 55 test attributes and 69 `SystemTime::now()` calls
  ([scripts/wasmify_upstream_tests.py](scripts/wasmify_upstream_tests.py)). With
  `--include-ignored`, the 3 upstream "slow" tests run as well. One test-only crate was
  vendored with a one-line feature change ([third_party/README.md](third_party/README.md)).

Results (CI evidence in `evidence/ci/`):

> _Table pending: generated by `tools/summarize-evidence.mjs` from the final CI run's evidence (in progress when this revision was committed)._

### 2.2 G2: direct browser networking (LIVE, no account, no credentials)

**How it was tested.** `web/probe.html` is served as static files from an `http://localhost`
origin, which is distinct from Signal's origins and is a secure context. From that page, one
attempt per target:

- a CORS `fetch()` (what a client needs: a readable response);
- a `no-cors` fetch, used **only** as a TLS-reachability diagnostic and never counted as a
  usable response;
- the provisioning WebSocket (`wss://chat.signal.org/v1/websocket/provisioning/`, and the
  libsignal-net host `grpc.chat.signal.org`);
- a top-level navigation per host. The runner observes passively, with no request
  interception. It reads Chrome DevTools network events, Chrome NetLog (the certificate chain
  the browser actually received), console messages, and WebDriver navigation results.

**Where it was tested.** The authoring environment, a cloud container, re-terminates browser
TLS with its own interception CA. That run is kept only as a labelled environment artifact
(`evidence/live/probe-pw-chromium-cloud-container-direct.json`, verdict
`INVALID_FOR_SIGNAL_CONCLUSIONS`). The control host failed there in exactly the same way. All
G2 conclusions come from **GitHub-hosted runners** (ubuntu-24.04, macos-15), which reach the
internet without interception. The runner's verdict logic refuses to treat a network as valid
if a foreign certificate issuer appears or the public-CA control fails.

> _Table pending: generated by `tools/summarize-evidence.mjs` from the final CI run's evidence (in progress when this revision was committed)._

**Non-browser corroboration** (`tools/tls_trust_evidence.py` →
`evidence/live/tls-trust-summary.json`; openssl through a CONNECT tunnel that kept TLS end to
end):

| Host | Leaf issuer | Leaf verifies against the Signal root **alone** | Unexpired CT-logged public certs |
|---|---|---|---|
| chat, grpc.chat, storage | Signal Messenger (private) | OK (root not sent) | 0 |
| cdn, cdn2, cdn3, cdsi, svr2, svrb | Signal Messenger (private) | OK (root sent in chain) | 0 |
| updates.signal.org (control) | Google Trust Services WE1 | fails (as expected) | 11 |

CCADB `AllIncludedRootCertsCSV` lists 369 roots included by Apple, Chrome, Microsoft, or
Mozilla. None matches the Signal root's fingerprint or names Signal.

### 2.3 G3: linking (LOCAL implementation; live BLOCKED)

What is implemented, following current Signal-Desktop and libsignal (§4):

- the provisioning WebSocket framing (`PUT /v1/address`, `PUT /v1/message`, 200 acks);
- the `sgnl://linkdevice?uuid=…&pub_key=…&capabilities=nopni` URL, identical in format to
  Desktop's `linkDeviceRoute`;
- QR rendering (SVG, in WASM);
- `ProvisionEnvelope` decryption: ECDH → HKDF-SHA256 → HMAC-SHA256 verified before
  AES-256-CBC.

The UI (`web/index.html`) shows a QR code **only after** Signal's server sends a real
provisioning address, and decrypted secrets stay in WASM memory. Live, the socket never opens,
so no QR was ever shown and no phone interaction occurred. Device registration
(`PUT /v1/devices/link`) was deliberately not implemented: it cannot be exercised, and a
non-exercised implementation would be unverified code.

### 2.4 G5: encrypted persistence (LOCAL functional test; live BLOCKED)

`web/lib/vault.js` and `web/storage-test.*`. Phase 1 writes real libsignal state (identity
keys, registration ids, session records of a synthetic conversation). The browser process is
then **shut down completely**, and phase 2 starts a new browser process on the same profile
directory.

> _Table pending: generated by `tools/summarize-evidence.mjs` from the final CI run's evidence (in progress when this revision was committed)._

This shows that the browser-side mechanism works: encrypted storage, unlock, restore of
ratchet state, resumed messaging, and fail-safe handling of corruption and deletion. It
**does not** show resumption of live Signal messaging (that needs G3/G4), and it makes no
production-security claim (§9).

## 3. Tested versions

> _Table pending: generated by `tools/summarize-evidence.mjs` from the final CI run's evidence (in progress when this revision was committed)._

## 4. Pinned sources (inspected 2026-10-01)

| Repository | Commit | Commit date |
|---|---|---|
| signalapp/libsignal | [`e8cc2dddd578859b4a029c9c94670b24ce2b616a`][ls] | 2026-09-22 |
| signalapp/Signal-Desktop | [`abe80d32445e53b047b42d10c5b751c4fbfbbfc0`][sd] | 2026-09-23 |
| signalapp/Signal-Server | [`2d22cc4420d4da16a767c75eeb6e80b5a2c22e4b`][ss] | 2026-09-30 |
| signalapp/SparsePostQuantumRatchet | tag `v1.6.0` → `06959b47` (via libsignal) | |
| whisperfish/presage | [`33dd1491130793390e356e15a5711f1e6ca14fdb`][pr] | 2026-09-19 |

Web references, checked 2026-10-01:

- The WHATWG Fetch Standard and WebSockets Standard were downloaded and quoted (§8).
- [MDN `WebSocket()`](https://developer.mozilla.org/en-US/docs/Web/API/WebSocket/WebSocket)
  documents only `new WebSocket(url[, protocols])`, with no header parameter.
- [webassembly.org security](https://webassembly.org/docs/security/): modules are sandboxed
  "separated from the host runtime" and, in browsers, subject to the same-origin policy. That
  protects the host from the module, not the module's memory from same-origin script (§9).
- The Signal support article on linked devices returned HTTP 403 to both automated fetches
  (bot protection), so it was **not** consulted. Nothing here depends on it.

Key references:

- Trust roots. Official clients pin Signal's root:
  - libsignal [`rust/net/src/certs.rs:8`][ls-certs] (`SIGNAL_ROOT_CERTIFICATES` =
    [`res/signal.cer`][ls-signal-cer] + a new Ed25519 root);
  - every chat/CDSI/SVR domain uses it: [`env.rs:42-64`][ls-env-chat], [`env.rs:90-106`][ls-env-cdsi];
  - Desktop [`config/default.json:23`][sd-ca] `certificateAuthority` is passed as Node's `ca`
    for API and CDN requests ([`WebAPI.preload.ts:429`][sd-webapi-ca]);
    [`config/production.json`][sd-prod] holds the hosts.
- Censorship-circumvention reflectors (public certs; not used, see §8):
  [`env.rs:254-287`][ls-env-proxy]; the TLS tunnel sets the target with a custom
  `x-signal-host` upgrade header ([`reflector.rs:31`][ls-reflector], [`:221-230`][ls-reflector-hdr]).
- Provisioning:
  - libsignal [`env.rs:934-935`][ls-env-paths] (paths) and
    [`server_requests.rs:247-262`][ls-provreq] (`/v1/address`, `/v1/message`);
  - Desktop [`SocketManager.preload.ts:413-431`][sd-prov-conn],
    [`Provisioner.preload.ts:425-435`][sd-qr], [`signalRoutes.std.ts:335-358`][sd-route],
    [`ProvisioningCipher.node.ts`][sd-cipher], [`DeviceMessages.proto:23-48`][sd-proto].
- Chat authentication:
  - libsignal [`chat.rs:240-262`][ls-chat-auth] (`Authorization: Basic <aci>.<device>:<password>`
    on the upgrade) and [`auth.rs`][ls-auth];
  - Server [`WebSocketAccountAuthenticator.java:33`][ss-wsauth] reads only the `Authorization`
    header of the upgrade request;
  - Desktop sends registration and other REST calls in-band over the WebSocket
    ([`WebAPI.preload.ts:496-498`][sd-webapi-fetch], [`SocketManager.preload.ts:452-465`][sd-sm-fetch],
    [`linkDevice` 2950-3005][sd-link]).
- Delivery: [`WebSocketConnection.java:164,234`][ss-wsconn] (`PUT /api/v1/queue/empty`,
  `PUT /api/v1/message`); [`MessageController.java`][ss-msg] has no `@GET` (no HTTP fetch);
  the gRPC [`messages.proto:51`][ss-grpc-msgs] `GetMessages` is a bidirectional stream.
  There are no CORS headers and no `Origin` checks anywhere in the server's Java sources
  (searched).
- Protocol requirements: SPQR is mandatory ([`ratchet.rs:87`][ls-spqr]); the linked-device
  link request carries signed + Kyber last-resort prekeys ([`linkDevice`][sd-link]).

presage (`whisperfish/presage@33dd149`) builds on `libsignal-service-rs` and tokio, a native
networking stack. It was not used: its transport cannot run in a page, and its existence says
nothing about browser feasibility.

## 5. Endpoint and transport matrix

Hosts from Desktop `config/production.json` and libsignal `env.rs`. Paths are from the server
and client sources in §4. "Browser result" is from the clean-network CI runs in all tested
browsers. "Diagnostic" is curl trusting **only** the pinned Signal root
(`tools/server_behavior_diagnostic.py` → `evidence/live/server-behavior-diagnostic.json`).
That is non-browser evidence of what would happen after TLS.

| Operation | Host / path | Transport | Auth | Required headers | Browser constraint | Core? | Browser result | Diagnostic (non-browser) |
|---|---|---|---|---|---|---|---|---|
| Provisioning socket + QR | `chat.signal.org` (`grpc.chat.signal.org` in libsignal-net) `/v1/websocket/provisioning/` | WSS | none | none | private-CA TLS | core | **TLS rejected** | upgrade with browser `Origin` → **101** |
| Device link completion | `PUT /v1/devices/link` | in-band request on unauthenticated chat WS (Desktop) or HTTPS | Basic `aci:newPassword` per request | `Authorization`, JSON | TLS. Over HTTPS also CORS: the preflight answers 200 **without** `Access-Control-Allow-*` | core | not reachable | preflight 200, no CORS headers |
| Authenticated chat socket | `chat.signal.org /v1/websocket/` | WSS | Basic `aci.device:password` **on the upgrade** | `Authorization` (+ `X-Signal-Receive-Stories`) | TLS; plus pages cannot set `Authorization` on a WebSocket handshake (§8.2) | core | not reachable | unauthenticated upgrade → **101** (no 401 challenge) |
| Upload prekeys | `PUT /v2/keys` | in-band, authenticated | device | n/a | as above | core | not reachable | n/a |
| Fetch recipient prekeys | `GET /v2/keys/{id}/{device}` | in-band | device, or unidentified access key | `Unidentified-Access-Key` | as above | core | not reachable | n/a |
| Send message | `PUT /v1/messages/{destination}` | in-band | device, or sealed sender + access key | as above | as above | core | not reachable | n/a |
| Receive + ack | server push `PUT /api/v1/message`, ack = 200; `PUT /api/v1/queue/empty` | authenticated WS only (gRPC `GetMessages` bidi stream also exists) | device (on upgrade) | n/a | needs the authenticated socket; no HTTP fetch endpoint; no gRPC-Web | core | not reachable | n/a |
| Sender certificate | `GET /v1/certificate/delivery` | in-band or HTTPS | device | `Authorization` | TLS (+ CORS over HTTPS) | core for sealed sender | **TLS rejected** | 401 without credentials, no CORS headers |
| Sync with own devices | Signal messages to own ACI via `PUT /v1/messages` | in-band | device | n/a | as above | needed for coherent use | not reachable | n/a |
| Storage service | `storage.signal.org /v1/storage/...` | HTTPS | storage credentials | `Authorization` | private-CA TLS | optional for 1:1 text | **TLS rejected** | n/a |
| Attachment upload form | `GET /v4/attachments/form/upload` | in-band | device | n/a | as chat | G6 | not reachable | n/a |
| Attachment upload | cdn2 (GCS resumable) / cdn3 (TUS); domain from server config | HTTPS | signed URL / form headers | form headers | private-CA TLS; CORS needed | G6 | **TLS rejected** (cdn2/cdn3) | cdn3 preflight → 404, no CORS headers |
| Attachment download | `cdn{,2,3}.signal.org/attachments/<key>` | HTTPS | none (unguessable key) | none | private-CA TLS; CORS needed to read bytes | G6 | **TLS rejected** | 404 responses carry no CORS headers (real objects not tested) |
| Contact discovery | `cdsi.signal.org` | WSS + SGX attestation | auth credentials | n/a | private-CA TLS | optional | **TLS rejected** | n/a |
| SVR2/SVRB (PIN/backups) | `svr2/svrb.signal.org` | WSS + attestation | n/a | n/a | private-CA TLS | optional | **TLS rejected** (svr2) | n/a |

"In-band" means a `WebSocketRequestMessage` on the chat socket. Its headers travel inside the
protobuf frame, so CORS and forbidden-header rules do not apply to them.

**Deferred features with mandatory dependencies.** Groups, the storage service, CDSI, profiles,
calls, stories, and payments are not needed to *reply* to a 1:1 message from someone whose ACI
arrives in the envelope (hypothesis from source). All of them sit behind the same TLS blocker
anyway. The mandatory chain for core text is: provisioning socket → link request → prekey
upload → authenticated socket (receive/ack) → prekey fetch + send.

## 6. Reproduction

```sh
# toolchain (rust-toolchain.toml pins 1.97.0 + wasm32-unknown-unknown)
sudo apt-get install -y protobuf-compiler           # or: brew install protobuf
cargo install wasm-bindgen-cli --version 0.2.129 --locked
npm ci && npm run build:wasm

# G1/G5 local (no Signal contact). Browser specs: see tools/browsers.mjs
node tools/run-local-tests.mjs --browser pw:chromium [--browser pw:firefox ...]
bash scripts/prepare-upstream-tests.sh
node tools/run-upstream-tests.mjs --include-ignored --browser pw:chromium

# G2 live (contacts Signal's public hosts; no account; opt-in)
SIGNAL_WEB_LIVE=1 node tools/run-probe.mjs --browser pw:chromium --browser pw:firefox ...
SIGNAL_WEB_LIVE=1 python3 tools/tls_trust_evidence.py          # non-browser
SIGNAL_WEB_LIVE=1 python3 tools/server_behavior_diagnostic.py  # non-browser

# Real Firefox / Safari through W3C WebDriver
geckodriver --port 4444 &   node tools/run-probe.mjs --browser wd:firefox@http://127.0.0.1:4444
sudo safaridriver --enable && safaridriver -p 4445 &
                            node tools/run-probe.mjs --browser wd:safari@http://127.0.0.1:4445

# Recover evidence from a CI job log
node tools/extract-ci-evidence.mjs job-log.txt evidence/ci/<dir> <run-url>
```

The CI workflows ([`.github/workflows/`](.github/workflows/)) run exactly these commands on
ubuntu-24.04 and macos-15. They use plain `git` checkout and no third-party actions. For a
hands-on run with your own browsers, see [docs/OPERATOR_GUIDE.md](docs/OPERATOR_GUIDE.md).

## 7. Implemented vs. hypotheses vs. untested

| Item | Status |
|---|---|
| libsignal-protocol in WASM, local tests, upstream tests | implemented and executed (7 browser builds) |
| Provisioning framing, QR URL, envelope decryption | implemented; executed locally against an independent vector |
| Linking UI with honest failure reporting | implemented; executed (its failure path) |
| Encrypted IndexedDB vault, single-tab lock, restart persistence | implemented and executed locally |
| Device registration (`PUT /v1/devices/link`), prekey upload, authenticated chat, send/receive, sync, attachments | **not implemented**: unreachable (G2) |
| Live phone approval, live messaging, live restart resume, live attachments | **NOT RUN** (blocked) |
| Firefox/Safari would accept a provisioning WebSocket from a page origin if TLS were trusted | hypothesis; non-browser diagnostic shows the server returns 101 to a browser `Origin` |
| Registration can go in-band, avoiding CORS | source observation (Desktop does this); not executed |
| Pages cannot authenticate the chat socket (§8.2) | spec plus server source, plus non-browser diagnostic (101 without a challenge); not executed in a browser because TLS fails first |
| Background / closed-browser delivery | not tested; not claimed (§9) |
| Mobile browsers, staging environment | not tested |

## 8. Blockers and alternatives

### 8.1 Primary blocker: private-CA TLS on every service host

Browsers verify server certificates against their root store. The WebSocket constructor takes
only `(url, protocols)` (WHATWG WebSockets Standard). Fetch's `RequestInit` has no
trust-anchor option. So a page cannot make Chrome, Firefox, or Safari accept a certificate
chained to Signal's private root. Alternatives examined:

| Alternative | Result | Category |
|---|---|---|
| Other official hostnames (`grpc.chat.signal.org`, CDN variants) | same private CA (live) | n/a |
| `updates.signal.org` (public cert) | serves desktop update files only, not an API | n/a |
| Signal's censorship-circumvention reflectors (Fastly / Google Cloud Run, public certs) | **Not used, by decision.** They exist for users facing censorship. The TLS-tunnel variant selects its target with a custom `x-signal-host` upgrade header, which page JavaScript cannot set. The HTTP variant ends TLS at a third-party CDN, and authenticated chat would still need an upgrade header (§8.2). Relying on undocumented behavior of circumvention infrastructure is not a sound basis for a client. | not a client-only fix |
| User installs Signal's root in the OS/browser trust store | would work technically, but changes browser security configuration | excluded by the brief |
| Disable certificate checks / click through the interstitial | | excluded by the brief |
| WebTransport `serverCertificateHashes` | needs Signal servers to speak WebTransport (HTTP/3) and certificates valid ≤ 14 days | Signal-side change |
| Direct Sockets API + TLS (e.g. rustls) inside WASM with the pinned root | would remove both blockers, but is only exposed to Chrome **Isolated Web Apps** (packaged and installed), not ordinary pages. Not verified here. | browser/platform change |
| A TLS-terminating proxy or relay we operate | | prohibited backend workaround |
| **Signal serves publicly trusted (CT-logged) certificates** on chat/CDN hosts or a web-facing hostname | removes this blocker | **Signal-side change** |

### 8.2 Second blocker, for receiving: authenticating the chat socket

Messages are delivered only on an **authenticated** chat connection. In the server source,
that means either an `Authorization` header on the WebSocket upgrade
(`WebSocketAccountAuthenticator`) or gRPC metadata on the `GetMessages` stream. There is no
HTTP fetch endpoint and no gRPC-Web.

A page cannot add headers to a WebSocket handshake. The only other route is URL credentials,
and the Fetch Standard (HTTP-network-or-cache fetch) turns them into an `Authorization` value
only when *"httpRequest's current URL does include credentials and isAuthenticationFetch is
true"*, that is, when retrying after a 401. Signal's server answers an unauthenticated upgrade
with `101` (non-browser diagnostic), so no challenge ever happens. In-band requests can carry
`Authorization` for REST-style calls, which is how Desktop registers, but they do not turn the
socket into an authenticated one.

Removing this blocker would take a Signal-side change, for example an authentication message
inside the socket, or a token carried in `Sec-WebSocket-Protocol`. Status: derived from spec
and source, consistent with the observed 101, and **not executed in a browser** because §8.1
fails first.

### 8.3 Attachments

The CDN hosts use the same private CA (live). The responses observed by the non-browser
diagnostic (404s) carry no CORS headers, so a page could not read downloaded ciphertext even
with TLS fixed. That is untested for real objects. Uploads also need the upload form, which
comes over the chat connection.

### 8.4 What would remove the blockers

- **Client-only fix:** none found.
- **Browser change:** a page-level trust-anchor API for specific origins (none exists), or
  Direct Sockets for ordinary pages.
- **Signal-side change:**
  - publicly trusted certificates;
  - a browser-compatible authenticated-socket mechanism;
  - CORS on the CDNs.
- **Prohibited:** any proxy or relay of ours.

## 9. Security assessment (separate from the functional result)

- **Code delivery.** Whoever controls the static origin or its build pipeline can ship code
  that exfiltrates keys and plaintext, possibly to selected users only. Browsers have no code
  signing or transparency for ordinary web apps; SRI does not cover the top-level document.
  This is the main structural weakness of any web E2EE client. Options include Isolated Web
  Apps or published reproducible builds with independent verification, each with its own
  limits.
- **Script injection and dependencies.** The served CSP is strict: `script-src 'self'
  'wasm-unsafe-eval'`, no inline script, no `unsafe-eval`, `connect-src` limited to `'self'`
  and `*.signal.org`, `object-src 'none'`, and `frame-ancestors 'self'`. The tests caught two
  of our own CSP mistakes, so it is enforced. There is no third-party runtime JavaScript. Rust
  dependencies are locked (`Cargo.lock`), and npm is dev-only (Playwright, `package-lock.json`).
  The CI workflows use no third-party actions.
- **Local database theft.**
  - Records are AES-256-GCM encrypted with record-id AAD. The key comes from a passphrase via
    PBKDF2-SHA256 at 600,000 iterations and is non-extractable and memory-only. A copied
    profile yields only salt and ciphertext.
  - PBKDF2 is cheap on GPUs, so a weak passphrase means weak protection; Argon2id in WASM
    would be better.
  - While unlocked, protocol keys and session state sit in WASM linear memory and the JS heap.
    **WASM is not an enclave**: its linear memory is an ordinary `ArrayBuffer` that any script
    running in the origin can read.
  - The key-check record cannot tell "wrong passphrase" from "corrupted check record" (both
    are reported as unlock failure).
- **Extensions and compromised browsers.** An extension with host access can inject
  main-world scripts and read everything. A compromised browser or OS is game over. The
  spike makes no attempt to resist either.
- **Leakage.**
  - The code never logs keys or plaintext. Probe evidence records sizes and event types, not
    message contents.
  - Raw NetLogs and job logs stay out of the repository; only sanitized summaries are
    committed. The storage test's throwaway passphrase never reaches evidence files (checked).
  - QR codes contain only the provisioning address and an ephemeral public key. The
    provisioning *message* holds the account identity key and stays in WASM memory.
- **Lifecycle.**
  - Tabs can be frozen or discarded, and pages hold no sockets after closing. There is no
    closed-browser delivery: the server's push senders are APNs and FCM only, with no Web
    Push in its source. Nothing here tests or claims background operation.
  - `navigator.storage.persist()` was not granted in headless runs (Firefox prompts the
    user), so storage is "best effort" and can be evicted.
  - WebKit caps script-writable storage for sites without recent user interaction (7 days
    under ITP). That was not tested; losing storage means losing the device identity and
    relinking.
- **Concurrent tabs.** A Web Locks guard admits exactly one active context per profile. This
  was tested: a second same-origin context is refused. Writes for one logical step must be
  committed in one IndexedDB transaction *before* acknowledging a message to the server.
  `vault.commit()` provides this atomic write; the ack ordering is a design rule here, not
  tested live.
- **Protocol drift.** Signal changes its requirements often: SPQR is now mandatory, and the
  chat host moved to libsignal-net's `grpc.chat` endpoint. An unofficial client must track
  libsignal closely or break.
- **Licensing.** libsignal is AGPL-3.0-only. A hosted web client conveys AGPL object code (the
  `.wasm`), with source-offer obligations. This repo's own code is MIT. Signal's terms and
  trademark rules for third-party clients were not assessed.

## 10. Next concrete step

The evidence says more client engineering will not change the outcome. Every gate after G1
stops at the same TLS trust boundary, and receiving has a second, server-defined boundary.
The next step is a **decision about constraints**, in this order:

1. **If the "ordinary web page" constraint can be relaxed to a Chrome Isolated Web App:**
   prototype the transport. That means Direct Sockets `TCPSocket` → rustls compiled to WASM,
   pinned to Signal's root → WebSocket client with in-band `Authorization`, reusing
   `crates/signal-web-core` unchanged. It is the only path found that needs neither a backend
   nor a Signal change. First verify IWA installability for the target users.
2. **Otherwise,** the only route is Signal-side: publicly trusted certificates, a
   browser-compatible chat authentication, and CORS on the CDNs. This spike documents the
   precise asks (§8). Signal publishes no official web client, and whether it would make
   these changes is outside what this spike can establish.
3. If neither is acceptable, **stop**. The architecture is not feasible under the stated
   constraints.

[ls]: https://github.com/signalapp/libsignal/tree/e8cc2dddd578859b4a029c9c94670b24ce2b616a
[ls-certs]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/certs.rs#L8-L13
[ls-signal-cer]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/res/signal.cer
[ls-env-chat]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/env.rs#L42-L64
[ls-env-cdsi]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/env.rs#L90-L106
[ls-env-proxy]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/env.rs#L254-L287
[ls-env-paths]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/env.rs#L933-L936
[ls-reflector]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/infra/src/tcp_ssl/proxy/reflector.rs#L31
[ls-reflector-hdr]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/infra/src/tcp_ssl/proxy/reflector.rs#L221-L230
[ls-provreq]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/chat/server_requests.rs#L247-L262
[ls-chat-auth]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/chat.rs#L240-L262
[ls-auth]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/net/src/auth.rs
[ls-spqr]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/protocol/src/ratchet.rs#L87
[ls-kyber-now]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/protocol/src/state/kyber_prekey.rs#L63
[ls-ss-par]: https://github.com/signalapp/libsignal/blob/e8cc2dddd578859b4a029c9c94670b24ce2b616a/rust/protocol/src/sealed_sender.rs#L1570
[sd]: https://github.com/signalapp/Signal-Desktop/tree/abe80d32445e53b047b42d10c5b751c4fbfbbfc0
[sd-ca]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/config/default.json#L23
[sd-prod]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/config/production.json
[sd-webapi-ca]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/textsecure/WebAPI.preload.ts#L429
[sd-webapi-fetch]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/textsecure/WebAPI.preload.ts#L496-L498
[sd-link]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/textsecure/WebAPI.preload.ts#L2950-L3005
[sd-sm-fetch]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/textsecure/SocketManager.preload.ts#L452-L465
[sd-prov-conn]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/textsecure/SocketManager.preload.ts#L413-L431
[sd-qr]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/textsecure/Provisioner.preload.ts#L425-L435
[sd-route]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/util/signalRoutes.std.ts#L335-L358
[sd-cipher]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/ts/textsecure/ProvisioningCipher.node.ts
[sd-proto]: https://github.com/signalapp/Signal-Desktop/blob/abe80d32445e53b047b42d10c5b751c4fbfbbfc0/protos/DeviceMessages.proto#L23-L48
[ss]: https://github.com/signalapp/Signal-Server/tree/2d22cc4420d4da16a767c75eeb6e80b5a2c22e4b
[ss-wsauth]: https://github.com/signalapp/Signal-Server/blob/2d22cc4420d4da16a767c75eeb6e80b5a2c22e4b/service/src/main/java/org/whispersystems/textsecuregcm/websocket/WebSocketAccountAuthenticator.java#L33
[ss-wsconn]: https://github.com/signalapp/Signal-Server/blob/2d22cc4420d4da16a767c75eeb6e80b5a2c22e4b/service/src/main/java/org/whispersystems/textsecuregcm/websocket/WebSocketConnection.java#L164
[ss-msg]: https://github.com/signalapp/Signal-Server/blob/2d22cc4420d4da16a767c75eeb6e80b5a2c22e4b/service/src/main/java/org/whispersystems/textsecuregcm/controllers/MessageController.java
[ss-grpc-msgs]: https://github.com/signalapp/Signal-Server/blob/2d22cc4420d4da16a767c75eeb6e80b5a2c22e4b/service/src/main/proto/org/signal/chat/messages.proto#L51
[pr]: https://github.com/whisperfish/presage/tree/33dd1491130793390e356e15a5711f1e6ca14fdb
