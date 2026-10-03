# Proposal: a browser-compatible entry point for third-party Signal web clients

**To:** the Signal engineering team
**From:** the author of the `signal-web` feasibility spike (unofficial, not affiliated with or endorsed by Signal)
**Date:** 2026-10-02
**Status:** request for comment — asks for a time-boxed trial on a non-production environment

This document is a request. It asks Signal to consider exposing a browser-reachable entry
point to its services so that an **unmodified** Signal client can run in a normal web browser.
It is backed by a reproducible spike whose evidence is in
[`VALIDATION_REPORT.md`](VALIDATION_REPORT.md); every claim here links to that evidence rather
than restating it. Nothing in this spike contacted a real account, and nothing here asks Signal
to weaken the protocol.

## 1. One-paragraph summary

Signal's current cryptography already runs, unchanged, in a browser via WebAssembly. What a web
client cannot do today is **connect**: every Signal service host presents a certificate from
Signal's private root CA, which no browser trusts, and the authenticated chat socket is
authenticated by an HTTP header that a page is not allowed to set. Both are server-side facts,
not client bugs. This proposal asks for a browser-compatible way in — a publicly trusted
hostname and a handshake a page can perform — ideally trialled first on a staging environment,
so the approach can be proven end to end before any production change is considered.

## 2. What the spike already established (with evidence)

All results are from real browsers on GitHub-hosted runners with ordinary internet (no TLS
interception), plus non-browser corroboration. Source is pinned to
`signalapp/libsignal@e8cc2dddd578859b4a029c9c94670b24ce2b616a`.

- **Signal's crypto runs in the browser, unmodified.** `libsignal-protocol` (PQXDH + Kyber1024,
  the mandatory SPQR ratchet, sealed sender) compiles to `wasm32-unknown-unknown` with **no
  source patches**. It passes a 33-check self-test in **seven** browser builds — Chromium,
  Chrome, Edge, Firefox (Playwright and installed), WebKit, and **real Safari 26.6.1** — and
  libsignal's own 55 `rust/protocol/tests` in six of them.
  (Evidence: [`VALIDATION_REPORT.md` §2.1](VALIDATION_REPORT.md), `evidence/ci/local/`.)
- **Device state persists across a browser restart.** Real session state, encrypted in
  IndexedDB under a passphrase-derived key, survives a full browser restart and messaging
  resumes. (Evidence: [§2.4](VALIDATION_REPORT.md), `evidence/ci/local/storage-test-*`.)

The spike's overall outcome is nonetheless **`BLOCKED_UNDER_CURRENT_CONSTRAINTS`**, for exactly
the two reasons below.

## 3. The two blockers (both server-side, both verified)

### Blocker A — TLS: browsers do not trust Signal's private root

Every service host (`chat.signal.org`, `grpc.chat.signal.org`, `storage.signal.org`,
`cdn.signal.org`, `cdn2`, `cdn3`, `cdsi`, `svr2`) presents a certificate chaining only to the
**"Signal Messenger"** private root (SHA-256 `DD:B0:F9:2B:…:9D:F6:5A`). That root is in no
browser root program (CCADB), and Certificate Transparency shows no publicly trusted
certificate for these names. A web page has no API to add a trust anchor: the `WebSocket`
constructor takes only `(url, protocols)`, and `fetch` has no trust-anchor option.

In the live test, **every** browser rejected **every** Signal host and named the certificate
problem itself (Chromium family `ERR_CERT_AUTHORITY_INVALID`, with NetLogs confirming the
"Signal Messenger" issuer; Firefox `SEC_ERROR_UNKNOWN_ISSUER`; WebKit `Unacceptable TLS
certificate`; Safari's "This Connection Is Not Private" page). The control host
`updates.signal.org`, which uses a publicly trusted certificate, loaded fine from the same
page — so the network and the test harness are not the cause.
(Evidence: [§2.2](VALIDATION_REPORT.md), `evidence/ci/live/`.)

### Blocker B — authentication: the chat socket is authenticated by an upgrade header

After linking, almost every account operation (receiving and acking messages, uploading
prekeys, fetching a sender certificate, identified sends, capability updates, sync) runs over
an **authenticated** chat connection. In the server source, that connection is tied to an
account only by the `Authorization` header on the WebSocket **upgrade** request
(`WebSocketAccountAuthenticator`), or by gRPC metadata. In-band requests inside the socket take
their identity from that upgrade, not from headers in the frame.

A browser page cannot set a header on a WebSocket handshake. The one browser-managed path —
`Authorization` supplied after a `401` challenge — never triggers, because the server answers
an unauthenticated upgrade with `101`. There is no HTTP fetch endpoint for messages and no
gRPC-Web. (Evidence: [§8.2](VALIDATION_REPORT.md), confirmed against Signal-Server source and a
non-browser diagnostic; device **linking** is the one exception — it carries its own
credentials and would work once Blocker A is removed.)

## 4. What we are asking for

Any one of these would unblock linking; the full set unblocks a complete 1:1 text client. We
are not asking for protocol changes or for the private pinned root to be removed from official
apps — only for an **additional**, browser-compatible way to reach the same services.

1. **A publicly trusted (CT-logged) certificate on a web-facing hostname** for the chat and CDN
   services — for example a dedicated `*.web.signal.org` front that terminates TLS with a
   publicly trusted certificate and speaks the existing protocol behind it. This is the single
   most important ask; it removes Blocker A.
2. **A browser-performable authentication for the chat socket** — e.g. accepting the device
   credential inside the WebSocket stream (an in-band auth message) or in
   `Sec-WebSocket-Protocol`, rather than only on the upgrade header. This removes Blocker B.
3. **CORS response headers on the attachment CDNs** (`Access-Control-Allow-Origin` and the
   headers the upload flow needs), so a page can read downloaded ciphertext and perform
   resumable uploads.

**Suggested first step: a staging trial.** None of this needs to touch production to be proven.
A single staging endpoint with a publicly trusted certificate and one of the auth options above
would let this client be driven end to end against a test account, producing the
interoperability evidence that a spike alone cannot.

## 5. The question you will ask first: code delivery

A web client is served fresh code on every load, so whoever controls the origin (or its build
pipeline) could ship code that exfiltrates keys or plaintext to selected users, and Subresource
Integrity does not cover the top-level document. This is the central security weakness of any
browser E2EE client and we are not minimizing it. Partial mitigations exist — a Chrome Isolated
Web App (signed, versioned, installed) or published reproducible builds with independent
verification — each with real limits. We raise it up front because it, not feasibility, is the
decision that matters, and it is documented honestly in
[`VALIDATION_REPORT.md` §9](VALIDATION_REPORT.md).

## 6. What this proposal is *not*

- **Not** a request to weaken, bypass, or alter the Signal protocol, PQXDH/SPQR, or sealed
  sender. The client uses `libsignal` unchanged.
- **Not** a request to disable certificate pinning in the official apps.
- **Not** a backend or proxy operated by us. The spike's constraint is *no backend of ours*; a
  relay that forwarded requests would defeat the purpose and is excluded.
- **Not** dependent on Signal's censorship-circumvention front ends — those were deliberately
  **not** evaluated and are out of scope here ([§8.1](VALIDATION_REPORT.md)).

## 7. An alternative that needs nothing from Signal (for context)

If a browser-reachable endpoint is not something Signal wants to offer, there is one client-side
route that needs **no** server change: a **Chrome Isolated Web App**, which can open raw TCP
sockets and run TLS itself (in WASM) pinned to Signal's existing root — reusing this spike's
`crates/signal-web-core` unchanged. A throwaway experiment confirmed the platform pieces are
available (Chromium 141 installs such an app and exposes `TCPSocket` inside it); a connection to
Signal through them has **not** been attempted. This is noted only so the trade-off is explicit:
it is an installed app, not an ordinary web page, and it still relies on the undocumented stance
that an unofficial client may connect at all.

## 8. References

- Spike repository and full evidence: this repo; start at
  [`VALIDATION_REPORT.md`](VALIDATION_REPORT.md).
- Reproducible CI evidence (real browsers, ordinary network): local run
  [`36880051338`](https://github.com/jaredwray/signal-web/actions/runs/36880051338), live probe
  [`36880051146`](https://github.com/jaredwray/signal-web/actions/runs/36880051146).
- Pinned upstream sources, with commit-linked line references for every claim above:
  [`VALIDATION_REPORT.md` §4](VALIDATION_REPORT.md).

*This is an independent experiment. "Signal" is a trademark of Signal Messenger, LLC; its use
here is descriptive and implies no affiliation or endorsement.*
