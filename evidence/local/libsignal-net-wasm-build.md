# libsignal-net on wasm32-unknown-unknown (LOCAL build experiment, 2026-10-01)

Question: can libsignal's own networking crate (used by Signal-Desktop for the
chat/provisioning connections) be reused in a browser?

Setup: a scratch crate depending only on
`libsignal-net = { git = "https://github.com/signalapp/libsignal", rev = "e8cc2dddd578859b4a029c9c94670b24ce2b616a" }`,
plus the same getrandom `wasm_js` opt-ins as `crates/signal-web-core`, built with
Rust 1.97.0:

    cargo build --target wasm32-unknown-unknown

Result: **does not compile.**

    error: This wasm target is unsupported by mio. If using Tokio, disable the net feature.
    error: could not compile `mio` (lib) due to 48 previous errors

Dependency path: `mio 1.2.3 <- tokio 1.53.1 <- h2 0.4.19 <- hyper 1.11.1 <- hyper-util <- libsignal-net`.
The crate's transport is a native stack: tokio/mio sockets, hyper/h2,
tungstenite, and BoringSSL (`boring 5.2.0`, `boring-sys 5.2.0`) plus rustls.

Implication: a browser client cannot reuse libsignal-net's transport. It must
speak Signal's WebSocket framing over the browser's own `WebSocket` (as
`crates/signal-web-core/src/provisioning.rs` does for provisioning) and inherits
the browser's TLS trust store. That is exactly where the G2 blocker lies.
