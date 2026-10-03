# third_party

## proptest-arbitrary-interop (0.1.0, MIT OR Apache-2.0)

Verbatim copy of the crates.io release, used only by the test-only
`crates/upstream-protocol-tests` crate (via `[patch.crates-io]`).

The single change is in `Cargo.toml`: proptest is depended on with
`default-features = false, features = ["std"]`. Upstream enables proptest's
default `fork` feature, which pulls in `rusty-fork` -> `wait-timeout`, a
process-spawning crate that cannot compile for `wasm32-unknown-unknown`.
Nothing in libsignal's tests uses forking.
