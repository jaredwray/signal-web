//! signal-web-core: the Rust half of a feasibility spike that asks whether a
//! Signal client can run entirely inside a normal web browser.
//!
//! This crate links the current libsignal-protocol (PQXDH + SPQR) and exposes
//! it to JavaScript via wasm-bindgen. See VALIDATION_REPORT.md.

use wasm_bindgen::prelude::*;

mod clock;
pub mod provisioning;
mod selftest;
pub use selftest::LocalConversation;

#[wasm_bindgen(start)]
pub fn start() {
    console_error_panic_hook::set_once();
}

/// Version of the linked libsignal (from libsignal-core).
#[wasm_bindgen(js_name = libsignalVersion)]
pub fn libsignal_version() -> String {
    libsignal_core::VERSION.to_owned()
}

/// Runs the local cryptographic self-test and returns a JSON report.
///
/// LOCAL test with synthetic identities: it never contacts Signal.
#[wasm_bindgen(js_name = runProtocolSelftest)]
pub async fn run_protocol_selftest() -> String {
    let report = selftest::run().await;
    serde_json::to_string(&report).expect("report serializes")
}

/// Runs the local provisioning (QR linking) self-test against an independent
/// test vector (web/testdata/provisioning-vector.json). LOCAL test only.
#[wasm_bindgen(js_name = runProvisioningSelftest)]
pub async fn run_provisioning_selftest(vector_json: String) -> String {
    let report = selftest::run_provisioning(&vector_json).await;
    serde_json::to_string(&report).expect("report serializes")
}
