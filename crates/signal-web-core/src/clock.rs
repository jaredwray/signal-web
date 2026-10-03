//! Wall-clock access that works on `wasm32-unknown-unknown`.
//!
//! `std::time::SystemTime::now()` panics on `wasm32-unknown-unknown` ("time not
//! implemented on this platform"), but `SystemTime` arithmetic works. libsignal's
//! session APIs take `now: SystemTime` as a parameter, so we derive it from the
//! browser clock instead.

use std::time::{Duration, SystemTime};

pub fn now_millis() -> u64 {
    #[cfg(target_arch = "wasm32")]
    {
        js_sys::Date::now() as u64
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after 1970")
            .as_millis() as u64
    }
}

pub fn now() -> SystemTime {
    SystemTime::UNIX_EPOCH + Duration::from_millis(now_millis())
}

/// High-resolution monotonic milliseconds (`performance.now()` in the browser).
pub fn perf_ms() -> f64 {
    #[cfg(target_arch = "wasm32")]
    {
        use wasm_bindgen::JsCast;
        let global = js_sys::global();
        js_sys::Reflect::get(&global, &"performance".into())
            .ok()
            .and_then(|perf| {
                let now = js_sys::Reflect::get(&perf, &"now".into()).ok()?;
                let now: js_sys::Function = now.dyn_into().ok()?;
                now.call0(&perf).ok()?.as_f64()
            })
            .unwrap_or_else(js_sys::Date::now)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        use std::sync::OnceLock;
        use std::time::Instant;
        static START: OnceLock<Instant> = OnceLock::new();
        START.get_or_init(Instant::now).elapsed().as_secs_f64() * 1000.0
    }
}
