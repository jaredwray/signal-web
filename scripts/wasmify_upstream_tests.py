#!/usr/bin/env python3
"""Mechanical transforms applied to libsignal's rust/protocol/tests.

Only two kinds of change are made; test bodies and assertions are untouched:

1. `#[test]` -> `#[wasm_bindgen_test::wasm_bindgen_test]`, plus one
   `wasm_bindgen_test_configure!(run_in_browser)` line per test crate, because
   libtest's harness cannot run on wasm32-unknown-unknown.
2. `SystemTime::now()` -> `support::wasm_now()`, because std's SystemTime::now()
   panics on wasm32-unknown-unknown. `wasm_now()` returns the same type
   (std::time::SystemTime), derived from the browser's Date.now().

Every substitution is counted and printed so the log shows exactly what changed.
"""
import pathlib
import re
import sys

dest = pathlib.Path(sys.argv[1])
counts = {}

SHIM = '''

/// Added by signal-web's wasmify_upstream_tests.py: std's SystemTime::now()
/// panics on wasm32-unknown-unknown, so derive the time from Date.now().
pub fn wasm_now() -> std::time::SystemTime {
    std::time::SystemTime::UNIX_EPOCH
        + std::time::Duration::from_millis(js_sys::Date::now() as u64)
}
'''

for path in sorted(dest.rglob("*.rs")):
    src = path.read_text()
    is_support = path.parent.name == "support"
    n_test = src.count("#[test]")
    src = src.replace("#[test]", "#[wasm_bindgen_test::wasm_bindgen_test]")
    pattern = re.compile(r"(?:std::time::)?SystemTime::now\(\)")
    replacement = "wasm_now()" if is_support else "support::wasm_now()"
    src, n_now = pattern.subn(replacement, src)
    if is_support:
        src += SHIM
    else:
        # Insert the configure line after the leading comment/attribute block.
        lines = src.split("\n")
        i = 0
        while i < len(lines) and (lines[i].startswith("//") or lines[i].startswith("#!") or not lines[i].strip()):
            i += 1
        lines.insert(i, "wasm_bindgen_test::wasm_bindgen_test_configure!(run_in_browser);\n")
        src = "\n".join(lines)
    path.write_text(src)
    counts[str(path.relative_to(dest))] = {"#[test]": n_test, "SystemTime::now()": n_now}

for name, c in counts.items():
    print(f"{name}: replaced {c['#[test]']} test attributes, {c['SystemTime::now()']} SystemTime::now() calls")
