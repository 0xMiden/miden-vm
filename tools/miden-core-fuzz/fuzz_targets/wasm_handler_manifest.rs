//! Fuzz target for the Wasm handler manifest extraction.
//!
//! `manifest_from_module` parses an untrusted Wasm binary with wasmparser and reads the
//! `miden:event-manifest` custom-section records; malformed input must be rejected without
//! panics.
//!
//! Run with: cargo +nightly fuzz run wasm_handler_manifest --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_wasm_event_handlers::manifest_from_module;

fuzz_target!(|data: &[u8]| {
    let _ = manifest_from_module(data);
});
