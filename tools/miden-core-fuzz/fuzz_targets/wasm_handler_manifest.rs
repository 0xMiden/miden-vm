//! Fuzz target for the Wasm handler manifest extraction.
//!
//! `manifest_from_module` walks the section layout of an untrusted Wasm binary and parses the
//! `miden:event-manifest` custom-section records; the walk must reject malformed input without
//! panics.
//!
//! Run with: cargo +nightly fuzz run wasm_handler_manifest --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_wasm_event_handlers::manifest_from_module;

fuzz_target!(|data: &[u8]| {
    let _ = manifest_from_module(data);
});
