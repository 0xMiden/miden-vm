//! Fuzz target for EventHandlerSection deserialization.
//!
//! The section is untrusted package input with explicit decode-time size caps; the decoder must
//! reject malformed and oversized payloads without panics or large allocations.
//!
//! The target calls `EventHandlerSection::from_payload`, which is the same function
//! `Package::event_handlers` uses, so the fuzzed path cannot drift from the production one.
//!
//! Run with: cargo +nightly fuzz run event_handler_section_deserialize --fuzz-dir tools/miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_mast_package::EventHandlerSection;

fuzz_target!(|data: &[u8]| {
    let _ = EventHandlerSection::from_payload(data);
});
