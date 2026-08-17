//! Differential fuzz target: the handler loader's Wasm section walker vs wasmi's validator.
//!
//! The loader's start-section check and manifest extraction re-parse the binary with a small
//! hand-rolled section walker and conservatively reject modules whose walk fails. A module that
//! wasmi validates but the walker rejects would therefore be falsely refused. This target hunts
//! for such disagreements.
//!
//! Run with: cargo +nightly fuzz run wasm_section_walk_differential --fuzz-dir tools/miden-core-fuzz

#![no_main]

use std::sync::OnceLock;

use libfuzzer_sys::fuzz_target;
use wasmi::{Engine, Module};

fuzz_target!(|data: &[u8]| {
    static ENGINE: OnceLock<Engine> = OnceLock::new();
    let engine = ENGINE.get_or_init(Engine::default);

    // wasmi's default config accepts a superset of what the handler loader's restricted config
    // accepts, so walk-success on this set is the stronger property.
    if Module::new(engine, data).is_ok() {
        assert!(
            miden_wasm_event_handlers::fuzz_walk_sections(data),
            "wasmi validated a module the section walker rejects"
        );
    }
});
