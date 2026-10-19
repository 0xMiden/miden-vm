//! Differential fuzz target: the handler loader's wasmparser pass vs wasmi's validator.
//!
//! The loader's start-section check, instantiation-cost estimate, and manifest extraction
//! re-parse the binary with wasmparser, pinned to the version wasmi validates with, and
//! conservatively reject modules that do not parse. A module that wasmi validates but the pass
//! rejects would therefore be falsely refused; such a disagreement means the loader's
//! wasmparser pin and wasmi's own wasmparser dependency drifted apart. This target hunts for
//! it, in the plain parse and in the static analysis the loader builds on it.
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
        assert!(
            miden_wasm_event_handlers::fuzz_module_statics(data),
            "wasmi validated a module the loader's static analysis rejects"
        );
    }
});
