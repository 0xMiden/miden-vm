//! Fuzz target for Program serde deserialization.
//!
//! Run with: cargo +nightly fuzz run program_serde_deserialize --fuzz-dir miden-core-fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_core::program::Program;

fuzz_target!(|data: &[u8]| {
    if let Ok(program) = serde_json::from_slice::<Program>(data) {
        let _ = program.hash();
        let _ = program.to_info();
    }

    if let Ok(programs) = serde_json::from_slice::<Vec<Program>>(data) {
        for program in programs.iter().take(4) {
            let _ = program.hash();
            let _ = program.to_info();
        }
    }

    if let Ok(maybe_program) = serde_json::from_slice::<Option<Program>>(data) {
        if let Some(program) = maybe_program {
            let _ = program.hash();
            let _ = program.to_info();
        }
    }
});
