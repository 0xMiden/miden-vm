//! Miden VM relation proving, native verification, and recursive advice.
#![no_std]

extern crate alloc;
#[cfg(feature = "std")]
extern crate std;

pub mod debug;
pub mod memory;
#[cfg(feature = "prover")]
pub mod prover;
pub mod recursive;
pub mod security;
pub mod setup;
pub mod verifier;

pub use miden_core::proof::MAX_STARK_PROOF_BYTES;

#[cfg(all(test, feature = "std", feature = "prover"))]
mod block_stack_entry_kind_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod ctx_continuation_end_soundness_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod dyncall_bottom_slot_soundness_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod dyncall_end_relabel_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod dyncall_saved_frame_soundness_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod first_row_repeat_soundness_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod mrupdate_sibling_level_soundness_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod overflow_pointer_soundness_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod repeat_loop_schema_soundness_repro;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod repro_harness;
#[cfg(all(test, feature = "std", feature = "prover"))]
mod span_entry_soundness_repro;
