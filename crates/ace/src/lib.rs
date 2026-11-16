//! ACE circuit runtime and optional compiler for Miden AIRs.
//!
//! The default runtime supports `no_std` with `alloc`. It owns encoded circuits, instruction
//! packing and decoding, input layouts, and proof-order tags. Enable `compiler` in build
//! dependencies to capture AIRs, generate circuits, and render MASM through `miden_ace::compiler`.
//! Core, STARK, and the constraint compiler are optional compiler dependencies, absent from the
//! normal runtime dependency graph. The `std` feature enables standard-library support without
//! enabling compilation.
//!
//! The compiler pipeline is:
//! 1. Capture AIR constraints into the `miden-constraint-compiler` IR.
//! 2. Lower the constraint graph into a DAG that mirrors verifier constraints evaluation.
//! 3. Emit an ACE circuit plus an `InputLayout` describing the MASM ACE-READ section order.
//!
//! `compiler::CapturedAir` captures a handwritten AIR once. A `compiler::CompiledRelation` borrows
//! selected captures in canonical order and derives constraint degrees, committed row geometry,
//! quotient padding, and the ACE input layout. Native evaluator emission and recursive verifier
//! generation consume the same captures. Logical quotient chunks and padded committed coordinates
//! are tracked separately.
//!
//! Authored PVM constraints and height rules live in
//! `miden_air_definitions::precompiles::relation`; `miden-air` owns protocol configuration and
//! identity pins. Its build script emits native evaluators and canonical ACE streams into
//! `OUT_DIR`; recursive verifier parameter generators regenerate MASM explicitly. Relation
//! identities and verifier roots are explicit pins checked independently.
//!
//! The resulting circuit is intended to run inside the recursive verifier. All
//! input layout decisions (point-major OOD ordering, aux/quotient coords, and
//! alpha/beta randomness expansion) are centralized in this crate so tests can
//! validate both layout and evaluation.
//!
//! Quick start:
//! ```ignore
//! use miden_ace::compiler::{AceConfig, LayoutKind, build_ace_circuit_for_air};
//! use miden_air_definitions::vm::MidenAir;
//!
//! let config = AceConfig { num_quotient_chunks: 8, layout: LayoutKind::Masm };
//! let circuit = build_ace_circuit_for_air(&MidenAir::CORE, config);
//! ```
//!
//! Module map (data flow):
//! - `compiler`: AIR capture, verifier DAG lowering, circuit emission, and MASM rendering.
//! - [`InputLayout`]: runtime READ-section layout and index mapping.
//! - [`EncodedCircuit`]: runtime ACE instruction stream and padding metadata.
//! - [`order_tag`] and [`order_from_tag`]: committed-trace proof-order encodings.
//! - `instruction`: packed arithmetic operations shared with the processor.
//!
//! See [`migration`] for changed public paths and compiler API replacements.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;
#[cfg(all(test, not(feature = "std")))]
extern crate std;

/// AIR capture, circuit compilation, and MASM generation.
#[cfg(feature = "compiler")]
pub mod compiler;

mod encode;
pub mod instruction;
mod layout;
pub mod migration;
mod proof_order;

/// Extension field degree (quadratic extension for Miden VM).
pub const EXT_DEGREE: usize = 2;

pub use crate::{
    encode::{EncodedCircuit, RecursiveAceCircuit},
    layout::{InputCounts, InputKey, InputLayout},
    proof_order::{MAX_ORDER_AIRS, factorial, order_from_tag, order_tag},
};
