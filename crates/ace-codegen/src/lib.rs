//! ACE circuit codegen for Plonky3-based Miden AIRs.
//!
//! The default, `no_std` API provides encoded circuits and their input layouts.
//! Enable `compiler` in build dependencies to capture AIRs and generate circuits.
//!
//! The compiler pipeline is:
//! 1. Capture AIR constraints into the `miden-constraint-compiler` IR.
//! 2. Lower the constraint graph into a DAG that mirrors verifier constraints evaluation.
//! 3. Emit an ACE circuit plus an `InputLayout` describing the MASM ACE-READ section order.
//!
//! The resulting circuit is intended to run inside the recursive verifier. All
//! input layout decisions (point-major OOD ordering, aux/quotient coords, and
//! alpha/beta randomness expansion) are centralized in this crate so tests can
//! validate both layout and evaluation.
//!
//! Quick start:
//! ```ignore
//! use miden_ace_codegen::compiler::{AceConfig, LayoutKind, build_ace_circuit_for_air};
//! use miden_air::ChipletsAir;
//!
//! let config = AceConfig { num_quotient_chunks: 8, layout: LayoutKind::Masm };
//! let circuit = build_ace_circuit_for_air(&ChipletsAir, config)?;
//! ```
//!
//! Module map (data flow):
//! - `compiler`: AIR capture, verifier DAG lowering, circuit emission, and MASM rendering.
//! - [`InputLayout`]: runtime READ-section layout and index mapping.
//! - [`EncodedCircuit`]: runtime ACE instruction stream and padding metadata.
//! - [`order_tag`] and [`order_from_tag`]: committed-trace proof-order encodings.

#![cfg_attr(not(feature = "compiler"), no_std)]

extern crate alloc;

use alloc::string::String;

/// AIR capture, circuit compilation, and MASM generation.
#[cfg(feature = "compiler")]
pub mod compiler;

mod encode;
mod layout;
mod proof_order;
mod randomness;

/// Extension field degree (quadratic extension for Miden VM).
pub const EXT_DEGREE: usize = 2;

/// Errors returned by ACE codegen.
#[derive(Debug, thiserror::Error)]
pub enum AceError {
    #[error("invalid input length: expected {expected}, got {got}")]
    InvalidInputLength { expected: usize, got: usize },
    #[error("invalid input layout: {message}")]
    InvalidInputLayout { message: String },
}

pub use crate::{
    encode::{EncodedCircuit, RecursiveAceCircuit},
    layout::{InputCounts, InputKey, InputLayout},
    proof_order::{MAX_ORDER_AIRS, factorial, order_from_tag, order_tag},
};
