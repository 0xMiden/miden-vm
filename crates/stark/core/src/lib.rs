//! Lifted STARK prover and verifier (LMCS-based).
//!
//! This crate implements the lifted STARK protocol combining LMCS (Lifted Matrix
//! Commitment Scheme), DEEP quotient construction, and FRI for low-degree testing.
//!
//! # AIR Trust Model
//!
//! The lifted STARK has three trust domains:
//!
//! 1. **AIR = trusted** — [`air::LiftedAir`] / [`air::MultiAir`] implementations are application
//!    code. Structural mistakes, including an empty AIR collection, may panic; check them in
//!    tests/setup with [`crate::air::debug::assert_multi_air_valid`] or
//!    [`debug::assert_prover_setup`].
//!
//! 2. **Runtime inputs = validated** — [`Statement::new`](air::Statement::new),
//!    [`ProverStatement::new`](air::ProverStatement::new), internal trace-order reconstruction, and
//!    domain checks validate caller/proof shape data and return typed [`ProverError`] /
//!    [`VerifierError`] values.
//!
//! 3. **Proof = untrusted** — Transcript data is verified cryptographically (PCS errors, constraint
//!    mismatch, etc.).
//!
//! ## Validated at runtime
//!
//! Checked before cryptographic work begins: [`Statement::new`](air::Statement::new) /
//! [`ProverStatement::new`](air::ProverStatement::new) for caller inputs and prover trace shape,
//! internal trace-order reconstruction for proof/caller heights, and domain checks for
//! `log_quotient_degree(air) ≤ log_blowup`:
//!
//! - **Shape well-formedness** — ≤ 256 instances, with the maximum LDE order `log_trace_height +
//!   log_blowup` bounded by the field's two-adicity and the host's `usize` width.
//! - **Compat** — `log_quotient_degree(air) ≤ log_blowup`, per AIR.
//! - **Per-AIR instance dimensions** — public values length matches `num_public_values()`, trace
//!   height is at least 2 rows, trace height ≥ max periodic column length, trace width matches
//!   `width()` (prover-only), raw height is a power of two (prover-only), `aux_inputs.len() ≤
//!   max_aux_inputs`.
//!
//! ## Trusted AIR contracts
//!
//! These are AIR implementer responsibilities. Run [`debug::assert_prover_setup`] (or its
//! components) from your test harness to catch structural mistakes early:
//!
//! 1. **AIR structural contract** — non-empty AIR collection, shared public-value count, positive
//!    aux width, power-of-two periodic column lengths, and matching override helpers. Checked by
//!    [`crate::air::debug::assert_multi_air_valid`]. These are not typed `Statement::new` errors.
//! 2. **Window size** — only transition window size 2.
//! 3. **Deterministic constraints** — `eval()` emits the same number and types of constraints
//!    regardless of builder implementation.
//! 4. **Aux trace output** —
//!    [`build_aux_trace_with_preprocessed`](air::LiftedAir::build_aux_trace_with_preprocessed)
//!    returns, per AIR, a trace of width `aux_width()`, height matching the main trace, and exactly
//!    `num_aux_values()` aux values. A malformed output is caught by the prover (LDE/commit panic)
//!    or by verification, since the verifier re-derives these shapes from the AIR contract.
//! 5. **Sound [`Statement::eval_external`](air::Statement::eval_external)** — Returns cross-AIR
//!    assertion values that are zero iff the proof's cross-AIR interactions are well-formed for the
//!    given aux values and public inputs.

#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

pub use miden_core::Felt;

// ============================================================================
// Private implementation modules
// ============================================================================

pub mod config;
mod engine_config;
pub mod lookup;
pub mod security;
pub mod transcript;

#[cfg(feature = "capture")]
pub mod capture;
pub mod debug;
pub(crate) mod domain;
pub mod lmcs;
mod order;
pub mod pcs;
mod preprocessed;
pub mod proof;
pub mod prover;
mod selectors;
pub(crate) mod util;
pub mod verifier;

#[cfg(test)]
mod eidos_tests;

pub use debug::check_constraints;
// `domain` and `order` are internal modules. Their error types surface through the public
// `ProverError` / `VerifierError`, and quotient-degree derivation is part of the relation
// configuration contract, so these items need public paths of their own.
pub use domain::{
    DomainError, QuotientRecompositionInputs, log_quotient_degree, quotient_recomposition_inputs,
};
pub use engine_config::{GenericStarkConfig, StarkConfig};
pub use order::ShapeError;
pub use preprocessed::{Preprocessed, PreprocessedValidationError};
pub use prover::{ProverError, ProverInstance};
pub use verifier::{VerifierError, VerifierInstance};

// ============================================================================
// Namespaced re-exports from upstream crates
// ============================================================================

/// AIR traits, statement types, and portable symbolic analysis.
pub mod air;

/// Stateful hasher primitives for LMCS construction.
pub mod hasher {
    pub use miden_crypto::hasher::*;
}

/// Upstream Fiat-Shamir challenger traits and implementations.
pub mod challenger {
    pub use p3_challenger::{
        CanFinalizeDigest, CanObserve, DuplexChallenger, FieldChallenger, GrindingChallenger,
        HashChallenger, SerializingChallenger64,
    };
}

/// Upstream DFT traits and implementations.
pub mod dft {
    pub use p3_dft::{Radix2DFTSmallBatch, Radix2DitParallel, TwoAdicSubgroupDft};
}

/// Upstream matrix types; core imports these directly from `p3-matrix`.
pub mod matrix {
    pub use p3_matrix::{Matrix, dense::RowMajorMatrix};
}

/// Upstream symmetric cryptographic primitives.
pub mod symmetric {
    pub use p3_symmetric::{
        CompressionFunctionFromHasher, CryptographicPermutation, PaddingFreeSponge, Permutation,
        SerializingHasher, TruncatedPermutation,
    };
}

/// Shared test support and FRI vector generation.
///
/// Available during `cargo test`; external consumers must enable the `testing` feature. That
/// feature also exposes hash configurations and example AIRs.
#[cfg(any(test, feature = "testing"))]
pub mod testing;
