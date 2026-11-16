//! Lifted STARK prover and verifier (LMCS-based).
//!
//! This crate implements the lifted STARK protocol combining LMCS (Lifted Matrix
//! Commitment Scheme), DEEP quotient construction, and FRI for low-degree testing.
//!
//! # AIR Trust Model
//!
//! The lifted STARK has three trust domains:
//!
//! 1. **AIR = trusted** — Authored [`air::LiftedAir`], executable [`air::AirKernel`] and collection
//!    [`air::MultiAir`] implementations are application code. The kernel must implement the
//!    relation described by its descriptor. A descriptor fingerprint associates configuration; it
//!    does not authenticate evaluator code. Structural diagnostics are available through
//!    [`air::debug::assert_multi_air_valid`] and [`debug::assert_prover_setup`].
//!
//! 2. **Runtime inputs = validated** — [`Statement::new`](air::Statement::new),
//!    [`ProverStatement::new`](air::ProverStatement::new), setup association and the per-proof
//!    execution plan validate caller/proof shapes, degree capacity, quotient allocation and domains
//!    before transcript work. Failures return typed [`ProverError`] / [`VerifierError`].
//!
//! 3. **Proof = untrusted** — Transcript data is verified cryptographically (PCS errors, constraint
//!    mismatch, strict transcript consumption and external assertions).
//!
//! ## Validated at runtime
//!
//! - **Shape well-formedness** — At most 256 instances; power-of-two heights of at least 2 rows.
//!   Maximum LDE order is bounded by the field's two-adicity and the host's `usize` width.
//! - **Per-AIR dimensions** — Public inputs and main trace width match the descriptor schema; each
//!   height supports its periodic columns and `aux_inputs` fits the collection's budget.
//! - **Degree capacity** — Actual-height descriptor analysis must fit the kernel's conservative
//!   quotient allocation, and that allocation must fit the PCS blowup.
//! - **Preprocessed table ownership** — Each fixed-data AIR's main log height equals
//!   [`PreprocessedSpec::log_height`](air::PreprocessedSpec::log_height) in its source schema.
//!   Setup validates and owns the fixed matrices; witnesses and diagnostics borrow them.
//!   [`VerifierInstance::new`] validates an optional owned [`SetupIdentity`] against ordered
//!   fingerprints and PCS blowup/alignment, without constructing tables. The caller supplies an
//!   already trusted commitment.
//!
//! ## Trusted AIR contracts
//!
//! - Source configuration stays immutable while capture or analyzed data is reused. Equation
//!   structure, assertion class/global order and addressing cannot depend on input values or the
//!   selected expression backend.
//! - Row evaluation consumes immutable current/next rows, including the cyclic last-to-first pair,
//!   separately from the assertion sink and uniform public/challenge/export inputs.
//! - [`ProverAir::build_aux_trace`](air::ProverAir::build_aux_trace) returns owned auxiliary
//!   columns with the declared width, the main trace's height and ordered exports. Recoverable
//!   source/input failures are returned; successful output dimensions are trusted construction
//!   invariants asserted by the prover. Lookup arithmetic assumes nonzero divisors.
//! - [`Statement::eval_external`](air::Statement::eval_external) must return zero exactly when the
//!   cross-AIR interactions are well formed for the supplied inputs, exports and heights.

#![no_std]

extern crate alloc;

#[cfg(any(test, feature = "std"))]
extern crate std;

// ============================================================================
// Private implementation modules
// ============================================================================

pub mod air;
pub mod config;
pub mod debug;
pub(crate) mod domain;
pub mod lmcs;
pub mod lookup;
pub mod memory;
mod order;
pub mod pcs;
mod plan;
mod preprocessed;
pub mod proof;
pub mod prover;
pub mod recursive;
pub mod security;
mod selectors;
pub mod transcript;
pub(crate) mod util;
pub mod verifier;

pub use config::{GenericStarkConfig, StarkConfig};
pub use debug::check_constraints;
// `domain` and `order` are internal modules. Their error types surface through the public
// `ProverError` / `VerifierError`, and quotient-degree derivation is part of the relation
// configuration contract, so these items need public paths of their own.
pub use domain::{
    DomainError, QuotientRecompositionInputs, log_quotient_degree, quotient_recomposition_inputs,
};
pub use order::ShapeError;
pub use plan::PlanError;
pub use preprocessed::{Preprocessed, PreprocessedValidationError, SetupIdentity};
pub use prover::{ProverError, ProverInstance};
pub use verifier::{VerifierError, VerifierInstance};

// ============================================================================
// Namespaced re-exports from upstream crates
// ============================================================================

/// Stateful hasher primitives for LMCS construction.
pub mod hasher {
    pub use miden_crypto::hash::stateful::{
        Alignable, ChainingHasher, SerializingStatefulSponge, StatefulHasher, StatefulSponge,
    };
}

/// Shared test support and FRI vector generation.
///
/// Available during `cargo test`; external consumers must enable the `testing` feature. That
/// feature also exposes hash configurations and example AIRs.
#[cfg(any(test, feature = "testing"))]
pub mod testing;
