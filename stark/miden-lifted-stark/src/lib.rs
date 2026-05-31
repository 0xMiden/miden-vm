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
//!    tests/setup with [`miden_lifted_air::debug::assert_multi_air_valid`] or
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
//! 1. **AIR structural contract** — non-empty AIR collection, shared public-value count, no
//!    preprocessed trace, positive aux width, power-of-two periodic column lengths, and matching
//!    override helpers. Checked by [`miden_lifted_air::debug::assert_multi_air_valid`]. These are
//!    not typed `Statement::new` errors.
//! 2. **Window size** — only transition window size 2.
//! 3. **Deterministic constraints** — `eval()` emits the same number and types of constraints
//!    regardless of builder implementation.
//! 4. **[`ProverStatement::build_aux_traces`](air::ProverStatement::build_aux_traces) output** —
//!    per AIR, an aux trace of width `aux_width()`, height matching the main trace, and exactly
//!    `num_aux_values()` aux values. A malformed output is caught by the prover (LDE/commit panic)
//!    or by verification, since the verifier re-derives these shapes from the AIR contract.
//! 5. **Sound [`Statement::eval_external`](air::Statement::eval_external)** — Returns external
//!    assertions that are satisfied (equal zero) iff the proof's cross-AIR interactions are
//!    well-formed for the given aux values and public inputs.

#![no_std]

extern crate alloc;

// ============================================================================
// Private implementation modules
// ============================================================================

mod config;
pub mod debug;
pub(crate) mod domain;
pub mod lmcs;
mod order;
pub mod pcs;
pub mod proof;
pub mod prover;
mod selectors;
pub(crate) mod util;
pub mod verifier;

pub use config::{GenericStarkConfig, StarkConfig};
pub use debug::check_constraints;
// `domain` and `order` are internal modules, but these error types surface through the public
// `ProverError` / `VerifierError`, so they need a public path of their own.
pub use domain::DomainError;
pub use order::ShapeError;
pub use prover::{ProverError, prove};
pub use verifier::{VerifierError, verify};

// ============================================================================
// Namespaced re-exports from upstream crates
// ============================================================================

/// AIR traits, statement/witness types, and upstream `p3-air` re-exports.
///
/// This module re-exports items from [`miden_lifted_air`], which in turn
/// re-exports `p3-air` types. Consumers should never need to depend on `p3-air`
/// directly.
pub mod air {
    pub use miden_lifted_air::{
        // Upstream p3-air re-exports
        Air,
        AirBuilder,
        AirBuilderWithContext,
        BaseAir,
        ConstraintDegrees,
        EmptyWindow,
        ExtensionBuilder,
        FilteredAirBuilder,
        // Lifted AIR types
        InstanceError,
        LiftedAir,
        LiftedAirBuilder,
        MultiAir,
        PeriodicAirBuilder,
        PermutationAirBuilder,
        ProverStatement,
        ReductionError,
        RowWindow,
        Statement,
        WindowAccess,
        debug,
        log2_strict_u8,
    };

    /// Symbolic constraint analysis types from upstream p3-air.
    pub mod symbolic {
        pub use miden_lifted_air::symbolic::*;
    }

    /// AIR constraint utility functions from upstream p3-air.
    pub mod utils {
        pub use miden_lifted_air::utils::*;
    }
}

/// Stateful hasher primitives for LMCS construction.
pub mod hasher {
    pub use miden_stateful_hasher::{
        Alignable, ChainingHasher, SerializingStatefulSponge, StatefulHasher, StatefulSponge,
    };
}

/// Testing infrastructure: configurations, fixtures, and example AIRs.
///
/// Available when the `testing` feature is enabled or during `cargo test`.
/// Integration tests should use `cargo test --features testing`.
#[cfg(any(test, feature = "testing"))]
pub mod testing;
