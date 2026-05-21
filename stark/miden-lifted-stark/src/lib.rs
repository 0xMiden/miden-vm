//! Lifted STARK prover and verifier (LMCS-based).
//!
//! This crate implements the lifted STARK protocol combining LMCS (Lifted Matrix
//! Commitment Scheme), DEEP quotient construction, and FRI for low-degree testing.
//!
//! # AIR Trust Model
//!
//! The lifted STARK has three trust domains:
//!
//! 1. **AIR = trusted** — [`air::LiftedAir`] implementations are correct application code. It is
//!    the AIR implementer's responsibility to satisfy the structural contract below.
//!    [`miden_lifted_air::debug::assert_airs_valid`] / [`debug::assert_prover_setup`] are
//!    panic-based helpers that check the statically-verifiable subset; passing a malformed AIR to
//!    the prover or verifier is undefined behaviour.
//!
//! 2. **Statement = validated** — The prover validates that its witness matches the AIR spec. The
//!    verifier validates the proof's shape metadata and the per-AIR contracts. Both return typed
//!    errors ([`ProverError`] / [`VerifierError`]) — see [`miden_lifted_air::validate`] for the
//!    underlying check functions.
//!
//! 3. **Proof = untrusted** — Transcript data is verified cryptographically (PCS errors, constraint
//!    mismatch, etc.).
//!
//! ## Validated at runtime
//!
//! Checked by [`miden_lifted_air::validate_inputs`] /
//! [`miden_lifted_air::validate_log_heights`] /
//! [`miden_lifted_air::validate_prover_traces`] plus
//! [`setup::validate_compatible`] plus
//! [`instance::TraceOrder::from_log_heights`], all run before any
//! cryptographic work begins:
//!
//! - **Shape well-formedness** — non-empty, ≤ 256 instances, each log trace height within the
//!   host's `usize` width.
//! - **Compat** — `log_quotient_degree(air) ≤ log_blowup`, per AIR.
//! - **Per-AIR instance dimensions** — public values length matches `num_public_values()`, trace
//!   height ≥ max periodic column length, trace width matches `width()` (prover-only), height is a
//!   power of two (prover-only), `aux_inputs.len() ≤ max_aux_inputs`.
//!
//! ## Trusted (NOT validated)
//!
//! These cannot be verified statically and are the AIR implementer's
//! responsibility. Run [`debug::assert_prover_setup`] (or its components)
//! from your test harness to enforce them in debug builds:
//!
//! 1. **AIR structural contract** — no preprocessed trace, positive aux width, power-of-two
//!    periodic column lengths. Checked by [`miden_lifted_air::debug::check_one_air`].
//! 2. **Window size** — only transition window size 2.
//! 3. **Deterministic constraints** — `eval()` emits the same number and types of constraints
//!    regardless of builder implementation.
//! 4. **[`ProverStatement::build_aux_traces`] output** — per AIR, an aux trace of width
//!    `aux_width()`, height matching the main trace, and exactly `num_aux_values()` aux values.
//!    Surface contract violations from tests via [`debug::assert_aux_traces_shape`].
//! 5. **Sound [`Statement::eval_external`]** — Returns external assertions that are satisfied
//!    (equal zero) iff the proof's cross-AIR interactions are well-formed for the given aux values
//!    and public inputs.

#![no_std]

extern crate alloc;

// ============================================================================
// Private implementation modules
// ============================================================================

mod config;
pub mod debug;
pub mod domain;
pub mod instance;
pub mod lmcs;
mod pcs;
pub mod proof;
pub mod prover;
mod selectors;
pub mod setup;
pub(crate) mod util;
pub mod verifier;

pub use config::{GenericStarkConfig, StarkConfig};
pub use debug::check_constraints;
pub use domain::{
    Coset, DomainError, EvaluationDomain, LiftedDomain, TwoAdicCoset, TwoAdicSubgroup,
    log_quotient_degree,
};
pub use instance::{ShapeError, TraceOrder};
pub use lmcs::{
    Lmcs, LmcsError, LmcsTree, OpenedRows,
    config::LmcsConfig,
    hiding_config::HidingLmcsConfig,
    lifted_tree::LiftedMerkleTree,
    merkle_witness::MerkleWitness,
    node_id::NodeId,
    proof::{
        BatchProof as LmcsBatchProof, BatchProofView as LmcsBatchProofView,
        LeafOpening as LmcsLeafOpening, Proof as LmcsProof,
    },
    row_list::RowList,
    tree_indices::{MissingSiblingsIter, TreeIndices},
};
pub use miden_lifted_air::{
    InstanceError, MultiAir, ProverStatement, ReductionError, Statement, log2_ceil_u8,
    log2_strict_u8, validate_inputs, validate_log_heights, validate_prover_traces,
};
pub use pcs::{
    deep::{
        proof::{DeepTranscript, OpenedValues as PcsOpenedValues},
        verifier::DeepError,
    },
    fri::{
        proof::{FriRoundTranscript, FriTranscript},
        verifier::FriError,
    },
    params::{PcsParams, PcsParamsError},
    proof::PcsTranscript,
    verifier::PcsError,
};
pub use proof::{StarkDigest, StarkOutput, StarkProof, StarkTranscript};
pub use prover::{ProverError, prove};
pub use setup::{CompatError, validate_compatible};
pub use util::bitrev::{BitReversibleMatrix, materialize_bitrev};
pub use verifier::{VerifierError, verify};

// ============================================================================
// Namespaced re-exports from upstream crates
// ============================================================================

/// AIR traits, instance/witness types, and upstream `p3-air` re-exports.
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
        // New surface (Commit 1):
        debug,
        log2_strict_u8,
        validate,
    };

    pub use crate::instance::TraceOrder;

    /// Symbolic constraint analysis types from upstream p3-air.
    pub mod symbolic {
        pub use miden_lifted_air::symbolic::*;
    }

    /// AIR constraint utility functions from upstream p3-air.
    pub mod utils {
        pub use miden_lifted_air::utils::*;
    }
}

/// Fiat-Shamir transcript channels and data types.
pub mod transcript {
    pub use miden_stark_transcript::{TranscriptChallenger, TranscriptData, TranscriptError};
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
