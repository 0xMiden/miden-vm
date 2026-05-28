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
//!    [`miden_lifted_air::debug::assert_multi_air_valid`] / [`debug::assert_prover_setup`] are
//!    panic-based helpers that check the statically-verifiable subset; passing a malformed AIR to
//!    the prover or verifier may panic or produce invalid proofs.
//!
//! 2. **Statement = validated** — The prover validates that its witness matches the AIR spec. The
//!    verifier validates the proof's shape metadata and the per-AIR contracts. Both return typed
//!    errors ([`ProverError`] / [`VerifierError`]) — the underlying checks run on the [`Statement`]
//!    / [`ProverStatement`] constructors and on `TraceOrder`.
//!
//! 3. **Proof = untrusted** — Transcript data is verified cryptographically (PCS errors, constraint
//!    mismatch, etc.).
//!
//! ## Validated at runtime
//!
//! Checked by [`Statement::new`] / [`ProverStatement::new`] (caller inputs and trace shape), the
//! inline `log_quotient_degree(air) ≤ log_blowup` compat check, plus the internal trace-order
//! reconstruction from the proof's log heights, all run before any cryptographic work begins:
//!
//! - **Shape well-formedness** — ≤ 256 instances, with the maximum LDE order `log_trace_height +
//!   log_blowup` bounded by the field's two-adicity and the host's `usize` width.
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
//! 1. **AIR structural contract** — non-empty AIR collection, shared public-value count, no
//!    preprocessed trace, positive aux width, power-of-two periodic column lengths, and matching
//!    override helpers. Checked by [`miden_lifted_air::debug::assert_multi_air_valid`].
//! 2. **Window size** — only transition window size 2.
//! 3. **Deterministic constraints** — `eval()` emits the same number and types of constraints
//!    regardless of builder implementation.
//! 4. **[`ProverStatement::build_aux_traces`] output** — per AIR, an aux trace of width
//!    `aux_width()`, height matching the main trace, and exactly `num_aux_values()` aux values.
//!    Debug builds assert these postconditions; release builds trust the AIR contract, and
//!    malformed output may panic later or produce invalid proofs.
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
pub mod lmcs;
mod order;
mod pcs;
pub mod proof;
pub mod prover;
mod selectors;
pub(crate) mod util;
pub mod verifier;

pub use config::{GenericStarkConfig, StarkConfig};
pub use debug::check_constraints;
pub use domain::{
    Coset, DomainError, EvaluationDomain, LiftedDomain, TwoAdicCoset, TwoAdicSubgroup,
    log_quotient_degree,
};
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
    log2_strict_u8,
};
pub use order::ShapeError;
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
