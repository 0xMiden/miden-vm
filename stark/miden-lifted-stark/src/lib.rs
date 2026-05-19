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
//!    the AIR implementer's responsibility to satisfy the contract below.
//!    [`miden_lifted_air::validate_air`] (single AIR) and [`miden_lifted_air::validate_airs`] (list
//!    of AIRs) are debug/testing helpers that check the statically-verifiable subset; passing a
//!    malformed AIR to the prover or verifier is undefined behaviour.
//!
//! 2. **Instance = validated** — The prover validates that its witness matches the AIR spec. The
//!    verifier validates the proof's shape metadata and the per-AIR contracts. Both return
//!    structured errors.
//!
//! 3. **Proof = untrusted** — Transcript data is verified cryptographically (PCS errors, constraint
//!    mismatch, etc.).
//!
//! ## Validated properties
//!
//! These are checked by [`instance::TraceOrder::from_log_heights`] (shape
//! well-formedness) and [`instance::validate_instance`] (per-AIR contract),
//! both run by prover and verifier before any cryptographic work begins:
//!
//! - **Shape well-formedness** — non-empty, ≤ 256 instances, each log trace height within the
//!   host's `usize` width.
//! - **Constraint degree** — log quotient degree ≤ log_blowup.
//! - **Per-AIR instance dimensions** — public values length matches `num_public_values()`, trace
//!   height ≥ max periodic column length, trace width matches `width()` (prover-only). Auxiliary
//!   public inputs are a flat slice with no framework-imposed shape; [`Instance::eval_external`]
//!   validates them itself.
//!
//! ## Unchecked trust assumptions
//!
//! These cannot be verified statically and are the AIR implementer's responsibility:
//!
//! 1. **AIR structural contract** — see [`miden_lifted_air::validate_air`] /
//!    [`miden_lifted_air::validate_airs`]: no preprocessed trace, positive aux width, power-of-two
//!    periodic column lengths.
//! 2. **Window size** — Only transition window size 2.
//! 3. **Deterministic constraints** — `eval()` emits the same number and types of constraints
//!    regardless of builder implementation.
//! 4. **Consistent prover inputs** — [`ProverInstance::build_aux_traces`] returns, per AIR, an aux
//!    trace of width `aux_width()`, height matching the main trace, and exactly `num_aux_values()`
//!    aux values. (The prover asserts these at runtime as a defense-in-depth sanity check.)
//! 5. **Sound [`Instance::eval_external`]** — Returns external assertions that are satisfied (equal
//!    zero) iff the proof's cross-AIR interactions are well-formed for the given aux values and
//!    public inputs.

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
pub(crate) mod util;
pub mod verifier;

pub use config::{GenericStarkConfig, StarkConfig};
pub use debug::check_constraints;
pub use domain::{
    Coset, DomainError, EvaluationDomain, LiftedDomain, TwoAdicCoset, TwoAdicSubgroup,
    log_quotient_degree,
};
pub use instance::{InstanceValidationError, ShapeError, TraceOrder};
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
    Instance, ProverInstance, ReductionError, log2_ceil_u8, log2_strict_u8,
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
        // Lifted AIR types
        AirStructureError,
        BaseAir,
        ConstraintDegrees,
        EmptyWindow,
        ExtensionBuilder,
        FilteredAirBuilder,
        Instance,
        LiftedAir,
        LiftedAirBuilder,
        PeriodicAirBuilder,
        PermutationAirBuilder,
        ProverInstance,
        ReductionError,
        RowWindow,
        TracePart,
        WindowAccess,
        log2_strict_u8,
        validate_air,
        validate_airs,
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
