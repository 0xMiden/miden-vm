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
//!    [`air::LiftedAir::validate`] checks the statically-verifiable subset.
//!
//! 2. **Instance = validated** — The prover validates that its witness matches the AIR spec. The
//!    verifier validates instance metadata. Both return structured errors.
//!
//! 3. **Proof = untrusted** — Transcript data is verified cryptographically (PCS errors, constraint
//!    mismatch, etc.).
//!
//! ## Validated properties
//!
//! These are checked by [`air::LiftedAir::validate`]
//! and [`air::AirInstance::validate`], and enforced
//! by both prover and verifier before proceeding:
//!
//! - **No preprocessed trace** — the lifted protocol does not support them.
//! - **Positive aux width** — every AIR must have an auxiliary trace.
//! - **Periodic columns** — each has positive, power-of-two length ≤ trace height.
//! - **Constraint degree** — `log_quotient_degree() ≤ log_blowup`.
//! - **Instance dimensions** — trace width, public values length, var-len public inputs count, and
//!   trace height (power of two) all match the AIR specification.
//!
//! ## Unchecked trust assumptions
//!
//! These cannot be verified statically and are the AIR implementer's responsibility:
//!
//! 1. **Window size** — Only transition window size 2.
//! 2. **Deterministic constraints** — `eval()` emits the same number and types of constraints
//!    regardless of builder implementation.
//! 3. **Consistent aux builder** — `AuxBuilder::build_aux_trace` returns width = `aux_width()`,
//!    height = main trace height, and exactly `num_aux_values()` values. (The prover asserts these
//!    at runtime as a defense-in-depth sanity check.)
//! 4. **Sound `reduced_aux_values`** — Returns correct bus contributions for valid inputs.

#![no_std]

extern crate alloc;

// ============================================================================
// Private implementation modules
// ============================================================================

mod config;
mod coset;
pub mod debug;
pub mod lmcs;
mod pcs;
pub mod proof;
pub mod prover;
mod selectors;
pub mod verifier;

pub use config::{GenericStarkConfig, StarkConfig};
pub use coset::LiftedCoset;
pub use debug::{check_constraints, check_constraints_multi};
pub use lmcs::{
    Lmcs, LmcsError, LmcsTree, OpenedRows,
    bitrev::{BitReversibleMatrix, materialize_bitrev},
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
    utils::log2_strict_u8,
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
pub use prover::{ProverError, prove_multi, prove_single};
pub use verifier::{VerifierError, verify_multi, verify_single};

/// Backward-compatible PCS namespace.
///
/// Older consumers accessed DEEP/FRI/PCS types through `miden_lifted_stark::fri`.
/// The current implementation organizes them under an internal `pcs` module, so this
/// public facade preserves the earlier module path.
pub mod fri {
    pub use crate::{
        DeepError, DeepTranscript, FriError, FriRoundTranscript, FriTranscript, PcsError,
        PcsOpenedValues, PcsParams, PcsParamsError, PcsTranscript,
    };

    pub mod deep {
        pub use crate::{DeepError, DeepTranscript, PcsOpenedValues};

        pub mod proof {
            pub use crate::{DeepTranscript, PcsOpenedValues};
        }

        pub mod verifier {
            pub use crate::DeepError;
        }
    }

    pub mod params {
        pub use crate::{PcsParams, PcsParamsError};
    }

    pub mod proof {
        pub use crate::PcsTranscript;
    }

    pub mod round_proof {
        pub use crate::{FriRoundTranscript, FriTranscript};
    }

    pub mod verifier {
        pub use crate::{FriError, PcsError};
    }
}

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
        AirInstance,
        AirValidationError,
        AirWitness,
        AuxBuilder,
        BaseAir,
        EmptyWindow,
        ExtensionBuilder,
        FilteredAirBuilder,
        LiftedAir,
        LiftedAirBuilder,
        PeriodicAirBuilder,
        PermutationAirBuilder,
        ReducedAuxValues,
        ReductionError,
        RowWindow,
        TracePart,
        VarLenPublicInputs,
        WindowAccess,
        log2_strict_u8,
        validate_instances,
    };

    /// Symbolic constraint analysis types from upstream p3-air.
    pub mod symbolic {
        pub use miden_lifted_air::symbolic::*;
    }

    /// Auxiliary trace types (builder, cross-AIR identity checking).
    pub mod auxiliary {
        pub use miden_lifted_air::auxiliary::*;
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
