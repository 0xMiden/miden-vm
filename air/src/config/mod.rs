//! STARK configuration factories for different hash functions.
//!
//! This module provides factory functions that create [`StarkConfig`] instances
//! for different hash functions (Blake3, Keccak, RPO256, Poseidon2, RPX256). Each config
//! bundles the PCS parameters, LMCS commitment scheme, and challenger for proving
//! and verification.
//!
//! The [`prove`] and [`verify`] free functions handle transcript management
//! (Fiat-Shamir seeding, serialization) on top of the upstream prover/verifier.

use alloc::vec::Vec;

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_crypto::stark::{
    StarkConfig,
    air::{AuxBuilder, VarLenPublicInputs},
    challenger::CanObserve,
    fri::{DeepParams, FriFold, FriParams, PcsParams},
    lmcs::Lmcs,
    proof::{StarkOutput, StarkProof},
};
use serde::{Serialize, de::DeserializeOwned};

use crate::LiftedAir;

mod blake3;
mod keccak;
mod poseidon2;
mod rpo;
mod rpx;

pub use blake3::create_blake3_256_config;
pub use keccak::create_keccak_config;
pub use poseidon2::create_poseidon2_config;
pub use rpo::create_rpo_config;
pub use rpx::create_rpx_config;

// SHARED TYPES
// ================================================================================================

/// DFT implementation for polynomial operations.
pub type Dft = miden_crypto::stark::dft::Radix2DitParallel<Felt>;

/// PCS parameters shared by all hash function configurations.
///
/// - FRI with 8x blowup (log_blowup = 3)
/// - Arity-4 folding
/// - Final polynomial degree 2^7 = 128
/// - 16 bits of folding proof-of-work
/// - 27 query repetitions
pub const PCS_PARAMS: PcsParams = PcsParams {
    fri: FriParams {
        log_blowup: 3,
        fold: FriFold::ARITY_4,
        log_final_degree: 7,
        folding_pow_bits: 16,
    },
    deep: DeepParams { deep_pow_bits: 0 },
    num_queries: 27,
    query_pow_bits: 0,
};

// ERRORS
// ================================================================================================

/// Errors that can occur during STARK proof generation.
#[derive(Debug, thiserror::Error)]
pub enum ProvingError {
    #[error(transparent)]
    Prover(#[from] miden_crypto::stark::prover::ProverError),
    #[error("failed to serialize proof: {0}")]
    Serialization(#[from] bincode::Error),
}

/// Errors that can occur during STARK proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to deserialize proof: {0}")]
    Deserialization(#[from] bincode::Error),
    #[error(transparent)]
    Verifier(#[from] miden_crypto::stark::verifier::VerifierError),
}

// PROVE / VERIFY
// ================================================================================================

/// Generates a STARK proof for the given AIR, trace, and public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// prover. Returns the serialized proof bytes.
pub fn prove<A, B, SC>(
    config: &SC,
    air: &A,
    trace: &RowMajorMatrix<Felt>,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    aux_builder: &B,
) -> Result<Vec<u8>, ProvingError>
where
    A: LiftedAir<Felt, QuadFelt>,
    B: AuxBuilder<Felt, QuadFelt>,
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: Serialize,
{
    let mut challenger = config.challenger();
    challenger.observe_slice(public_values);
    // TODO: observe var_len_public_inputs in the transcript for Fiat-Shamir binding.
    //   This also requires updating the recursive verifier to absorb both fixed and
    //   variable-length public inputs.
    // TODO: observe ACE commitment once ACE verification is integrated.
    let output: StarkOutput<Felt, QuadFelt, SC> = miden_crypto::stark::prover::prove_single(
        config,
        air,
        trace,
        public_values,
        var_len_public_inputs,
        aux_builder,
        challenger,
    )?;
    Ok(bincode::serialize(&output.proof)?)
}

/// Verifies a STARK proof for the given AIR and public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// verifier.
pub fn verify<A, SC>(
    config: &SC,
    air: &A,
    log_trace_height: usize,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    proof_bytes: &[u8],
) -> Result<(), VerificationError>
where
    A: LiftedAir<Felt, QuadFelt>,
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: DeserializeOwned,
{
    let proof: StarkProof<Felt, QuadFelt, SC> = bincode::deserialize(proof_bytes)?;
    let mut challenger = config.challenger();
    challenger.observe_slice(public_values);
    // TODO: observe var_len_public_inputs in the transcript for Fiat-Shamir binding.
    //   This also requires updating the recursive verifier to absorb both fixed and
    //   variable-length public inputs.
    // TODO: observe ACE commitment once ACE verification is integrated.
    miden_crypto::stark::verifier::verify_single(
        config,
        air,
        log_trace_height,
        public_values,
        var_len_public_inputs,
        &proof,
        challenger,
    )?;
    Ok(())
}
