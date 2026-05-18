#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, vec::Vec};

use miden_air::{ProcessorAir, PublicInputs, config};
use miden_core::{
    Felt, WORD_SIZE,
    deferred::{DeferredState, IntegrityError, Schema},
    field::QuadFelt,
};
use miden_crypto::stark::{
    StarkConfig, air::VarLenPublicInputs, challenger::CanObserve, lmcs::Lmcs, proof::StarkProof,
};
use serde::de::DeserializeOwned;

// RE-EXPORTS
// ================================================================================================
mod exports {
    pub use miden_core::{
        Word,
        program::{Kernel, ProgramInfo, StackInputs, StackOutputs},
        proof::{ExecutionProof, HashFunction},
    };
    pub mod math {
        pub use miden_core::Felt;
    }
}
pub use exports::*;

// VERIFIER
// ================================================================================================

/// Verifies a STARK proof of correct VM execution under the supplied deferred-DAG `schema`.
///
/// Stack inputs are expected to be ordered as if they would be pushed onto the stack one by one.
/// Stack outputs are expected in the order they appear at the top of the stack (reverse of inputs).
///
/// This is **L2** of the layered verifier API:
/// 1. Rehydrate the proof's deferred-DAG wire under `schema`. This re-runs every reachable
///    predicate's `reduce`, validates content-addressing, and walks the AND-chain. The hydrated
///    state's `root` is the canonical *deferred commitment*.
/// 2. Verify the STARK proof with that commitment as a public input (delegating to
///    [`verify_stark`], the L1 raw-STARK entry-point).
///
/// Returns the security level (in bits) and the deferred commitment that the proof commits to.
///
/// # Errors
/// Returns an error if the deferred-DAG wire fails any rehydration check
/// ([`VerificationError::DeferredIntegrity`]) or if the STARK proof fails to verify under that
/// commitment ([`VerificationError::StarkVerificationError`]). Rehydration runs first; a tampered
/// wire fails fast before any STARK work happens.
#[tracing::instrument("verify_program", skip_all)]
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    schema: &dyn Schema,
    proof: ExecutionProof,
) -> Result<(u32, Word), VerificationError> {
    let security_level = proof.security_level();

    let (hash_fn, proof_bytes, deferred_wire) = proof.into_parts();

    // Rehydrate the wire under the installed schema. This validates content-addressing, the
    // AND-chain shape, AND re-evaluates every reachable predicate. The hydrated state's root
    // is the canonical deferred commitment used as a public input to the STARK proof below.
    let state = DeferredState::rehydrate(&deferred_wire, schema)
        .map_err(VerificationError::DeferredIntegrity)?;
    let deferred_commitment = state.root();

    verify_stark(
        program_info,
        stack_inputs,
        stack_outputs,
        deferred_commitment,
        hash_fn,
        proof_bytes,
    )?;

    Ok((security_level, deferred_commitment))
}

// HELPER FUNCTIONS
// ================================================================================================

/// **L1 of the layered verifier API.** Verifies a STARK proof against the supplied public inputs,
/// including the `deferred_commitment` (the deferred-DAG root) as a verifier-supplied public
/// input.
///
/// Pure STARK verification — no schema, no deferred-DAG walk. The caller is responsible for
/// computing `deferred_commitment` honestly; typically by calling
/// [`DeferredState::rehydrate`] on the proof's wire. The schema-aware [`verify`] does both
/// steps; this entry-point is exposed for callers that derive the commitment by other means
/// (e.g. a recursive precompile-VM proof that proves the wire's correctness independently).
pub fn verify_stark(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    deferred_commitment: Word,
    hash_fn: HashFunction,
    proof_bytes: Vec<u8>,
) -> Result<(), VerificationError> {
    let program_hash = *program_info.program_hash();

    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, deferred_commitment);
    let (public_values, kernel_felts) = pub_inputs.to_air_inputs();
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

    let params = config::pcs_params();
    match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
    }
    .map_err(|e| VerificationError::StarkVerificationError(program_hash, Box::new(e)))?;

    Ok(())
}

// ERRORS
// ================================================================================================

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify STARK proof for program with hash {0}")]
    StarkVerificationError(Word, #[source] Box<StarkVerificationError>),
    #[error("deferred-DAG integrity check failed: {0}")]
    DeferredIntegrity(#[from] IntegrityError),
}

// STARK PROOF VERIFICATION
// ================================================================================================

/// Errors that can occur during low-level STARK proof verification.
#[derive(Debug, thiserror::Error)]
pub enum StarkVerificationError {
    #[error("failed to deserialize proof: {0}")]
    Deserialization(#[from] bincode::Error),
    #[error("log_trace_height {0} exceeds the two-adic order of the field")]
    InvalidTraceHeight(u8),
    #[error(transparent)]
    Verifier(#[from] miden_crypto::stark::verifier::VerifierError),
}

/// Verifies a STARK proof for the given public values.
fn verify_stark_proof<SC>(
    config: &SC,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    proof_bytes: &[u8],
) -> Result<(), StarkVerificationError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: DeserializeOwned,
{
    let proof: StarkProof<Felt, QuadFelt, SC> = bincode::deserialize(proof_bytes)?;

    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);
    challenger.observe_slice(public_values);
    config::observe_var_len_public_inputs(&mut challenger, var_len_public_inputs, &[WORD_SIZE]);
    miden_crypto::stark::verifier::verify_single(
        config,
        &ProcessorAir,
        public_values,
        var_len_public_inputs,
        &proof,
        challenger,
    )?;
    Ok(())
}
