#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, vec::Vec};

use miden_air::{LiftedAir, ProcessorAir, PublicInputs, config};
use miden_core::{
    Felt,
    field::{QuadFelt, TwoAdicField},
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
        precompile::{
            PrecompileTranscriptDigest, PrecompileTranscriptState, PrecompileVerificationError,
            PrecompileVerifierRegistry,
        },
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

/// Returns the security level of the proof if the specified program was executed correctly against
/// the specified inputs and outputs.
///
/// Specifically, verifies that if a program with the specified `program_hash` is executed against
/// the provided `stack_inputs` and some secret inputs, the result is equal to the `stack_outputs`.
///
/// Stack inputs are expected to be ordered as if they would be pushed onto the stack one by one.
/// Thus, their expected order on the stack will be the reverse of the order in which they are
/// provided, and the last value in the `stack_inputs` slice is expected to be the value at the top
/// of the stack.
///
/// Stack outputs are expected to be ordered as if they would be popped off the stack one by one.
/// Thus, the value at the top of the stack is expected to be in the first position of the
/// `stack_outputs` slice, and the order of the rest of the output elements will also match the
/// order on the stack. This is the reverse of the order of the `stack_inputs` slice.
///
/// # Errors
/// Returns an error if:
/// - The provided proof does not prove a correct execution of the program.
/// - The proof contains one or more precompile requests. When precompile requests are present, use
///   [`verify_with_precompiles`] instead with an appropriate [`PrecompileVerifierRegistry`] to
///   verify the precompile computations.
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    let (security_level, _commitment) = verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &PrecompileVerifierRegistry::new(),
    )?;
    Ok(security_level)
}

/// Identical to [`verify`], with additional verification of any precompile requests made during the
/// VM execution. The resulting aggregated precompile commitment is returned, which can be compared
/// against the commitment computed by the VM.
///
/// # Returns
/// Returns a tuple `(security_level, aggregated_commitment)` where:
/// - `security_level`: The security level (in bits) of the verified proof
/// - `aggregated_commitment`: A [`Word`] containing the final aggregated commitment to all
///   precompile requests, computed by recomputing and recording each precompile commitment in a
///   transcript. This value is the finalized digest of the recomputed precompile transcript.
///
/// # Errors
/// Returns any error produced by [`verify`], as well as any errors resulting from precompile
/// verification.
#[tracing::instrument("verify_program", skip_all)]
pub fn verify_with_precompiles(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
    precompile_verifiers: &PrecompileVerifierRegistry,
) -> Result<(u32, PrecompileTranscriptDigest), VerificationError> {
    let security_level = proof.security_level();

    let (hash_fn, proof_bytes, precompile_requests) = proof.into_parts();

    // Recompute the precompile transcript by verifying all precompile requests and recording the
    // commitments.
    // If no verifiers were provided (e.g. when this function was called from `verify()`),
    // but the proof contained requests anyway, returns a `NoVerifierFound` error.
    let recomputed_transcript = precompile_verifiers
        .requests_transcript(&precompile_requests)
        .map_err(VerificationError::PrecompileVerificationError)?;
    let pc_transcript_state = recomputed_transcript.state();

    // Verify the STARK proof with the recomputed transcript state in public inputs
    verify_stark(
        program_info,
        stack_inputs,
        stack_outputs,
        pc_transcript_state,
        hash_fn,
        proof_bytes,
    )?;

    // Finalize transcript to return the digest
    let digest = recomputed_transcript.finalize();
    Ok((security_level, digest))
}

// HELPER FUNCTIONS
// ================================================================================================

fn verify_stark(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    pc_transcript_state: PrecompileTranscriptState,
    hash_fn: HashFunction,
    proof_bytes: Vec<u8>,
) -> Result<(), VerificationError> {
    let program_hash = *program_info.program_hash();

    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, pc_transcript_state);
    let (public_values, kernel_digests) = pub_inputs.to_air_inputs();
    let var_len_refs: Vec<&[_]> = kernel_digests.iter().map(|w| w.as_ref()).collect();
    let var_len_public_inputs: &[&[_]] = &var_len_refs;

    let air = ProcessorAir::new(kernel_digests.len());

    match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::create_blake3_256_config();
            verify_stark_proof(&config, &air, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Rpo256 => {
            let config = config::create_rpo_config();
            verify_stark_proof(&config, &air, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Rpx256 => {
            let config = config::create_rpx_config();
            verify_stark_proof(&config, &air, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Poseidon2 => {
            let config = config::create_poseidon2_config();
            verify_stark_proof(&config, &air, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Keccak => {
            let config = config::create_keccak_config();
            verify_stark_proof(&config, &air, &public_values, var_len_public_inputs, &proof_bytes)
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
    #[error("failed to verify precompile calls")]
    PrecompileVerificationError(#[source] PrecompileVerificationError),
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

/// Verifies a STARK proof for the given AIR and public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// verifier.
fn verify_stark_proof<A, SC>(
    config: &SC,
    air: &A,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    proof_bytes: &[u8],
) -> Result<(), StarkVerificationError>
where
    A: LiftedAir<Felt, QuadFelt>,
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: DeserializeOwned,
{
    // Proof deserialization via bincode; see https://github.com/0xMiden/miden-vm/issues/2550
    // The proof is serialized as a `(log_trace_height, stark_proof)` tuple; this is a temporary
    // approach until the lifted STARK integrates trace height on its side.
    let (log_trace_height, proof): (u8, StarkProof<Felt, QuadFelt, SC>) =
        bincode::deserialize(proof_bytes)?;

    if log_trace_height as usize > Felt::TWO_ADICITY {
        return Err(StarkVerificationError::InvalidTraceHeight(log_trace_height));
    }

    let mut challenger = config.challenger();
    challenger.observe_slice(public_values);
    // TODO: observe log_trace_height in the transcript for Fiat-Shamir binding.
    // TODO: observe var_len_public_inputs in the transcript for Fiat-Shamir binding.
    //   This also requires updating the recursive verifier to absorb both fixed and
    //   variable-length public inputs.
    // TODO: observe ACE commitment once ACE verification is integrated.
    // See https://github.com/0xMiden/miden-vm/issues/2822
    miden_crypto::stark::verifier::verify_single(
        config,
        air,
        log_trace_height as usize,
        public_values,
        var_len_public_inputs,
        &proof,
        challenger,
    )?;
    Ok(())
}
