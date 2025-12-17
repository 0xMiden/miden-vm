#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec::Vec;

use miden_air::{HashFunction, ProcessorAir, PublicInputs, config};
// EXPORTS
// ================================================================================================
pub use miden_core::{
    Kernel, ProgramInfo, StackInputs, StackOutputs, Word,
    precompile::{
        PrecompileTranscriptDigest, PrecompileTranscriptState, PrecompileVerificationError,
        PrecompileVerifierRegistry,
    },
};
pub mod math {
    pub use miden_core::Felt;
}
pub use miden_air::ExecutionProof;

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
/// - The proof contains precompile requests. When precompile requests are present, use
///   [`verify_with_precompiles`] instead with an appropriate [`PrecompileVerifierRegistry`].
#[tracing::instrument("verify_program", skip_all)]
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    let (security_level, _) = verify_with_precompiles(
        program_info,
        stack_inputs,
        stack_outputs,
        proof,
        &PrecompileVerifierRegistry::new(),
    )?;
    Ok(security_level)
}

/// Verifies the proof together with all deferred precompile requests.
///
/// This helper recomputes the precompile commitments using the supplied
/// [`PrecompileVerifierRegistry`], rebuilds the transcript, and verifies the STARK proof
/// with the recomputed transcript state as part of the public inputs.
pub fn verify_with_precompiles(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
    registry: &PrecompileVerifierRegistry,
) -> Result<(u32, PrecompileTranscriptDigest), VerificationError> {
    let security_level = proof.security_level();
    let (hash_fn, proof_bytes, precompile_requests) = proof.into_parts();

    // Recompute the precompile transcript by verifying all precompile requests
    let transcript = registry.requests_transcript(&precompile_requests)?;
    let pc_transcript_state = transcript.state();
    let recomputed_digest = transcript.finalize();

    // Verify the STARK proof with the recomputed transcript state in public inputs
    verify_stark(
        program_info,
        stack_inputs,
        stack_outputs,
        pc_transcript_state,
        hash_fn,
        proof_bytes,
    )?;
    Ok((security_level, recomputed_digest))
}

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
    let public_values = pub_inputs.to_elements();
    let air = ProcessorAir::new();

    match hash_fn {
        HashFunction::Blake3_192 => {
            let config = config::create_blake3_256_config();
            let proof = bincode::deserialize(&proof_bytes)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))?;
            miden_prover_p3::verify(&config, &air, &proof, &public_values)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))
        },
        HashFunction::Blake3_256 => {
            let config = config::create_blake3_256_config();
            let proof = bincode::deserialize(&proof_bytes)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))?;
            miden_prover_p3::verify(&config, &air, &proof, &public_values)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))
        },
        HashFunction::Keccak => {
            let config = config::create_keccak_config();
            let proof = bincode::deserialize(&proof_bytes)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))?;
            miden_prover_p3::verify(&config, &air, &proof, &public_values)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))
        },
        HashFunction::Rpo256 => {
            let config = config::create_rpo_config();
            let proof = bincode::deserialize(&proof_bytes)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))?;
            miden_prover_p3::verify(&config, &air, &proof, &public_values)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))
        },
        HashFunction::Poseidon2 => {
            let config = config::create_poseidon2_config();
            let proof = bincode::deserialize(&proof_bytes)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))?;
            miden_prover_p3::verify(&config, &air, &proof, &public_values)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))
        },
        HashFunction::Rpx256 => {
            let config = config::create_rpx_config();
            let proof = bincode::deserialize(&proof_bytes)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))?;
            miden_prover_p3::verify(&config, &air, &proof, &public_values)
                .map_err(|_| VerificationError::ProgramVerificationError(program_hash))
        },
    }?;

    Ok(())
}

// ERRORS
// ================================================================================================

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    /// The STARK proof failed to verify for the given program.
    #[error("failed to verify proof for program with hash {0}")]
    ProgramVerificationError(Word),
    /// A precompile verification check failed.
    #[error("precompile verification failed: {0}")]
    PrecompileVerification(#[from] PrecompileVerificationError),
    /// A public input value is not a valid field element.
    #[error("the input {0} is not a valid field element")]
    InputNot(u64),
    /// A public output value is not a valid field element.
    #[error("the output {0} is not a valid field element")]
    OutputNot(u64),
    /// A detailed verification error with additional context.
    #[error("verification error: {0}")]
    DetailedError(alloc::string::String),
}
