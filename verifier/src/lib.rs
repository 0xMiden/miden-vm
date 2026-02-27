#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{string::String, vec::Vec};

use miden_air::{Felt, ProcessorAir, PublicInputs, config};

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

    let (hash_fn, proof_bytes, log_trace_height, precompile_requests) = proof.into_parts();

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
        log_trace_height,
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
    log_trace_height: u32,
    proof_bytes: Vec<u8>,
) -> Result<(), VerificationError> {
    let program_hash = *program_info.program_hash();

    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, pc_transcript_state);
    let (public_values, kernel_digests) = pub_inputs.to_air_inputs();

    // Build var-len public inputs from kernel digests.
    let kernel_group_refs: Vec<&[Felt]> = kernel_digests.iter().map(|d| d.as_slice()).collect();
    let var_len_public_inputs: [&[&[Felt]]; 1] = [&kernel_group_refs];

    let air = ProcessorAir;
    let log_height = log_trace_height as usize;
    let err = |reason| VerificationError::ProgramVerificationError { program_hash, reason };

    match hash_fn {
        HashFunction::Blake3_256 => config::verify(
            &config::create_blake3_256_config(),
            &air,
            log_height,
            &public_values,
            &var_len_public_inputs,
            &proof_bytes,
        )
        .map_err(err),
        HashFunction::Rpo256 => config::verify(
            &config::create_rpo_config(),
            &air,
            log_height,
            &public_values,
            &var_len_public_inputs,
            &proof_bytes,
        )
        .map_err(err),
        HashFunction::Rpx256 => config::verify(
            &config::create_rpx_config(),
            &air,
            log_height,
            &public_values,
            &var_len_public_inputs,
            &proof_bytes,
        )
        .map_err(err),
        HashFunction::Poseidon2 => config::verify(
            &config::create_poseidon2_config(),
            &air,
            log_height,
            &public_values,
            &var_len_public_inputs,
            &proof_bytes,
        )
        .map_err(err),
        HashFunction::Keccak => config::verify(
            &config::create_keccak_config(),
            &air,
            log_height,
            &public_values,
            &var_len_public_inputs,
            &proof_bytes,
        )
        .map_err(err),
    }
}

// ERRORS
// ================================================================================================

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify proof for program with hash {program_hash}: {reason}")]
    ProgramVerificationError { program_hash: Word, reason: String },
    #[error("failed to verify precompile calls")]
    PrecompileVerificationError(#[source] PrecompileVerificationError),
}
