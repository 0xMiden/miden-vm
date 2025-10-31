#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec;

use miden_air::{HashFunction, ProcessorAir, ProvingOptions, PublicInputs};
use miden_core::crypto::{
    hash::{Blake3_192, Blake3_256, Poseidon2, Rpo256, Rpx256},
    random::{RpoRandomCoin, RpxRandomCoin, WinterRandomCoin},
};
use winter_verifier::{crypto::MerkleTree, verify as verify_proof};

// EXPORTS
// ================================================================================================
mod exports {
    pub use miden_core::{
        Kernel, ProgramInfo, StackInputs, StackOutputs, Word,
        precompile::{
            PrecompileError, PrecompileTranscriptDigest, PrecompileVerificationError,
            PrecompileVerifierRegistry,
        },
    };
    pub use winter_verifier::{AcceptableOptions, VerifierError};
    pub mod math {
        pub use miden_core::{Felt, FieldElement, StarkField};
    }
    pub use miden_air::ExecutionProof;
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
/// The verifier accepts proofs generated using a parameter set defined in [ProvingOptions].
/// Specifically, parameter sets targeting the following are accepted:
/// - 96-bit security level, non-recursive context (BLAKE3 hash function).
/// - 96-bit security level, recursive context (BLAKE3 hash function).
/// - 128-bit security level, non-recursive context (RPO hash function).
/// - 128-bit security level, recursive context (RPO hash function).
///
/// # Errors
/// Returns an error if:
/// - The provided proof does not prove a correct execution of the program.
/// - The protocol parameters used to generate the proof are not in the set of acceptable
///   parameters.
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
    // get security level of the proof
    let security_level = proof.security_level();
    let program_hash = *program_info.program_hash();

    let (hash_fn, proof, precompile_requests) = proof.into_parts();

    // recompute the precompile transcript by verifying all precompile requests and recording the
    // commitments.
    // if no verifiers were provided (e.g. when this function was called from `verify()`),
    // but the proof contained requests anyway, returns a `NoVerifierFound` error.
    let recomputed_transcript = precompile_verifiers
        .requests_transcript(&precompile_requests)
        .map_err(VerificationError::PrecompileVerificationError)?;

    // build public inputs, explicitly passing the recomputed precompile transcript state
    let pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, recomputed_transcript.state());

    match hash_fn {
        HashFunction::Blake3_192 => {
            let opts = AcceptableOptions::OptionSet(vec![ProvingOptions::REGULAR_96_BITS]);
            verify_proof::<ProcessorAir, Blake3_192, WinterRandomCoin<_>, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
        HashFunction::Blake3_256 => {
            let opts = AcceptableOptions::OptionSet(vec![ProvingOptions::REGULAR_128_BITS]);
            verify_proof::<ProcessorAir, Blake3_256, WinterRandomCoin<_>, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
        HashFunction::Rpo256 => {
            let opts = AcceptableOptions::OptionSet(vec![
                ProvingOptions::RECURSIVE_96_BITS,
                ProvingOptions::RECURSIVE_128_BITS,
            ]);
            verify_proof::<ProcessorAir, Rpo256, RpoRandomCoin, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
        HashFunction::Rpx256 => {
            let opts = AcceptableOptions::OptionSet(vec![
                ProvingOptions::RECURSIVE_96_BITS,
                ProvingOptions::RECURSIVE_128_BITS,
            ]);
            verify_proof::<ProcessorAir, Rpx256, RpxRandomCoin, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
        HashFunction::Poseidon2 => {
            let opts = AcceptableOptions::OptionSet(vec![
                ProvingOptions::RECURSIVE_96_BITS,
                ProvingOptions::REGULAR_128_BITS,
            ]);
            verify_proof::<ProcessorAir, Poseidon2, WinterRandomCoin<_>, MerkleTree<_>>(
                proof, pub_inputs, &opts,
            )
        },
    }
    .map_err(|source| VerificationError::ProgramVerificationError(program_hash, source))?;

    // finalize transcript to return the digest
    let digest = recomputed_transcript.finalize();
    Ok((security_level, digest))
}

// ERRORS
// ================================================================================================

/// Errors that can occur during proof verification.
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify proof for program with hash {0}")]
    ProgramVerificationError(Word, #[source] VerifierError),
    #[error("the input {0} is not a valid field element")]
    InputNotFieldElement(u64),
    #[error("the output {0} is not a valid field element")]
    OutputNotFieldElement(u64),
    #[error("failed to verify precompile calls")]
    PrecompileVerificationError(#[source] PrecompileVerificationError),
}
