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
// EXPORTS
// ================================================================================================
pub use miden_core::{Kernel, ProgramInfo, StackInputs, StackOutputs, Word};
pub use winter_verifier::{AcceptableOptions, VerifierError};
use winter_verifier::{crypto::MerkleTree, verify as verify_proof};
pub mod math {
    pub use miden_core::{Felt, FieldElement, StarkField};
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
#[tracing::instrument("verify_program", skip_all)]
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> {
    // get security level of the proof
    let security_level = proof.security_level();
    let program_hash = *program_info.program_hash();

    // build public inputs and try to verify the proof
    let pub_inputs = PublicInputs::new(program_info, stack_inputs, stack_outputs);
    let (hash_fn, proof) = proof.into_parts();
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

    Ok(security_level)
}

// ERRORS
// ================================================================================================

/// TODO: add docs
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify proof for program with hash {0}")]
    ProgramVerificationError(Word, #[source] VerifierError),
    #[error("the input {0} is not a valid field element")]
    InputNotFieldElement(u64),
    #[error("the output {0} is not a valid field element")]
    OutputNotFieldElement(u64),
}
