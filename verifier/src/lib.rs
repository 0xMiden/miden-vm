#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use miden_air::{HashFunction, ProcessorAir, PublicInputs};
// EXPORTS
// ================================================================================================
pub use miden_core::{Kernel, ProgramInfo, StackInputs, StackOutputs, Word};
pub mod math {
    pub use miden_core::Felt;
}
pub use miden_air::ExecutionProof;
// Re-export config factories from prover
// (The verifier uses the same STARK configs as the prover)
use miden_prover::config;

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
//#[tracing::instrument("verify_program", skip_all)]
pub fn verify(
    program_info: ProgramInfo,
    stack_inputs: StackInputs,
    stack_outputs: StackOutputs,
    proof: ExecutionProof,
) -> Result<u32, VerificationError> where
{
    // get security level of the proof
    let security_level = proof.security_level();
    let program_hash = *program_info.program_hash();

    // Build public inputs
    let pub_inputs = PublicInputs::new(program_info, stack_inputs, stack_outputs);
    let public_values = pub_inputs.to_elements();

    // Deserialize proof and verify using unified miden-prover
    let (hash_fn, proof_bytes) = proof.into_parts();
    let air = ProcessorAir::new();

    match hash_fn {
        HashFunction::Blake3_192 => {
            // TODO: Blake3_192 currently uses Blake3_256 config (32-byte output instead of
            // 24-byte). Proper 192-bit support requires Plonky3 to implement
            // CryptographicHasher<u8, [u8; 24]> for Blake3. Create an issue in
            // 0xMiden/Plonky3 to add this support.
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

    Ok(security_level)
}

// ERRORS
// ================================================================================================

/// TODO: add docs
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify proof for program with hash {0}")]
    ProgramVerificationError(Word),
    #[error("the input {0} is not a valid field element")]
    InputNot(u64),
    #[error("the output {0} is not a valid field element")]
    OutputNot(u64),
    #[error("verification error: {0}")]
    DetailedError(alloc::string::String),
}
