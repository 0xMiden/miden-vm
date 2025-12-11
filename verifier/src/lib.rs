#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::vec;
use std::println;

// use air::{Felt, HashFunction, ProcessorAir, Proof, PublicInputs};
use miden_air::{ExecutionProof, Felt, HashFunction, ProcessorAir, Proof, PublicInputs};
use miden_core::precompile::{
    PrecompileTranscriptDigest, PrecompileVerificationError, PrecompileVerifierRegistry,
};
use p3_blake3::Blake3;
use p3_challenger::{HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use p3_uni_stark::StarkConfig;

mod verify;
// EXPORTS
// ================================================================================================
pub use miden_core::{Kernel, ProgramInfo, StackInputs, StackOutputs, Word};
use verify::verify as verify_proof;
pub use winter_verifier::{AcceptableOptions, VerifierError};
pub mod math {
    pub use miden_core::Felt;
}

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
    let _pub_inputs =
        PublicInputs::new(program_info, stack_inputs, stack_outputs, recomputed_transcript.state());

    match hash_fn {
        HashFunction::Blake3_192 | HashFunction::Blake3_256 => {
            println!("blake verifying");
            type Val = Felt;
            type Challenge = BinomialExtensionField<Felt, 2>;
            type H = Blake3;
            type FieldHash = SerializingHasher<H>;
            type Compress<H> = CompressionFunctionFromHasher<H, 2, 32>;
            type ValMmcs<H> = MerkleTreeMmcs<Val, u8, FieldHash, Compress<H>, 32>;
            type ChallengeMmcs<H> = ExtensionMmcs<Val, Challenge, ValMmcs<H>>;
            type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs<H>, ChallengeMmcs<H>>;
            type Dft = Radix2DitParallel<Val>;

            type Challenger<H> = SerializingChallenger64<Val, HashChallenger<u8, H, 32>>;
            type Config = StarkConfig<Pcs, Challenge, Challenger<H>>;

            let field_hash = FieldHash::new(H {});
            let compress = Compress::new(H {});

            let val_mmcs = ValMmcs::new(field_hash, compress);
            let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

            let dft = Dft::default();

            let fri_config = FriParameters {
                log_blowup: 3,
                log_final_poly_len: 7,
                num_queries: 27,
                proof_of_work_bits: 16,
                log_folding_factor: 1,
                mmcs: challenge_mmcs,
            };

            let pcs = Pcs::new(dft, val_mmcs, fri_config);

            let challenger = Challenger::from_hasher(vec![], H {});

            let config = Config::new(pcs, challenger);

            let air = ProcessorAir {};
            let proof: Proof<Config> = bincode::deserialize(&proof).unwrap();
            verify_proof(&config, &air, &proof, &vec![])
        },
        HashFunction::Rpo256 => {
            todo!()
        },
        HashFunction::Rpx256 => {
            todo!()
        },
        HashFunction::Poseidon2 => {
            todo!()
        },
        HashFunction::Keccak => {
            todo!()
        },
    }
    .map_err(|_source| VerificationError::ProgramVerificationError(program_hash))?;

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
    ProgramVerificationError(Word),
    #[error("the input {0} is not a valid field element")]
    InputNotFieldElement(u64),
    #[error("the output {0} is not a valid field element")]
    OutputNotFieldElement(u64),
    #[error("failed to verify precompile calls")]
    PrecompileVerificationError(#[source] PrecompileVerificationError),
}

/*
pub enum VerificationError {
    FailedVerification,
} */
