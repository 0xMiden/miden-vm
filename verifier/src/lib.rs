#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use std::println;

use alloc::vec;

use air::{Felt, HashFunction, ProcessorAir, Proof, PublicInputs};
use p3_blake3::Blake3;
use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger64};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::{Field, extension::BinomialExtensionField};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation
};
use p3_uni_stark::{StarkConfig};
use vm_core::RpoPermutation256;

mod verify;
use verify::verify as verify_proof;

// EXPORTS
// ================================================================================================
pub use vm_core::{Kernel, ProgramInfo, StackInputs, StackOutputs, Word, chiplets::hasher::Digest};
pub use winter_verifier::{AcceptableOptions, VerifierError};
pub mod math {
    pub use vm_core::Felt;
}
pub use air::ExecutionProof;

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

    // build public inputs and try to verify the proof
    let pub_inputs = PublicInputs::new(program_info, stack_inputs, stack_outputs);
    let (hash_fn, proof) = proof.into_parts();
    let processor_air = ProcessorAir {};

    type Val = Felt;
    type Challenge = BinomialExtensionField<Val, 2>;

    match hash_fn {
        HashFunction::Blake3_192 | HashFunction::Blake3_256 => {
                        println!("blake verifying");
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
                            mmcs: challenge_mmcs,
                        };
        
                        let pcs = Pcs::new(dft, val_mmcs, fri_config);
        
                        let challenger = Challenger::from_hasher(vec![], H {});
        
                        let config = Config::new(pcs, challenger);
        
                        let proof: Proof<Config> = bincode::deserialize(&proof).unwrap();
                        verify_proof(&config, &processor_air, &proof, &vec![])
            },
        HashFunction::Rpo256 => {
                type Perm = RpoPermutation256;

                type MyHash = PaddingFreeSponge<Perm, 12, 8, 4>;
                let hash = MyHash::new(Perm {});

                type MyCompress = TruncatedPermutation<Perm, 2, 4, 12>;
                let compress = MyCompress::new(Perm {});

                type Challenger = DuplexChallenger<Val, Perm, 12, 8>;
                let challenger = Challenger::new(Perm {});

                type ValMmcs = MerkleTreeMmcs<
                    <Val as Field>::Packing,
                    <Val as Field>::Packing,
                    MyHash,
                    MyCompress,
                    4,
                >;
                let val_mmcs = ValMmcs::new(hash, compress);

                type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

                type Dft = Radix2DitParallel<Val>;
                let dft = Dft::default();

                let fri_config = FriParameters {
                    log_blowup: 3,
                    log_final_poly_len: 7,
                    num_queries: 27,
                    proof_of_work_bits: 16,
                    mmcs: challenge_mmcs,
                };
            
                type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
                let pcs = Pcs::new(dft, val_mmcs, fri_config);
                type Config = StarkConfig<Pcs, Challenge, Challenger>;
                let config = Config::new(pcs, challenger);

                let proof: Proof<Config> = bincode::deserialize(&proof).unwrap();
                verify_proof(&config, &processor_air, &proof, &pub_inputs.to_elements())
            },
        HashFunction::Rpx256 => {
                todo!()
            },
HashFunction::Keccak => todo!(),
    }
    .map_err(|_source| VerificationError::ProgramVerificationError(program_hash))?;

    Ok(security_level)
}

// ERRORS
// ================================================================================================

/// TODO: add docs
#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("failed to verify proof for program with hash {0}")]
    //ProgramVerificationError(Digest, #[source] VerificationError),
    ProgramVerificationError(Digest),

    #[error("the input {0} is not a valid field element")]
    InputNotFieldElement(u64),
    #[error("the output {0} is not a valid field element")]
    OutputNotFieldElement(u64),
}

/*
pub enum VerificationError {
    FailedVerification,
} */
