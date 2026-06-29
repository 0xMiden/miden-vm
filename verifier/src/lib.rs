#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "std")]
use core::any::{Any, TypeId};

use alloc::{boxed::Box, vec::Vec};

use miden_air::{MidenMultiAir, PublicInputs, Statement, config};
use miden_core::{Felt, field::QuadFelt};
use miden_crypto::stark::{
    Preprocessed, PreprocessedValidationError, StarkConfig, VerifierInstance, lmcs::Lmcs,
    proof::StarkProofData, verifier::VerifierError,
};
use serde::de::DeserializeOwned;
use serde_wincode::SerdeCompat;

const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

type PreprocessedCommitment<SC> = <<SC as StarkConfig<Felt, QuadFelt>>::Lmcs as Lmcs>::Commitment;

#[cfg(feature = "std")]
type PreprocessedCache = std::collections::HashMap<(TypeId, u8), Box<dyn Any + Send + Sync>>;

#[cfg(feature = "std")]
static PREPROCESSED_COMMITMENTS: std::sync::OnceLock<std::sync::Mutex<PreprocessedCache>> =
    std::sync::OnceLock::new();

// RE-EXPORTS
// ================================================================================================
mod exports {
    pub use miden_core::{
        Word,
        precompile::{
            PrecompileTranscriptState, PrecompileVerificationError, PrecompileVerifierRegistry,
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
/// Returns a tuple `(security_level, transcript_state)` where:
/// - `security_level`: The security level (in bits) of the verified proof.
/// - `transcript_state`: A [`Word`] containing the rolling commitment to all precompile requests,
///   computed by recomputing and recording each precompile commitment in a transcript. The state is
///   itself a complete digest; no separate finalization step is needed.
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
) -> Result<(u32, PrecompileTranscriptState), VerificationError> {
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

    verify_stark(
        program_info,
        stack_inputs,
        stack_outputs,
        pc_transcript_state,
        hash_fn,
        proof_bytes,
    )?;

    Ok((security_level, pc_transcript_state))
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
    let (public_values, kernel_felts) = pub_inputs.to_air_inputs();

    let params = config::pcs_params();
    match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Eidos => {
            let config = config::eidos_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            verify_stark_proof(&config, &public_values, &kernel_felts, &proof_bytes)
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
    Deserialization(#[from] wincode::error::ReadError),
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    #[error(transparent)]
    Verifier(#[from] VerifierError),
    #[error(transparent)]
    Preprocessed(#[from] PreprocessedValidationError),
}

/// Verifies a multi-AIR STARK proof for the Miden VM relation.
///
/// Pre-seeds the challenger with the protocol parameters, public values, and the
/// concatenated kernel-procedure digests (the only variable-length public input today,
/// owned by the Chiplets AIR). Then delegates to the lifted multi-AIR verifier.
fn verify_stark_proof<SC>(
    config: &SC,
    public_values: &[Felt],
    kernel_felts: &[Felt],
    proof_bytes: &[u8],
) -> Result<(), StarkVerificationError>
where
    SC: StarkConfig<Felt, QuadFelt> + 'static,
    PreprocessedCommitment<SC>: Clone + Send + Sync + DeserializeOwned + 'static,
{
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(StarkVerificationError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof: StarkProofData<Felt, QuadFelt, SC> = <SerdeCompat<
        StarkProofData<Felt, QuadFelt, SC>,
    > as wincode::config::Deserialize<_>>::deserialize(
        proof_bytes, proof_encoding_config
    )?;

    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);

    // `air_inputs` are the fixed public values; `aux_inputs` are the kernel-procedure
    // digests. The lifted verifier absorbs both into Fiat-Shamir internally, and derives
    // the multi-AIR ordering deterministically from the proof's per-AIR trace heights.
    let statement = Statement::<Felt, QuadFelt, _>::new(
        MidenMultiAir::new(),
        public_values.to_vec(),
        kernel_felts.to_vec(),
    )
    .map_err(|e| StarkVerificationError::Verifier(VerifierError::from(e)))?;

    let preprocessed_commitment = cached_preprocessed_commitment(&statement, config);
    VerifierInstance::new(config, &statement, preprocessed_commitment)?
        .verify(&proof, challenger)?;
    Ok(())
}

#[cfg(feature = "std")]
fn cached_preprocessed_commitment<SC>(
    statement: &Statement<Felt, QuadFelt, MidenMultiAir>,
    config: &SC,
) -> Option<PreprocessedCommitment<SC>>
where
    SC: StarkConfig<Felt, QuadFelt> + 'static,
    PreprocessedCommitment<SC>: Clone + Send + Sync + 'static,
{
    const EIDOS_PREPROCESSED_LOG_BLOWUP: u8 = 3;

    // MidenMultiAir preprocessed traces are fixed circuit data; their commitment changes only
    // with the concrete commitment scheme and LDE blowup used by the verifier config.
    let key = (TypeId::of::<SC>(), config.pcs().log_blowup());
    let mut cache = PREPROCESSED_COMMITMENTS
        .get_or_init(Default::default)
        .lock()
        .expect("preprocessed commitment cache poisoned");

    if let Some(value) = cache.get(&key) {
        return value
            .downcast_ref::<Option<PreprocessedCommitment<SC>>>()
            .expect("preprocessed commitment cache type mismatch")
            .clone();
    }

    if TypeId::of::<SC>() == TypeId::of::<config::EidosConfig>()
        && config.pcs().log_blowup() == EIDOS_PREPROCESSED_LOG_BLOWUP
    {
        let value = Some(eidos_preprocessed_commitment());
        let generic = (&value as &dyn Any)
            .downcast_ref::<Option<PreprocessedCommitment<SC>>>()
            .expect("Eidos preprocessed commitment type mismatch")
            .clone();
        cache.insert(key, Box::new(value));
        return generic;
    }

    let value =
        Preprocessed::build(statement, config).map(|preprocessed| preprocessed.commitment());
    cache.insert(key, Box::new(value.clone()));
    value
}

#[cfg(feature = "std")]
fn eidos_preprocessed_commitment() -> PreprocessedCommitment<config::EidosConfig> {
    // Commitment to the fixed preprocessed table for the standard Eidos verifier config.
    // `eidos_preprocessed_commitment_matches_fixed_table` recomputes it from the AIR.
    [
        8101824786889297799,
        5557459202643843712,
        8609469204800341145,
        5780773595731865481,
    ]
    .into()
}

#[cfg(not(feature = "std"))]
fn cached_preprocessed_commitment<SC>(
    statement: &Statement<Felt, QuadFelt, MidenMultiAir>,
    config: &SC,
) -> Option<PreprocessedCommitment<SC>>
where
    SC: StarkConfig<Felt, QuadFelt>,
{
    Preprocessed::build(statement, config).map(|preprocessed| preprocessed.commitment())
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use super::*;

    #[test]
    fn proof_encoding_config_rejects_oversized_native_vec_preallocation() {
        let proof_encoding_config = wincode::config::Configuration::default()
            .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
        let element_count = MAX_STARK_PROOF_BYTES + 1;
        let mut length_prefix = Vec::new();

        <usize as wincode::config::Serialize<_>>::serialize_into(
            &mut length_prefix,
            &element_count,
            proof_encoding_config,
        )
        .unwrap();
        let err = <Vec<u8> as wincode::config::Deserialize<_>>::deserialize(
            &length_prefix,
            proof_encoding_config,
        )
        .unwrap_err();

        assert!(
            matches!(
                err,
                wincode::error::ReadError::PreallocationSizeLimit { needed, limit }
                    if needed == element_count && limit == MAX_STARK_PROOF_BYTES
            ),
            "expected proof encoding config to reject oversized allocation, got {err:?}"
        );
    }

    #[test]
    fn verify_stark_proof_rejects_oversized_proof_bytes() {
        let params = config::pcs_params();
        let config = config::poseidon2_config(params);
        let proof_bytes = Vec::from_iter(core::iter::repeat_n(0, MAX_STARK_PROOF_BYTES + 1));

        let err = verify_stark_proof(&config, &[], &[], &proof_bytes).unwrap_err();

        assert!(
            matches!(
                err,
                StarkVerificationError::ProofTooLarge {
                    size,
                    max: MAX_STARK_PROOF_BYTES,
                } if size == proof_bytes.len()
            ),
            "expected explicit proof byte limit to reject oversized proof, got {err:?}"
        );
    }

    #[cfg(feature = "std")]
    #[test]
    fn eidos_preprocessed_commitment_matches_fixed_table() {
        let config = config::eidos_config(config::pcs_params());
        let statement = Statement::<Felt, QuadFelt, MidenMultiAir>::new(
            MidenMultiAir::new(),
            vec![Felt::ZERO; miden_air::NUM_PUBLIC_VALUES],
            Vec::new(),
        )
        .unwrap();

        let commitment =
            Preprocessed::build(&statement, &config).map(|preprocessed| preprocessed.commitment());

        assert_eq!(commitment, Some(eidos_preprocessed_commitment()));
    }
}
