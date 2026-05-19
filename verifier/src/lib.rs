#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, vec, vec::Vec};

use miden_air::{AirInstance, InstanceShapes, MidenAir, PublicInputs, config};
use miden_core::{
    Felt, WORD_SIZE,
    deferred::{DeferredState, IntegrityError, PrecompileRegistry},
    field::QuadFelt,
};
use miden_crypto::stark::{StarkConfig, challenger::CanObserve, lmcs::Lmcs, proof::StarkProof};
use serde::de::DeserializeOwned;
use serde_wincode::SerdeCompat;

const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

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
    schema: &PrecompileRegistry,
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
    #[error("deferred-DAG integrity check failed: {0}")]
    DeferredIntegrity(#[from] IntegrityError),
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
    #[error("log_trace_height {0} exceeds the two-adic order of the field")]
    InvalidTraceHeight(u8),
    #[error(
        "non-canonical multi-AIR instance shape: expected air_order {expected:?}, got {actual:?}"
    )]
    NonCanonicalAirOrder { expected: Vec<u32>, actual: Vec<u32> },
    #[error(transparent)]
    Verifier(#[from] miden_crypto::stark::verifier::VerifierError),
}

/// Verifies a multi-AIR STARK proof for the given (Core, Chiplets) split.
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
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: DeserializeOwned,
{
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(StarkVerificationError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof: StarkProof<Felt, QuadFelt, SC> =
        <SerdeCompat<StarkProof<Felt, QuadFelt, SC>> as wincode::config::Deserialize<_>>::deserialize(
            proof_bytes,
            proof_encoding_config,
        )?;
    validate_canonical_air_order(proof_bytes)?;

    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);
    challenger.observe_slice(public_values);
    let chiplets_var_len: &[&[Felt]] = &[kernel_felts];
    config::observe_var_len_public_inputs(&mut challenger, chiplets_var_len, &[WORD_SIZE]);

    config::observe_air_order(&mut challenger, proof.air_order());

    let core_air = MidenAir::CORE;
    let chiplets_air = MidenAir::CHIPLETS;
    let core_instance = AirInstance {
        public_values,
        var_len_public_inputs: &[],
    };
    let chiplets_instance = AirInstance {
        public_values,
        var_len_public_inputs: chiplets_var_len,
    };
    let instances = [(&core_air, core_instance), (&chiplets_air, chiplets_instance)];

    miden_crypto::stark::verifier::verify_multi(config, &instances, &proof, challenger)?;
    Ok(())
}

fn validate_canonical_air_order(proof_bytes: &[u8]) -> Result<(), StarkVerificationError> {
    // `StarkProof` serializes `instance_shapes` first, so decoding `InstanceShapes` from
    // the proof-byte prefix yields the shape metadata; wincode reads exactly what the type
    // needs and ignores the trailing transcript bytes.
    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof_shapes: InstanceShapes =
        <SerdeCompat<InstanceShapes> as wincode::config::Deserialize<_>>::deserialize(
            proof_bytes,
            proof_encoding_config,
        )?;

    let proof_air_order = proof_shapes.air_order();
    let log_trace_heights = proof_shapes.log_trace_heights();
    let non_canonical = || StarkVerificationError::NonCanonicalAirOrder {
        expected: vec![0, 1],
        actual: proof_air_order.to_vec(),
    };

    if proof_air_order.len() != 2 || log_trace_heights.len() != 2 {
        return Err(non_canonical());
    }

    let mut caller_heights = [0usize; 2];
    let mut seen = [false; 2];
    for (&caller_idx, &log_h) in proof_air_order.iter().zip(log_trace_heights) {
        let seen_slot = seen.get_mut(caller_idx as usize).ok_or_else(non_canonical)?;
        if *seen_slot {
            return Err(non_canonical());
        }
        *seen_slot = true;
        caller_heights[caller_idx as usize] = 1usize
            .checked_shl(log_h as u32)
            .ok_or(StarkVerificationError::InvalidTraceHeight(log_h))?;
    }

    let expected_shapes =
        InstanceShapes::from_trace_heights(caller_heights.to_vec()).map_err(|_| non_canonical())?;
    if expected_shapes.air_order() != proof_air_order
        || expected_shapes.log_trace_heights() != log_trace_heights
    {
        return Err(StarkVerificationError::NonCanonicalAirOrder {
            expected: expected_shapes.air_order().to_vec(),
            actual: proof_air_order.to_vec(),
        });
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

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
}
