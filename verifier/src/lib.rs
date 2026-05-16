#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, vec::Vec};

use miden_air::{ProcessorAir, PublicInputs, config};
use miden_core::{
    Felt, WORD_SIZE,
    deferred::{Digest, DeferredState, TRUE_DIGEST, TRUE_TAG},
    field::QuadFelt,
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
/// Returns a tuple `(security_level, deferred_root)` where:
/// - `security_level`: The security level (in bits) of the verified proof.
/// - `deferred_root`: A [`Word`] containing the rolling commitment to all precompile requests
///   (the final root of the deferred-DAG transcript chain, recovered from the proof and checked
///   against the AND-chain walk).
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

    let (hash_fn, proof_bytes, precompile_requests, deferred_state) = proof.into_parts();

    // Walk the deferred-DAG's AND-chain from `root` down to `TRUE_DIGEST`, collecting each
    // `log_precompile` statement (oldest first). Every AND-node is structurally re-validated:
    // its own digest must equal Poseidon2::merge(prev_root, stmnt), its tag must be TRUE_TAG,
    // and the chain must terminate at TRUE_DIGEST.
    let statements = walk_deferred_and_chain(&deferred_state)?;

    // Each statement must match the commitment of the corresponding PrecompileRequest. If no
    // verifiers were registered but the proof carries requests, the registry returns
    // `VerifierNotFound` at the first request.
    precompile_verifiers
        .verify_against_statements(&precompile_requests, &statements)
        .map_err(VerificationError::PrecompileVerificationError)?;

    let pc_transcript_state = deferred_state.root();

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

/// Walks the AND-chain rooted at `deferred_state.root()` down to [`TRUE_DIGEST`], returning the
/// per-step `log_precompile` statements in execution order (oldest first).
///
/// Each AND-node is structurally re-validated: its key in the map must equal its content-addressed
/// digest, its tag must be [`TRUE_TAG`], and its 8-felt payload decodes as `(prev_root || stmnt)`.
/// A broken chain (missing node, wrong tag, digest mismatch) surfaces as
/// [`VerificationError::DeferredChainCorrupt`].
fn walk_deferred_and_chain(
    deferred_state: &DeferredState,
) -> Result<Vec<Digest>, VerificationError> {
    let mut statements = Vec::new();
    let mut current = deferred_state.root();
    while current != TRUE_DIGEST {
        let node = deferred_state
            .get(&current)
            .map_err(|_| VerificationError::DeferredChainCorrupt {
                reason: DeferredChainErrorReason::MissingNode { digest: current },
            })?;
        if node.tag != TRUE_TAG {
            return Err(VerificationError::DeferredChainCorrupt {
                reason: DeferredChainErrorReason::NonAndNode { digest: current },
            });
        }
        if node.digest() != current {
            return Err(VerificationError::DeferredChainCorrupt {
                reason: DeferredChainErrorReason::DigestMismatch { expected: current },
            });
        }
        let payload = node.expression_payload().ok_or(
            VerificationError::DeferredChainCorrupt {
                reason: DeferredChainErrorReason::NonExpressionPayload { digest: current },
            },
        )?;
        let (prev_root, stmnt) = payload.binary_op_children();
        statements.push(stmnt);
        current = prev_root;
    }
    statements.reverse();
    Ok(statements)
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
    let (public_values, kernel_felts) = pub_inputs.to_air_inputs();
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];

    let params = config::pcs_params();
    match hash_fn {
        HashFunction::Blake3_256 => {
            let config = config::blake3_256_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Rpo256 => {
            let config = config::rpo_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Rpx256 => {
            let config = config::rpx_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Poseidon2 => {
            let config = config::poseidon2_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
        },
        HashFunction::Keccak => {
            let config = config::keccak_config(params);
            verify_stark_proof(&config, &public_values, var_len_public_inputs, &proof_bytes)
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
    #[error("deferred-DAG transcript chain is corrupt: {reason}")]
    DeferredChainCorrupt { reason: DeferredChainErrorReason },
}

/// Specific failure mode encountered while walking the deferred-DAG AND-chain.
#[derive(Debug, thiserror::Error)]
pub enum DeferredChainErrorReason {
    #[error("expected AND-node {digest} is not present in the deferred state")]
    MissingNode { digest: Digest },
    #[error("node {digest} is reachable from the transcript root but is not an AND-node")]
    NonAndNode { digest: Digest },
    #[error("node keyed by {expected} does not hash to its key")]
    DigestMismatch { expected: Digest },
    #[error("AND-node {digest} has a chunk-bodied payload (expected expression body)")]
    NonExpressionPayload { digest: Digest },
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

/// Verifies a STARK proof for the given public values.
///
/// Pre-seeds the challenger with `public_values`, then delegates to the lifted
/// verifier.
fn verify_stark_proof<SC>(
    config: &SC,
    public_values: &[Felt],
    var_len_public_inputs: VarLenPublicInputs<'_, Felt>,
    proof_bytes: &[u8],
) -> Result<(), StarkVerificationError>
where
    SC: StarkConfig<Felt, QuadFelt>,
    <SC::Lmcs as Lmcs>::Commitment: DeserializeOwned,
{
    // Proof deserialization via bincode; see https://github.com/0xMiden/miden-vm/issues/2550.
    let proof: StarkProof<Felt, QuadFelt, SC> = bincode::deserialize(proof_bytes)?;

    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);
    challenger.observe_slice(public_values);
    config::observe_var_len_public_inputs(&mut challenger, var_len_public_inputs, &[WORD_SIZE]);
    miden_crypto::stark::verifier::verify_single(
        config,
        &ProcessorAir,
        public_values,
        var_len_public_inputs,
        &proof,
        challenger,
    )?;
    Ok(())
}
