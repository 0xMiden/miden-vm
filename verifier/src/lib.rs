#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use miden_air::{ProcessorAir, PublicInputs, config};
use miden_core::{
    Felt, WORD_SIZE,
    deferred::{
        DeferredStateWire, Digest, Node, Payload, TRUE_DIGEST, TRUE_INDEX, TRUE_TAG, WireBody,
    },
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

    let (hash_fn, proof_bytes, precompile_requests, deferred_wire) = proof.into_parts();

    // Walk the deferred-DAG's AND-chain on the wire from `root` down to `TRUE_DIGEST`, collecting
    // each `log_precompile` statement (oldest first). Every AND-node is structurally
    // re-validated: its own digest must equal Poseidon2::merge(prev_root, stmnt), its tag must
    // be TRUE_TAG, and the chain must terminate at TRUE_DIGEST.
    let statements = walk_deferred_and_chain(&deferred_wire)?;

    // Each statement must match the commitment of the corresponding PrecompileRequest. If no
    // verifiers were registered but the proof carries requests, the registry returns
    // `VerifierNotFound` at the first request.
    precompile_verifiers
        .verify_against_statements(&precompile_requests, &statements)
        .map_err(VerificationError::PrecompileVerificationError)?;

    let pc_transcript_state = deferred_wire.root;

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

/// Walks the AND-chain rooted at `wire.root` down to [`TRUE_DIGEST`], returning the per-step
/// `log_precompile` statements in execution order (oldest first).
///
/// First materialises each wire entry into a digest-form `Node` by recomputing its digest
/// (Binary entries reconstruct their payload from earlier entries' digests via the indices).
/// Each entry's recomputed digest is keyed into a lookup map; a tampered entry ends up under
/// the digest its bytes actually hash to, so a forged chain child reference fails to find
/// anything in this map. Then walks AND-nodes via the lookup.
fn walk_deferred_and_chain(
    wire: &DeferredStateWire,
) -> Result<Vec<Digest>, VerificationError> {
    // Phase 1: materialise. Each entry's payload is reconstructed using only earlier entries
    // (`Binary` indices resolve into the `digests` vector built so far).
    let mut digests: Vec<Digest> = Vec::with_capacity(wire.entries.len());
    let mut by_digest: BTreeMap<Digest, Node> = BTreeMap::new();
    for (i, entry) in wire.entries.iter().enumerate() {
        let node = match &entry.body {
            WireBody::Value(payload) => Node::expression(entry.tag, *payload),
            WireBody::Chunks(chunks) => Node::chunk(entry.tag, chunks.clone()),
            WireBody::Binary { lhs, rhs } => {
                let lhs_d = resolve_wire_index(*lhs, i, &digests)?;
                let rhs_d = resolve_wire_index(*rhs, i, &digests)?;
                Node::expression(entry.tag, Payload::binary_op(lhs_d, rhs_d))
            },
        };
        let d = node.digest();
        digests.push(d);
        by_digest.insert(d, node);
    }

    // Phase 2: walk the AND-chain.
    let mut statements = Vec::new();
    let mut current = wire.root;
    while current != TRUE_DIGEST {
        let node = by_digest.get(&current).ok_or(VerificationError::DeferredChainCorrupt {
            reason: DeferredChainErrorReason::MissingNode { digest: current },
        })?;
        if node.tag != TRUE_TAG {
            return Err(VerificationError::DeferredChainCorrupt {
                reason: DeferredChainErrorReason::NonAndNode { digest: current },
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

/// Same semantics as `core::deferred::state::resolve_index`, copied here because the helper is
/// `pub(crate)` to its origin module.
fn resolve_wire_index(idx: u32, current: usize, digests: &[Digest]) -> Result<Digest, VerificationError> {
    if idx == TRUE_INDEX {
        return Ok(TRUE_DIGEST);
    }
    let i = idx as usize;
    if i >= current || i >= digests.len() {
        return Err(VerificationError::DeferredChainCorrupt {
            reason: DeferredChainErrorReason::BadIndex { idx },
        });
    }
    Ok(digests[i])
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
///
/// Content-addressing is verified implicitly when building the wire's digest-keyed lookup map
/// (a tampered node ends up under the digest its bytes hash to, so it can't be reached via a
/// forged child reference). The variants below cover the structural failures that survive that
/// implicit check.
#[derive(Debug, thiserror::Error)]
pub enum DeferredChainErrorReason {
    #[error("expected AND-node {digest} is not present in the deferred state")]
    MissingNode { digest: Digest },
    #[error("node {digest} is reachable from the transcript root but is not an AND-node")]
    NonAndNode { digest: Digest },
    #[error("AND-node {digest} has a chunk-bodied payload (expected expression body)")]
    NonExpressionPayload { digest: Digest },
    #[error("wire Binary entry references out-of-range child index {idx}")]
    BadIndex { idx: u32 },
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
