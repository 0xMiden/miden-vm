//! Advice provision for the recursive STARK verifier.
//!
//! This module mirrors the Fiat-Shamir protocol implemented in MASM
//! (`crates/lib/core/asm/stark/`) on the Rust side. It deserializes a STARK proof,
//! replays the verifier transcript to extract commitments, challenges, and openings,
//! then packs them into the advice inputs (advice stack, Merkle store, and advice map)
//! that the MASM recursive verifier consumes.
//!
//! The advice stack ordering must match the MASM consumption order exactly:
//!
//!   security params (nq, query_pow, deep_pow, folding_pow) ->
//!   dynamic Miden AIR heights ->
//!   fixed-length PI -> num_kernel_proc_digests -> kernel_digests ->
//!   aux randomness -> main commit -> aux commit ->
//!   aux finals -> quotient commit -> deep alpha ND -> OOD evals ->
//!   DEEP PoW witness -> FRI rounds -> FRI remainder -> query PoW witness
//!
//! See `build_advice` for the authoritative layout.

use alloc::{vec, vec::Vec};

use miden_air::{
    MidenMultiAir, ProofOrder, PublicInputs, Statement, ace::build_recursive_verifier_ace_circuit,
    config, trace::and8_lookup::LOG_AND8_LOOKUP_TRACE_HEIGHT,
};
use miden_core::{Felt, WORD_SIZE, Word, field::QuadFelt};
use miden_crypto::{
    field::BasedVectorSpace,
    hash::eidos::{EidosLmcs, MidenEidosChallenger},
    stark::{
        Preprocessed, PreprocessedValidationError, StarkConfig, VerifierInstance,
        air::InstanceError,
        lmcs::{Lmcs, LmcsError, proof::BatchProofView},
        pcs::PcsProof,
        proof::{StarkProof, StarkProofData},
        verifier::VerifierError as CryptoVerifierError,
    },
};

use crate::crypto::{MerklePath, MerkleStore, PartialMerkleTree};

// TYPES
// ================================================================================================

type Challenge = QuadFelt;
type RecursiveConfig = config::MidenStarkConfig<EidosLmcs, MidenEidosChallenger>;
type RecursiveLmcs = <RecursiveConfig as StarkConfig<Felt, Challenge>>::Lmcs;
const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifierData {
    pub initial_stack: Vec<u64>,
    pub advice_stack: Vec<u64>,
    pub store: MerkleStore,
    pub advice_map: Vec<(Word, Vec<Felt>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("proof deserialization error")]
    ProofDeserialization(#[from] wincode::error::ReadError),
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
    #[error(transparent)]
    Statement(#[from] InstanceError),
    #[error(transparent)]
    Preprocessed(#[from] PreprocessedValidationError),
    #[error(transparent)]
    Transcript(#[from] CryptoVerifierError),
    #[error(transparent)]
    Lmcs(#[from] LmcsError),
}

/// Merkle store + advice map pair returned by Merkle data construction.
type MerkleAdvice = (MerkleStore, Vec<(Word, Vec<Felt>)>);

/// Partial trees + advice map entries returned by single batch proof conversion.
type BatchMerkleResult = (Vec<PartialMerkleTree>, Vec<(Word, Vec<Felt>)>);

// PUBLIC API
// ================================================================================================

/// Deserialize a STARK proof and build the advice inputs for the MASM recursive verifier.
pub fn generate_advice_inputs(
    proof_bytes: &[u8],
    pub_inputs: PublicInputs,
) -> Result<VerifierData, VerifierError> {
    let params = config::pcs_params();
    let config = config::eidos_config(params);

    // 1. Deserialize STARK proof bytes.
    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof_data: StarkProofData<Felt, QuadFelt, RecursiveConfig> = <serde_wincode::SerdeCompat<
        StarkProofData<Felt, QuadFelt, RecursiveConfig>,
    > as wincode::config::Deserialize<_>>::deserialize(
        proof_bytes,
        proof_encoding_config,
    )?;

    // 2. Build the Statement.
    let (public_values, kernel_felts) = pub_inputs.to_air_inputs();
    let kernel_digests: Vec<Word> = kernel_felts
        .chunks_exact(WORD_SIZE)
        .map(|c| Word::new([c[0], c[1], c[2], c[3]]))
        .collect();
    let statement: Statement<Felt, QuadFelt, MidenMultiAir> =
        Statement::new(MidenMultiAir::new(), public_values, kernel_felts)?;

    let preprocessed = Preprocessed::build(&statement, &config);
    let preprocessed_commitment = preprocessed.as_ref().map(Preprocessed::commitment);
    if preprocessed_commitment.is_none() {
        return Err(VerifierError::InvalidProofShape("missing Miden preprocessed setup"));
    }

    // 3. Seed challenger with protocol params. `StarkProof::from_data` absorbs the trusted
    //    preprocessed commitment, then the statement and log trace heights.
    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);

    // 4. Replay the Fiat-Shamir transcript.
    let verifier_instance = VerifierInstance::new(&config, &statement, preprocessed_commitment)?;
    let (proof, _digest) = StarkProof::from_data(&verifier_instance, &proof_data, challenger)?;

    // log_trace_heights() returns instance order, which is caller order for MidenMultiAir.
    let log_trace_heights = proof.log_trace_heights();
    let log_core_trace_height = log_trace_heights[0] as usize;
    let log_chiplets_trace_height = log_trace_heights[1] as usize;
    let log_blakeg_compression_trace_height = log_trace_heights[2] as usize;
    if log_trace_heights[3] != LOG_AND8_LOOKUP_TRACE_HEIGHT {
        return Err(VerifierError::InvalidProofShape("invalid And8Lookup trace height"));
    }
    let proof_order = ProofOrder::from_instance_log_heights(&log_trace_heights);

    build_advice(
        &config,
        &proof,
        preprocessed.as_ref().expect("preprocessed presence was checked above"),
        log_core_trace_height,
        log_chiplets_trace_height,
        log_blakeg_compression_trace_height,
        &proof_order,
        pub_inputs,
        &kernel_digests,
    )
}

// ADVICE CONSTRUCTION
// ================================================================================================

fn build_miden_air_shape(
    log_core_trace_height: usize,
    log_chiplets_trace_height: usize,
    log_blakeg_compression_trace_height: usize,
) -> [u64; 3] {
    [
        log_core_trace_height as u64,
        log_chiplets_trace_height as u64,
        log_blakeg_compression_trace_height as u64,
    ]
}

/// Packs the parsed STARK transcript into the advice inputs consumed by the MASM verifier.
///
/// The initial operand stack is empty. The advice stack receives security parameters first,
/// then the dynamic Miden AIR heights, then all remaining data in the order listed above.
fn build_advice(
    config: &RecursiveConfig,
    proof: &StarkProof<Challenge, RecursiveLmcs>,
    preprocessed: &Preprocessed<Felt, RecursiveLmcs>,
    log_core_trace_height: usize,
    log_chiplets_trace_height: usize,
    log_blakeg_compression_trace_height: usize,
    proof_order: &ProofOrder,
    pub_inputs: PublicInputs,
    kernel_digests: &[Word],
) -> Result<VerifierData, VerifierError> {
    let pcs = &proof.pcs_proof;

    // --- initial stack ---
    let initial_stack = vec![];

    // --- advice stack ---
    let mut advice_stack = Vec::new();

    // 0. Security parameters: [num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits].
    //    Consumed first by load_security_params in the specific verifier. num_queries is the
    //    configured protocol parameter, not the potentially deduplicated count (e.g.
    //    tree_indices.len())
    let params = config::pcs_params();
    let num_queries = params.num_queries();
    advice_stack.push(num_queries as u64);
    advice_stack.push(params.query_pow_bits() as u64);
    // DEEP and folding PoW bits are not publicly exposed on PcsParams.
    advice_stack.push(config::DEEP_POW_BITS as u64);
    advice_stack.push(config::FOLDING_POW_BITS as u64);

    // 1. Dynamic Miden AIR heights. The VM wrapper appends the fixed AND8 height before calling the
    //    generic verifier and caches the per-AIR log heights in memory.
    advice_stack.extend_from_slice(&build_miden_air_shape(
        log_core_trace_height,
        log_chiplets_trace_height,
        log_blakeg_compression_trace_height,
    ));

    // 2. Fixed-length public inputs.
    let fixed_len_inputs = build_fixed_len_inputs(&pub_inputs);
    advice_stack.extend_from_slice(&fixed_len_inputs);

    // 3. Number of kernel procedure digests.
    let num_kernel_proc_digests = kernel_digests.len();
    advice_stack.push(num_kernel_proc_digests as u64);

    // 4. Kernel procedure digest elements (each digest padded to 8 elements, reversed).
    let kernel_advice = build_kernel_digest_advice(kernel_digests);
    advice_stack.extend_from_slice(&kernel_advice);

    // 5. Auxiliary randomness [beta0, beta1, alpha0, alpha1].
    assert!(
        proof.randomness.len() >= 2,
        "expected at least 2 randomness challenges (alpha, beta), got {}",
        proof.randomness.len()
    );
    let alpha = proof.randomness[0];
    let beta = proof.randomness[1];
    let beta_coeffs: &[Felt] = beta.as_basis_coefficients_slice();
    let alpha_coeffs: &[Felt] = alpha.as_basis_coefficients_slice();
    advice_stack.extend_from_slice(&[
        beta_coeffs[0].as_canonical_u64(),
        beta_coeffs[1].as_canonical_u64(),
        alpha_coeffs[0].as_canonical_u64(),
        alpha_coeffs[1].as_canonical_u64(),
    ]);

    // 6. Main trace commitment (4 felts).
    advice_stack.extend_from_slice(&commitment_to_u64s(proof.main_commit));

    // 7. Aux trace commitment.
    advice_stack.extend_from_slice(&commitment_to_u64s(proof.aux_commit));

    // 8. Aux finals (bus boundary values), one slot per AIR in proof order.
    for aux_values in &proof.all_aux_values {
        advice_stack.extend_from_slice(&challenges_to_u64s(aux_values));
    }

    // 9. Quotient commitment.
    advice_stack.extend_from_slice(&commitment_to_u64s(proof.quotient_commit));

    // 10. Deep alpha (2 felts) -- the DEEP column-batching challenge.
    let deep_alpha = pcs.deep_proof.challenge_columns;
    let deep_coeffs: &[Felt] = deep_alpha.as_basis_coefficients_slice();
    advice_stack
        .extend_from_slice(&[deep_coeffs[1].as_canonical_u64(), deep_coeffs[0].as_canonical_u64()]);

    // 11. OOD evaluations.
    append_ood_evaluations(&mut advice_stack, pcs);

    // 12. DEEP PoW witness.
    advice_stack.push(pcs.deep_proof.pow_witness.as_canonical_u64());

    // 13. FRI layer commitments + per-round PoW witnesses.
    for round in &pcs.fri_proof.rounds {
        advice_stack.extend_from_slice(&commitment_to_u64s(round.commitment));
        advice_stack.push(round.pow_witness.as_canonical_u64());
    }

    // 14. FRI remainder polynomial (already in descending degree order from the prover, matching
    //     the order observed into the Fiat-Shamir transcript).
    let final_poly = &pcs.fri_proof.final_poly;
    let remainder_base: Vec<Felt> = QuadFelt::flatten_to_base(final_poly.to_vec());
    let remainder_u64s: Vec<u64> = remainder_base.iter().map(Felt::as_canonical_u64).collect();
    advice_stack.extend_from_slice(&remainder_u64s);

    // 15. Query PoW witness.
    advice_stack.push(pcs.query_pow_witness.as_canonical_u64());

    // --- Merkle data ---
    let (store, advice_map) = build_merkle_data(config, proof, preprocessed, proof_order)?;

    Ok(VerifierData {
        initial_stack,
        advice_stack,
        store,
        advice_map,
    })
}

// OOD EVALUATIONS
// ================================================================================================

/// Flatten OOD evaluations into the advice stack.
///
/// The DEEP transcript contains evaluations at two points (z and z*g) for each committed
/// matrix group (preprocessed, main, aux, quotient). We split them into local (at z) and
/// next (at z*g) rows, then append local followed by next.
fn append_ood_evaluations<L>(advice_stack: &mut Vec<u64>, pcs: &PcsProof<Challenge, L>)
where
    L: Lmcs<F = Felt>,
{
    let evals = &pcs.deep_proof.evals;
    let mut local_values = Vec::new();
    let mut next_values = Vec::new();

    for group in evals {
        for matrix in group {
            let width = matrix.width;
            let values = matrix.values.as_slice();
            let local_row = &values[..width];
            let next_row = if values.len() > width {
                &values[width..2 * width]
            } else {
                &[]
            };
            local_values.extend_from_slice(local_row);
            next_values.extend_from_slice(next_row);
        }
    }

    advice_stack.extend_from_slice(&challenges_to_u64s(&local_values));
    advice_stack.extend_from_slice(&challenges_to_u64s(&next_values));
}

// MERKLE DATA
// ================================================================================================

/// Build Merkle store and advice map from the DEEP and FRI opening proofs.
///
/// Each opening proof is converted into a `PartialMerkleTree` (for the Merkle store)
/// and leaf-hash -> leaf-data entries (for the advice map). The MASM verifier uses
/// `mtree_get` to fetch authentication paths and `adv_keyval` to retrieve leaf data.
fn build_merkle_data(
    config: &RecursiveConfig,
    proof: &StarkProof<Challenge, RecursiveLmcs>,
    preprocessed: &Preprocessed<Felt, RecursiveLmcs>,
    proof_order: &ProofOrder,
) -> Result<MerkleAdvice, VerifierError> {
    let pcs = &proof.pcs_proof;
    let lmcs = config.lmcs();

    let mut partial_trees = Vec::new();
    let mut advice_map = Vec::new();

    let query_log_height = proof
        .log_trace_heights()
        .iter()
        .copied()
        .max()
        .ok_or(VerifierError::InvalidProofShape("missing AIR trace heights"))?
        + config.pcs().log_blowup();
    let preprocessed_batch = preprocessed.batch_proof::<Challenge, _>(
        config,
        pcs.query_indices.iter().copied(),
        query_log_height,
    )?;
    let (trees, advs) = batch_proof_to_merkle(lmcs, &preprocessed_batch)?;
    partial_trees.extend(trees);
    advice_map.extend(advs);

    // DEEP openings -- one BatchProof per commitment group.
    for batch_proof in pcs.deep_witnesses.iter() {
        let (trees, advs) = batch_proof_to_merkle(lmcs, batch_proof)?;
        partial_trees.extend(trees);
        advice_map.extend(advs);
    }

    // FRI openings -- one BatchProof per FRI round.
    for batch_proof in pcs.fri_witnesses.iter() {
        let (trees, advs) = batch_proof_to_merkle(lmcs, batch_proof)?;
        partial_trees.extend(trees);
        advice_map.extend(advs);
    }

    let mut store = MerkleStore::new();
    for tree in &partial_trees {
        store.extend(tree.inner_nodes());
    }
    extend_ace_registry_store(&mut store);
    extend_ace_circuit_advice(&mut advice_map, proof_order)?;

    Ok((store, advice_map))
}

fn extend_ace_registry_store(store: &mut MerkleStore) {
    let registry_tree = config::ace_circuit_registry_tree();
    store.extend(registry_tree.inner_nodes());
}

fn extend_ace_circuit_advice(
    advice_map: &mut Vec<(Word, Vec<Felt>)>,
    proof_order: &ProofOrder,
) -> Result<(), VerifierError> {
    let circuit = build_recursive_verifier_ace_circuit(proof_order)
        .map_err(|_| VerifierError::InvalidProofShape("failed to build recursive ACE circuit"))?;
    advice_map.push((circuit.commitment, circuit.instructions));
    Ok(())
}

/// Convert a `BatchProof` into `PartialMerkleTree` entries and advice map entries.
///
/// For each query index, reconstructs the Merkle authentication path from the batch proof,
/// computes the leaf hash, and produces:
/// - A one-path partial Merkle tree for the Merkle store
/// - A `(leaf_hash, leaf_data)` pair for the advice map
fn batch_proof_to_merkle<L>(
    lmcs: &L,
    batch_proof: &L::BatchProof,
) -> Result<BatchMerkleResult, VerifierError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + Into<[u64; 4]>,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
    L::Commitment: PartialEq,
{
    let mut trees = Vec::new();
    let mut advice_entries = Vec::new();

    for index in batch_proof.indices() {
        let rows = batch_proof
            .opening(index)
            .ok_or(VerifierError::InvalidProofShape("missing opening for query index"))?;
        let siblings = batch_proof
            .path(index)
            .ok_or(VerifierError::InvalidProofShape("missing Merkle path for query index"))?;

        let leaf_data: Vec<Felt> = rows.as_slice().to_vec();
        let leaf_hash = lmcs.hash(rows.iter_rows());
        let leaf_word = commitment_to_word(leaf_hash);
        let merkle_path = MerklePath::new(siblings.into_iter().map(commitment_to_word).collect());

        let tree = PartialMerkleTree::with_paths([(index as u64, leaf_word, merkle_path)])
            .map_err(|_| VerifierError::InvalidProofShape("invalid merkle path"))?;
        trees.push(tree);
        advice_entries.push((leaf_word, leaf_data));
    }

    Ok((trees, advice_entries))
}

/// Build kernel digest advice data.
///
/// Each digest (4 elements) is padded to 8 elements with zeros, then reversed. This matches
/// the format used by the MASM `reduce_kernel_digests` procedure which uses `mem_stream` +
/// `horner_eval_base` to process digests in 8-element chunks.
fn build_kernel_digest_advice(kernel_digests: &[Word]) -> Vec<u64> {
    let mut result = Vec::with_capacity(kernel_digests.len() * 8);
    for digest in kernel_digests {
        let mut padded: Vec<u64> =
            digest.as_elements().iter().map(Felt::as_canonical_u64).collect();
        padded.resize(8, 0);
        padded.reverse();
        result.extend_from_slice(&padded);
    }
    result
}

/// Build the fixed-length public inputs in the order the MASM random coin observes them.
///
/// Must stay in sync with `PublicInputs::to_air_inputs()`.
fn build_fixed_len_inputs(pub_inputs: &PublicInputs) -> Vec<u64> {
    let mut felts = Vec::<Felt>::new();
    felts.extend_from_slice(pub_inputs.program_info().program_hash().as_elements());
    felts.extend_from_slice(pub_inputs.stack_inputs().as_ref());
    felts.extend_from_slice(pub_inputs.stack_outputs().as_ref());
    felts.extend_from_slice(pub_inputs.pc_transcript_state().as_ref());
    let mut fixed_len: Vec<u64> = felts.iter().map(Felt::as_canonical_u64).collect();
    fixed_len.resize(fixed_len.len().next_multiple_of(8), 0);
    fixed_len
}

fn commitment_to_u64s<C: Copy + Into<[u64; 4]>>(commitment: C) -> Vec<u64> {
    commitment.into().to_vec()
}

fn commitment_to_word<C: Copy + Into<[u64; 4]>>(commitment: C) -> Word {
    Word::new(commitment.into().map(Felt::new_unchecked))
}

fn challenges_to_u64s(challenges: &[Challenge]) -> Vec<u64> {
    let base: Vec<Felt> = QuadFelt::flatten_to_base(challenges.to_vec());
    base.iter().map(Felt::as_canonical_u64).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::NodeIndex;

    #[test]
    fn ace_registry_tree_is_available_in_recursive_advice_store() {
        let mut store = MerkleStore::new();
        extend_ace_registry_store(&mut store);

        let root = Word::new(config::RELATION_DIGEST);
        for (index, leaf) in config::ACE_CIRCUIT_REGISTRY_LEAVES.iter().enumerate() {
            let node_index =
                NodeIndex::new(config::ACE_CIRCUIT_REGISTRY_DEPTH as u8, index as u64).unwrap();
            let stored = store.get_node(root, node_index).unwrap();
            assert_eq!(stored, Word::new(*leaf));
        }
    }
}
