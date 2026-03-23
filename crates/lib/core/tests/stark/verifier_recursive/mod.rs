//! Advice provision for the recursive STARK verifier.
//!
//! This module mirrors the Fiat-Shamir protocol implemented in MASM
//! (`crates/lib/core/asm/stark/`) on the Rust side. It deserializes a STARK proof,
//! replays the verifier transcript to extract commitments, challenges, and openings,
//! then packs them into the advice inputs (initial stack, advice stack, Merkle store,
//! and advice map) that the MASM recursive verifier consumes.
//!
//! The advice stack ordering must match the MASM consumption order exactly:
//!
//!   security params (nq, query_pow, deep_pow, folding_pow) ->
//!   fixed-length PI -> num_kernel_proc_digests -> kernel_digests ->
//!   aux randomness -> main commit -> aux commit ->
//!   aux finals -> quotient commit -> deep alpha ND -> OOD evals ->
//!   DEEP PoW witness -> FRI rounds -> FRI remainder -> query PoW witness
//!
//! See `build_advice` for the authoritative layout.

use alloc::vec::Vec;

use miden_air::{ProcessorAir, PublicInputs, config, config::InitTranscript};
use miden_core::{Felt, WORD_SIZE, Word, field::QuadFelt};
use miden_crypto::{
    field::BasedVectorSpace,
    hash::poseidon2::Poseidon2Permutation256,
    stark::{
        StarkConfig,
        air::AirInstance,
        challenger::{CanObserve, DuplexChallenger},
        fri::PcsTranscript,
        lmcs::{BatchProof, Lmcs},
        proof::StarkTranscript,
        verifier::VerifierError as CryptoVerifierError,
    },
};
use miden_utils_testing::crypto::{MerklePath, MerkleStore, PartialMerkleTree};

// TYPES
// ================================================================================================

type Challenge = QuadFelt;
type P2Config = config::Poseidon2Config;
type P2Lmcs = <P2Config as StarkConfig<Felt, Challenge>>::Lmcs;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct VerifierData {
    pub initial_stack: Vec<u64>,
    pub advice_stack: Vec<u64>,
    pub store: MerkleStore,
    pub advice_map: Vec<(Word, Vec<Felt>)>,
}

#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("proof deserialization error: {0}")]
    ProofDeserializationError(String),
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
    #[error("transcript error: {0}")]
    Transcript(#[from] CryptoVerifierError),
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
    let config = config::poseidon2_config(params);

    // 1. Deserialize (log_trace_height, transcript_data) from proof bytes.
    let (log_trace_height, transcript_data): (u8, _) = bincode::deserialize(proof_bytes)
        .map_err(|e| VerifierError::ProofDeserializationError(e.to_string()))?;
    let log_trace_height = log_trace_height as usize;

    // 2. Build domain-separated challenger, then observe public values.
    let (public_values, kernel_felts) = pub_inputs.to_air_inputs();
    let mut challenger: DuplexChallenger<Felt, Poseidon2Permutation256, 12, 8> =
        InitTranscript::seeded(log_trace_height as u64);
    challenger.observe_slice(&public_values);
    let var_len_public_inputs: &[&[Felt]] = &[&kernel_felts];
    config::observe_var_len_public_inputs(&mut challenger, var_len_public_inputs, &[WORD_SIZE]);

    // 3. Build AIR instance.
    let air = ProcessorAir;
    let instance = AirInstance {
        log_trace_height: log_trace_height as u8,
        public_values: &public_values,
        var_len_public_inputs,
    };

    // 4. Parse STARK transcript (mirrors Fiat-Shamir protocol).
    let (stark, _digest) =
        StarkTranscript::from_proof(&config, &[(&air, instance)], &transcript_data, challenger)?;

    // 5. Reconstruct kernel digests as Words for advice building.
    let kernel_digests: Vec<Word> = kernel_felts
        .chunks_exact(4)
        .map(|c| Word::new([c[0], c[1], c[2], c[3]]))
        .collect();

    // 6. Build advice from parsed transcript.
    build_advice(&config, &stark, log_trace_height, pub_inputs, &kernel_digests)
}

// ADVICE CONSTRUCTION
// ================================================================================================

/// Packs the parsed STARK transcript into the advice inputs consumed by the MASM verifier.
///
/// The initial operand stack receives `[log_trace_height]`.
/// The advice stack receives security parameters first, then all remaining data
/// in the order listed in the module doc.
fn build_advice(
    config: &P2Config,
    stark: &StarkTranscript<Challenge, P2Lmcs>,
    log_trace_height: usize,
    pub_inputs: PublicInputs,
    kernel_digests: &[Word],
) -> Result<VerifierData, VerifierError> {
    let pcs = &stark.pcs_transcript;

    // --- initial stack ---
    // Only log(trace_length) is on the operand stack. Security parameters are on the advice stack.
    let initial_stack = vec![log_trace_height as u64];

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
    // DEEP and folding PoW bits are not publicly exposed on PcsParams;
    // use the constants from air/src/config.rs directly.
    advice_stack.push(config::DEEP_POW_BITS as u64);
    advice_stack.push(config::FOLDING_POW_BITS as u64);

    // 1. Fixed-length public inputs.
    let fixed_len_inputs = build_fixed_len_inputs(&pub_inputs);
    advice_stack.extend_from_slice(&fixed_len_inputs);

    // 2. Number of kernel procedure digests.
    let num_kernel_proc_digests = kernel_digests.len();
    advice_stack.push(num_kernel_proc_digests as u64);

    // 3. Kernel procedure digest elements (each digest padded to 8 elements, reversed).
    let kernel_advice = build_kernel_digest_advice(kernel_digests);
    advice_stack.extend_from_slice(&kernel_advice);

    // 4. Auxiliary randomness [beta0, beta1, alpha0, alpha1].
    assert!(
        stark.randomness.len() >= 2,
        "expected at least 2 randomness challenges (alpha, beta), got {}",
        stark.randomness.len()
    );
    let alpha = stark.randomness[0];
    let beta = stark.randomness[1];
    let beta_coeffs: &[Felt] = beta.as_basis_coefficients_slice();
    let alpha_coeffs: &[Felt] = alpha.as_basis_coefficients_slice();
    advice_stack.extend_from_slice(&[
        beta_coeffs[0].as_canonical_u64(),
        beta_coeffs[1].as_canonical_u64(),
        alpha_coeffs[0].as_canonical_u64(),
        alpha_coeffs[1].as_canonical_u64(),
    ]);

    // 5. Main trace commitment (4 felts).
    advice_stack.extend_from_slice(&commitment_to_u64s(stark.main_commit));

    // 6. Aux trace commitment.
    advice_stack.extend_from_slice(&commitment_to_u64s(stark.aux_commit));

    // 7. Aux finals (bus boundary values).
    if !stark.all_aux_values.is_empty() {
        let aux_values = &stark.all_aux_values[0];
        advice_stack.extend_from_slice(&challenges_to_u64s(aux_values));
    }

    // 8. Quotient commitment.
    advice_stack.extend_from_slice(&commitment_to_u64s(stark.quotient_commit));

    // 9. Deep alpha (2 felts) -- the DEEP column-batching challenge.
    let deep_alpha = pcs.deep_transcript.challenge_columns;
    let deep_coeffs: &[Felt] = deep_alpha.as_basis_coefficients_slice();
    advice_stack
        .extend_from_slice(&[deep_coeffs[1].as_canonical_u64(), deep_coeffs[0].as_canonical_u64()]);

    // 10. OOD evaluations.
    append_ood_evaluations(&mut advice_stack, pcs);

    // 11. DEEP PoW witness.
    advice_stack.push(pcs.deep_transcript.pow_witness.as_canonical_u64());

    // 12. FRI layer commitments + per-round PoW witnesses.
    for round in &pcs.fri_transcript.rounds {
        advice_stack.extend_from_slice(&commitment_to_u64s(round.commitment));
        advice_stack.push(round.pow_witness.as_canonical_u64());
    }

    // 13. FRI remainder polynomial (already in descending degree order from the prover, matching
    //     the order observed into the Fiat-Shamir transcript).
    let final_poly = &pcs.fri_transcript.final_poly;
    let remainder_base: Vec<Felt> = QuadFelt::flatten_to_base(final_poly.to_vec());
    let remainder_u64s: Vec<u64> = remainder_base.iter().map(|f| f.as_canonical_u64()).collect();
    advice_stack.extend_from_slice(&remainder_u64s);

    // 14. Query PoW witness.
    advice_stack.push(pcs.query_pow_witness.as_canonical_u64());

    // --- Merkle data ---
    let (store, advice_map) = build_merkle_data(config, stark, log_trace_height)?;

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
/// matrix (main, aux, quotient). We split them into local (at z) and next (at z*g) rows,
/// then append local followed by next.
fn append_ood_evaluations<L>(advice_stack: &mut Vec<u64>, pcs: &PcsTranscript<Challenge, L>)
where
    L: Lmcs<F = Felt>,
{
    let evals = &pcs.deep_transcript.evals;
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
    config: &P2Config,
    stark: &StarkTranscript<Challenge, P2Lmcs>,
    log_trace_height: usize,
) -> Result<MerkleAdvice, VerifierError> {
    let pcs = &stark.pcs_transcript;
    let lmcs = config.lmcs();
    let log_blowup = config::pcs_params().log_blowup() as usize;
    let log_lde_height = log_trace_height + log_blowup;

    let mut partial_trees = Vec::new();
    let mut advice_map = Vec::new();

    // DEEP openings -- one BatchProof per commitment (main, aux, quotient).
    for batch_proof in pcs.deep_openings.iter() {
        let (trees, advs) =
            batch_proof_to_merkle(lmcs, batch_proof, log_lde_height, &pcs.tree_indices)?;
        partial_trees.extend(trees);
        advice_map.extend(advs);
    }

    // FRI openings -- one BatchProof per FRI round.
    let log_arity = config::LOG_FOLDING_ARITY as usize;
    for (round_idx, batch_proof) in pcs.fri_openings.iter().enumerate() {
        let log_folded = log_arity * (round_idx + 1);
        let round_indices: Vec<usize> =
            pcs.tree_indices.iter().map(|&idx| idx >> log_folded).collect();
        let fri_log_height = log_lde_height - log_folded;
        let (trees, advs) =
            batch_proof_to_merkle(lmcs, batch_proof, fri_log_height, &round_indices)?;
        partial_trees.extend(trees);
        advice_map.extend(advs);
    }

    let mut store = MerkleStore::new();
    for tree in &partial_trees {
        store.extend(tree.inner_nodes());
    }

    Ok((store, advice_map))
}

/// Convert a `BatchProof` into `PartialMerkleTree` entries and advice map entries.
///
/// For each query index, reconstructs the Merkle authentication path from the batch proof,
/// computes the leaf hash, and produces:
/// - A `(index, leaf_hash, path)` triple for the partial Merkle tree
/// - A `(leaf_hash, leaf_data)` pair for the advice map
fn batch_proof_to_merkle<L>(
    lmcs: &L,
    batch_proof: &L::BatchProof,
    log_height: usize,
    query_indices: &[usize],
) -> Result<BatchMerkleResult, VerifierError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + Into<[Felt; 4]>,
    L::BatchProof: AsLmcsBatchProof<Felt, L::Commitment>,
    L::Commitment: PartialEq,
{
    let batch = batch_proof.as_batch_proof();

    let widths = infer_widths(batch);
    let single_proofs = batch
        .single_proofs(lmcs, &widths, log_height as u8)
        .ok_or(VerifierError::InvalidProofShape("failed to reconstruct merkle paths"))?;

    let mut paths = Vec::new();
    let mut advice_entries = Vec::new();

    for &index in query_indices {
        let proof = single_proofs
            .get(&index)
            .ok_or(VerifierError::InvalidProofShape("missing opening for query index"))?;

        let leaf_data: Vec<Felt> = proof.rows.as_slice().to_vec();
        let leaf_hash = lmcs.hash(proof.rows.iter_rows());
        let leaf_word: Word = Word::new(leaf_hash.into());
        let merkle_path =
            MerklePath::new(proof.siblings.iter().map(|c| Word::new((*c).into())).collect());

        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }

    let tree = PartialMerkleTree::with_paths(paths)
        .map_err(|_| VerifierError::InvalidProofShape("invalid merkle paths"))?;

    Ok((vec![tree], advice_entries))
}

// BATCH PROOF TRAIT
// ================================================================================================

/// Trait to access `BatchProof` fields generically through the `Lmcs::BatchProof` associated type.
pub trait AsLmcsBatchProof<F, C> {
    fn as_batch_proof(&self) -> &BatchProof<F, C>;
}

impl<F, C> AsLmcsBatchProof<F, C> for BatchProof<F, C> {
    fn as_batch_proof(&self) -> &BatchProof<F, C> {
        self
    }
}

// HELPERS
// ================================================================================================

fn infer_widths<F, C>(batch: &BatchProof<F, C>) -> Vec<usize> {
    batch
        .openings
        .values()
        .next()
        .map(|opening| opening.rows.iter_rows().map(|row| row.len()).collect())
        .unwrap_or_default()
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
            digest.as_elements().iter().map(|f| f.as_canonical_u64()).collect();
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
    let mut fixed_len = Vec::new();
    fixed_len
        .extend_from_slice(&felts_to_u64(pub_inputs.program_info().program_hash().as_elements()));
    fixed_len.extend_from_slice(&felts_to_u64(pub_inputs.stack_inputs().as_ref()));
    fixed_len.extend_from_slice(&felts_to_u64(pub_inputs.stack_outputs().as_ref()));
    fixed_len.extend_from_slice(&felts_to_u64(pub_inputs.pc_transcript_state().as_ref()));
    fixed_len.resize(fixed_len.len().next_multiple_of(8), 0);
    fixed_len
}

fn felts_to_u64(felts: &[Felt]) -> Vec<u64> {
    felts.iter().map(|f| f.as_canonical_u64()).collect()
}

fn commitment_to_u64s<C: Copy + Into<[Felt; 4]>>(commitment: C) -> Vec<u64> {
    let felts: [Felt; 4] = commitment.into();
    felts.iter().map(|f| f.as_canonical_u64()).collect()
}

fn challenges_to_u64s(challenges: &[Challenge]) -> Vec<u64> {
    let base: Vec<Felt> = QuadFelt::flatten_to_base(challenges.to_vec());
    base.iter().map(|f| f.as_canonical_u64()).collect()
}

