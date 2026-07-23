//! Advice provision for the MASM recursive STARK verifier.
//!
//! The Rust side parses the proof transcript, then provides the stack, Merkle store,
//! and advice-map entries consumed by `crates/lib/core/asm/stark`.
//!
//! The advice stack ordering must match the MASM consumption order exactly. The kernel digests and
//! stack i/o lead the tape because the test marshalling in `run_recursive_verifier` copies them
//! into caller-owned memory before `verify_proof` runs:
//!
//!   kernel_digests -> stack i/o ->
//!   security params (nq, query_pow, deep_pow, folding_pow) ->
//!   deferred root -> Miden AIR heights -> main commit -> aux commit ->
//!   aux finals -> quotient commit -> deep alpha ND -> OOD evals ->
//!   DEEP PoW witness -> FRI rounds -> FRI remainder -> query PoW witness
//!
//! The program digest, kernel digest count, and kernel/stack-i/o pointers are supplied on the
//! initial operand stack. See `build_advice` for the authoritative layout.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use miden_air::{
    MIDEN_AIR_COUNT, MidenMultiAir, ProofOrder, PublicInputs, Statement,
    ace::build_recursive_verifier_ace_circuit, config,
};
use miden_core::{Felt, Word, field::QuadFelt};
use miden_crypto::{
    field::BasedVectorSpace,
    stark::{
        StarkConfig, VerifierInstance,
        lmcs::{Lmcs, proof::BatchProofView},
        pcs::PcsProof,
        proof::{StarkProof, StarkProofData},
        verifier::VerifierError as CryptoVerifierError,
    },
};

use crate::crypto::{MerklePath, MerkleStore, PartialMerkleTree};

// TYPES
// ================================================================================================

type Challenge = QuadFelt;
type P2Config = config::Poseidon2Config;
type P2Lmcs = <P2Config as StarkConfig<Felt, Challenge>>::Lmcs;
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

struct MidenTraceHeights {
    instance_order: [usize; MIDEN_AIR_COUNT],
    proof_order: ProofOrder,
}

// PUBLIC API
// ================================================================================================

/// Deserialize a STARK proof and build the advice inputs for the MASM recursive verifier.
pub fn generate_advice_inputs(
    proof_bytes: &[u8],
    pub_inputs: PublicInputs,
) -> Result<VerifierData, VerifierError> {
    let params = config::pcs_params();
    let config = config::poseidon2_config(params);

    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof: StarkProofData<Felt, QuadFelt, P2Config> = <serde_wincode::SerdeCompat<
        StarkProofData<Felt, QuadFelt, P2Config>,
    > as wincode::config::Deserialize<_>>::deserialize(
        proof_bytes, proof_encoding_config
    )
    .map_err(|e| VerifierError::ProofDeserializationError(e.to_string()))?;

    let (public_values, aux_inputs) = pub_inputs.to_air_inputs();
    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);

    let statement =
        Statement::<Felt, QuadFelt, _>::new(MidenMultiAir::new(), public_values, aux_inputs)
            .map_err(|e| VerifierError::ProofDeserializationError(e.to_string()))?;
    let verifier_instance = VerifierInstance::new(&config, &statement, None)
        .expect("Miden AIRs declare no preprocessed columns");

    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof, challenger)?;

    let heights = miden_trace_heights(&stark)?;

    let kernel_digests: Vec<Word> = pub_inputs.program_info().kernel_procedures().to_vec();

    build_advice(&config, &stark, heights, pub_inputs, &kernel_digests)
}

fn miden_trace_heights(
    stark: &StarkProof<Challenge, P2Lmcs>,
) -> Result<MidenTraceHeights, VerifierError> {
    let log_heights = stark.log_trace_heights();
    let Ok(log_heights): Result<[u8; MIDEN_AIR_COUNT], _> = log_heights.try_into() else {
        return Err(VerifierError::InvalidProofShape("unexpected number of AIR log heights"));
    };
    let instance_order = log_heights.map(usize::from);

    Ok(MidenTraceHeights {
        instance_order,
        proof_order: ProofOrder::from_instance_log_heights(&log_heights),
    })
}

// ADVICE CONSTRUCTION
// ================================================================================================

/// Packs the parsed STARK transcript into the advice inputs consumed by the MASM verifier.
///
/// The initial operand stack contains caller pointers, the kernel digest count, and the program
/// digest. The advice stack starts with data copied into caller memory by the test prologue, then
/// continues in the order consumed by the verifier.
fn build_advice(
    config: &P2Config,
    stark: &StarkProof<Challenge, P2Lmcs>,
    heights: MidenTraceHeights,
    pub_inputs: PublicInputs,
    kernel_digests: &[Word],
) -> Result<VerifierData, VerifierError> {
    let pcs = &stark.pcs_proof;
    if stark.all_aux_values.len() != MIDEN_AIR_COUNT {
        return Err(VerifierError::InvalidProofShape("unexpected number of aux-final groups"));
    }

    // Caller-owned memory regions consumed by the test marshalling in `run_recursive_verifier`:
    // kernel digests at KERNEL_PTR, the claim region at CLAIM_PTR. These must match the
    // constants in that MASM prologue.
    const KERNEL_PTR: u64 = 0;
    const CLAIM_PTR: u64 = 4096;

    let num_kernel_proc_digests = kernel_digests.len();
    let program_digest: Word = *pub_inputs.program_info().program_hash();
    let program_digest = program_digest.as_elements();

    // `claim_ptr` is on top. `StackInputs::try_from_ints` puts `vec[0]` on top.
    let initial_stack = vec![CLAIM_PTR, KERNEL_PTR, num_kernel_proc_digests as u64];

    let mut advice_stack = Vec::new();

    // Kernel procedure digests are copied into the witness region at KERNEL_PTR.
    let kernel_advice = build_kernel_digest_advice(kernel_digests);
    advice_stack.extend_from_slice(&kernel_advice);

    // The program digest and stack i/o are copied into the claim region at CLAIM_PTR
    // (P at +0, I/O at +8); the verifier writes K at +4.
    advice_stack.extend(program_digest.iter().map(Felt::as_canonical_u64));
    advice_stack.extend_from_slice(&build_stack_io_advice(&pub_inputs));

    // Security parameters: [num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits].
    let params = config::pcs_params();
    let num_queries = params.num_queries();
    advice_stack.push(num_queries as u64);
    advice_stack.push(params.query_pow_bits() as u64);
    // DEEP and folding PoW bits are not publicly exposed on PcsParams;
    // use the constants from air/src/config.rs directly.
    advice_stack.push(config::DEEP_POW_BITS as u64);
    advice_stack.push(config::FOLDING_POW_BITS as u64);

    // Final deferred root, loaded by `public_inputs::stage_boundary_inputs`.
    advice_stack.extend(pub_inputs.deferred_root().as_ref().iter().map(Felt::as_canonical_u64));

    for height in heights.instance_order {
        advice_stack.push(height as u64);
    }

    advice_stack.extend_from_slice(&commitment_to_u64s(stark.main_commit));
    advice_stack.extend_from_slice(&commitment_to_u64s(stark.aux_commit));

    for aux_values in &stark.all_aux_values {
        advice_stack.extend_from_slice(&challenges_to_u64s(aux_values));
    }

    advice_stack.extend_from_slice(&commitment_to_u64s(stark.quotient_commit));

    let deep_alpha = pcs.deep_proof.challenge_columns;
    let deep_coeffs: &[Felt] = deep_alpha.as_basis_coefficients_slice();
    advice_stack
        .extend_from_slice(&[deep_coeffs[1].as_canonical_u64(), deep_coeffs[0].as_canonical_u64()]);

    append_ood_evaluations(&mut advice_stack, pcs);

    advice_stack.push(pcs.deep_proof.pow_witness.as_canonical_u64());

    for round in &pcs.fri_proof.rounds {
        advice_stack.extend_from_slice(&commitment_to_u64s(round.commitment));
        advice_stack.push(round.pow_witness.as_canonical_u64());
    }

    let final_poly = &pcs.fri_proof.final_poly;
    let remainder_base: Vec<Felt> = QuadFelt::flatten_to_base(final_poly.to_vec());
    let remainder_u64s: Vec<u64> = remainder_base.iter().map(Felt::as_canonical_u64).collect();
    advice_stack.extend_from_slice(&remainder_u64s);

    advice_stack.push(pcs.query_pow_witness.as_canonical_u64());

    let (store, advice_map) = build_merkle_data(config, stark, &heights.proof_order)?;

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
    config: &P2Config,
    stark: &StarkProof<Challenge, P2Lmcs>,
    proof_order: &ProofOrder,
) -> Result<MerkleAdvice, VerifierError> {
    let pcs = &stark.pcs_proof;
    let lmcs = config.lmcs();

    let mut partial_trees = Vec::new();
    let mut advice_map = Vec::new();

    // DEEP openings -- one BatchProof per commitment (main, aux, quotient).
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
/// - A `(index, leaf_hash, path)` triple for the partial Merkle tree
/// - A `(leaf_hash, leaf_data)` pair for the advice map
fn batch_proof_to_merkle<L>(
    lmcs: &L,
    batch_proof: &L::BatchProof,
) -> Result<BatchMerkleResult, VerifierError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + Into<[Felt; 4]>,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
    L::Commitment: PartialEq,
{
    let mut paths = Vec::new();
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
        let leaf_word: Word = Word::new(leaf_hash.into());
        let merkle_path =
            MerklePath::new(siblings.into_iter().map(|c| Word::new(c.into())).collect());

        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }

    let tree = PartialMerkleTree::with_paths(paths)
        .map_err(|_| VerifierError::InvalidProofShape("invalid merkle paths"))?;

    Ok((vec![tree], advice_entries))
}

/// Build kernel digest advice data: 4 canonical felts per digest, in order. The test marshalling
/// copies these felts into the caller-owned kernel region at KERNEL_PTR, which `verify_proof`
/// hashes with `hash_elements` to recompute the kernel commitment.
fn build_kernel_digest_advice(kernel_digests: &[Word]) -> Vec<u64> {
    let mut result = Vec::with_capacity(kernel_digests.len() * 4);
    for digest in kernel_digests {
        result.extend(digest.as_elements().iter().map(Felt::as_canonical_u64));
    }
    result
}

/// Build the fixed-length public inputs (stack i/o): stack inputs (16), stack outputs (16). The
/// test marshalling copies these 32 felts into the caller-owned region at STACK_IO_PTR.
fn build_stack_io_advice(pub_inputs: &PublicInputs) -> Vec<u64> {
    let mut felts = Vec::<Felt>::new();
    felts.extend_from_slice(pub_inputs.stack_inputs().as_ref());
    felts.extend_from_slice(pub_inputs.stack_outputs().as_ref());
    felts.iter().map(Felt::as_canonical_u64).collect()
}

fn commitment_to_u64s<C: Copy + Into<[Felt; 4]>>(commitment: C) -> Vec<u64> {
    let felts: [Felt; 4] = commitment.into();
    felts.iter().map(Felt::as_canonical_u64).collect()
}

fn challenges_to_u64s(challenges: &[Challenge]) -> Vec<u64> {
    let base: Vec<Felt> = QuadFelt::flatten_to_base(challenges.to_vec());
    base.iter().map(Felt::as_canonical_u64).collect()
}
