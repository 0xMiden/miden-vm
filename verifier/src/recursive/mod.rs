//! Building the advice a MASM recursive verifier consumes to verify a Miden VM proof.
//!
//! `exec.vm::verify_vm_proof` reads a STARK proof from the advice provider in a fixed order. This
//! module is the producer side of that ABI: it destructures an [`ExecutionProof`] against its
//! [`ExecutionClaim`] into the advice-stack stream, the Merkle store, and the query advice-map
//! entries the verifier consumes. The consumption order is exercised end to end by the recursive
//! verification tests, which drive the real MASM verifier over this output.
//!
//! The stream carries only the proof — the claim is the consumer's and never travels in it:
//!
//!   security params (nq, query_pow, deep_pow, folding_pow) ->
//!   deferred root -> Miden AIR heights -> main commit -> aux commit ->
//!   aux finals -> quotient commit -> deep alpha -> OOD evals ->
//!   DEEP PoW witness -> FRI rounds -> FRI remainder -> query PoW witness
//!
//! The consumer fills the kernel witness, program digest, and stack i/o into VM memory from its
//! own claim; `verify_vm_proof` verifies this stream against that claim, so a substituted stream
//! fails rather than redefining the claim. The Merkle store and query advice-map are
//! content-addressed and merge across proofs without collision.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use miden_air::{
    MIDEN_AIR_COUNT, MidenMultiAir, ProofOrder, PublicInputs, Statement,
    ace::build_recursive_verifier_ace_circuit, config,
};
use miden_core::{
    Felt, Word,
    crypto::merkle::{MerklePath, MerkleStore, PartialMerkleTree},
    field::QuadFelt,
    program::{ExecutionClaim, request_key},
    proof::{ExecutionProof, HashFunction},
};
use miden_crypto::{
    field::BasedVectorSpace,
    stark::{
        StarkConfig, VerifierInstance,
        lmcs::{Lmcs, proof::BatchProofView},
        pcs::{PcsParams, PcsProof},
        proof::{StarkProof, StarkProofData},
        verifier::VerifierError as CryptoVerifierError,
    },
};

// TYPES
// ================================================================================================

type Challenge = QuadFelt;
type P2Config = config::Poseidon2Config;
type P2Lmcs = <P2Config as StarkConfig<Felt, Challenge>>::Lmcs;
type P2ProofData = StarkProofData<Felt, Challenge, P2Config>;

/// Bound on the wincode preallocation while deserializing a proof, so a corrupt length prefix
/// cannot trigger an outsized allocation. Generously above any real Miden VM proof.
const MAX_STARK_PROOF_BYTES: usize = 64 * 1024 * 1024;

/// The advice a MASM recursive verifier consumes to verify one Miden VM proof.
///
/// The `advice_stack` stream feeds `exec.vm::verify_vm_proof` directly;
/// [`Self::into_request_package`] instead registers it in the advice map under
/// `request_key(verifier_root, claim_commitment)` for consumers that fetch proofs by content
/// (`exec.vm::verify_vm_proof_from_claim`).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecursiveVerifierInputs {
    /// The advice-stack stream, in the order `verify_vm_proof` (with the standard staging
    /// prologue) consumes it.
    pub advice_stack: Vec<Felt>,
    /// Merkle store backing the query openings (`mtree_get` authentication paths).
    pub store: MerkleStore,
    /// Query advice-map entries (`leaf_hash -> leaf_data`) and the ACE circuit.
    pub advice_map: Vec<(Word, Vec<Felt>)>,
    /// Commitment to the execution claim: the content address (paired with a verifier root) the
    /// proof stream is registered under.
    pub claim_commitment: Word,
}

impl RecursiveVerifierInputs {
    /// Moves the proof stream into the advice map under
    /// `request_key(verifier_root, claim_commitment)`, leaving the advice stack empty.
    ///
    /// The result is order-free — all of it (Merkle nodes, query rows, proof stream) is
    /// content-addressed, so packages for any number of proofs merge into one advice provider in
    /// any order. A consumer holding the claim fetches and verifies the proof with
    /// `exec.vm::verify_vm_proof_from_claim`; the key is addressing, not trust — a package that
    /// does not match the consumer's claim fails verification.
    pub fn into_request_package(mut self, verifier_root: Word) -> Self {
        let key = request_key(verifier_root, self.claim_commitment);
        let proof_stream = core::mem::take(&mut self.advice_stack);
        self.advice_map.push((key, proof_stream));
        self
    }
}

/// Errors returned while building the advice for recursive verification.
#[derive(Debug, thiserror::Error)]
pub enum RecursiveAdviceError {
    #[error("proof deserialization error: {0}")]
    ProofDeserialization(String),
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
    #[error("statement assembly error: {0}")]
    StatementAssembly(String),
    #[error("recursive verification supports only Poseidon2 proofs, got {0:?}")]
    UnsupportedHashFunction(HashFunction),
    #[error("transcript error: {0}")]
    Transcript(#[from] CryptoVerifierError),
}

/// Merkle store + advice map pair returned by Merkle data construction.
type MerkleAdvice = (MerkleStore, Vec<(Word, Vec<Felt>)>);

/// The per-AIR log trace heights, in both arrangements the advice needs: the fixed instance
/// order (streamed to the verifier) and the sorted proof order (ACE circuit selection).
struct MidenTraceHeights {
    instance_log_heights: [usize; MIDEN_AIR_COUNT],
    proof_order: ProofOrder,
}

// PUBLIC API
// ================================================================================================

/// Builds the advice a MASM recursive verifier consumes to verify a Miden VM proof against
/// its claim.
///
/// The proof must be a Poseidon2 proof — the recursive verifier verifies only Poseidon2 STARKs.
pub fn advice_inputs(
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<RecursiveVerifierInputs, RecursiveAdviceError> {
    if proof.hash_fn() != HashFunction::Poseidon2 {
        return Err(RecursiveAdviceError::UnsupportedHashFunction(proof.hash_fn()));
    }
    let pub_inputs = PublicInputs::new(
        claim.program_info().clone(),
        *claim.stack_inputs(),
        *claim.stack_outputs(),
        proof.deferred_root(),
    );

    build_from_proof_bytes(proof.stark_proof(), &pub_inputs, claim.commitment())
}

// ADVICE CONSTRUCTION
// ================================================================================================

fn build_from_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveAdviceError> {
    let params = config::pcs_params();
    let config = config::poseidon2_config(params);

    let proof = deserialize_proof(proof_bytes)?;

    let (public_values, aux_inputs) = pub_inputs.to_air_inputs();
    let mut challenger = config.challenger();
    config::observe_protocol_params(&mut challenger);

    let statement =
        Statement::<Felt, Challenge, _>::new(MidenMultiAir::new(), public_values, aux_inputs)
            .map_err(|e| RecursiveAdviceError::StatementAssembly(e.to_string()))?;
    let verifier_instance = VerifierInstance::new(&config, &statement, None)
        .expect("Miden AIRs declare no preprocessed columns");

    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof, challenger)?;

    let heights = miden_trace_heights(&stark)?;

    build_advice(&config, params, &stark, heights, pub_inputs, claim_commitment)
}

/// Deserializes a wincode-encoded Poseidon2 STARK proof, bounding preallocation by
/// [`MAX_STARK_PROOF_BYTES`].
fn deserialize_proof(proof_bytes: &[u8]) -> Result<P2ProofData, RecursiveAdviceError> {
    let encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    <serde_wincode::SerdeCompat<P2ProofData> as wincode::config::Deserialize<_>>::deserialize(
        proof_bytes,
        encoding_config,
    )
    .map_err(|e| RecursiveAdviceError::ProofDeserialization(e.to_string()))
}

fn miden_trace_heights(
    stark: &StarkProof<Challenge, P2Lmcs>,
) -> Result<MidenTraceHeights, RecursiveAdviceError> {
    let log_heights = stark.log_trace_heights();
    let Ok(log_heights): Result<[u8; MIDEN_AIR_COUNT], _> = log_heights.try_into() else {
        return Err(RecursiveAdviceError::InvalidProofShape(
            "unexpected number of AIR log heights",
        ));
    };
    Ok(MidenTraceHeights {
        instance_log_heights: log_heights.map(usize::from),
        proof_order: ProofOrder::from_instance_log_heights(&log_heights),
    })
}

/// Packs the parsed STARK transcript into the advice-stack stream, Merkle store, and advice map.
fn build_advice(
    config: &P2Config,
    params: PcsParams,
    stark: &StarkProof<Challenge, P2Lmcs>,
    heights: MidenTraceHeights,
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveAdviceError> {
    let pcs = &stark.pcs_proof;
    if stark.all_aux_values.len() != MIDEN_AIR_COUNT {
        return Err(RecursiveAdviceError::InvalidProofShape(
            "unexpected number of aux-final groups",
        ));
    }

    // The stream carries only the proof: the deferred root the execution produced, the proof
    // shape, and the STARK transcript. The claim itself (kernel witness, program digest, stack
    // i/o) is the consumer's — it fills those into VM memory from its own inputs, never from this
    // (untrusted, fetched) stream — so a substituted package fails verification against the
    // consumer's claim rather than silently redefining it.
    //
    // The section order below mirrors the consumption-order list in the module doc; both are
    // pinned against the MASM verifier by the stark e2e differential tests.

    // Security parameters: [num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits]. DEEP
    // and folding PoW bits are not publicly exposed on PcsParams; use the config constants.
    let mut advice_stack = vec![
        Felt::new_unchecked(params.num_queries() as u64),
        Felt::new_unchecked(params.query_pow_bits() as u64),
        Felt::new_unchecked(config::DEEP_POW_BITS as u64),
        Felt::new_unchecked(config::FOLDING_POW_BITS as u64),
    ];

    // Final deferred root, loaded by `public_inputs::stage_boundary_inputs`.
    advice_stack.extend_from_slice(pub_inputs.deferred_root().as_ref());

    for height in heights.instance_log_heights {
        advice_stack.push(Felt::new_unchecked(height as u64));
    }

    advice_stack.extend_from_slice(&commitment_felts(stark.main_commit));
    advice_stack.extend_from_slice(&commitment_felts(stark.aux_commit));

    for aux_values in &stark.all_aux_values {
        advice_stack.extend_from_slice(&challenge_felts(aux_values));
    }

    advice_stack.extend_from_slice(&commitment_felts(stark.quotient_commit));

    // The verifier consumes the DEEP alpha's two extension coordinates high-first.
    let deep_alpha = pcs.deep_proof.challenge_columns;
    let deep_coeffs: &[Felt] = deep_alpha.as_basis_coefficients_slice();
    advice_stack.extend_from_slice(&[deep_coeffs[1], deep_coeffs[0]]);

    append_ood_evaluations(&mut advice_stack, pcs)?;

    advice_stack.push(pcs.deep_proof.pow_witness);

    for round in &pcs.fri_proof.rounds {
        advice_stack.extend_from_slice(&commitment_felts(round.commitment));
        advice_stack.push(round.pow_witness);
    }

    let final_poly = &pcs.fri_proof.final_poly;
    advice_stack.extend_from_slice(&QuadFelt::flatten_to_base(final_poly.to_vec()));

    advice_stack.push(pcs.query_pow_witness);

    let (store, advice_map) = build_merkle_data(config, stark, &heights.proof_order)?;

    Ok(RecursiveVerifierInputs {
        advice_stack,
        store,
        advice_map,
        claim_commitment,
    })
}

// OOD EVALUATIONS
// ================================================================================================

/// Flatten OOD evaluations into the advice stack.
///
/// The DEEP transcript contains evaluations at two points (z and z*g) for each committed matrix
/// (main, aux, quotient), split into local (at z) and next (at z*g) rows, appended local-first.
fn append_ood_evaluations<L>(
    advice_stack: &mut Vec<Felt>,
    pcs: &PcsProof<Challenge, L>,
) -> Result<(), RecursiveAdviceError>
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
            // A matrix carries its local row and, for two-point openings, its next row.
            if values.len() != width && values.len() != 2 * width {
                return Err(RecursiveAdviceError::InvalidProofShape(
                    "OOD matrix must hold exactly one or two rows",
                ));
            }
            local_values.extend_from_slice(&values[..width]);
            if values.len() == 2 * width {
                next_values.extend_from_slice(&values[width..]);
            }
        }
    }

    advice_stack.extend_from_slice(&challenge_felts(&local_values));
    advice_stack.extend_from_slice(&challenge_felts(&next_values));
    Ok(())
}

// MERKLE DATA
// ================================================================================================

/// Build the Merkle store and advice map from the DEEP and FRI opening proofs.
///
/// Each opening proof becomes a `PartialMerkleTree` (for the store) and `leaf_hash -> leaf_data`
/// entries (for the advice map). The verifier fetches authentication paths with `mtree_get` and
/// leaf data with `adv.push_mapval`.
fn build_merkle_data(
    config: &P2Config,
    stark: &StarkProof<Challenge, P2Lmcs>,
    proof_order: &ProofOrder,
) -> Result<MerkleAdvice, RecursiveAdviceError> {
    let pcs = &stark.pcs_proof;
    let lmcs = config.lmcs();

    let mut partial_trees = Vec::new();
    let mut advice_map = Vec::new();

    // DEEP openings (one BatchProof per commitment: main, aux, quotient), then FRI openings
    // (one per FRI round).
    for batch_proof in pcs.deep_witnesses.iter().chain(pcs.fri_witnesses.iter()) {
        let (tree, entries) = batch_proof_to_merkle(lmcs, batch_proof)?;
        partial_trees.push(tree);
        advice_map.extend(entries);
    }

    let mut store = MerkleStore::new();
    for tree in &partial_trees {
        store.extend(tree.inner_nodes());
    }
    let registry_tree = config::ace_circuit_registry_tree();
    store.extend(registry_tree.inner_nodes());

    let circuit = build_recursive_verifier_ace_circuit(proof_order).map_err(|_| {
        RecursiveAdviceError::InvalidProofShape("failed to build recursive ACE circuit")
    })?;
    advice_map.push((circuit.commitment, circuit.instructions));

    Ok((store, advice_map))
}

/// Converts a `BatchProof` into a `PartialMerkleTree` (for the store) and its
/// `leaf_hash -> leaf_data` advice-map entries.
fn batch_proof_to_merkle<L>(
    lmcs: &L,
    batch_proof: &L::BatchProof,
) -> Result<(PartialMerkleTree, Vec<(Word, Vec<Felt>)>), RecursiveAdviceError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + PartialEq + Into<[Felt; 4]>,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
{
    let mut paths = Vec::new();
    let mut advice_entries = Vec::new();

    for index in batch_proof.indices() {
        let rows = batch_proof
            .opening(index)
            .ok_or(RecursiveAdviceError::InvalidProofShape("missing opening for query index"))?;
        let siblings = batch_proof.path(index).ok_or(RecursiveAdviceError::InvalidProofShape(
            "missing Merkle path for query index",
        ))?;

        let leaf_data: Vec<Felt> = rows.as_slice().to_vec();
        let leaf_word: Word = Word::new(lmcs.hash(rows.iter_rows()).into());
        let merkle_path =
            MerklePath::new(siblings.into_iter().map(|c| Word::new(c.into())).collect());

        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }

    let tree = PartialMerkleTree::with_paths(paths)
        .map_err(|_| RecursiveAdviceError::InvalidProofShape("invalid merkle paths"))?;

    Ok((tree, advice_entries))
}

fn commitment_felts<C: Copy + Into<[Felt; 4]>>(commitment: C) -> [Felt; 4] {
    commitment.into()
}

fn challenge_felts(challenges: &[Challenge]) -> Vec<Felt> {
    QuadFelt::flatten_to_base(challenges.to_vec())
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::{
        deferred::DeferredRoot,
        program::{KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
    };

    use super::*;

    /// The top-level entry rejects non-Poseidon2 proofs up front, before touching the proof
    /// bytes — the recursive verifier verifies only Poseidon2 STARKs.
    #[test]
    fn advice_inputs_rejects_non_poseidon2_proofs() {
        let proof = ExecutionProof::new(
            Vec::new(),
            HashFunction::Blake3_256,
            DeferredRoot::default(),
            None,
        );
        let claim = ExecutionClaim::new(
            ProgramInfo::new(Word::default(), KernelDescriptor::default()),
            StackInputs::default(),
            StackOutputs::default(),
        );

        let err = advice_inputs(&proof, &claim).expect_err("a Blake3 proof must be rejected");
        assert!(matches!(
            err,
            RecursiveAdviceError::UnsupportedHashFunction(HashFunction::Blake3_256)
        ));
    }

    /// Request packaging is a pure repackaging: the proof stream moves — unchanged and in
    /// order — into the advice map under `request_key(verifier_root, claim_commitment)`, and
    /// everything else is untouched.
    #[test]
    fn request_package_moves_proof_under_request_key() {
        let proof_stream: Vec<Felt> = (1..=8u64).map(Felt::new_unchecked).collect();
        let claim_commitment = Word::from([11u64, 12, 13, 14].map(Felt::new_unchecked));
        let verifier_root = Word::from([21u64, 22, 23, 24].map(Felt::new_unchecked));
        let query_entry = (
            Word::from([31u64, 32, 33, 34].map(Felt::new_unchecked)),
            vec![Felt::new_unchecked(7)],
        );

        let inputs = RecursiveVerifierInputs {
            advice_stack: proof_stream.clone(),
            store: MerkleStore::new(),
            advice_map: vec![query_entry.clone()],
            claim_commitment,
        };

        let package = inputs.into_request_package(verifier_root);

        assert!(package.advice_stack.is_empty(), "the proof must leave the advice stack");
        assert_eq!(package.claim_commitment, claim_commitment);
        assert_eq!(package.advice_map.len(), 2, "existing entries stay, proof entry added");
        assert_eq!(package.advice_map[0], query_entry);
        assert_eq!(
            package.advice_map[1],
            (request_key(verifier_root, claim_commitment), proof_stream)
        );
    }
}
