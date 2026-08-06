//! Building the advice a MASM recursive verifier consumes to verify a Miden VM proof.
//!
//! `exec.vm::verify_vm_proof` reads a STARK proof from the advice provider in a fixed
//! order. This module is the producer side of that ABI: it destructures an [`ExecutionProof`]
//! against its [`ExecutionClaim`] into the advice-stack stream, Merkle store, and advice-map
//! entries the verifier consumes. The consumption order is exercised end to end by the
//! recursive verification tests, which drive the real MASM verifier over this output.
//!
//! Before calling `verify_vm_proof`, the consumer places this proof stream on top of the advice
//! stack:
//!
//!   security params (nq, query_pow, deep_pow, folding_pow) ->
//!   deferred root -> Miden AIR heights -> main commit -> aux commit ->
//!   aux finals -> quotient commit -> deep alpha -> OOD evals ->
//!   DEEP PoW witness -> FRI rounds -> FRI remainder -> query PoW witness
//!
//! [`RecursiveVerifierInputs::for_request`] stores this stream in the advice map under the verifier
//! and claim commitments. The consumer fetches it before calling `verify_vm_proof`. The consumer
//! also supplies the claim commitment; the advice map stores its 40-felt preimage under that
//! commitment, and `verify_vm_proof` authenticates the preimage before using it. The advice map
//! stores the flattened kernel procedure digests under the kernel commitment as well. Query rows,
//! the Merkle store, and the ACE circuit are content-addressed too.

use alloc::{
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use miden_air::{
    MIDEN_AIR_COUNT, MidenMultiAir, ProofOrder, PublicInputs, Statement,
    ace::build_recursive_verifier_ace_circuit, config,
};
use miden_core::{
    Felt, Word,
    advice::AdviceInputs,
    crypto::merkle::{MerklePath, MerkleStore, PartialMerkleTree},
    deferred::{DEFAULT_MAX_DEFERRED_ELEMENTS, DeferredState, IntegrityError, TRUE_DIGEST},
    field::QuadFelt,
    program::{ExecutionClaim, proof_request_key},
    proof::{DeferredProof, ExecutionProof, HashFunction},
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
use miden_serde_utils::deserialize_schema_exact;
use serde_wincode::{SerdeCompat, wincode};

use crate::MAX_STARK_PROOF_BYTES;

// TYPES
// ================================================================================================

type Challenge = QuadFelt;
type P2Config = config::Poseidon2Config;
type P2Lmcs = <P2Config as StarkConfig<Felt, Challenge>>::Lmcs;
type P2ProofData = StarkProofData<Felt, Challenge, P2Config>;

/// Request-packaged inputs for MASM recursive verification.
///
/// Pass [`Self::claim_commitment`] on the operand stack. The consumer derives the request key,
/// fetches the proof stream from the advice map, and then invokes `exec.vm::verify_vm_proof`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RecursiveVerifierInputs {
    advice: AdviceInputs,
    claim_commitment: Word,
}

impl RecursiveVerifierInputs {
    /// Builds a proof package addressed by the verifier and claim commitments.
    ///
    /// The proof must be a Poseidon2 proof because the recursive verifier supports only
    /// Poseidon2 STARKs. Wire-backed deferred state is hydrated with the standard precompile
    /// registry and [`DEFAULT_MAX_DEFERRED_ELEMENTS`].
    ///
    /// # Errors
    ///
    /// Returns an error if the proof cannot be converted into verifier advice.
    pub fn for_request(
        verifier_root: Word,
        proof: &ExecutionProof,
        claim: &ExecutionClaim,
    ) -> Result<Self, RecursiveVerifierInputsError> {
        Ok(build_verifier_inputs(proof, claim)?.into_request_package(verifier_root))
    }

    /// Returns the VM advice inputs.
    pub fn advice(&self) -> &AdviceInputs {
        &self.advice
    }

    /// Returns the execution claim commitment.
    pub fn claim_commitment(&self) -> Word {
        self.claim_commitment
    }

    /// Consumes these inputs into their VM advice and claim commitment.
    pub fn into_parts(self) -> (AdviceInputs, Word) {
        (self.advice, self.claim_commitment)
    }

    /// Moves the proof stream into the advice map under
    /// `proof_request_key(verifier_root, claim_commitment)`, leaving the advice stack empty.
    fn into_request_package(mut self, verifier_root: Word) -> Self {
        let key = proof_request_key(verifier_root, self.claim_commitment);
        let (proof_stream, map, store) = self.advice.into_parts();
        self.advice = AdviceInputs::default().with_merkle_store(store);
        self.advice.map = map;
        self.advice.map.insert(key, proof_stream.into_elements());
        self
    }
}

/// Builds the raw advice consumed by `verify_vm_proof` before request packaging.
fn build_verifier_inputs(
    proof: &ExecutionProof,
    claim: &ExecutionClaim,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    let stark = proof.miden_proof();
    if stark.hash_fn() != HashFunction::Poseidon2 {
        return Err(RecursiveVerifierInputsError::UnsupportedHashFunction(stark.hash_fn()));
    }
    let pub_inputs = PublicInputs::new(
        claim.to_program_info(),
        *claim.stack_inputs(),
        *claim.stack_outputs(),
        resolve_deferred_root(proof.deferred_proof())?,
    );

    let claim_commitment = claim.commitment();
    let mut inputs = build_from_proof_bytes(stark.bytes(), &pub_inputs, claim_commitment)?;

    // The MASM verifier authenticates this preimage against the caller-provided commitment.
    inputs.advice.map.insert(claim_commitment, claim.to_elements().to_vec());

    let kernel = claim.kernel();
    // The MASM verifier derives the procedure count from the value length.
    let kernel_witness = Word::words_as_elements(kernel.proc_hashes()).to_vec();
    inputs.advice.map.insert(kernel.commitment(), kernel_witness);

    Ok(inputs)
}

/// Errors returned while building the advice for recursive verification.
#[derive(Debug, thiserror::Error)]
pub enum RecursiveVerifierInputsError {
    #[error("proof deserialization error: {0}")]
    ProofDeserialization(String),
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
    #[error("statement assembly error: {0}")]
    StatementAssembly(String),
    #[error("deferred wire hydration failed: {0}")]
    DeferredIntegrity(#[from] IntegrityError),
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

/// Resolves the deferred root the outer VM statement binds, from the proof's deferred material:
/// the canonical TRUE digest when no precompile claims were produced, the nested proof's public
/// root when STARK-backed, and the hydrated wire's root for partial proofs (standard precompile
/// registry, default deferred-element budget).
fn resolve_deferred_root(deferred: &DeferredProof) -> Result<Word, RecursiveVerifierInputsError> {
    match deferred {
        DeferredProof::Empty => Ok(TRUE_DIGEST),
        DeferredProof::Stark { public_root, .. } => Ok(*public_root),
        DeferredProof::Wire(wire) => Ok(DeferredState::from_wire(
            Arc::new(miden_precompiles::registry()),
            wire,
            DEFAULT_MAX_DEFERRED_ELEMENTS,
        )?
        .root()),
    }
}

// ADVICE CONSTRUCTION
// ================================================================================================

fn build_from_proof_bytes(
    proof_bytes: &[u8],
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    let config = config::poseidon2_config(config::pcs_params(), config::RELATION_DIGEST);

    let proof = deserialize_proof(proof_bytes)?;

    let (public_values, aux_inputs) = pub_inputs.to_air_inputs();
    let mut challenger = config.challenger();
    config::observe_protocol_params(config.pcs(), &mut challenger);

    let statement =
        Statement::<Felt, Challenge, _>::new(MidenMultiAir::new(), public_values, aux_inputs)
            .map_err(|e| RecursiveVerifierInputsError::StatementAssembly(e.to_string()))?;
    let verifier_instance = VerifierInstance::new(&config, &statement, None)
        .expect("Miden AIRs declare no preprocessed columns");

    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof, challenger)?;

    let heights = miden_trace_heights(&stark)?;

    build_advice(&config, &stark, heights, pub_inputs, claim_commitment)
}

/// Deserializes a wincode-encoded Poseidon2 STARK proof, enforcing the total byte limit,
/// bounding preallocation, and rejecting trailing bytes.
fn deserialize_proof(proof_bytes: &[u8]) -> Result<P2ProofData, RecursiveVerifierInputsError> {
    if proof_bytes.len() > MAX_STARK_PROOF_BYTES {
        return Err(RecursiveVerifierInputsError::ProofTooLarge {
            size: proof_bytes.len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    deserialize_schema_exact::<SerdeCompat<P2ProofData>, _>(proof_bytes, encoding_config)
        .map_err(|e| RecursiveVerifierInputsError::ProofDeserialization(e.to_string()))
}

fn miden_trace_heights(
    stark: &StarkProof<Challenge, P2Lmcs>,
) -> Result<MidenTraceHeights, RecursiveVerifierInputsError> {
    let log_heights = stark.log_trace_heights();
    let Ok(log_heights): Result<[u8; MIDEN_AIR_COUNT], _> = log_heights.try_into() else {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
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
    stark: &StarkProof<Challenge, P2Lmcs>,
    heights: MidenTraceHeights,
    pub_inputs: &PublicInputs,
    claim_commitment: Word,
) -> Result<RecursiveVerifierInputs, RecursiveVerifierInputsError> {
    let pcs = &stark.pcs_proof;
    if stark.all_aux_values.len() != MIDEN_AIR_COUNT {
        return Err(RecursiveVerifierInputsError::InvalidProofShape(
            "unexpected number of aux-final groups",
        ));
    }

    // This stream contains the verifier inputs derived from the proof. The claim preimage and
    // kernel witness live in the advice map and are authenticated by the verifier against
    // commitments supplied by the consumer.
    //
    // The section order below mirrors the consumption-order list in the module doc; both are
    // pinned against the MASM verifier by the stark e2e differential tests.

    let mut advice_stack = security_parameter_words(config.pcs()).to_vec();

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

    let advice = AdviceInputs::default()
        .with_advice_stack(advice_stack.into())
        .with_map(advice_map)
        .with_merkle_store(store);

    Ok(RecursiveVerifierInputs { advice, claim_commitment })
}

/// Returns the proof-package header in the order consumed by the recursive MASM verifier.
fn security_parameter_words(params: &PcsParams) -> [Felt; 4] {
    [
        Felt::new_unchecked(params.num_queries() as u64),
        Felt::new_unchecked(params.query_pow_bits() as u64),
        Felt::new_unchecked(params.deep_pow_bits() as u64),
        Felt::new_unchecked(params.folding_pow_bits() as u64),
    ]
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
) -> Result<(), RecursiveVerifierInputsError>
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
                return Err(RecursiveVerifierInputsError::InvalidProofShape(
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
) -> Result<MerkleAdvice, RecursiveVerifierInputsError> {
    let pcs = &stark.pcs_proof;
    let lmcs = config.lmcs();

    let mut store = MerkleStore::new();
    let mut advice_map = Vec::new();

    // DEEP openings (one BatchProof per commitment: main, aux, quotient), then FRI openings
    // (one per FRI round).
    for batch_proof in pcs.deep_witnesses.iter().chain(pcs.fri_witnesses.iter()) {
        let (tree, entries) = batch_proof_to_merkle(lmcs, batch_proof)?;
        store.extend(tree.inner_nodes());
        advice_map.extend(entries);
    }

    let registry_tree = config::ace_circuit_registry_tree();
    store.extend(registry_tree.inner_nodes());

    let circuit = build_recursive_verifier_ace_circuit(proof_order).map_err(|_| {
        RecursiveVerifierInputsError::InvalidProofShape("failed to build recursive ACE circuit")
    })?;
    advice_map.push((circuit.commitment, circuit.instructions));

    Ok((store, advice_map))
}

/// Converts a `BatchProof` into a `PartialMerkleTree` (for the store) and its
/// `leaf_hash -> leaf_data` advice-map entries.
fn batch_proof_to_merkle<L>(
    lmcs: &L,
    batch_proof: &L::BatchProof,
) -> Result<(PartialMerkleTree, Vec<(Word, Vec<Felt>)>), RecursiveVerifierInputsError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + PartialEq + Into<[Felt; 4]>,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
{
    let mut paths = Vec::new();
    let mut advice_entries = Vec::new();

    for index in batch_proof.indices() {
        let rows =
            batch_proof
                .opening(index)
                .ok_or(RecursiveVerifierInputsError::InvalidProofShape(
                    "missing opening for query index",
                ))?;
        let siblings = batch_proof.path(index).ok_or(
            RecursiveVerifierInputsError::InvalidProofShape("missing Merkle path for query index"),
        )?;

        let leaf_data: Vec<Felt> = rows.as_slice().to_vec();
        let leaf_word: Word = Word::new(lmcs.hash(rows.iter_rows()).into());
        let merkle_path =
            MerklePath::new(siblings.into_iter().map(|c| Word::new(c.into())).collect());

        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }

    let tree = PartialMerkleTree::with_paths(paths)
        .map_err(|_| RecursiveVerifierInputsError::InvalidProofShape("invalid merkle paths"))?;

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
    use alloc::vec;

    use miden_core::{
        crypto::merkle::InnerNodeInfo,
        program::{KernelDescriptor, ProgramInfo, StackInputs, StackOutputs},
    };

    use super::*;

    /// The top-level entry rejects non-Poseidon2 proofs up front, before touching the proof
    /// bytes — the recursive verifier verifies only Poseidon2 STARKs.
    #[test]
    fn recursive_verifier_inputs_reject_non_poseidon2_proofs() {
        let proof = ExecutionProof::from_parts(
            Vec::new(),
            HashFunction::Blake3_256,
            DeferredProof::empty(),
        );
        let claim = ExecutionClaim::from_program_info(
            ProgramInfo::new(Word::default(), KernelDescriptor::default()),
            StackInputs::default(),
            StackOutputs::default(),
        );

        let err = RecursiveVerifierInputs::for_request(Word::default(), &proof, &claim)
            .expect_err("a Blake3 proof must be rejected");
        assert!(matches!(
            err,
            RecursiveVerifierInputsError::UnsupportedHashFunction(HashFunction::Blake3_256)
        ));
    }

    /// The proof-package header must describe the supplied PCS parameters rather than the Miden
    /// VM's current defaults; otherwise its transcript and MASM security checks can disagree.
    #[test]
    fn security_parameter_header_uses_the_supplied_pcs_params() {
        let params = PcsParams::new(4, 3, 6, 5, 11, 19, 13).expect("valid distinct PCS params");

        assert_eq!(security_parameter_words(&params), [19, 13, 11, 5].map(Felt::new_unchecked),);
    }

    #[test]
    fn proof_deserialization_rejects_oversized_input() {
        let proof_bytes = vec![0; MAX_STARK_PROOF_BYTES + 1];

        let err = deserialize_proof(&proof_bytes).expect_err("oversized proof must be rejected");
        assert!(matches!(
            err,
            RecursiveVerifierInputsError::ProofTooLarge {
                size,
                max: MAX_STARK_PROOF_BYTES,
            } if size == proof_bytes.len()
        ));
    }

    /// Request packaging is a pure repackaging: the proof stream moves — unchanged and in
    /// order — into the advice map under `proof_request_key(verifier_root, claim_commitment)`, and
    /// everything else is untouched.
    #[test]
    fn request_package_uses_proof_request_key() {
        let proof_stream: Vec<Felt> = (1..=8u64).map(Felt::new_unchecked).collect();
        let claim_commitment = Word::from([11u64, 12, 13, 14].map(Felt::new_unchecked));
        let verifier_root = Word::from([21u64, 22, 23, 24].map(Felt::new_unchecked));
        let query_entry = (
            Word::from([31u64, 32, 33, 34].map(Felt::new_unchecked)),
            vec![Felt::new_unchecked(7)],
        );
        let merkle_node = InnerNodeInfo {
            value: Word::from([41u64, 42, 43, 44].map(Felt::new_unchecked)),
            left: Word::from([51u64, 52, 53, 54].map(Felt::new_unchecked)),
            right: Word::from([61u64, 62, 63, 64].map(Felt::new_unchecked)),
        };
        let store: MerkleStore = [merkle_node].into_iter().collect();

        let advice = AdviceInputs::default()
            .with_advice_stack(proof_stream.clone().into())
            .with_map([query_entry.clone()])
            .with_merkle_store(store.clone());
        let inputs = RecursiveVerifierInputs { advice, claim_commitment };

        let package = inputs.into_request_package(verifier_root);

        assert!(
            package.advice().advice_stack().is_empty(),
            "the proof must leave the advice stack"
        );
        assert_eq!(package.claim_commitment(), claim_commitment);
        assert_eq!(&package.advice().store, &store);
        assert_eq!(package.advice().map.len(), 2, "existing entries stay, proof entry added");
        assert_eq!(package.advice().map.get(&query_entry.0).unwrap().as_ref(), query_entry.1);
        assert_eq!(
            package
                .advice()
                .map
                .get(&proof_request_key(verifier_root, claim_commitment))
                .unwrap()
                .as_ref(),
            proof_stream
        );
    }
}
