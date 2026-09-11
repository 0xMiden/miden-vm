//! Advice construction for the in-VM PVM STARK verifier.
//!
//! This module parses a Poseidon2 PVM proof into the exact stack, Merkle-store, and advice-map
//! inputs consumed by `miden::core::sys::pvm::verify_proof`. The caller supplies the deferred claim
//! on the operand stack; its root is the PVM statement.

use alloc::{
    string::{String, ToString},
    vec,
    vec::Vec,
};

use miden_core::{
    Felt, Word,
    advice::{AdviceInputs, AdviceStack},
    crypto::merkle::MerkleStore,
    deferred::DeferredClaim,
    field::{BasedVectorSpace, QuadFelt},
    program::proof_request_key,
    proof::{
        HashFunction, MAX_STARK_PROOF_BYTES, PrecompileProof, StarkProof as SerializedStarkProof,
    },
};
use miden_crypto::{
    merkle::{MerklePath, PartialMerkleTree},
    stark::{
        StarkConfig,
        lmcs::{Lmcs, proof::BatchProofView},
        pcs::PcsProof,
        proof::{StarkProof, StarkProofData},
    },
};
use miden_lifted_air::Statement;
use miden_lifted_stark::VerifierInstance;
use miden_precompiles_air::{
    ChipletAir, ChipletMultiAir, NUM_CHIPLETS, preprocessed,
    stark_config::{
        Poseidon2Config, observe_protocol_params, poseidon2_config, precompile_pcs_params,
    },
};
use miden_serde_utils::deserialize_schema_exact;
use serde_wincode::SerdeCompat;

use crate::{
    ace::{order_tag_from_log_heights, proof_order_from_log_heights},
    ace_registry::{factory, pvm_ace_registry_path},
};

type Challenge = QuadFelt;
type P2Lmcs = <Poseidon2Config as StarkConfig<Felt, Challenge>>::Lmcs;

/// Request-packaged inputs for MASM recursive verification of a PVM proof.
///
/// Pass [`Self::claim_commitment`] on the operand stack. The consumer derives the request key,
/// fetches the proof stream from the advice map, and then invokes `exec.pvm::verify_proof`.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct PvmRecursiveVerifierInputs {
    advice: AdviceInputs,
    claim_commitment: Word,
}

impl PvmRecursiveVerifierInputs {
    /// Builds a proof package addressed by the verifier and claim commitments.
    ///
    /// The proof must contain exactly one deferred root. Aggregated precompile proofs require a
    /// separate authentication of their ordered constituent roots, which the MASM verifier does
    /// not yet implement. The underlying STARK must use Poseidon2.
    ///
    /// # Errors
    ///
    /// Returns an error if the proof cannot be converted into verifier advice.
    pub fn for_request(
        verifier_root: Word,
        proof: &PrecompileProof,
    ) -> Result<Self, PvmRecursiveVerifierInputsError> {
        let [root] = proof.roots.as_slice() else {
            return Err(PvmRecursiveVerifierInputsError::UnsupportedRootCount {
                roots: proof.roots.len(),
            });
        };
        let claim = DeferredClaim::new(*root);
        let advice = build_verifier_advice(&proof.proof, claim)?;
        Ok(Self::package(verifier_root, claim, advice))
    }

    /// Returns the packaged verifier advice.
    pub fn advice(&self) -> &AdviceInputs {
        &self.advice
    }

    /// Returns the claim commitment supplied to the verifier.
    pub fn claim_commitment(&self) -> Word {
        self.claim_commitment
    }

    /// Consumes these inputs into their packaged advice and claim commitment.
    pub fn into_parts(self) -> (AdviceInputs, Word) {
        (self.advice, self.claim_commitment)
    }

    fn package(verifier_root: Word, claim: DeferredClaim, advice: AdviceInputs) -> Self {
        let claim_commitment = claim.commitment();
        let (proof_stream, mut map, store) = advice.into_parts();
        map.insert(
            proof_request_key(verifier_root, claim_commitment),
            proof_stream.into_elements(),
        );
        let advice = AdviceInputs::new(AdviceStack::default(), map, store);
        Self { advice, claim_commitment }
    }
}

/// Failures while parsing and adapting a PVM proof for the MASM verifier.
#[derive(Debug, thiserror::Error)]
pub enum PvmRecursiveVerifierInputsError {
    /// The current MASM verifier authenticates one deferred root at a time.
    #[error("the PVM MASM verifier requires exactly one deferred root, found {roots}")]
    UnsupportedRootCount { roots: usize },
    /// The MASM verifier implements the Poseidon2 transcript only.
    #[error("the PVM MASM verifier supports Poseidon2 proofs only")]
    UnsupportedHashFunction,
    /// The serialized proof exceeds the adapter's allocation limit.
    #[error("STARK proof is too large: {size} bytes exceeds the {max} byte limit")]
    ProofTooLarge { size: usize, max: usize },
    /// The serialized proof could not be decoded.
    #[error("proof deserialization error: {0}")]
    ProofDeserialization(String),
    /// The proof transcript could not be parsed against the PVM statement and setup.
    #[error(transparent)]
    Transcript(#[from] miden_lifted_stark::VerifierError),
    /// The trusted setup commitment did not match the PVM AIR declaration.
    #[error(transparent)]
    Preprocessed(#[from] miden_lifted_stark::PreprocessedValidationError),
    /// The parsed proof does not have the fixed ten-chiplet shape expected by the wrapper.
    #[error("invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
}

type MerkleAdvice = (MerkleStore, Vec<(Word, Vec<Felt>)>);
type BatchMerkleResult = (PartialMerkleTree, Vec<(Word, Vec<Felt>)>);

fn build_verifier_advice(
    proof: &SerializedStarkProof,
    claim: DeferredClaim,
) -> Result<AdviceInputs, PvmRecursiveVerifierInputsError> {
    if proof.hash_fn() != HashFunction::Poseidon2 {
        return Err(PvmRecursiveVerifierInputsError::UnsupportedHashFunction);
    }
    if proof.bytes().len() > MAX_STARK_PROOF_BYTES {
        return Err(PvmRecursiveVerifierInputsError::ProofTooLarge {
            size: proof.bytes().len(),
            max: MAX_STARK_PROOF_BYTES,
        });
    }

    let config = poseidon2_config(
        precompile_pcs_params(),
        crate::ace_registry::PVM_RELATION_DIGEST.map(Felt::new_unchecked),
    );
    let preprocessed = preprocessed::poseidon2();
    let proof_encoding_config = wincode::config::Configuration::default()
        .with_preallocation_size_limit::<MAX_STARK_PROOF_BYTES>();
    let proof_data: StarkProofData<Felt, Challenge, Poseidon2Config> = deserialize_schema_exact::<
        SerdeCompat<StarkProofData<Felt, Challenge, Poseidon2Config>>,
        _,
    >(
        proof.bytes(),
        proof_encoding_config,
    )
    .map_err(|err| PvmRecursiveVerifierInputsError::ProofDeserialization(err.to_string()))?;

    let public_root = claim.root();
    let statement =
        Statement::new(ChipletMultiAir::new(), public_root.as_elements().to_vec(), Vec::new())
            .map_err(|_| {
                PvmRecursiveVerifierInputsError::InvalidProofShape("invalid PVM statement")
            })?;
    let verifier_instance =
        VerifierInstance::new(&config, &statement, Some(preprocessed.commitment()))?;
    let mut challenger = config.challenger();
    observe_protocol_params(config.pcs(), &mut challenger);
    let (stark, _digest) = StarkProof::from_data(&verifier_instance, &proof_data, challenger)?;

    build_advice(&config, &stark)
}

fn build_advice(
    config: &Poseidon2Config,
    stark: &StarkProof<Challenge, P2Lmcs>,
) -> Result<AdviceInputs, PvmRecursiveVerifierInputsError> {
    let log_heights: [u8; NUM_CHIPLETS] = stark.log_trace_heights().try_into().map_err(|_| {
        PvmRecursiveVerifierInputsError::InvalidProofShape("unexpected AIR-height count")
    })?;
    // Fixed-height instances must arrive at exactly their pinned height: the MASM verifier
    // opens the setup tree at the matching fixed depth, so any other value would let the
    // recursive and native verifiers disagree on proof shape.
    for (air, &log_height) in ChipletAir::all().iter().zip(&log_heights) {
        if air.fixed_log_height().is_some_and(|fixed| u32::from(log_height) != fixed) {
            return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
                "fixed-height AIR arrived at a different trace height",
            ));
        }
    }
    if stark.all_aux_values.len() != NUM_CHIPLETS {
        return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
            "unexpected number of aux-final groups",
        ));
    }
    if stark.all_aux_values.iter().any(|values| values.len() != 1) {
        return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
            "unexpected aux-final group width",
        ));
    }

    // The registry and MASM wrapper implement the same stable (height, instance-index) order as
    // lifted-stark. Make that coupling executable so a future proof-order convention change fails
    // here rather than selecting a circuit for a different ordering.
    let proof_order = proof_order_from_log_heights(&log_heights);
    if stark
        .air_order()
        .iter()
        .map(|&index| usize::from(index))
        .ne(proof_order.iter().copied())
    {
        return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
            "proof ordering does not match the PVM registry convention",
        ));
    }

    let params = config.pcs();
    let mut advice_stack = vec![
        Felt::new_unchecked(params.num_queries() as u64),
        Felt::new_unchecked(params.query_pow_bits() as u64),
        Felt::new_unchecked(params.deep_pow_bits() as u64),
        Felt::new_unchecked(params.folding_pow_bits() as u64),
    ];

    advice_stack.extend(log_heights.iter().copied().map(Felt::from_u8));
    advice_stack.extend(commitment_felts(stark.main_commit));
    advice_stack.extend(commitment_felts(stark.aux_commit));
    for aux_values in &stark.all_aux_values {
        advice_stack.extend(challenge_felts(aux_values));
    }
    advice_stack.extend(commitment_felts(stark.quotient_commit));

    let pcs = &stark.pcs_proof;
    let deep_alpha = pcs.deep_proof.challenge_columns;
    let deep_coeffs: &[Felt] = deep_alpha.as_basis_coefficients_slice();
    advice_stack.extend([deep_coeffs[1], deep_coeffs[0]]);
    append_ood_evaluations(&mut advice_stack, pcs)?;
    advice_stack.push(pcs.deep_proof.pow_witness);

    for round in &pcs.fri_proof.rounds {
        advice_stack.extend(commitment_felts(round.commitment));
        advice_stack.push(round.pow_witness);
    }
    let final_poly: Vec<Felt> = QuadFelt::flatten_to_base(pcs.fri_proof.final_poly.to_vec());
    advice_stack.extend(final_poly);
    advice_stack.push(pcs.query_pow_witness);

    let (store, advice_map) = build_merkle_data(config, stark, &log_heights, &proof_order)?;
    Ok(AdviceInputs::default()
        .with_stack(advice_stack.into())
        .with_map(advice_map)
        .with_merkle_store(store))
}

fn append_ood_evaluations<L>(
    advice_stack: &mut Vec<Felt>,
    pcs: &PcsProof<Challenge, L>,
) -> Result<(), PvmRecursiveVerifierInputsError>
where
    L: Lmcs<F = Felt>,
{
    let mut local_values = Vec::new();
    let mut next_values = Vec::new();
    for group in &pcs.deep_proof.evals {
        for matrix in group {
            let width = matrix.width;
            let values = matrix.values.as_slice();
            if values.len() != width && values.len() != 2 * width {
                return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
                    "OOD matrix must hold exactly one or two rows",
                ));
            }
            local_values.extend_from_slice(&values[..width]);
            if values.len() == 2 * width {
                next_values.extend_from_slice(&values[width..]);
            }
        }
    }
    advice_stack.extend(challenge_felts(&local_values));
    advice_stack.extend(challenge_felts(&next_values));
    Ok(())
}

fn build_merkle_data(
    config: &Poseidon2Config,
    stark: &StarkProof<Challenge, P2Lmcs>,
    log_heights: &[u8; NUM_CHIPLETS],
    proof_order: &[usize; NUM_CHIPLETS],
) -> Result<MerkleAdvice, PvmRecursiveVerifierInputsError> {
    let lmcs = config.lmcs();
    let mut store = MerkleStore::new();
    let mut advice_map = Vec::new();

    // The first DEEP witness is the setup-fixed preprocessed tree. The remaining witnesses are
    // main, auxiliary, and quotient. FRI witnesses follow them in proof order.
    for batch_proof in stark.pcs_proof.deep_witnesses.iter().chain(&stark.pcs_proof.fri_witnesses) {
        let (tree, entries) = batch_proof_to_merkle(lmcs, batch_proof)?;
        store.extend(tree.inner_nodes());
        advice_map.extend(entries);
    }

    let order_tag = order_tag_from_log_heights(log_heights);
    let (leaf, path) = pvm_ace_registry_path(order_tag).ok_or(
        PvmRecursiveVerifierInputsError::InvalidProofShape(
            "ACE registry has no slot for this order tag",
        ),
    )?;
    store.add_merkle_path(u64::from(order_tag), leaf, path).map_err(|_| {
        PvmRecursiveVerifierInputsError::InvalidProofShape("ACE registry path could not be stored")
    })?;

    let circuit = factory().circuit_for_order(proof_order).map_err(|_| {
        PvmRecursiveVerifierInputsError::InvalidProofShape(
            "failed to build the selected ACE circuit",
        )
    })?;
    if circuit.commitment != leaf {
        return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
            "selected ACE circuit does not match the registry leaf",
        ));
    }
    advice_map.push((leaf, circuit.encoded.instructions().to_vec()));

    Ok((store, advice_map))
}

fn batch_proof_to_merkle<L>(
    lmcs: &L,
    batch_proof: &L::BatchProof,
) -> Result<BatchMerkleResult, PvmRecursiveVerifierInputsError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + Into<[Felt; 4]> + PartialEq,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
{
    let mut paths = Vec::new();
    let mut advice_entries = Vec::new();
    for index in batch_proof.indices() {
        let rows = batch_proof.opening(index).ok_or(
            PvmRecursiveVerifierInputsError::InvalidProofShape("missing opening for query index"),
        )?;
        let siblings =
            batch_proof
                .path(index)
                .ok_or(PvmRecursiveVerifierInputsError::InvalidProofShape(
                    "missing Merkle path for query index",
                ))?;
        let salt =
            batch_proof
                .salt(index)
                .ok_or(PvmRecursiveVerifierInputsError::InvalidProofShape(
                    "missing LMCS salt for query index",
                ))?;
        if !salt.is_empty() {
            return Err(PvmRecursiveVerifierInputsError::InvalidProofShape(
                "hiding LMCS openings are unsupported by the MASM adapter",
            ));
        }
        let leaf_data = rows.as_slice().to_vec();
        let leaf_hash = lmcs.hash(rows.iter_rows());
        let leaf_word = Word::new(leaf_hash.into());
        let merkle_path =
            MerklePath::new(siblings.into_iter().map(|commit| Word::new(commit.into())).collect());
        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }
    let tree = PartialMerkleTree::with_paths(paths)
        .map_err(|_| PvmRecursiveVerifierInputsError::InvalidProofShape("invalid Merkle paths"))?;
    Ok((tree, advice_entries))
}

fn commitment_felts<C: Copy + Into<[Felt; 4]>>(commitment: C) -> [Felt; 4] {
    commitment.into()
}

fn challenge_felts(challenges: &[Challenge]) -> Vec<Felt> {
    QuadFelt::flatten_to_base(challenges.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recursive_inputs_reject_non_poseidon2_proofs_before_parsing() {
        let proof = PrecompileProof {
            proof: SerializedStarkProof::new(Vec::new(), HashFunction::Rpo256),
            roots: vec![Word::default()],
        };
        assert!(matches!(
            PvmRecursiveVerifierInputs::for_request(Word::default(), &proof),
            Err(PvmRecursiveVerifierInputsError::UnsupportedHashFunction),
        ));
    }

    #[test]
    fn recursive_inputs_reject_oversized_proofs_before_parsing() {
        let size = MAX_STARK_PROOF_BYTES + 1;
        let proof = PrecompileProof {
            proof: SerializedStarkProof::new(vec![0; size], HashFunction::Poseidon2),
            roots: vec![Word::default()],
        };
        assert!(matches!(
            PvmRecursiveVerifierInputs::for_request(Word::default(), &proof),
            Err(PvmRecursiveVerifierInputsError::ProofTooLarge {
                size: actual,
                max: MAX_STARK_PROOF_BYTES,
            }) if actual == size,
        ));
    }

    #[test]
    fn recursive_inputs_reject_non_singleton_precompile_proofs() {
        let serialized = || SerializedStarkProof::new(Vec::new(), HashFunction::Poseidon2);
        for roots in [Vec::new(), vec![Word::default(); 2]] {
            let root_count = roots.len();
            let proof = PrecompileProof { proof: serialized(), roots };
            assert!(matches!(
                PvmRecursiveVerifierInputs::for_request(Word::default(), &proof),
                Err(PvmRecursiveVerifierInputsError::UnsupportedRootCount { roots })
                    if roots == root_count,
            ));
        }
    }

    #[test]
    fn request_package_moves_the_proof_under_the_request_key() {
        let proof_stream: Vec<_> = [1, 2, 3, 4].map(Felt::new_unchecked).into();
        let deferred_root = Word::from([11u64, 12, 13, 14].map(Felt::new_unchecked));
        let claim = DeferredClaim::new(deferred_root);
        let verifier_root = Word::from([21u64, 22, 23, 24].map(Felt::new_unchecked));
        let existing = (
            Word::from([31u64, 32, 33, 34].map(Felt::new_unchecked)),
            vec![Felt::new_unchecked(7)],
        );
        let advice = AdviceInputs::default()
            .with_stack(proof_stream.clone().into())
            .with_map([existing.clone()]);
        let package = PvmRecursiveVerifierInputs::package(verifier_root, claim, advice);

        assert!(package.advice().stack().is_empty());
        assert_eq!(
            package.advice().map().get(&existing.0).map(AsRef::as_ref),
            Some(existing.1.as_slice())
        );
        assert_eq!(
            package
                .advice()
                .map()
                .get(&proof_request_key(verifier_root, claim.commitment()))
                .map(AsRef::as_ref),
            Some(proof_stream.as_slice()),
        );
        assert_eq!(package.claim_commitment(), claim.commitment());
    }
}
