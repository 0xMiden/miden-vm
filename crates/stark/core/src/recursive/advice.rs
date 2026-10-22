//! Common STARK transcript and opening data consumed by MASM recursive verifiers.
//!
//! Relation adapters validate their proof shapes and supply their statement-specific headers and
//! ACE circuits. These helpers encode the common proof payload without selecting a relation or
//! changing the order of its AIRs.

use alloc::vec::Vec;

use miden_core::{
    Felt, Word,
    advice::{AdviceInputs, AdviceStack},
    crypto::merkle::{MerklePath, MerkleStore, PartialMerkleTree},
    field::QuadFelt,
    program::proof_request_key,
};
use miden_crypto::field::BasedVectorSpace;

use crate::{
    lmcs::{Lmcs, proof::BatchProofView},
    pcs::{OpenedValues, PcsParams},
    proof::StarkProof,
};

/// A malformed proof component encountered while encoding recursive verifier advice.
#[derive(Debug, Clone, Copy, Eq, PartialEq, thiserror::Error)]
#[error("{}", self.message())]
pub enum AdviceError {
    InvalidOodMatrix,
    MissingOpening,
    MissingMerklePath,
    MissingSalt,
    HidingSalt,
    MissingLeafHash,
    InvalidMerklePaths,
}

impl AdviceError {
    /// Returns the malformed component's description for relation-specific error adapters.
    pub fn message(self) -> &'static str {
        match self {
            Self::InvalidOodMatrix => "OOD matrix must hold exactly one or two rows",
            Self::MissingOpening => "missing opening for query index",
            Self::MissingMerklePath => "missing Merkle path for query index",
            Self::MissingSalt => "missing LMCS salt for query index",
            Self::HidingSalt => "hiding LMCS openings are unsupported by the MASM adapter",
            Self::MissingLeafHash => "missing leaf hash for query index",
            Self::InvalidMerklePaths => "invalid merkle paths",
        }
    }
}

/// Merkle store and content-addressed leaf data, without a relation's ACE circuit.
pub type MerkleAdvice = (MerkleStore, Vec<(Word, Vec<Felt>)>);

/// Returns the security header in MASM consumption order.
pub fn security_parameter_words(params: &PcsParams) -> [Felt; 4] {
    [
        Felt::new_unchecked(params.num_queries() as u64),
        Felt::new_unchecked(params.query_pow_bits() as u64),
        Felt::new_unchecked(params.deep_pow_bits() as u64),
        Felt::new_unchecked(params.folding_pow_bits() as u64),
    ]
}

/// Appends commitments, auxiliary finals, DEEP evaluations and witnesses, and the FRI proof.
///
/// The adapter must first append its security header and relation-specific statement data and
/// heights. Auxiliary final groups and opening matrices retain the parsed proof's order.
pub fn append_proof_payload<L>(
    advice_stack: &mut Vec<Felt>,
    stark: &StarkProof<QuadFelt, L>,
) -> Result<(), AdviceError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + Into<[u64; 4]>,
{
    let pcs = &stark.pcs_proof;
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
    append_ood_evaluations(advice_stack, &pcs.deep_proof.evals)?;
    advice_stack.push(pcs.deep_proof.pow_witness);

    for round in &pcs.fri_proof.rounds {
        advice_stack.extend_from_slice(&commitment_felts(round.commitment));
        advice_stack.push(round.pow_witness);
    }
    advice_stack.extend_from_slice(&QuadFelt::flatten_to_base(pcs.fri_proof.final_poly.to_vec()));
    advice_stack.push(pcs.query_pow_witness);
    Ok(())
}

/// Builds Merkle paths and content-addressed rows from DEEP openings followed by FRI openings.
pub fn build_merkle_advice<L>(stark: &StarkProof<QuadFelt, L>) -> Result<MerkleAdvice, AdviceError>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + PartialEq + Into<[u64; 4]>,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
{
    let mut store = MerkleStore::new();
    let mut advice_map = Vec::new();
    let pcs = &stark.pcs_proof;
    for batch_proof in pcs.deep_witnesses.iter().chain(pcs.fri_witnesses.iter()) {
        let (tree, entries) = batch_proof_to_merkle::<L::Commitment, _>(batch_proof)?;
        store.extend(tree.inner_nodes());
        advice_map.extend(entries);
    }
    Ok((store, advice_map))
}

/// Moves the proof stream into the advice map under the verifier and claim's request key.
pub fn package_for_request(
    verifier_root: Word,
    claim_commitment: Word,
    advice: AdviceInputs,
) -> AdviceInputs {
    let key = proof_request_key(verifier_root, claim_commitment);
    let (proof_stream, mut map, store) = advice.into_parts();
    map.insert(key, proof_stream.into_elements());
    AdviceInputs::new(AdviceStack::default(), map, store)
}

/// Encodes commitment limbs as canonical advice field elements.
fn commitment_felts<C: Copy + Into<[u64; 4]>>(commitment: C) -> [Felt; 4] {
    // Eidos LMCS commitments are canonical, but this generic adapter accepts raw u64 limbs.
    commitment.into().map(|limb| Felt::new_unchecked(limb % Felt::ORDER))
}

fn challenge_felts(challenges: &[QuadFelt]) -> Vec<Felt> {
    QuadFelt::flatten_to_base(challenges.to_vec())
}

/// Appends all local OOD rows (at z), then all next rows (at z*g).
fn append_ood_evaluations(
    advice_stack: &mut Vec<Felt>,
    evals: &OpenedValues<QuadFelt>,
) -> Result<(), AdviceError> {
    let mut local_values = Vec::new();
    let mut next_values = Vec::new();
    for group in evals {
        for matrix in group {
            let width = matrix.width;
            let values = matrix.values.as_slice();
            if values.len() != width && values.len() != 2 * width {
                return Err(AdviceError::InvalidOodMatrix);
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

/// Converts batch openings to paths and `leaf_hash -> leaf_data` entries.
fn batch_proof_to_merkle<C, B>(
    batch_proof: &B,
) -> Result<(PartialMerkleTree, Vec<(Word, Vec<Felt>)>), AdviceError>
where
    C: Copy + PartialEq + Into<[u64; 4]>,
    B: BatchProofView<Felt, C>,
{
    let mut paths = Vec::new();
    let mut advice_entries = Vec::new();
    for index in batch_proof.indices() {
        let rows = batch_proof.opening(index).ok_or(AdviceError::MissingOpening)?;
        let siblings = batch_proof.path(index).ok_or(AdviceError::MissingMerklePath)?;
        validate_non_hiding_lmcs_salt(batch_proof.salt(index))?;
        let leaf_data = rows.as_slice().to_vec();
        let leaf_hash = *batch_proof.leaf_hash(index).ok_or(AdviceError::MissingLeafHash)?;
        let leaf_word = Word::new(commitment_felts(leaf_hash));
        let merkle_path =
            MerklePath::new(siblings.into_iter().map(|c| Word::new(commitment_felts(c))).collect());
        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }
    let tree = PartialMerkleTree::with_paths(paths).map_err(|_| AdviceError::InvalidMerklePaths)?;
    Ok((tree, advice_entries))
}

/// Rejects absent or hiding salts, which the MASM advice ABI cannot represent.
fn validate_non_hiding_lmcs_salt(salt: Option<&[Felt]>) -> Result<(), AdviceError> {
    let salt = salt.ok_or(AdviceError::MissingSalt)?;
    if !salt.is_empty() {
        return Err(AdviceError::HidingSalt);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_matrix::dense::RowMajorMatrix;

    use super::*;
    use crate::lmcs::row_list::RowList;

    #[test]
    fn commitment_limbs_are_canonicalized_before_entering_advice() {
        let felts = commitment_felts([Felt::ORDER + 7, u64::MAX, 0, Felt::ORDER - 1]);
        assert_eq!(
            felts.map(|felt| felt.as_canonical_u64()),
            [7, u32::MAX as u64 - 1, 0, Felt::ORDER - 1],
        );
    }

    /// The header must describe the supplied parameters, independently of either relation preset.
    #[test]
    fn security_parameter_header_uses_the_supplied_pcs_params() {
        let params = PcsParams::new(4, 3, 6, 5, 11, 19, 13).expect("valid distinct PCS params");
        assert_eq!(security_parameter_words(&params), [19, 13, 11, 5].map(Felt::new_unchecked));
    }

    #[test]
    fn malformed_ood_rows_do_not_append_partial_advice() {
        // A valid two-point matrix stages both local and next evaluations before the malformed
        // matrix is encountered. Neither staged group may leak into the caller's advice.
        let valid = RowMajorMatrix::new(vec![QuadFelt::default(); 2], 1);
        let sentinel = Felt::new_unchecked(37);
        for num_values in [0, 1, 3, 6] {
            let mut malformed = RowMajorMatrix::new_col(vec![QuadFelt::default(); num_values]);
            malformed.width = 2;
            let evals = vec![vec![valid.clone()], vec![malformed]];
            let mut output = vec![sentinel];

            assert_eq!(
                append_ood_evaluations(&mut output, &evals),
                Err(AdviceError::InvalidOodMatrix),
                "width-two OOD matrix with {num_values} values must be rejected",
            );
            assert_eq!(output, [sentinel], "malformed OOD rows must not append partial advice");
        }
    }

    #[test]
    fn non_hiding_advice_requires_a_present_empty_salt() {
        assert_eq!(validate_non_hiding_lmcs_salt(None), Err(AdviceError::MissingSalt));
        assert_eq!(
            validate_non_hiding_lmcs_salt(Some(&[Felt::new_unchecked(1)])),
            Err(AdviceError::HidingSalt),
        );
        assert_eq!(validate_non_hiding_lmcs_salt(Some(&[])), Ok(()));
    }

    /// An incomplete view exercises defensive checks without constructing a STARK or bypassing
    /// the invariants enforced by the concrete LMCS proof constructors.
    #[derive(Default)]
    struct TestBatch {
        opening: Option<RowList<Felt>>,
        path: Option<Vec<[u64; 4]>>,
        salt: Option<Vec<Felt>>,
        leaf_hash: Option<[u64; 4]>,
    }

    impl BatchProofView<Felt, [u64; 4]> for TestBatch {
        fn opening(&self, _index: usize) -> Option<&RowList<Felt>> {
            self.opening.as_ref()
        }

        fn leaf_hash(&self, _index: usize) -> Option<&[u64; 4]> {
            self.leaf_hash.as_ref()
        }

        fn salt(&self, _index: usize) -> Option<&[Felt]> {
            self.salt.as_deref()
        }

        fn path(&self, _index: usize) -> Option<Vec<[u64; 4]>> {
            self.path.clone()
        }

        fn indices(&self) -> impl Iterator<Item = usize> + '_ {
            core::iter::once(0)
        }
    }

    #[test]
    fn incomplete_batch_openings_reject_in_consumption_order() {
        let mut batch = TestBatch::default();
        assert_eq!(
            batch_proof_to_merkle::<[u64; 4], _>(&batch).unwrap_err(),
            AdviceError::MissingOpening,
        );

        batch.opening = Some(RowList::new(vec![Felt::new_unchecked(1)], vec![1]));
        assert_eq!(
            batch_proof_to_merkle::<[u64; 4], _>(&batch).unwrap_err(),
            AdviceError::MissingMerklePath,
        );

        batch.path = Some(vec![[2; 4]]);
        assert_eq!(
            batch_proof_to_merkle::<[u64; 4], _>(&batch).unwrap_err(),
            AdviceError::MissingSalt,
        );

        batch.salt = Some(vec![Felt::new_unchecked(1)]);
        assert_eq!(
            batch_proof_to_merkle::<[u64; 4], _>(&batch).unwrap_err(),
            AdviceError::HidingSalt,
        );

        batch.salt = Some(Vec::new());
        assert_eq!(
            batch_proof_to_merkle::<[u64; 4], _>(&batch).unwrap_err(),
            AdviceError::MissingLeafHash,
        );
    }

    #[test]
    fn batch_openings_reject_invalid_merkle_paths() {
        let batch = TestBatch {
            opening: Some(RowList::new(vec![Felt::new_unchecked(1)], vec![1])),
            path: Some(Vec::new()),
            salt: Some(Vec::new()),
            leaf_hash: Some([1; 4]),
        };
        assert_eq!(
            batch_proof_to_merkle::<[u64; 4], _>(&batch).unwrap_err(),
            AdviceError::InvalidMerklePaths,
        );
    }
}
