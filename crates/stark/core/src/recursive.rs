//! Shared PCS-to-MASM advice conversions for relation-specific recursive adapters.
use alloc::vec::Vec;

use miden_core::{
    Felt, Word,
    crypto::merkle::{MerklePath, PartialMerkleTree},
    field::{BasedVectorSpace, QuadFelt},
};

use crate::{
    lmcs::{Lmcs, proof::BatchProofView},
    pcs::OpenedValues,
};

/// Append all local OOD rows, then all next rows, preserving group and matrix order.
/// A malformed matrix leaves the destination unchanged.
pub fn append_ood_evaluations(
    out: &mut Vec<Felt>,
    evals: &OpenedValues<QuadFelt>,
) -> Result<(), &'static str> {
    let mut local = Vec::new();
    let mut next = Vec::new();
    for matrix in evals.iter().flatten() {
        let width = matrix.width;
        let values = matrix.values.as_slice();
        let two_rows = width.checked_mul(2) == Some(values.len());
        if values.len() != width && !two_rows {
            return Err("OOD matrix must hold exactly one or two rows");
        }
        local.extend_from_slice(&values[..width]);
        if two_rows {
            next.extend_from_slice(&values[width..]);
        }
    }
    out.extend(<QuadFelt as BasedVectorSpace<Felt>>::flatten_to_base(local));
    out.extend(<QuadFelt as BasedVectorSpace<Felt>>::flatten_to_base(next));
    Ok(())
}

/// Convert non-hiding LMCS openings to Merkle-store and advice-map entries.
pub fn batch_proof_to_merkle<L>(
    batch_proof: &L::BatchProof,
) -> Result<(PartialMerkleTree, Vec<(Word, Vec<Felt>)>), &'static str>
where
    L: Lmcs<F = Felt>,
    L::Commitment: Copy + PartialEq + Into<[u64; 4]>,
    L::BatchProof: BatchProofView<Felt, L::Commitment>,
{
    let mut paths = Vec::new();
    let mut advice_entries = Vec::new();

    for index in batch_proof.indices() {
        let rows = batch_proof.opening(index).ok_or("missing opening for query index")?;
        let siblings = batch_proof.path(index).ok_or("missing Merkle path for query index")?;
        validate_non_hiding_lmcs_salt(batch_proof.salt(index))?;

        let leaf_data: Vec<Felt> = rows.as_slice().to_vec();
        let leaf_hash = *batch_proof.leaf_hash(index).ok_or("missing leaf hash for query index")?;
        let leaf_word = Word::new(commitment_felts(leaf_hash));
        let merkle_path =
            MerklePath::new(siblings.into_iter().map(|c| Word::new(commitment_felts(c))).collect());

        paths.push((index as u64, leaf_word, merkle_path));
        advice_entries.push((leaf_word, leaf_data));
    }

    let tree = PartialMerkleTree::with_paths(paths).map_err(|_| "invalid Merkle paths")?;

    Ok((tree, advice_entries))
}

fn validate_non_hiding_lmcs_salt(salt: Option<&[Felt]>) -> Result<(), &'static str> {
    let salt = salt.ok_or("missing LMCS salt for query index")?;
    if !salt.is_empty() {
        return Err("hiding LMCS openings are unsupported by the MASM adapter");
    }
    Ok(())
}

/// Convert commitment limbs into canonical advice felts.
pub fn commitment_felts<C: Copy + Into<[u64; 4]>>(commitment: C) -> [Felt; 4] {
    // Eidos LMCS commitments are canonical, but this generic adapter accepts raw u64 limbs.
    // Reduce them explicitly because advice words require canonical field representations.
    commitment.into().map(|limb| Felt::new_unchecked(limb % Felt::ORDER))
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use miden_core::utils::RowMajorMatrix;

    use super::*;

    #[test]
    fn commitment_limbs_are_canonicalized_before_entering_advice() {
        let felts = commitment_felts([Felt::ORDER + 7, u64::MAX, 0, Felt::ORDER - 1]);
        assert_eq!(
            felts.map(|felt| felt.as_canonical_u64()),
            [7, u32::MAX as u64 - 1, 0, Felt::ORDER - 1]
        );
    }

    #[test]
    fn recursive_masm_adapter_requires_present_empty_lmcs_salt() {
        assert_eq!(validate_non_hiding_lmcs_salt(Some(&[])), Ok(()));
        assert_eq!(
            validate_non_hiding_lmcs_salt(Some(&[Felt::ONE])),
            Err("hiding LMCS openings are unsupported by the MASM adapter")
        );
        assert_eq!(validate_non_hiding_lmcs_salt(None), Err("missing LMCS salt for query index"));
    }

    #[test]
    fn ood_rows_are_local_first_and_shape_failure_preserves_output() {
        let q = |n: u32| QuadFelt::new([Felt::from(n), Felt::from(n + 10)]);
        let mut evals = vec![
            vec![RowMajorMatrix::new(vec![q(1), q(2)], 1)],
            vec![RowMajorMatrix::new(vec![q(3)], 1)],
        ];
        let mut out = vec![Felt::ONE];
        append_ood_evaluations(&mut out, &evals).unwrap();
        assert_eq!(out, [1u32, 1, 11, 3, 13, 2, 12].map(Felt::from));
        evals[1].push(RowMajorMatrix::new(vec![q(4), q(5), q(6)], 1));
        let before = out.clone();
        assert_eq!(
            append_ood_evaluations(&mut out, &evals),
            Err("OOD matrix must hold exactly one or two rows")
        );
        assert_eq!(out, before);
        let malformed = evals[1].last_mut().unwrap();
        malformed.width = usize::MAX / 2 + 1;
        malformed.values.clear();
        assert_eq!(
            append_ood_evaluations(&mut out, &evals),
            Err("OOD matrix must hold exactly one or two rows")
        );
        assert_eq!(out, before);
    }
}
