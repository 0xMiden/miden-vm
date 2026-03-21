use alloc::vec::Vec;

use miden_air::trace::{
    AUX_TRACE_RAND_CHALLENGES, Challenges, MainTrace, chiplets::hasher::P1_COL_IDX,
};
use miden_core::{
    ONE, Word, ZERO,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    field::{ExtensionField, Field},
    operations::Operation,
};
use rstest::rstest;

use super::{Felt, build_trace_from_ops_with_inputs, rand_array};
use crate::{AdviceInputs, StackInputs};

// SIBLING TABLE TESTS
// ================================================================================================

#[rstest]
#[case(5_u64)]
#[case(4_u64)]
fn hasher_p1_mp_verify(#[case] index: u64) {
    let (tree, _) = build_merkle_tree();
    let store = MerkleStore::from(&tree);
    let depth = 3;
    let node = tree.get_node(NodeIndex::new(depth as u8, index).unwrap()).unwrap();

    // build program inputs
    let mut init_stack = vec![];
    append_word(&mut init_stack, node);
    init_stack.extend_from_slice(&[depth, index]);
    append_word(&mut init_stack, tree.root());
    let stack_inputs = StackInputs::try_from_ints(init_stack).unwrap();
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    // build execution trace and extract the sibling table column from it
    let ops = vec![Operation::MpVerify(ZERO)];
    let trace = build_trace_from_ops_with_inputs(ops, stack_inputs, advice_inputs);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    // executing MPVERIFY does not affect the sibling table - so, all values in the column must be
    // ONE
    for value in p1.iter() {
        assert_eq!(ONE, *value);
    }
}

#[rstest]
#[case(5_u64)]
#[case(4_u64)]
fn hasher_p1_mr_update(#[case] index: u64) {
    let (tree, _) = build_merkle_tree();
    let old_node = tree.get_node(NodeIndex::new(3, index).unwrap()).unwrap();
    let new_node = init_leaf(11);
    let path = tree.get_path(NodeIndex::new(3, index).unwrap()).unwrap();

    // build program inputs
    let mut init_stack = vec![];
    append_word(&mut init_stack, old_node);
    init_stack.extend_from_slice(&[3, index]);
    append_word(&mut init_stack, tree.root());
    append_word(&mut init_stack, new_node);
    let stack_inputs = StackInputs::try_from_ints(init_stack).unwrap();
    let store = MerkleStore::from(&tree);
    let advice_inputs = AdviceInputs::default().with_merkle_store(store);

    // build execution trace and extract the sibling table column from it
    let ops = vec![Operation::MrUpdate];
    let trace = build_trace_from_ops_with_inputs(ops, stack_inputs, advice_inputs);
    let challenges = rand_array::<Felt, AUX_TRACE_RAND_CHALLENGES>();
    let aux_columns = trace.build_aux_trace(&challenges).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let challenges = Challenges::<Felt>::new(challenges[0], challenges[1]);
    // mrupdate_id = 1 for the first (and only) MR_UPDATE operation.
    let mrupdate_id = ONE;
    let row_values = [
        SiblingTableRow::new(Felt::new(index), path[0], mrupdate_id)
            .to_value(&trace.main_trace, &challenges),
        SiblingTableRow::new(Felt::new(index >> 1), path[1], mrupdate_id)
            .to_value(&trace.main_trace, &challenges),
        SiblingTableRow::new(Felt::new(index >> 2), path[2], mrupdate_id)
            .to_value(&trace.main_trace, &challenges),
    ];

    // Make sure the first entry is ONE.
    let mut expected_value = ONE;
    assert_eq!(expected_value, p1[0]);

    // The running product does not change while the hasher computes the hash of the SPAN block.
    // In the controller/perm split, the span uses 2 controller rows (0-1). The MR_UPDATE starts
    // at controller row 2. Each Merkle level is a 2-row controller pair.
    //
    // MV leg (old path, depth 3): input rows at 2, 4, 6. Siblings added at rows 3, 5, 7.
    // MU leg (new path, depth 3): input rows at 8, 10, 12. Siblings removed at rows 9, 11, 13.
    let row_add_1 = 3;
    for value in p1.iter().take(row_add_1).skip(1) {
        assert_eq!(expected_value, *value);
    }

    // First sibling is added (MV level 0).
    expected_value *= row_values[0];
    assert_eq!(expected_value, p1[row_add_1]);

    // The value remains the same until the next sibling is added.
    let row_add_2 = 5;
    for value in p1.iter().take(row_add_2).skip(row_add_1 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Second sibling is added (MV level 1).
    expected_value *= row_values[1];
    assert_eq!(expected_value, p1[row_add_2]);

    // The value remains the same until the last sibling is added.
    let row_add_3 = 7;
    for value in p1.iter().take(row_add_3).skip(row_add_2 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Last sibling is added (MV level 2).
    expected_value *= row_values[2];
    assert_eq!(expected_value, p1[row_add_3]);

    // The value remains the same until computation of the "new Merkle root" is started.
    // MU leg starts at controller row 8, first sibling removed at row 9.
    let row_remove_1 = 9;
    for value in p1.iter().take(row_remove_1).skip(row_add_3 + 1) {
        assert_eq!(expected_value, *value);
    }

    // First sibling is removed from the table in the following row.
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p1[row_remove_1]);

    // The value remains the same until the next sibling is removed (MU level 1, row 11).
    let row_remove_2 = 11;
    for value in p1.iter().take(row_remove_2).skip(row_remove_1 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Second sibling is removed (MU level 1).
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p1[row_remove_2]);

    // The value remains the same until the last sibling is removed (MU level 2, row 13).
    let row_remove_3 = 13;
    for value in p1.iter().take(row_remove_3).skip(row_remove_2 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Last sibling is removed (MU level 2).
    expected_value *= row_values[2].inverse();
    assert_eq!(expected_value, p1[row_remove_3]);

    // at this point the table should be empty again, and it should stay empty until the end
    assert_eq!(expected_value, ONE);
    for value in p1.iter().skip(row_remove_3 + 1) {
        assert_eq!(ONE, *value);
    }
}

// HELPER STRUCTS, METHODS AND FUNCTIONS
// ================================================================================================

fn build_merkle_tree() -> (MerkleTree, Vec<Word>) {
    // build a Merkle tree
    let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
    (MerkleTree::new(leaves.clone()).unwrap(), leaves)
}

fn init_leaves(values: &[u64]) -> Vec<Word> {
    values.iter().map(|&v| init_leaf(v)).collect()
}

fn init_leaf(value: u64) -> Word {
    [Felt::new(value), ZERO, ZERO, ZERO].into()
}

fn append_word(target: &mut Vec<u64>, word: Word) {
    word.iter().for_each(|v| target.push(v.as_canonical_u64()));
}

/// Describes a single entry in the sibling table which consists of a tuple `(index, node)` where
/// index is the index of the node at its depth. For example, assume a leaf has index n. For the
/// leaf's parent the index will be n << 1. For the parent of the parent, the index will be
/// n << 2 etc.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SiblingTableRow {
    index: Felt,
    sibling: Word,
    mrupdate_id: Felt,
}

impl SiblingTableRow {
    pub fn new(index: Felt, sibling: Word, mrupdate_id: Felt) -> Self {
        Self { index, sibling, mrupdate_id }
    }

    /// Reduces this row to a single field element in the field specified by E.
    ///
    /// The encoding includes:
    /// - `mrupdate_id` at position 1: prevents cross-operation sibling reuse by binding
    ///   each sibling table entry to a specific MRUPDATE operation. Without this, a prover
    ///   could swap siblings between the old path of one update and the new path of another.
    /// - `node_index` at position 2: the Merkle tree index at this path level.
    /// - sibling word at positions 3-6 or 7-10: which rate half holds the sibling depends
    ///   on the direction bit (LSB of node_index).
    pub fn to_value<E: ExtensionField<Felt>>(
        &self,
        _main_trace: &MainTrace,
        challenges: &Challenges<E>,
    ) -> E {
        let lsb = self.index.as_canonical_u64() & 1;
        if lsb == 0 {
            // Sibling at rate1 (positions 7-10)
            challenges.alpha
                + challenges.beta_powers[1] * self.mrupdate_id
                + challenges.beta_powers[2] * self.index
                + challenges.beta_powers[7] * self.sibling[0]
                + challenges.beta_powers[8] * self.sibling[1]
                + challenges.beta_powers[9] * self.sibling[2]
                + challenges.beta_powers[10] * self.sibling[3]
        } else {
            // Sibling at rate0 (positions 3-6)
            challenges.alpha
                + challenges.beta_powers[1] * self.mrupdate_id
                + challenges.beta_powers[2] * self.index
                + challenges.beta_powers[3] * self.sibling[0]
                + challenges.beta_powers[4] * self.sibling[1]
                + challenges.beta_powers[5] * self.sibling[2]
                + challenges.beta_powers[6] * self.sibling[3]
        }
    }
}
