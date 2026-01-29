use alloc::vec::Vec;

use miden_air::trace::{
    AUX_TRACE_RAND_ELEMENTS, MainTrace,
    chiplets::hasher::{HASH_CYCLE_LEN, P1_COL_IDX},
};
use miden_core::{
    ONE, Operation, Word, ZERO,
    crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
    field::{ExtensionField, Field},
};
use rstest::rstest;

use super::{Felt, build_trace_from_ops_with_inputs, rand_array};
use crate::{AdviceInputs, PrimeField64, StackInputs};

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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
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
    let alphas = rand_array::<Felt, AUX_TRACE_RAND_ELEMENTS>();
    let aux_columns = trace.build_aux_trace(&alphas).unwrap();
    let p1 = aux_columns.get_column(P1_COL_IDX);

    let row_values = [
        SiblingTableRow::new(Felt::new(index), path[0]).to_value(&trace.main_trace, &alphas),
        SiblingTableRow::new(Felt::new(index >> 1), path[1]).to_value(&trace.main_trace, &alphas),
        SiblingTableRow::new(Felt::new(index >> 2), path[2]).to_value(&trace.main_trace, &alphas),
    ];

    // Make sure the first entry is ONE.
    let mut expected_value = ONE;
    assert_eq!(expected_value, p1[0]);

    // The running product does not change while the hasher computes the hash of the SPAN block.
    let row_add_1 = HASH_CYCLE_LEN + 1;
    for value in p1.iter().take(row_add_1).skip(1) {
        assert_eq!(expected_value, *value);
    }

    // When computation of the "old Merkle root" is started, the first sibling is added to the
    // table in the following row.
    expected_value *= row_values[0];
    assert_eq!(expected_value, p1[row_add_1]);

    // The value remains the same until the next sibling is added.
    let row_add_2 = 2 * HASH_CYCLE_LEN;
    for value in p1.iter().take(row_add_2).skip(row_add_1 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Next sibling is added.
    expected_value *= row_values[1];
    assert_eq!(expected_value, p1[row_add_2]);

    // The value remains the same until the last sibling is added.
    let row_add_3 = 3 * HASH_CYCLE_LEN;
    for value in p1.iter().take(row_add_3).skip(row_add_2 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Last sibling is added.
    expected_value *= row_values[2];
    assert_eq!(expected_value, p1[row_add_3]);

    // The value remains the same until computation of the "new Merkle root" is started.
    let row_remove_1 = 4 * HASH_CYCLE_LEN + 1;
    for value in p1.iter().take(row_remove_1).skip(row_add_3 + 1) {
        assert_eq!(expected_value, *value);
    }

    // First sibling is removed from the table in the following row.
    expected_value *= row_values[0].inverse();
    assert_eq!(expected_value, p1[row_remove_1]);

    // The value remains the same until the next sibling is removed.
    let row_remove_2 = 5 * HASH_CYCLE_LEN;
    for value in p1.iter().take(row_remove_2).skip(row_remove_1 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Next sibling is removed.
    expected_value *= row_values[1].inverse();
    assert_eq!(expected_value, p1[row_remove_2]);

    // The value remains the same until the last sibling is removed.
    let row_remove_3 = 6 * HASH_CYCLE_LEN;
    for value in p1.iter().take(row_remove_3).skip(row_remove_2 + 1) {
        assert_eq!(expected_value, *value);
    }

    // Last sibling is removed.
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
}

impl SiblingTableRow {
    pub fn new(index: Felt, sibling: Word) -> Self {
        Self { index, sibling }
    }

    /// Reduces this row to a single field element in the field specified by E. This requires
    /// at least 6 alpha values.
    pub fn to_value<E: ExtensionField<Felt>>(&self, _main_trace: &MainTrace, alphas: &[E]) -> E {
        // when the least significant bit of the index is 0, the sibling will be in the 3rd word
        // of the hasher state, and when the least significant bit is 1, it will be in the 2nd
        // word. we compute the value in this way to make constraint evaluation a bit easier since
        // we need to compute the 2nd and the 3rd word values for other purposes as well.
        let lsb = self.index.as_canonical_u64() & 1;
        if lsb == 0 {
            alphas[0]
                + alphas[3] * self.index
                + alphas[12] * self.sibling[0]
                + alphas[13] * self.sibling[1]
                + alphas[14] * self.sibling[2]
                + alphas[15] * self.sibling[3]
        } else {
            alphas[0]
                + alphas[3] * self.index
                + alphas[8] * self.sibling[0]
                + alphas[9] * self.sibling[1]
                + alphas[10] * self.sibling[2]
                + alphas[11] * self.sibling[3]
        }
    }
}
