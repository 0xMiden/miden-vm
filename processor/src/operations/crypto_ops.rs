use miden_air::trace::{
    chiplets::hasher::{HasherState, STATE_WIDTH},
    log_precompile::STATE_CAP_RANGE,
};
use miden_core::mast::MastForest;

use super::{ExecutionError, Operation, Process};
use crate::{ErrorContext, Felt, Word};

// CRYPTOGRAPHIC OPERATIONS
// ================================================================================================

impl Process {
    // HASHING OPERATIONS
    // --------------------------------------------------------------------------------------------
    /// Performs a Rescue Prime Optimized permutation to the top 12 elements of the operand stack,
    /// where the top two words are the rate (words C and B), the deepest word is the capacity
    /// (word A), and the digest output is the middle word E.
    ///
    /// Stack transition:
    /// [C, B, A, ...] -> [F, E, D, ...]
    pub(super) fn op_hperm(&mut self) -> Result<(), ExecutionError> {
        let input_state = [
            self.stack.get(11),
            self.stack.get(10),
            self.stack.get(9),
            self.stack.get(8),
            self.stack.get(7),
            self.stack.get(6),
            self.stack.get(5),
            self.stack.get(4),
            self.stack.get(3),
            self.stack.get(2),
            self.stack.get(1),
            self.stack.get(0),
        ];

        let (addr, output_state) = self.chiplets.hasher.permute(input_state);
        self.decoder.set_user_op_helpers(Operation::HPerm, &[addr]);
        for (i, &value) in output_state.iter().rev().enumerate() {
            self.stack.set(i, value);
        }
        self.stack.copy_state(12);
        Ok(())
    }

    // MERKLE TREES
    // --------------------------------------------------------------------------------------------

    /// Verifies that a Merkle path from the specified node resolves to the specified root. The
    /// stack is expected to be arranged as follows (from the top):
    /// - value of the node, 4 elements.
    /// - depth of the node, 1 element; this is expected to be the depth of the Merkle tree
    /// - index of the node, 1 element.
    /// - root of the tree, 4 elements.
    ///
    /// To perform the operation we do the following:
    /// 1. Look up the Merkle path in the advice provider for the specified tree root.
    /// 2. Use the hasher to compute the root of the Merkle path for the specified node.
    /// 3. Verify that the computed root is equal to the root provided via the stack.
    /// 4. Copy the stack state over to the next clock cycle with no changes.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Merkle tree for the specified root cannot be found in the advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Path to the node at the specified depth and index is not known to the advice provider.
    ///
    /// # Panics
    /// Panics if the computed root does not match the root provided via the stack.
    pub(super) fn op_mpverify(
        &mut self,
        err_code: Felt,
        program: &MastForest,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read node value, depth, index and root value from the stack
        let node =
            [self.stack.get(3), self.stack.get(2), self.stack.get(1), self.stack.get(0)].into();
        let depth = self.stack.get(4);
        let index = self.stack.get(5);
        let root =
            [self.stack.get(9), self.stack.get(8), self.stack.get(7), self.stack.get(6)].into();

        // get a Merkle path from the advice provider for the specified root and node index.
        // the path is expected to be of the specified depth.
        let path = self
            .advice
            .get_merkle_path(root, &depth, &index)
            .map_err(|err| ExecutionError::advice_error(err, self.system.clk(), err_ctx))?;

        // use hasher to compute the Merkle root of the path
        let (addr, computed_root) = self.chiplets.hasher.build_merkle_root(node, &path, index);

        // save address(r) of the hasher trace from when the computation starts in the decoder
        // helper registers.
        self.decoder.set_user_op_helpers(Operation::MpVerify(err_code), &[addr]);

        if root != computed_root {
            // If the hasher chiplet doesn't compute the same root (using the same path),
            // then it means that `node` is not the value currently in the tree at `index`
            let err_msg = program.resolve_error_message(err_code);
            return Err(ExecutionError::merkle_path_verification_failed(
                node, index, root, err_code, err_msg, err_ctx,
            ));
        }

        // The same state is copied over to the next clock cycle with no changes.
        self.stack.copy_state(0);
        Ok(())
    }

    /// Computes a new root of a Merkle tree where a node at the specified index is updated to
    /// the specified value. The stack is expected to be arranged as follows (from the top):
    /// - old value of the node, 4 elements.
    /// - depth of the node, 1 element; this is expected to be the depth of the Merkle tree.
    /// - index of the node, 1 element.
    /// - current root of the tree, 4 elements.
    /// - new value of the node, 4 elements.
    ///
    /// To perform the operation we do the following:
    /// 1. Update the node at the specified index in the Merkle tree with the specified root, and
    ///    get the Merkle path to it.
    /// 2. Use the hasher to update the root of the Merkle path for the specified node. For this we
    ///    need to provide the old and the new node value.
    /// 3. Verify that the computed old root is equal to the input root provided via the stack.
    /// 4. Replace the old node value with the computed new root.
    ///
    /// The Merkle path for the node is expected to be provided by the prover non-deterministically
    /// (via the advice provider). At the end of the operation, the old node value is replaced with
    /// the new roots value computed based on the provided path. Everything else on the stack
    /// remains the same.
    ///
    /// The original Merkle tree is cloned before the update is performed, and thus, after the
    /// operation, the advice provider will keep track of both the old and the new trees.
    ///
    /// # Errors
    /// Returns an error if:
    /// - Merkle tree for the specified root cannot be found in the advice provider.
    /// - The specified depth is either zero or greater than the depth of the Merkle tree identified
    ///   by the specified root.
    /// - Path to the node at the specified depth and index is not known to the advice provider.
    ///
    /// # Panics
    /// Panics if the computed old root does not match the input root provided via the stack.
    pub(super) fn op_mrupdate(
        &mut self,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read old node value, depth, index, tree root and new node values from the stack
        let old_node =
            [self.stack.get(3), self.stack.get(2), self.stack.get(1), self.stack.get(0)].into();
        let depth = self.stack.get(4);
        let index = self.stack.get(5);
        let old_root =
            [self.stack.get(9), self.stack.get(8), self.stack.get(7), self.stack.get(6)].into();
        let new_node =
            [self.stack.get(13), self.stack.get(12), self.stack.get(11), self.stack.get(10)].into();

        // update the node at the specified index in the Merkle tree specified by the old root, and
        // get a Merkle path to it. the length of the returned path is expected to match the
        // specified depth. if the new node is the root of a tree, this instruction will append the
        // whole sub-tree to this node.
        let (path, _) = self
            .advice
            .update_merkle_node(old_root, &depth, &index, new_node)
            .map_err(|err| ExecutionError::advice_error(err, self.system.clk(), err_ctx))?;

        assert_eq!(path.len(), depth.as_int() as usize);

        let merkle_tree_update =
            self.chiplets.hasher.update_merkle_root(old_node, new_node, &path, index);

        // Asserts the computed old root of the Merkle path from the advice provider is consistent
        // with the input root provided via the stack. This will panic only if the advice provider
        // returns a Merkle path inconsistent with the specified root.
        assert_eq!(old_root, merkle_tree_update.get_old_root(), "inconsistent Merkle tree root");

        // save address(r) of the hasher trace from when the computation starts in the decoder
        // helper registers.
        self.decoder
            .set_user_op_helpers(Operation::MrUpdate, &[merkle_tree_update.get_address()]);

        // Replace the old node value with computed new root; everything else remains the same.
        for (i, &value) in merkle_tree_update.get_new_root().iter().rev().enumerate() {
            self.stack.set(i, value);
        }
        self.stack.copy_state(4);

        Ok(())
    }

    /// Logs a precompile event by absorbing TAG and COMM into the precompile sponge
    /// capacity.
    ///
    /// Stack transition:
    /// `[COMM, TAG, PAD, ...] -> [R1, R0, CAP_NEXT, ...]`
    ///
    /// Where:
    /// - The hasher computes: `[CAP_NEXT, R0, R1] = Rpo([CAP_PREV, TAG, COMM])`
    /// - `CAP_PREV` is the previous sponge capacity provided non-deterministically via helper
    ///   registers.
    /// - The VM stack stores each 4-element word in reverse element order, so the top of the stack
    ///   exposes the elements of `R1` first, followed by the elements of `R0`, then `CAP_NEXT`.
    pub(super) fn op_log_precompile(&mut self) -> Result<(), ExecutionError> {
        // Read TAG and COMM from stack, and CAP_PREV from the processor state
        let comm = self.stack.get_word(0);
        let tag = self.stack.get_word(4);
        let cap_prev = self.pc_transcript_state;

        let input_state: HasherState = {
            let input_state_words = [cap_prev, tag, comm];
            Word::words_as_elements(&input_state_words).try_into().unwrap()
        };

        // Perform the RPO permutation, with output state [CAP_NEXT, R0, R1]
        let (addr, output_state) = self.chiplets.hasher.permute(input_state);

        // Save the hasher address and CAP_PREV in helper registers
        self.decoder.set_user_op_helpers(
            Operation::LogPrecompile,
            &[addr, cap_prev[0], cap_prev[1], cap_prev[2], cap_prev[3]],
        );

        // Update the processor's precompile sponge capacity with CAP_NEXT
        let cap_next = Word::from([
            output_state[STATE_CAP_RANGE.start],
            output_state[STATE_CAP_RANGE.start + 1],
            output_state[STATE_CAP_RANGE.start + 2],
            output_state[STATE_CAP_RANGE.start + 3],
        ]);
        self.pc_transcript_state = cap_next;

        // The output state is represented as 3 words [CAP_NEXT[0..3], R0[0..3], R1[0..3]].
        // In the next row, we overwrite the top 3 words with [R1[3..0], R0[3..0], CAP_NEXT[3..0]],
        // which is just the reversal of the original output state.
        // This matches the semantics of hperm when writing the next hasher to the stack.
        for i in 0..STATE_WIDTH {
            self.stack.set(i, output_state[STATE_WIDTH - 1 - i]);
        }

        // Copy state for the rest of the stack
        self.stack.copy_state(STATE_WIDTH);

        Ok(())
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;

    use miden_core::{
        chiplets::hasher::{STATE_WIDTH, apply_permutation},
        crypto::merkle::{MerkleStore, MerkleTree, NodeIndex},
        mast::MastForest,
    };
    use miden_utils_testing::rand::rand_vector;

    use super::{
        super::{Felt, Operation},
        Process,
    };
    use crate::{AdviceInputs, DefaultHost, StackInputs, Word, ZERO};

    #[test]
    fn op_hperm() {
        // --- test hashing [ONE, ONE] ------------------------------------------------------------
        #[rustfmt::skip]
        let inputs: [u64; STATE_WIDTH] = [
            1, 0, 0, 0,      // capacity: first element set to 1 because padding is used
            1, 1,            // data: [ONE, ONE]
            1, 0, 0, 0, 0, 0 // padding: ONE followed by the necessary ZEROs
        ];
        let stack = StackInputs::try_from_ints(inputs).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        let mut host = DefaultHost::default();
        let program = &MastForest::default();

        let expected: [Felt; STATE_WIDTH] = build_expected_perm(&inputs);
        process.execute_op(Operation::HPerm, program, &mut host).unwrap();
        assert_eq!(expected, &process.stack.trace_state()[0..12]);

        // --- test hashing 8 random values -------------------------------------------------------
        let values = rand_vector::<u64>(8);
        let mut inputs: Vec<u64> = vec![values.len() as u64, 0, 0, 0];
        inputs.extend_from_slice(&values);
        let stack = StackInputs::try_from_ints(inputs.clone()).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);

        // add the capacity to prepare the input vector
        let expected: [Felt; STATE_WIDTH] = build_expected_perm(&inputs);
        process.execute_op(Operation::HPerm, program, &mut host).unwrap();
        assert_eq!(expected, &process.stack.trace_state()[0..12]);

        // --- test that the rest of the stack isn't affected -------------------------------------
        let mut inputs: Vec<u64> = vec![1, 2, 3, 4];
        let expected = inputs.iter().rev().map(|&v| Felt::new(v)).collect::<Vec<Felt>>();
        let values: Vec<u64> = vec![2, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0];
        inputs.extend_from_slice(&values);

        let stack = StackInputs::try_from_ints(inputs).unwrap();
        let mut process = Process::new_dummy_with_decoder_helpers(stack);
        process.execute_op(Operation::HPerm, program, &mut host).unwrap();
        assert_eq!(expected, &process.stack.trace_state()[12..16]);
    }

    #[test]
    fn op_mpverify() {
        let index = 5usize;
        let nodes = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);
        let tree = MerkleTree::new(&nodes).unwrap();
        let store = MerkleStore::from(&tree);
        let root = tree.root();
        let node = nodes[index];
        let index = index as u64;
        let depth = tree.depth() as u64;

        let stack_inputs = [
            root[0].as_int(),
            root[1].as_int(),
            root[2].as_int(),
            root[3].as_int(),
            index,
            depth,
            node[0].as_int(),
            node[1].as_int(),
            node[2].as_int(),
            node[3].as_int(),
        ];

        let depth = Felt::new(depth);
        let index = Felt::new(index);

        let advice_inputs = AdviceInputs::default().with_merkle_store(store);
        let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
        let program = &MastForest::default();

        process.execute_op(Operation::MpVerify(ZERO), program, &mut host).unwrap();
        let expected_stack = build_expected(&[
            node[3], node[2], node[1], node[0], depth, index, root[3], root[2], root[1], root[0],
        ]);
        assert_eq!(expected_stack, process.stack.trace_state());
    }

    #[test]
    fn op_mrupdate() {
        let leaves = init_leaves(&[1, 2, 3, 4, 5, 6, 7, 8]);

        let leaf_index = 5usize;
        let new_leaf = init_node(9);
        let mut new_leaves = leaves.clone();
        new_leaves[leaf_index] = new_leaf;

        let tree = MerkleTree::new(leaves.clone()).unwrap();
        let new_tree = MerkleTree::new(new_leaves).unwrap();

        let stack_inputs = [
            new_leaf[0].as_int(),
            new_leaf[1].as_int(),
            new_leaf[2].as_int(),
            new_leaf[3].as_int(),
            tree.root()[0].as_int(),
            tree.root()[1].as_int(),
            tree.root()[2].as_int(),
            tree.root()[3].as_int(),
            leaf_index as u64,
            tree.depth() as u64,
            leaves[leaf_index][0].as_int(),
            leaves[leaf_index][1].as_int(),
            leaves[leaf_index][2].as_int(),
            leaves[leaf_index][3].as_int(),
        ];

        let store = MerkleStore::from(&tree);
        let advice_inputs = AdviceInputs::default().with_merkle_store(store);
        let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
        let program = &MastForest::default();

        // update the Merkle tree but keep the old copy
        process.execute_op(Operation::MrUpdate, program, &mut host).unwrap();
        let expected_stack = build_expected(&[
            new_tree.root()[3],
            new_tree.root()[2],
            new_tree.root()[1],
            new_tree.root()[0],
            Felt::new(tree.depth() as u64),
            Felt::new(leaf_index as u64),
            tree.root()[3],
            tree.root()[2],
            tree.root()[1],
            tree.root()[0],
            new_leaf[3],
            new_leaf[2],
            new_leaf[1],
            new_leaf[0],
        ]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // make sure both Merkle trees are still in the advice provider
        assert!(process.advice.has_merkle_root(tree.root()));
        assert!(process.advice.has_merkle_root(new_tree.root()));
    }

    #[test]
    fn op_mrupdate_merge_subtree() {
        // init 3 trees, `a` and `b` to be the initial trees, and `c` to be the merged product of
        // `a` and `b`
        let leaves_a = init_leaves(&[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]);
        let leaves_b = init_leaves(&[100, 101, 102, 103]);
        let leaves_c = init_leaves(&[0, 1, 2, 3, 100, 101, 102, 103, 8, 9, 10, 11, 12, 13, 14, 15]);

        let tree_a = MerkleTree::new(leaves_a.clone()).unwrap();
        let tree_b = MerkleTree::new(leaves_b.clone()).unwrap();
        let tree_c = MerkleTree::new(leaves_c.clone()).unwrap();

        // appends only the input trees to the Merkle store
        let mut store = MerkleStore::default();
        store.extend(tree_a.inner_nodes());
        store.extend(tree_b.inner_nodes());

        // set the target coordinates to update the indexes 4..8
        let target_depth = 2;
        let target_index = 1;
        let target_node = tree_b.root();

        // fetch the final root after the sub-tree merge
        let expected_root = tree_c.root();

        // fetch the node to be replaced
        let replaced_root = tree_a.root();
        let replaced_node = store
            .get_node(replaced_root, NodeIndex::new(target_depth as u8, target_index).unwrap())
            .unwrap();

        // setup the process
        let advice_inputs = AdviceInputs::default().with_merkle_store(store);
        let stack_inputs = [
            target_node[0].as_int(),
            target_node[1].as_int(),
            target_node[2].as_int(),
            target_node[3].as_int(),
            replaced_root[0].as_int(),
            replaced_root[1].as_int(),
            replaced_root[2].as_int(),
            replaced_root[3].as_int(),
            target_index,
            target_depth,
            replaced_node[0].as_int(),
            replaced_node[1].as_int(),
            replaced_node[2].as_int(),
            replaced_node[3].as_int(),
        ];
        let stack_inputs = StackInputs::try_from_ints(stack_inputs).unwrap();
        let (mut process, mut host) =
            Process::new_dummy_with_inputs_and_decoder_helpers(stack_inputs, advice_inputs);
        let program = &MastForest::default();

        // assert the expected root doesn't exist before the merge operation
        assert!(!process.advice.has_merkle_root(expected_root));

        // update the previous root
        process.execute_op(Operation::MrUpdate, program, &mut host).unwrap();
        let expected_stack = build_expected(&[
            expected_root[3],
            expected_root[2],
            expected_root[1],
            expected_root[0],
            Felt::new(target_depth),
            Felt::new(target_index),
            replaced_root[3],
            replaced_root[2],
            replaced_root[1],
            replaced_root[0],
            target_node[3],
            target_node[2],
            target_node[1],
            target_node[0],
        ]);
        assert_eq!(expected_stack, process.stack.trace_state());

        // assert the expected root now exists in the advice provider
        assert!(process.advice.has_merkle_root(expected_root));
    }

    // HELPER FUNCTIONS
    // --------------------------------------------------------------------------------------------
    fn init_leaves(values: &[u64]) -> Vec<Word> {
        values.iter().map(|&v| init_node(v)).collect()
    }

    fn init_node(value: u64) -> Word {
        [Felt::new(value), ZERO, ZERO, ZERO].into()
    }

    fn build_expected(values: &[Felt]) -> [Felt; 16] {
        let mut expected = [ZERO; 16];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = value;
        }
        expected
    }

    fn build_expected_perm(values: &[u64]) -> [Felt; STATE_WIDTH] {
        let mut expected = [ZERO; STATE_WIDTH];
        for (&value, result) in values.iter().zip(expected.iter_mut()) {
            *result = Felt::new(value);
        }
        apply_permutation(&mut expected);
        expected.reverse();

        expected
    }
}
