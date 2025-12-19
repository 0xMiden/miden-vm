use miden_air::trace::{
    chiplets::hasher::{HasherState, STATE_WIDTH},
    log_precompile::STATE_CAP_RANGE,
};
use miden_core::mast::MastForest;

use super::{ExecutionError, Operation, Process};
use crate::{ErrorContext, Felt, Word, operations::utils::validate_dual_word_stream_addrs};

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
            .get_merkle_path(root, depth, index)
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
            .update_merkle_node(old_root, depth, index, new_node)
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

    // STREAM CIPHER OPERATIONS
    // --------------------------------------------------------------------------------------------

    /// Encrypts data from source memory to destination memory using RPO sponge keystream.
    ///
    /// This operation performs AEAD encryption by:
    /// 1. Loading 8 elements (2 words) from source memory at stack[12]
    /// 2. Adding each element to the corresponding rate element (stack[0..7])
    /// 3. Writing the resulting ciphertext to destination memory at stack[13]
    /// 4. Updating stack[0..7] with the ciphertext (becomes new rate for next hperm)
    /// 5. Preserving capacity (stack[8..11])
    /// 6. Incrementing both source and destination pointers by 8
    ///
    /// Stack transition:
    /// [rate(8), cap(4), src_ptr, dst_ptr, ...] -> [ciphertext(8), cap(4), src_ptr+8, dst_ptr+8,
    /// ...]
    pub(super) fn op_crypto_stream(
        &mut self,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        const WORD_SIZE_FELT: Felt = Felt::new(4);
        const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

        // Stack layout: [rate(8), capacity(4), src_ptr, dst_ptr, ...]
        const SRC_PTR_IDX: usize = 12;
        const DST_PTR_IDX: usize = 13;

        let ctx = self.system.ctx();
        let clk = self.system.clk();

        // Get source and destination pointers
        let src_addr = self.stack.get(SRC_PTR_IDX);
        let dst_addr = self.stack.get(DST_PTR_IDX);

        // Validate address ranges and check for overlap
        validate_dual_word_stream_addrs(src_addr, dst_addr, ctx, clk, err_ctx)?;

        // Load plaintext from source memory (2 words = 8 elements)
        let src_addr_word2 = src_addr + WORD_SIZE_FELT;
        let plaintext_word1 = self
            .chiplets
            .memory
            .read_word(ctx, src_addr, clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        let plaintext_word2 = self
            .chiplets
            .memory
            .read_word(ctx, src_addr_word2, clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        // Get rate (keystream) from stack[0..7]
        let rate = [
            self.stack.get(7),
            self.stack.get(6),
            self.stack.get(5),
            self.stack.get(4),
            self.stack.get(3),
            self.stack.get(2),
            self.stack.get(1),
            self.stack.get(0),
        ];

        // Encrypt: ciphertext = plaintext + rate (element-wise addition in field)
        let ciphertext_word1 = [
            plaintext_word1[0] + rate[0],
            plaintext_word1[1] + rate[1],
            plaintext_word1[2] + rate[2],
            plaintext_word1[3] + rate[3],
        ];
        let ciphertext_word2 = [
            plaintext_word2[0] + rate[4],
            plaintext_word2[1] + rate[5],
            plaintext_word2[2] + rate[6],
            plaintext_word2[3] + rate[7],
        ];

        // Write ciphertext to destination memory
        let dst_addr_word2 = dst_addr + WORD_SIZE_FELT;
        self.chiplets
            .memory
            .write_word(ctx, dst_addr, clk, ciphertext_word1.into(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        self.chiplets
            .memory
            .write_word(ctx, dst_addr_word2, clk, ciphertext_word2.into(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        // Update stack[0..7] with ciphertext (becomes new rate for next hperm)
        // Stack order is reversed: stack[0] = top
        // Word 2 goes to stack[0..3]
        self.stack.set(0, ciphertext_word2[3]);
        self.stack.set(1, ciphertext_word2[2]);
        self.stack.set(2, ciphertext_word2[1]);
        self.stack.set(3, ciphertext_word2[0]);
        // Word 1 goes to stack[4..7]
        self.stack.set(4, ciphertext_word1[3]);
        self.stack.set(5, ciphertext_word1[2]);
        self.stack.set(6, ciphertext_word1[1]);
        self.stack.set(7, ciphertext_word1[0]);

        // Copy capacity elements (stack[8..11]) to preserve them
        for i in 8..SRC_PTR_IDX {
            let value = self.stack.get(i);
            self.stack.set(i, value);
        }

        // Increment pointers by 8 (2 words)
        self.stack.set(SRC_PTR_IDX, src_addr + DOUBLE_WORD_SIZE);
        self.stack.set(DST_PTR_IDX, dst_addr + DOUBLE_WORD_SIZE);

        // Copy the rest of the stack (position 14 onwards)
        self.stack.copy_state(14);

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
