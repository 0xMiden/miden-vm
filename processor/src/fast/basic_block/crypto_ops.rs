use miden_core::{
    Felt, ZERO, chiplets::hasher::STATE_WIDTH, crypto::hash::Rpo256, mast::MastForest, utils::range,
};

use super::FastProcessor;
use crate::{ErrorContext, ExecutionError, fast::tracer::Tracer};

impl FastProcessor {
    /// Applies a permutation of the Rpo256 hash function to the top 12 elements of the stack.
    ///
    /// Analogous to `Process::op_hperm`.
    #[inline(always)]
    pub fn op_hperm(&mut self, tracer: &mut impl Tracer) {
        let state_range = range(self.stack_top_idx - STATE_WIDTH, STATE_WIDTH);
        let hashed_state = {
            let mut input_state: [Felt; STATE_WIDTH] =
                self.stack[state_range.clone()].try_into().unwrap();

            Rpo256::apply_permutation(&mut input_state);

            input_state
        };

        self.stack[state_range].copy_from_slice(&hashed_state);

        tracer.record_hasher_permute(hashed_state);
    }

    /// Analogous to `Process::op_mpverify`.
    pub fn op_mpverify(
        &mut self,
        err_code: Felt,
        program: &MastForest,
        tracer: &mut impl Tracer,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read node value, depth, index and root value from the stack
        let node = self.stack_get_word(0);
        let depth = self.stack_get(4);
        let index = self.stack_get(5);
        let root = self.stack_get_word(6);

        // get a Merkle path from the advice provider for the specified root and node index
        let path = self
            .advice
            .get_merkle_path(root, &depth, &index)
            .map_err(|err| ExecutionError::advice_error(err, self.clk, err_ctx))?;

        tracer.record_hasher_build_merkle_root(&path, root);

        // verify the path
        match path.verify(index.as_int(), node, &root) {
            Ok(_) => Ok(()),
            Err(_) => {
                let err_msg = program.resolve_error_message(err_code);
                Err(ExecutionError::merkle_path_verification_failed(
                    node, index, root, err_code, err_msg, err_ctx,
                ))
            },
        }
    }

    /// Analogous to `Process::op_mrupdate`.
    pub fn op_mrupdate(
        &mut self,
        tracer: &mut impl Tracer,
        err_ctx: &impl ErrorContext,
    ) -> Result<(), ExecutionError> {
        // read old node value, depth, index, tree root and new node values from the stack
        let old_node = self.stack_get_word(0);
        let depth = self.stack_get(4);
        let index = self.stack_get(5);
        let old_root = self.stack_get_word(6);
        let new_node = self.stack_get_word(10);

        // update the node at the specified index in the Merkle tree specified by the old root, and
        // get a Merkle path to it. The length of the returned path is expected to match the
        // specified depth. If the new node is the root of a tree, this instruction will append the
        // whole sub-tree to this node.
        let (path, new_root) =
            self.advice
                .update_merkle_node(old_root, &depth, &index, new_node)
                .map_err(|err| ExecutionError::advice_error(err, self.clk, err_ctx))?;

        assert_eq!(path.len(), depth.as_int() as usize);

        // verify that the old node is consistent with the Merkle path
        if path.verify(index.as_int(), old_node, &old_root).is_err() {
            return Err(ExecutionError::merkle_path_verification_failed(
                old_node, index, old_root, ZERO, None, err_ctx,
            ));
        }

        // Replace the old node value with computed new root; everything else remains the same.
        self.stack_write_word(0, &new_root);

        tracer.record_hasher_update_merkle_root(&path, old_root, new_root);

        Ok(())
    }
}
