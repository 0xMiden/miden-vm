use alloc::sync::Arc;
use core::ops::ControlFlow;

use miden_air::{
    Felt,
    trace::{RowIndex, chiplets::hasher::HasherState},
};
use miden_core::{
    WORD_SIZE, Word, ZERO,
    crypto::{hash::Poseidon2, merkle::MerklePath},
    mast::{BasicBlockNode, MastForest, MastNodeId},
    precompile::{PrecompileTranscript, PrecompileTranscriptState},
};

use super::step::BreakReason;
use crate::{
    AdviceProvider, ContextId, ExecutionError, Host,
    errors::OperationError,
    fast::{FastProcessor, STACK_BUFFER_SIZE, memory::Memory},
    processor::{HasherInterface, Processor, StackInterface, SystemInterface},
};

impl Processor for FastProcessor {
    type System = Self;
    type Stack = Self;
    type AdviceProvider = AdviceProvider;
    type Memory = Memory;
    type Hasher = Self;

    #[inline(always)]
    fn stack(&self) -> &Self::Stack {
        self
    }

    #[inline(always)]
    fn stack_mut(&mut self) -> &mut Self::Stack {
        self
    }

    #[inline(always)]
    fn advice_provider(&self) -> &Self::AdviceProvider {
        &self.advice
    }

    #[inline(always)]
    fn advice_provider_mut(&mut self) -> &mut Self::AdviceProvider {
        &mut self.advice
    }

    #[inline(always)]
    fn memory_mut(&mut self) -> &mut Self::Memory {
        &mut self.memory
    }

    #[inline(always)]
    fn hasher(&mut self) -> &mut Self::Hasher {
        self
    }

    #[inline(always)]
    fn system(&self) -> &Self::System {
        self
    }

    #[inline(always)]
    fn system_mut(&mut self) -> &mut Self::System {
        self
    }

    #[inline(always)]
    fn save_context_and_truncate_stack(&mut self) {
        self.save_context_and_truncate_stack();
    }

    #[inline(always)]
    fn restore_context(&mut self) -> Result<(), OperationError> {
        self.restore_context()
    }

    #[inline(always)]
    fn precompile_transcript_state(&self) -> PrecompileTranscriptState {
        self.pc_transcript.state()
    }

    #[inline(always)]
    fn set_precompile_transcript_state(&mut self, state: PrecompileTranscriptState) {
        self.pc_transcript = PrecompileTranscript::from_state(state);
    }

    #[inline(always)]
    fn execute_before_enter_decorators(
        &self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        self.execute_before_enter_decorators(node_id, current_forest, host)
    }

    #[inline(always)]
    fn execute_after_exit_decorators(
        &self,
        node_id: MastNodeId,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        self.execute_after_exit_decorators(node_id, current_forest, host)
    }

    #[inline(always)]
    fn execute_decorators_for_op(
        &self,
        node_id: MastNodeId,
        op_idx_in_block: usize,
        current_forest: &MastForest,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        if self.should_execute_decorators() {
            #[cfg(test)]
            self.record_decorator_retrieval();

            for decorator in current_forest.decorators_for_op(node_id, op_idx_in_block) {
                self.execute_decorator(decorator, host)?;
            }
        }

        ControlFlow::Continue(())
    }

    #[inline(always)]
    fn execute_end_of_block_decorators(
        &self,
        basic_block_node: &BasicBlockNode,
        node_id: MastNodeId,
        current_forest: &Arc<MastForest>,
        host: &mut impl Host,
    ) -> ControlFlow<BreakReason> {
        self.execute_end_of_block_decorators(basic_block_node, node_id, current_forest, host)
    }
}

impl HasherInterface for FastProcessor {
    #[inline(always)]
    fn permute(
        &mut self,
        mut input_state: HasherState,
    ) -> Result<(Felt, HasherState), OperationError> {
        Poseidon2::apply_permutation(&mut input_state);

        // Return a default value for the address, as it is not needed in trace generation.
        Ok((ZERO, input_state))
    }

    #[inline(always)]
    fn verify_merkle_root(
        &mut self,
        claimed_root: Word,
        value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<Felt, OperationError> {
        let path = path.expect("fast processor expects a valid Merkle path");
        match path.verify(index.as_canonical_u64(), value, &claimed_root) {
            // Return a default value for the address, as it is not needed in trace generation.
            Ok(_) => Ok(ZERO),
            Err(_) => Err(on_err()),
        }
    }

    #[inline(always)]
    fn update_merkle_root(
        &mut self,
        claimed_old_root: Word,
        old_value: Word,
        new_value: Word,
        path: Option<&MerklePath>,
        index: Felt,
        on_err: impl FnOnce() -> OperationError,
    ) -> Result<(Felt, Word), OperationError> {
        let path = path.expect("fast processor expects a valid Merkle path");

        // Verify the old value against the claimed old root.
        if path.verify(index.as_canonical_u64(), old_value, &claimed_old_root).is_err() {
            return Err(on_err());
        };

        // Compute the new root.
        let new_root =
            path.compute_root(index.as_canonical_u64(), new_value).map_err(|_| on_err())?;

        Ok((ZERO, new_root))
    }
}

impl SystemInterface for FastProcessor {
    #[inline(always)]
    fn caller_hash(&self) -> Word {
        self.caller_hash
    }

    #[inline(always)]
    fn clock(&self) -> RowIndex {
        self.clk
    }

    #[inline(always)]
    fn ctx(&self) -> ContextId {
        self.ctx
    }

    #[inline(always)]
    fn increment_clock(&mut self) {
        self.clk += 1_u32;
    }

    #[inline(always)]
    fn set_caller_hash(&mut self, caller_hash: Word) {
        self.caller_hash = caller_hash;
    }

    #[inline(always)]
    fn set_ctx(&mut self, ctx: ContextId) {
        self.ctx = ctx;
    }
}

impl StackInterface for FastProcessor {
    #[inline(always)]
    fn top(&self) -> &[Felt] {
        self.stack_top()
    }

    #[inline(always)]
    fn get(&self, idx: usize) -> Felt {
        self.stack_get(idx)
    }

    #[inline(always)]
    fn get_mut(&mut self, idx: usize) -> &mut Felt {
        self.stack_get_mut(idx)
    }

    #[inline(always)]
    fn get_word(&self, start_idx: usize) -> Word {
        self.stack_get_word(start_idx)
    }

    #[inline(always)]
    fn depth(&self) -> u32 {
        self.stack_depth()
    }

    #[inline(always)]
    fn set(&mut self, idx: usize, element: Felt) {
        self.stack_write(idx, element)
    }

    #[inline(always)]
    fn set_word(&mut self, start_idx: usize, word: &Word) {
        self.stack_write_word(start_idx, word);
    }

    #[inline(always)]
    fn swap(&mut self, idx1: usize, idx2: usize) {
        self.stack_swap(idx1, idx2)
    }

    #[inline(always)]
    fn swapw_nth(&mut self, n: usize) {
        // For example, for n=3, the stack words and variables look like:
        //    3     2     1     0
        // | ... | ... | ... | ... |
        // ^                 ^
        // nth_word       top_word
        let (rest_of_stack, top_word) = self.stack.split_at_mut(self.stack_top_idx - WORD_SIZE);
        let (_, nth_word) = rest_of_stack.split_at_mut(rest_of_stack.len() - n * WORD_SIZE);

        nth_word[0..WORD_SIZE].swap_with_slice(&mut top_word[0..WORD_SIZE]);
    }

    #[inline(always)]
    fn rotate_left(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_top_element = self.stack[rotation_bot_index];

        // shift the top n elements down by 1, starting from the bottom of the rotation.
        for i in 0..n - 1 {
            self.stack[rotation_bot_index + i] = self.stack[rotation_bot_index + i + 1];
        }

        // Set the top element (which comes from the bottom of the rotation).
        self.stack_write(0, new_stack_top_element);
    }

    #[inline(always)]
    fn rotate_right(&mut self, n: usize) {
        let rotation_bot_index = self.stack_top_idx - n;
        let new_stack_bot_element = self.stack[self.stack_top_idx - 1];

        // shift the top n elements up by 1, starting from the top of the rotation.
        for i in 1..n {
            self.stack[self.stack_top_idx - i] = self.stack[self.stack_top_idx - i - 1];
        }

        // Set the bot element (which comes from the top of the rotation).
        self.stack[rotation_bot_index] = new_stack_bot_element;
    }

    #[inline(always)]
    fn increment_size(&mut self) -> Result<(), ExecutionError> {
        if self.stack_top_idx < STACK_BUFFER_SIZE - 1 {
            self.increment_stack_size();
            Ok(())
        } else {
            Err(ExecutionError::Internal("stack overflow"))
        }
    }

    #[inline(always)]
    fn decrement_size(&mut self) {
        self.decrement_stack_size()
    }
}
