use alloc::vec::Vec;

use miden_air::{
    Felt,
    trace::{RowIndex, chiplets::hasher::HasherState},
};
use miden_core::{
    WORD_SIZE, Word, ZERO,
    crypto::{hash::Poseidon2, merkle::MerklePath},
    deferred::Digest,
    program::MIN_STACK_DEPTH,
    utils::range,
};

use crate::{
    AdviceProvider, ContextId, ExecutionError,
    errors::OperationError,
    fast::{FastProcessor, INITIAL_STACK_TOP_IDX, SystemCallState, memory::Memory},
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
    fn deferred_root(&self) -> Word {
        self.deferred_state.root()
    }

    #[inline(always)]
    fn increment_clock(&mut self) {
        self.clk += 1_u32;
    }

    #[inline(always)]
    fn log_deferred_statement(
        &mut self,
        statement_digest: Digest,
        expected_new_root: Word,
    ) -> Result<(), OperationError> {
        self.deferred_state
            .log_verified_statement(statement_digest, expected_new_root)
            .map(|_| ())
            .map_err(OperationError::from)
    }

    #[inline(always)]
    fn set_caller_hash(&mut self, caller_hash: Word) {
        self.caller_hash = caller_hash;
    }

    #[inline(always)]
    fn set_ctx(&mut self, ctx: ContextId) {
        self.ctx = ctx;
    }

    #[inline(always)]
    fn save_call_state(&mut self) {
        self.system_call_state_stack.push(SystemCallState {
            ctx: self.ctx,
            caller_hash: self.caller_hash,
        });
    }

    #[inline(always)]
    fn restore_call_state(&mut self) -> Result<(), OperationError> {
        let saved = self
            .system_call_state_stack
            .pop()
            .expect("system call state stack should never be empty when restoring context");
        self.ctx = saved.ctx;
        self.caller_hash = saved.caller_hash;
        Ok(())
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
        self.ensure_stack_capacity_for_push()?;
        self.increment_stack_size();
        Ok(())
    }

    #[inline(always)]
    fn decrement_size(&mut self) -> Result<(), OperationError> {
        self.decrement_stack_size();
        Ok(())
    }

    #[inline(always)]
    fn start_context(&mut self) {
        let overflow_stack = if self.stack_size() > MIN_STACK_DEPTH {
            // save the overflow stack, and zero out the buffer.
            //
            // Note: we need to zero the overflow buffer, since the new context expects ZERO's to be
            // pulled in if they decrement the stack size (e.g. by executing a `drop`).
            let overflow_stack =
                self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].to_vec();
            self.stack[self.stack_bot_idx..self.stack_top_idx - MIN_STACK_DEPTH].fill(ZERO);

            overflow_stack
        } else {
            Vec::new()
        };

        self.stack_bot_idx = self.stack_top_idx - MIN_STACK_DEPTH;

        // Charge the suspended overflow against the aggregate operand-stack budget. The elements
        // are merely moved from the active stack into the saved overflow, so the aggregate depth is
        // unchanged here; tracking it lets `ensure_stack_capacity_for_push` cap the total across
        // all nested contexts rather than only the active one.
        self.saved_overflow_len += overflow_stack.len();
        self.stack_overflow_save_stack.push(overflow_stack);
    }

    #[inline(always)]
    fn restore_context(&mut self) -> Result<(), OperationError> {
        // when a call/dyncall/syscall node ends, stack depth must be exactly 16.
        if self.stack_size() > MIN_STACK_DEPTH {
            return Err(OperationError::InvalidStackDepthOnReturn { depth: self.stack_size() });
        }

        let overflow_stack = self
            .stack_overflow_save_stack
            .pop()
            .expect("stack overflow save stack should never be empty when restoring context");

        let target_overflow_len = overflow_stack.len();
        debug_assert!(
            MIN_STACK_DEPTH.saturating_add(target_overflow_len) <= self.options.max_stack_depth(),
            "suspended caller stacks are checked against the operand stack depth limit before being saved"
        );

        // Release this segment from the aggregate operand-stack budget; the elements are about to
        // be moved back into the active context below.
        self.saved_overflow_len -= target_overflow_len;

        // Check if there's enough room to restore the overflow stack in the current stack buffer.
        // If not, move the stack within the buffer so that after restoring the overflow stack, the
        // `stack_bot_idx` is at its original position (i.e. `INITIAL_STACK_TOP_IDX - 16`).
        if target_overflow_len > self.stack_bot_idx {
            let new_stack_top_idx = INITIAL_STACK_TOP_IDX + target_overflow_len;
            self.ensure_stack_capacity_for_top_idx(new_stack_top_idx);

            self.reset_stack_in_buffer(new_stack_top_idx);
        }

        // Restore the overflow.
        self.stack[range(self.stack_bot_idx - target_overflow_len, target_overflow_len)]
            .copy_from_slice(&overflow_stack);
        self.stack_bot_idx -= target_overflow_len;

        Ok(())
    }
}
