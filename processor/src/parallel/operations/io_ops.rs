use miden_core::Felt;

use super::CoreTraceFragmentGenerator;
use crate::processor::Processor;

impl CoreTraceFragmentGenerator {
    /// Pops a value from the advice stack and pushes it onto the operand stack.
    pub(crate) fn op_advpop(&mut self) {
        let value = self.state.advice.replay_pop_stack();
        self.increment_stack_size();
        self.stack_write(0, value);
    }

    /// Pops a word from the advice stack and pushes it onto the operand stack.
    pub(crate) fn op_advpopw(&mut self) {
        let word = self.state.advice.replay_pop_stack_word();
        self.stack_write_word(0, &word);
    }

    /// Loads a word from memory and pushes it onto the stack.
    pub(crate) fn op_mloadw(&mut self) {
        let addr = self.stack_get(0);
        self.decrement_stack_size();

        let word = self.state.memory.replay_read_word(addr);
        self.stack_write_word(0, &word);
    }

    /// Stores a word from the stack into memory.
    ///
    /// In this implementation, we don't actually talk to the memory directly, so all we do is
    /// decrement the stack size.
    pub(crate) fn op_mstorew(&mut self) {
        self.decrement_stack_size();
    }

    /// Loads a single element from memory.
    pub(crate) fn op_mload(&mut self) {
        let element = {
            let addr = self.stack_get(0);
            self.state.memory.replay_read_element(addr)
        };

        self.stack_write(0, element);
    }

    /// Stores a single element into memory.
    ///
    /// Similar to `mstorew`, we don't actually interact with memory in this implementation, so we
    /// just decrement the stack size.
    pub(crate) fn op_mstore(&mut self) {
        self.decrement_stack_size();
    }

    /// Reads from memory stream.
    pub(crate) fn op_mstream(&mut self) {
        const DOUBLE_WORD_SIZE: Felt = Felt::new(8);
        const WORD_SIZE_FELT: Felt = Felt::new(4);
        // The stack index where the memory address to load the words from is stored.
        const MEM_ADDR_STACK_IDX: usize = 12;

        // load two words from memory
        let addr_first_word = self.stack_get(MEM_ADDR_STACK_IDX);
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;
        let words = [
            self.state.memory.replay_read_word(addr_first_word),
            self.state.memory.replay_read_word(addr_second_word),
        ];

        // Replace the stack elements with the elements from memory (in stack order). The word at
        // address `addr + 4` is at the top of the stack.
        self.stack_write_word(0, &words[1]);
        self.stack_write_word(4, &words[0]);

        // increment the address by 8 (2 words)
        self.stack_write(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);
    }

    /// Analogous to `FastProcess::op_pipe`, except that it does not write to memory.
    pub(crate) fn op_pipe(&mut self) {
        const DOUBLE_WORD_SIZE: Felt = Felt::new(8);
        // The stack index where the memory address to load the words from is stored.
        const MEM_ADDR_STACK_IDX: usize = 12;

        let addr_first_word = self.stack_get(MEM_ADDR_STACK_IDX);

        // pop two words from the advice stack
        let words = self.state.advice.replay_pop_stack_dword();

        // (skip) write the words to memory

        // replace the elements on the stack with the word elements (in stack order)
        self.stack_write_word(0, &words[1]);
        self.stack_write_word(4, &words[0]);

        // increment the address by 8 (2 words)
        self.stack_write(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);
    }
}
