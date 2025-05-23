use vm_core::Word;

use super::{DOUBLE_WORD_SIZE, ExecutionError, FastProcessor, Felt, WORD_SIZE_FELT};
use crate::{AdviceProvider, ErrorContext, Host, ProcessState};

impl FastProcessor {
    /// Analogous to `Process::op_push`.
    pub fn op_push(&mut self, element: Felt) {
        self.increment_stack_size();
        self.stack_write(0, element);
    }

    /// Analogous to `Process::op_advpop`.
    pub fn op_advpop(&mut self, op_idx: usize, host: &mut impl Host) -> Result<(), ExecutionError> {
        let value = host
            .advice_provider_mut()
            .pop_stack(ProcessState::new_fast(self, op_idx), &ErrorContext::default())?;
        self.increment_stack_size();
        self.stack_write(0, value);
        Ok(())
    }

    /// Analogous to `Process::op_advpopw`.
    pub fn op_advpopw(
        &mut self,
        op_idx: usize,
        host: &mut impl Host,
    ) -> Result<(), ExecutionError> {
        let word: Word = host
            .advice_provider_mut()
            .pop_stack_word(ProcessState::new_fast(self, op_idx), &ErrorContext::default())?;
        self.stack_write_word(0, &word);

        Ok(())
    }

    /// Analogous to `Process::op_mloadw`.
    pub fn op_mloadw(&mut self, op_idx: usize) -> Result<(), ExecutionError> {
        let addr = self.stack_get(0);
        self.decrement_stack_size();

        let word = *self.memory.read_word(self.ctx, addr, self.clk + op_idx)?;
        self.stack_write_word(0, &word);

        Ok(())
    }

    /// Analogous to `Process::op_mstorew`.
    pub fn op_mstorew(&mut self, op_idx: usize) -> Result<(), ExecutionError> {
        let addr = self.stack_get(0);
        let word = self.stack_get_word(1);
        self.decrement_stack_size();

        self.memory.write_word(self.ctx, addr, self.clk + op_idx, word)?;
        Ok(())
    }

    /// Analogous to `Process::op_mload`.
    pub fn op_mload(&mut self) -> Result<(), ExecutionError> {
        let element = {
            let addr = self.stack_get(0);
            self.memory.read_element(self.ctx, addr)?
        };

        self.stack_write(0, element);

        Ok(())
    }

    /// Analogous to `Process::op_mstore`.
    pub fn op_mstore(&mut self) -> Result<(), ExecutionError> {
        let addr = self.stack_get(0);
        let value = self.stack_get(1);
        self.decrement_stack_size();

        self.memory.write_element(self.ctx, addr, value)?;

        Ok(())
    }

    /// Analogous to `Process::op_mstream`.
    pub fn op_mstream(&mut self, op_idx: usize) -> Result<(), ExecutionError> {
        // The stack index where the memory address to load the words from is stored.
        const MEM_ADDR_STACK_IDX: usize = 12;

        // load two words from memory
        let addr_first_word = self.stack_get(MEM_ADDR_STACK_IDX);
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;
        let words = [
            *self.memory.read_word(self.ctx, addr_first_word, self.clk + op_idx)?,
            *self.memory.read_word(self.ctx, addr_second_word, self.clk + op_idx)?,
        ];

        // Replace the stack elements with the elements from memory (in stack order). The word at
        // address `addr + 4` is at the top of the stack.
        self.stack_write_word(0, &words[1]);
        self.stack_write_word(4, &words[0]);

        // increment the address by 8 (2 words)
        self.stack_write(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

        Ok(())
    }

    /// Analogous to `Process::op_pipe`.
    pub fn op_pipe(&mut self, op_idx: usize, host: &mut impl Host) -> Result<(), ExecutionError> {
        // The stack index where the memory address to load the words from is stored.
        const MEM_ADDR_STACK_IDX: usize = 12;

        let addr_first_word = self.stack_get(MEM_ADDR_STACK_IDX);
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;

        // pop two words from the advice stack
        let words = host
            .advice_provider_mut()
            .pop_stack_dword(ProcessState::new_fast(self, op_idx), &ErrorContext::default())?;

        // write the words to memory
        self.memory.write_word(self.ctx, addr_first_word, self.clk + op_idx, words[0])?;
        self.memory
            .write_word(self.ctx, addr_second_word, self.clk + op_idx, words[1])?;

        // replace the elements on the stack with the word elements (in stack order)
        self.stack_write_word(0, &words[1]);
        self.stack_write_word(4, &words[0]);

        // increment the address by 8 (2 words)
        self.stack_write(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

        Ok(())
    }
}
