use super::{DOUBLE_WORD_SIZE, ExecutionError, FastProcessor, Felt, WORD_SIZE_FELT};
use crate::ErrorContext;

impl FastProcessor {
    /// Analogous to `Process::op_push`.
    pub fn op_push(&mut self, element: Felt) {
        self.increment_stack_size();
        self.stack_write(0, element);
    }

    /// Analogous to `Process::op_advpop`.
    #[inline(always)]
    pub fn op_advpop(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let value = self
            .advice
            .pop_stack()
            .map_err(|err| ExecutionError::advice_error(err, self.clk, err_ctx))?;
        self.increment_stack_size();
        self.stack_write(0, value);
        Ok(())
    }

    /// Analogous to `Process::op_advpopw`.
    #[inline(always)]
    pub fn op_advpopw(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let word = self
            .advice
            .pop_stack_word()
            .map_err(|err| ExecutionError::advice_error(err, self.clk, err_ctx))?;
        self.stack_write_word(0, &word);

        Ok(())
    }

    /// Analogous to `Process::op_mloadw`.
    #[inline(always)]
    pub fn op_mloadw(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let addr = self.stack_get(0);
        self.decrement_stack_size();

        let word = self
            .memory
            .read_word(self.ctx, addr, self.clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        self.stack_write_word(0, &word);

        Ok(())
    }

    /// Analogous to `Process::op_mstorew`.
    #[inline(always)]
    pub fn op_mstorew(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let addr = self.stack_get(0);
        let word = self.stack_get_word(1);
        self.decrement_stack_size();

        self.memory
            .write_word(self.ctx, addr, self.clk, word, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        Ok(())
    }

    /// Analogous to `Process::op_mload`.
    #[inline(always)]
    pub fn op_mload(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let element = {
            let addr = self.stack_get(0);
            self.memory
                .read_element(self.ctx, addr, err_ctx)
                .map_err(ExecutionError::MemoryError)?
        };

        self.stack_write(0, element);

        Ok(())
    }

    /// Analogous to `Process::op_mstore`.
    #[inline(always)]
    pub fn op_mstore(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let addr = self.stack_get(0);
        let value = self.stack_get(1);
        self.decrement_stack_size();

        self.memory
            .write_element(self.ctx, addr, value, err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        Ok(())
    }

    /// Analogous to `Process::op_mstream`.
    #[inline(always)]
    pub fn op_mstream(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        // The stack index where the memory address to load the words from is stored.
        const MEM_ADDR_STACK_IDX: usize = 12;

        // load two words from memory
        let addr_first_word = self.stack_get(MEM_ADDR_STACK_IDX);
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;
        let words = [
            self.memory
                .read_word(self.ctx, addr_first_word, self.clk, err_ctx)
                .map_err(ExecutionError::MemoryError)?,
            self.memory
                .read_word(self.ctx, addr_second_word, self.clk, err_ctx)
                .map_err(ExecutionError::MemoryError)?,
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
    #[inline(always)]
    pub fn op_pipe(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        // The stack index where the memory address to load the words from is stored.
        const MEM_ADDR_STACK_IDX: usize = 12;

        let addr_first_word = self.stack_get(MEM_ADDR_STACK_IDX);
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;

        // pop two words from the advice stack
        let words = self
            .advice
            .pop_stack_dword()
            .map_err(|err| ExecutionError::advice_error(err, self.clk, err_ctx))?;

        // write the words to memory
        self.memory
            .write_word(self.ctx, addr_first_word, self.clk, words[0], err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        self.memory
            .write_word(self.ctx, addr_second_word, self.clk, words[1], err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        // replace the elements on the stack with the word elements (in stack order)
        self.stack_write_word(0, &words[1]);
        self.stack_write_word(4, &words[0]);

        // increment the address by 8 (2 words)
        self.stack_write(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

        Ok(())
    }
}
