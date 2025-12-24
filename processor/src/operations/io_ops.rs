use miden_core::WORD_SIZE;

use super::{ExecutionError, Felt, Process};
use crate::errors::ErrorContext;

// INPUT / OUTPUT OPERATIONS
// ================================================================================================

impl Process {
    // CONSTANT INPUTS
    // --------------------------------------------------------------------------------------------

    /// Pushes the provided value onto the stack.
    ///
    /// The original stack is shifted to the right by one item.
    pub(super) fn op_push(&mut self, value: Felt) -> Result<(), ExecutionError> {
        self.stack.set(0, value);
        self.stack.shift_right(0);
        Ok(())
    }

    // MEMORY READING AND WRITING
    // --------------------------------------------------------------------------------------------

    /// Loads a word (4 elements) starting at the specified memory address onto the stack.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - A word is retrieved from memory starting at the specified address, which must be aligned
    ///   to a word boundary. The memory is always initialized to ZEROs, and thus, for any of the
    ///   four addresses which were not previously been written to, four ZERO elements are returned.
    /// - The top four elements of the stack are overwritten with values retrieved from memory.
    ///
    /// Thus, the net result of the operation is that the stack is shifted left by one item.
    ///
    /// # Errors
    /// - Returns an error if the address is not aligned to a word boundary.
    pub(super) fn op_mloadw(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        // get the address from the stack and read the word from current memory context
        let mut word: [Felt; WORD_SIZE] = self
            .chiplets
            .memory
            .read_word(self.system.ctx(), self.stack.get(0), self.system.clk(), err_ctx)
            .map_err(ExecutionError::MemoryError)?
            .into();
        word.reverse();

        // update the stack state
        for (i, &value) in word.iter().enumerate() {
            self.stack.set(i, value);
        }
        self.stack.shift_left(5);

        Ok(())
    }

    /// Loads the element from the specified memory address onto the stack.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - The element is retrieved from memory at the specified address. The memory is always
    ///   initialized to ZEROs, and thus, if the specified address has never been written to, the
    ///   ZERO element is returned.
    /// - The element retrieved from memory is pushed to the top of the stack.
    pub(super) fn op_mload(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let element = self
            .chiplets
            .memory
            .read(self.system.ctx(), self.stack.get(0), self.system.clk(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        self.stack.set(0, element);
        self.stack.copy_state(1);

        Ok(())
    }

    /// Stores a word (4 elements) from the stack into the specified memory address.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - The top four stack items are saved starting at the specified memory address, which must be
    ///   aligned on a word boundary. The items are not removed from the stack.
    ///
    /// Thus, the net result of the operation is that the stack is shifted left by one item.
    ///
    /// # Errors
    /// - Returns an error if the address is not aligned to a word boundary.
    pub(super) fn op_mstorew(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        // get the address from the stack and build the word to be saved from the stack values
        let addr = self.stack.get(0);

        // build the word in memory order (reverse of stack order)
        let word = [self.stack.get(4), self.stack.get(3), self.stack.get(2), self.stack.get(1)];

        // write the word to memory and get the previous word
        self.chiplets
            .memory
            .write_word(self.system.ctx(), addr, self.system.clk(), word.into(), err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        // reverse the order of the memory word & update the stack state
        for (i, &value) in word.iter().rev().enumerate() {
            self.stack.set(i, value);
        }
        self.stack.shift_left(5);

        Ok(())
    }

    /// Stores an element from the stack into the first slot at the specified memory address.
    ///
    /// The operation works as follows:
    /// - The memory address is popped off the stack.
    /// - The top stack element is saved at the specified memory address. The element is not removed
    ///   from the stack.
    ///
    /// Thus, the net result of the operation is that the stack is shifted left by one item.
    pub(super) fn op_mstore(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        // get the address and the value from the stack
        let ctx = self.system.ctx();
        let addr = self.stack.get(0);
        let value = self.stack.get(1);

        // write the value to the memory and get the previous word
        self.chiplets
            .memory
            .write(ctx, addr, self.system.clk(), value, err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        // update the stack state
        self.stack.shift_left(1);

        Ok(())
    }

    /// Loads two words from memory and replaces the top 8 elements of the stack with their
    /// contents.
    ///
    /// The operation works as follows:
    /// - The memory address of the first word is retrieved from 13th stack element (position 12).
    /// - Two consecutive words, starting at this address, are loaded from memory.
    /// - Elements of these words are written to the top 8 elements of the stack (element-wise, in
    ///   stack order).
    /// - Memory address (in position 12) is incremented by 8.
    /// - All other stack elements remain the same.
    ///
    /// # Errors
    /// - Returns an error if the address is not aligned to a word boundary.
    pub(super) fn op_mstream(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        const MEM_ADDR_STACK_IDX: usize = 12;

        let ctx = self.system.ctx();
        let clk = self.system.clk();
        let addr_first_word = self.stack.get(MEM_ADDR_STACK_IDX);
        let addr_second_word = addr_first_word + Felt::from(WORD_SIZE as u32);

        // load two words from memory
        let words = [
            self.chiplets
                .memory
                .read_word(ctx, addr_first_word, clk, err_ctx)
                .map_err(ExecutionError::MemoryError)?,
            self.chiplets
                .memory
                .read_word(ctx, addr_second_word, clk, err_ctx)
                .map_err(ExecutionError::MemoryError)?,
        ];

        // replace the stack elements with the elements from memory (in stack order)
        for (i, &mem_value) in words.iter().flat_map(|word| word.iter()).rev().enumerate() {
            self.stack.set(i, mem_value);
        }

        // copy over the next 4 elements
        for i in 8..MEM_ADDR_STACK_IDX {
            let stack_value = self.stack.get(i);
            self.stack.set(i, stack_value);
        }

        // increment the address by 8 (2 words)
        self.stack
            .set(MEM_ADDR_STACK_IDX, addr_first_word + Felt::from(WORD_SIZE as u32 * 2));

        // copy over the rest of the stack
        self.stack.copy_state(13);

        Ok(())
    }

    /// Moves 8 elements from the advice stack to the memory, via the operand stack.
    ///
    /// The operation works as follows:
    /// - Two words are popped from the top of the advice stack.
    /// - The destination memory address for the first word is retrieved from the 13th stack element
    ///   (position 12).
    /// - The two words are written to memory consecutively, starting at this address.
    /// - These words replace the top 8 elements of the stack (element-wise, in stack order).
    /// - Memory address (in position 12) is incremented by 8.
    /// - All other stack elements remain the same.
    ///
    /// # Errors
    /// - Returns an error if the address is not aligned to a word boundary.
    pub(super) fn op_pipe(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        const MEM_ADDR_STACK_IDX: usize = 12;

        // get the address from position 12 on the stack
        let ctx = self.system.ctx();
        let clk = self.system.clk();
        let addr_first_word = self.stack.get(MEM_ADDR_STACK_IDX);
        let addr_second_word = addr_first_word + Felt::from(WORD_SIZE as u32);

        // pop two words from the advice stack
        let words = self
            .advice
            .pop_stack_dword()
            .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;

        // write the words memory
        self.chiplets
            .memory
            .write_word(ctx, addr_first_word, clk, words[0], err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        self.chiplets
            .memory
            .write_word(ctx, addr_second_word, clk, words[1], err_ctx)
            .map_err(ExecutionError::MemoryError)?;

        // replace the elements on the stack with the word elements (in stack order)
        for (i, &adv_value) in words.iter().flat_map(|word| word.iter()).rev().enumerate() {
            self.stack.set(i, adv_value);
        }

        // copy over the next 4 elements
        for i in 8..12 {
            let stack_value = self.stack.get(i);
            self.stack.set(i, stack_value);
        }

        // increment the address by 8 (2 words)
        self.stack
            .set(MEM_ADDR_STACK_IDX, addr_first_word + Felt::from(WORD_SIZE as u32 * 2));

        // copy over the rest of the stack
        self.stack.copy_state(13);

        Ok(())
    }

    // ADVICE INPUTS
    // --------------------------------------------------------------------------------------------

    /// Pops an element from the advice stack and pushes it onto the operand stack.
    ///
    /// # Errors
    /// Returns an error if the advice stack is empty.
    pub(super) fn op_advpop(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let value = self
            .advice
            .pop_stack()
            .map_err(|err| ExecutionError::advice_error(err, self.system.clk(), err_ctx))?;
        self.stack.set(0, value);
        self.stack.shift_right(0);
        Ok(())
    }

    /// Pops a word (4 elements) from the advice stack and overwrites the top word on the operand
    /// stack with it.
    ///
    /// # Errors
    /// Returns an error if the advice stack contains fewer than four elements.
    pub(super) fn op_advpopw(&mut self, err_ctx: &impl ErrorContext) -> Result<(), ExecutionError> {
        let word = self
            .advice
            .pop_stack_word()
            .map_err(|err| ExecutionError::advice_error(err, self.system.clk(), err_ctx))?;

        self.stack.set(0, word[3]);
        self.stack.set(1, word[2]);
        self.stack.set(2, word[1]);
        self.stack.set(3, word[0]);
        self.stack.copy_state(4);

        Ok(())
    }
}
