use miden_air::Felt;

use super::{DOUBLE_WORD_SIZE, WORD_SIZE_FELT};
pub use crate::errors::IoError;
use crate::{
    fast::Tracer,
    processor::{
        AdviceProviderInterface, MemoryInterface, Processor, StackInterface, SystemInterface,
    },
};

#[cfg(test)]
mod tests;

/// Pops an element from the advice stack and pushes it onto the operand stack.
///
/// # Errors
/// Returns an error if the advice stack is empty.
#[inline(always)]
pub(super) fn op_advpop<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    let value = processor.advice_provider().pop_stack()?;
    tracer.record_advice_pop_stack(value);

    processor.stack().increment_size(tracer)?;
    processor.stack().set(0, value);

    Ok(())
}

/// Pops a word (4 elements) from the advice stack and overwrites the top word on the operand
/// stack with it.
///
/// # Errors
/// Returns an error if the advice stack contains fewer than four elements.
#[inline(always)]
pub(super) fn op_advpopw<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    let word = processor.advice_provider().pop_stack_word()?;
    tracer.record_advice_pop_stack_word(word);

    // Set word on stack (word[0] at top).
    processor.stack().set_word(0, &word);

    Ok(())
}

/// Loads a word (4 elements) starting at the specified memory address onto the stack.
///
/// The operation works as follows:
/// - The memory address is popped off the stack.
/// - A word is retrieved from memory starting at the specified address, which must be aligned to a
///   word boundary. The memory is always initialized to ZEROs, and thus, for any of the four
///   addresses which were not previously been written to, four ZERO elements are returned.
/// - The top four elements of the stack are overwritten with values retrieved from memory.
///
/// Thus, the net result of the operation is that the stack is shifted left by one item.
///
/// # Errors
/// - Returns an error if the address is not aligned to a word boundary.
#[inline(always)]
pub(super) fn op_mloadw<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    let addr = processor.stack().get(0);
    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    processor.stack().decrement_size(tracer);

    let word = processor.memory().read_word(ctx, addr, clk)?;
    tracer.record_memory_read_word(word, addr, processor.system().ctx(), processor.system().clk());

    // Set word on stack (word[0] at top).
    processor.stack().set_word(0, &word);

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
#[inline(always)]
pub(super) fn op_mstorew<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    let addr = processor.stack().get(0);
    // Address is at position 0, so word starts at position 1
    let word = [
        processor.stack().get(1),
        processor.stack().get(2),
        processor.stack().get(3),
        processor.stack().get(4),
    ]
    .into();
    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    processor.stack().decrement_size(tracer);

    processor.memory().write_word(ctx, addr, clk, word)?;
    tracer.record_memory_write_word(word, addr, processor.system().ctx(), processor.system().clk());

    Ok(())
}

/// Loads the element from the specified memory address onto the stack.
///
/// The operation works as follows:
/// - The memory address is popped off the stack.
/// - The element is retrieved from memory at the specified address. The memory is always
///   initialized to ZEROs, and thus, if the specified address has never been written to, the ZERO
///   element is returned.
/// - The element retrieved from memory is pushed to the top of the stack.
#[inline(always)]
pub(super) fn op_mload<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    let ctx = processor.system().ctx();
    let addr = processor.stack().get(0);

    let element = processor.memory().read_element(ctx, addr)?;
    tracer.record_memory_read_element(
        element,
        addr,
        processor.system().ctx(),
        processor.system().clk(),
    );

    processor.stack().set(0, element);

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
#[inline(always)]
pub(super) fn op_mstore<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    let addr = processor.stack().get(0);
    let value = processor.stack().get(1);
    let ctx = processor.system().ctx();

    processor.stack().decrement_size(tracer);

    processor.memory().write_element(ctx, addr, value)?;
    tracer.record_memory_write_element(
        value,
        addr,
        processor.system().ctx(),
        processor.system().clk(),
    );

    Ok(())
}

/// Loads two words from memory and replaces the top 8 elements of the stack with their
/// contents.
///
/// The operation works as follows:
/// - The memory address of the first word is retrieved from 13th stack element (position 12).
/// - Two consecutive words, starting at this address, are loaded from memory.
/// - Elements of these words are written to the top 8 elements of the stack (element-wise, in stack
///   order).
/// - Memory address (in position 12) is incremented by 8.
/// - All other stack elements remain the same.
///
/// # Errors
/// - Returns an error if the address is not aligned to a word boundary.
#[inline(always)]
pub(super) fn op_mstream<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    // The stack index where the memory address to load the words from is stored.
    const MEM_ADDR_STACK_IDX: usize = 12;

    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    // load two words from memory
    let addr_first_word = processor.stack().get(MEM_ADDR_STACK_IDX);
    let words = {
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;

        let first_word = processor.memory().read_word(ctx, addr_first_word, clk)?;
        tracer.record_memory_read_word(
            first_word,
            addr_first_word,
            processor.system().ctx(),
            processor.system().clk(),
        );

        let second_word = processor.memory().read_word(ctx, addr_second_word, clk)?;
        tracer.record_memory_read_word(
            second_word,
            addr_second_word,
            processor.system().ctx(),
            processor.system().clk(),
        );

        [first_word, second_word]
    };

    // Replace the stack elements with the elements from memory (in stack order). The word at
    // address `addr` is at the top of the stack.
    processor.stack().set_word(0, &words[0]);
    processor.stack().set_word(4, &words[1]);

    // increment the address by 8 (2 words)
    processor.stack().set(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

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
#[inline(always)]
pub(super) fn op_pipe<P: Processor>(
    processor: &mut P,
    tracer: &mut impl Tracer,
) -> Result<(), IoError> {
    /// WORD_SIZE, but as a `Felt`.
    const WORD_SIZE_FELT: Felt = Felt::new(4);
    /// The size of a double-word.
    const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

    // The stack index where the memory address to load the words from is stored.
    const MEM_ADDR_STACK_IDX: usize = 12;

    let clk = processor.system().clk();
    let ctx = processor.system().ctx();
    let addr_first_word = processor.stack().get(MEM_ADDR_STACK_IDX);
    let addr_second_word = addr_first_word + WORD_SIZE_FELT;

    // pop two words from the advice stack
    let words = processor.advice_provider().pop_stack_dword()?;
    tracer.record_advice_pop_stack_dword(words);

    // write the words to memory
    processor.memory().write_word(ctx, addr_first_word, clk, words[0])?;
    tracer.record_memory_write_word(
        words[0],
        addr_first_word,
        processor.system().ctx(),
        processor.system().clk(),
    );

    processor.memory().write_word(ctx, addr_second_word, clk, words[1])?;
    tracer.record_memory_write_word(
        words[1],
        addr_second_word,
        processor.system().ctx(),
        processor.system().clk(),
    );

    // Replace the elements on the stack with the word elements (in stack order).
    // words[0] goes to top positions (0-3), words[1] goes to positions (4-7).
    processor.stack().set_word(0, &words[0]);
    processor.stack().set_word(4, &words[1]);

    // increment the address by 8 (2 words)
    processor.stack().set(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

    Ok(())
}
