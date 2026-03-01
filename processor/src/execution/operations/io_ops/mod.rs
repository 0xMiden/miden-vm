use super::{DOUBLE_WORD_SIZE, WORD_SIZE_FELT};
use crate::{
    Felt,
    errors::IoError,
    processor::{
        AdviceProviderInterface, MemoryInterface, Processor, StackInterface, SystemInterface,
    },
    tracer::{OperationHelperRegisters, Tracer},
};

#[cfg(test)]
mod tests;

// IO OPERATIONS
// ================================================================================================

/// Pops an element from the advice stack and pushes it onto the operand stack.
///
/// # Errors
/// Returns an error if the advice stack is empty.
#[inline(always)]
pub(super) fn op_advpop<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let value = processor.advice_provider_mut().pop_stack()?;
    tracer.record_advice_pop_stack(value);

    processor.stack_mut().increment_size()?;
    processor.stack_mut().set(0, value);

    Ok(OperationHelperRegisters::Empty)
}

/// Pops a word (4 elements) from the advice stack and overwrites the top word on the operand
/// stack with it.
///
/// # Errors
/// Returns an error if the advice stack contains fewer than four elements.
#[inline(always)]
pub(super) fn op_advpopw<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let word = processor.advice_provider_mut().pop_stack_word()?;
    tracer.record_advice_pop_stack_word(word);

    // Set word on stack (word[0] at top).
    processor.stack_mut().set_word(0, &word);

    Ok(OperationHelperRegisters::Empty)
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
pub(super) fn op_mloadw<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let addr = processor.stack().get(0);
    let ctx = processor.system().ctx();
    let clk = processor.system().clock();

    processor.stack_mut().decrement_size();

    let word = processor.memory_mut().read_word(ctx, addr, clk)?;
    tracer.record_memory_read_word(
        word,
        addr,
        processor.system().ctx(),
        processor.system().clock(),
    );

    // Set word on stack (word[0] at top).
    processor.stack_mut().set_word(0, &word);

    Ok(OperationHelperRegisters::Empty)
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
pub(super) fn op_mstorew<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
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
    let clk = processor.system().clock();

    processor.stack_mut().decrement_size();

    processor.memory_mut().write_word(ctx, addr, clk, word)?;
    tracer.record_memory_write_word(
        word,
        addr,
        processor.system().ctx(),
        processor.system().clock(),
    );

    Ok(OperationHelperRegisters::Empty)
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
pub(super) fn op_mload<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError> {
    let ctx = processor.system().ctx();
    let addr = processor.stack().get(0);

    let element = processor.memory_mut().read_element(ctx, addr)?;
    tracer.record_memory_read_element(
        element,
        addr,
        processor.system().ctx(),
        processor.system().clock(),
    );

    processor.stack_mut().set(0, element);

    Ok(OperationHelperRegisters::Empty)
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
pub(super) fn op_mstore<P, T>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError>
where
    P: Processor,
    T: Tracer<Processor = P>,
{
    let addr = processor.stack().get(0);
    let value = processor.stack().get(1);
    let ctx = processor.system().ctx();

    processor.stack_mut().decrement_size();

    processor.memory_mut().write_element(ctx, addr, value)?;
    tracer.record_memory_write_element(
        value,
        addr,
        processor.system().ctx(),
        processor.system().clock(),
    );

    Ok(OperationHelperRegisters::Empty)
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
pub(super) fn op_mstream<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError> {
    // The stack index where the memory address to load the words from is stored.
    const MEM_ADDR_STACK_IDX: usize = 12;

    let ctx = processor.system().ctx();
    let clk = processor.system().clock();

    // load two words from memory
    let addr_first_word = processor.stack().get(MEM_ADDR_STACK_IDX);
    let words = {
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;

        let first_word = processor.memory_mut().read_word(ctx, addr_first_word, clk)?;
        let second_word = processor.memory_mut().read_word(ctx, addr_second_word, clk)?;

        tracer.record_memory_read_dword([first_word, second_word], addr_first_word, ctx, clk);

        [first_word, second_word]
    };

    // Replace the stack elements with the elements from memory (in stack order). The word at
    // address `addr` is at the top of the stack.
    processor.stack_mut().set_word(0, &words[0]);
    processor.stack_mut().set_word(4, &words[1]);

    // increment the address by 8 (2 words)
    processor
        .stack_mut()
        .set(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

    Ok(OperationHelperRegisters::Empty)
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
pub(super) fn op_pipe<P: Processor, T: Tracer>(
    processor: &mut P,
    tracer: &mut T,
) -> Result<OperationHelperRegisters, IoError> {
    /// WORD_SIZE, but as a `Felt`.
    const WORD_SIZE_FELT: Felt = Felt::new(4);
    /// The size of a double-word.
    const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

    // The stack index where the memory address to load the words from is stored.
    const MEM_ADDR_STACK_IDX: usize = 12;

    let clk = processor.system().clock();
    let ctx = processor.system().ctx();
    let addr_first_word = processor.stack().get(MEM_ADDR_STACK_IDX);
    let addr_second_word = addr_first_word + WORD_SIZE_FELT;

    // pop two words from the advice stack
    let words = processor.advice_provider_mut().pop_stack_dword()?;

    // write the words to memory
    processor.memory_mut().write_word(ctx, addr_first_word, clk, words[0])?;
    processor.memory_mut().write_word(ctx, addr_second_word, clk, words[1])?;

    tracer.record_pipe(words, addr_first_word, ctx, clk);

    // Replace the elements on the stack with the word elements (in stack order).
    // words[0] goes to top positions (0-3), words[1] goes to positions (4-7).
    processor.stack_mut().set_word(0, &words[0]);
    processor.stack_mut().set_word(4, &words[1]);

    // increment the address by 8 (2 words)
    processor
        .stack_mut()
        .set(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

    Ok(OperationHelperRegisters::Empty)
}
