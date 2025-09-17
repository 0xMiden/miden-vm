use miden_air::Felt;

use crate::{
    ErrorContext, ExecutionError,
    fast::Tracer,
    processor::{
        AdviceProviderInterface, MemoryInterface, Processor, StackInterface, SystemInterface,
    },
};

#[inline(always)]
pub(super) fn op_advpop<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let value = processor
        .advice_provider()
        .pop_stack()
        .map_err(|err| ExecutionError::advice_error(err, processor.system().clk(), err_ctx))?;
    tracer.record_advice_pop_stack(value);

    processor.stack().increment_size(tracer);
    processor.stack().set(0, value);

    Ok(())
}

#[inline(always)]
pub(super) fn op_advpopw<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let word = processor
        .advice_provider()
        .pop_stack_word()
        .map_err(|err| ExecutionError::advice_error(err, processor.system().clk(), err_ctx))?;
    tracer.record_advice_pop_stack_word(word);

    processor.stack().set_word(0, &word);

    Ok(())
}

#[inline(always)]
pub(super) fn op_mloadw<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let addr = processor.stack().get(0);
    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    processor.stack().decrement_size(tracer);

    let word = processor
        .memory()
        .read_word(ctx, addr, clk, err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    tracer.record_memory_read_word(word, addr);

    processor.stack().set_word(0, &word);

    Ok(())
}

#[inline(always)]
pub(super) fn op_mstorew<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let addr = processor.stack().get(0);
    let word = processor.stack().get_word(1);
    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    processor.stack().decrement_size(tracer);

    processor
        .memory()
        .write_word(ctx, addr, clk, word, err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    Ok(())
}

#[inline(always)]
pub(super) fn op_mload<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let ctx = processor.system().ctx();
    let addr = processor.stack().get(0);

    let element = processor
        .memory()
        .read_element(ctx, addr, err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    tracer.record_memory_read_element(element, addr);

    processor.stack().set(0, element);

    Ok(())
}

#[inline(always)]
pub(super) fn op_mstore<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    let addr = processor.stack().get(0);
    let value = processor.stack().get(1);
    let ctx = processor.system().ctx();

    processor.stack().decrement_size(tracer);

    processor
        .memory()
        .write_element(ctx, addr, value, err_ctx)
        .map_err(ExecutionError::MemoryError)?;

    Ok(())
}

#[inline(always)]
pub(super) fn op_mstream<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    /// WORD_SIZE, but as a `Felt`.
    const WORD_SIZE_FELT: Felt = Felt::new(4);
    /// The size of a double-word.
    const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

    // The stack index where the memory address to load the words from is stored.
    const MEM_ADDR_STACK_IDX: usize = 12;

    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    // load two words from memory
    let addr_first_word = processor.stack().get(MEM_ADDR_STACK_IDX);
    let words = {
        let addr_second_word = addr_first_word + WORD_SIZE_FELT;

        let first_word = processor
            .memory()
            .read_word(ctx, addr_first_word, clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        tracer.record_memory_read_word(first_word, addr_first_word);

        let second_word = processor
            .memory()
            .read_word(ctx, addr_second_word, clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        tracer.record_memory_read_word(second_word, addr_second_word);

        [first_word, second_word]
    };

    // Replace the stack elements with the elements from memory (in stack order). The word at
    // address `addr + 4` is at the top of the stack.
    processor.stack().set_word(0, &words[1]);
    processor.stack().set_word(4, &words[0]);

    // increment the address by 8 (2 words)
    processor.stack().set(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

    Ok(())
}

#[inline(always)]
pub(super) fn op_pipe<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
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
    let words = processor
        .advice_provider()
        .pop_stack_dword()
        .map_err(|err| ExecutionError::advice_error(err, clk, err_ctx))?;
    tracer.record_advice_pop_stack_dword(words);

    // write the words to memory
    processor
        .memory()
        .write_word(ctx, addr_first_word, clk, words[0], err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    processor
        .memory()
        .write_word(ctx, addr_second_word, clk, words[1], err_ctx)
        .map_err(ExecutionError::MemoryError)?;

    // replace the elements on the stack with the word elements (in stack order)
    processor.stack().set_word(0, &words[1]);
    processor.stack().set_word(4, &words[0]);

    // increment the address by 8 (2 words)
    processor.stack().set(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

    Ok(())
}
