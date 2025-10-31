use core::convert::TryFrom;

use miden_air::Felt;

use crate::{
    ErrorContext, ExecutionError, MemoryError,
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

    processor.stack().increment_size(tracer)?;
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
    tracer.record_memory_read_word(word, addr, processor.system().ctx(), processor.system().clk());

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
    tracer.record_memory_write_word(word, addr, processor.system().ctx(), processor.system().clk());

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
    tracer.record_memory_read_element(
        element,
        addr,
        processor.system().ctx(),
        processor.system().clk(),
    );

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
    tracer.record_memory_write_element(
        value,
        addr,
        processor.system().ctx(),
        processor.system().clk(),
    );

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
        tracer.record_memory_read_word(
            first_word,
            addr_first_word,
            processor.system().ctx(),
            processor.system().clk(),
        );

        let second_word = processor
            .memory()
            .read_word(ctx, addr_second_word, clk, err_ctx)
            .map_err(ExecutionError::MemoryError)?;
        tracer.record_memory_read_word(
            second_word,
            addr_second_word,
            processor.system().ctx(),
            processor.system().clk(),
        );

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
    tracer.record_memory_write_word(
        words[0],
        addr_first_word,
        processor.system().ctx(),
        processor.system().clk(),
    );

    processor
        .memory()
        .write_word(ctx, addr_second_word, clk, words[1], err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    tracer.record_memory_write_word(
        words[1],
        addr_second_word,
        processor.system().ctx(),
        processor.system().clk(),
    );

    // replace the elements on the stack with the word elements (in stack order)
    processor.stack().set_word(0, &words[1]);
    processor.stack().set_word(4, &words[0]);

    // increment the address by 8 (2 words)
    processor.stack().set(MEM_ADDR_STACK_IDX, addr_first_word + DOUBLE_WORD_SIZE);

    Ok(())
}

#[inline(always)]
pub(super) fn op_crypto_stream<P: Processor>(
    processor: &mut P,
    err_ctx: &impl ErrorContext,
    tracer: &mut impl Tracer,
) -> Result<(), ExecutionError> {
    const WORD_SIZE_FELT: Felt = Felt::new(4);
    const DOUBLE_WORD_SIZE: Felt = Felt::new(8);

    // Stack layout: [rate(8), capacity(4), src_ptr, dst_ptr, ...]
    const SRC_PTR_IDX: usize = 12;
    const DST_PTR_IDX: usize = 13;

    let ctx = processor.system().ctx();
    let clk = processor.system().clk();

    // Get source and destination pointers
    let src_addr = processor.stack().get(SRC_PTR_IDX);
    let dst_addr = processor.stack().get(DST_PTR_IDX);

    if src_addr == dst_addr {
        let addr_u64 = src_addr.as_int();
        let addr = match u32::try_from(addr_u64) {
            Ok(addr) => addr,
            Err(_) => {
                return Err(ExecutionError::MemoryError(MemoryError::address_out_of_bounds(
                    addr_u64, err_ctx,
                )));
            },
        };

        return Err(ExecutionError::MemoryError(MemoryError::IllegalMemoryAccess {
            ctx,
            addr,
            clk: Felt::from(clk),
        }));
    }

    // Load plaintext from source memory (2 words = 8 elements)
    let src_addr_word2 = src_addr + WORD_SIZE_FELT;
    let plaintext_word1 = processor
        .memory()
        .read_word(ctx, src_addr, clk, err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    tracer.record_memory_read_word(plaintext_word1, src_addr, ctx, clk);

    let plaintext_word2 = processor
        .memory()
        .read_word(ctx, src_addr_word2, clk, err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    tracer.record_memory_read_word(plaintext_word2, src_addr_word2, ctx, clk);

    // Get rate (keystream) from stack[0..7]
    let rate = [
        processor.stack().get(7),
        processor.stack().get(6),
        processor.stack().get(5),
        processor.stack().get(4),
        processor.stack().get(3),
        processor.stack().get(2),
        processor.stack().get(1),
        processor.stack().get(0),
    ];

    // Encrypt: ciphertext = plaintext + rate (element-wise addition in field)
    let ciphertext_word1 = [
        plaintext_word1[0] + rate[0],
        plaintext_word1[1] + rate[1],
        plaintext_word1[2] + rate[2],
        plaintext_word1[3] + rate[3],
    ];
    let ciphertext_word2 = [
        plaintext_word2[0] + rate[4],
        plaintext_word2[1] + rate[5],
        plaintext_word2[2] + rate[6],
        plaintext_word2[3] + rate[7],
    ];

    // Write ciphertext to destination memory
    let dst_addr_word2 = dst_addr + WORD_SIZE_FELT;
    processor
        .memory()
        .write_word(ctx, dst_addr, clk, ciphertext_word1.into(), err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    tracer.record_memory_write_word(ciphertext_word1.into(), dst_addr, ctx, clk);

    processor
        .memory()
        .write_word(ctx, dst_addr_word2, clk, ciphertext_word2.into(), err_ctx)
        .map_err(ExecutionError::MemoryError)?;
    tracer.record_memory_write_word(ciphertext_word2.into(), dst_addr_word2, ctx, clk);

    // Update stack[0..7] with ciphertext (becomes new rate for next hperm)
    // Stack order is reversed: stack[0] = top
    processor.stack().set_word(0, &ciphertext_word2.into());
    processor.stack().set_word(4, &ciphertext_word1.into());

    // Increment pointers by 8 (2 words)
    processor.stack().set(SRC_PTR_IDX, src_addr + DOUBLE_WORD_SIZE);
    processor.stack().set(DST_PTR_IDX, dst_addr + DOUBLE_WORD_SIZE);

    Ok(())
}
