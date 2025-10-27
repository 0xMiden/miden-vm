use alloc::vec::Vec;

use miden_core::{FMP_ADDR, FMP_INIT_VALUE, Felt, Operation, WORD_SIZE};

use crate::push_value_ops;

/// Returns the sequence of operations that initialize the frame pointer in memory.
///
/// This must be called at the beginning of a new execution context, i.e. at the start of the
/// program, and after a `CALL` or `DYNCALL` instruction.
pub(crate) fn fmp_initialization_sequence() -> Vec<Operation> {
    vec![
        Operation::Push(FMP_INIT_VALUE),
        Operation::Push(FMP_ADDR),
        Operation::MStore,
        Operation::Drop,
    ]
}

/// Increments the frame pointer to allocate space for the given number of locals.
///
/// This sequence must be inserted at the start of every procedure that uses local variables.
///
/// The number of locals is rounded up to the nearest multiple of the word size to ensure the frame
/// pointer is always word-aligned for operations that require it.
pub(crate) fn fmp_start_frame_sequence(num_locals: u16) -> Vec<Operation> {
    let locals_frame = Felt::from(num_locals.next_multiple_of(WORD_SIZE as u16));

    [Operation::Push(locals_frame)]
        .into_iter()
        .chain(add_fmp_to_stack_top())
        .chain(store_stack_top_to_fmp())
        .collect()
}

/// Decrements the frame pointer to deallocate space for the given number of locals.
///
/// This sequence must be inserted at the end of every procedure that uses local variables.
///
/// The number of locals is rounded up to the nearest multiple of the word size to ensure the frame
/// pointer is always word-aligned for operations that require it.
pub(crate) fn fmp_end_frame_sequence(num_locals: u16) -> Vec<Operation> {
    let locals_frame = Felt::from(num_locals.next_multiple_of(WORD_SIZE as u16));

    [Operation::Push(-locals_frame)]
        .into_iter()
        .chain(add_fmp_to_stack_top())
        .chain(store_stack_top_to_fmp())
        .collect()
}

/// Returns the sequence of operations that pushes the current frame pointer value plus the given
/// offset onto the stack.
///
/// To decrement the fmp, use a negative offset.
pub(crate) fn push_offset_fmp_sequence(offset: Felt) -> Vec<Operation> {
    push_value_ops(offset).into_iter().chain(add_fmp_to_stack_top()).collect()
}

// HELPERS
// ================================================================================================

/// Returns the sequence of operations that adds the current frame pointer value to the top of
/// the stack.
fn add_fmp_to_stack_top() -> impl Iterator<Item = Operation> {
    [
        // Compute the new frame pointer by adding the offset to the current frame pointer
        Operation::Push(FMP_ADDR),
        Operation::MLoad,
        Operation::Add,
    ]
    .into_iter()
}

/// Stores the value on the top of the stack back to memory.
fn store_stack_top_to_fmp() -> impl Iterator<Item = Operation> {
    [Operation::Push(FMP_ADDR), Operation::MStore, Operation::Drop].into_iter()
}
