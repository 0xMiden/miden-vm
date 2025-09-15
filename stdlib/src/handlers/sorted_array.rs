use alloc::{vec, vec::Vec};

use miden_core::{EventId, Felt, LexicographicWord, Word};
use miden_processor::{AdviceMutation, EventError, MemoryError, ProcessState, get_mem_addr_range};

/// Qualified event names for `lowerbound` events.
pub const LOWERBOUND_ARRAY_EVENT_NAME: &str = "stdlib::collections::sorted_array::lowerbound_array";
pub const LOWERBOUND_KEY_VALUE_EVENT_NAME: &str =
    "stdlib::collections::sorted_array::lowerbound_key_value";

/// Constant Event ID for `lowerbound` events, derived via `EventId::from_name(EVENT_NAME)`.
pub const LOWERBOUND_ARRAY_EVENT_ID: EventId = EventId::from_u64(2382974753388103136);
pub const LOWERBOUND_KEY_VALUE_EVENT_ID: EventId = EventId::from_u64(486819235893213157);

/// Pushes onto the advice stack the first pointer in [start_ptr, end_ptr) such that
/// `mem[word_ptr] >= KEY` in lexicographic order of words. If all words are < KEY, returns end_ptr.
/// The array must be sorted in non-decreasing order.
///
/// Inputs:
///   Operand stack: [KEY, start_ptr, end_ptr, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Operand stack: [KEY, start_ptr, end_ptr, ...]
///   Advice stack: [maybe_key_ptr, was_key_found, ...]
///
/// # Errors
/// Returns an error if the provided word array is not sorted in non-decreasing order.
pub fn handle_lowerbound_array(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    push_lowerbound_result(process, 4)
}

/// Pushes onto the advice stack the first pointer in [start_ptr, end_ptr) such that
/// `mem[word_ptr] >= KEY` in lexicographic order of words. If all keys are < KEY, returns end_ptr.
/// The array must be a list of key-value pairs (word tuples) where all keys are in non-decreasing
/// order.
///
/// This event returns
///
/// Inputs:
///   Operand stack: [KEY, start_ptr, end_ptr, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Operand stack: [KEY, start_ptr, end_ptr, ...]
///   Advice stack: [maybe_key_ptr, was_key_found, ...]
///
/// # Errors
/// Returns an error if the keys are not sorted in non-decreasing order.
pub fn handle_lowerbound_key_value(
    process: &ProcessState,
) -> Result<Vec<AdviceMutation>, EventError> {
    push_lowerbound_result(process, 8)
}

/// Offsets for the push_lowerbound_result inputs from the top of the stack
const KEY_OFFSET: usize = 1;
const START_ADDR_OFFSET: usize = 5;
const END_ADDR_OFFSET: usize = 6;

fn push_lowerbound_result(
    process: &ProcessState,
    stride: u32,
) -> Result<Vec<AdviceMutation>, EventError> {
    // only support sorted arrays (stride = 4) and sorted key-value arrays (stride = 8)
    assert!(stride == 4 || stride == 8);

    // Read inputs from the stack
    let key = LexicographicWord::new(process.get_stack_word(KEY_OFFSET));
    let (start_addr, end_addr) = get_mem_addr_range(process, START_ADDR_OFFSET, END_ADDR_OFFSET)?;

    // Validate the start_addr is word-aligned (multiple of 4)
    if start_addr % 4 != 0 {
        return Err(MemoryError::unaligned_word_access(
            start_addr,
            process.ctx(),
            Felt::from(process.clk()),
            &(),
        )
        .into());
    }

    // Validate address range is valid
    if start_addr > end_addr {
        return Err(MemoryError::InvalidMemoryRange {
            start_addr: start_addr as u64,
            end_addr: end_addr as u64,
        }
        .into());
    }

    // Validate the end_addr is properly aligned (i.e. the entire array has size divisible by
    // stride)
    if (end_addr - start_addr) % stride != 0 {
        if stride == 4 {
            return Err(SortedArrayError::InvalidArrayRange { size: end_addr - start_addr }.into());
        } else {
            return Err(
                SortedArrayError::InvalidKeyValueRange { size: end_addr - start_addr }.into()
            );
        }
    }

    // If range is empty, result is end_ptr
    if start_addr == end_addr {
        return Ok(vec![AdviceMutation::extend_stack(vec![
            Felt::from(false),
            Felt::from(end_addr),
        ])]);
    }

    // Helper function to get a word from memory and convert it to a LexicographicWord
    let get_word = {
        |addr: u32| {
            process
                .get_mem_word(process.ctx(), addr)
                .map(|word| LexicographicWord::new(word.unwrap_or(Word::empty())))
        }
    };

    let mut was_key_found = false;
    let mut result = None;

    // Test the first element
    let mut previous_word = get_word(start_addr)?;
    if previous_word >= key {
        was_key_found = previous_word == key;
        result = Some(start_addr);
    }

    // Validate the entire array is non-decreasing and find the first element where `element >= key`
    let mut current_addr = start_addr + stride;
    while current_addr < end_addr {
        let current_word = get_word(current_addr)?;
        if current_word < previous_word {
            return Err(SortedArrayError::NotAscendingOrder {
                index: current_addr,
                value: current_word.into(),
                predecessor: previous_word.into(),
            }
            .into());
        }
        if current_word >= key && result.is_none() {
            was_key_found = current_word == key;
            result = Some(current_addr);
        }
        previous_word = current_word;
        current_addr += stride;
    }

    Ok(vec![AdviceMutation::extend_stack(vec![
        Felt::from(was_key_found),
        Felt::from(result.unwrap_or(end_addr)),
    ])])
}

// ERROR TYPES
// ================================================================================================

/// Error types that can occur during LOWERBOUND event operations.
#[derive(Debug, thiserror::Error)]
pub enum SortedArrayError {
    /// Elements are not sorted in non-decreasing order.
    #[error("element at index {index} ({value}) is smaller than the predecessor ({predecessor})")]
    NotAscendingOrder {
        index: u32,
        value: Word,
        predecessor: Word,
    },

    /// Last element is an incomplete word.
    #[error("array size must be divisible by 4, but was {size}")]
    InvalidArrayRange { size: u32 },

    /// Last key or value is an incomplete word.
    #[error("key-value array must have size divisible by 4 or 8, but was {size}")]
    InvalidKeyValueRange { size: u32 },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_id() {
        let expected_event_id = EventId::from_name(LOWERBOUND_ARRAY_EVENT_NAME);
        assert_eq!(LOWERBOUND_ARRAY_EVENT_ID, expected_event_id);

        let expected_event_id = EventId::from_name(LOWERBOUND_KEY_VALUE_EVENT_NAME);
        assert_eq!(LOWERBOUND_KEY_VALUE_EVENT_ID, expected_event_id);
    }
}
