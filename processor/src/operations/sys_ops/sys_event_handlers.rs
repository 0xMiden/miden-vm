use alloc::vec::Vec;

use miden_core::{
    Felt, WORD_SIZE, Word, ZERO,
    crypto::hash::Rpo256,
    field::{BasedVectorSpace, Field, PrimeCharacteristicRing, QuadFelt},
    sys_events::SystemEvent,
};

use crate::{AdviceError, MemoryError, PrimeField64, ProcessorState, errors::OperationError};

// SYSTEM EVENT ERROR
// ================================================================================================

/// Context-free error type for system event handlers.
///
/// This enum captures error conditions without source location information.
/// The caller wraps it with context when converting to `ExecutionError`.
#[derive(Debug, thiserror::Error)]
pub enum SystemEventError {
    #[error(transparent)]
    Advice(#[from] AdviceError),
    #[error(transparent)]
    Operation(#[from] OperationError),
    #[error(transparent)]
    Memory(#[from] MemoryError),
}

/// The offset of the domain value on the stack in the `hdword_to_map_with_domain` system event.
/// Offset accounts for the event ID at position 0 on the stack.
pub const HDWORD_TO_MAP_WITH_DOMAIN_DOMAIN_OFFSET: usize = 9;

pub fn handle_system_event(
    process: &mut ProcessorState,
    system_event: SystemEvent,
) -> Result<(), SystemEventError> {
    match system_event {
        SystemEvent::MerkleNodeMerge => merge_merkle_nodes(process),
        SystemEvent::MerkleNodeToStack => copy_merkle_node_to_adv_stack(process),
        SystemEvent::MapValueToStack => copy_map_value_to_adv_stack(process, false, 0),
        SystemEvent::MapValueCountToStack => copy_map_value_length_to_adv_stack(process),
        SystemEvent::MapValueToStackN0 => copy_map_value_to_adv_stack(process, true, 0),
        SystemEvent::MapValueToStackN4 => copy_map_value_to_adv_stack(process, true, 4),
        SystemEvent::MapValueToStackN8 => copy_map_value_to_adv_stack(process, true, 8),
        SystemEvent::HasMapKey => push_key_presence_flag(process),
        SystemEvent::Ext2Inv => push_ext2_inv_result(process),
        SystemEvent::U32Clz => push_leading_zeros(process),
        SystemEvent::U32Ctz => push_trailing_zeros(process),
        SystemEvent::U32Clo => push_leading_ones(process),
        SystemEvent::U32Cto => push_trailing_ones(process),
        SystemEvent::ILog2 => push_ilog2(process),
        SystemEvent::MemToMap => insert_mem_values_into_adv_map(process),
        SystemEvent::HdwordToMap => insert_hdword_into_adv_map(process, ZERO),
        SystemEvent::HdwordToMapWithDomain => {
            let domain = process.get_stack_item(HDWORD_TO_MAP_WITH_DOMAIN_DOMAIN_OFFSET);
            insert_hdword_into_adv_map(process, domain)
        },
        SystemEvent::HqwordToMap => insert_hqword_into_adv_map(process),
        SystemEvent::HpermToMap => insert_hperm_into_adv_map(process),
    }
}

/// Reads elements from memory at the specified range and inserts them into the advice map under
/// the key `KEY` located at the top of the stack.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, KEY, start_addr, end_addr, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: values}
/// ```
///
/// Where `values` are the elements located in `memory[start_addr..end_addr]`.
///
/// # Errors
/// Returns an error:
/// - `start_addr` is greater than or equal to 2^32.
/// - `end_addr` is greater than or equal to 2^32.
/// - `start_addr` > `end_addr`.
fn insert_mem_values_into_adv_map(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    let addr_range = process.get_mem_addr_range(5, 6)?;
    let ctx = process.ctx();

    let mut values = Vec::with_capacity(addr_range.len() * WORD_SIZE);
    for addr in addr_range {
        let mem_value = process.get_mem_value(ctx, addr).unwrap_or(ZERO);
        values.push(mem_value);
    }

    let key = process.get_stack_word(1);
    process.advice_provider_mut().insert_into_map(key, values)?;
    Ok(())
}

/// Reads two words from the operand stack and inserts them into the advice map under the key
/// defined by the hash of these words.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, A, B, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: [A, B]}
/// ```
///
/// Where A is the first word after event_id (positions 1-4) and B is the second (positions 5-8).
/// KEY is computed as `hash(A || B, domain)`, which matches `hmerge` on stack `[A, B, ...]`.
fn insert_hdword_into_adv_map(
    process: &mut ProcessorState,
    domain: Felt,
) -> Result<(), SystemEventError> {
    // Stack: [event_id, A, B, ...] where A is at positions 1-4, B at positions 5-8.
    let a = process.get_stack_word(1);
    let b = process.get_stack_word(5);

    // Hash as [A, B] to match `hmerge` behavior directly.
    let key = Rpo256::merge_in_domain(&[a, b], domain);

    // Store values as [A, B] matching the hash order.
    // Retrieval with `padw adv_loadw padw adv_loadw swapw` produces [A, B] on operand stack.
    let mut values = Vec::with_capacity(2 * WORD_SIZE);
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(a));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(b));

    process.advice_provider_mut().insert_into_map(key, values)?;
    Ok(())
}

/// Reads four words from the operand stack and inserts them into the advice map under the key
/// defined by the hash of these words.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, A, B, C, D, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: [A, B, C, D]} (16 elements)
/// ```
///
/// Where A is at positions 1-4, B at 5-8, C at 9-12, D at 13-16.
/// KEY is computed as `hash_elements([A, B, C, D].concat())` (two-round absorption).
fn insert_hqword_into_adv_map(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    // Stack: [event_id, A, B, C, D, ...] where A is at positions 1-4, B at 5-8, etc.
    let a = process.get_stack_word(1);
    let b = process.get_stack_word(5);
    let c = process.get_stack_word(9);
    let d = process.get_stack_word(13);

    // Hash in natural stack order [A, B, C, D].
    let key = Rpo256::hash_elements(&[*a, *b, *c, *d].concat());

    // Store values in [A, B, C, D] order.
    let mut values = Vec::with_capacity(4 * WORD_SIZE);
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(a));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(b));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(c));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(d));

    process.advice_provider_mut().insert_into_map(key, values)?;
    Ok(())
}

/// Reads three words from the operand stack and inserts the rate portion into the advice map
/// under the key defined by applying an RPO permutation to all three words.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, RATE1, RATE2, CAP, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: [RATE1, RATE2]} (8 elements from rate portion)
/// ```
///
/// Where `KEY` is computed by applying `hperm` to the 12-element state and extracting the digest.
/// The state is read as `[RATE1, RATE2, CAP]` matching the LE sponge convention.
fn insert_hperm_into_adv_map(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    // Read the 12-element state from stack positions 1-12.
    // State layout: [RATE1, RATE2, CAP] where RATE1 is at positions 1-4.
    // We read in reverse order to build the state array.
    let mut state = [
        process.get_stack_item(12),
        process.get_stack_item(11),
        process.get_stack_item(10),
        process.get_stack_item(9),
        process.get_stack_item(8),
        process.get_stack_item(7),
        process.get_stack_item(6),
        process.get_stack_item(5),
        process.get_stack_item(4),
        process.get_stack_item(3),
        process.get_stack_item(2),
        process.get_stack_item(1),
    ];

    // Extract the rate portion (first 8 elements) as values to store.
    let values = state[Rpo256::RATE_RANGE].to_vec();

    // Apply permutation and extract digest as the key.
    Rpo256::apply_permutation(&mut state);
    let key = Word::new(
        state[Rpo256::DIGEST_RANGE]
            .try_into()
            .expect("failed to extract digest from state"),
    );

    process.advice_provider_mut().insert_into_map(key, values)?;
    Ok(())
}

/// Creates a new Merkle tree in the advice provider by combining Merkle trees with the
/// specified roots. The root of the new tree is defined as `Hash(LEFT_ROOT, RIGHT_ROOT)`.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, RIGHT_ROOT, LEFT_ROOT, ...]
///   Merkle store: {RIGHT_ROOT, LEFT_ROOT}
///
/// Outputs:
///   Merkle store: {RIGHT_ROOT, LEFT_ROOT, hash(LEFT_ROOT, RIGHT_ROOT)}
/// ```
///
/// After the operation, both the original trees and the new tree remains in the advice
/// provider (i.e., the input trees are not removed).
///
/// It is not checked whether the provided roots exist as Merkle trees in the advice provider.
fn merge_merkle_nodes(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    // fetch the arguments from the stack
    let lhs = process.get_stack_word(5);
    let rhs = process.get_stack_word(1);

    // perform the merge
    process.advice_provider_mut().merge_roots(lhs, rhs)?;

    Ok(())
}

/// Pushes a node of the Merkle tree specified by the values on the top of the operand stack
/// onto the advice stack in structural order for consumption by `AdvPopW`.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, depth, index, TREE_ROOT, ...]
///   Advice stack: [...]
///   Merkle store: {TREE_ROOT<-NODE}
///
/// Outputs:
///   Advice stack: [NODE, ...]
///   Merkle store: {TREE_ROOT<-NODE}
/// ```
///
/// # Errors
/// Returns an error if:
/// - Merkle tree for the specified root cannot be found in the advice provider.
/// - The specified depth is either zero or greater than the depth of the Merkle tree identified by
///   the specified root.
/// - Value of the node at the specified depth and index is not known to the advice provider.
fn copy_merkle_node_to_adv_stack(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    // Stack at this point is `[event_id, d, i, R, ...]` where:
    // - `d` is depth,
    // - `i` is index,
    // - `R` is the Merkle root as it appears on the operand stack.
    let depth = process.get_stack_item(1);
    let index = process.get_stack_item(2);
    // Read the root in structural (little-endian) word order from the operand stack.
    let root = process.get_stack_word(3);

    let node = process.advice_provider().get_tree_node(root, depth, index)?;

    // push_stack_word pushes in reverse order so that node[0] ends up on top of advice stack.
    // AdvPopW then pops the word maintaining structural order on the operand stack.
    process.advice_provider_mut().push_stack_word(&node);

    Ok(())
}

/// Pushes a list of field elements onto the advice stack. The list is looked up in the advice
/// map using the specified word from the operand stack as the key.
///
/// If `include_len` is set to true, the number of elements in the value is also pushed onto the
/// advice stack.
///
/// If `pad_to` is not equal to 0, the elements list obtained from the advice map will be padded
/// with zeros, increasing its length to the next multiple of `pad_to`.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, KEY, ...]
///   Advice stack: [...]
///   Advice map: {KEY: values}
///
/// Outputs:
///   Advice stack: [values_len?, values, padding?, ...]
///   Advice map: {KEY: values}
/// ```
///
/// # Errors
/// Returns an error if the required key was not found in the key-value map.
fn copy_map_value_to_adv_stack(
    process: &mut ProcessorState,
    include_len: bool,
    pad_to: u8,
) -> Result<(), SystemEventError> {
    let key = process.get_stack_word(1);

    process.advice_provider_mut().push_from_map(key, include_len, pad_to)?;

    Ok(())
}

/// Pushes a number of elements in a list of field elements onto the advice stack. The list is
/// looked up in the advice map using the specified word from the operand stack as the key.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, KEY, ...]
///   Advice stack: [...]
///   Advice map: {KEY: values}
///
/// Outputs:
///   Advice stack: [values.len(), ...]
///   Advice map: {KEY: values}
/// ```
///
/// # Errors
/// Returns an error if the required key was not found in the key-value map.
fn copy_map_value_length_to_adv_stack(
    process: &mut ProcessorState,
) -> Result<(), SystemEventError> {
    let key = process.get_stack_word(1);
    let advice_provider = process.advice_provider_mut();

    let values_len = advice_provider
        .get_mapped_values(&key)
        .ok_or(AdviceError::MapKeyNotFound { key })?
        .len();

    // Note: we assume values_len fits within the field modulus. This is always true
    // in practice since the field modulus (2^64 - 2^32 + 1) is much larger than any
    // practical vector length that could fit in memory.
    advice_provider.push_stack(Felt::new(values_len as u64));

    Ok(())
}

/// Checks whether the key placed at the top of the operand stack exists in the advice map and
/// pushes the resulting flag onto the advice stack. If the advice map has the provided key, `1`
/// will be pushed to the advice stack, `0` otherwise.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, KEY, ...]
///   Advice stack:  [...]
///
/// Outputs:
///   Advice stack: [has_mapkey, ...]
/// ```
pub fn push_key_presence_flag(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    let map_key = process.get_stack_word(1);

    let presence_flag = process.advice_provider().contains_map_key(&map_key);
    process.advice_provider_mut().push_stack(Felt::from_bool(presence_flag));

    Ok(())
}

/// Given an element in a quadratic extension field on the top of the stack (low coefficient
/// closer to top), computes its multiplicative inverse and pushes the result onto the advice
/// stack.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, a0, a1, ...] where a = a0 + a1*x
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [..., b0, b1] where b1 is on top
/// ```
///
/// Where `(b0, b1)` is the multiplicative inverse of the extension field element `(a0, a1)`.
/// After two AdvPops, the operand stack will have [b0, b1, ...].
///
/// # Errors
/// Returns an error if the input is a zero element in the extension field.
fn push_ext2_inv_result(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    // Stack layout: [event_id, a0, a1, ...] with event_id on top, a0 (low) at position 1
    // Read from positions 1 and 2 (skipping event_id at position 0)
    let coef0 = process.get_stack_item(1); // low coefficient
    let coef1 = process.get_stack_item(2); // high coefficient

    let element = QuadFelt::from_basis_coefficients_fn(|i: usize| [coef0, coef1][i]);
    if element == QuadFelt::ZERO {
        return Err(OperationError::DivideByZero.into());
    }
    let result = element.inverse();
    let result = result.as_basis_coefficients_slice();

    // Push for LE output: after two AdvPops, result should be [b0', b1', ...] with b0' on top
    // AdvPop pops from advice top, so push result[0] first (goes to bottom), result[1] second (on
    // top) After AdvPop #1: gets result[1], stack becomes [result[1], b0, b1, ...]
    // After AdvPop #2: gets result[0], stack becomes [result[0], result[1], b0, b1, ...]
    process.advice_provider_mut().push_stack(result[0]);
    process.advice_provider_mut().push_stack(result[1]);
    Ok(())
}

/// Pushes the number of the leading zeros of the top stack element onto the advice stack.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [leading_zeros, ...]
/// ```
fn push_leading_zeros(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    push_transformed_stack_top(process, |stack_top| Felt::from_u32(stack_top.leading_zeros()))
}

/// Pushes the number of the trailing zeros of the top stack element onto the advice stack.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [trailing_zeros, ...]
/// ```
fn push_trailing_zeros(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    push_transformed_stack_top(process, |stack_top| Felt::from_u32(stack_top.trailing_zeros()))
}

/// Pushes the number of the leading ones of the top stack element onto the advice stack.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [leading_ones, ...]
/// ```
fn push_leading_ones(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    push_transformed_stack_top(process, |stack_top| Felt::from_u32(stack_top.leading_ones()))
}

/// Pushes the number of the trailing ones of the top stack element onto the advice stack.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [trailing_ones, ...]
/// ```
fn push_trailing_ones(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    push_transformed_stack_top(process, |stack_top| Felt::from_u32(stack_top.trailing_ones()))
}

/// Pushes the base 2 logarithm of the top stack element, rounded down.
///
/// ```text
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [ilog2(n), ...]
/// ```
///
/// # Errors
/// Returns an error if the logarithm argument (top stack element) equals `ZERO`.
fn push_ilog2(process: &mut ProcessorState) -> Result<(), SystemEventError> {
    let n = process.get_stack_item(1).as_canonical_u64();
    if n == 0 {
        return Err(OperationError::LogArgumentZero.into());
    }
    let ilog2 = Felt::from_u32(n.ilog2());
    process.advice_provider_mut().push_stack(ilog2);

    Ok(())
}

// HELPER METHODS
// --------------------------------------------------------------------------------------------

/// Gets the top stack element, applies a provided function to it and pushes it to the advice
/// provider.
fn push_transformed_stack_top(
    process: &mut ProcessorState,
    f: impl FnOnce(u32) -> Felt,
) -> Result<(), SystemEventError> {
    let stack_top = process.get_stack_item(1);
    let stack_top: u32 = stack_top
        .as_canonical_u64()
        .try_into()
        .map_err(|_| OperationError::NotU32Values { values: vec![stack_top] })?;
    let transformed_stack_top = f(stack_top);
    process.advice_provider_mut().push_stack(transformed_stack_top);
    Ok(())
}
