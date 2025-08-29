use alloc::vec::Vec;

use miden_core::{
    Felt, FieldElement, QuadFelt, WORD_SIZE, Word, ZERO,
    crypto::{
        hash::Rpo256,
        merkle::{EmptySubtreeRoots, SMT_DEPTH, Smt},
    },
    sys_events::SystemEvent,
};

use crate::{ExecutionError, MemoryError, ProcessState, errors::ErrorContext};

/// The offset of the domain value on the stack in the `hdword_to_map_with_domain` system event.
/// Offset accounts for the event ID at position 0 on the stack.
pub const HDWORD_TO_MAP_WITH_DOMAIN_DOMAIN_OFFSET: usize = 9;

/// Falcon signature prime.
const M: u64 = 12289;

pub fn handle_system_event(
    process: &mut ProcessState,
    system_event: SystemEvent,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    match system_event {
        SystemEvent::MerkleNodeMerge => merge_merkle_nodes(process, err_ctx),
        SystemEvent::MerkleNodeToStack => copy_merkle_node_to_adv_stack(process, err_ctx),
        SystemEvent::MapValueToStack => copy_map_value_to_adv_stack(process, false, err_ctx),
        SystemEvent::MapValueToStackN => copy_map_value_to_adv_stack(process, true, err_ctx),
        SystemEvent::HasMapKey => push_key_presence_flag(process),
        SystemEvent::U64Div => push_u64_div_result(process, err_ctx),
        SystemEvent::FalconDiv => push_falcon_mod_result(process, err_ctx),
        SystemEvent::Ext2Inv => push_ext2_inv_result(process, err_ctx),
        SystemEvent::SmtPeek => push_smtpeek_result(process, err_ctx),
        SystemEvent::U32Clz => push_leading_zeros(process, err_ctx),
        SystemEvent::U32Ctz => push_trailing_zeros(process, err_ctx),
        SystemEvent::U32Clo => push_leading_ones(process, err_ctx),
        SystemEvent::U32Cto => push_trailing_ones(process, err_ctx),
        SystemEvent::ILog2 => push_ilog2(process, err_ctx),
        SystemEvent::MemToMap => insert_mem_values_into_adv_map(process, err_ctx),
        SystemEvent::HdwordToMap => insert_hdword_into_adv_map(process, ZERO, err_ctx),
        SystemEvent::HdwordToMapWithDomain => {
            let domain = process.get_stack_item(HDWORD_TO_MAP_WITH_DOMAIN_DOMAIN_OFFSET);
            insert_hdword_into_adv_map(process, domain, err_ctx)
        },
        SystemEvent::HqwordToMap => insert_hqword_into_adv_map(process, err_ctx),
        SystemEvent::HpermToMap => insert_hperm_into_adv_map(process, err_ctx),
    }
}

/// Reads elements from memory at the specified range and inserts them into the advice map under
/// the key `KEY` located at the top of the stack.
///
/// Inputs:
///   Operand stack: [event_id, KEY, start_addr, end_addr, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: values}
///
/// Where `values` are the elements located in memory[start_addr..end_addr].
///
/// # Errors
/// Returns an error:
/// - `start_addr` is greater than or equal to 2^32.
/// - `end_addr` is greater than or equal to 2^32.
/// - `start_addr` > `end_addr`.
fn insert_mem_values_into_adv_map(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let (start_addr, end_addr) =
        get_mem_addr_range(process, 5, 6).map_err(ExecutionError::MemoryError)?;
    let ctx = process.ctx();

    let mut values = Vec::with_capacity(((end_addr - start_addr) as usize) * WORD_SIZE);
    for addr in start_addr..end_addr {
        let mem_value = process.get_mem_value(ctx, addr).unwrap_or(ZERO);
        values.push(mem_value);
    }

    let key = process.get_stack_word(1);
    process
        .advice_provider_mut()
        .insert_into_map(key, values)
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))
}

/// Reads two words from the operand stack and inserts them into the advice map under the key
/// defined by the hash of these words.
///
/// Inputs:
///   Operand stack: [event_id, B, A, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: [a0, a1, a2, a3, b0, b1, b2, b3]}
///
/// Where KEY is computed as hash(A || B, domain), where domain is provided via the immediate
/// value.
fn insert_hdword_into_adv_map(
    process: &mut ProcessState,
    domain: Felt,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    // get the top two words from the stack and hash them to compute the key value
    let word0 = process.get_stack_word(1);
    let word1 = process.get_stack_word(5);
    let key = Rpo256::merge_in_domain(&[word1, word0], domain);

    // build a vector of values from the two word and insert it into the advice map under the
    // computed key
    let mut values = Vec::with_capacity(2 * WORD_SIZE);
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(word1));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(word0));

    process
        .advice_provider_mut()
        .insert_into_map(key, values)
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))
}

/// Reads four words from the operand stack and inserts them into the advice map under the key
/// defined by the hash of these words.
///
/// Inputs:
///   Operand stack: [event_id, D, C, B, A, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: [A', B', C', D'])}
///
/// Where:
/// - KEY is the hash computed as hash(hash(hash(A || B) || C) || D) with domain=0.
/// - A' (and other words with `'`) is the A word with the reversed element order: A = [a3, a2, a1,
///   a0], A' = [a0, a1, a2, a3].
fn insert_hqword_into_adv_map(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    // get the top four words from the stack and hash them to compute the key value
    let word0 = process.get_stack_word(1);
    let word1 = process.get_stack_word(5);
    let word2 = process.get_stack_word(9);
    let word3 = process.get_stack_word(13);
    let key = Rpo256::hash_elements(&[*word3, *word2, *word1, *word0].concat());

    // build a vector of values from the two word and insert it into the advice map under the
    // computed key
    let mut values = Vec::with_capacity(4 * WORD_SIZE);
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(word3));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(word2));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(word1));
    values.extend_from_slice(&Into::<[Felt; WORD_SIZE]>::into(word0));

    process
        .advice_provider_mut()
        .insert_into_map(key, values)
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))
}

/// Reads three words from the operand stack and inserts the top two words into the advice map
/// under the key defined by applying an RPO permutation to all three words.
///
/// Inputs:
///   Operand stack: [event_id, B, A, C, ...]
///   Advice map: {...}
///
/// Outputs:
///   Advice map: {KEY: [a0, a1, a2, a3, b0, b1, b2, b3]}
///
/// Where KEY is computed by extracting the digest elements from hperm([C, A, B]). For example,
/// if C is [0, d, 0, 0], KEY will be set as hash(A || B, d).
fn insert_hperm_into_adv_map(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    // read the state from the stack
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

    // get the values to be inserted into the advice map from the state
    let values = state[Rpo256::RATE_RANGE].to_vec();

    // apply the permutation to the state and extract the key from it
    Rpo256::apply_permutation(&mut state);
    let key = Word::new(
        state[Rpo256::DIGEST_RANGE]
            .try_into()
            .expect("failed to extract digest from state"),
    );

    process
        .advice_provider_mut()
        .insert_into_map(key, values)
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))
}

/// Creates a new Merkle tree in the advice provider by combining Merkle trees with the
/// specified roots. The root of the new tree is defined as `Hash(LEFT_ROOT, RIGHT_ROOT)`.
///
/// Inputs:
///   Operand stack: [event_id, RIGHT_ROOT, LEFT_ROOT, ...]
///   Merkle store: {RIGHT_ROOT, LEFT_ROOT}
///
/// Outputs:
///   Merkle store: {RIGHT_ROOT, LEFT_ROOT, hash(LEFT_ROOT, RIGHT_ROOT)}
///
/// After the operation, both the original trees and the new tree remains in the advice
/// provider (i.e., the input trees are not removed).
///
/// It is not checked whether the provided roots exist as Merkle trees in the advide providers.
fn merge_merkle_nodes(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    // fetch the arguments from the stack
    let lhs = process.get_stack_word(5);
    let rhs = process.get_stack_word(1);

    // perform the merge
    process
        .advice_provider_mut()
        .merge_roots(lhs, rhs)
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))?;

    Ok(())
}

/// Pushes a node of the Merkle tree specified by the values on the top of the operand stack
/// onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, depth, index, TREE_ROOT, ...]
///   Advice stack: [...]
///   Merkle store: {TREE_ROOT<-NODE}
///
/// Outputs:
///   Advice stack: [NODE, ...]
///   Merkle store: {TREE_ROOT<-NODE}
///
/// # Errors
/// Returns an error if:
/// - Merkle tree for the specified root cannot be found in the advice provider.
/// - The specified depth is either zero or greater than the depth of the Merkle tree identified by
///   the specified root.
/// - Value of the node at the specified depth and index is not known to the advice provider.
fn copy_merkle_node_to_adv_stack(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let depth = process.get_stack_item(1);
    let index = process.get_stack_item(2);
    let root = process.get_stack_word(3);

    let node = process
        .advice_provider()
        .get_tree_node(root, &depth, &index)
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))?;

    process.advice_provider_mut().push_stack_word(&node);

    Ok(())
}

/// Pushes a list of field elements onto the advice stack. The list is looked up in the advice
/// map using the specified word from the operand stack as the key. If `include_len` is set to
/// true, the number of elements in the value is also pushed onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, KEY, ...]
///   Advice stack: [...]
///   Advice map: {KEY: values}
///
/// Outputs:
///   Advice stack: [values_len?, values, ...]
///   Advice map: {KEY: values}
///
///
/// # Errors
/// Returns an error if the required key was not found in the key-value map.
fn copy_map_value_to_adv_stack(
    process: &mut ProcessState,
    include_len: bool,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let key = process.get_stack_word(1);
    process
        .advice_provider_mut()
        .push_from_map(key, include_len)
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))?;

    Ok(())
}

/// Checks whether the key placed at the top of the operand stack exists in the advice map and
/// pushes the resulting flag onto the advice stack. If the advice map has the provided key, `1`
/// will be pushed to the advice stack, `0` otherwise.
///
/// Inputs:
///   Operand stack: [event_id, KEY, ...]
///   Advice stack:  [...]
///
/// Outputs:
///   Advice stack: [has_mapkey, ...]
pub fn push_key_presence_flag(process: &mut ProcessState) -> Result<(), ExecutionError> {
    let map_key = process.get_stack_word(1);

    let presence_flag = process.advice_provider().contains_map_key(&map_key);
    process.advice_provider_mut().push_stack(Felt::from(presence_flag));

    Ok(())
}

/// Pushes the result of [u64] division (both the quotient and the remainder) onto the advice
/// stack.
///
/// Inputs:
///   Operand stack: [event_id, b1, b0, a1, a0, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [q0, q1, r0, r1, ...]
///
/// Where (a0, a1) and (b0, b1) are the 32-bit limbs of the dividend and the divisor
/// respectively (with a0 representing the 32 lest significant bits and a1 representing the
/// 32 most significant bits). Similarly, (q0, q1) and (r0, r1) represent the quotient and
/// the remainder respectively.
///
/// # Errors
/// Returns an error if the divisor is ZERO.
fn push_u64_div_result(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let divisor = {
        let divisor_hi = process.get_stack_item(1).as_int();
        let divisor_lo = process.get_stack_item(2).as_int();

        // Ensure the divisor is a pair of u32 values
        if divisor_hi > u32::MAX.into() {
            return Err(ExecutionError::not_u32_value(Felt::new(divisor_hi), ZERO, err_ctx));
        }
        if divisor_lo > u32::MAX.into() {
            return Err(ExecutionError::not_u32_value(Felt::new(divisor_lo), ZERO, err_ctx));
        }

        let divisor = (divisor_hi << 32) + divisor_lo;

        if divisor == 0 {
            return Err(ExecutionError::divide_by_zero(process.clk(), err_ctx));
        }

        divisor
    };

    let dividend = {
        let dividend_hi = process.get_stack_item(3).as_int();
        let dividend_lo = process.get_stack_item(4).as_int();

        // Ensure the dividend is a pair of u32 values
        if dividend_hi > u32::MAX.into() {
            return Err(ExecutionError::not_u32_value(Felt::new(dividend_hi), ZERO, err_ctx));
        }
        if dividend_lo > u32::MAX.into() {
            return Err(ExecutionError::not_u32_value(Felt::new(dividend_lo), ZERO, err_ctx));
        }

        (dividend_hi << 32) + dividend_lo
    };

    let quotient = dividend / divisor;
    let remainder = dividend - quotient * divisor;

    let (q_hi, q_lo) = u64_to_u32_elements(quotient);
    let (r_hi, r_lo) = u64_to_u32_elements(remainder);

    process.advice_provider_mut().push_stack(r_hi);
    process.advice_provider_mut().push_stack(r_lo);
    process.advice_provider_mut().push_stack(q_hi);
    process.advice_provider_mut().push_stack(q_lo);
    Ok(())
}

/// Pushes the result of divison (both the quotient and the remainder) of a [u64] by the Falcon
/// prime (M = 12289) onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, a1, a0, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [q1, q0, r, ...]
///
/// where (a0, a1) are the 32-bit limbs of the dividend (with a0 representing the 32 least
/// significant bits and a1 representing the 32 most significant bits).
/// Similarly, (q0, q1) represent the quotient and r the remainder.
///
/// # Errors
/// - Returns an error if the divisor is ZERO.
/// - Returns an error if either a0 or a1 is not a u32.
fn push_falcon_mod_result(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let dividend_hi = process.get_stack_item(1).as_int();
    let dividend_lo = process.get_stack_item(2).as_int();
    if dividend_lo > u32::MAX as u64 {
        return Err(ExecutionError::input_not_u32(process.clk(), dividend_lo, err_ctx));
    }
    if dividend_hi > u32::MAX as u64 {
        return Err(ExecutionError::input_not_u32(process.clk(), dividend_hi, err_ctx));
    }
    let dividend = (dividend_hi << 32) + dividend_lo;

    let (quotient, remainder) = (dividend / M, dividend % M);

    let (q_hi, q_lo) = u64_to_u32_elements(quotient);
    let (r_hi, r_lo) = u64_to_u32_elements(remainder);
    assert_eq!(r_hi, ZERO);

    process.advice_provider_mut().push_stack(r_lo);
    process.advice_provider_mut().push_stack(q_lo);
    process.advice_provider_mut().push_stack(q_hi);
    Ok(())
}

/// Given an element in a quadratic extension field on the top of the stack (i.e., a0, b1),
/// computes its multiplicative inverse and push the result onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, a1, a0, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [b0, b1...]
///
/// Where (b0, b1) is the multiplicative inverse of the extension field element (a0, a1) at the
/// top of the stack.
///
/// # Errors
/// Returns an error if the input is a zero element in the extension field.
fn push_ext2_inv_result(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let coef0 = process.get_stack_item(2);
    let coef1 = process.get_stack_item(1);

    let element = QuadFelt::new(coef0, coef1);
    if element == QuadFelt::ZERO {
        return Err(ExecutionError::divide_by_zero(process.clk(), err_ctx));
    }
    let result = element.inv().to_base_elements();

    process.advice_provider_mut().push_stack(result[1]);
    process.advice_provider_mut().push_stack(result[0]);
    Ok(())
}

/// Pushes the number of the leading zeros of the top stack element onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [leading_zeros, ...]
fn push_leading_zeros(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    push_transformed_stack_top(process, |stack_top| Felt::from(stack_top.leading_zeros()), err_ctx)
}

/// Pushes the number of the trailing zeros of the top stack element onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [trailing_zeros, ...]
fn push_trailing_zeros(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    push_transformed_stack_top(process, |stack_top| Felt::from(stack_top.trailing_zeros()), err_ctx)
}

/// Pushes the number of the leading ones of the top stack element onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [leading_ones, ...]
fn push_leading_ones(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    push_transformed_stack_top(process, |stack_top| Felt::from(stack_top.leading_ones()), err_ctx)
}

/// Pushes the number of the trailing ones of the top stack element onto the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [trailing_ones, ...]
fn push_trailing_ones(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    push_transformed_stack_top(process, |stack_top| Felt::from(stack_top.trailing_ones()), err_ctx)
}

/// Pushes the base 2 logarithm of the top stack element, rounded down.
/// Inputs:
///   Operand stack: [event_id, n, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [ilog2(n), ...]
///
/// # Errors
/// Returns an error if the logarithm argument (top stack element) equals ZERO.
fn push_ilog2(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let n = process.get_stack_item(1).as_int();
    if n == 0 {
        return Err(ExecutionError::log_argument_zero(process.clk(), err_ctx));
    }
    let ilog2 = Felt::from(n.ilog2());
    process.advice_provider_mut().push_stack(ilog2);

    Ok(())
}

/// Pushes onto the advice stack the value associated with the specified key in a Sparse
/// Merkle Tree defined by the specified root.
///
/// If no value was previously associated with the specified key, [ZERO; 4] is pushed onto
/// the advice stack.
///
/// Inputs:
///   Operand stack: [event_id, KEY, ROOT, ...]
///   Advice stack: [...]
///
/// Outputs:
///   Advice stack: [VALUE, ...]
///
/// # Errors
/// Returns an error if the provided Merkle root doesn't exist on the advice provider.
///
/// # Panics
/// Will panic as unimplemented if the target depth is `64`.
fn push_smtpeek_result(
    process: &mut ProcessState,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let empty_leaf = EmptySubtreeRoots::entry(SMT_DEPTH, SMT_DEPTH);
    // fetch the arguments from the operand stack
    let key = process.get_stack_word(1);
    let root = process.get_stack_word(5);

    // get the node from the SMT for the specified key; this node can be either a leaf node,
    // or a root of an empty subtree at the returned depth
    let node = process
        .advice_provider()
        .get_tree_node(root, &Felt::new(SMT_DEPTH as u64), &key[3])
        .map_err(|err| ExecutionError::advice_error(err, process.clk(), err_ctx))?;

    if node == *empty_leaf {
        // if the node is a root of an empty subtree, then there is no value associated with
        // the specified key
        process.advice_provider_mut().push_stack_word(&Smt::EMPTY_VALUE);
    } else {
        let leaf_preimage = get_smt_leaf_preimage(process, node, err_ctx)?;

        for (key_in_leaf, value_in_leaf) in leaf_preimage {
            if key == key_in_leaf {
                // Found key - push value associated with key, and return
                process.advice_provider_mut().push_stack_word(&value_in_leaf);

                return Ok(());
            }
        }

        // if we can't find any key in the leaf that matches `key`, it means no value is
        // associated with `key`
        process.advice_provider_mut().push_stack_word(&Smt::EMPTY_VALUE);
    }
    Ok(())
}

// HELPER METHODS
// --------------------------------------------------------------------------------------------

/// Reads (start_addr, end_addr) tuple from the specified elements of the operand stack (
/// without modifying the state of the stack), and verifies that memory range is valid.
fn get_mem_addr_range(
    process: &ProcessState,
    start_idx: usize,
    end_idx: usize,
) -> Result<(u32, u32), MemoryError> {
    let start_addr = process.get_stack_item(start_idx).as_int();
    let end_addr = process.get_stack_item(end_idx).as_int();

    if start_addr > u32::MAX as u64 {
        return Err(MemoryError::address_out_of_bounds(start_addr, &()));
    }
    if end_addr > u32::MAX as u64 {
        return Err(MemoryError::address_out_of_bounds(end_addr, &()));
    }

    if start_addr > end_addr {
        return Err(MemoryError::InvalidMemoryRange { start_addr, end_addr });
    }

    Ok((start_addr as u32, end_addr as u32))
}

fn u64_to_u32_elements(value: u64) -> (Felt, Felt) {
    let hi = Felt::from((value >> 32) as u32);
    let lo = Felt::from(value as u32);
    (hi, lo)
}

/// Gets the top stack element, applies a provided function to it and pushes it to the advice
/// provider.
fn push_transformed_stack_top(
    process: &mut ProcessState,
    f: impl FnOnce(u32) -> Felt,
    err_ctx: &impl ErrorContext,
) -> Result<(), ExecutionError> {
    let stack_top = process.get_stack_item(1);
    let stack_top: u32 = stack_top
        .as_int()
        .try_into()
        .map_err(|_| ExecutionError::not_u32_value(stack_top, ZERO, err_ctx))?;
    let transformed_stack_top = f(stack_top);
    process.advice_provider_mut().push_stack(transformed_stack_top);
    Ok(())
}

fn get_smt_leaf_preimage(
    process: &ProcessState,
    node: Word,
    err_ctx: &impl ErrorContext,
) -> Result<Vec<(Word, Word)>, ExecutionError> {
    let kv_pairs = process
        .advice_provider()
        .get_mapped_values(&node)
        .ok_or_else(|| ExecutionError::smt_node_not_found(node, err_ctx))?;

    if kv_pairs.len() % WORD_SIZE * 2 != 0 {
        return Err(ExecutionError::smt_node_preimage_not_valid(node, kv_pairs.len(), err_ctx));
    }

    Ok(kv_pairs
        .chunks_exact(WORD_SIZE * 2)
        .map(|kv_chunk| {
            let key = [kv_chunk[0], kv_chunk[1], kv_chunk[2], kv_chunk[3]];
            let value = [kv_chunk[4], kv_chunk[5], kv_chunk[6], kv_chunk[7]];

            (key.into(), value.into())
        })
        .collect())
}
