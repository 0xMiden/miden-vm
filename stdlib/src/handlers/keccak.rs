use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{AdviceMap, Felt, crypto::hash::Digest};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::handlers::read_memory;

pub const KECCAK_EVENT_ID: &str = "miden_stdlib::hash::keccak";

/// Keccak256 event handler that defers hash computation to the native verifier.
///
/// Reads u32 values from memory, extracts the specified number of bytes (with overflow
/// bytes required to be zero), computes Keccak256 hash, and stores both the hash on the
/// advice stack and a commitment in the advice map for proof verification.
///
/// Inputs:
///   Operand stack: [event_id, ptr, len, ...]
///   Memory: u32 values in word-aligned region starting from `ptr`
///
/// Outputs:
///   Advice stack: 8 u32 values (Keccak256 hash in little-endian, reversed for stack order)
///   Advice map: `RPO([RPO(input), RPO(hash)]) -> input` mapping
///
/// Where:
/// - ptr: word-aligned memory address containing u32 data
/// - len: number of bytes to hash (unused bytes in final u32 must be zero)
pub fn push_keccak(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // Extract parameters from stack (event_id at index 0)
    let ptr = process.get_stack_item(1).as_int();
    let len = process.get_stack_item(2).as_int();

    // Calculate number of u32 elements needed to store len bytes
    let len_u32 = len.div_ceil(4);

    // Read u32 values from memory
    let input_felt =
        read_memory(process, ptr, len_u32).ok_or(KeccakError::MemoryReadFailed { ptr, len })?;

    // Convert Felt values to u32
    let input_u32: Vec<u32> = input_felt
        .iter()
        .enumerate()
        .map(|(index, felt)| {
            let value = felt.as_int();
            u32::try_from(value).map_err(|_| KeccakError::InvalidValue { value, index })
        })
        .collect::<Result<_, _>>()?;

    // Extract bytes and validate that overflow bytes in final u32 are zero
    let mut input_u8: Vec<u8> = input_u32.into_iter().flat_map(u32::to_le_bytes).collect();
    for (index, &to_drop) in input_u8[len as usize..].iter().enumerate() {
        if to_drop != 0 {
            return Err(KeccakError::InvalidValue { index, value: to_drop as u64 })?;
        }
    }
    input_u8.truncate(len as usize);

    // Compute Keccak256 hash and pack into 8 u32 values
    let hash_u8: [u8; 32] = Keccak256::hash(&input_u8).as_bytes();
    let hash_felt: [Felt; 8] = pack_digest_u32(hash_u8).map(Felt::from);

    // Create commitment: RPO([RPO(input), RPO(hash)])
    let calldata_commitment =
        Rpo256::merge(&[Rpo256::hash_elements(&input_felt), Rpo256::hash_elements(&hash_felt)]);

    // Reverse hash for stack order (first popped = first u32)
    let mut hash_felt_rev = hash_felt;
    hash_felt_rev.reverse();
    let advice_stack_extension = AdviceMutation::extend_stack(hash_felt_rev);

    // Store commitment -> input mapping for prover recovery
    let entry = (calldata_commitment, input_felt);
    let advice_map_extension = AdviceMutation::extend_map(AdviceMap::from_iter([entry]));

    Ok(vec![advice_stack_extension, advice_map_extension])
}

pub fn pack_digest_u32(input: [u8; 32]) -> [u32; 8] {
    const U32_SIZE: usize = size_of::<u32>();
    array::from_fn(|i| {
        let bytes: [u8; U32_SIZE] = array::from_fn(|j| input[U32_SIZE * i + j]);
        u32::from_le_bytes(bytes)
    })
}

// KECCAK EVENT ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum KeccakError {
    #[error("failed to read memory at ptr {ptr}, len {len}")]
    MemoryReadFailed { ptr: u64, len: u64 },
    #[error("invalid byte at index {index} with value: {value}")]
    InvalidValue { value: u64, index: usize },
}
