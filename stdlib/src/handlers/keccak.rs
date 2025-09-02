use alloc::{vec, vec::Vec};
use core::array;

use miden_core::{AdviceMap, Felt, crypto::hash::Digest};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::handlers::read_memory;

pub const KECCAK_EVENT_ID: &str = "miden_stdlib::hash::keccak";

// KECCAK EVENT ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum KeccakError {
    #[error("failed to read memory at ptr {ptr}, len {len}")]
    MemoryReadFailed { ptr: u64, len: u64 },
    #[error("invalid byte at index {index} with value: {value}")]
    InvalidValue { value: u64, index: usize },
}

/// Event handler which pushes keccak256 hash to the advice stack.
///
/// This handler is used to defer expensive keccak computation to the native verifier.
/// The verifier will re-execute the keccak operation and verify the result.
///
/// Inputs:
///   Operand stack: [event_id, ptr, len, ...]
///   Memory: bytes at [ptr, len) where each memory location contains a single byte value
///
/// Outputs:
///   Advice stack: [hash_u32...] (8 u32 values representing 32-byte hash)
///   Advice map: commitment -> preimage mapping for prover recovery
///
/// Where:
/// - ptr is the memory address where the input bytes start (word aligned)
/// - len is the number of bytes to read from memory
/// - hash_u32 are 8 u32 values representing the 32-byte keccak256 hash in little-endian order
pub fn push_keccak(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // start at 1 since 0 holds the event id
    // Note: stack layout after emit is [event_id, ptr, len, ptr_out, ...]
    let ptr = process.get_stack_item(1).as_int();
    let len = process.get_stack_item(2).as_int();

    // Attempt to collect the field elements between `ptr` and `ptr+len`.
    let input_felt =
        read_memory(process, ptr, len).ok_or(KeccakError::MemoryReadFailed { ptr, len })?;

    // Convert each Felt to u8 (each memory location contains a single byte)
    let input_u8: Vec<u8> = input_felt
        .iter()
        .enumerate()
        .map(|(index, felt)| {
            let value = felt.as_int();
            u8::try_from(value).map_err(|_| KeccakError::InvalidValue { value, index })
        })
        .collect::<Result<_, _>>()?;

    // Resulting Keccak hash of the preimage
    let hash_u8: [u8; 32] = Keccak256::hash(&input_u8).as_bytes();

    // Pack the 32-byte hash into 8 u32 values using little-endian byte order
    let hash_u32: [u32; 8] = pack_digest_u32(hash_u8);

    let hash_felt = hash_u32.map(Felt::from);

    // Commitment to precompile call
    // Rpo( Rpo(input), Rpo(Keccak(input)) )
    let calldata_commitment = Rpo256::merge(&[
        Rpo256::hash_elements(&input_felt), // Rpo(input)
        Rpo256::hash_elements(&hash_felt),  // Rpo(hash)
    ]);

    // Reverse the keccak hash u32s before extending the advice stack, so that
    // the first popped element corresponds to the first u32 of the hash.
    let mut hash_felt_rev = hash_felt;
    hash_felt_rev.reverse();
    let advice_stack_extension = AdviceMutation::extend_stack(hash_felt_rev);

    // store the calldata in the advice map to be recovered later on by the prover
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
