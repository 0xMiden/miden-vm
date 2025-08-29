use alloc::{vec, vec::Vec};

use miden_core::{AdviceMap, Felt};
use miden_crypto::hash::{keccak::Keccak256, rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};

use crate::precompiles::read_memory;

pub const KECCAK_EVENT_ID: &str = "miden_stdlib::hash::keccak";

// KECCAK EVENT ERROR
// ================================================================================================

#[derive(Debug, thiserror::Error)]
pub enum KeccakError {
    #[error("failed to read memory at ptr {ptr}, len {len}")]
    MemoryReadFailed { ptr: u64, len: u64 },
    #[error("invalid byte value in memory: {value}")]
    InvalidByteValue { value: u64 },
}

/// Event handler which pushes keccak256 hash to the advice stack.
///
/// This handler is used to defer expensive keccak computation to the native verifier.
/// The verifier will re-execute the keccak operation and verify the result.
///
/// Inputs:
///   Operand stack: [event_id, ptr, len, ...]
///   Memory: bytes at [ptr, len)
///
/// Outputs:
///   Advice stack: [hash_bytes...] (32 bytes as individual Felts)
///   Advice map: commitment -> preimage mapping for prover recovery
///
/// Where:
/// - ptr is the memory address where the input bytes start
/// - len is the number of bytes to hash
/// - hash_bytes are the 32 bytes of the keccak256 hash
pub fn push_keccak(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // start at 1 since 0 holds the event id
    // Note: stack layout after emit is [event_id, ptr, len, ...]
    let ptr = process.get_stack_item(1).as_int();
    let len = process.get_stack_item(2).as_int();

    // Attempt to collect the field elements between `ptr` and `ptr+len`.
    let witness =
        read_memory(process, ptr, len).map_err(|_| KeccakError::MemoryReadFailed { ptr, len })?;

    // Try to convert to bytes
    let preimage = witness
        .iter()
        .map(|felt| {
            u8::try_from(felt.as_int())
                .map_err(|_| KeccakError::InvalidByteValue { value: felt.as_int() })
        })
        .collect::<Result<Vec<_>, _>>()?;

    // Resulting Keccak hash of the preimage
    let keccak_hash = Keccak256::hash(&preimage);
    let mut keccak_hash_felt: Vec<_> = keccak_hash.iter().copied().map(Felt::from).collect();

    // Commitment to precompile call
    // Rpo(
    //     Rpo(preimage),
    //     Rpo(Keccak(preimage))
    // )
    let calldata_commitment = Rpo256::merge(&[
        Rpo256::hash_elements(&witness),          // Commitment to pre-image
        Rpo256::hash_elements(&keccak_hash_felt), // Commitment to hash
    ]);

    // store the calldata in the advice map to be recovered later on by the prover
    // reverse hash
    keccak_hash_felt.reverse();
    let advice_stack_extension = AdviceMutation::extend_stack(keccak_hash_felt);
    let entry = (calldata_commitment, witness);
    let advice_map_extension = AdviceMutation::extend_map(AdviceMap::from_iter([entry]));
    Ok(vec![advice_stack_extension, advice_map_extension])
}
