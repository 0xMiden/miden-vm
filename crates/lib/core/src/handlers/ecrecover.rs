//! Host support for the core-library ECRECOVER procedure.

use alloc::{vec, vec::Vec};

use miden_core::{events::EventName, utils::packed_u32_elements_to_bytes};
use miden_crypto::{
    SequentialCommit,
    dsa::ecdsa_k256_keccak::{PublicKey, Signature},
};
use miden_processor::{
    ProcessorState,
    advice::{AdviceMutation, AdviceStack},
    event::EventError,
};

use crate::handlers::read_uninitialized_memory_region;

/// Event emitted by `miden::core::crypto::dsa::ecdsa_k256_keccak::ecrecover` when it needs the
/// recovered public key.
pub const ECRECOVER_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::ecdsa_k256_keccak::ecrecover");

const ECRECOVER_INPUT_FELTS: u64 = 32;
const ECRECOVER_INPUT_BYTES: usize = 128;
const HASH_START: usize = 0;
const V_START: usize = 32;
const R_START: usize = 64;
const S_START: usize = 96;

/// Reads an Ethereum `(hash, v, r, s)` input, recovers the public key, and puts `QX[8] || QY[8]`
/// on the advice stack.
///
/// The key remains untrusted advice. The MASM procedure checks it against the input before deriving
/// the address.
pub fn handle_ecrecover(process: &ProcessorState<'_>) -> Result<Vec<AdviceMutation>, EventError> {
    let input_ptr = process.get_stack_item(1).as_canonical_u64();
    let input_felts = read_uninitialized_memory_region(process, input_ptr, ECRECOVER_INPUT_FELTS)
        .ok_or(EcrecoverEventError::InvalidInputPointer { input_ptr })?;

    for (offset, felt) in input_felts.iter().enumerate() {
        let value = felt.as_canonical_u64();
        if value > u32::MAX as u64 {
            return Err(EcrecoverEventError::NonU32Input {
                address: input_ptr + offset as u64,
                value,
            }
            .into());
        }
    }

    let input: [u8; ECRECOVER_INPUT_BYTES] = packed_u32_elements_to_bytes(&input_felts)
        .try_into()
        .expect("32 u32 elements always encode to 128 bytes");

    let v_word = &input[V_START..R_START];
    if v_word[..31].iter().any(|&byte| byte != 0) || !matches!(v_word[31], 27 | 28) {
        return Err(EcrecoverEventError::InvalidRecoveryId.into());
    }
    let recovery_id = v_word[31] - 27;

    let mut signature_bytes = [0u8; 64];
    signature_bytes[..32].copy_from_slice(&input[R_START..S_START]);
    signature_bytes[32..].copy_from_slice(&input[S_START..]);
    let signature = Signature::from_sec1_bytes_and_recovery_id(signature_bytes, recovery_id)
        .map_err(|_| EcrecoverEventError::RecoveryFailed)?;
    let prehash: [u8; 32] = input[HASH_START..V_START]
        .try_into()
        .expect("the ECRECOVER prehash slice has a fixed length");
    let public_key = PublicKey::recover_from_prehash(prehash, &signature)
        .map_err(|_| EcrecoverEventError::RecoveryFailed)?;

    let public_key_elements = public_key.to_elements();
    debug_assert_eq!(public_key_elements.len(), 16);
    let mut advice_stack = AdviceStack::new();
    advice_stack.append_for_adv_pipe(&public_key_elements);

    Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum EcrecoverEventError {
    #[error(
        "invalid ECRECOVER input pointer {input_ptr}; expected a word-aligned 32-element memory region"
    )]
    InvalidInputPointer { input_ptr: u64 },
    #[error("ECRECOVER input value {value} at address {address} exceeds u32::MAX")]
    NonU32Input { address: u64, value: u64 },
    #[error("ECRECOVER v must be the 32-byte big-endian encoding of 27 or 28")]
    InvalidRecoveryId,
    #[error("failed to recover a secp256k1 public key from the ECRECOVER input")]
    RecoveryFailed,
}
