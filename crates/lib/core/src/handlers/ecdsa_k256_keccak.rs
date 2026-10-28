//! secp256k1 ECDSA public-key recovery event handler.
//!
//! The handler supplies a candidate public key as advice. The calling MASM procedure treats that
//! key as untrusted and constrains it against the exact digest and signature stored in VM memory.

use alloc::{vec, vec::Vec};

use miden_core::{Felt, events::EventName, utils::packed_u32_elements_to_bytes};
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

/// Event emitted when the ECDSA recovery procedures need a candidate public key.
pub const ECDSA_K256_KECCAK_RECOVER_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::ecdsa_k256_keccak::recover");

const DIGEST_FELTS: u64 = 8;
const SIGNATURE_FELTS: u64 = 17;
const SCALAR_LIMBS: usize = 8;

/// Recovers a candidate secp256k1 public key from the digest and native EVM recovery witness in VM
/// memory.
///
/// Expected event payload (excluding the event ID):
///
/// ```text
/// [DIGEST_PTR, SIG_PTR, ...]
/// ```
///
/// `DIGEST_PTR` addresses the packed Keccak digest written by the core hash procedure. `SIG_PTR`
/// must be word-aligned and address `R_LE_U32[8] || S_LE_U32[8] || V`, where `V` is 27 or 28. This
/// native memory format is distinct from external EVM wire bytes, whose scalar components are
/// fixed-width big-endian byte strings.
pub fn handle_ecdsa_k256_keccak_recover(
    process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    let digest_ptr = process.get_stack_item(1).as_canonical_u64();
    let signature_ptr = process.get_stack_item(2).as_canonical_u64();

    let digest_felts = read_uninitialized_memory_region(process, digest_ptr, DIGEST_FELTS)
        .ok_or(RecoveryEventError::InvalidDigestPointer { digest_ptr })?;
    let signature_felts = read_uninitialized_memory_region(process, signature_ptr, SIGNATURE_FELTS)
        .ok_or(RecoveryEventError::InvalidSignaturePointer { signature_ptr })?;

    validate_u32_limbs(&digest_felts, digest_ptr)?;
    validate_u32_limbs(&signature_felts[..2 * SCALAR_LIMBS], signature_ptr)?;

    let prehash: [u8; 32] = packed_u32_elements_to_bytes(&digest_felts)
        .try_into()
        .map_err(|_| RecoveryEventError::InvalidDigestPointer { digest_ptr })?;

    let recovery_byte = signature_felts[2 * SCALAR_LIMBS].as_canonical_u64();
    let recovery_id = match recovery_byte {
        27 => 0,
        28 => 1,
        value => return Err(RecoveryEventError::InvalidRecoveryByte { value }.into()),
    };

    let mut signature_bytes = [0u8; 64];
    write_scalar_bytes(&signature_felts[..SCALAR_LIMBS], &mut signature_bytes[..32]);
    write_scalar_bytes(
        &signature_felts[SCALAR_LIMBS..2 * SCALAR_LIMBS],
        &mut signature_bytes[32..],
    );
    let signature = Signature::from_sec1_bytes_and_recovery_id(signature_bytes, recovery_id)
        .map_err(|_| RecoveryEventError::RecoveryFailed)?;
    let public_key = PublicKey::recover_from_prehash(prehash, &signature)
        .map_err(|_| RecoveryEventError::RecoveryFailed)?;

    let public_key_elements = public_key.to_elements();
    debug_assert_eq!(public_key_elements.len(), 16);
    let mut advice_stack = AdviceStack::new();
    advice_stack.append_for_adv_pipe(&public_key_elements);

    Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
}

fn write_scalar_bytes(limbs: &[Felt], output: &mut [u8]) {
    debug_assert_eq!(limbs.len(), SCALAR_LIMBS);
    debug_assert_eq!(output.len(), 32);

    let mut bytes = packed_u32_elements_to_bytes(limbs);
    bytes.reverse();
    output.copy_from_slice(&bytes);
}

fn validate_u32_limbs(limbs: &[Felt], start_address: u64) -> Result<(), EventError> {
    for (index, felt) in limbs.iter().enumerate() {
        let value = felt.as_canonical_u64();
        if value > u32::MAX as u64 {
            return Err(RecoveryEventError::NonU32Limb {
                address: start_address + index as u64,
                value,
            }
            .into());
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum RecoveryEventError {
    #[error("invalid ECDSA digest pointer {digest_ptr}")]
    InvalidDigestPointer { digest_ptr: u64 },
    #[error(
        "invalid native EVM recovery witness pointer {signature_ptr}; expected a word-aligned 17-element memory region"
    )]
    InvalidSignaturePointer { signature_ptr: u64 },
    #[error("native EVM recovery witness limb {value} at address {address} exceeds u32::MAX")]
    NonU32Limb { address: u64, value: u64 },
    #[error("invalid EVM recovery byte {value}; expected 27 or 28")]
    InvalidRecoveryByte { value: u64 },
    #[error("failed to recover a secp256k1 public key")]
    RecoveryFailed,
}
