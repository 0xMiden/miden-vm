//! P-256 ECDSA public-key recovery event handler.
//!
//! The handler supplies a candidate public key as advice. The calling MASM procedure treats that
//! key as untrusted and constrains it against the exact digest and signature stored in VM memory.

use miden_core::{Felt, WORD_SIZE, events::EventName, utils::packed_u32_elements_to_bytes};
use miden_event_handler::{AdviceRecorder, EventContext, EventError, InvocationKind};
use p256::ecdsa::{RecoveryId, Signature, VerifyingKey};

use crate::dsa::ecdsa_p256_sha256::public_key_felts;

/// Event emitted when the ECDSA recovery procedures need a candidate public key.
pub const ECDSA_P256_SHA256_RECOVER_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::dsa::ecdsa_p256_sha256::recover");

const DIGEST_FELTS: u64 = 8;
const SIGNATURE_FELTS: u64 = 17;
const SCALAR_LIMBS: usize = 8;

/// Recovers a candidate P-256 public key from the digest and native recovery witness in VM memory.
///
/// Expected event payload (excluding the event ID):
///
/// ```text
/// [DIGEST_PTR, SIG_PTR, ...]
/// ```
///
/// `DIGEST_PTR` addresses the packed SHA-256 digest written by the core hash procedure. `SIG_PTR`
/// must be word-aligned and address `R_LE_U32[8] || S_LE_U32[8] || V`, where `V` is 0 or 1 (the
/// y-parity of R). This native memory format is distinct from external wire encodings, whose
/// scalar components are fixed-width big-endian byte strings.
pub fn handle_ecdsa_p256_sha256_recover(
    context: EventContext<'_>,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    let [digest_ptr, signature_ptr] =
        context.read_stack_array(0).map(|felt| felt.as_canonical_u64());

    if !digest_ptr.is_multiple_of(WORD_SIZE as u64) {
        return Err(RecoveryEventError::InvalidDigestPointer { digest_ptr }.into());
    }
    let digest_felts = context
        .memory_slice(digest_ptr, DIGEST_FELTS)
        .map_err(|_| RecoveryEventError::InvalidDigestPointer { digest_ptr })?;
    if !signature_ptr.is_multiple_of(WORD_SIZE as u64) {
        return Err(RecoveryEventError::InvalidSignaturePointer { signature_ptr }.into());
    }
    let signature_felts = context
        .memory_slice(signature_ptr, SIGNATURE_FELTS)
        .map_err(|_| RecoveryEventError::InvalidSignaturePointer { signature_ptr })?;

    validate_u32_limbs(&digest_felts, digest_ptr)?;
    validate_u32_limbs(&signature_felts[..2 * SCALAR_LIMBS], signature_ptr)?;

    let prehash: [u8; 32] = packed_u32_elements_to_bytes(&digest_felts)
        .try_into()
        .map_err(|_| RecoveryEventError::InvalidDigestPointer { digest_ptr })?;

    let recovery_byte = signature_felts[2 * SCALAR_LIMBS].as_canonical_u64();
    let recovery_id = match recovery_byte {
        0 | 1 => RecoveryId::from_byte(recovery_byte as u8).expect("0 and 1 are valid"),
        value => return Err(RecoveryEventError::InvalidRecoveryByte { value }.into()),
    };

    let mut signature_bytes = [0u8; 64];
    write_scalar_bytes(&signature_felts[..SCALAR_LIMBS], &mut signature_bytes[..32]);
    write_scalar_bytes(
        &signature_felts[SCALAR_LIMBS..2 * SCALAR_LIMBS],
        &mut signature_bytes[32..],
    );
    let signature =
        Signature::from_slice(&signature_bytes).map_err(|_| RecoveryEventError::RecoveryFailed)?;
    let public_key = VerifyingKey::recover_from_prehash(&prehash, &signature, recovery_id)
        .map_err(|_| RecoveryEventError::RecoveryFailed)?;

    let point = public_key.to_sec1_point(false);
    let x = point.x().ok_or(RecoveryEventError::RecoveryFailed)?;
    let y = point.y().ok_or(RecoveryEventError::RecoveryFailed)?;
    advice.prepend_stack(public_key_felts(&(*x).into(), &(*y).into()));
    Ok(())
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
        "invalid native recovery witness pointer {signature_ptr}; expected a word-aligned 17-element memory region"
    )]
    InvalidSignaturePointer { signature_ptr: u64 },
    #[error("native recovery witness limb {value} at address {address} exceeds u32::MAX")]
    NonU32Limb { address: u64, value: u64 },
    #[error("invalid ECDSA recovery byte {value}; expected 0 or 1")]
    InvalidRecoveryByte { value: u64 },
    #[error("failed to recover a P-256 public key")]
    RecoveryFailed,
}
