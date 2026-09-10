//! Host advice for Eidos AEAD decryption.

use miden_core::{Word, events::EventName};
use miden_crypto::aead::aead_eidos::expanded::{
    checked_mac_input_len, decrypt_felts_expanded_authenticated,
};
use miden_event_handler::{
    AdviceRecorder, EventContext, EventError, InvocationKind, MAX_AEAD_PLAINTEXT_BYTES,
};

/// Event emitted when `aead_eidos::decrypt_empty_ad` needs a plaintext witness.
pub const AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::aead_eidos::decrypt_empty_ad");

/// Authenticates and decrypts expanded Eidos ciphertext and supplies the plaintext as advice.
///
/// The event payload, excluding the event ID, is
/// `[key(4), nonce(4), src_ptr, dst_ptr, num_felts, scratch_ptr, ...]`. `src_ptr` addresses
/// `2 * num_felts` ciphertext limbs followed by the two-Felt tag. The MASM procedure treats the
/// returned plaintext as untrusted and binds it by re-encrypting it and comparing the ciphertext.
/// Plaintext is limited to [`MAX_AEAD_PLAINTEXT_BYTES`] serialized bytes per invocation; the
/// processor separately validates the complete advice batch against its aggregate budget.
pub fn handle_aead_eidos_decrypt_empty_ad(
    context: EventContext,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    const KEY_OFFSET: u64 = 0;
    const NONCE_OFFSET: u64 = 4;
    const SRC_PTR_OFFSET: u64 = 8;
    const NUM_FELTS_OFFSET: u64 = 10;

    let key = context.stack_word(KEY_OFFSET);
    let nonce = context.stack_word(NONCE_OFFSET);
    let src_ptr = context.stack_item(SRC_PTR_OFFSET).as_canonical_u64();
    let num_felts = context.stack_item(NUM_FELTS_OFFSET).as_canonical_u64();

    let num_felts = usize::try_from(num_felts).map_err(|_| AeadEidosDecryptError::SizeOverflow)?;
    let ciphertext_len = num_felts.checked_mul(2).ok_or(AeadEidosDecryptError::SizeOverflow)?;
    checked_mac_input_len(0, ciphertext_len)
        .ok_or(AeadEidosDecryptError::AuthenticationInputTooLong)?;
    let input_len = ciphertext_len.checked_add(2).ok_or(AeadEidosDecryptError::SizeOverflow)?;

    let plaintext_bytes = num_felts
        .checked_mul(Word::SERIALIZED_SIZE / Word::NUM_ELEMENTS)
        .ok_or(AeadEidosDecryptError::SizeOverflow)?;
    let max_plaintext_bytes = MAX_AEAD_PLAINTEXT_BYTES;
    if plaintext_bytes > max_plaintext_bytes {
        return Err(AeadEidosDecryptError::PlaintextTooLarge {
            plaintext_bytes,
            max_plaintext_bytes,
        }
        .into());
    }

    let input_len_u64 =
        u64::try_from(input_len).map_err(|_| AeadEidosDecryptError::SizeOverflow)?;
    let invalid_range =
        || AeadEidosDecryptError::InvalidInputRange { src_ptr, input_len: input_len_u64 };
    let start = u32::try_from(src_ptr).map_err(|_| invalid_range())?;
    let len = u32::try_from(input_len).map_err(|_| invalid_range())?;
    let end = start.checked_add(len).ok_or_else(invalid_range)?;
    if !start.is_multiple_of(Word::NUM_ELEMENTS as u32) {
        return Err(invalid_range().into());
    }
    let input = context
        .memory_range(u64::from(start), u64::from(end))
        .map_err(|_| invalid_range())?;
    let ciphertext = &input[..ciphertext_len];
    let tag = [input[ciphertext_len], input[ciphertext_len + 1]];

    let plaintext = decrypt_felts_expanded_authenticated(key, nonce, &[], ciphertext, tag)
        .ok_or(AeadEidosDecryptError::AuthenticationFailed)?;
    debug_assert_eq!(plaintext.len(), num_felts);

    advice.prepend_stack(plaintext);
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum AeadEidosDecryptError {
    #[error("Eidos AEAD decryption size overflow")]
    SizeOverflow,
    #[error("Eidos AEAD authentication input exceeds its supported length")]
    AuthenticationInputTooLong,
    #[error(
        "Eidos AEAD plaintext needs {plaintext_bytes} advice bytes, exceeding the per-invocation maximum of {max_plaintext_bytes}"
    )]
    PlaintextTooLarge {
        plaintext_bytes: usize,
        max_plaintext_bytes: usize,
    },
    #[error("invalid Eidos AEAD input range at address {src_ptr} with length {input_len}")]
    InvalidInputRange { src_ptr: u64, input_len: u64 },
    #[error("Eidos AEAD authentication failed")]
    AuthenticationFailed,
}
