//! Host advice for Eidos AEAD decryption.

use alloc::{vec, vec::Vec};

use miden_core::{Word, advice::AdviceStack, events::EventName};
use miden_crypto::aead::aead_eidos::expanded::{
    checked_mac_input_len, decrypt_felts_expanded_authenticated,
};
use miden_processor::{ProcessorState, advice::AdviceMutation, event::EventError};

use crate::handlers::read_uninitialized_memory_region;

/// Event emitted when `aead_eidos::decrypt_empty_ad` needs a plaintext witness.
pub const AEAD_EIDOS_DECRYPT_EMPTY_AD_EVENT_NAME: EventName =
    EventName::new("miden::core::crypto::aead_eidos::decrypt_empty_ad");

/// Authenticates and decrypts expanded Eidos ciphertext and supplies the plaintext as advice.
///
/// The event payload, excluding the event ID, is
/// `[key(4), nonce(4), src_ptr, dst_ptr, num_felts, scratch_ptr, ...]`. `src_ptr` addresses
/// `2 * num_felts` ciphertext limbs followed by the two-Felt tag. The MASM procedure treats the
/// returned plaintext as untrusted and binds it by re-encrypting it and comparing the ciphertext.
pub fn handle_aead_eidos_decrypt_empty_ad(
    process: &ProcessorState<'_>,
) -> Result<Vec<AdviceMutation>, EventError> {
    const KEY_OFFSET: usize = 1;
    const NONCE_OFFSET: usize = 5;
    const SRC_PTR_OFFSET: usize = 9;
    const NUM_FELTS_OFFSET: usize = 11;

    let key = process.get_stack_word(KEY_OFFSET);
    let nonce = process.get_stack_word(NONCE_OFFSET);
    let src_ptr = process.get_stack_item(SRC_PTR_OFFSET).as_canonical_u64();
    let num_felts = process.get_stack_item(NUM_FELTS_OFFSET).as_canonical_u64();

    let num_felts = usize::try_from(num_felts).map_err(|_| AeadEidosDecryptError::SizeOverflow)?;
    let ciphertext_len = num_felts.checked_mul(2).ok_or(AeadEidosDecryptError::SizeOverflow)?;
    checked_mac_input_len(0, ciphertext_len)
        .ok_or(AeadEidosDecryptError::AuthenticationInputTooLong)?;
    let input_len = ciphertext_len.checked_add(2).ok_or(AeadEidosDecryptError::SizeOverflow)?;

    let plaintext_bytes = num_felts
        .checked_mul(Word::SERIALIZED_SIZE / Word::NUM_ELEMENTS)
        .ok_or(AeadEidosDecryptError::SizeOverflow)?;
    let max_advice_bytes = process.execution_options().max_advice_size_bytes();
    if plaintext_bytes > max_advice_bytes {
        return Err(
            AeadEidosDecryptError::PlaintextTooLarge { plaintext_bytes, max_advice_bytes }.into()
        );
    }

    let input_len_u64 =
        u64::try_from(input_len).map_err(|_| AeadEidosDecryptError::SizeOverflow)?;
    let input = read_uninitialized_memory_region(process, src_ptr, input_len_u64)
        .ok_or(AeadEidosDecryptError::InvalidInputRange { src_ptr, input_len: input_len_u64 })?;
    let ciphertext = &input[..ciphertext_len];
    let tag = [input[ciphertext_len], input[ciphertext_len + 1]];

    let plaintext = decrypt_felts_expanded_authenticated(key, nonce, &[], ciphertext, tag)
        .ok_or(AeadEidosDecryptError::AuthenticationFailed)?;
    debug_assert_eq!(plaintext.len(), num_felts);

    let advice_stack = AdviceStack::from(plaintext);
    Ok(vec![AdviceMutation::extend_advice_stack(advice_stack)])
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
enum AeadEidosDecryptError {
    #[error("Eidos AEAD decryption size overflow")]
    SizeOverflow,
    #[error("Eidos AEAD authentication input exceeds its supported length")]
    AuthenticationInputTooLong,
    #[error(
        "Eidos AEAD plaintext needs {plaintext_bytes} advice bytes, exceeding the configured maximum of {max_advice_bytes}"
    )]
    PlaintextTooLarge {
        plaintext_bytes: usize,
        max_advice_bytes: usize,
    },
    #[error("invalid Eidos AEAD input range at address {src_ptr} with length {input_len}")]
    InvalidInputRange { src_ptr: u64, input_len: u64 },
    #[error("Eidos AEAD authentication failed")]
    AuthenticationFailed,
}
