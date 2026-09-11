//! AEAD decryption event handler for the Miden VM.
//!
//! This module provides an event handler for decrypting AEAD ciphertext using non-deterministic
//! advice. When the VM emits an AEAD_DECRYPT_EVENT, this handler reads the ciphertext from memory,
//! performs decryption using the AEAD-Poseidon2 scheme, and pushes the plaintext onto the advice
//! stack for the MASM decrypt procedure to load.

use alloc::vec::Vec;

use miden_core::{Word, events::EventName};
use miden_crypto::aead::{
    DataType, EncryptionError,
    aead_poseidon2::{AuthTag, EncryptedData, Nonce, SecretKey},
};
use miden_event_handler::{
    AdviceRecorder, EventContext, EventError, InvocationKind, MAX_AEAD_PLAINTEXT_BYTES,
};

/// Qualified event name for the AEAD decrypt event.
pub const AEAD_DECRYPT_EVENT_NAME: EventName = EventName::new("miden::core::crypto::aead::decrypt");

/// Event handler for AEAD decryption.
///
/// This handler is called when the VM emits an AEAD_DECRYPT_EVENT. It reads the full
/// ciphertext (including padding block) and tag from memory, performs decryption and
/// tag verification using AEAD-Poseidon2, then pushes the plaintext onto the advice stack.
/// Plaintext is limited to [`MAX_AEAD_PLAINTEXT_BYTES`] serialized bytes per invocation; the
/// processor separately checks the pending advice against its aggregate advice budget.
///
/// Process:
/// 1. Reads full ciphertext from memory at src_ptr ((num_blocks + 1) * 8 elements)
/// 2. Reads authentication tag from memory at src_ptr + (num_blocks + 1) * 8
/// 3. Constructs EncryptedData and decrypts using AEAD-Poseidon2
/// 4. Extracts only the data blocks (first num_blocks * 8 elements) from plaintext
/// 5. Pushes the data blocks (WITHOUT padding) onto the advice stack for `adv_pipe`
///
/// Expected event payload order:
/// `(key: Word, nonce: Word, src_ptr, dst_ptr, num_blocks)`.
///
/// Memory layout at src_ptr:
/// - [ciphertext_blocks(num_blocks * 8), encrypted_padding(8), tag(4)]
/// - This handler reads ALL elements: data blocks + padding + tag
/// - Every ciphertext, padding, and tag word must be initialized
///
/// The MASM decrypt procedure will then:
/// 1. Load the plaintext data blocks from advice stack and write to dst_ptr using adv_pipe
/// 2. Call encrypt which reads the data blocks and adds padding automatically
/// 3. Re-encrypt data + padding to compute authentication tag
/// 4. Compare computed tag with expected tag and halt if they don't match
///
/// Non-determinism soundness: Using advice for decryption is cryptographically sound
/// because:
/// 1. The MASM procedure re-verifies the tag when decrypting
/// 2. The deterministic encryption creates a bijection between plaintext and ciphertext
/// 3. A malicious prover cannot provide incorrect plaintext without causing tag mismatch
pub fn handle_aead_decrypt(
    context: EventContext,
    advice: &mut AdviceRecorder<'_>,
) -> Result<(), EventError> {
    context.kind().require(InvocationKind::Event)?;
    // Event payload: [key:Word(4), nonce:Word(4), src_ptr, dst_ptr, num_blocks, ...]
    // where:
    //   src_ptr = ciphertext + encrypted_padding + tag location (input)
    //   dst_ptr = plaintext destination (output)
    //   num_blocks = number of plaintext data blocks (NO padding)

    // Read parameters from stack
    // Words on the stack are interpreted in little-endian (memory) order, i.e. element at stack
    // index N becomes the first limb of the word.
    let key_word = context.stack_word(0);
    let nonce_word = context.stack_word(4);

    let src_ptr = context.stack_item(8).as_canonical_u64();
    let num_blocks = context.stack_item(10).as_canonical_u64();

    let (num_ciphertext_elements, tag_ptr, data_blocks_count) = compute_sizes(num_blocks, src_ptr)?;

    // Read ciphertext from memory: (num_blocks + 1) * 8 elements (data + padding)
    let read_error = || AeadDecryptError::MemoryReadFailed {
        addr: src_ptr,
        len: num_ciphertext_elements,
    };
    // `tag_ptr` is the checked exclusive end, so both bounds also constrain the count to u32.
    let start = u32::try_from(src_ptr).map_err(|_| read_error())?;
    let end = u32::try_from(tag_ptr).map_err(|_| read_error())?;
    if !start.is_multiple_of(Word::NUM_ELEMENTS as u32) {
        return Err(read_error().into());
    }
    let ciphertext = (start..end)
        .map(|addr| context.memory_value(u64::from(addr)).ok().flatten().ok_or_else(read_error))
        .collect::<Result<Vec<_>, _>>()?;

    // Read authentication tag: 4 elements (1 word) immediately after ciphertext
    let tag_word = context
        .memory_word(tag_ptr)
        .map_err(|_| AeadDecryptError::MemoryReadFailed { addr: tag_ptr, len: 4 })?
        .ok_or(AeadDecryptError::MemoryReadFailed { addr: tag_ptr, len: 4 })?;

    let tag_elements: [miden_core::Felt; 4] = tag_word.into();

    // Convert to reference implementation types
    let secret_key = SecretKey::from_elements(key_word.into());
    let nonce = Nonce::from(nonce_word);
    let auth_tag = AuthTag::new(tag_elements);

    // Construct EncryptedData
    let encrypted_data = EncryptedData::from_parts(DataType::Elements, ciphertext, auth_tag, nonce);

    // Decrypt using the standard reference implementation
    // This performs tag verification internally
    let plaintext_with_padding = secret_key.decrypt_elements(&encrypted_data)?;

    // Extract only the data blocks (without padding) to push onto advice stack
    // The MASM encrypt procedure will add padding automatically during re-encryption
    let mut plaintext_data = plaintext_with_padding;
    plaintext_data.truncate(data_blocks_count);

    // Preserve the VM's sequential word/block consumption order.
    advice.prepend_stack(plaintext_data);
    Ok(())
}

fn compute_sizes(num_blocks: u64, src_ptr: u64) -> Result<(u64, u64, usize), AeadDecryptError> {
    let num_ciphertext_elements = num_blocks
        .checked_add(1)
        .and_then(|blocks| blocks.checked_mul(8))
        .ok_or(AeadDecryptError::SizeOverflow)?;
    let tag_ptr = src_ptr
        .checked_add(num_ciphertext_elements)
        .ok_or(AeadDecryptError::SizeOverflow)?;
    let data_blocks_count: usize = num_blocks
        .checked_mul(8)
        .and_then(|count| count.try_into().ok())
        .ok_or(AeadDecryptError::SizeOverflow)?;
    if data_blocks_count
        .checked_mul(Word::SERIALIZED_SIZE / Word::NUM_ELEMENTS)
        .is_none_or(|size_bytes| size_bytes > MAX_AEAD_PLAINTEXT_BYTES)
    {
        return Err(AeadDecryptError::SizeOverflow);
    }

    Ok((num_ciphertext_elements, tag_ptr, data_blocks_count))
}

// ERROR HANDLING
// ================================================================================================

/// Error types that can occur during AEAD decryption.
#[derive(Debug, thiserror::Error)]
enum AeadDecryptError {
    /// Memory read failed or address overflow.
    #[error("failed to read memory region at addr={addr}, len={len}")]
    MemoryReadFailed { addr: u64, len: u64 },

    /// Size or address computation overflowed.
    #[error("size overflow in AEAD decrypt handler")]
    SizeOverflow,

    /// Decryption failed (wraps EncryptionError from miden-crypto).
    #[error(transparent)]
    DecryptionFailed(#[from] EncryptionError),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use miden_core::Word;
    use miden_event_handler::MAX_AEAD_PLAINTEXT_BYTES;

    use crate::handlers::aead_decrypt::{AEAD_DECRYPT_EVENT_NAME, AeadDecryptError, compute_sizes};

    #[test]
    fn test_event_name() {
        assert_eq!(AEAD_DECRYPT_EVENT_NAME.as_str(), "miden::core::crypto::aead::decrypt");
    }

    #[test]
    fn test_compute_sizes_happy_path() {
        let (num_ciphertext_elements, tag_ptr, data_blocks_count) =
            compute_sizes(1, 0).expect("sizes should fit");
        assert_eq!(num_ciphertext_elements, 16);
        assert_eq!(tag_ptr, 16);
        assert_eq!(data_blocks_count, 8);
    }

    #[test]
    fn test_compute_sizes_enforces_plaintext_limit() {
        let max_plaintext_elements =
            MAX_AEAD_PLAINTEXT_BYTES / (Word::SERIALIZED_SIZE / Word::NUM_ELEMENTS);
        let max_num_blocks = (max_plaintext_elements / 8) as u64;
        let (_, _, data_blocks_count) =
            compute_sizes(max_num_blocks, 0).expect("exact plaintext limit should fit");
        assert_eq!(data_blocks_count, max_plaintext_elements);
        assert!(matches!(
            compute_sizes(max_num_blocks + 1, 0),
            Err(AeadDecryptError::SizeOverflow)
        ));
    }

    #[test]
    fn test_compute_sizes_overflow_num_blocks() {
        let err = compute_sizes(u64::MAX, 0).expect_err("should overflow");
        assert!(matches!(err, AeadDecryptError::SizeOverflow));
    }

    #[test]
    fn test_compute_sizes_overflow_tag_ptr() {
        let err = compute_sizes(0, u64::MAX).expect_err("should overflow tag ptr");
        assert!(matches!(err, AeadDecryptError::SizeOverflow));
    }

    #[cfg(target_pointer_width = "32")]
    #[test]
    fn test_compute_sizes_overflow_data_blocks_count() {
        let num_blocks = (usize::MAX as u64 / 8) + 1;
        let err = compute_sizes(num_blocks, 0).expect_err("should overflow usize");
        assert!(matches!(err, AeadDecryptError::SizeOverflow));
    }
}
