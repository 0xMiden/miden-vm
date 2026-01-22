//! AEAD decryption event handler for the Miden VM.
//!
//! This module provides an event handler for decrypting AEAD ciphertext using non-deterministic
//! advice. When the VM emits an AEAD_DECRYPT_EVENT, this handler reads the ciphertext from memory,
//! performs decryption using the AEAD-Poseidon2 scheme, and pushes the plaintext onto the advice
//! stack for the MASM decrypt procedure to load.

use alloc::{vec, vec::Vec};

use miden_core::{EventName, field::PrimeField64};
use miden_crypto::aead::{
    DataType, EncryptionError,
    aead_poseidon2::{AuthTag, EncryptedData, Nonce, SecretKey},
};
use miden_processor::{AdviceMutation, EventError, ProcessorState};

use crate::handlers::read_memory_region;

/// Qualified event name for the AEAD decrypt event.
pub const AEAD_DECRYPT_EVENT_NAME: EventName = EventName::new("miden::core::crypto::aead::decrypt");

/// Event handler for AEAD decryption.
///
/// This handler is called when the VM emits an AEAD_DECRYPT_EVENT. It reads the full
/// ciphertext (including padding block) and tag from memory, performs decryption and
/// tag verification using AEAD-Poseidon2, then pushes the plaintext onto the advice stack.
///
/// Process:
/// 1. Reads full ciphertext from memory at src_ptr ((num_blocks + 1) * 8 elements)
/// 2. Reads authentication tag from memory at src_ptr + (num_blocks + 1) * 8
/// 3. Constructs EncryptedData and decrypts using AEAD-Poseidon2
/// 4. Extracts only the data blocks (first num_blocks * 8 elements) from plaintext
/// 5. Pushes the data blocks (WITHOUT padding) onto the advice stack in reverse order
///
/// Memory layout at src_ptr:
/// - [ciphertext_blocks(num_blocks * 8), encrypted_padding(8), tag(4)]
/// - This handler reads ALL elements: data blocks + padding + tag
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
pub fn handle_aead_decrypt(process: &ProcessorState) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [event_id, key(4), nonce(4), src_ptr, dst_ptr, num_blocks, ...]
    // where:
    //   src_ptr = ciphertext + encrypted_padding + tag location (input)
    //   dst_ptr = plaintext destination (output)
    //   num_blocks = number of plaintext data blocks (NO padding)

    // Read parameters from stack
    // Note: Stack position 0 contains the Event ID when the handler is called,
    // so the actual parameters start at position 1. Words on the stack are
    // interpreted in little-endian (memory) order, i.e. element at stack index N
    // becomes the first limb of the word.
    let key_word = process.get_stack_word(1);
    let nonce_word = process.get_stack_word(5);

    let src_ptr = process.get_stack_item(9).as_canonical_u64();
    let num_blocks = process.get_stack_item(11).as_canonical_u64();

    // Read ciphertext from memory: (num_blocks + 1) * 8 elements (data + padding)
    let num_ciphertext_elements = (num_blocks + 1) * 8;
    let ciphertext = read_memory_region(process, src_ptr, num_ciphertext_elements).ok_or(
        AeadDecryptError::MemoryReadFailed {
            addr: src_ptr,
            len: num_ciphertext_elements,
        },
    )?;

    // Read authentication tag: 4 elements (1 word) immediately after ciphertext
    let tag_ptr = src_ptr + num_ciphertext_elements;
    let tag_addr: u32 = tag_ptr
        .try_into()
        .ok()
        .ok_or(AeadDecryptError::MemoryReadFailed { addr: tag_ptr, len: 4 })?;

    let ctx = process.ctx();
    let tag_word = process
        .get_mem_word(ctx, tag_addr)
        .map_err(|_| AeadDecryptError::MemoryReadFailed { addr: tag_ptr, len: 4 })?
        .ok_or(AeadDecryptError::MemoryReadFailed { addr: tag_ptr, len: 4 })?;

    let tag_elements: [miden_core::Felt; 4] = tag_word.into();

    // Convert to reference implementation types
    let secret_key = SecretKey::from_elements(key_word.into());
    let nonce = Nonce::from(nonce_word);
    let auth_tag = AuthTag::new(tag_elements);

    // Construct EncryptedData
    let encrypted_data =
        EncryptedData::from_parts(DataType::Elements, ciphertext, auth_tag, nonce.clone());

    // Decrypt using the standard reference implementation
    // This performs tag verification internally
    let plaintext_with_padding = secret_key.decrypt_elements(&encrypted_data)?;

    // Extract only the data blocks (without padding) to push onto advice stack
    // The MASM encrypt procedure will add padding automatically during re-encryption
    let data_blocks_count = (num_blocks * 8) as usize;
    let mut plaintext_data = plaintext_with_padding;
    plaintext_data.truncate(data_blocks_count);

    // Push plaintext data (WITHOUT padding) onto advice stack.
    // Values are provided in structural order; `extend_stack` ensures the first element
    // ends up at the top of the advice stack, matching `adv_pipe` expectations.
    let advice_stack_mutation = AdviceMutation::extend_stack(plaintext_data);

    Ok(vec![advice_stack_mutation])
}

// ERROR HANDLING
// ================================================================================================

/// Error types that can occur during AEAD decryption.
#[derive(Debug, thiserror::Error)]
enum AeadDecryptError {
    /// Memory read failed or address overflow.
    #[error("failed to read memory region at addr={addr}, len={len}")]
    MemoryReadFailed { addr: u64, len: u64 },

    /// Decryption failed (wraps EncryptionError from miden-crypto).
    #[error(transparent)]
    DecryptionFailed(#[from] EncryptionError),
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use crate::handlers::aead_decrypt::AEAD_DECRYPT_EVENT_NAME;

    #[test]
    fn test_event_name() {
        assert_eq!(AEAD_DECRYPT_EVENT_NAME.as_str(), "miden::core::crypto::aead::decrypt");
    }
}
