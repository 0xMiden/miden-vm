//! AEAD decryption event handler for the Miden VM.
//!
//! This module provides an event handler for decrypting AEAD ciphertext using non-deterministic
//! advice. When the VM emits an AEAD_DECRYPT_EVENT, this handler reads the ciphertext from memory,
//! performs decryption using the reference implementation, and inserts the plaintext into the
//! advice map for the MASM decrypt procedure to load.

use alloc::{vec, vec::Vec};

use miden_core::{EventName, FieldElement, Word};
use miden_crypto::aead::{
    DataType,
    aead_rpo::{AuthTag, EncryptedData, Nonce, SecretKey},
};
use miden_processor::{AdviceMutation, EventError, ProcessState};

/// Qualified event name for the AEAD decrypt event.
pub const AEAD_DECRYPT_EVENT_NAME: EventName = EventName::new("stdlib::crypto::aead::decrypt");

/// Event handler for AEAD decryption.
///
/// This handler is called when the VM emits an AEAD_DECRYPT_EVENT. It reads the full
/// ciphertext (including padding block) and tag from memory, performs decryption and
/// tag verification using the reference implementation, then provides the plaintext
/// via the advice map.
///
/// Process:
/// 1. Reads full ciphertext from memory at src_ptr ((num_blocks + 1) * 8 elements)
/// 2. Reads authentication tag from memory at src_ptr + (num_blocks + 1) * 8
/// 3. Constructs EncryptedData and decrypts using the reference implementation
/// 4. Tag verification is performed by the reference implementation decrypt method
/// 5. Extracts only the data blocks (first num_blocks * 8 elements) from plaintext
/// 6. Inserts the data blocks (WITHOUT padding) into the advice map (keyed by nonce)
///
/// Memory layout at src_ptr:
/// - [ciphertext_blocks(num_blocks * 8), encrypted_padding(8), tag(4)]
/// - This handler reads ALL elements: data blocks + padding + tag
///
/// The MASM decrypt procedure will then:
/// 1. Load the plaintext data blocks from advice and write to dst_ptr
/// 2. Call encrypt which reads the data blocks and adds padding automatically
/// 3. Re-encrypt data + padding to compute authentication tag
/// 4. Compare computed tag with expected tag and halt if they don't match
///
/// Security: Tag verification happens TWICE in this design:
/// 1. Once in this event handler (via reference implementation)
/// 2. Once in the MASM decrypt procedure (via re-encryption)
///
/// Both verifications must pass for execution to succeed. The double verification
/// provides defense in depth and ensures cryptographic soundness.
///
/// Non-determinism soundness: Using advice for decryption is cryptographically sound
/// because:
/// 1. The event handler verifies the tag before providing plaintext
/// 2. The MASM procedure re-verifies the tag via re-encryption
/// 3. The deterministic encryption creates a bijection between plaintext and ciphertext
/// 4. A malicious prover cannot provide incorrect plaintext without causing tag mismatch
pub fn handle_aead_decrypt(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [nonce(4), key(4), src_ptr, dst_ptr, num_blocks, ...]
    // where:
    //   src_ptr = ciphertext + encrypted_padding + tag location (input)
    //   dst_ptr = plaintext destination (output)
    //   num_blocks = number of plaintext data blocks (NO padding)

    // Read parameters from stack
    // Note: Stack position 0 contains the Event ID when the handler is called,
    // so the actual parameters start at position 1
    // Also note: Words on the stack are stored in reverse element order
    let nonce_word = Word::new([
        process.get_stack_item(4),
        process.get_stack_item(3),
        process.get_stack_item(2),
        process.get_stack_item(1),
    ]);

    let key_word = Word::new([
        process.get_stack_item(8),
        process.get_stack_item(7),
        process.get_stack_item(6),
        process.get_stack_item(5),
    ]);

    let src_ptr = process.get_stack_item(9).as_int();
    let _dst_ptr = process.get_stack_item(10).as_int(); // Not needed for decryption
    let num_blocks = process.get_stack_item(11).as_int();

    // Read full ciphertext from memory including padding block
    // Total: (num_blocks + 1) * 8 elements (data blocks + padding block)
    let num_ciphertext_elements = ((num_blocks + 1) * 8) as usize;
    let mut ciphertext = Vec::with_capacity(num_ciphertext_elements);
    let ctx = process.ctx();
    for i in 0..num_ciphertext_elements {
        let addr = (src_ptr + i as u64) as u32;
        let value =
            process
                .get_mem_value(ctx, addr)
                .ok_or_else(|| AeadDecryptError::MemoryReadFailed {
                    addr,
                    reason: alloc::string::String::from("memory read returned None"),
                })?;
        ciphertext.push(value);
    }

    // Read the authentication tag (4 elements at src_ptr + (num_blocks + 1) * 8)
    let tag_addr = (src_ptr + (num_blocks + 1) * 8) as u32;
    let mut tag_elements = [miden_core::Felt::ZERO; 4];
    for i in 0..4 {
        let addr = tag_addr + i as u32;
        let value =
            process
                .get_mem_value(ctx, addr)
                .ok_or_else(|| AeadDecryptError::MemoryReadFailed {
                    addr,
                    reason: alloc::string::String::from("tag read returned None"),
                })?;
        tag_elements[i as usize] = value;
    }

    // Convert to reference implementation types
    let secret_key = SecretKey::from_elements(key_word.into());
    let nonce = Nonce::from(nonce_word);
    let auth_tag = AuthTag::new(tag_elements);

    // Construct EncryptedData
    let encrypted_data =
        EncryptedData::from_parts(DataType::Elements, ciphertext, auth_tag, nonce.clone());

    // Decrypt using the standard reference implementation
    // This performs tag verification internally
    let plaintext_with_padding = secret_key.decrypt_elements(&encrypted_data).map_err(|e| {
        AeadDecryptError::DecryptionFailed {
            reason: alloc::format!("decryption failed: {:?}", e),
        }
    })?;

    // Extract only the data blocks (without padding) to insert into advice
    // The MASM encrypt procedure will add padding automatically during re-encryption
    let data_blocks_count = (num_blocks * 8) as usize;
    let plaintext_data: Vec<_> =
        plaintext_with_padding.into_iter().take(data_blocks_count).collect();

    // Insert plaintext data (WITHOUT padding) into advice map with key = nonce (4 elements)
    // The padding will be added by the MASM encrypt procedure during re-encryption
    // Create an AdviceMap from the iterator
    let advice_map: miden_core::AdviceMap =
        core::iter::once((nonce_word, plaintext_data)).collect();
    let advice_map_mutation = AdviceMutation::extend_map(advice_map);

    Ok(vec![advice_map_mutation])
}

// ERROR HANDLING
// ================================================================================================

/// Error types that can occur during AEAD decryption.
#[derive(Debug, thiserror::Error)]
enum AeadDecryptError {
    /// Memory read failed.
    #[error("failed to read memory at address {addr}: {reason}")]
    MemoryReadFailed { addr: u32, reason: alloc::string::String },

    /// Decryption failed.
    #[error("decryption failed: {reason}")]
    DecryptionFailed { reason: alloc::string::String },
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_event_name() {
        assert_eq!(AEAD_DECRYPT_EVENT_NAME.as_str(), "stdlib::crypto::aead::decrypt");
    }
}
