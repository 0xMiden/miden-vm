//! AEAD decryption event handler for the Miden VM.
//!
//! This module provides an event handler for decrypting AEAD ciphertext using non-deterministic
//! advice. When the VM emits an AEAD_DECRYPT_EVENT, this handler reads the ciphertext from memory,
//! performs decryption using the reference implementation, and inserts the plaintext into the
//! advice map for the MASM decrypt procedure to load.

use alloc::{vec, vec::Vec};

use miden_core::{EventId, Word};
use miden_crypto::aead::aead_rpo::{Nonce, SecretKey};
use miden_processor::{AdviceMutation, EventError, ProcessState};

/// Qualified event name for the AEAD decrypt event.
pub const AEAD_DECRYPT_EVENT_NAME: &str = "stdlib::crypto::aead::decrypt";

/// Constant Event ID for the AEAD decrypt event.
/// Computed via `EventId::from_name(AEAD_DECRYPT_EVENT_NAME)`
pub const AEAD_DECRYPT_EVENT_ID: EventId = EventId::from_u64(12034814376348458125);

/// Event handler for AEAD decryption.
///
/// This handler is called when the VM emits an AEAD_DECRYPT_EVENT. It:
/// 1. Reads the ciphertext from memory at src_ptr (num_blocks * 8 elements)
/// 2. Decrypts using the provided key and nonce via the reference implementation
/// 3. Inserts the plaintext (with padding) into the advice map (keyed by nonce)
///
/// Memory layout at src_ptr: [ciphertext_blocks..., tag(4)]
/// - The tag is located at src_ptr + (num_blocks * 8)
/// - Only the ciphertext blocks are read by this handler (not the tag)
///
/// The MASM decrypt procedure will then:
/// 1. Load the plaintext from advice and write it to dst_ptr
/// 2. Re-encrypt the plaintext to compute an authentication tag
/// 3. Read the expected tag from src_ptr + (num_blocks * 8)
/// 4. Compare computed tag with expected tag and halt if they don't match
///
/// Security: This handler provides plaintext via non-deterministic advice. The MASM
/// procedure MUST verify the authentication tag to ensure the plaintext is authentic.
/// The tag verification is automatic and mandatory in the MASM decrypt procedure.
///
/// Non-determinism soundness: Using advice for decryption is cryptographically sound
/// because the MASM procedure re-encrypts the claimed plaintext and verifies the tag.
/// The deterministic encryption creates a bijection between plaintext and ciphertext,
/// so the tag uniquely commits to both. A malicious prover cannot provide incorrect
/// plaintext without causing a tag mismatch, which halts execution.
pub fn handle_aead_decrypt(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [nonce(4), key(4), src_ptr, dst_ptr, num_blocks, ...]
    // where:
    //   src_ptr = ciphertext + tag location (input)
    //   dst_ptr = plaintext destination (output)
    //   num_blocks = number of data blocks (excluding tag word)

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

    // Read ciphertext from memory (num_blocks * 8 elements)
    let num_elements = (num_blocks * 8) as usize;
    let mut ciphertext = Vec::with_capacity(num_elements);
    let ctx = process.ctx();
    for i in 0..num_elements {
        let addr = (src_ptr + i as u64) as u32;
        let value = process.get_mem_value(ctx, addr).ok_or_else(|| {
            AeadDecryptError::MemoryReadFailed {
                addr,
                reason: alloc::string::String::from("memory read returned None"),
            }
        })?;
        ciphertext.push(value);
    }

    // Convert to reference implementation types
    let secret_key = SecretKey::from_elements(key_word.into());
    let nonce = Nonce::from(nonce_word);

    // Decrypt using the reference implementation (no tag verification)
    // Tag verification happens in MASM after re-encryption
    let plaintext = secret_key
        .decrypt_elements_no_verify(&ciphertext, &nonce, &[])
        .map_err(|e| AeadDecryptError::DecryptionFailed {
            reason: alloc::format!("decryption failed: {:?}", e),
        })?;

    // Insert plaintext into advice map with key = nonce (4 elements)
    // Create an AdviceMap from the iterator
    let advice_map: miden_core::AdviceMap =
        core::iter::once((nonce_word, plaintext)).collect();
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
    fn test_compute_event_id() {
        let expected_event_id = EventId::from_name(AEAD_DECRYPT_EVENT_NAME);
        // This will fail and show us the correct value
        assert_eq!(AEAD_DECRYPT_EVENT_ID, expected_event_id);
    }
}
