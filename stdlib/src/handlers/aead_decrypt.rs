//! AEAD decryption event handler for the Miden VM.
//!
//! This module provides an event handler for decrypting AEAD ciphertext using non-deterministic
//! advice. When the VM emits an AEAD_DECRYPT_EVENT, this handler reads the ciphertext from memory,
//! performs decryption using the reference implementation, and inserts the plaintext into the
//! advice map for the MASM decrypt procedure to load.

use alloc::{vec, vec::Vec};

use miden_core::{EventId, Felt, Word};
use miden_crypto::{aead::aead_rpo::SecretKey, hash::rpo::Rpo256};
use miden_processor::{AdviceMutation, EventError, ProcessState};
use libc_print::libc_println;

/// Qualified event name for the AEAD decrypt event.
pub const AEAD_DECRYPT_EVENT_NAME: &str = "stdlib::crypto::aead::decrypt";

/// Constant Event ID for the AEAD decrypt event.
/// Computed via `EventId::from_name(AEAD_DECRYPT_EVENT_NAME)`
pub const AEAD_DECRYPT_EVENT_ID: EventId = EventId::from_u64(12034814376348458125);

/// Event handler for AEAD decryption.
///
/// This handler is called when the VM emits an AEAD_DECRYPT_EVENT. It:
/// 1. Reads the ciphertext from memory at src_ptr
/// 2. Decrypts using the provided key and nonce via the reference implementation
/// 3. Inserts the plaintext into the advice map (keyed by nonce)
pub fn handle_aead_decrypt(process: &ProcessState) -> Result<Vec<AdviceMutation>, EventError> {
    // Stack: [nonce(4), key(4), src_ptr, dst_ptr, num_blocks, ...]

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

    libc_println!("Event handler - nonce: {:?}", nonce_word);
    libc_println!("Event handler - key: {:?}", key_word);
    libc_println!("Event handler - src_ptr: {}", src_ptr);
    libc_println!("Event handler - dst_ptr: {}", _dst_ptr);
    libc_println!("Event handler - num_blocks: {}", num_blocks);

    // Read ciphertext from memory (num_blocks * 8 elements)
    let num_elements = (num_blocks * 8) as usize;
    let mut ciphertext = Vec::with_capacity(num_elements);
libc_println!("src_ptr handler {:?}", src_ptr);
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
libc_println!("ciphertext handler {:?}", ciphertext);
    // Convert to reference implementation types
    let _secret_key = SecretKey::from_elements(key_word.into()); // kept for future reference

    // Manually decrypt the ciphertext using the AEAD algorithm
    // This follows the same logic as SecretKey::decrypt_elements but without tag verification
    // (tag verification happens in MASM after re-encryption)

    const RATE_WIDTH: usize = 8;
    const STATE_WIDTH: usize = 12;

    // Initialize sponge state: [key(4), nonce(4), capacity(4)]
    let mut state = [Felt::new(0); STATE_WIDTH];
    let key_elements: [Felt; 4] = key_word.into();
    let nonce_elements: [Felt; 4] = nonce_word.into();

    state[0..4].copy_from_slice(&key_elements);
    state[4..8].copy_from_slice(&nonce_elements);
    // capacity elements [8..12] remain zero (no domain separator)

    // Process associated data padding [1,0,0,0,0,0,0,0] (empty AD)
    Rpo256::apply_permutation(&mut state);
    state[8] += Felt::new(1); // add 1 to first capacity element
    state[0] = Felt::new(1);  // overwrite rate with AD padding
    for i in 1..8 {
        state[i] = Felt::new(0);
    }

    // Decrypt each 8-element block
    let mut plaintext = Vec::with_capacity(num_elements);

    for chunk in ciphertext.chunks(RATE_WIDTH) {
        // Apply permutation to generate keystream
        Rpo256::apply_permutation(&mut state);

        // Squeeze the keystream (rate portion)
        let keystream: [Felt; 8] = [
            state[0], state[1], state[2], state[3],
            state[4], state[5], state[6], state[7],
        ];

        // Decrypt: plaintext = ciphertext - keystream
        for (i, &ciphertext_felt) in chunk.iter().enumerate() {
            let plaintext_felt = ciphertext_felt - keystream[i];
            plaintext.push(plaintext_felt);
        }

        // Update rate portion with ciphertext for next iteration
        state[0..chunk.len()].copy_from_slice(chunk);
    }

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
    #[allow(dead_code)]
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
