use proptest::{
    prelude::{any, prop},
    prop_assert_eq, prop_assert_ne, prop_assume, proptest,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::aead::AeadScheme;

// PROPERTY-BASED TESTS
// ================================================================================================

proptest! {
    #[test]
    fn prop_bytes_felts_roundtrip(bytes in prop::collection::vec(any::<u8>(), 0..500)) {
        // bytes -> felts -> bytes
        let felts = bytes_to_elements_with_padding(&bytes);
        let back = padded_elements_to_bytes(&felts).unwrap();
        prop_assert_eq!(bytes, back);

        // And the other direction on valid encodings: felts come from bytes_to_felts,
        // so they must satisfy the padding invariant expected by felts_to_bytes.
        let felts_roundtrip = bytes_to_elements_with_padding(&padded_elements_to_bytes(&felts).unwrap());
        prop_assert_eq!(felts, felts_roundtrip);
    }

    #[test]
    fn test_encrypted_data_serialization_roundtrip(
        seed in any::<u64>(),
        associated_data_len in 1usize..100,
        data_len in 1usize..100,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random field elements
        let associated_data: Vec<Felt> = (0..associated_data_len)
            .map(|_| Felt::new_unchecked(rng.next_u64()))
            .collect();
        let data: Vec<Felt> = (0..data_len)
            .map(|_| Felt::new_unchecked(rng.next_u64()))
            .collect();

        let encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();
        let encrypted_serialized = encrypted.to_bytes();
        let encrypted_deserialized = EncryptedData::read_from_bytes(&encrypted_serialized).unwrap();

        prop_assert_eq!(encrypted, encrypted_deserialized);
    }

    #[test]
    fn test_encryption_decryption_roundtrip(
        seed in any::<u64>(),
        associated_data_len in 1usize..100,
        data_len in 1usize..100,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random field elements
        let associated_data: Vec<Felt> = (0..associated_data_len)
            .map(|_| Felt::new_unchecked(rng.next_u64()))
            .collect();
        let data: Vec<Felt> = (0..data_len)
            .map(|_| Felt::new_unchecked(rng.next_u64()))
            .collect();

        let encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();
        let decrypted = key.decrypt_elements_with_associated_data(&encrypted, &associated_data).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_bytes_encryption_decryption_roundtrip(
        seed in any::<u64>(),
        associated_data_len in 0usize..1000,
        data_len in 0usize..1000,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random bytes
        let mut associated_data = vec![0_u8; associated_data_len];
        rng.fill_bytes(&mut associated_data);

        let mut data = vec![0_u8; data_len];
        rng.fill_bytes(&mut data);


        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();
        let decrypted = key.decrypt_bytes_with_associated_data(&encrypted, &associated_data).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_different_keys_different_outputs(
        seed1 in any::<u64>(),
        seed2 in any::<u64>(),
        associated_data in prop::collection::vec(any::<u64>(), 1..500),
        data in prop::collection::vec(any::<u64>(), 1..500),
    ) {
        prop_assume!(seed1 != seed2);

        let mut rng1 = ChaCha20Rng::seed_from_u64(seed1);
        let mut rng2 = ChaCha20Rng::seed_from_u64(seed2);

        let key1 = SecretKey::with_rng(&mut rng1);
        let key2 = SecretKey::with_rng(&mut rng2);
        let nonce_word: Word = [ONE; 4].into();
        let nonce1 = Nonce::from(nonce_word);
        let nonce2 = Nonce::from(nonce_word);

        let associated_data: Vec<Felt> = associated_data.into_iter()
            .map(Felt::new_unchecked)
            .collect();
        let data: Vec<Felt> = data.into_iter()
            .map(Felt::new_unchecked)
            .collect();

        let encrypted1 = key1.encrypt_elements_with_nonce(&data, &associated_data, nonce1).unwrap();
        let encrypted2 = key2.encrypt_elements_with_nonce(&data, &associated_data, nonce2).unwrap();

        // Different keys should produce different ciphertexts
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        prop_assert_ne!(encrypted1.auth_tag, encrypted2.auth_tag);
    }

    #[test]
    fn test_different_nonces_different_outputs(
        seed in any::<u64>(),
        associated_data in prop::collection::vec(any::<u64>(), 1..50),
        data in prop::collection::vec(any::<u64>(), 1..50),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce1 = Nonce::from([ZERO; 4]);
        let nonce2 = Nonce::from([ONE; 4]);

        let associated_data: Vec<Felt> = associated_data.into_iter()
            .map(Felt::new_unchecked)
            .collect();
        let data: Vec<Felt> = data.into_iter()
            .map(Felt::new_unchecked)
            .collect();

        let encrypted1 = key.encrypt_elements_with_nonce(&data,&associated_data, nonce1).unwrap();
        let encrypted2 = key.encrypt_elements_with_nonce(&data, &associated_data, nonce2).unwrap();

        // Different nonces should produce different ciphertexts (with very high probability)
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        prop_assert_ne!(encrypted1.auth_tag, encrypted2.auth_tag);
    }
}

// UNIT TESTS
// ================================================================================================

#[test]
fn test_secret_key_creation() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key1 = SecretKey::with_rng(&mut rng);
    let key2 = SecretKey::with_rng(&mut rng);

    // Keys should be different
    assert_ne!(key1, key2);
}

#[test]
fn test_key_from_bytes_rejects_invalid_length() {
    let mut bytes = vec![0_u8; SK_SIZE_BYTES];
    bytes.push(0);

    assert!(AeadPoseidon2::key_from_bytes(&bytes).is_err());
}

#[test]
fn test_key_from_bytes_rejects_noncanonical_limb() {
    // 0xffffffff00000002 is Felt::ORDER + 1 (ORDER = 0xffffffff00000001), the smallest
    // noncanonical u64. Random HKDF output (as used by the IES CryptoBox path) lands here
    // with ~2^-32 per limb.
    let mut bytes = [0u8; SK_SIZE_BYTES];
    bytes[0] = 0x02;
    bytes[4] = 0xff;
    bytes[5] = 0xff;
    bytes[6] = 0xff;
    bytes[7] = 0xff;
    assert!(AeadPoseidon2::key_from_bytes(&bytes).is_err());
}

#[test]
fn test_key_from_uniform_bytes_accepts_noncanonical_limb() {
    // Limb 0 is 0xffffffff00000002 = Felt::ORDER + 1. Reduced mod ORDER it is 1.
    // Limbs 1-3 are zero. Pin both the acceptance and the exact reduction so a wrong mapping
    // (e.g. silently swapping to a different derivation) would fail this test.
    let mut bytes = [0u8; SK_SIZE_BYTES];
    bytes[0] = 0x02;
    bytes[4] = 0xff;
    bytes[5] = 0xff;
    bytes[6] = 0xff;
    bytes[7] = 0xff;
    let key = AeadPoseidon2::key_from_uniform_bytes(&bytes).unwrap();
    let elements = key.to_elements();
    assert_eq!(elements[0].as_canonical_u64(), 1);
    assert_eq!(elements[1].as_canonical_u64(), 0);
    assert_eq!(elements[2].as_canonical_u64(), 0);
    assert_eq!(elements[3].as_canonical_u64(), 0);
}

#[test]
fn test_key_from_uniform_bytes_rejects_invalid_length() {
    let bytes = [0u8; SK_SIZE_BYTES + 1];
    assert!(AeadPoseidon2::key_from_uniform_bytes(&bytes).is_err());
}

#[test]
fn test_decrypt_rejects_trailing_ciphertext_bytes() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);

    let mut encrypted_bytes =
        AeadPoseidon2::encrypt_bytes(&key, &mut rng, b"hello", b"associated").unwrap();
    encrypted_bytes.push(0);
    assert!(
        AeadPoseidon2::decrypt_bytes_with_associated_data(&key, &encrypted_bytes, b"associated")
            .is_err()
    );

    let mut encrypted_elements =
        AeadPoseidon2::encrypt_elements(&key, &mut rng, &[ONE], &[ZERO]).unwrap();
    encrypted_elements.push(0);
    assert!(
        AeadPoseidon2::decrypt_elements_with_associated_data(&key, &encrypted_elements, &[ZERO],)
            .is_err()
    );
}

#[test]
fn test_nonce_creation() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let nonce1 = Nonce::with_rng(&mut rng);
    let nonce2 = Nonce::with_rng(&mut rng);

    // Nonces should be different
    assert_ne!(nonce1, nonce2);
}

#[test]
fn test_empty_data_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let empty_data: Vec<Felt> = vec![];
    let encrypted = key.encrypt_elements_with_nonce(&empty_data, &associated_data, nonce).unwrap();
    let decrypted =
        key.decrypt_elements_with_associated_data(&encrypted, &associated_data).unwrap();

    assert_eq!(empty_data, decrypted);
    assert!(!encrypted.ciphertext.is_empty());
}

#[test]
fn test_single_element_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ZERO; 8];
    let data = vec![Felt::new_unchecked(42)];
    let encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();
    let decrypted =
        key.decrypt_elements_with_associated_data(&encrypted, &associated_data).unwrap();

    assert_eq!(data, decrypted);
    assert_eq!(encrypted.ciphertext.len(), 8);
}

#[test]
fn test_large_data_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    // Test with data larger than rate
    let data: Vec<Felt> = (0..100).map(|i| Felt::new_unchecked(i as u64)).collect();

    let encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();
    let decrypted =
        key.decrypt_elements_with_associated_data(&encrypted, &associated_data).unwrap();

    assert_eq!(data, decrypted);
}

#[test]
fn test_encryption_various_lengths() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let associated_data: Vec<Felt> = vec![ONE; 8];

    for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 35, 39, 54, 67, 100, 1000] {
        let data: Vec<Felt> = (0..len).map(|i| Felt::new_unchecked(i as u64)).collect();

        let nonce = Nonce::with_rng(&mut rng);
        let encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();
        let decrypted =
            key.decrypt_elements_with_associated_data(&encrypted, &associated_data).unwrap();

        assert_eq!(data, decrypted, "Failed for length {len}");
    }
}

#[test]
fn test_bytes_encryption_various_lengths() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let associated_data: Vec<u8> = vec![1; 8];

    for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 35, 39, 54, 67, 100, 1000] {
        let mut data = vec![0_u8; len];
        rng.fill_bytes(&mut data);

        let nonce = Nonce::with_rng(&mut rng);
        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();
        let decrypted =
            key.decrypt_bytes_with_associated_data(&encrypted, &associated_data).unwrap();

        assert_eq!(data, decrypted, "Failed for length {len}");
    }
}

#[test]
fn test_ciphertext_tampering_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new_unchecked(123), Felt::new_unchecked(456)];
    let mut encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();

    // Tamper with ciphertext
    encrypted.ciphertext[0] += ONE;

    let result = key.decrypt_elements_with_associated_data(&encrypted, &associated_data);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

#[test]
fn test_auth_tag_tampering_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new_unchecked(123), Felt::new_unchecked(456)];
    let mut encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();

    // Tamper with auth tag
    let mut tampered_tag = encrypted.auth_tag.0;
    tampered_tag[0] += ONE;
    encrypted.auth_tag = AuthTag(tampered_tag);

    let result = key.decrypt_elements_with_associated_data(&encrypted, &associated_data);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

#[test]
fn test_wrong_key_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key1 = SecretKey::with_rng(&mut rng);
    let key2 = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new_unchecked(123), Felt::new_unchecked(456)];
    let encrypted = key1.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();

    // Try to decrypt with wrong key
    let result = key2.decrypt_elements_with_associated_data(&encrypted, &associated_data);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

#[test]
fn test_wrong_nonce_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);
    let nonce1 = Nonce::with_rng(&mut rng);
    let nonce2 = Nonce::with_rng(&mut rng);

    let associated_data: Vec<Felt> = vec![ONE; 8];
    let data = vec![Felt::new_unchecked(123), Felt::new_unchecked(456)];
    let mut encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce1).unwrap();

    // Try to decrypt with wrong nonce
    encrypted.nonce = nonce2;
    let result = key.decrypt_elements_with_associated_data(&encrypted, &associated_data);
    assert!(matches!(result, Err(EncryptionError::InvalidAuthTag)));
}

// SECURITY TESTS
// ================================================================================================

#[cfg(test)]
mod security_tests {
    use alloc::collections::BTreeSet;

    use super::*;

    #[test]
    fn test_key_serialization() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let key = SecretKey::with_rng(&mut rng);

        let key_serialized = key.to_bytes();
        let key_deserialized = SecretKey::read_from_bytes(&key_serialized).unwrap();

        assert_eq!(key, key_deserialized)
    }

    #[test]
    fn test_key_uniqueness() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut keys = BTreeSet::new();

        // Generate 1000 keys and ensure they're all unique
        for _ in 0..1000 {
            let key = SecretKey::with_rng(&mut rng);
            let key_bytes = format!("{:?}", key.0);
            assert!(keys.insert(key_bytes), "Duplicate key generated!");
        }
    }

    #[test]
    fn test_nonce_uniqueness() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let mut nonces = BTreeSet::new();

        // Generate 1000 nonces and ensure they're all unique
        for _ in 0..1000 {
            let nonce = Nonce::with_rng(&mut rng);
            let nonce_bytes = format!("{:?}", nonce.0);
            assert!(nonces.insert(nonce_bytes), "Duplicate nonce generated!");
        }
    }

    #[test]
    fn test_ciphertext_appears_random() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let key = SecretKey::with_rng(&mut rng);

        // Encrypt the same plaintext with different nonces
        let associated_data: Vec<Felt> = vec![ONE; 8];
        let plaintext = vec![ZERO; 10]; // All zeros
        let mut ciphertexts = Vec::new();

        for _ in 0..100 {
            let nonce = Nonce::with_rng(&mut rng);
            let encrypted =
                key.encrypt_elements_with_nonce(&plaintext, &associated_data, nonce).unwrap();
            ciphertexts.push(encrypted.ciphertext);
        }

        // Ensure all ciphertexts are different (randomness test)
        for i in 0..ciphertexts.len() {
            for j in i + 1..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "Ciphertexts {i} and {j} are identical!",
                );
            }
        }
    }

    #[test]
    fn test_secret_key_from_to_elements() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // Generate a random key
        let key1 = SecretKey::with_rng(&mut rng);

        // Extract elements and reconstruct
        let elements = key1.to_elements();
        let key2 = SecretKey::from_elements(elements);

        // Should be equal
        assert_eq!(key1, key2);

        // Should produce same ciphertext
        let plaintext = vec![Felt::new_unchecked(42), Felt::new_unchecked(100)];
        let nonce = Nonce::with_rng(&mut rng);

        let encrypted1 = key1.encrypt_elements_with_nonce(&plaintext, &[], nonce.clone()).unwrap();
        let encrypted2 = key2.encrypt_elements_with_nonce(&plaintext, &[], nonce).unwrap();

        assert_eq!(encrypted1, encrypted2);
    }

    #[test]
    fn test_secret_key_debug_redaction() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let key = SecretKey::with_rng(&mut rng);

        // Verify Debug impl produces expected redacted output
        let debug_output = format!("{key:?}");
        assert_eq!(debug_output, "<elided secret for SecretKey>");

        // Verify Display impl also elides
        let display_output = format!("{key}");
        assert_eq!(display_output, "<elided secret for SecretKey>");
    }

    #[test]
    fn test_secret_key_constant_time_equality() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        let key1 = SecretKey::with_rng(&mut rng);
        let key2 = SecretKey::with_rng(&mut rng);
        let key1_clone = key1.clone();

        // Same key should be equal
        assert_eq!(key1, key1_clone);

        // Different keys should not be equal
        assert_ne!(key1, key2);
    }
}
