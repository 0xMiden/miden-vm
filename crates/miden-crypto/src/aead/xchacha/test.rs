use proptest::{
    prelude::{any, prop},
    prop_assert_eq, prop_assert_ne, proptest,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::aead::AeadScheme;

// PROPERTY-BASED TESTS
// ================================================================================================

proptest! {
    #[test]
    fn test_encryption_decryption_roundtrip(
        seed in any::<u64>(),
        data_len in 1usize..1000,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random field elements
        let data: Vec<Felt> = (0..data_len)
            .map(|_| Felt::new_unchecked(rng.random::<u64>()))
            .collect();

        let encrypted = key.encrypt_elements_with_nonce(&data, &[], nonce).unwrap();
        let decrypted = key.decrypt_elements(&encrypted).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_encryption_decryption_with_ad_roundtrip(
        seed in any::<u64>(),
        associated_data_len in 1usize..1000,
        data_len in 1usize..1000,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random field elements
        let associated_data: Vec<Felt> = (0..associated_data_len)
            .map(|_| Felt::new_unchecked(rng.random::<u64>()))
            .collect();
        let data: Vec<Felt> = (0..data_len)
            .map(|_| Felt::new_unchecked(rng.random::<u64>()))
            .collect();

        let encrypted = key.encrypt_elements_with_nonce(&data, &associated_data, nonce).unwrap();
        let decrypted = key.decrypt_elements_with_associated_data(&encrypted, &associated_data).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_bytes_encryption_decryption_roundtrip(
        seed in any::<u64>(),
        data_len in 0usize..1000,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random bytes
        let mut data = vec![0_u8; data_len];
        rng.fill(&mut data[..]);

        let encrypted = key.encrypt_bytes_with_nonce(&data, &[], nonce).unwrap();
        let decrypted = key.decrypt_bytes(&encrypted).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_bytes_encryption_decryption_with_ad_roundtrip(
        seed in any::<u64>(),
        associated_data_len in 0usize..1000,
        data_len in 0usize..1000,
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);

        // Generate random bytes
        let mut associated_data = vec![0_u8; associated_data_len];
        rng.fill(&mut associated_data[..]);

        let mut data = vec![0_u8; data_len];
        rng.fill(&mut data[..]);


        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();
        let decrypted = key.decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data).unwrap();

        prop_assert_eq!(data, decrypted);
    }

    #[test]
    fn test_different_keys_different_outputs(
        seed1 in any::<u64>(),
        seed2 in any::<u64>(),
        associated_data in prop::collection::vec(any::<u8>(), 1..500),
        data in prop::collection::vec(any::<u8>(), 1..500),
    ) {
        let mut rng1 = ChaCha20Rng::seed_from_u64(seed1);
        let mut rng2 = ChaCha20Rng::seed_from_u64(seed2);

        let key1 = SecretKey::with_rng(&mut rng1);
        let key2 = SecretKey::with_rng(&mut rng2);
        let mut nonce_bytes = [0_u8; 24];
        rng2.fill(&mut nonce_bytes[..]);
        let nonce1 = Nonce::from_slice(&nonce_bytes);
        let nonce2 = Nonce::from_slice(&nonce_bytes);

        let encrypted1 = key1.encrypt_bytes_with_nonce(&data, &associated_data, nonce1).unwrap();
        let encrypted2 = key2.encrypt_bytes_with_nonce(&data, &associated_data, nonce2).unwrap();

        // Different keys should produce different ciphertexts (unless seeds collide)
        if seed1 != seed2 {
            prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
        }
    }

    #[test]
    fn test_different_nonces_different_outputs(
        seed in any::<u64>(),
        associated_data in prop::collection::vec(any::<u8>(), 1..500),
        data in prop::collection::vec(any::<u8>(), 1..500),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let mut nonce_bytes = [0_u8; 24];
        rng.fill(&mut nonce_bytes[..]);
        let nonce1 = Nonce::from_slice(&nonce_bytes);
        rng.fill(&mut nonce_bytes[..]);
        let nonce2 = Nonce::from_slice(&nonce_bytes);

        let encrypted1 = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce1).unwrap();
        let encrypted2 = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce2).unwrap();

        // Different nonces should produce different ciphertexts (with very high probability)
        prop_assert_ne!(encrypted1.ciphertext, encrypted2.ciphertext);
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

    assert!(XChaCha::key_from_bytes(&bytes).is_err());
}

#[test]
fn test_secret_key_serialization() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let key_bytes = key.to_bytes();
    let key_serialized = SecretKey::read_from_bytes(&key_bytes).unwrap();

    assert_eq!(key, key_serialized);
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

    let associated_data = vec![1; 8];
    let empty_data = vec![];
    let encrypted = key.encrypt_bytes_with_nonce(&empty_data, &associated_data, nonce).unwrap();
    let decrypted = key
        .decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data)
        .unwrap();

    assert_eq!(empty_data, decrypted);
}

#[test]
fn test_single_element_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data = vec![1; 8];
    let data = vec![42];
    let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();
    let decrypted = key
        .decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data)
        .unwrap();

    assert_eq!(data, decrypted);
}

#[test]
fn test_large_data_encryption() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data = vec![1; 8];
    // Test with data larger than rate
    let data: Vec<_> = (0..100).collect();

    let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();
    let decrypted = key
        .decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data)
        .unwrap();

    assert_eq!(data, decrypted);
}

#[test]
fn test_encryption_various_lengths() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let associated_data = vec![1; 8];

    for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 35, 39, 54, 67, 100, 255] {
        let data: Vec<_> = (0..len).collect();

        let nonce = Nonce::with_rng(&mut rng);
        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();
        let decrypted = key
            .decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data)
            .unwrap();

        assert_eq!(data, decrypted, "Failed for length {len}");
    }
}

#[test]
fn test_encrypted_data_serialization() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let associated_data = vec![1; 8];

    for len in [1, 7, 8, 9, 15, 16, 17, 31, 32, 35, 39, 54, 67, 100, 255] {
        let data: Vec<_> = (0..len).collect();

        let nonce = Nonce::with_rng(&mut rng);
        let encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();
        let encrypted_data_bytes = encrypted.to_bytes();

        let encrypted_data_serialized =
            EncryptedData::read_from_bytes(&encrypted_data_bytes).unwrap();

        assert_eq!(encrypted, encrypted_data_serialized, "Failed for length {len}");
    }
}

#[test]
fn test_ciphertext_tampering_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data = vec![1; 8];
    let data = vec![123, 45];
    let mut encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();

    // Tamper with ciphertext
    encrypted.ciphertext[0] = encrypted.ciphertext[0].wrapping_add(1);

    let result = key.decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data);
    assert!(result.is_err());
}

#[test]
fn test_wrong_key_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key1 = SecretKey::with_rng(&mut rng);
    let key2 = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let associated_data = vec![1; 8];
    let data = vec![123, 45];
    let encrypted = key1.encrypt_bytes_with_nonce(&data, &associated_data, nonce).unwrap();

    // Try to decrypt with wrong key
    let result = key2.decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data);
    assert!(result.is_err());
}

#[test]
fn test_wrong_nonce_detection() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let key = SecretKey::with_rng(&mut rng);
    let nonce1 = Nonce::with_rng(&mut rng);
    let nonce2 = Nonce::with_rng(&mut rng);

    let associated_data: Vec<u8> = vec![1; 8];
    let data = vec![123, 55];
    let mut encrypted = key.encrypt_bytes_with_nonce(&data, &associated_data, nonce1).unwrap();

    // Try to decrypt with wrong nonce
    encrypted.nonce = nonce2;
    let result = key.decrypt_bytes_with_associated_data_unchecked(&encrypted, &associated_data);
    assert!(result.is_err());
}

// SECURITY TESTS
// ================================================================================================

#[cfg(test)]
mod security_tests {
    use alloc::collections::BTreeSet;

    use super::*;

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

        // Generate 1000 nonces and ensure they're all unique
        let mut nonces = BTreeSet::new();
        for _ in 0..1000 {
            let nonce = Nonce::with_rng(&mut rng);
            let nonce_bytes = format!("{:?}", nonce.inner);
            assert!(nonces.insert(nonce_bytes), "Duplicate nonce generated!");
        }
    }

    #[test]
    fn test_ciphertext_appears_random() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);
        let key = SecretKey::with_rng(&mut rng);

        // Encrypt the same plaintext with different nonces
        let associated_data = vec![1; 8];
        let plaintext = vec![3; 10];
        let mut ciphertexts = Vec::new();

        for _ in 0..100 {
            let nonce = Nonce::with_rng(&mut rng);
            let encrypted =
                key.encrypt_bytes_with_nonce(&plaintext, &associated_data, nonce).unwrap();
            ciphertexts.push(encrypted.ciphertext);
        }

        // Ensure all ciphertexts are different (randomness test)
        for i in 0..ciphertexts.len() {
            for j in i + 1..ciphertexts.len() {
                assert_ne!(
                    ciphertexts[i], ciphertexts[j],
                    "Ciphertexts {i} and {j} are identical!"
                );
            }
        }
    }
}
