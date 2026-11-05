use proptest::{
    prelude::{any, prop},
    prop_assert_eq, prop_assert_ne, proptest,
};
use rand::{RngExt, SeedableRng};
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
            .map(|_| rng.random::<Felt>())
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
            .map(|_| rng.random::<Felt>())
            .collect();
        let data: Vec<Felt> = (0..data_len)
            .map(|_| rng.random::<Felt>())
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
fn test_decrypt_rejects_trailing_ciphertext_bytes() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let key = SecretKey::with_rng(&mut rng);

    let mut encrypted = XChaCha::encrypt_bytes(&key, &mut rng, b"hello", b"associated").unwrap();
    encrypted.push(0);

    assert!(XChaCha::decrypt_bytes_with_associated_data(&key, &encrypted, b"associated").is_err());
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

// DATA TYPE AUTHENTICATION TESTS
// ================================================================================================

#[test]
fn test_discriminator_flip_bytes_to_elements_fails_authentication() {
    let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
    let key = SecretKey::with_rng(&mut rng);

    // Empty and nonempty equivalent byte/Felt AAD encodings.
    let aad_fixtures = [
        (Vec::<u8>::new(), Vec::<Felt>::new()),
        (elements_to_bytes(&[Felt::new_unchecked(7)]), vec![Felt::new_unchecked(7)]),
    ];

    for (ad_bytes, ad_felts) in aad_fixtures {
        let nonce = Nonce::with_rng(&mut rng);

        // Eight zero bytes are the canonical encoding of the single Felt zero, so the flipped
        // discriminator still produces a valid field-element plaintext.
        let encrypted = key.encrypt_bytes_with_nonce(&[0_u8; 8], &ad_bytes, nonce).unwrap();
        let mut serialized = encrypted.to_bytes();
        assert_eq!(serialized[0], DataType::Bytes as u8);

        serialized[0] = DataType::Elements as u8;
        let flipped = EncryptedData::read_from_bytes(&serialized).unwrap();

        // Match the new discriminator and supply the equivalent Felt AAD so neither the
        // wrong-type precheck nor the field conversion can mask the missing authentication.
        let result = key.decrypt_elements_with_associated_data(&flipped, &ad_felts);
        assert!(
            matches!(result, Err(EncryptionError::FailedOperation)),
            "expected FailedOperation for AAD byte length {}, got {result:?}",
            ad_bytes.len()
        );
    }
}

#[test]
fn test_discriminator_flip_elements_to_bytes_fails_authentication() {
    let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
    let key = SecretKey::with_rng(&mut rng);

    // Empty and nonempty equivalent Felt/byte AAD encodings.
    let aad_fixtures = [
        (Vec::<Felt>::new(), Vec::<u8>::new()),
        (vec![Felt::new_unchecked(9)], elements_to_bytes(&[Felt::new_unchecked(9)])),
    ];

    for (ad_felts, ad_bytes) in aad_fixtures {
        let nonce = Nonce::with_rng(&mut rng);

        let plaintext = [Felt::new_unchecked(1), Felt::new_unchecked(2)];
        let encrypted = key.encrypt_elements_with_nonce(&plaintext, &ad_felts, nonce).unwrap();
        let mut serialized = encrypted.to_bytes();
        assert_eq!(serialized[0], DataType::Elements as u8);

        serialized[0] = DataType::Bytes as u8;
        let flipped = EncryptedData::read_from_bytes(&serialized).unwrap();

        // Match the new discriminator and supply the equivalent byte AAD so neither the
        // wrong-type precheck nor the field conversion can mask the missing authentication.
        let result = key.decrypt_bytes_with_associated_data(&flipped, &ad_bytes);
        assert!(
            matches!(result, Err(EncryptionError::FailedOperation)),
            "expected FailedOperation for AAD byte length {}, got {result:?}",
            ad_bytes.len()
        );
    }
}

#[test]
fn test_intact_ciphertexts_roundtrip_with_equivalent_aad_encodings() {
    let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
    let key = SecretKey::with_rng(&mut rng);

    // Empty associated data for both representations.
    let nonce = Nonce::with_rng(&mut rng);
    let encrypted = key.encrypt_bytes_with_nonce(&[0_u8; 8], &[], nonce).unwrap();
    assert_eq!(key.decrypt_bytes(&encrypted).unwrap(), vec![0_u8; 8]);

    let nonce = Nonce::with_rng(&mut rng);
    let elements = vec![Felt::ZERO];
    let encrypted = key.encrypt_elements_with_nonce(&elements, &[], nonce).unwrap();
    assert_eq!(key.decrypt_elements(&encrypted).unwrap(), elements);

    // The byte encoding of a Felt associated data is also a valid byte associated data;
    // both encodings must round-trip through their matching typed APIs.
    let ad_felts = [Felt::new_unchecked(7)];
    let ad_bytes = elements_to_bytes(&ad_felts);
    assert_eq!(ad_bytes.len(), 8);

    let nonce = Nonce::with_rng(&mut rng);
    let encrypted = key.encrypt_bytes_with_nonce(b"payload", &ad_bytes, nonce).unwrap();
    assert_eq!(
        key.decrypt_bytes_with_associated_data(&encrypted, &ad_bytes).unwrap(),
        b"payload".to_vec()
    );

    let nonce = Nonce::with_rng(&mut rng);
    let encrypted = key.encrypt_elements_with_nonce(&elements, &ad_felts, nonce).unwrap();
    assert_eq!(
        key.decrypt_elements_with_associated_data(&encrypted, &ad_felts).unwrap(),
        elements
    );
}

#[test]
fn test_intact_wrong_typed_api_calls_return_invalid_data_type() {
    let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
    let key = SecretKey::with_rng(&mut rng);

    let nonce = Nonce::with_rng(&mut rng);
    let encrypted_bytes = key.encrypt_bytes_with_nonce(b"payload", &[], nonce).unwrap();
    let result = key.decrypt_elements(&encrypted_bytes);
    assert!(
        matches!(
            result,
            Err(EncryptionError::InvalidDataType {
                expected: DataType::Elements,
                found: DataType::Bytes,
            })
        ),
        "expected InvalidDataType, got {result:?}"
    );

    let nonce = Nonce::with_rng(&mut rng);
    let encrypted_elements = key.encrypt_elements_with_nonce(&[Felt::ZERO], &[], nonce).unwrap();
    let result = key.decrypt_bytes(&encrypted_elements);
    assert!(
        matches!(
            result,
            Err(EncryptionError::InvalidDataType {
                expected: DataType::Bytes,
                found: DataType::Elements,
            })
        ),
        "expected InvalidDataType, got {result:?}"
    );
}

#[test]
fn test_tampered_ciphertext_returns_failed_operation() {
    let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let nonce = Nonce::with_rng(&mut rng);

    let mut encrypted = key.encrypt_bytes_with_nonce(b"payload", b"associated", nonce).unwrap();
    encrypted.ciphertext[0] ^= 1;

    let result = key.decrypt_bytes_with_associated_data(&encrypted, b"associated");
    assert!(
        matches!(result, Err(EncryptionError::FailedOperation)),
        "expected FailedOperation, got {result:?}"
    );
}

#[test]
fn test_aead_scheme_default_paths_roundtrip() {
    let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
    let key = XChaCha::key_from_bytes(&[7_u8; SK_SIZE_BYTES]).unwrap();

    let associated_data = b"associated";
    let ciphertext = XChaCha::encrypt_bytes(&key, &mut rng, b"payload", associated_data).unwrap();
    let plaintext =
        XChaCha::decrypt_bytes_with_associated_data(&key, &ciphertext, associated_data).unwrap();
    assert_eq!(plaintext, b"payload".to_vec());

    // IES element sealing uses these default trait methods, which convert elements to bytes
    // and label the serialized ciphertext as bytes.
    let elements = vec![Felt::ZERO, Felt::new_unchecked(42)];
    let ad_felts = vec![Felt::new_unchecked(9)];
    let ciphertext = XChaCha::encrypt_elements(&key, &mut rng, &elements, &ad_felts).unwrap();
    let plaintext =
        XChaCha::decrypt_elements_with_associated_data(&key, &ciphertext, &ad_felts).unwrap();
    assert_eq!(plaintext, elements);
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
