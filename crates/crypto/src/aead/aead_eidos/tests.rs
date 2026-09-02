use proptest::{prelude::any, prop_assert_eq, proptest};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::{ONE, utils::Serializable};

fn test_key() -> SecretKey {
    SecretKey::from_elements([
        Felt::new_unchecked(1),
        Felt::new_unchecked(2),
        Felt::new_unchecked(3),
        Felt::new_unchecked(4),
    ])
}

fn test_nonce() -> Nonce {
    Nonce::from([
        Felt::new_unchecked(0x10),
        Felt::new_unchecked(0x20),
        Felt::new_unchecked(0x30),
        Felt::new_unchecked(0x40),
    ])
}

#[test]
fn key_and_nonce_serialization_roundtrip() {
    let key = test_key();
    let nonce = test_nonce();

    assert_eq!(SecretKey::read_from_bytes(&key.to_bytes()).unwrap(), key);
    assert_eq!(Nonce::read_from_bytes(&nonce.to_bytes()).unwrap(), nonce);
}

#[test]
fn key_from_bytes_rejects_invalid_input() {
    let short = [0_u8; SK_SIZE_BYTES - 1];
    assert!(AeadEidos::key_from_bytes(&short).is_err());

    // Felt::ORDER + 1 is the smallest non-canonical u64 after the modulus itself.
    let mut noncanonical = [0_u8; SK_SIZE_BYTES];
    noncanonical[..8].copy_from_slice(&(Felt::ORDER + 1).to_le_bytes());
    assert!(AeadEidos::key_from_bytes(&noncanonical).is_err());
}

#[test]
fn key_from_uniform_bytes_reduces_each_limb() {
    let mut bytes = [0_u8; SK_SIZE_BYTES];
    bytes[..8].copy_from_slice(&(Felt::ORDER + 1).to_le_bytes());

    let key = AeadEidos::key_from_uniform_bytes(&bytes).unwrap();
    assert_eq!(key.to_elements(), [Felt::ONE, Felt::ZERO, Felt::ZERO, Felt::ZERO]);
    assert!(AeadEidos::key_from_uniform_bytes(&bytes[..SK_SIZE_BYTES - 1]).is_err());
}

#[test]
fn encrypted_data_serialization_roundtrip() {
    let encrypted = test_key()
        .encrypt_elements_with_nonce(
            &[Felt::ZERO, Felt::new_unchecked(1 << 63), Felt::new_unchecked(42)],
            &[Felt::new_unchecked(9)],
            test_nonce(),
        )
        .unwrap();

    let encoded = encrypted.to_bytes();
    assert_eq!(EncryptedData::read_from_bytes(&encoded).unwrap(), encrypted);
}

#[test]
fn element_encryption_handles_edge_lengths_and_values() {
    let key = test_key();
    let associated_data = [Felt::new_unchecked(7), Felt::new_unchecked(8)];

    for len in [0, 1, 7, 8, 9, 16, 17, 31] {
        let mut plaintext =
            (0..len).map(|value| Felt::new_unchecked(value as u64)).collect::<Vec<_>>();
        if len > 2 {
            plaintext[1] = Felt::new_unchecked(1 << 63);
            plaintext[2] = Felt::new(Felt::ORDER - 1).unwrap();
        }

        let encrypted = key
            .encrypt_elements_with_nonce(&plaintext, &associated_data, test_nonce())
            .unwrap();
        assert_eq!(encrypted.ciphertext().len(), plaintext.len() * 2);
        assert_eq!(
            key.decrypt_elements_with_associated_data(&encrypted, &associated_data).unwrap(),
            plaintext
        );
    }
}

#[test]
fn byte_encryption_handles_edge_lengths() {
    let key = test_key();
    let associated_data = b"associated data\0with zeros";

    for len in [0, 1, 7, 8, 9, 15, 16, 17, 31, 32, 33] {
        let plaintext = (0..len).map(|value| value as u8).collect::<Vec<_>>();
        let encrypted =
            key.encrypt_bytes_with_nonce(&plaintext, associated_data, test_nonce()).unwrap();
        assert_eq!(
            key.decrypt_bytes_with_associated_data(&encrypted, associated_data).unwrap(),
            plaintext
        );
    }
}

#[test]
fn authentication_covers_every_input() {
    let key = test_key();
    let plaintext = [Felt::new_unchecked(11), Felt::new_unchecked(12)];
    let associated_data = [Felt::new_unchecked(13)];
    let encrypted = key
        .encrypt_elements_with_nonce(&plaintext, &associated_data, test_nonce())
        .unwrap();

    let mut forged_ciphertext = encrypted.clone();
    forged_ciphertext.ciphertext[0] += ONE;
    assert!(matches!(
        key.decrypt_elements_with_associated_data(&forged_ciphertext, &associated_data),
        Err(EncryptionError::InvalidAuthTag)
    ));

    let mut forged_tag = encrypted.clone();
    forged_tag.auth_tag.0[1] += ONE;
    assert!(matches!(
        key.decrypt_elements_with_associated_data(&forged_tag, &associated_data),
        Err(EncryptionError::InvalidAuthTag)
    ));

    let mut forged_nonce = encrypted.clone();
    forged_nonce.nonce.0[0] += ONE;
    assert!(matches!(
        key.decrypt_elements_with_associated_data(&forged_nonce, &associated_data),
        Err(EncryptionError::InvalidAuthTag)
    ));

    assert!(matches!(
        key.decrypt_elements_with_associated_data(&encrypted, &[Felt::new_unchecked(14)]),
        Err(EncryptionError::InvalidAuthTag)
    ));
}

#[test]
fn data_representation_is_authenticated() {
    let key = test_key();
    let mut encrypted = key
        .encrypt_elements_with_nonce(&[Felt::new_unchecked(5)], &[], test_nonce())
        .unwrap();

    assert!(matches!(
        key.decrypt_bytes(&encrypted),
        Err(EncryptionError::InvalidDataType { .. })
    ));

    encrypted.data_type = DataType::Bytes;
    assert!(matches!(key.decrypt_bytes(&encrypted), Err(EncryptionError::InvalidAuthTag)));
}

#[test]
fn malformed_ciphertext_is_rejected_at_public_boundaries() {
    assert!(matches!(
        EncryptedData::from_parts(
            DataType::Elements,
            vec![Felt::ONE],
            AuthTag::default(),
            test_nonce(),
        ),
        Err(EncryptionError::MalformedCiphertext)
    ));

    assert!(matches!(
        EncryptedData::from_parts(
            DataType::Elements,
            vec![Felt::new_unchecked(1 << 40), Felt::ZERO],
            AuthTag::default(),
            test_nonce(),
        ),
        Err(EncryptionError::MalformedCiphertext)
    ));
}

#[test]
fn authenticated_input_limit_accounts_for_expansion_and_type_marker() {
    let largest_plaintext = (MAX_AUTHENTICATED_INPUT_FELTS - 8) / 2;
    assert!(validate_encryption_lengths(largest_plaintext, 0).is_ok());
    assert!(matches!(
        validate_encryption_lengths(largest_plaintext + 1, 0),
        Err(EncryptionError::InputTooLong)
    ));

    let largest_associated_data = MAX_AUTHENTICATED_INPUT_FELTS - 7;
    assert!(validate_encryption_lengths(0, largest_associated_data).is_ok());
    assert!(matches!(
        validate_encryption_lengths(0, largest_associated_data + 1),
        Err(EncryptionError::InputTooLong)
    ));
}

#[test]
fn trait_decryption_rejects_trailing_bytes() {
    let key = test_key();
    let mut rng = ChaCha20Rng::seed_from_u64(1);
    let mut ciphertext = AeadEidos::encrypt_bytes(&key, &mut rng, b"message", b"context").unwrap();
    ciphertext.push(0);

    assert!(AeadEidos::decrypt_bytes_with_associated_data(&key, &ciphertext, b"context").is_err());
}

#[test]
fn different_keys_and_nonces_change_the_result() {
    let key = test_key();
    let other_key = SecretKey::from_elements([
        Felt::new_unchecked(5),
        Felt::new_unchecked(6),
        Felt::new_unchecked(7),
        Felt::new_unchecked(8),
    ]);
    let nonce = test_nonce();
    let other_nonce = Nonce::from([Felt::ONE; NONCE_SIZE]);
    let plaintext = [Felt::new_unchecked(9)];

    let first = key.encrypt_elements_with_nonce(&plaintext, &[], nonce).unwrap();
    let second = other_key.encrypt_elements_with_nonce(&plaintext, &[], nonce).unwrap();
    let third = key.encrypt_elements_with_nonce(&plaintext, &[], other_nonce).unwrap();

    assert_ne!(first.ciphertext(), second.ciphertext());
    assert_ne!(first.auth_tag(), second.auth_tag());
    assert_ne!(first.ciphertext(), third.ciphertext());
    assert_ne!(first.auth_tag(), third.auth_tag());
}

proptest! {
    #[test]
    fn byte_roundtrip_property(seed in any::<u64>(), data_len in 0usize..512, ad_len in 0usize..128) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);
        let mut plaintext = vec![0_u8; data_len];
        let mut associated_data = vec![0_u8; ad_len];
        rng.fill_bytes(&mut plaintext);
        rng.fill_bytes(&mut associated_data);

        let encrypted = key
            .encrypt_bytes_with_nonce(&plaintext, &associated_data, nonce)
            .unwrap();
        prop_assert_eq!(
            key.decrypt_bytes_with_associated_data(&encrypted, &associated_data)
                .unwrap(),
            plaintext
        );
    }

    #[test]
    fn element_roundtrip_property(
        seed in any::<u64>(),
        plaintext in proptest::collection::vec(0u64..Felt::ORDER, 0..128),
        associated_data in proptest::collection::vec(0u64..Felt::ORDER, 0..64),
    ) {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let key = SecretKey::with_rng(&mut rng);
        let nonce = Nonce::with_rng(&mut rng);
        let plaintext = plaintext.into_iter().map(Felt::new_unchecked).collect::<Vec<_>>();
        let associated_data = associated_data
            .into_iter()
            .map(Felt::new_unchecked)
            .collect::<Vec<_>>();

        let encrypted = key
            .encrypt_elements_with_nonce(&plaintext, &associated_data, nonce)
            .unwrap();
        prop_assert_eq!(
            key.decrypt_elements_with_associated_data(&encrypted, &associated_data)
                .unwrap(),
            plaintext
        );
    }
}
