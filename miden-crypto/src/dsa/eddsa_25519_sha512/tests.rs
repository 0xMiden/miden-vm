#![cfg(test)]
mod signing_key {
    use miden_field::{Felt, Word};
    use miden_serde_utils::{Deserializable, Serializable};

    use crate::{
        dsa::eddsa_25519_sha512::{PublicKey, SigningKey, UncheckedVerificationError},
        rand::test_utils::seeded_rng,
    };

    #[test]
    fn sign_and_verify_roundtrip() {
        let mut rng = seeded_rng([0u8; 32]);
        let sk = SigningKey::with_rng(&mut rng);
        let pk = sk.public_key();

        let msg = Word::default(); // all zeros
        let sig = sk.sign(msg);

        assert!(pk.verify(msg, &sig));
    }

    #[test]
    fn test_key_generation_serialization() {
        let mut rng = seeded_rng([1u8; 32]);

        let sk = SigningKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // Secret key -> bytes -> recovered secret key
        let sk_bytes = sk.to_bytes();
        let serialized_sk = SigningKey::read_from_bytes(&sk_bytes)
            .expect("deserialization of valid secret key bytes should succeed");
        assert_eq!(sk.to_bytes(), serialized_sk.to_bytes());

        // Public key -> bytes -> recovered public key
        let pk_bytes = pk.to_bytes();
        let serialized_pk = PublicKey::read_from_bytes(&pk_bytes)
            .expect("deserialization of valid public key bytes should succeed");
        assert_eq!(pk, serialized_pk);
    }

    #[test]
    fn test_secret_key_debug_redaction() {
        let mut rng = seeded_rng([2u8; 32]);
        let sk = SigningKey::with_rng(&mut rng);

        // Verify Debug impl produces expected redacted output
        let debug_output = format!("{sk:?}");
        assert_eq!(debug_output, "<elided secret for SigningKey>");

        // Verify Display impl also elides
        let display_output = format!("{sk}");
        assert_eq!(display_output, "<elided secret for SigningKey>");
    }

    #[test]
    fn test_compute_challenge_k_equivalence() {
        let mut rng = seeded_rng([3u8; 32]);
        let sk = SigningKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // Test with multiple different messages
        let messages = [
            Word::default(),
            Word::from([
                Felt::new_unchecked(1),
                Felt::new_unchecked(2),
                Felt::new_unchecked(3),
                Felt::new_unchecked(4),
            ]),
            Word::from([
                Felt::new_unchecked(42),
                Felt::new_unchecked(100),
                Felt::new_unchecked(255),
                Felt::new_unchecked(1000),
            ]),
        ];

        for message in messages {
            let signature = sk.sign(message);

            // Compute the challenge hash using the helper method
            let k_hash = pk.compute_challenge_k(message, &signature);

            // Verify using verify_with_unchecked_k should give the same result as verify()
            let result_with_k = pk.verify_with_unchecked_k(k_hash, &signature).is_ok();
            let result_standard = pk.verify(message, &signature);

            assert_eq!(
                result_with_k, result_standard,
                "verify_with_unchecked_k(compute_challenge_k(...)) should equal verify()"
            );
            assert!(result_standard, "Signature should be valid");

            // Test with wrong message - both should fail
            let wrong_message = Word::from([
                Felt::new_unchecked(999),
                Felt::new_unchecked(888),
                Felt::new_unchecked(777),
                Felt::new_unchecked(666),
            ]);
            let wrong_k_hash = pk.compute_challenge_k(wrong_message, &signature);

            assert!(matches!(
                pk.verify_with_unchecked_k(wrong_k_hash, &signature),
                Err(UncheckedVerificationError::EquationMismatch)
            ));
            assert!(!pk.verify(wrong_message, &signature), "verify with wrong message should fail");
        }
    }
}

mod key_exchange_key {
    use miden_serde_utils::{Deserializable, Serializable};

    use crate::{
        dsa::eddsa_25519_sha512::{KeyExchangeKey, PublicKey},
        rand::test_utils::seeded_rng,
    };

    #[test]
    fn test_key_generation_serialization() {
        let mut rng = seeded_rng([1u8; 32]);

        let sk = KeyExchangeKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // Secret key -> bytes -> recovered secret key
        let sk_bytes = sk.to_bytes();
        let serialized_sk = KeyExchangeKey::read_from_bytes(&sk_bytes)
            .expect("deserialization of valid secret key bytes should succeed");
        assert_eq!(sk.to_bytes(), serialized_sk.to_bytes());

        // Public key -> bytes -> recovered public key
        let pk_bytes = pk.to_bytes();
        let serialized_pk = PublicKey::read_from_bytes(&pk_bytes)
            .expect("deserialization of valid public key bytes should succeed");
        assert_eq!(pk, serialized_pk);
    }

    #[test]
    fn test_secret_key_debug_redaction() {
        let mut rng = seeded_rng([2u8; 32]);
        let sk = KeyExchangeKey::with_rng(&mut rng);

        // Verify Debug impl produces expected redacted output
        let debug_output = format!("{sk:?}");
        assert_eq!(debug_output, "<elided secret for KeyExchangeKey>");

        // Verify Display impl also elides
        let display_output = format!("{sk}");
        assert_eq!(display_output, "<elided secret for KeyExchangeKey>");
    }
}
