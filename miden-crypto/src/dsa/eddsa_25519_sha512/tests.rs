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

mod signature {
    use crate::{dsa::eddsa_25519_sha512::Signature, rand::test_utils::seeded_rng};

    /// Wraps `sig_bytes` in a DER BIT STRING: tag `0x03`, length, zero unused-bits byte, payload.
    fn encode_bitstring(sig_bytes: &[u8; 64]) -> alloc::vec::Vec<u8> {
        let mut out = alloc::vec::Vec::with_capacity(2 + 1 + 64); // tag + length + unused-bits + payload
        out.push(0x03); // BIT STRING tag
        out.push(65); // content length: 1 (unused-bits byte) + 64 (signature bytes)
        out.push(0x00); // unused bits: 0 means all bits in the final byte are significant
        out.extend_from_slice(sig_bytes);
        out
    }

    /// Generates a deterministic 64-byte Ed25519 signature from the given RNG seed.
    fn make_sig_bytes(rng_seed: [u8; 32]) -> [u8; 64] {
        use miden_field::Word;

        use crate::dsa::eddsa_25519_sha512::SigningKey;
        let mut rng = seeded_rng(rng_seed);
        let sk = SigningKey::with_rng(&mut rng);
        sk.sign(Word::default()).inner.to_bytes()
    }

    #[test]
    fn from_der_bitstring_roundtrip() {
        let sig_bytes = make_sig_bytes([0u8; 32]);
        let der = encode_bitstring(&sig_bytes);
        let sig = Signature::from_der(&der).expect("valid DER BIT STRING should parse");
        assert_eq!(sig.inner.to_bytes(), sig_bytes);
    }

    #[test]
    fn from_der_accepts_arbitrary_64_bytes() {
        let bytes = [0xff; 64];
        assert!(Signature::from_der(&bytes).is_ok());
    }

    #[test]
    fn from_der_raw_64_bytes() {
        let sig_bytes = make_sig_bytes([1u8; 32]);
        let sig = Signature::from_der(&sig_bytes).expect("raw 64 bytes should parse");
        assert_eq!(sig.inner.to_bytes(), sig_bytes);
    }

    #[test]
    fn from_der_rejects_bad_tag() {
        let sig_bytes = make_sig_bytes([2u8; 32]);
        let mut der = encode_bitstring(&sig_bytes);
        der[0] = 0x30; // SEQUENCE tag instead of BIT STRING
        assert!(Signature::from_der(&der).is_err());
    }

    #[test]
    fn from_der_rejects_trailing_data() {
        let sig_bytes = make_sig_bytes([3u8; 32]);
        let mut der = encode_bitstring(&sig_bytes);
        der.push(0x00); // trailing byte
        assert!(Signature::from_der(&der).is_err());
    }

    #[test]
    fn from_der_rejects_empty_input() {
        assert!(Signature::from_der(&[]).is_err());
    }

    #[test]
    fn from_der_rejects_nonzero_unused_bits() {
        let sig_bytes = make_sig_bytes([4u8; 32]);
        let mut der = encode_bitstring(&sig_bytes);
        der[2] = 0x01; // set unused bits to 1
        assert!(Signature::from_der(&der).is_err());
    }

    #[test]
    fn from_der_rejects_wrong_length() {
        // 32-byte raw input: not 64 bytes so not raw, and not valid DER BIT STRING
        let short: [u8; 32] = [0xab; 32];
        assert!(Signature::from_der(&short).is_err());
    }

    #[test]
    fn from_der_rejects_truncated_payload() {
        let sig_bytes = make_sig_bytes([6u8; 32]);
        let mut der = encode_bitstring(&sig_bytes);
        der.pop(); // remove one byte
        assert!(Signature::from_der(&der).is_err());
    }

    #[test]
    fn from_der_rejects_non_minimal_length_encoding() {
        // BER long-form length encoding: 0x81 0x41 instead of 0x41
        let sig_bytes = make_sig_bytes([5u8; 32]);
        let mut der = alloc::vec![0x03u8, 0x81, 65, 0x00];
        der.extend_from_slice(&sig_bytes);
        assert!(Signature::from_der(&der).is_err());
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
