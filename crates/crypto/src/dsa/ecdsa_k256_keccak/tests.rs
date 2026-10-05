#![cfg(test)]

mod signing_key {
    use alloc::string::{String, ToString};

    use k256::elliptic_curve::sec1::ToSec1Point;
    use miden_field::{Felt, Word};
    #[cfg(feature = "std")]
    use miden_serde_utils::ByteReader;
    use miden_serde_utils::{Deserializable, Serializable};

    use crate::{
        dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey},
        hash::{keccak::Keccak256, poseidon2::Poseidon2},
        rand::test_utils::seeded_rng,
        utils::hex_to_bytes,
    };

    #[test]
    fn test_key_generation() {
        let mut rng = seeded_rng([0u8; 32]);

        let secret_key = SigningKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        // Test that we can convert to/from bytes
        let sk_bytes = secret_key.to_bytes();
        let recovered_sk = SigningKey::read_from_bytes(&sk_bytes).unwrap();
        assert_eq!(secret_key.to_bytes(), recovered_sk.to_bytes());

        let pk_bytes = public_key.to_bytes();
        let recovered_pk = PublicKey::read_from_bytes(&pk_bytes).unwrap();
        assert_eq!(public_key, recovered_pk);
    }

    #[test]
    fn test_public_key_serialization_uses_compressed_sec1() {
        let mut rng = seeded_rng([14u8; 32]);
        let public_key = SigningKey::with_rng(&mut rng).public_key();

        let serialized = public_key.to_bytes();
        let affine_sec1 = public_key.as_affine().to_sec1_point(true);

        assert_eq!(serialized.len(), 33);
        assert!(matches!(serialized[0], 0x02 | 0x03));
        assert_eq!(serialized.as_slice(), affine_sec1.as_bytes());

        let recovered_pk = PublicKey::read_from_bytes(&serialized).unwrap();
        assert_eq!(public_key, recovered_pk);
        assert_eq!(public_key.to_string(), canonical_hex(&serialized));
    }

    #[test]
    fn test_secret_key_deserialization_rejects_invalid_bytes() {
        // A scalar of all 0xFF is above the secp256k1 curve order, and an all-zero scalar is
        // also invalid, so both must be rejected with an error rather than a panic. This is the
        // early-return path that previously skipped zeroizing the read buffer.
        for invalid in [[0xffu8; 32], [0u8; 32]] {
            let result = SigningKey::read_from_bytes(&invalid);
            assert!(result.is_err(), "invalid secret key bytes must fail to deserialize");
        }
    }

    #[test]
    fn test_public_key_recovery() {
        let mut rng = seeded_rng([1u8; 32]);

        let secret_key = SigningKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        // Generate a signature using the secret key
        let message = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let signature = secret_key.sign(message);

        // Recover the public key
        let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
        assert_eq!(public_key, recovered_pk);

        // Using the wrong message, we shouldn't be able to recover the public key
        let message = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(5),
        ]
        .into();
        let recovered_pk = PublicKey::recover_from(message, &signature).unwrap();
        assert!(public_key != recovered_pk);
    }

    #[test]
    fn test_public_key_recovery_matches_ethereum_consensus_vector() {
        // Ethereum execution-spec test `CallEcrecover0`:
        // https://github.com/ethereum/execution-spec-tests/blob/62035359cc4bd2d326844188f2003d29f6be1d97/tests/static/state_tests/stPreCompiledContracts2/CallEcrecover0Filler.json
        let digest = hex_to_bytes::<32>(
            "0x18c547e4f7b0f325ad1e56f57e26c745b09a3e503d86e00e5255ff7f715d3d1c",
        )
        .unwrap();
        let signature_bytes = hex_to_bytes::<64>(concat!(
            "0x73b1693892219d736caba55bdb67216e485557ea6b6af75f37096c9aa6a5a75f",
            "eeb940b1d03b21e36b0e47e79769f095fe2ab855bd91e3a38756b7d75a9c4549",
        ))
        .unwrap();
        let signature = Signature::from_sec1_bytes_and_recovery_id(signature_bytes, 1).unwrap();
        let public_key = PublicKey::recover_from_prehash(digest, &signature).unwrap();
        let uncompressed = public_key.as_affine().to_sec1_point(false);
        let address_digest = Keccak256::hash(&uncompressed.as_bytes()[1..]);
        let expected_address =
            hex_to_bytes::<20>("0xa94f5374fce5edbc8e2a8697c15331677e6ebf0b").unwrap();

        assert_eq!(&address_digest.as_bytes()[12..], expected_address);
    }

    #[test]
    fn test_sign_and_verify() {
        let mut rng = seeded_rng([2u8; 32]);

        let secret_key = SigningKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        let message = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let signature = secret_key.sign(message);

        // Verify using public key method
        assert!(public_key.verify(message, &signature));

        // Verify using signature method
        assert!(signature.verify(message, &public_key));

        // Test with wrong message
        let wrong_message = [
            Felt::new_unchecked(5),
            Felt::new_unchecked(6),
            Felt::new_unchecked(7),
            Felt::new_unchecked(8),
        ]
        .into();
        assert!(!public_key.verify(wrong_message, &signature));
    }

    #[test]
    fn test_signature_serialization_default() {
        let mut rng = seeded_rng([3u8; 32]);

        let secret_key = SigningKey::with_rng(&mut rng);
        let message = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let signature = secret_key.sign(message);

        let sig_bytes = signature.to_bytes();
        let recovered_sig = Signature::read_from_bytes(&sig_bytes).unwrap();

        assert_eq!(signature, recovered_sig);
    }

    #[test]
    fn test_signature_serialization() {
        let mut rng = seeded_rng([4u8; 32]);

        let secret_key = SigningKey::with_rng(&mut rng);
        let message = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let signature = secret_key.sign(message);
        let recovery_id = signature.v();

        let sig_bytes = signature.to_sec1_bytes();
        let recovered_sig =
            Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();

        assert_eq!(signature, recovered_sig);

        let recovery_id = (recovery_id + 1) % 4;
        let recovered_sig =
            Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();
        assert_ne!(signature, recovered_sig);

        let recovered_sig =
            Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();
        assert_ne!(signature, recovered_sig);
    }

    #[test]
    fn test_secret_key_debug_redaction() {
        let mut rng = seeded_rng([5u8; 32]);
        let secret_key = SigningKey::with_rng(&mut rng);

        // Verify Debug impl produces expected redacted output
        let debug_output = format!("{secret_key:?}");
        assert_eq!(debug_output, "<elided secret for SigningKey>");

        // Verify Display impl also elides
        let display_output = format!("{secret_key}");
        assert_eq!(display_output, "<elided secret for SigningKey>");
    }

    #[test]
    fn test_public_key_and_signature_display_hex() {
        let mut rng = seeded_rng([6u8; 32]);
        let secret_key = SigningKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let message = [
            Felt::new_unchecked(1),
            Felt::new_unchecked(2),
            Felt::new_unchecked(3),
            Felt::new_unchecked(4),
        ]
        .into();
        let signature = secret_key.sign(message);

        // `Display` must render the canonical serialized bytes as `0x`-prefixed lowercase hex.
        assert_eq!(public_key.to_string(), canonical_hex(&public_key.to_bytes()));
        assert_eq!(signature.to_string(), canonical_hex(&signature.to_bytes()));
        assert!(public_key.to_string().starts_with("0x"));
        assert!(signature.to_string().starts_with("0x"));
    }

    /// Renders `bytes` as a `0x`-prefixed lowercase hex string, mirroring the expected `Display`
    /// output.
    fn canonical_hex(bytes: &[u8]) -> String {
        let mut s = String::from("0x");
        for byte in bytes {
            s.push_str(&format!("{byte:02x}"));
        }
        s
    }

    #[test]
    fn test_public_key_native_commitment_test_vector() {
        let mut secret_key_bytes = [0u8; 32];
        secret_key_bytes[31] = 1;
        let signing_key = SigningKey::read_from_bytes(&secret_key_bytes).unwrap();
        let public_key = signing_key.public_key();

        const COMPRESSED_SEC1: [u8; 33] = [
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce,
            0x87, 0x0b, 0x07, 0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81,
            0x5b, 0x16, 0xf8, 0x17, 0x98,
        ];
        const NATIVE_ELEMENTS: [Felt; 16] = [
            Felt::new_unchecked(0x16f81798),
            Felt::new_unchecked(0x59f2815b),
            Felt::new_unchecked(0x2dce28d9),
            Felt::new_unchecked(0x029bfcdb),
            Felt::new_unchecked(0xce870b07),
            Felt::new_unchecked(0x55a06295),
            Felt::new_unchecked(0xf9dcbbac),
            Felt::new_unchecked(0x79be667e),
            Felt::new_unchecked(0xfb10d4b8),
            Felt::new_unchecked(0x9c47d08f),
            Felt::new_unchecked(0xa6855419),
            Felt::new_unchecked(0xfd17b448),
            Felt::new_unchecked(0x0e1108a8),
            Felt::new_unchecked(0x5da4fbfc),
            Felt::new_unchecked(0x26a3c465),
            Felt::new_unchecked(0x483ada77),
        ];
        const COMMITMENT: Word = Word::new([
            Felt::new_unchecked(11823917948314246078),
            Felt::new_unchecked(15960174880805474786),
            Felt::new_unchecked(15208912687411787098),
            Felt::new_unchecked(1636772189670681504),
        ]);

        assert_eq!(public_key.to_bytes(), COMPRESSED_SEC1);
        assert_eq!(public_key.to_commitment(), Poseidon2::hash_elements(&NATIVE_ELEMENTS));
        assert_eq!(public_key.to_commitment(), COMMITMENT);
    }

    #[cfg(feature = "std")]
    #[test]
    fn test_signature_serde() {
        use crate::utils::SliceReader;
        let sig0 = SigningKey::new().sign(Word::from([5, 0, 0, 0u32]));
        let sig_bytes = sig0.to_bytes();
        let mut slice_reader = SliceReader::new(&sig_bytes);
        let sig0_deserialized = Signature::read_from(&mut slice_reader).unwrap();

        assert!(!slice_reader.has_more_bytes());
        assert_eq!(sig0, sig0_deserialized);
    }
}

mod key_exchange_key {
    use miden_serde_utils::{Deserializable, Serializable};

    use crate::{
        dsa::ecdsa_k256_keccak::{KeyExchangeKey, PublicKey},
        rand::test_utils::seeded_rng,
    };

    #[test]
    fn test_key_generation() {
        let mut rng = seeded_rng([0u8; 32]);

        let secret_key = KeyExchangeKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();

        // Test that we can convert to/from bytes
        let sk_bytes = secret_key.to_bytes();
        let recovered_sk = KeyExchangeKey::read_from_bytes(&sk_bytes).unwrap();
        assert_eq!(secret_key.to_bytes(), recovered_sk.to_bytes());

        let pk_bytes = public_key.to_bytes();
        let recovered_pk = PublicKey::read_from_bytes(&pk_bytes).unwrap();
        assert_eq!(public_key, recovered_pk);
    }

    #[test]
    fn test_secret_key_debug_redaction() {
        let mut rng = seeded_rng([5u8; 32]);
        let secret_key = KeyExchangeKey::with_rng(&mut rng);

        // Verify Debug impl produces expected redacted output
        let debug_output = format!("{secret_key:?}");
        assert_eq!(debug_output, "<elided secret for KeyExchangeKey>");

        // Verify Display impl also elides
        let display_output = format!("{secret_key}");
        assert_eq!(display_output, "<elided secret for KeyExchangeKey>");
    }
}

mod signature {
    use alloc::vec::Vec;

    use miden_serde_utils::{DeserializationError, Serializable};

    use crate::{
        dsa::ecdsa_k256_keccak::{PublicKey, SecretKey, Signature, SigningKey},
        rand::test_utils::seeded_rng,
    };

    #[test]
    fn test_signature_from_der_success() {
        // DER-encoded form of an ASN.1 SEQUENCE containing two INTEGER values.
        let der: [u8; 8] = [
            0x30, 0x06, // Sequence tag and length of sequence contents.
            0x02, 0x01, 0x01, // Integer 1.
            0x02, 0x01, 0x09, // Integer 2.
        ];
        let v = 2u8;

        let sig = Signature::from_der(&der, v).expect("from_der should parse valid DER");

        // Expect r = 1 and s = 9 in 32-byte big-endian form.
        let mut expected_r = [0u8; 32];
        expected_r[31] = 1;
        let mut expected_s = [0u8; 32];
        expected_s[31] = 9;

        assert_eq!(sig.r(), &expected_r);
        assert_eq!(sig.s(), &expected_s);
        assert_eq!(sig.v(), v);
    }

    #[test]
    fn test_signature_from_der_recovery_id_variation() {
        // DER encoding with two integers both equal to 1.
        let der: [u8; 8] = [0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];

        let sig_v0 = Signature::from_der(&der, 0).unwrap();
        let sig_v3 = Signature::from_der(&der, 3).unwrap();

        // r and s must be identical; v differs, so signatures should not be equal.
        assert_eq!(sig_v0.r(), sig_v3.r());
        assert_eq!(sig_v0.s(), sig_v3.s());
        assert_ne!(sig_v0.v(), sig_v3.v());
        assert_ne!(sig_v0, sig_v3);
    }

    #[test]
    fn test_signature_from_der_invalid() {
        // Empty input should fail at DER parsing stage (der error).
        match Signature::from_der(&[], 0) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => panic!("expected InvalidValue for empty DER, got {other:?}"),
        }

        // Malformed/truncated DER should also fail.
        let der_bad: [u8; 2] = [0x30, 0x01];
        match Signature::from_der(&der_bad, 0) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => panic!("expected InvalidValue for malformed DER, got {other:?}"),
        }
    }

    #[test]
    fn test_signature_from_der_high_s_normalizes_and_flips_v() {
        // Construct a DER signature with r = 3 and s = n - 2 (high-S), which requires a leading
        // 0x00 in DER to force a positive INTEGER.
        //
        // secp256k1 curve order (n):
        // n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
        // We set s = n - 2 = ... D036413F (> n/2), so normalize_s() should trigger and flip
        // recovery id.
        let der: [u8; 40] = [
            0x30, 0x26, // SEQUENCE, length 38
            0x02, 0x01, 0x03, // INTEGER r = 3
            0x02, 0x21, 0x00, // INTEGER s, length 33 with leading 0x00 to keep positive
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c,
            0xd0, 0x36, 0x41, 0x3f,
        ];
        let v_initial: u8 = 2;
        let sig =
            Signature::from_der(&der, v_initial).expect("from_der should parse valid high-S DER");

        // After normalization:
        // - v should have its parity bit flipped (XOR with 1).
        // - s should be normalized to low-s; since s = n - 2, the normalized s is 2.
        let mut expected_r = [0u8; 32];
        expected_r[31] = 3;
        let mut expected_s_low = [0u8; 32];
        expected_s_low[31] = 2;

        assert_eq!(sig.r(), &expected_r);
        assert_eq!(sig.s(), &expected_s_low);
        assert_eq!(sig.v(), v_initial ^ 1);
    }

    #[test]
    fn test_public_key_from_der_success() {
        // Build a valid SPKI DER for the compressed SEC1 point of our generated key.
        let mut rng = seeded_rng([9u8; 32]);
        let secret_key = SigningKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_bytes(); // compressed SEC1 (33 bytes).

        // AlgorithmIdentifier: id-ecPublicKey + secp256k1
        let algo: [u8; 18] = [
            0x30, 0x10, // SEQUENCE, length 16
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, // OID 1.3.132.0.10 (secp256k1)
        ];

        // subjectPublicKey BIT STRING: 0 unused bits + compressed SEC1.
        let mut spk = Vec::with_capacity(2 + 1 + public_key_bytes.len());
        spk.push(0x03); // BIT STRING
        spk.push((1 + public_key_bytes.len()) as u8); // length
        spk.push(0x00); // unused bits = 0
        spk.extend_from_slice(&public_key_bytes);

        // Outer SEQUENCE.
        let mut der = Vec::with_capacity(2 + algo.len() + spk.len());
        der.push(0x30); // SEQUENCE
        der.push((algo.len() + spk.len()) as u8); // total length
        der.extend_from_slice(&algo);
        der.extend_from_slice(&spk);

        let parsed = PublicKey::from_der(&der).expect("should parse valid SPKI DER");
        assert_eq!(parsed, public_key);
    }

    #[test]
    fn test_public_key_from_der_invalid() {
        // Empty DER.
        match PublicKey::from_der(&[]) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => panic!("expected InvalidValue for empty DER, got {other:?}"),
        }

        // Malformed: SEQUENCE with zero length (missing fields).
        let der_bad: [u8; 2] = [0x30, 0x00];
        match PublicKey::from_der(&der_bad) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => panic!("expected InvalidValue for malformed DER, got {other:?}"),
        }
    }

    #[test]
    fn test_public_key_from_der_rejects_non_canonical_long_form_length() {
        // Build a valid SPKI structure but encode the outer SEQUENCE length using non-canonical
        // long-form (0x81 <len>) even though the length < 128. DER should reject this.
        let mut rng = seeded_rng([10u8; 32]);
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_bytes(); // compressed SEC1 (33 bytes)

        // AlgorithmIdentifier: id-ecPublicKey + secp256k1
        let algo: [u8; 18] = [
            0x30, 0x10, // SEQUENCE, length 16
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, // OID 1.3.132.0.10 (secp256k1)
        ];

        // subjectPublicKey BIT STRING: 0 unused bits + compressed SEC1
        let mut spk = Vec::with_capacity(2 + 1 + public_key_bytes.len());
        spk.push(0x03); // BIT STRING
        spk.push((1 + public_key_bytes.len()) as u8); // length
        spk.push(0x00); // unused bits = 0
        spk.extend_from_slice(&public_key_bytes);

        // Outer SEQUENCE using non-canonical long-form length (0x81)
        let total_len = (algo.len() + spk.len()) as u8; // fits in one byte
        let mut der = Vec::with_capacity(3 + algo.len() + spk.len());
        der.push(0x30); // SEQUENCE
        der.push(0x81); // long-form length marker with one subsequent length byte
        der.push(total_len);
        der.extend_from_slice(&algo);
        der.extend_from_slice(&spk);

        match PublicKey::from_der(&der) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => {
                panic!("expected InvalidValue for non-canonical long-form length, got {other:?}")
            },
        }
    }

    #[test]
    fn test_public_key_from_der_rejects_trailing_bytes() {
        // Build a valid SPKI DER but append trailing bytes after the sequence; DER should reject.
        let mut rng = seeded_rng([11u8; 32]);
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_bytes(); // compressed SEC1 (33 bytes)

        // AlgorithmIdentifier: id-ecPublicKey + secp256k1.
        let algo: [u8; 18] = [
            0x30, 0x10, // SEQUENCE, length 16
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID 1.2.840.10045.2.1
            0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x0a, // OID 1.3.132.0.10 (secp256k1)
        ];

        // subjectPublicKey BIT STRING: 0 unused bits + compressed SEC1.
        let mut spk = Vec::with_capacity(2 + 1 + public_key_bytes.len());
        spk.push(0x03); // BIT STRING
        spk.push((1 + public_key_bytes.len()) as u8); // length
        spk.push(0x00); // unused bits = 0
        spk.extend_from_slice(&public_key_bytes);

        // Outer SEQUENCE with short-form length.
        let total_len = (algo.len() + spk.len()) as u8;
        let mut der = Vec::with_capacity(2 + algo.len() + spk.len() + 2);
        der.push(0x30); // SEQUENCE
        der.push(total_len);
        der.extend_from_slice(&algo);
        der.extend_from_slice(&spk);

        // Append trailing junk.
        der.push(0x00);
        der.push(0x00);

        match PublicKey::from_der(&der) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => panic!("expected InvalidValue for DER with trailing bytes, got {other:?}"),
        }
    }

    #[test]
    fn test_public_key_from_der_rejects_wrong_curve_oid() {
        // Same structure but with prime256v1 (P-256) curve OID instead of secp256k1.
        let mut rng = seeded_rng([12u8; 32]);
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_bytes(); // compressed SEC1 (33 bytes)

        // AlgorithmIdentifier: id-ecPublicKey + prime256v1 (1.2.840.10045.3.1.7).
        // Completed prime256v1 OID tail for correctness
        // Full DER OID bytes for 1.2.840.10045.3.1.7 are: 06 08 2A 86 48 CE 3D 03 01 07
        // We'll encode properly below with 8 length, then adjust the outer lengths accordingly.

        // AlgorithmIdentifier with correct OID encoding but wrong curve:
        let algo_full: [u8; 21] = [
            0x30, 0x12, // SEQUENCE, length 18
            0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // id-ecPublicKey
            0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // prime256v1
        ];

        // subjectPublicKey BIT STRING.
        let mut spk = Vec::with_capacity(2 + 1 + public_key_bytes.len());
        spk.push(0x03);
        spk.push((1 + public_key_bytes.len()) as u8);
        spk.push(0x00);
        spk.extend_from_slice(&public_key_bytes);

        let mut der = Vec::with_capacity(2 + algo_full.len() + spk.len());
        der.push(0x30);
        der.push((algo_full.len() + spk.len()) as u8);
        der.extend_from_slice(&algo_full);
        der.extend_from_slice(&spk);

        match PublicKey::from_der(&der) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => panic!("expected InvalidValue for wrong curve OID, got {other:?}"),
        }
    }

    #[test]
    fn test_public_key_from_der_rejects_wrong_algorithm_oid() {
        // Use rsaEncryption (1.2.840.113549.1.1.1) instead of id-ecPublicKey.
        let mut rng = seeded_rng([13u8; 32]);
        let secret_key = SecretKey::with_rng(&mut rng);
        let public_key = secret_key.public_key();
        let public_key_bytes = public_key.to_bytes();

        // AlgorithmIdentifier: rsaEncryption + NULL parameter.
        // OID bytes for 1.2.840.113549.1.1.1: 06 09 2A 86 48 86 F7 0D 01 01 01.
        // NULL parameter: 05 00.
        let algo_rsa: [u8; 15] = [
            0x30, 0x0d, // SEQUENCE, length 13
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, // rsaEncryption
            0x05, 0x00, // NULL
        ];

        // subjectPublicKey BIT STRING with EC compressed point (intentionally mismatched with
        // algo).
        let mut spk = Vec::with_capacity(2 + 1 + public_key_bytes.len());
        spk.push(0x03);
        spk.push((1 + public_key_bytes.len()) as u8);
        spk.push(0x00);
        spk.extend_from_slice(&public_key_bytes);

        let mut der = Vec::with_capacity(2 + algo_rsa.len() + spk.len());
        der.push(0x30);
        der.push((algo_rsa.len() + spk.len()) as u8);
        der.extend_from_slice(&algo_rsa);
        der.extend_from_slice(&spk);

        match PublicKey::from_der(&der) {
            Err(DeserializationError::InvalidValue(_)) => {},
            other => panic!("expected InvalidValue for wrong algorithm OID, got {other:?}"),
        }
    }
}

mod public_key_parsing {
    use alloc::format;

    use miden_serde_utils::Serializable;

    use crate::{dsa::ecdsa_k256_keccak::PublicKey, utils::hex_to_bytes};

    /// The secp256k1 generator point (even y coordinate) in both SEC1 encodings.
    const GEN_COMPRESSED: &str =
        "0x0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";
    const GEN_UNCOMPRESSED: &str = "0x0479be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b1\
        6f81798483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8";

    /// The point 6·G (odd y coordinate), so the odd-parity branch of the uncompressed encoding is
    /// exercised as well.
    const SIX_GEN_COMPRESSED: &str =
        "0x03fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a1460297556";
    const SIX_GEN_UNCOMPRESSED: &str = "0x04fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057\
        a1460297556ae12777aacfbb620f3be96017f45c560de80f0f6518fe4a03c870c36b075f297";

    #[test]
    fn accepts_compressed_key() {
        let key = PublicKey::from_hex(GEN_COMPRESSED).expect("compressed key should parse");

        let expected = hex_to_bytes::<33>(GEN_COMPRESSED).unwrap();
        assert_eq!(key.to_bytes(), expected);
    }

    #[test]
    fn accepts_uncompressed_key_with_even_y() {
        let from_uncompressed =
            PublicKey::from_hex(GEN_UNCOMPRESSED).expect("uncompressed key should parse");
        let from_compressed = PublicKey::from_hex(GEN_COMPRESSED).unwrap();

        assert_eq!(from_uncompressed, from_compressed);
    }

    #[test]
    fn accepts_uncompressed_key_with_odd_y() {
        let from_uncompressed =
            PublicKey::from_hex(SIX_GEN_UNCOMPRESSED).expect("uncompressed key should parse");
        let from_compressed = PublicKey::from_hex(SIX_GEN_COMPRESSED).unwrap();

        assert_eq!(from_uncompressed, from_compressed);
    }

    #[test]
    fn rejects_missing_hex_prefix() {
        let err = PublicKey::from_hex(&GEN_COMPRESSED[2..])
            .expect_err("a key without the 0x prefix should be rejected");

        assert!(format!("{err}").contains("0x"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_invalid_length() {
        let err = PublicKey::from_hex("0x1234")
            .expect_err("a key with an unsupported length should be rejected");

        assert!(format!("{err}").contains("length"), "unexpected error: {err}");
    }

    #[test]
    fn rejects_compressed_x_not_on_curve() {
        // x = 5 has no square root of x³ + 7 on secp256k1, so no point has this x coordinate.
        let not_on_curve = "0x020000000000000000000000000000000000000000000000000000000000000005";

        PublicKey::from_hex(not_on_curve)
            .expect_err("a compressed key with no matching curve point should be rejected");
    }

    #[test]
    fn rejects_uncompressed_point_not_on_curve() {
        // (1, 1) does not satisfy the curve equation.
        let not_on_curve = format!("0x04{:064x}{:064x}", 1, 1);

        PublicKey::from_hex(&not_on_curve)
            .expect_err("an uncompressed point off the curve should be rejected");
    }

    #[test]
    fn from_sec1_bytes_accepts_compressed_and_uncompressed_keys() {
        let compressed = hex_to_bytes::<33>(SIX_GEN_COMPRESSED).unwrap();
        let uncompressed = hex_to_bytes::<65>(SIX_GEN_UNCOMPRESSED).unwrap();

        let from_compressed =
            PublicKey::from_sec1_bytes(&compressed).expect("compressed key should parse");
        let from_uncompressed =
            PublicKey::from_sec1_bytes(&uncompressed).expect("uncompressed key should parse");

        assert_eq!(from_compressed, from_uncompressed);
        assert_eq!(from_compressed.to_bytes(), compressed);
    }

    #[test]
    fn from_sec1_bytes_rejects_unsupported_tags() {
        let with_tag = |hex: &str, tag: u8| {
            let mut bytes = hex_to_bytes::<65>(hex).unwrap();
            bytes[0] = tag;
            bytes
        };
        let mut compact = hex_to_bytes::<33>(GEN_COMPRESSED).unwrap();
        compact[0] = 0x05;

        // Encodings that k256 or other libraries accept, but this function does not.
        let cases: [(&str, &[u8]); 3] = [
            // 0x05 followed by the x coordinate only.
            ("compact", &compact),
            // X9.62 hybrid: both coordinates, and the parity of y in the tag (0x06 even, 0x07
            // odd).
            ("hybrid, even y", &with_tag(GEN_UNCOMPRESSED, 0x06)),
            ("hybrid, odd y", &with_tag(SIX_GEN_UNCOMPRESSED, 0x07)),
        ];

        for (case, bytes) in cases {
            let err = PublicKey::from_sec1_bytes(bytes)
                .expect_err(&format!("the {case} encoding should be rejected"));
            assert!(format!("{err}").contains("tag"), "{case}: unexpected error: {err}");
        }
    }

    #[test]
    fn from_sec1_bytes_rejects_invalid_lengths() {
        let uncompressed = hex_to_bytes::<65>(GEN_UNCOMPRESSED).unwrap();

        let empty: &[u8] = &[];
        // The x coordinate alone, without the tag byte.
        let x_coordinate_only = &uncompressed[1..33];
        // Both coordinates without the 0x04 tag byte.
        let untagged_uncompressed = &uncompressed[1..];
        // A valid uncompressed key followed by one extra byte.
        let uncompressed_with_trailing_byte = &[&uncompressed[..], &[0x00]].concat()[..];

        for bytes in
            [empty, x_coordinate_only, untagged_uncompressed, uncompressed_with_trailing_byte]
        {
            let err = PublicKey::from_sec1_bytes(bytes)
                .expect_err("a key with an unsupported length should be rejected");
            assert!(format!("{err}").contains("length"), "unexpected error: {err}");
        }
    }

    #[test]
    fn from_sec1_bytes_rejects_identity_and_out_of_range_coordinates() {
        // secp256k1 field modulus p.
        const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";
        const P_PLUS_ONE: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30";
        const MAX_U256: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
        // (1, ONE_Y) is a point on the curve, with an even y coordinate.
        const ONE: &str = "0000000000000000000000000000000000000000000000000000000000000001";
        const ONE_Y: &str = "4218f20ae6c646b363db68605822fb14264ca8d2587fdd6fbc750d587e76a7ee";

        let compressed = |x: &str| hex_to_bytes::<33>(&format!("0x02{x}")).unwrap();
        let uncompressed = |x: &str, y: &str| hex_to_bytes::<65>(&format!("0x04{x}{y}")).unwrap();

        // The canonical encodings of (1, ONE_Y) are accepted, so the rejections below are caused
        // only by the out-of-range coordinate.
        let canonical = PublicKey::from_sec1_bytes(&compressed(ONE)).unwrap();
        assert_eq!(PublicKey::from_sec1_bytes(&uncompressed(ONE, ONE_Y)).unwrap(), canonical);

        let cases: [(&str, &[u8]); 7] = [
            ("k256 identity", &[0x00; 33]),
            ("all zero bytes at uncompressed length", &[0x00; 65]),
            ("compressed x = p", &compressed(P)),
            ("compressed x = p + 1", &compressed(P_PLUS_ONE)),
            ("compressed x = 2^256 - 1", &compressed(MAX_U256)),
            ("uncompressed x = p + 1", &uncompressed(P_PLUS_ONE, ONE_Y)),
            ("uncompressed y = p", &uncompressed(ONE, P)),
        ];

        for (case, bytes) in cases {
            assert!(PublicKey::from_sec1_bytes(bytes).is_err(), "{case} should be rejected");
        }
    }
}
