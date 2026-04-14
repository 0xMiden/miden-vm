use super::*;
use crate::{Felt, rand::test_utils::seeded_rng};

#[test]
fn test_key_generation() {
    let mut rng = seeded_rng([0u8; 32]);

    let secret_key = SecretKey::with_rng(&mut rng);
    let public_key = secret_key.public_key();

    // Test that we can convert to/from bytes
    let sk_bytes = secret_key.to_bytes();
    let recovered_sk = SecretKey::read_from_bytes(&sk_bytes).unwrap();
    assert_eq!(secret_key.to_bytes(), recovered_sk.to_bytes());

    let pk_bytes = public_key.to_bytes();
    let recovered_pk = PublicKey::read_from_bytes(&pk_bytes).unwrap();
    assert_eq!(public_key, recovered_pk);
}

#[test]
fn test_public_key_recovery() {
    let mut rng = seeded_rng([1u8; 32]);

    let secret_key = SecretKey::with_rng(&mut rng);
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
fn test_sign_and_verify() {
    let mut rng = seeded_rng([2u8; 32]);

    let secret_key = SecretKey::with_rng(&mut rng);
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

    let secret_key = SecretKey::with_rng(&mut rng);
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

    let secret_key = SecretKey::with_rng(&mut rng);
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
    let recovered_sig = Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();

    assert_eq!(signature, recovered_sig);

    let recovery_id = (recovery_id + 1) % 4;
    let recovered_sig = Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);

    let recovered_sig = Signature::from_sec1_bytes_and_recovery_id(sig_bytes, recovery_id).unwrap();
    assert_ne!(signature, recovered_sig);
}

#[test]
fn test_secret_key_debug_redaction() {
    let mut rng = seeded_rng([5u8; 32]);
    let secret_key = SecretKey::with_rng(&mut rng);

    // Verify Debug impl produces expected redacted output
    let debug_output = format!("{secret_key:?}");
    assert_eq!(debug_output, "<elided secret for SecretKey>");

    // Verify Display impl also elides
    let display_output = format!("{secret_key}");
    assert_eq!(display_output, "<elided secret for SecretKey>");
}

#[cfg(feature = "std")]
#[test]
fn test_signature_serde() {
    use crate::utils::SliceReader;
    let sig0 = SecretKey::new().sign(Word::from([5, 0, 0, 0u32]));
    let sig_bytes = sig0.to_bytes();
    let mut slice_reader = SliceReader::new(&sig_bytes);
    let sig0_deserialized = Signature::read_from(&mut slice_reader).unwrap();

    assert!(!slice_reader.has_more_bytes());
    assert_eq!(sig0, sig0_deserialized);
}

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
        other => panic!("expected InvalidValue for empty DER, got {:?}", other),
    }

    // Malformed/truncated DER should also fail.
    let der_bad: [u8; 2] = [0x30, 0x01];
    match Signature::from_der(&der_bad, 0) {
        Err(DeserializationError::InvalidValue(_)) => {},
        other => panic!("expected InvalidValue for malformed DER, got {:?}", other),
    }
}

#[test]
fn test_signature_from_der_high_s_normalizes_and_flips_v() {
    // Construct a DER signature with r = 3 and s = n - 2 (high-S), which requires a leading 0x00
    // in DER to force a positive INTEGER.
    //
    // secp256k1 curve order (n):
    // n = FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE BAAEDCE6 AF48A03B BFD25E8C D0364141
    // We set s = n - 2 = ... D036413F (> n/2), so normalize_s() should trigger and flip recovery
    // id.
    let der: [u8; 40] = [
        0x30, 0x26, // SEQUENCE, length 38
        0x02, 0x01, 0x03, // INTEGER r = 3
        0x02, 0x21, 0x00, // INTEGER s, length 33 with leading 0x00 to keep positive
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36,
        0x41, 0x3f,
    ];
    let v_initial: u8 = 2;
    let sig = Signature::from_der(&der, v_initial).expect("from_der should parse valid high-S DER");

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
    let secret_key = SecretKey::with_rng(&mut rng);
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
        other => panic!("expected InvalidValue for empty DER, got {:?}", other),
    }

    // Malformed: SEQUENCE with zero length (missing fields).
    let der_bad: [u8; 2] = [0x30, 0x00];
    match PublicKey::from_der(&der_bad) {
        Err(DeserializationError::InvalidValue(_)) => {},
        other => panic!("expected InvalidValue for malformed DER, got {:?}", other),
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
            panic!("expected InvalidValue for non-canonical long-form length, got {:?}", other)
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
        other => panic!("expected InvalidValue for DER with trailing bytes, got {:?}", other),
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
        other => panic!("expected InvalidValue for wrong curve OID, got {:?}", other),
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

    // subjectPublicKey BIT STRING with EC compressed point (intentionally mismatched with algo).
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
        other => panic!("expected InvalidValue for wrong algorithm OID, got {:?}", other),
    }
}
