use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::Felt;

#[test]
fn encapsulation_and_implicit_rejection() {
    let mut rng = ChaCha20Rng::from_seed([17; 32]);
    for _ in 0..8 {
        let key = SecretKey::with_rng(&mut rng);
        let restored = SecretKey::from_bytes(key.to_bytes().as_ref()).unwrap();
        assert_eq!(key.public_key(), restored.public_key());
        assert_eq!(key.to_bytes(), restored.to_bytes());
        let (ciphertext, secret) = key.public_key().encapsulate(&mut rng);
        assert_eq!(secret.to_word(), key.decapsulate(&ciphertext).to_word());
        assert_eq!(secret.to_word(), restored.decapsulate(&ciphertext).to_word());
        let mut invalid = ciphertext.clone();
        invalid.0[CIPHERTEXT_BYTES - 1] |= 0x80;
        // Noncanonical ciphertext padding and an invalid recovered message take the same
        // fallback path. An all-zero ciphertext recovers m = 0, which fails the weight check.
        for invalid in [invalid, Ciphertext(Box::new([0; CIPHERTEXT_BYTES]))] {
            let rejected = key.decapsulate(&invalid).to_word();
            assert_ne!(secret.to_word(), rejected);
            assert_eq!(rejected, key.decapsulate(&invalid).to_word());
            assert_eq!(rejected, restored.decapsulate(&invalid).to_word());
            let mut expected = key.fallback.to_vec();
            expected.extend_from_slice(invalid.as_bytes());
            assert_eq!(rejected, framing::bytes(framing::FALLBACK, &expected));
        }
    }
}

#[test]
fn secret_key_decoding_rejects_bad_encodings_and_relations() {
    let mut rng = ChaCha20Rng::from_seed([19; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let bytes = key.to_bytes();
    assert!(SecretKey::from_bytes(&bytes[..SECRET_KEY_BYTES - 1]).is_err());
    let mut extended = bytes.to_vec();
    extended.push(0);
    assert!(SecretKey::from_bytes(&extended).is_err());
    assert!(SecretKey::from_bytes(&[0; SECRET_KEY_BYTES]).is_err());
    for (offset, value) in [
        (0, 255),  // A full S3 byte encodes at most 242.
        (101, 27), // The last S3 byte contains only three trits.
        (203, 27),
        (902, bytes[902] | 0x80),
        (102, (bytes[102] + 1) % 243), // Canonical, but not the inverse of f.
        (204, bytes[204] ^ 1),         // Canonical, but not f/(3g).
    ] {
        let mut changed = bytes.clone();
        changed[offset] = value;
        assert!(SecretKey::from_bytes(changed.as_ref()).is_err(), "offset {offset}");
    }
}

#[test]
fn public_key_encoding_and_commitment() {
    let mut rng = ChaCha20Rng::from_seed([18; 32]);
    let key = SecretKey::with_rng(&mut rng);
    assert_eq!(PublicKey::from_bytes(key.public_key().as_bytes()).unwrap(), *key.public_key());
    let mut noncanonical = *key.public_key().as_bytes();
    noncanonical[PUBLIC_KEY_BYTES - 1] |= 0x80;
    assert_eq!(PublicKey::from_bytes(&noncanonical), Err(Error));
    assert!(PublicKey::from_bytes(&noncanonical[..698]).is_err());
    assert_eq!(
        key.public_key().to_commitment(),
        Eidos::hash_elements_in_domain(&key.public_key().to_elements(), NTRU_HPS509_PUBLIC_KEY)
    );
    assert_ne!(
        key.public_key().to_commitment(),
        Eidos::hash_elements(&key.public_key().to_elements())
    );
    assert_ne!(
        key.public_key().to_commitment(),
        framing::fields(framing::CONTEXT, &key.public_key().polynomial().map(Felt::from)),
    );
}
