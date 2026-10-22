use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::{
    aead::DataType,
    ies::{SealedMessage, SealingKey, UnsealingKey},
    utils::{Deserializable, Serializable, bytes_to_elements_with_padding},
};

#[test]
fn common_ies_roundtrip_and_type_binding() {
    let mut rng = ChaCha20Rng::from_seed([24; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let sealing = SealingKey::NtruEidos(key.public_key().clone());
    let unsealing = UnsealingKey::NtruEidos(key);
    let restored = UnsealingKey::read_from_bytes(&unsealing.to_bytes()).unwrap();
    assert_eq!(SealingKey::read_from_bytes(&sealing.to_bytes()).unwrap(), sealing);
    for len in [0, 1, 7, 8, 32] {
        let plaintext = vec![0x85; len];
        for context in [&b""[..], &b"associated data"[..]] {
            let initial_rng = rng.clone();
            let sealed =
                sealing.seal_bytes_with_associated_data(&mut rng, &plaintext, context).unwrap();
            let decoded = SealedMessage::read_from_bytes(&sealed.to_bytes()).unwrap();
            assert_eq!(
                restored.unseal_bytes_with_associated_data(decoded, context).unwrap(),
                plaintext
            );
            assert!(
                restored
                    .unseal_bytes_with_associated_data(sealed.clone(), b"different")
                    .is_err()
            );
            let felts = bytes_to_elements_with_padding(&plaintext);
            let felt_context = bytes_to_elements_with_padding(context);
            let mut same_randomness = initial_rng;
            let felt_sealed = sealing
                .seal_elements_with_associated_data(&mut same_randomness, &felts, &felt_context)
                .unwrap();
            assert_eq!(sealed.encapsulation, felt_sealed.encapsulation);
            assert_ne!(sealed.ciphertext[1..], felt_sealed.ciphertext[1..]);
            assert_eq!(
                restored
                    .unseal_elements_with_associated_data(felt_sealed.clone(), &felt_context)
                    .unwrap(),
                felts
            );
            let envelope = Envelope::try_from(felt_sealed).unwrap();
            assert_eq!(
                restored
                    .unseal_elements_with_associated_data(envelope.into(), &felt_context)
                    .unwrap(),
                felts
            );
            let mut changed = sealed;
            changed.ciphertext[0] = DataType::Elements as u8;
            assert!(restored.unseal_elements_with_associated_data(changed, &felt_context).is_err());
        }
    }
}

#[test]
fn common_ies_rejects_malformed_and_tampered_payloads() {
    use crate::ies::keys::PublicEncapsulation;
    let mut rng = ChaCha20Rng::from_seed([25; 32]);
    let key = SecretKey::with_rng(&mut rng);
    let sealing = SealingKey::NtruEidos(key.public_key().clone());
    let sealed = sealing.seal_bytes(&mut rng, b"secret").unwrap();
    let unsealing = UnsealingKey::NtruEidos(key);
    for offset in [0, 1, 17] {
        let mut changed = sealed.clone();
        changed.ciphertext[offset] ^= 0x80;
        assert!(unsealing.unseal_bytes(changed).is_err());
    }
    let mut changed = sealed.clone();
    changed.ciphertext[1..9].copy_from_slice(&Felt::ORDER.to_le_bytes());
    assert!(unsealing.unseal_bytes(changed).is_err());
    let mut changed = sealed.clone();
    let mut bytes = changed.encapsulation.to_bytes();
    bytes[0] ^= 1;
    changed.encapsulation = PublicEncapsulation::NtruEidos(Ciphertext::from_bytes(&bytes).unwrap());
    assert!(unsealing.unseal_bytes(changed).is_err());
    let mut changed = sealed;
    changed.ciphertext.push(0);
    assert!(unsealing.unseal_bytes(changed).is_err());
}

#[test]
fn valid_tags_do_not_allow_noncanonical_byte_padding() {
    let mut rng = ChaCha20Rng::from_seed([26; 32]);
    let recipient = SecretKey::with_rng(&mut rng);
    let digest = framing::bytes(framing::BYTE_CONTEXT, &[]);
    // No delimiter, an empty final chunk, and a high byte discarded from a non-final chunk.
    for plaintext in [vec![Felt::ZERO], vec![Felt::ONE], vec![felt(1 << 56), felt(0x100)]] {
        let (encapsulation, secret) = recipient.public_key().encapsulate(&mut rng);
        let sealed = seal_inner(
            recipient.public_key(),
            encapsulation.clone(),
            &secret,
            &plaintext,
            &[],
            digest,
        );
        let payload =
            crate::ies::eidos_envelope::encode(&sealed.ciphertext, sealed.tag, DataType::Bytes);
        assert!(adapter::open_bytes(&recipient, encapsulation, &payload, &[]).is_err());
    }
}

#[test]
fn seal_open_and_envelope_boundaries() {
    let mut rng = ChaCha20Rng::from_seed([23; 32]);
    let recipient = SecretKey::with_rng(&mut rng);
    let other = SecretKey::with_rng(&mut rng);
    for len in [0, 1, 3, 4, 8, 32, 421, 422] {
        let plaintext = vec![-Felt::ONE; len];
        let context = [felt(7); 7];
        let envelope =
            seal_with_rng(recipient.public_key(), &mut rng, &plaintext, &context).unwrap();
        let encoded = envelope.to_elements();
        assert_eq!(Envelope::from_elements(&encoded).unwrap(), envelope);
        assert_eq!(open(&recipient, &context, &envelope).unwrap(), plaintext);
        assert_eq!(open(&other, &context, &envelope), Err(Error::AuthenticationFailed));
        assert_eq!(open(&recipient, &[], &envelope), Err(Error::AuthenticationFailed));
        for offset in [HEADER_FELTS, PAYLOAD_OFFSET + 2 * len] {
            let mut changed = encoded.clone();
            changed[offset] += Felt::ONE;
            let changed = Envelope::from_elements(&changed).unwrap();
            assert_eq!(open(&recipient, &context, &changed), Err(Error::AuthenticationFailed));
        }
        for offset in [0, 1, 2, 3, PAYLOAD_OFFSET - 1] {
            let mut changed = encoded.clone();
            changed[offset] += Felt::ONE;
            assert!(Envelope::from_elements(&changed).is_err(), "offset {offset}");
        }
        let mut changed = encoded.clone();
        changed[PAYLOAD_OFFSET - 2] += felt(1 << 24);
        assert_eq!(Envelope::from_elements(&changed), Err(Error::InvalidEncoding));
        if len != 0 {
            let mut changed = encoded.clone();
            changed[PAYLOAD_OFFSET] = felt(changed[PAYLOAD_OFFSET].as_canonical_u64() ^ 1);
            let changed = Envelope::from_elements(&changed).unwrap();
            assert_eq!(open(&recipient, &context, &changed), Err(Error::AuthenticationFailed));
        }
        let end = PAYLOAD_OFFSET + 2 * len + 2;
        if end < encoded.len() {
            let mut changed = encoded.clone();
            changed[end] = Felt::ONE;
            assert_eq!(Envelope::from_elements(&changed), Err(Error::InvalidEncoding));
        }
        assert!(Envelope::from_elements(&encoded[..encoded.len() - 1]).is_err());
        let mut extra = encoded;
        extra.extend([Felt::ZERO; 4]);
        assert!(Envelope::from_elements(&extra).is_err());
    }
}
