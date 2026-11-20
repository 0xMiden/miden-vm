use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use super::*;
use crate::{
    aead::DataType,
    ies::{IesError, SealedMessage, SealingKey, UnsealingKey},
    utils::{Deserializable, bytes_to_elements_with_padding},
};

fn fixture() -> (SecretKey, PublicKey, SecretKey) {
    let mut rng = ChaCha20Rng::from_seed([93; 32]);
    let recipient = SecretKey::with_rng(&mut rng);
    let public_key = recipient.public_key();
    (recipient, public_key, SecretKey::with_rng(&mut rng))
}

#[test]
fn key_schedule_matches_framed_blocks() {
    let mut recipient_bytes = [0; 40];
    recipient_bytes[0] = 7;
    let recipient = SecretKey::from_bytes(&recipient_bytes).unwrap();
    let mut ephemeral_bytes = [0; 40];
    ephemeral_bytes[0] = 11;
    let ephemeral = SecretKey::from_bytes(&ephemeral_bytes).unwrap();
    let shared = ephemeral.diffie_hellman(&recipient.public_key());
    let public_key = ephemeral.public_key();
    let context =
        Eidos::hash_elements_in_domain(&[Felt::ONE, -Felt::ONE, Felt::ZERO], ECGFP5_SEAL_CONTEXT);

    // Spell out the compression blocks independently of the length-framed hashing API.
    let mut blocks = [[Felt::ZERO; 8]; 3];
    blocks[0][..5].copy_from_slice(&shared.to_elements());
    blocks[1][..5].copy_from_slice(&public_key.to_elements());
    blocks[2][..5].copy_from_slice(&recipient.public_key().to_elements());
    let prk = blocks
        .into_iter()
        .fold(Eidos::init_chaining_word(ECGFP5_SEAL_EXTRACT, 24), Eidos::compress);
    let mut expansion = [Felt::ZERO; 8];
    expansion[..4].copy_from_slice(prk.as_elements());
    expansion[4..].copy_from_slice(context.as_elements());
    let expected_key = Eidos::compress(Eidos::init_chaining_word(ECGFP5_SEAL_KEY, 8), expansion);
    let expected_nonce =
        Eidos::compress(Eidos::init_chaining_word(ECGFP5_SEAL_NONCE, 8), expansion);
    let (key, nonce) = derive_key_nonce(&shared, public_key, recipient.public_key(), context);
    assert_eq!(key.0, expected_key.into_elements());
    assert_eq!(nonce.0, expected_nonce.into_elements());
    assert_ne!(key.0, nonce.0);
    assert_eq!(
        [prk.into_elements(), key.0, nonce.0].map(|word| word.map(|x| x.as_canonical_u64())),
        [
            [25475688220594797, 6593773511568837525, 5672347651529970750, 1571398451320045741],
            [
                985188699437635699,
                4011114783528589108,
                9013745638415963787,
                6768601164963949975
            ],
            [
                2121419445738193183,
                3399474574639566747,
                8887082783243738043,
                6014069674738146342
            ],
        ],
    );
}

#[test]
fn round_trips_exact_lengths_and_full_field_values() {
    let (recipient, public_key, ephemeral) = fixture();
    for len in 0..=17 {
        let plaintext: Vec<_> = (0..len).map(|i| -Felt::from_u32(i + 1)).collect();
        let context: Vec<_> = (0..17 - len).map(|i| Felt::from_u32(i * 19)).collect();
        let sealed = seal_with_scalar(&public_key, &plaintext, &context, &ephemeral).unwrap();
        assert_eq!(sealed.to_elements().len(), 8 + 2 * plaintext.len());
        let decoded = Envelope::from_elements(&sealed.to_elements()).unwrap();
        assert_eq!(decoded, sealed);
        assert_eq!(open(&recipient, &context, &decoded).unwrap(), plaintext);
        assert_eq!(
            sealed,
            seal_with_scalar(&public_key, &plaintext, &context, &ephemeral).unwrap()
        );
    }
}

#[test]
fn rng_wrapper_matches_supplied_scalar() {
    let (_, public_key, _) = fixture();
    let mut rng = ChaCha20Rng::from_seed([22; 32]);
    let mut same_rng = rng.clone();
    let scalar = SecretKey::with_rng(&mut same_rng);
    assert_eq!(
        seal_with_rng(&public_key, &[Felt::ONE], &[Felt::ZERO], &mut rng).unwrap(),
        seal_with_scalar(&public_key, &[Felt::ONE], &[Felt::ZERO], &scalar).unwrap(),
    );
}

#[test]
fn rejects_modified_envelope_and_bindings() {
    let (recipient, public_key, ephemeral) = fixture();
    let context = [Felt::ONE, Felt::ZERO, -Felt::ONE];
    let sealed =
        seal_with_scalar(&public_key, &[Felt::ZERO, -Felt::ONE], &context, &ephemeral).unwrap();
    for index in 5..sealed.to_elements().len() {
        let mut elements = sealed.to_elements();
        elements[index] += Felt::ONE;
        if let Ok(modified) = Envelope::from_elements(&elements) {
            assert_eq!(open(&recipient, &context, &modified), Err(Error::AuthenticationFailed));
        }
    }
    let mut modified = sealed.clone();
    modified.ephemeral_key = recipient.public_key();
    assert_eq!(open(&recipient, &context, &modified), Err(Error::AuthenticationFailed));
    assert_eq!(open(&ephemeral, &context, &sealed), Err(Error::AuthenticationFailed));
    let mut other_context = context.to_vec();
    other_context.push(Felt::ZERO);
    assert_eq!(open(&recipient, &other_context, &sealed), Err(Error::AuthenticationFailed));
    for index in 0..context.len() {
        let mut other_context = context;
        other_context[index] += Felt::ONE;
        assert_eq!(open(&recipient, &other_context, &sealed), Err(Error::AuthenticationFailed));
    }
}

#[test]
fn rejects_malformed_encoding_and_oversized_inputs() {
    let (_, public_key, ephemeral) = fixture();
    let sealed = seal_with_scalar(&public_key, &[Felt::ONE], &[], &ephemeral).unwrap();
    let elements = sealed.to_elements();
    for len in 0..elements.len() {
        assert_eq!(Envelope::from_elements(&elements[..len]), Err(Error::InvalidEnvelope));
    }
    let mut extended = elements.clone();
    extended.push(Felt::ZERO);
    assert_eq!(Envelope::from_elements(&extended), Err(Error::InvalidEnvelope));
    let mut invalid_point = elements.clone();
    invalid_point[..5].fill(Felt::ZERO);
    assert_eq!(Envelope::from_elements(&invalid_point), Err(Error::InvalidEnvelope));
    let mut non_u32 = elements;
    non_u32[8] = Felt::new_unchecked(1_u64 << 32);
    assert_eq!(Envelope::from_elements(&non_u32), Err(Error::InvalidEnvelope));
    assert!(check_lengths(MAX_PLAINTEXT_FELTS, 0).is_ok());
    assert_eq!(check_lengths(MAX_PLAINTEXT_FELTS, 1), Err(Error::MessageTooLong));
    assert_eq!(check_lengths(MAX_PLAINTEXT_FELTS + 1, 0), Err(Error::MessageTooLong));
    if usize::BITS > 32 {
        assert_eq!(check_lengths(0, usize::MAX), Err(Error::ContextTooLong));
    }
}

#[test]
fn common_api_round_trips_bytes_and_felts() {
    let (recipient, public_key, _) = fixture();
    let sealing_key = SealingKey::Ecgfp5Eidos(public_key);
    let unsealing_key = UnsealingKey::Ecgfp5Eidos(recipient);
    let mut rng = ChaCha20Rng::from_seed([14; 32]);

    for len in [0, 1, 6, 7, 8, 13, 14, 15, 64] {
        let plaintext: Vec<_> = (0..len).map(|i| i as u8).collect();
        for context in [&b""[..], &b"context\0"[..]] {
            let sealed = sealing_key
                .seal_bytes_with_associated_data(&mut rng, &plaintext, context)
                .unwrap();
            let decoded = SealedMessage::read_from_bytes(&sealed.to_bytes()).unwrap();
            assert_eq!(sealed, decoded);
            assert_eq!(
                unsealing_key.unseal_bytes_with_associated_data(decoded, context).unwrap(),
                plaintext,
            );
        }
    }

    let context = [Felt::ONE, -Felt::ONE];
    let plaintext = [Felt::ZERO, Felt::ONE, -Felt::ONE];
    let mut same_rng = rng.clone();
    let expected = seal_with_rng(&public_key, &plaintext, &context, &mut same_rng).unwrap();
    let sealed = sealing_key
        .seal_elements_with_associated_data(&mut rng, &plaintext, &context)
        .unwrap();
    let envelope = Envelope::try_from(sealed.clone()).unwrap();
    assert_eq!(envelope, expected);
    assert_eq!(SealedMessage::from(envelope), sealed);
    let decoded = SealedMessage::read_from_bytes(&sealed.to_bytes()).unwrap();
    assert_eq!(
        unsealing_key.unseal_elements_with_associated_data(decoded, &context).unwrap(),
        plaintext,
    );
}

#[test]
fn common_api_authenticates_data_type_context_and_recipient() {
    let (recipient, public_key, other_recipient) = fixture();
    let sealing_key = SealingKey::Ecgfp5Eidos(public_key);
    let unsealing_key = UnsealingKey::Ecgfp5Eidos(recipient);
    let wrong_key = UnsealingKey::Ecgfp5Eidos(other_recipient);
    let mut rng = ChaCha20Rng::from_seed([15; 32]);

    for context in [&b""[..], &b"context"[..]] {
        let sealed = sealing_key
            .seal_bytes_with_associated_data(&mut rng, b"message", context)
            .unwrap();
        assert!(wrong_key.unseal_bytes_with_associated_data(sealed.clone(), context).is_err());
        let mut changed_context = context.to_vec();
        changed_context.push(0);
        assert!(
            unsealing_key
                .unseal_bytes_with_associated_data(sealed.clone(), &changed_context)
                .is_err()
        );
        assert!(Envelope::try_from(sealed.clone()).is_err());

        // Change the wire type too: rejection must not rely only on its cleartext flag.
        let mut changed = sealed;
        changed.ciphertext[0] = DataType::Elements as u8;
        let felt_context = bytes_to_elements_with_padding(context);
        assert!(
            unsealing_key
                .unseal_elements_with_associated_data(changed, &felt_context)
                .is_err()
        );

        let mut changed = sealing_key
            .seal_elements_with_associated_data(
                &mut rng,
                &bytes_to_elements_with_padding(b"message"),
                &felt_context,
            )
            .unwrap();
        changed.ciphertext[0] = DataType::Bytes as u8;
        assert!(unsealing_key.unseal_bytes_with_associated_data(changed, context).is_err());
    }
}

#[test]
fn common_api_rejects_malformed_payloads_and_keys() {
    let (recipient, public_key, ephemeral) = fixture();
    let mut rng = ChaCha20Rng::from_seed([16; 32]);
    let sealed = SealingKey::Ecgfp5Eidos(public_key).seal_bytes(&mut rng, b"message").unwrap();
    let unsealing_key = UnsealingKey::Ecgfp5Eidos(recipient);
    for len in 0..sealed.ciphertext.len() {
        let mut changed = sealed.clone();
        changed.ciphertext.truncate(len);
        assert!(unsealing_key.unseal_bytes(changed).is_err());
    }
    for index in 0..sealed.ciphertext.len() {
        let mut changed = sealed.clone();
        changed.ciphertext[index] ^= 1;
        assert!(unsealing_key.unseal_bytes(changed).is_err());
    }
    let mut noncanonical_tag = sealed.clone();
    noncanonical_tag.ciphertext[1..9].fill(0xff);
    assert!(unsealing_key.unseal_bytes(noncanonical_tag).is_err());
    let mut extra = sealed;
    extra.ciphertext.extend_from_slice(&[0; 8]);
    assert!(unsealing_key.unseal_bytes(extra).is_err());

    // A valid tag must not make a noncanonical byte encoding acceptable.
    let context = Eidos::hash_in_domain(b"", crate::hash::eidos::domains::ECGFP5_SEAL_BYTE_CONTEXT);
    for plaintext in [
        vec![Felt::ZERO],
        vec![Felt::ONE],
        vec![Felt::from_u32(0x0201)],
        vec![Felt::new_unchecked(1 << 63), Felt::from_u32(0x0161)],
    ] {
        let envelope = seal_inner(&public_key, &plaintext, &[], context, &ephemeral);
        let mut message = SealedMessage::from(envelope);
        message.ciphertext[0] = DataType::Bytes as u8;
        assert!(unsealing_key.unseal_bytes(message).is_err());
    }

    let mut invalid_key = vec![0; 41];
    invalid_key[0] = crate::ies::IesScheme::Ecgfp5Eidos as u8;
    assert!(SealingKey::read_from_bytes(&invalid_key).is_err());
    assert!(UnsealingKey::read_from_bytes(&invalid_key).is_err());

    let other = crate::dsa::eddsa_25519_sha512::KeyExchangeKey::with_rng(&mut rng);
    let message = SealingKey::X25519AeadEidos(other.public_key())
        .seal_bytes(&mut rng, b"")
        .unwrap();
    assert!(matches!(unsealing_key.unseal_bytes(message), Err(IesError::SchemeMismatch)));
}
