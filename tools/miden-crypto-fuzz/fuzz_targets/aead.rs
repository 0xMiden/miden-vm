#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    Felt,
    aead::{
        aead_eidos::{
            EncryptedData as EidosEncryptedData, Nonce as EidosNonce,
            SecretKey as EidosSecretKey,
        },
        xchacha::{EncryptedData as XChaChaEncryptedData, SecretKey as XChaChaSecretKey},
    },
    utils::Deserializable,
};

const MAX_STRUCTURED_INPUT_LEN: usize = 4096;

fuzz_target!(|data: &[u8]| {
    // Malformed encodings must return an error without panicking.
    let _ = XChaChaEncryptedData::read_from_bytes(data);
    let _ = EidosEncryptedData::read_from_bytes(data);

    // A fixed key keeps decryption deterministic.
    let key_bytes = [0u8; 32];
    if let Ok(key) = XChaChaSecretKey::read_from_bytes(&key_bytes)
        && let Ok(encrypted_data) = XChaChaEncryptedData::read_from_bytes(data)
    {
        let _ = key.decrypt_bytes_with_associated_data(&encrypted_data, &[]);
        let _ = key.decrypt_elements_with_associated_data(&encrypted_data, &[]);
    }

    if let Ok(key) = EidosSecretKey::read_from_bytes(&key_bytes)
        && let Ok(encrypted_data) = EidosEncryptedData::read_from_bytes(data)
    {
        let _ = key.decrypt_bytes_with_associated_data(&encrypted_data, &[]);
        let _ = key.decrypt_elements_with_associated_data(&encrypted_data, &[]);
    }

    let _ = XChaChaSecretKey::read_from_bytes(data);
    let _ = EidosSecretKey::read_from_bytes(data);

    let _ = Vec::<XChaChaEncryptedData>::read_from_bytes(data);
    let _ = Vec::<EidosEncryptedData>::read_from_bytes(data);

    let _ = Option::<XChaChaEncryptedData>::read_from_bytes(data);
    let _ = Option::<EidosEncryptedData>::read_from_bytes(data);

    // Exercise successful encryption as well as malformed-input handling. Capping the input keeps
    // each fuzz iteration cheap enough to explore mutations effectively.
    let structured = &data[..data.len().min(MAX_STRUCTURED_INPUT_LEN)];
    if let Some((&split_seed, payload)) = structured.split_first() {
        let split = usize::from(split_seed) % (payload.len() + 1);
        let (plaintext, associated_data) = payload.split_at(split);
        let key = EidosSecretKey::from_elements([Felt::ZERO; 4]);
        let nonce = EidosNonce::from([Felt::ZERO; 4]);
        let encrypted = key
            .encrypt_bytes_with_nonce(plaintext, associated_data, nonce)
            .expect("bounded inputs must encrypt");

        assert_eq!(
            key.decrypt_bytes_with_associated_data(&encrypted, associated_data)
                .expect("fresh ciphertext must authenticate"),
            plaintext,
        );

        if let Some(first_limb) = encrypted.ciphertext().first() {
            let mut forged_ciphertext = encrypted.ciphertext().to_vec();
            forged_ciphertext[0] =
                Felt::from_u32((first_limb.as_canonical_u64() as u32) ^ 1);
            let forged = EidosEncryptedData::from_parts(
                encrypted.data_type(),
                forged_ciphertext,
                *encrypted.auth_tag(),
                *encrypted.nonce(),
            )
            .expect("mutated u32 limb remains a valid ciphertext encoding");

            assert!(
                key.decrypt_bytes_with_associated_data(&forged, associated_data)
                    .is_err(),
                "altered ciphertext must not authenticate",
            );
        }
    }
});
