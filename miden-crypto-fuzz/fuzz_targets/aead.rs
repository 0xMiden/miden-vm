#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    aead::xchacha::{SecretKey as XChaChaSecretKey, EncryptedData as XChaChaEncryptedData},
    aead::aead_poseidon2::{SecretKey as Poseidon2SecretKey, EncryptedData as Poseidon2EncryptedData},
    utils::Deserializable,
};

fuzz_target!(|data: &[u8]| {
    // Test XChaCha EncryptedData deserialization directly
    // This should NEVER panic - it should return Err on malformed input
    let _ = XChaChaEncryptedData::read_from_bytes(data);

    // Test Poseidon2 EncryptedData deserialization
    let _ = Poseidon2EncryptedData::read_from_bytes(data);

    // Test XChaCha decryption with deserialized data
    // Using a fixed key for deterministic fuzzing
    let key_bytes = [0u8; 32];
    if let Ok(key) = XChaChaSecretKey::read_from_bytes(&key_bytes) {
        if let Ok(encrypted_data) = XChaChaEncryptedData::read_from_bytes(data) {
            // This should NEVER panic - authentication failure should return Err
            let _ = key.decrypt_bytes_with_associated_data(&encrypted_data, &[]);
            let _ = key.decrypt_elements_with_associated_data(&encrypted_data, &[]);
        }
    }

    // Test Poseidon2 decryption with deserialized data
    if let Ok(key) = Poseidon2SecretKey::read_from_bytes(&key_bytes) {
        if let Ok(encrypted_data) = Poseidon2EncryptedData::read_from_bytes(data) {
            let _ = key.decrypt_bytes_with_associated_data(&encrypted_data, &[]);
            let _ = key.decrypt_elements_with_associated_data(&encrypted_data, &[]);
        }
    }

    // Test SecretKey deserialization with arbitrary data
    let _ = XChaChaSecretKey::read_from_bytes(data);
    let _ = Poseidon2SecretKey::read_from_bytes(data);

    // Test Vec of encrypted data
    let _ = Vec::<XChaChaEncryptedData>::read_from_bytes(data);
    let _ = Vec::<Poseidon2EncryptedData>::read_from_bytes(data);

    // Test Option of encrypted data
    let _ = Option::<XChaChaEncryptedData>::read_from_bytes(data);
    let _ = Option::<Poseidon2EncryptedData>::read_from_bytes(data);
});
