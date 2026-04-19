#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    dsa::{
        eddsa_25519_sha512::{PublicKey as EdDsaPublicKey, Signature as EdDsaSignature},
        ecdsa_k256_keccak::{PublicKey as EcdsaPublicKey, Signature as EcdsaSignature},
        falcon512_poseidon2::{PublicKey as FalconPublicKey, Signature as FalconSignature},
    },
    utils::Deserializable,
    Word,
};

fuzz_target!(|data: &[u8]| {
    // Split input data for different uses
    // First 32 bytes can be used as message, rest for signatures/keys
    let (message_bytes, sig_key_bytes) = data.split_at(min(32, data.len()));
    let mut word_bytes = [0u8; 32];
    word_bytes[..message_bytes.len()].copy_from_slice(message_bytes);

    // Try to create a Word from the bytes - may fail if invalid
    let message: Option<Word> = Word::try_from(word_bytes).ok();

    // =========================================================================
    // EdDSA (Ed25519) Signature Deserialization
    // =========================================================================

    // EdDSA Signature is 64 bytes
    let _ = EdDsaSignature::read_from_bytes(data);
    let _ = Vec::<EdDsaSignature>::read_from_bytes(data);
    let _ = Option::<EdDsaSignature>::read_from_bytes(data);

    // EdDSA PublicKey is 32 bytes
    let _ = EdDsaPublicKey::read_from_bytes(data);
    let _ = Vec::<EdDsaPublicKey>::read_from_bytes(data);
    let _ = Option::<EdDsaPublicKey>::read_from_bytes(data);

    // Verify path: deserialize both key and signature, then verify
    // This should NEVER panic - it should return false on invalid input
    if let (Ok(pk), Ok(sig)) = (
        EdDsaPublicKey::read_from_bytes(&sig_key_bytes.get(0..32).unwrap_or(&[])),
        EdDsaSignature::read_from_bytes(&sig_key_bytes.get(32..96).unwrap_or(&[])),
    ) {
        if let Some(msg) = message {
            let _ = pk.verify(msg, &sig);
        }
    }

    // =========================================================================
    // ECDSA (secp256k1) Signature Deserialization
    // =========================================================================

    // ECDSA Signature is 65 bytes (r: 32, s: 32, v: 1)
    let _ = EcdsaSignature::read_from_bytes(data);
    let _ = Vec::<EcdsaSignature>::read_from_bytes(data);
    let _ = Option::<EcdsaSignature>::read_from_bytes(data);

    // ECDSA PublicKey is 33 bytes (compressed)
    let _ = EcdsaPublicKey::read_from_bytes(data);
    let _ = Vec::<EcdsaPublicKey>::read_from_bytes(data);
    let _ = Option::<EcdsaPublicKey>::read_from_bytes(data);

    // Verify path
    if let (Ok(pk), Ok(sig)) = (
        EcdsaPublicKey::read_from_bytes(&sig_key_bytes.get(0..33).unwrap_or(&[])),
        EcdsaSignature::read_from_bytes(&sig_key_bytes.get(33..98).unwrap_or(&[])),
    ) {
        if let Some(msg) = message {
            let _ = pk.verify(msg, &sig);
        }
    }

    // Public key recovery from signature
    if let Ok(sig) = EcdsaSignature::read_from_bytes(data) {
        if let Some(msg) = message {
            let _ = EcdsaPublicKey::recover_from(msg, &sig);
        }
    }

    // =========================================================================
    // Falcon512 Signature Deserialization
    // =========================================================================

    // Falcon512 Signature has variable size but includes header, nonce, s2, h
    let _ = FalconSignature::read_from_bytes(data);
    let _ = Vec::<FalconSignature>::read_from_bytes(data);
    let _ = Option::<FalconSignature>::read_from_bytes(data);

    // Falcon512 PublicKey is 56 bytes (header + 14-bit packed coefficients)
    let _ = FalconPublicKey::read_from_bytes(data);
    let _ = Vec::<FalconPublicKey>::read_from_bytes(data);
    let _ = Option::<FalconPublicKey>::read_from_bytes(data);

    // Verify path - Falcon signatures are complex, just test deserialization paths
    // The actual verify is tested in crypto.rs target
    if let (Ok(_pk), Ok(sig)) = (
        FalconPublicKey::read_from_bytes(&sig_key_bytes.get(0..56).unwrap_or(&[])),
        FalconSignature::read_from_bytes(sig_key_bytes.get(56..).unwrap_or(&[])),
    ) {
        if let Some(msg) = message {
            // Note: verify internally uses signature.verify(message, pk)
            // which may access signature fields - ensure no panics
            let _ = sig.verify(msg, &_pk);
        }
    }

    // Falcon public key recovery from signature
    if let Ok(sig) = FalconSignature::read_from_bytes(data) {
        if let Some(msg) = message {
            let _ = FalconPublicKey::recover_from(msg, &sig);
        }
    }
});

fn min(a: usize, b: usize) -> usize {
    if a < b { a } else { b }
}
