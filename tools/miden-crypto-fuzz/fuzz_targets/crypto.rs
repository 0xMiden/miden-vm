#![no_main]

use libfuzzer_sys::fuzz_target;
use miden_crypto::{
    utils::Deserializable,
    dsa::falcon512_poseidon2::PublicKey,
    ies::{SealingKey, SealedMessage},
};

fuzz_target!(|data: &[u8]| {
    // Test Falcon public key deserialization - complex bit-packing encoding
    // with field element validation
    let _ = PublicKey::read_from_bytes(data);

    // Test Vec<PublicKey>
    let _ = Vec::<PublicKey>::read_from_bytes(data);

    // Test Option<PublicKey>
    let _ = Option::<PublicKey>::read_from_bytes(data);

    // Test IES SealingKey deserialization - enum discriminator with nested key types
    let _ = SealingKey::read_from_bytes(data);

    // Test SealedMessage deserialization - scheme discriminator + ephemeral key + ciphertext
    let _ = SealedMessage::read_from_bytes(data);

    // Test arrays
    let _ = <[PublicKey; 1]>::read_from_bytes(data);
});
