use miden_core::{Felt, Word, serde::Deserializable};
use miden_core_lib::dsa::ecdsa_k256_keccak;
use miden_crypto::dsa::ecdsa_k256_keccak::{PublicKey, Signature, SigningKey};
use rand_chacha::{ChaCha20Rng, rand_core::SeedableRng};

pub(crate) struct EcdsaFixture {
    pub public_key: PublicKey,
    pub signature: Signature,
    pub public_key_commitment: Word,
    pub message: Word,
    pub advice: Vec<Felt>,
}

pub(crate) fn valid_fixture() -> EcdsaFixture {
    let mut rng = ChaCha20Rng::from_seed([0xe5; 32]);
    fixture_from_signing_key(SigningKey::with_rng(&mut rng))
}

pub(crate) fn generator_public_key_fixture() -> EcdsaFixture {
    let mut secret_key_bytes = [0u8; 32];
    secret_key_bytes[31] = 1;
    let signing_key =
        SigningKey::read_from_bytes(&secret_key_bytes).expect("scalar 1 is a valid key");
    fixture_from_signing_key(signing_key)
}

pub(crate) fn fixture_from_signing_key(signing_key: SigningKey) -> EcdsaFixture {
    let message = fixed_message();
    let public_key = signing_key.public_key();
    let signature = signing_key.sign(message);

    assert!(
        public_key.verify(message, &signature),
        "Rust fixture signature must verify before passing it to MASM",
    );

    let public_key_commitment = ecdsa_k256_keccak::public_key_commitment(&public_key);
    let advice = ecdsa_k256_keccak::encode_signature(&public_key, &signature);

    EcdsaFixture {
        public_key,
        signature,
        public_key_commitment,
        message,
        advice,
    }
}

fn fixed_message() -> Word {
    Word::new([
        Felt::new_unchecked(0x0001_0203_0405_0607),
        Felt::new_unchecked(0x0809_0a0b_0c0d_0e0f),
        Felt::new_unchecked(0x1011_1213_1415_1617),
        Felt::new_unchecked(0x1819_1a1b_1c1d_1e1f),
    ])
}
