use super::{
    Signature,
    math::{FalconFelt, Polynomial},
};
use crate::{
    Felt,
    utils::{ByteReader, ByteWriter, Deserializable, DeserializationError, Serializable},
};

mod public_key;
pub use public_key::PublicKey;

mod secret_key;
pub use secret_key::SecretKey;
pub(crate) use secret_key::{WIDTH_BIG_POLY_COEFFICIENT, WIDTH_SMALL_POLY_COEFFICIENT};

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    use rand::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    use super::{super::TestVariant, SecretKey};
    use crate::{
        ONE, Word,
        utils::{Deserializable, Serializable},
    };

    type TestSecretKey = SecretKey<TestVariant>;

    #[test]
    fn test_falcon_verification() {
        let seed = [0_u8; 32];
        let mut rng = ChaCha20Rng::from_seed(seed);

        // generate random keys
        let sk = TestSecretKey::with_rng(&mut rng);
        let pk = sk.public_key();

        // test secret key serialization/deserialization
        let mut buffer = vec![];
        sk.write_into(&mut buffer);
        let sk_deserialized = TestSecretKey::read_from_bytes(&buffer).unwrap();
        assert_eq!(sk.short_lattice_basis(), sk_deserialized.short_lattice_basis());

        // sign a random message
        let message = Word::new([ONE; 4]);
        let signature = sk.sign_with_rng(message, &mut rng);

        // make sure the signature verifies correctly
        assert!(pk.verify(message, &signature));

        // a signature should not verify against a wrong message
        let message2 = Word::new([ONE.double(); 4]);
        assert!(!pk.verify(message2, &signature));

        // a signature should not verify against a wrong public key
        let sk2 = TestSecretKey::with_rng(&mut rng);
        assert!(!sk2.public_key().verify(message, &signature))
    }
}
