use data::{
    DETERMINISTIC_SIGNATURE, EXPECTED_SIG, EXPECTED_SIG_POLYS, NUM_TEST_VECTORS, SK_POLYS,
    SYNC_DATA_FOR_TEST_VECTOR,
};
use prng::Shake256Testing;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::{Serializable, math::Polynomial};
use crate::dsa::falcon512_poseidon2::{
    PREVERSIONED_NONCE, PREVERSIONED_NONCE_LEN, SIG_NONCE_LEN, SIG_POLY_BYTE_LEN, SecretKey,
};

mod data;
mod prng;
pub(crate) use prng::ChaCha;

/// Tests the Falcon512 implementation using the test vectors in
/// <https://github.com/tprest/falcon.py/blob/88d01ede1d7fa74a8392116bc5149dee57af93f2/scripts/sign_KAT.py#L1131>
#[test]
fn test_signature_gen_reference_impl() {
    // message and initial seed used for generating the test vectors in the reference implementation
    let message = b"data1";
    let seed = b"external";

    // the reference implementation uses SHAKE256 for generating:
    // 1. The nonce for the hash-to-point algorithm.
    // 2. The seed used for initializing the ChaCha20 PRNG which is used in signature generation.
    let mut rng_shake = Shake256Testing::new(seed.to_vec());

    // the test vectors in the reference implementation include test vectors for signatures with
    // parameter N = 2^i for i = 1..10, where N is the exponent of the monic irreducible polynomial
    // phi. We are only interested in the test vectors for N = 2^9 = 512 and thus need to "sync"
    // the SHAKE256 PRNG before we can use it in testing the test vectors that are relevant for
    // N = 512.
    // The following makes the necessary calls to the PRNG in order to prepare it for use with
    // the test vectors for N = 512.
    rng_shake.sync_rng();

    for i in 0..NUM_TEST_VECTORS {
        // construct the four polynomials defining the secret key for this test vector
        let [f, g, big_f, big_g] = SK_POLYS[i];
        let f = Polynomial::new(f.to_vec());
        let g = Polynomial::new(g.to_vec());
        let big_f = Polynomial::new(big_f.to_vec());
        let big_g = Polynomial::new(big_g.to_vec());

        // we generate the secret key using the above four polynomials
        let sk = SecretKey::from_short_lattice_basis([g, f, big_g, big_f]);

        // we compare the signature as a polynomial

        // 1. first we synchronize the `SHAKE256` context with the one in the reference C
        // implementation as done in <https://github.com/tprest/falcon.py/blob/88d01ede1d7fa74a8392116bc5149dee57af93f2/test.py#L256>
        let skip_bytes = SYNC_DATA_FOR_TEST_VECTOR[i].0 * 8;
        let mut dummy = vec![0_u8; skip_bytes];
        rng_shake.fill_bytes(&mut dummy);

        // 2. generate the signature
        let signature = sk.sign_with_rng_testing(message, &mut rng_shake);

        // 3. compare against the expected signature
        let sig_coef = signature.sig_poly().to_balanced_values();
        assert_eq!(sig_coef, EXPECTED_SIG_POLYS[i]);

        // 4. compare the encoded signatures including the nonce
        let sig_bytes = &signature.to_bytes();
        let expected_sig_bytes = EXPECTED_SIG[i];
        let hex_expected_sig_bytes = hex::decode(expected_sig_bytes).unwrap();
        // to compare against the test vectors we:
        // 1. remove the headers when comparing as FALCON512_Poseidon2 uses a different header
        //    format,
        // 2. compare the nonce part separately as the deterministic version we use omits the
        //    inclusion of the preversioned portion of the nonce by in its serialized format,
        // 3. we remove the public key from the FALCON512_Poseidon2 signature as this is not part of
        //    the signature in the reference implementation,
        // 4. remove the nonce version byte, in addition to the header, from `sig_bytes`.
        let nonce = signature.nonce();
        assert_eq!(hex_expected_sig_bytes[1..1 + SIG_NONCE_LEN], nonce.as_bytes());
        assert_eq!(
            &hex_expected_sig_bytes[1 + SIG_NONCE_LEN..],
            &sig_bytes[2..2 + SIG_POLY_BYTE_LEN]
        );
    }
}

#[test]
fn test_secret_key_debug_redaction() {
    let seed = [1_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);
    let sk = SecretKey::with_rng(&mut rng);

    // Verify Debug impl produces expected redacted output
    let debug_output = format!("{sk:?}");
    assert_eq!(debug_output, "<elided secret for SecretKey>");

    // Verify Display impl also elides
    let display_output = format!("{sk}");
    assert_eq!(display_output, "<elided secret for SecretKey>");
}

#[test]
fn test_signature_determinism() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let sk = SecretKey::with_rng(&mut rng);
    let message = b"data";
    let signature = sk.sign(message.into());
    let serialized_signature = signature.to_bytes();

    assert_eq!(serialized_signature, DETERMINISTIC_SIGNATURE);
}

#[test]
fn check_preversioned_fixed_nonce() {
    assert_eq!(build_preversioned_fixed_nonce(), PREVERSIONED_NONCE)
}

/// Builds the preversioned portion of the fixed nonce following [1].
///
/// Note that [1] uses the term salt instead of nonce.
///
/// [1]: <https://github.com/algorand/falcon/blob/main/falcon-det.pdf>
fn build_preversioned_fixed_nonce() -> [u8; PREVERSIONED_NONCE_LEN] {
    use crate::dsa::falcon512_poseidon2::LOG_N;

    let mut result = [0_u8; 39];
    result[0] = LOG_N;
    let domain_separator = "FALCON-POSEIDON2-DET".as_bytes();

    result
        .iter_mut()
        .skip(1)
        .zip(domain_separator.iter())
        .for_each(|(dst, src)| *dst = *src);

    result
}
