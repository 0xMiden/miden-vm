use alloc::string::{String, ToString};

use data::{
    DETERMINISTIC_SIGNATURE, EXPECTED_SIG, EXPECTED_SIG_POLYS, HASH_TO_POINT_COEFFICIENTS,
    NUM_TEST_VECTORS, SK_POLYS, SYNC_DATA, SYNC_DATA_FOR_TEST_VECTOR,
};
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha20Rng;

use super::{
    FalconFelt, N, Nonce, Polynomial, PublicKey, Signature, hash_to_point::hash_to_point_eidos,
};
use crate::{
    Felt, SequentialCommit, Word,
    dsa::{
        falcon512_common::test_utils::Shake256Testing,
        falcon512_eidos::{
            PREVERSIONED_NONCE, PREVERSIONED_NONCE_LEN, SIG_NONCE_LEN, SIG_POLY_BYTE_LEN, SecretKey,
        },
    },
    hash::eidos::{Eidos, domains::FALCON_PUBLIC_KEY},
    utils::{Deserializable, Serializable},
};

mod data;

/// Generates the deterministic seed corpus used by `tools/miden-crypto-fuzz/signatures`.
///
/// Each coefficient seed is a little-endian signed-magnitude word. Bit 15 stores the sign, and bits
/// 0 through 10 store the magnitude. Bits 11 through 14 remain zero. This format lets generation
/// avoid calling `SignaturePoly::to_bytes` on a value that the old constructor accepted but the
/// encoder could not represent. These seeds reproduce the former panic and now verify rejection.
#[cfg(feature = "std")]
#[test]
#[ignore = "run manually to generate fuzz seeds"]
fn generate_fuzz_seeds() {
    use alloc::vec::Vec;
    use std::path::Path;

    fn write_seed(corpus_dir: &Path, name: &str, bytes: &[u8]) {
        std::fs::create_dir_all(corpus_dir).expect("failed to create corpus directory");
        std::fs::write(corpus_dir.join(name), bytes).expect("failed to write seed");
        std::println!("Generated signatures/{name} ({} bytes)", bytes.len());
    }

    fn sigpoly_bytes(coefficients: &[i16; N]) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(2 * N);
        for &coefficient in coefficients {
            let magnitude = coefficient.unsigned_abs();
            let raw = magnitude | if coefficient < 0 { 0x8000 } else { 0 };
            bytes.extend_from_slice(&raw.to_le_bytes());
        }
        bytes
    }

    fn magnitude_coefficients(count: usize, magnitude: i16) -> [i16; N] {
        let mut coefficients = [0i16; N];
        for coefficient in coefficients.iter_mut().take(count) {
            *coefficient = magnitude;
        }
        coefficients
    }

    let corpus_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tools/miden-crypto-fuzz/corpus/signatures");

    // The issue's reproducer: accepted by the old range-only validator, 1,536 encoded bytes.
    let all_2047 = [2047i16; N];
    write_seed(&corpus_dir, "sigpoly_constructor_all_2047.bin", &sigpoly_bytes(&all_2047));

    // Squared norm 8,388,608 is below SIG_L2_BOUND, but the encoding needs 640 bytes.
    let all_128 = [128i16; N];
    write_seed(&corpus_dir, "sigpoly_constructor_all_128.bin", &sigpoly_bytes(&all_128));

    // Exactly 5,000 bits: 392 * 10 + 120 * 9. Accepted and serialized to 625 bytes.
    let exact_budget = magnitude_coefficients(392, 128);
    write_seed(
        &corpus_dir,
        "sigpoly_constructor_exact_budget.bin",
        &sigpoly_bytes(&exact_budget),
    );

    // 5,001 bits: 393 * 10 + 119 * 9. Rejected by the fixed constructor.
    let over_budget = magnitude_coefficients(393, 128);
    write_seed(
        &corpus_dir,
        "sigpoly_constructor_one_bit_over.bin",
        &sigpoly_bytes(&over_budget),
    );

    // Accepted extremes: one 2,047 coefficient plus 511 zeros is 4,623 bits.
    let mut single_2047 = [0i16; N];
    single_2047[0] = 2047;
    write_seed(&corpus_dir, "sigpoly_constructor_single_2047.bin", &sigpoly_bytes(&single_2047));

    // Both signs at the exact budget.
    let mut mixed_signs = [0i16; N];
    for (index, coefficient) in mixed_signs.iter_mut().take(392).enumerate() {
        *coefficient = if index.is_multiple_of(2) { 128 } else { -128 };
    }
    write_seed(&corpus_dir, "sigpoly_constructor_mixed_signs.bin", &sigpoly_bytes(&mixed_signs));

    let zeros = [0i16; N];
    write_seed(&corpus_dir, "sigpoly_constructor_zero.bin", &sigpoly_bytes(&zeros));

    // message || public key || signature. The harness splits this at PK_LEN and reaches verify.
    let mut rng = ChaCha20Rng::from_seed([0_u8; 32]);
    let sk = SecretKey::with_rng(&mut rng);
    let message = Word::default();
    let signature = sk.sign(message);
    let public_key = sk.public_key();
    assert!(public_key.verify(message, &signature));

    let mut valid_signature_seed = Vec::new();
    valid_signature_seed.extend_from_slice(&message.to_bytes());
    valid_signature_seed.extend_from_slice(&(&public_key).to_bytes());
    valid_signature_seed.extend_from_slice(&signature.to_bytes());
    write_seed(&corpus_dir, "signature_valid.bin", &valid_signature_seed);
}

#[test]
fn eidos_hash_to_point_is_frozen() {
    let nonce = Nonce::from_bytes(core::array::from_fn(|i| i as u8));
    let message: Word = [0, 1, 0x0123_4567_89ab_cdef, 0xffff_ffff_0000_0000]
        .map(Felt::new_unchecked)
        .into();
    let polynomial = hash_to_point_eidos(message, &nonce);
    assert_eq!(polynomial.coefficients, HASH_TO_POINT_COEFFICIENTS.map(FalconFelt::new));
}

#[test]
fn public_key_commitment_uses_eidos() {
    let mut eidos_rng = ChaCha20Rng::from_seed([3_u8; 32]);
    let eidos_public_key = SecretKey::with_rng(&mut eidos_rng).public_key();
    let elements = eidos_public_key.to_elements();
    let commitment = eidos_public_key.to_commitment();

    assert_eq!(commitment, Eidos::hash_elements_in_domain(&elements, FALCON_PUBLIC_KEY));
}

#[test]
fn eidos_public_key_commitment_is_frozen() {
    let public_key = PublicKey::from(Polynomial::new(
        (0..N).map(|value| FalconFelt::new(value as i16)).collect(),
    ));

    assert_eq!(
        public_key.to_commitment().into_elements().map(|value| value.as_canonical_u64()),
        [
            404_049_173_810_884_556,
            9_081_898_896_579_124_497,
            7_242_774_609_851_667_830,
            7_466_572_463_465_226_028,
        ],
    );
}

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
    let mut rng_shake = Shake256Testing::new(seed);

    // the test vectors in the reference implementation include test vectors for signatures with
    // parameter N = 2^i for i = 1..10, where N is the exponent of the monic irreducible polynomial
    // phi. We are only interested in the test vectors for N = 2^9 = 512 and thus need to "sync"
    // the SHAKE256 PRNG before we can use it in testing the test vectors that are relevant for
    // N = 512.
    // The following makes the necessary calls to the PRNG in order to prepare it for use with
    // the test vectors for N = 512.
    rng_shake.sync_rng(&SYNC_DATA);

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
        // 1. remove the headers when comparing as Falcon512-Eidos uses a different header format,
        // 2. compare the nonce part separately as the deterministic version we use omits the
        //    inclusion of the preversioned portion of the nonce in its serialized format,
        // 3. we remove the public key from the Falcon512-Eidos signature as this is not part of the
        //    signature in the reference implementation,
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
    assert!(sk.public_key().verify(message.into(), &signature));

    let decoded = Signature::read_from_bytes(&serialized_signature).unwrap();
    assert!(sk.public_key().verify(message.into(), &decoded));
    assert!(!sk.public_key().verify(b"datb".into(), &decoded));

    let mut changed_nonce = serialized_signature;
    changed_nonce[1] += 1;
    let decoded = Signature::read_from_bytes(&changed_nonce).unwrap();
    assert!(!sk.public_key().verify(message.into(), &decoded));
}

#[test]
fn test_public_key_and_signature_display_hex() {
    let seed = [0_u8; 32];
    let mut rng = ChaCha20Rng::from_seed(seed);

    let sk = SecretKey::with_rng(&mut rng);
    let pk = sk.public_key();
    let signature = sk.sign(b"data".into());

    // `Display` must render the canonical serialized bytes as `0x`-prefixed lowercase hex.
    // `Serializable` is implemented for `&PublicKey`, so the borrow is required here.
    assert_eq!(pk.to_string(), canonical_hex(&(&pk).to_bytes()));
    assert_eq!(signature.to_string(), canonical_hex(&signature.to_bytes()));
    assert!(pk.to_string().starts_with("0x"));
    assert!(signature.to_string().starts_with("0x"));
}

/// Renders `bytes` as a `0x`-prefixed lowercase hex string, mirroring the expected `Display`
/// output.
fn canonical_hex(bytes: &[u8]) -> String {
    let mut s = String::from("0x");
    for byte in bytes {
        s.push_str(&format!("{byte:02x}"));
    }
    s
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
    use crate::dsa::falcon512_eidos::LOG_N;

    let mut result = [0_u8; 39];
    result[0] = LOG_N;
    // This protocol-defined byte string contributes to deterministic signature outputs.
    let domain_separator = b"FALCON-EIDOS-DET";

    result
        .iter_mut()
        .skip(1)
        .zip(domain_separator.iter())
        .for_each(|(dst, src)| *dst = *src);

    result
}
