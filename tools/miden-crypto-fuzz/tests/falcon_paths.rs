//! Deterministic checks for the paths exercised by the `signatures` fuzz target.

use miden_crypto::{
    Word,
    dsa::falcon512_eidos::{PK_LEN, SecretKey},
    utils::Serializable,
};
use miden_crypto_fuzz::check_falcon_paths;

fn coefficient_seed(coefficients: &[i16; 512]) -> Vec<u8> {
    let mut seed = Vec::with_capacity(2 * 512);
    for &coefficient in coefficients {
        let magnitude = coefficient.unsigned_abs();
        let raw = magnitude | if coefficient < 0 { 0x8000 } else { 0 };
        seed.extend_from_slice(&raw.to_le_bytes());
    }
    seed
}

#[test]
fn actual_harness_reaches_valid_falcon_verification() {
    let sk = SecretKey::new();
    let message = Word::default();
    let signature = sk.sign(message);
    let public_key = sk.public_key();

    let public_key_bytes = (&public_key).to_bytes();
    assert_eq!(public_key_bytes.len(), PK_LEN);

    let mut seed = Vec::new();
    seed.extend_from_slice(&message.to_bytes());
    seed.extend_from_slice(&public_key_bytes);
    seed.extend_from_slice(&signature.to_bytes());

    let evidence = check_falcon_paths(&seed);
    assert!(
        evidence.verified,
        "valid seed must reach verification through the shared fuzz helper"
    );
}

#[test]
fn actual_harness_constructor_boundary() {
    let mut exact_budget = [0i16; 512];
    for coefficient in exact_budget.iter_mut().take(392) {
        *coefficient = 128;
    }

    let mut one_bit_over = [0i16; 512];
    for coefficient in one_bit_over.iter_mut().take(393) {
        *coefficient = 128;
    }

    let mut single_2047 = [0i16; 512];
    single_2047[0] = 2047;

    let cases = [
        (exact_budget, true),
        (one_bit_over, false),
        ([2047i16; 512], false),
        ([128i16; 512], false),
        (single_2047, true),
    ];

    for (coefficients, expected_accepted) in cases {
        let evidence = check_falcon_paths(&coefficient_seed(&coefficients));
        assert_eq!(evidence.constructor_accepted, expected_accepted);
        assert_eq!(evidence.constructor_roundtrip, expected_accepted);
    }
}
