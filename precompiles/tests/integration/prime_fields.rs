use miden_precompiles::{Ed25519Base, Ed25519Scalar, K1Base, K1Scalar, R1Base, R1Scalar};

use crate::uint_fixtures::{assert_cross_modulus_children_rejected, assert_prime_field_contract};

#[derive(Clone, Copy)]
struct PrimeFieldCase {
    module: &'static str,
    assert_contract: fn(&'static str),
}

const SUPPORTED_FIELDS: [PrimeFieldCase; 6] = [
    PrimeFieldCase {
        module: "k1_base",
        assert_contract: assert_prime_field_contract::<K1Base>,
    },
    PrimeFieldCase {
        module: "k1_scalar",
        assert_contract: assert_prime_field_contract::<K1Scalar>,
    },
    PrimeFieldCase {
        module: "r1_base",
        assert_contract: assert_prime_field_contract::<R1Base>,
    },
    PrimeFieldCase {
        module: "r1_scalar",
        assert_contract: assert_prime_field_contract::<R1Scalar>,
    },
    PrimeFieldCase {
        module: "ed25519_base",
        assert_contract: assert_prime_field_contract::<Ed25519Base>,
    },
    PrimeFieldCase {
        module: "ed25519_scalar",
        assert_contract: assert_prime_field_contract::<Ed25519Scalar>,
    },
];

#[test]
fn supported_prime_fields_satisfy_uint_contract() {
    for field in SUPPORTED_FIELDS {
        (field.assert_contract)(field.module);
    }

    assert_cross_modulus_children_rejected("k1_base", "k1_scalar");
    assert_cross_modulus_children_rejected("r1_base", "r1_scalar");
    assert_cross_modulus_children_rejected("ed25519_base", "ed25519_scalar");
    assert_cross_modulus_children_rejected("k1_base", "r1_base");
}
