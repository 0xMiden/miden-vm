use miden_precompiles::{K1Base, K1Scalar};

use super::uint_fixtures::{assert_cross_modulus_children_rejected, assert_prime_field_contract};

#[derive(Clone, Copy)]
struct PrimeFieldCase {
    module: &'static str,
    assert_contract: fn(&'static str),
}

const SUPPORTED_FIELDS: [PrimeFieldCase; 2] = [
    PrimeFieldCase {
        module: "k1_base",
        assert_contract: assert_prime_field_contract::<K1Base>,
    },
    PrimeFieldCase {
        module: "k1_scalar",
        assert_contract: assert_prime_field_contract::<K1Scalar>,
    },
];

#[test]
fn supported_prime_fields_satisfy_uint_contract() {
    for field in SUPPORTED_FIELDS {
        (field.assert_contract)(field.module);
    }

    assert_cross_modulus_children_rejected("k1_base", "k1_scalar");
}
