//! Native configuration projection and boundary regressions.

use super::*;

fn parameters(pcs_params: PcsParams) -> ProofSecurityParameters {
    ProofSecurityParameters {
        pcs_params,
        instance_shape: InstanceShape {
            log_max_height: 20,
            field_bits: CHALLENGE_FIELD_BITS,
            collision_resistance: 128,
        },
        hash_fn: HashFunction::Blake3_256,
        air_shape: AirShape {
            num_composed_constraints: 531,
            max_constraint_degree: 9,
            num_quotient_chunks: 8,
            max_combo: 2,
            num_deep_terms: Some(130),
            lookup: Some(LookupShape {
                fractions_per_row: 27,
                max_message_width: 16,
            }),
        },
        num_ood_points: 2,
        num_lookup_boundary_terms: 0,
    }
}

#[test]
fn native_parameters_compare_the_complete_pcs_configuration() {
    let params = PcsParams::new(3, 2, 0, 4, 12, 27, 17).unwrap();
    let same = PcsParams::new(3, 2, 0, 4, 12, 27, 17).unwrap();
    let changed = PcsParams::new(3, 2, 0, 4, 12, 28, 17).unwrap();
    assert_eq!(parameters(params), parameters(same));
    assert_ne!(parameters(params), parameters(changed));
    let case = testing::SecurityCase::from(parameters(params));
    assert_eq!(case.log_final_degree, u32::from(params.log_final_degree()));
    assert_eq!(case.protocol_params.num_queries, 27);
}

#[test]
fn malformed_planning_geometry_fails_closed_in_both_estimators() {
    let valid = parameters(PcsParams::new(3, 2, 0, 4, 12, 27, 17).unwrap());
    for hash_fn in [HashFunction::Eidos, HashFunction::Blake3_256] {
        for (lookup, boundary_terms, log_height, field_bits) in [
            (None, 1, 20, CHALLENGE_FIELD_BITS),
            (
                Some(LookupShape {
                    fractions_per_row: 0,
                    max_message_width: 16,
                }),
                0,
                20,
                CHALLENGE_FIELD_BITS,
            ),
            (
                Some(LookupShape {
                    fractions_per_row: 0,
                    max_message_width: 16,
                }),
                1,
                20,
                CHALLENGE_FIELD_BITS,
            ),
            (valid.air_shape.lookup, 1, 64, CHALLENGE_FIELD_BITS),
            (valid.air_shape.lookup, 0, 64, CHALLENGE_FIELD_BITS),
            (valid.air_shape.lookup, 0, 20, 0),
            (valid.air_shape.lookup, 0, 20, u64::MAX),
        ] {
            let mut malformed = valid;
            malformed.hash_fn = hash_fn;
            malformed.air_shape.lookup = lookup;
            malformed.num_lookup_boundary_terms = boundary_terms;
            malformed.instance_shape.log_max_height = log_height;
            malformed.instance_shape.field_bits = field_bits;
            assert!(malformed.numerical_inputs().is_none(), "{malformed:?}");
            assert_eq!(malformed.conjectured_security_level(), 0, "{malformed:?}");
            assert_eq!(malformed.proven_security_level(), 0, "{malformed:?}");
        }
    }
}

#[test]
fn planning_without_a_lookup_round_requires_no_boundary_terms() {
    let mut proof = parameters(PcsParams::new(3, 2, 0, 4, 12, 27, 17).unwrap());
    proof.air_shape.lookup = None;
    let report = proof.conjectured_security_report();
    assert_eq!(report.terms()[0].bits, proof.instance_shape.cap());
    assert!(report.security_level() > 0);
    assert!(proof.proven_security_level() > 0);
}

#[test]
fn an_empty_declared_deep_round_fails_closed_but_an_absent_round_is_valid() {
    let mut proof = parameters(PcsParams::new(3, 2, 0, 4, 12, 27, 17).unwrap());
    proof.air_shape.num_deep_terms = Some(0);
    assert_eq!(proof.conjectured_security_level(), 0);
    assert_eq!(proof.proven_security_level(), 0);

    proof.air_shape.num_deep_terms = None;
    assert!(proof.conjectured_security_level() > 0);
    assert!(proof.proven_security_level() > 0);
}

#[cfg(target_pointer_width = "64")]
#[test]
fn unrepresentable_native_counts_fail_closed_in_both_estimators() {
    let too_large = u32::MAX as usize + 1;
    for (folding, deep, queries, query) in [
        (too_large, 12, 27, 17),
        (4, too_large, 27, 17),
        (4, 12, too_large, 17),
        (4, 12, 27, too_large),
    ] {
        let params = PcsParams::new(3, 2, 0, folding, deep, queries, query).unwrap();
        let proof = parameters(params);
        assert_eq!(proof.conjectured_security_level(), 0);
        assert_eq!(proof.proven_security_level(), 0);
    }
}
