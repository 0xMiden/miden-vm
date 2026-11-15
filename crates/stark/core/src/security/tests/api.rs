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
