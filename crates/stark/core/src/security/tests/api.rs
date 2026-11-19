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

fn deployed_parameters() -> ProofSecurityParameters {
    parameters(PcsParams::new(3, 2, 0, 4, 12, 27, 17).unwrap())
}

#[test]
fn native_pcs_parameters_project_to_the_numerical_case() {
    let proof = deployed_parameters();
    let case = testing::SecurityCase::from(proof);
    assert_eq!(case.log_final_degree, u32::from(proof.pcs_params.log_final_degree()));
    assert_eq!(case.protocol_params.num_queries, 27);
}

#[test]
fn malformed_planning_geometry_fails_closed_in_both_estimators() {
    let valid = deployed_parameters();
    let lookup = valid.air_shape.lookup;
    let empty_lookup = Some(LookupShape {
        fractions_per_row: 0,
        max_message_width: 16,
    });
    for hash_fn in [HashFunction::Eidos, HashFunction::Blake3_256] {
        for (lookup, boundary_terms, log_height, field_bits) in [
            (None, 1, 20, CHALLENGE_FIELD_BITS),
            (empty_lookup, 0, 20, CHALLENGE_FIELD_BITS),
            (empty_lookup, 1, 20, CHALLENGE_FIELD_BITS),
            (lookup, 1, 64, CHALLENGE_FIELD_BITS),
            (lookup, 0, 64, CHALLENGE_FIELD_BITS),
            (lookup, 0, 20, 0),
            (lookup, 0, 20, u64::MAX),
        ] {
            let mut malformed = valid;
            malformed.hash_fn = hash_fn;
            malformed.air_shape.lookup = lookup;
            malformed.num_lookup_boundary_terms = boundary_terms;
            malformed.instance_shape.log_max_height = log_height;
            malformed.instance_shape.field_bits = field_bits;
            assert_rejected(malformed);
        }
        let mut empty_deep = valid;
        empty_deep.hash_fn = hash_fn;
        empty_deep.air_shape.num_deep_terms = Some(0);
        assert_rejected(empty_deep);
    }
}

fn assert_rejected(proof: ProofSecurityParameters) {
    assert_eq!(proof.conjectured_security_level(), 0, "{proof:?}");
    assert_eq!(proof.proven_security_level(), 0, "{proof:?}");
}

#[test]
fn absent_rounds_are_valid() {
    let valid = deployed_parameters();
    for (label, air_shape) in [
        (labels::LOOKUP_LABEL, AirShape { lookup: None, ..valid.air_shape }),
        (
            labels::DEEP_COMPOSITION_LABEL,
            AirShape { num_deep_terms: None, ..valid.air_shape },
        ),
    ] {
        let proof = ProofSecurityParameters { air_shape, ..valid };
        let report = proof.conjectured_security_report();
        let term = report.terms().iter().find(|term| term.label == label).unwrap();
        assert_eq!(term.bits, proof.instance_shape.cap(), "{label}");
        assert!(report.security_level() > 0, "{label}");
        assert!(proof.proven_security_level() > 0, "{label}");
    }
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
        assert_rejected(parameters(params));
    }
}
