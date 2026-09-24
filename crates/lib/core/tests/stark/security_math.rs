//! Native checks for the mathematics used by the common recursive security estimator.

use miden_air::{
    config,
    security::{self, ProofSecurityParameters},
};
use p3_security::{
    budget::{
        AirShape, LookupShape, ProtocolParams, SecurityReport,
        report::{
            COLLISION_LABEL, COMPOSITION_LABEL, DEEP_COMPOSITION_LABEL, FOLDING_LABEL,
            LOOKUP_LABEL, OUT_OF_DOMAIN_LABEL, QUERY_LABEL,
        },
    },
    fixed,
};

fn security_parameters(
    protocol_params: ProtocolParams,
    log_max_height: u32,
    air_shape: AirShape,
    num_lookup_boundary_terms: u32,
) -> ProofSecurityParameters {
    let mut parameters = security::proof_security_parameters(
        &config::pcs_params(),
        log_max_height,
        0,
        security::COMMITMENT_ALIGNMENT,
        security::COLLISION_RESISTANCE,
    );
    parameters.protocol_params = protocol_params;
    parameters.instance_shape.log_max_height = log_max_height;
    parameters.air_shape = air_shape;
    parameters.num_lookup_boundary_terms = num_lookup_boundary_terms;
    parameters
}

/// Checks the lookup slack bound at every coefficient and every remainder where either the exact
/// or bounded fractional-bit decision can change.
#[test]
fn lookup_slack_bound_is_conservative_at_every_transition() {
    use miden_precompiles_air::security as pvm;

    const COEFFICIENT_MAX: u64 = 65_536;

    let bound = |a: u64| {
        let q = u64::from(64 - (a - 1).leading_zeros());
        let p = 1u64 << q;
        let g = p - a;
        let t1 = security::LOG2_E * g / p;
        (q, g, t1 + t1 * g / (2 * p))
    };

    for a in 2..=COEFFICIENT_MAX {
        let (q, g, bounded_slack) = bound(a);
        let exact_slack = q * security::FIXED_POINT_ONE - fixed::ceil_log2(a);

        assert!(
            bounded_slack <= exact_slack,
            "slack bound exceeds the exact slack at {a}: {bounded_slack} > {exact_slack}"
        );
        assert_eq!(exact_slack == 0, g == 0, "zero slack must coincide with a power of two at {a}");

        let remainders = [
            0,
            65_535,
            bounded_slack.saturating_sub(2),
            bounded_slack.saturating_sub(1),
            bounded_slack,
            bounded_slack + 1,
            bounded_slack + 2,
            exact_slack.saturating_sub(2),
            exact_slack.saturating_sub(1),
            exact_slack,
            exact_slack + 1,
            exact_slack + 2,
        ];
        for r_f in remainders.into_iter().filter(|r_f| *r_f <= 65_535) {
            let exact_bit: i64 = if exact_slack >= r_f + 2 {
                1
            } else if exact_slack == 0 && r_f == 65_535 {
                -1
            } else {
                0
            };
            let bounded_bit: i64 = if bounded_slack >= r_f + 2 {
                1
            } else if g == 0 && r_f == 65_535 {
                -1
            } else {
                0
            };
            assert!(
                bounded_bit <= exact_bit && exact_bit - bounded_bit <= 1,
                "fractional-bit decision out of band at A = {a}, remainder {r_f}: bounded \
                 {bounded_bit} vs exact {exact_bit}"
            );
        }
    }

    let mvm_shape = security::AIR_SHAPE.lookup;
    let mvm_coefficient =
        (u64::from(mvm_shape.max_message_width) + 2) * u64::from(mvm_shape.fractions_per_row);
    let (mvm_q, _, mvm_bound) = bound(mvm_coefficient);
    assert_eq!(
        mvm_bound,
        mvm_q * security::FIXED_POINT_ONE - fixed::ceil_log2(mvm_coefficient),
        "the slack bound must be tight for the MVM lookup coefficient"
    );

    let pvm_shape = pvm::AIR_SHAPE.lookup;
    let pvm_coefficient =
        (u64::from(pvm_shape.max_message_width) + 2) * u64::from(pvm_shape.fractions_per_row);
    let (_, _, pvm_bound) = bound(pvm_coefficient);
    for log_height in 16..=29 {
        let correction = (u64::from(pvm::FIXED_BOUNDARY_LOOKUP_TERMS) * security::LOG2_E)
            .div_ceil(u64::from(pvm_shape.fractions_per_row))
            .div_ceil(1 << log_height);
        assert_eq!(correction, 1, "PVM correction moved at height {log_height}");
        assert!(pvm_bound >= correction + 2);
    }

    // The largest lookup coefficient and boundary correction can occur together when the
    // fractions-per-row count is one. Check every accepted height to show that the estimator's
    // `base >= 2` assertion follows from the preceding envelope bounds.
    let field_whole_bits = security::CHALLENGE_FIELD_BITS >> fixed::FRACTIONAL_BITS;
    let mut minimum_base = u64::MAX;
    for log_height in 6..=29 {
        let correction = (4_096 * security::LOG2_E).div_ceil(1 << log_height);
        let base = field_whole_bits - 16 - log_height - (correction >> fixed::FRACTIONAL_BITS);
        minimum_base = minimum_base.min(base);
        assert!(base >= 2, "lookup base falls below two at height {log_height}");
    }
    assert_eq!(minimum_base, 13);
}

/// Checks that the five terms omitted by the MASM estimator remain above the lookup term.
///
/// The minimum lookup coefficient and zero boundary correction make the lookup term as large as
/// the accepted bounds permit. The maximum constraint count, constraint degree, and DEEP term
/// count make the omitted terms as small as the bounds permit. Moving any of these values away
/// from this corner increases the margin. Every accepted height is checked because the
/// out-of-domain, lookup, and FRI folding terms all depend on height.
#[test]
fn omitted_rounds_are_dominated_at_envelope_extremes() {
    let base = security::protocol_params(&config::pcs_params());
    let air_shape = AirShape {
        num_composed_constraints: 8192,
        max_constraint_degree: 9,
        max_combo: security::AIR_SHAPE.max_combo,
        num_deep_terms: Some(8192),
        lookup: LookupShape {
            fractions_per_row: 1,
            max_message_width: 255,
        },
    };

    for log_max_height in 6..=29 {
        for (num_queries, query_pow_bits) in [(7, 0), (150, 31)] {
            let protocol_params = ProtocolParams {
                num_queries,
                query_pow_bits,
                deep_pow_bits: 0,
                folding_pow_bits: 0,
                ..base
            };
            let report = security_parameters(protocol_params, log_max_height, air_shape, 0)
                .conjectured_security_report();
            let lookup = report
                .terms()
                .iter()
                .find(|term| term.label == LOOKUP_LABEL)
                .expect("the lookup round must be present")
                .bits;

            for label in [
                COMPOSITION_LABEL,
                OUT_OF_DOMAIN_LABEL,
                DEEP_COMPOSITION_LABEL,
                FOLDING_LABEL,
                COLLISION_LABEL,
            ] {
                let term = report
                    .terms()
                    .iter()
                    .find(|term| term.label == label)
                    .expect("every native round must be present");
                assert!(
                    term.bits > lookup,
                    "{label} is not dominated by lookup at height {log_max_height}"
                );
            }

            let two_term = report
                .terms()
                .iter()
                .filter(|term| term.label == LOOKUP_LABEL || term.label == QUERY_LABEL)
                .map(|term| term.bits)
                .min()
                .expect("both computed rounds must be present")
                >> security::FIXED_POINT_FRACTIONAL_BITS;
            assert_eq!(
                u64::from(report.security_level()),
                two_term,
                "a dominated round binds at height {log_max_height}, queries {num_queries}, \
                 query grinding {query_pow_bits}"
            );
        }
    }
}

/// Checks that every supported DEEP and FRI folding grinding value can only raise its native
/// round, up to the common security cap.
#[test]
fn deep_and_fri_grinding_only_raise_their_rounds() {
    let term_bits = |report: &SecurityReport, label| {
        report.terms().iter().find(|term| term.label == label).unwrap().bits
    };
    let base = security::protocol_params(&config::pcs_params());
    let zero = security::security_report(
        &ProtocolParams {
            deep_pow_bits: 0,
            folding_pow_bits: 0,
            ..base
        },
        29,
        security::COLLISION_RESISTANCE,
        255,
    );
    let zero_deep = term_bits(&zero, DEEP_COMPOSITION_LABEL);
    let zero_folding = term_bits(&zero, FOLDING_LABEL);

    for pow_bits in 0..=31 {
        let deep = security::security_report(
            &ProtocolParams {
                deep_pow_bits: pow_bits,
                folding_pow_bits: 0,
                ..base
            },
            29,
            security::COLLISION_RESISTANCE,
            255,
        );
        assert_eq!(
            term_bits(&deep, DEEP_COMPOSITION_LABEL),
            (zero_deep + fixed::from_bits(pow_bits)).min(security::SECURITY_CAP),
            "DEEP grinding was not credited at {pow_bits} bits"
        );

        let folding = security::security_report(
            &ProtocolParams {
                deep_pow_bits: 0,
                folding_pow_bits: pow_bits,
                ..base
            },
            29,
            security::COLLISION_RESISTANCE,
            255,
        );
        assert_eq!(
            term_bits(&folding, FOLDING_LABEL),
            (zero_folding + fixed::from_bits(pow_bits)).min(security::SECURITY_CAP),
            "FRI folding grinding was not credited at {pow_bits} bits"
        );
    }
}
