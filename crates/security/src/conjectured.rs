//! Conjectured round budget for the lifted-STARK protocol.
//!
//! Fiat-Shamir security of the compiled argument is the minimum, over the protocol's rounds, of
//! that round's soundness error plus the grinding sited immediately before its challenge. This
//! module bounds each round and composes them.
//!
//! "Conjectured" here is the standard proximity-gaps conjecture regime: list sizes are taken as one
//! up to capacity, so the algebraic rounds pay a plain Schwartz-Zippel error with no list-size
//! multiplier, and the FRI query phase pays the random-words rate of
//! <https://eprint.iacr.org/2025/2010> section 1.5. Proven bounds for this parameter class are far
//! lower and are not modeled here; anything published from this module must be labeled conjectured.
//!
//! Every bound is stated as `error ≤ coefficient · size / |E|`, which in bits is
//! `log2|E| − log2(coefficient) − log2(size)`. Coefficients round up and the field size rounds
//! down, so each round is understated rather than overstated.

use crate::{
    fixed,
    report::{
        COLLISION_LABEL, COMPOSITION_LABEL, DEEP_LABEL, FOLDING_LABEL, LOOKUP_LABEL, OOD_LABEL,
        QUERY_LABEL, SecurityReport, SecurityTerm,
    },
    shape::{AirShape, InstanceShape, ProtocolParams},
};

/// Grades a proof configuration, returning the per-round breakdown.
///
/// The attained level is [`SecurityReport::security_level`]; the round that binds is
/// [`SecurityReport::binding_term`].
pub const fn security_report(
    params: &ProtocolParams,
    instance: &InstanceShape,
    air: &AirShape,
) -> SecurityReport {
    let cap = instance.cap();

    // The lookup challenges are sampled once, right after the main-trace commitment, and shared by
    // every bus. Each bus denominator is affine in the first challenge with total degree at most
    // `max_message_width` in the two challenges jointly. If the bus multiset is unbalanced, the
    // balance function is a nonzero rational function of the challenges, and the cheat succeeds
    // only if the sample zeroes the cleared numerator or degenerates some denominator — together
    // at most `2 · max_message_width · messages` roots by Schwartz-Zippel.
    let lookup = round(
        LOOKUP_LABEL,
        instance,
        2 * air.lookup.max_message_width as u64 * air.lookup.fractions_per_row as u64,
        instance.log_max_height,
        params.lookup_pow_bits,
        cap,
    );

    // Constraints are batched by powers of one challenge and the AIRs by a second, so a violated
    // constraint survives only on a root of the resulting univariate of degree below the total
    // number of batched slots. Independent of trace length.
    let composition =
        round(COMPOSITION_LABEL, instance, air.num_composed_constraints as u64, 0, 0, cap);

    // The out-of-domain point is rejection-sampled outside the trace and LDE domains but is not
    // ground. A violated constraint leaves the DEEP-ALI identity a nonzero polynomial in that point
    // of degree at most `(max_constraint_degree + 1) · height`. Lifting evaluates the shorter AIRs
    // at powers of the same point, so all of them pay the maximum height.
    let ood = round(
        OOD_LABEL,
        instance,
        air.max_constraint_degree as u64 + 1,
        instance.log_max_height,
        0,
        cap,
    );

    // The DEEP quotient batches every committed column and out-of-domain point by powers of two
    // further challenges, giving a univariate whose degree is the number of batched terms.
    let deep = round(DEEP_LABEL, instance, air.num_deep_terms as u64, 0, params.deep_pow_bits, cap);

    // Per folding round the error is at most `(arity − 1) · (n + 1) / |E|`, worst at the first
    // round where the domain is largest. Doubling the coefficient absorbs the `+ 1`.
    let folding = round(
        FOLDING_LABEL,
        instance,
        2 * ((1u64 << params.log_folding_arity) - 1),
        instance.log_max_height + params.log_blowup,
        params.folding_pow_bits,
        cap,
    );

    // Query sampling is the only round whose error is not a Schwartz-Zippel bound: it is the
    // random-words rate compounded over independent queries.
    let query_bits = params.num_queries as u64
        * fixed::bits_per_query(params.log_blowup, instance.field_bits)
        + fixed::from_bits(params.query_pow_bits);
    let query = SecurityTerm::new(QUERY_LABEL, min(query_bits, cap));

    SecurityReport::new([
        lookup,
        composition,
        ood,
        deep,
        folding,
        query,
        SecurityTerm::new(COLLISION_LABEL, cap),
    ])
}

/// Bounds one round whose error is `coefficient · 2^log_size / |E|`, crediting the grinding sited
/// before its challenge and capping at the transcript's own ceiling.
///
/// A zero coefficient means the protocol has no such round, which contributes no constraint on
/// security and is reported at the cap.
const fn round(
    label: &'static str,
    instance: &InstanceShape,
    coefficient: u64,
    log_size: u32,
    pow_bits: u32,
    cap: u64,
) -> SecurityTerm {
    if coefficient == 0 {
        return SecurityTerm::new(label, cap);
    }

    let error = fixed::ceil_log2(coefficient) + fixed::from_bits(log_size);
    let bits = if error >= instance.field_bits {
        fixed::from_bits(pow_bits)
    } else {
        instance.field_bits - error + fixed::from_bits(pow_bits)
    };

    SecurityTerm::new(label, min(bits, cap))
}

const fn min(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shape::LookupShape;

    const FIELD_BITS: u64 = 8_388_607;

    fn params() -> ProtocolParams {
        ProtocolParams {
            log_blowup: 3,
            log_folding_arity: 2,
            num_queries: 27,
            query_pow_bits: 17,
            deep_pow_bits: 12,
            folding_pow_bits: 4,
            lookup_pow_bits: 0,
        }
    }

    fn instance(log_max_height: u32) -> InstanceShape {
        InstanceShape {
            log_max_height,
            field_bits: FIELD_BITS,
            collision_resistance: 128,
        }
    }

    fn air() -> AirShape {
        AirShape {
            num_composed_constraints: 531,
            max_constraint_degree: 9,
            num_deep_terms: 130,
            lookup: LookupShape {
                fractions_per_row: 27,
                max_message_width: 16,
            },
        }
    }

    /// At moderate trace heights the query phase is what limits the configuration — the design
    /// intent behind the deployed query count and query grinding.
    #[test]
    fn query_phase_binds_at_moderate_heights() {
        let report = security_report(&params(), &instance(20), &air());
        assert_eq!(report.binding_term().label, QUERY_LABEL);
        assert_eq!(report.security_level(), 96);
    }

    /// The lookup round's error grows linearly in trace length while every other round is flat or
    /// grows only logarithmically, so past some height it becomes the bottleneck. Grading must
    /// surface that rather than continuing to report the query-phase figure.
    #[test]
    fn lookup_round_binds_at_large_heights() {
        let report = security_report(&params(), &instance(29), &air());
        assert_eq!(report.binding_term().label, LOOKUP_LABEL);
        assert!(
            report.security_level() < 96,
            "lookup round should fall below the query-phase level at maximum trace height, got {}",
            report.security_level()
        );
    }

    /// Grinding before the lookup challenges is the direct remedy for the round above, and must be
    /// credited to it bit for bit.
    #[test]
    fn lookup_grinding_lifts_the_lookup_round() {
        let ungrounded = security_report(&params(), &instance(29), &air());
        let grinding = ProtocolParams { lookup_pow_bits: 8, ..params() };
        let ground = security_report(&grinding, &instance(29), &air());

        let before = ungrounded.terms()[0];
        let after = ground.terms()[0];
        assert_eq!(before.label, LOOKUP_LABEL);
        assert_eq!(after.bits, before.bits + fixed::from_bits(8));
    }

    /// No round may be reported above the transcript's own ceiling: a hash collision forges the
    /// proof regardless of how sound the algebra is.
    #[test]
    fn every_round_is_capped_by_collision_resistance() {
        let instance = InstanceShape { collision_resistance: 96, ..instance(20) };
        let report = security_report(&params(), &instance, &air());
        for term in report.terms() {
            assert!(term.bits <= fixed::from_bits(96), "{} exceeds the cap", term.label);
        }
        assert_eq!(report.security_level(), 96);
    }

    /// Taller traces can never be more secure than shorter ones under the same parameters.
    #[test]
    fn security_is_monotone_in_trace_height() {
        let mut previous = u32::MAX;
        for log_height in 6..=30u32 {
            let level = security_report(&params(), &instance(log_height), &air()).security_level();
            assert!(level <= previous, "level rose at log height {log_height}");
            previous = level;
        }
    }

    /// A bigger or higher-degree AIR can never be more secure under the same parameters.
    #[test]
    fn security_is_monotone_in_air_size() {
        let small = security_report(&params(), &instance(24), &air());
        let large = AirShape {
            num_composed_constraints: 4096,
            max_constraint_degree: 9,
            num_deep_terms: 1024,
            lookup: LookupShape {
                fractions_per_row: 64,
                max_message_width: 16,
            },
        };
        let large = security_report(&params(), &instance(24), &large);
        assert!(large.security_level() <= small.security_level());
    }

    /// An AIR with no lookups pays no lookup round rather than being rejected or silently graded
    /// against a zero-message bus.
    #[test]
    fn absent_lookup_argument_contributes_no_round() {
        let air = AirShape {
            lookup: LookupShape {
                fractions_per_row: 0,
                max_message_width: 0,
            },
            ..air()
        };
        let report = security_report(&params(), &instance(29), &air);
        assert_eq!(report.terms()[0].bits, instance(29).cap());
        assert_ne!(report.binding_term().label, LOOKUP_LABEL);
    }
}
