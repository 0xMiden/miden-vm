// Derived from p3-security 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Adapted for Miden; source mapping and changes are recorded in provenance/README.md.

//! Conjectured round bounds in Q16, preserving conservative rounding.

use super::{AirShape, InstanceShape, SecurityReport, SecurityTerm, fixed, labels::*};

/// Protocol parameters that enter the round budget.
///
/// Every field must be bound into the protocol's Fiat-Shamir transcript, so a proof cannot be
/// graded under parameters it was not produced with.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ProtocolParams {
    /// Log2 of the LDE blowup factor; the FRI rate is `2^-log_blowup`.
    pub log_blowup: u32,
    /// Log2 of the FRI folding arity.
    pub log_folding_arity: u32,
    /// Number of FRI query repetitions.
    pub num_queries: u32,
    /// Grinding bits before query index sampling.
    pub query_pow_bits: u32,
    /// Grinding bits before the out-of-domain evaluation point is sampled.
    ///
    /// This round's error is the DEEP-ALI identity's degree over the field size, fixed by the AIR
    /// and the trace height. Every other round here has a second lever — the query count, the
    /// folding arity, the width of what is batched — so this is the only one whose bits nothing
    /// but grinding can buy back.
    pub ood_pow_bits: u32,
    /// Grinding bits before the DEEP-composition challenge is sampled. Read only when
    /// [`AirShape::num_deep_terms`] is `Some`.
    pub deep_pow_bits: u32,
    /// Grinding bits before each FRI folding challenge.
    pub folding_pow_bits: u32,
    /// Grinding bits before the lookup / permutation argument's challenges are sampled.
    ///
    /// The lookup round's error grows linearly in trace length, so its absence degrades with
    /// instance size.
    pub lookup_pow_bits: u32,
}

/// Grades a proof configuration, returning the per-round breakdown.
///
/// The attained level is [`SecurityReport::security_level`]; the round that binds is
/// [`SecurityReport::binding_term`].
#[cfg(any(test, feature = "testing"))]
pub(super) const fn security_report(
    params: &ProtocolParams,
    instance: &InstanceShape,
    air: &AirShape,
) -> SecurityReport {
    rounds(params, instance, air).report()
}

struct Rounds {
    lookup: SecurityTerm,
    composition: SecurityTerm,
    out_of_domain: SecurityTerm,
    deep_composition: SecurityTerm,
    folding: SecurityTerm,
    query: SecurityTerm,
    collision: SecurityTerm,
}

impl Rounds {
    const fn report(self) -> SecurityReport {
        SecurityReport::new([
            self.lookup,
            self.composition,
            self.out_of_domain,
            self.deep_composition,
            self.folding,
            self.query,
            self.collision,
        ])
    }
}

const fn rounds(params: &ProtocolParams, instance: &InstanceShape, air: &AirShape) -> Rounds {
    let cap = instance.cap();
    if cap == 0 {
        return Rounds {
            lookup: SecurityTerm::new(LOOKUP_LABEL, 0),
            composition: SecurityTerm::new(COMPOSITION_LABEL, 0),
            out_of_domain: SecurityTerm::new(OUT_OF_DOMAIN_LABEL, 0),
            deep_composition: SecurityTerm::new(DEEP_COMPOSITION_LABEL, 0),
            folding: SecurityTerm::new(FOLDING_LABEL, 0),
            query: SecurityTerm::new(QUERY_LABEL, 0),
            collision: SecurityTerm::new(COLLISION_LABEL, 0),
        };
    }

    // The lookup challenges are sampled once, right after the main-trace commitment, and shared
    // by every bus. Each bus denominator is affine in the first challenge with total degree at
    // most `max_message_width` in the two challenges jointly. If the bus multiset is unbalanced,
    // the balance function `Φ = Σ mₖ/Dₖ` is a nonzero rational function of the challenges, and the
    // cheat succeeds on either of two events.
    //
    // Each denominator `Dₖ = α + (bus + 1)·β^W + Σ_{j<W} β^j·payloadⱼ` has individual degree 1 in
    // `α` and `W` in `β`, so the cleared numerator `Σₖ mₖ·Π_{l≠k} D_l` over `M` denominators has
    // individual degrees `M − 1` and `W(M − 1)`. Sampling the two challenges independently and
    // uniformly, the per-variable Schwartz-Zippel union bounds a numerator root by
    // `(W + 1)(M − 1)/|E|`.
    //
    // Separately, a vanishing denominator degenerates the batched transition constraint: with
    // `Dⱼ = 0` the identity collapses to `mⱼ·Π_{s≠j} D_s = 0`, forcing `mⱼ = 0` and letting the
    // adversary drop message `j` from the bus for free. Each `Dₖ` is *monic* in `α`, so for any
    // `β` exactly one `α` annihilates it: that event costs only `M/|E|`, not `M·W/|E|`.
    //
    // Together `ε ≤ (W + 1)(M − 1)/|E| + M/|E| ≤ (W + 2)·M/|E|`.
    //
    // `M` is taken as `fractions_per_row · 2^log_max_height`, charging every AIR the maximum
    // height.
    let lookup = lookup_round(params, instance, air);

    // Constraints are batched by powers of one challenge and the AIRs by a second, so a violated
    // constraint survives only on a root of the resulting univariate of degree below the total
    // number of batched slots. Independent of trace length.
    let composition = round(
        COMPOSITION_LABEL,
        instance,
        Some(air.num_composed_constraints as u64),
        0,
        0,
        cap,
    );

    // The out-of-domain point is rejection-sampled outside the trace and LDE domains. A violated
    // constraint leaves the DEEP-ALI identity a nonzero polynomial in that point of degree at most
    // the larger of `max_constraint_degree · (height + max_combo − 1) + (height − 1)` (clearing the
    // shared denominator lifts each of a constraint's degree-many trace factors by one per
    // out-of-domain point referenced, and the quotient side contributes the rest) and
    // `(c + 1) · height + max_combo − 1` (the degree Plonky3's own power-of-two quotient chunking
    // induces, binding whenever `c` exceeds `max_constraint_degree`). Lifting evaluates the
    // shorter AIRs at powers of the same point, so all of them pay the maximum height.
    let out_of_domain = out_of_domain_round(
        instance,
        air.max_constraint_degree,
        air.num_quotient_chunks,
        air.max_combo,
        params.ood_pow_bits,
        cap,
    );

    // The DEEP quotient batches every committed column and out-of-domain point by powers of two
    // further challenges into the one word the low-degree test runs on. That is a random linear
    // combination of words over the LDE domain, the same kind of round as folding, so it pays the
    // proximity-gap error `(k − 1) · n / |E|` over the `k` batched terms: the conjecture removes
    // the list-size multiplier, not the domain size. `k` stands in for `k − 1`, which keeps the
    // coefficient nonzero and costs less than one bit.
    let deep_composition = round(
        DEEP_COMPOSITION_LABEL,
        instance,
        match air.num_deep_terms {
            Some(n) => Some(n as u64),
            None => None,
        },
        instance.log_max_height.saturating_add(params.log_blowup),
        params.deep_pow_bits,
        cap,
    );

    // Per folding round the error is at most `(arity − 1) · (n + 1) / |E|`, worst at the first
    // round where the domain is largest. Doubling the coefficient absorbs the `+ 1`.
    let folding = match folding_coefficient(params.log_folding_arity) {
        Some(coefficient) => round(
            FOLDING_LABEL,
            instance,
            Some(coefficient),
            instance.log_max_height.saturating_add(params.log_blowup),
            params.folding_pow_bits,
            cap,
        ),
        None => SecurityTerm::new(FOLDING_LABEL, 0),
    };

    // Query sampling is the only round whose error is not a Schwartz-Zippel bound: it is the
    // random-words rate compounded over independent queries.
    let query_bits = (params.num_queries as u64)
        .saturating_mul(fixed::bits_per_query(params.log_blowup, instance.field_bits))
        .saturating_add(fixed::from_bits(params.query_pow_bits));
    let query = SecurityTerm::new(QUERY_LABEL, min(query_bits, cap));

    Rounds {
        lookup,
        composition,
        out_of_domain,
        deep_composition,
        folding,
        query,
        collision: SecurityTerm::new(COLLISION_LABEL, cap),
    }
}

/// One lookup bound shared by the conjectured report and every proven candidate.
const fn lookup_round(
    params: &ProtocolParams,
    instance: &InstanceShape,
    air: &AirShape,
) -> SecurityTerm {
    if instance.cap() == 0 {
        return SecurityTerm::new(LOOKUP_LABEL, 0);
    }
    let cap = instance.cap();
    round(
        LOOKUP_LABEL,
        instance,
        match air.lookup {
            Some(lookup) => {
                Some((lookup.max_message_width as u64 + 2) * lookup.fractions_per_row as u64)
            },
            None => None,
        },
        instance.log_max_height,
        params.lookup_pow_bits,
        cap,
    )
}

fn sample_instance(inputs: &super::NumericalInputs) -> InstanceShape {
    match inputs.hash_fn {
        miden_core::proof::HashFunction::Eidos => InstanceShape {
            field_bits: super::EIDOS_CHALLENGE_SAMPLE_BITS,
            ..inputs.instance_shape
        },
        _ => inputs.instance_shape,
    }
}

fn correct_lookup(term: SecurityTerm, inputs: &super::NumericalInputs) -> SecurityTerm {
    let correction = super::lookup_boundary_correction(
        inputs.num_lookup_boundary_terms,
        inputs.air_shape.lookup.map_or(0, |lookup| lookup.fractions_per_row),
        inputs.instance_shape.log_max_height,
    );
    SecurityTerm::new(LOOKUP_LABEL, term.bits.saturating_sub(correction))
}

pub(super) fn lookup_bits(inputs: &super::NumericalInputs) -> u64 {
    correct_lookup(
        lookup_round(&inputs.protocol_params, &sample_instance(inputs), &inputs.air_shape),
        inputs,
    )
    .bits
}

pub(super) fn native_report(inputs: &super::NumericalInputs) -> SecurityReport {
    let mut rounds = rounds(&inputs.protocol_params, &sample_instance(inputs), &inputs.air_shape);
    if inputs.hash_fn == miden_core::proof::HashFunction::Eidos {
        let cap = inputs.instance_shape.cap();
        // Root-counting uses Eidos sampling support, while FRI queries use the field itself.
        let query_bits = u64::from(inputs.protocol_params.num_queries)
            .saturating_mul(fixed::bits_per_query(
                inputs.protocol_params.log_blowup,
                inputs.instance_shape.field_bits,
            ))
            .saturating_add(fixed::from_bits(inputs.protocol_params.query_pow_bits));
        rounds.query = SecurityTerm::new(QUERY_LABEL, query_bits.min(cap));
        rounds.collision = SecurityTerm::new(COLLISION_LABEL, cap);
        rounds.out_of_domain.bits = rounds.out_of_domain.bits.saturating_sub(1);
    }
    rounds.lookup = correct_lookup(rounds.lookup, inputs);
    rounds.report()
}

/// Coefficient `2 · (2^log_folding_arity − 1)` of the folding round, or `None` when the arity is
/// too large to compute it without wrapping.
///
/// `2^63` is the last shift that does not itself overflow `u64`, and `2 · (2^63 − 1) = 2^64 − 2`
/// still fits, so `log_folding_arity = 63` could be computed exactly; the cutoff at `63` is one
/// notch more conservative than the arithmetic strictly requires, refusing the input a step early
/// rather than relying on that margin. Larger exponents must never wrap to a smaller arity;
/// reporting zero bits refuses these unrepresentable configurations.
const fn folding_coefficient(log_folding_arity: u32) -> Option<u64> {
    if log_folding_arity >= u64::BITS - 1 {
        return None;
    }
    Some(2 * ((1u64 << log_folding_arity) - 1))
}

/// Bounds one round whose error is `coefficient · 2^log_size / |E|`, crediting the grinding sited
/// before its challenge and capping at the transcript's own ceiling.
///
/// Presence is explicit: only `None` waives a round. A present coefficient must validate as
/// nonzero before entering the arithmetic; malformed present rounds report zero security.
const fn round(
    label: &'static str,
    instance: &InstanceShape,
    coefficient: Option<u64>,
    log_size: u32,
    pow_bits: u32,
    cap: u64,
) -> SecurityTerm {
    let coefficient = match coefficient {
        None => return SecurityTerm::new(label, cap),
        Some(coefficient) => match core::num::NonZeroU64::new(coefficient) {
            Some(coefficient) => coefficient,
            None => return SecurityTerm::new(label, 0),
        },
    };

    let error = fixed::ceil_log2(coefficient.get()) + fixed::from_bits(log_size);
    let bits = if error >= instance.field_bits {
        fixed::from_bits(pow_bits)
    } else {
        instance.field_bits - error + fixed::from_bits(pow_bits)
    };

    SecurityTerm::new(label, min(bits, cap))
}

/// Bounds the out-of-domain round: error `max(d · (H + combo − 1) + (H − 1), (c + 1) · H + combo
/// − 1) / |E|`, with `H` the trace height, `d` the maximum constraint degree, `combo` the number
/// of out-of-domain points referenced per column, and `c` the exact number of committed
/// quotient chunks, including ZK degree padding and doubling.
///
/// Checking the DEEP-ALI identity at the sampled point clears the common denominator
/// `Π_i (x − z_i)`, which lifts each of a constraint's `d` trace factors from degree `≤ H − 1` to
/// degree `≤ H + combo − 1`, and the quotient side adds a further `H − 1`:
///
/// ```text
/// d · (H + combo − 1)     from the d lifted factors
///           + (H − 1)     from the quotient side
/// ```
///
/// That is ethSTARK's `X^i · h_i(X^d)` split. Plonky3 instead commits the quotient as `c`
/// power-of-two chunks reconstructed with degree-`(c − 1) · H` coset selectors, giving identity
/// degree `(c + 1) · H + combo − 1`; this exceeds the first term whenever `c > d`, which is why
/// the two are combined by a maximum rather than the first alone.
///
/// the floating-point DEEP-ALI bound states the same bound in `f64`. Unlike [`round`], both terms
/// are additive rather than a multiple of `H`, so the whole product is folded into the size
/// directly instead of decomposed into a coefficient and a log-size. This round is always charged
/// — there is no "no such round" case to special-case at zero.
///
/// `pow_bits` is the grinding sited immediately before the point is sampled, credited exactly as
/// [`round`] credits its own: a prover hunting for a favourable point pays `2^pow_bits` per
/// candidate. It is the only lever this round has, since both the degree and the height are fixed
/// by the statement being proved.
///
/// A degenerate degree or point count clamps to one, which keeps `size ≥ 1` and so keeps
/// [`fixed::ceil_log2`]'s zero-assert unreachable. A size too large to take the logarithm of is
/// reported at zero bits rather than wrapped, since truncating it would understate the error; the
/// grind is dropped with it rather than credited against an error this round could not bound.
const fn out_of_domain_round(
    instance: &InstanceShape,
    max_constraint_degree: u32,
    num_quotient_chunks: u32,
    max_combo: u32,
    pow_bits: u32,
    cap: u64,
) -> SecurityTerm {
    if instance.log_max_height >= u64::BITS || !num_quotient_chunks.is_power_of_two() {
        return SecurityTerm::new(OUT_OF_DOMAIN_LABEL, 0);
    }

    let d = if max_constraint_degree == 0 {
        1
    } else {
        max_constraint_degree as u128
    };
    let combo = if max_combo == 0 { 1 } else { max_combo as u128 };
    let height = 1u128 << instance.log_max_height;
    let ethstark = d * (height + combo - 1) + (height - 1);

    let chunks = num_quotient_chunks as u128;
    let chunked = (chunks + 1) * height + combo - 1;

    let size = if ethstark > chunked { ethstark } else { chunked };
    if size > u64::MAX as u128 {
        return SecurityTerm::new(OUT_OF_DOMAIN_LABEL, 0);
    }

    let error = fixed::ceil_log2(size as u64);
    let bits = instance.field_bits.saturating_sub(error) + fixed::from_bits(pow_bits);

    SecurityTerm::new(OUT_OF_DOMAIN_LABEL, min(bits, cap))
}

const fn min(a: u64, b: u64) -> u64 {
    if a < b { a } else { b }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::security::{LookupShape, report};

    const FIELD_BITS: u64 = 8_388_607;

    fn params() -> ProtocolParams {
        ProtocolParams {
            log_blowup: 3,
            log_folding_arity: 2,
            num_queries: 27,
            query_pow_bits: 17,
            ood_pow_bits: 0,
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
            num_quotient_chunks: 8,
            max_combo: 2,
            num_deep_terms: Some(130),
            lookup: Some(LookupShape {
                fractions_per_row: 27,
                max_message_width: 16,
            }),
        }
    }

    #[test]
    fn malformed_field_bits_report_zero_security_without_panicking() {
        for field_bits in [0, 18_446_744_073_709_391_531, u64::MAX, fixed::from_bits(u32::MAX) + 1]
        {
            let instance = InstanceShape { field_bits, ..instance(20) };
            let params = ProtocolParams {
                log_blowup: 1,
                // Grinding must not rescue an invalid field-size encoding.
                query_pow_bits: u32::MAX,
                ..params()
            };
            assert_eq!(security_report(&params, &instance, &air()).security_level(), 0);
        }
        let supported = InstanceShape {
            field_bits: fixed::from_bits(u32::MAX),
            ..instance(20)
        };
        assert!(security_report(&params(), &supported, &air()).security_level() > 0);
    }

    #[test]
    fn present_zero_coefficient_rounds_cannot_claim_the_cap() {
        for kind in [LOOKUP_LABEL, COMPOSITION_LABEL, DEEP_COMPOSITION_LABEL, FOLDING_LABEL] {
            let mut air = air();
            let mut params = params();
            match kind {
                LOOKUP_LABEL => air.lookup.as_mut().unwrap().fractions_per_row = 0,
                COMPOSITION_LABEL => air.num_composed_constraints = 0,
                DEEP_COMPOSITION_LABEL => air.num_deep_terms = Some(0),
                FOLDING_LABEL => params.log_folding_arity = 0,
                _ => unreachable!(),
            }
            let report = security_report(&params, &instance(20), &air);
            let term = report.terms().iter().find(|term| term.label == kind).unwrap();
            assert_eq!(term.bits, 0, "malformed present round {kind}");
        }
    }

    #[test]
    fn binding_round_changes_with_trace_height() {
        let moderate = security_report(&params(), &instance(20), &air());
        let large = security_report(&params(), &instance(29), &air());
        assert_eq!(moderate.binding_term().label, QUERY_LABEL);
        assert_eq!(moderate.security_level(), 96);
        assert_eq!(large.binding_term().label, LOOKUP_LABEL);
        assert!(large.security_level() < moderate.security_level());
    }

    /// A folding arity too large to compute the round's coefficient must be reported at zero
    /// bits, not silently dropped. The wrapped shift would leave the coefficient at zero, which
    /// [`round`] reads as "no such round" and reports at the cap — and unlike debug, a release
    /// build does not panic on the way there, so the round would simply disappear.
    #[test]
    fn absurd_folding_arity_reports_no_security_rather_than_the_cap() {
        assert_eq!(folding_coefficient(2), Some(6));
        assert_eq!(folding_coefficient(62), Some(u64::MAX - (1 << 63) - 1));
        assert_eq!(folding_coefficient(63), None);
        assert_eq!(folding_coefficient(u32::MAX), None);

        let absurd = ProtocolParams { log_folding_arity: 64, ..params() };
        let report = security_report(&absurd, &instance(20), &air());
        let folding = report
            .terms()
            .iter()
            .find(|t| t.label == FOLDING_LABEL)
            .expect("folding term is always present");

        assert_eq!(folding.bits, 0, "folding round vanished into the cap");
        assert_eq!(report.security_level(), 0);
    }

    #[test]
    fn lookup_and_ood_grinding_only_lift_their_own_rounds() {
        let base = security_report(&params(), &instance(29), &air());
        for (label, ground) in [
            (LOOKUP_LABEL, ProtocolParams { lookup_pow_bits: 8, ..params() }),
            (OUT_OF_DOMAIN_LABEL, ProtocolParams { ood_pow_bits: 8, ..params() }),
        ] {
            let report = security_report(&ground, &instance(29), &air());
            for (before, after) in base.terms().iter().zip(report.terms()) {
                assert_eq!(before.label, after.label, "term order changed");
                let expected =
                    before.bits + if before.label == label { fixed::from_bits(8) } else { 0 };
                assert_eq!(after.bits, expected, "{} with {label} grinding", before.label);
            }
        }
    }

    /// The DEEP quotient is a random linear combination of codewords over the LDE domain, so its
    /// round pays one bit for every doubling of that domain, whether the trace height or the
    /// blowup doubles it.
    #[test]
    fn deep_composition_round_pays_the_lde_domain_size() {
        let deep_bits = |params: &ProtocolParams, log_max_height: u32| {
            security_report(params, &instance(log_max_height), &air())
                .terms()
                .iter()
                .find(|t| t.label == DEEP_COMPOSITION_LABEL)
                .expect("term present")
                .bits
        };
        let base = deep_bits(&params(), 20);
        assert!(base < instance(20).cap(), "the round must not sit at the cap");

        assert_eq!(deep_bits(&params(), 21), base - fixed::ONE);
        let wider = ProtocolParams {
            log_blowup: params().log_blowup + 1,
            ..params()
        };
        assert_eq!(deep_bits(&wider, 20), base - fixed::ONE);
    }

    /// No round may be reported above the transcript's own ceiling.
    #[test]
    fn every_round_is_capped_by_collision_resistance() {
        let instance = InstanceShape { collision_resistance: 96, ..instance(20) };
        let report = security_report(&params(), &instance, &air());
        for term in report.terms() {
            assert!(term.bits <= fixed::from_bits(96), "{} exceeds the cap", term.label);
        }
        let collision = report.terms().iter().find(|term| term.label == COLLISION_LABEL).unwrap();
        assert_eq!(collision.bits, fixed::from_bits(96));
        assert_eq!(report.security_level(), 96);
    }

    #[test]
    fn every_round_is_monotone_in_trace_height() {
        let mut previous = [u64::MAX; report::NUM_TERMS];
        for log_height in 0..=64u32 {
            let report = security_report(&params(), &instance(log_height), &air());
            for (term, prev) in report.terms().iter().zip(previous.iter_mut()) {
                assert!(term.bits <= *prev, "{} rose at log height {log_height}", term.label);
                *prev = term.bits;
            }
        }
    }

    /// Opening more out-of-domain points raises the degree the DEEP-ALI identity is tested at, so
    /// it can only cost the out-of-domain round bits.
    #[test]
    fn security_is_monotone_in_max_combo() {
        let mut previous = u64::MAX;
        for max_combo in 1..=16u32 {
            let air = AirShape { max_combo, ..air() };
            let term = security_report(&params(), &instance(6), &air).terms()[2];
            assert_eq!(term.label, OUT_OF_DOMAIN_LABEL);
            assert!(term.bits <= previous, "out-of-domain rose at max_combo {max_combo}");
            previous = term.bits;
        }
    }

    /// A bigger or higher-degree AIR can never be more secure under the same parameters.
    #[test]
    fn security_is_monotone_in_air_size() {
        let small = security_report(&params(), &instance(24), &air());
        let large = AirShape {
            num_composed_constraints: 4096,
            max_constraint_degree: 9,
            num_quotient_chunks: 8,
            max_combo: 2,
            num_deep_terms: Some(1024),
            lookup: Some(LookupShape {
                fractions_per_row: 64,
                max_message_width: 16,
            }),
        };
        let large = security_report(&params(), &instance(24), &large);
        assert!(large.security_level() <= small.security_level());
    }

    #[test]
    fn absent_rounds_do_not_bind() {
        for (label, air) in [
            (LOOKUP_LABEL, AirShape { lookup: None, ..air() }),
            (DEEP_COMPOSITION_LABEL, AirShape { num_deep_terms: None, ..air() }),
        ] {
            let instance = instance(29);
            let report = security_report(&params(), &instance, &air);
            let term = report.terms().iter().find(|term| term.label == label).unwrap();
            assert_eq!(term.bits, instance.cap(), "{label}");
            assert_ne!(report.binding_term().label, label);
        }
    }
}
