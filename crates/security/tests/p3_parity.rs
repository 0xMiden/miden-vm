//! Cross-checks every round this crate grades against its `p3-security` counterpart, so the two
//! representations can never drift apart silently.
//!
//! # Correspondence
//!
//! | This crate | `p3-security` |
//! |---|---|
//! | `ProtocolParams{log_blowup, num_queries, query_pow_bits}` | `FriRegime{log_blowup, num_queries, query_pow_bits, max_log_arity: log_folding_arity, commit_pow_bits: folding_pow_bits, log_final_poly_len: 0}` |
//! | `InstanceShape{log_max_height, field_bits}` | `InstanceShape{log_trace_length: log_max_height, modulus_bits: 128, collision_resistance: 127}` |
//! | `AirShape{num_composed_constraints, max_constraint_degree}` | `StarkAirParams{num_constraints, max_constraint_degree, max_combo: 2}` |
//! | `AirShape.lookup` | `LogUpAir{num_interactions: fractions_per_row, max_message_width}` |
//! | `AirShape.num_deep_terms` + `deep_pow_bits` | a caller-built `extras` term: `boost(composition_error(num_deep_terms, 1.0, 128), deep_pow_bits)` |
//! | (no out-of-domain grind) | `GrindingSites::NONE` |
//!
//! `modulus_bits: 128` is a deliberate ceiling of this crate's `CHALLENGE_FIELD_BITS`
//! (`8_388_606`, i.e. `127.999985...` in Q16): `p3-security`'s `modulus_bits` is a plain `usize`
//! and cannot represent the fractional value, and rounding up is the direction that keeps every
//! upstream term at least as generous as this crate's, which is what the direction checks below
//! require.
//!
//! The out-of-domain round is the one place the two formulas are not the same closed form:
//! `p3-security`'s `deep_ali_error` accounts for `max_combo` out-of-domain points per column
//! (`factor = max_deg·(k + combo − 1) + (k − 1)`), while this crate's OOD round assumes a single
//! point (`factor = (max_deg + 1)·k`). At `combo = 2` the two factors differ by exactly
//! `max_deg − 1`, so this crate's round can read up to `log2(1 + (max_deg − 1) / ((max_deg + 1)·height))`
//! bits more generous than `p3-security`'s — sub-hundredth-of-a-bit at the shallowest height these
//! AIRs are graded at (`h = 6`) and vanishing well before it as height grows. [`ood_tolerance`]
//! bounds it analytically rather than papering over it with a flat epsilon.

use miden_security::{AirShape, InstanceShape, LookupShape, ProtocolParams, SecurityReport, fixed};
use p3_security::air::composition_error;
use p3_security::deep::deep_ali_error;
use p3_security::fri::{
    FriRegime, commit_phase_error_udr, conjectured_error as p3_conjectured_error,
};
use p3_security::grinding::{GrindingSites, boost};
use p3_security::logup::{LogUpAir, security_term as logup_security_term};
use p3_security::report::SecurityTerm as P3SecurityTerm;
use p3_security::shape::{InstanceShape as P3InstanceShape, StarkAirParams};
use p3_security::stark::conjectured_security_report;

/// Miden's Goldilocks field order, mirrored here (rather than depended on) so this crate does not
/// need `miden-core` as a dev-dependency just to run this test.
const GOLDILOCKS_ORDER: u64 = 0xFFFF_FFFF_0000_0001;

/// This crate's `CHALLENGE_FIELD_BITS`, in Q16 fixed point.
fn field_bits() -> u64 {
    2 * fixed::floor_log2(GOLDILOCKS_ORDER)
}

/// Ceiling of `field_bits()` to a whole bit count — see the module doc for why rounding up.
const MODULUS_BITS: usize = 128;

/// Collision resistance shared by every deployed Miden preset.
const COLLISION_RESISTANCE: u32 = 127;

const LOG_BLOWUP: u32 = 3;
const LOG_FOLDING_ARITY: u32 = 2;

/// Slack from two sources, both in the safe (p3-more-generous) direction: up to ~2 ulps of
/// fixed-point `log2` rounding (`fixed::floor_log2`/`ceil_log2` are documented to track the true
/// value within one ulp each), and the `field_bits()` vs. `MODULUS_BITS` gap (`2 / 65536`).
const TIGHT_TOL: f64 = 1e-4;

fn to_f64(fixed_bits: u64) -> f64 {
    fixed_bits as f64 / fixed::ONE as f64
}

/// Reproduces the private `round()` formula in `conjectured.rs` from its public building blocks,
/// without the final `min(_, cap)` — the tests below want the uncapped value.
fn round_bits(coefficient: u64, log_size: u32, pow_bits: u32) -> Option<u64> {
    if coefficient == 0 {
        return None;
    }
    let error = fixed::ceil_log2(coefficient) + fixed::from_bits(log_size);
    let bits = if error >= field_bits() {
        fixed::from_bits(pow_bits)
    } else {
        field_bits() - error + fixed::from_bits(pow_bits)
    };
    Some(bits)
}

fn query_round_bits(num_queries: u32, query_pow_bits: u32) -> u64 {
    num_queries as u64 * fixed::bits_per_query(LOG_BLOWUP, field_bits())
        + fixed::from_bits(query_pow_bits)
}

/// Analytic bound on how much more generous this crate's OOD round can read than `p3-security`'s
/// DEEP-ALI term at `max_combo = 2` — see the module doc.
fn ood_tolerance(max_constraint_degree: u32, log_max_height: u32) -> f64 {
    let d = max_constraint_degree as f64;
    let height = 2f64.powi(log_max_height as i32);
    (1.0 + (d - 1.0) / ((d + 1.0) * height)).log2() + TIGHT_TOL
}

fn p3_instance_shape(log_max_height: u32) -> P3InstanceShape {
    P3InstanceShape {
        log_trace_length: log_max_height as usize,
        modulus_bits: MODULUS_BITS,
        collision_resistance: COLLISION_RESISTANCE as usize,
        num_batched_functions: 1,
    }
}

fn p3_fri_regime(num_queries: u32, query_pow_bits: u32, folding_pow_bits: u32) -> FriRegime {
    FriRegime {
        log_blowup: LOG_BLOWUP as usize,
        num_queries: num_queries as usize,
        log_final_poly_len: 0,
        max_log_arity: LOG_FOLDING_ARITY as usize,
        commit_pow_bits: folding_pow_bits as usize,
        query_pow_bits: query_pow_bits as usize,
    }
}

struct AirVector {
    name: &'static str,
    shape: AirShape,
}

const VM: AirVector = AirVector {
    name: "vm",
    shape: AirShape {
        num_composed_constraints: 424,
        max_constraint_degree: 9,
        num_deep_terms: 138,
        lookup: LookupShape {
            fractions_per_row: 28,
            max_message_width: 16,
        },
    },
};

const PVM: AirVector = AirVector {
    name: "pvm",
    shape: AirShape {
        num_composed_constraints: 587,
        max_constraint_degree: 5,
        num_deep_terms: 770,
        lookup: LookupShape {
            fractions_per_row: 244,
            max_message_width: 18,
        },
    },
};

/// `(queries, query_pow, deep_pow, folding_pow)` rows exercised by `air/src/security.rs` and
/// `precompiles-prover/src/security.rs`'s own reference-vector tests, reused here as the parameter
/// points the per-round sweep holds fixed while height varies.
const PARAM_ROWS: &[(u32, u32, u32, u32)] = &[(27, 17, 12, 4), (7, 0, 0, 0), (150, 31, 31, 31)];

/// Every round direction and tightness bound holds across the full deployed height range, for
/// every AIR shape and every parameter row those AIRs are graded under.
#[test]
fn every_round_direction_and_tightness() {
    for air in [VM, PVM] {
        for &(num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits) in PARAM_ROWS {
            for log_max_height in 6..=29u32 {
                check_query(num_queries, query_pow_bits);
                check_lookup(&air, log_max_height);
                check_composition(&air);
                check_ood(&air, log_max_height);
                check_folding(log_max_height, folding_pow_bits);
                check_deep_composition_extra(&air, deep_pow_bits);
            }
        }
    }
}

fn check_query(num_queries: u32, query_pow_bits: u32) {
    let fixed_bits = to_f64(query_round_bits(num_queries, query_pow_bits));
    let regime = p3_fri_regime(num_queries, query_pow_bits, 0);
    let p3_bits = p3_conjectured_error(&regime, &p3_instance_shape(20)).bits();

    // `bits_per_query`'s own per-call slack (bounded at 2 ulps by `fixed`'s tests) is summed
    // `num_queries` times, so the round's tolerance scales with it rather than staying flat.
    let tolerance = num_queries as f64 * (2.0 / fixed::ONE as f64) + TIGHT_TOL;
    assert!(
        fixed_bits <= p3_bits + tolerance,
        "query: {fixed_bits} > {p3_bits} + {tolerance}"
    );
    assert!(
        p3_bits - fixed_bits < tolerance,
        "query: p3 {p3_bits} - fixed {fixed_bits} looser than {tolerance}"
    );
}

fn check_lookup(air: &AirVector, log_max_height: u32) {
    let coefficient =
        (air.shape.lookup.max_message_width as u64 + 2) * air.shape.lookup.fractions_per_row as u64;
    let fixed_bits = to_f64(round_bits(coefficient, log_max_height, 0).expect("has interactions"));

    let logup_air = LogUpAir {
        num_interactions: air.shape.lookup.fractions_per_row as usize,
        max_message_width: air.shape.lookup.max_message_width as usize,
    };
    let p3_bits =
        logup_security_term(&logup_air, &p3_instance_shape(log_max_height), &GrindingSites::NONE)
            .expect("has interactions")
            .bits
            .bits();

    assert!(
        fixed_bits <= p3_bits + TIGHT_TOL,
        "{}: lookup {fixed_bits} > {p3_bits}",
        air.name
    );
    assert!(
        p3_bits - fixed_bits < TIGHT_TOL,
        "{}: lookup p3 {p3_bits} - fixed {fixed_bits} too loose",
        air.name
    );
}

fn check_composition(air: &AirVector) {
    let fixed_bits =
        to_f64(round_bits(air.shape.num_composed_constraints as u64, 0, 0).expect("nonzero"));
    let p3_bits =
        composition_error(air.shape.num_composed_constraints as usize, 1.0, MODULUS_BITS).bits();

    assert!(
        fixed_bits <= p3_bits + TIGHT_TOL,
        "{}: composition {fixed_bits} > {p3_bits}",
        air.name
    );
    assert!(
        p3_bits - fixed_bits < TIGHT_TOL,
        "{}: composition p3 {p3_bits} - fixed {fixed_bits} too loose",
        air.name
    );
}

fn check_ood(air: &AirVector, log_max_height: u32) {
    let fixed_bits = to_f64(
        round_bits(air.shape.max_constraint_degree as u64 + 1, log_max_height, 0).expect("nonzero"),
    );
    let stark_air = StarkAirParams {
        num_constraints: air.shape.num_composed_constraints as usize,
        max_constraint_degree: air.shape.max_constraint_degree as usize,
        max_combo: 2,
    };
    let p3_bits = deep_ali_error(&stark_air, &p3_instance_shape(log_max_height), 1.0).bits();

    let tolerance = ood_tolerance(air.shape.max_constraint_degree, log_max_height);
    assert!(
        fixed_bits <= p3_bits + tolerance,
        "{}: ood {fixed_bits} > {p3_bits} + {tolerance} at h={log_max_height}",
        air.name
    );
}

fn check_folding(log_max_height: u32, folding_pow_bits: u32) {
    let coefficient = 2 * ((1u64 << LOG_FOLDING_ARITY) - 1);
    let fixed_bits = to_f64(
        round_bits(coefficient, log_max_height + LOG_BLOWUP, folding_pow_bits).expect("nonzero"),
    );

    let regime = p3_fri_regime(1, 0, folding_pow_bits);
    let p3_bits = commit_phase_error_udr(&regime, &p3_instance_shape(log_max_height))
        .expect("folds at every swept height")
        .bits();

    assert!(fixed_bits <= p3_bits + TIGHT_TOL, "folding: {fixed_bits} > {p3_bits}");
    // Worst-round-only (p3) vs. doubled-coefficient (this crate) always differ by strictly less
    // than one bit — see the module doc.
    assert!(
        p3_bits - fixed_bits < 1.0 + TIGHT_TOL,
        "folding: gap {} >= 1 bit",
        p3_bits - fixed_bits
    );
}

/// This crate's DEEP-composition round has no `p3-security` built-in counterpart; it round-trips
/// through the same `extras` mechanism the composite check uses, so a coefficient or grind wiring
/// mistake there is caught independently of the composite's exact-equality assertions.
fn check_deep_composition_extra(air: &AirVector, deep_pow_bits: u32) {
    let fixed_bits =
        to_f64(round_bits(air.shape.num_deep_terms as u64, 0, deep_pow_bits).expect("nonzero"));
    let p3_bits = boost(
        composition_error(air.shape.num_deep_terms as usize, 1.0, MODULUS_BITS),
        deep_pow_bits as usize,
    )
    .bits();

    assert!(
        fixed_bits <= p3_bits + TIGHT_TOL,
        "{}: deep-composition {fixed_bits} > {p3_bits}",
        air.name
    );
    assert!(
        p3_bits - fixed_bits < TIGHT_TOL,
        "{}: deep-composition p3 {p3_bits} - fixed {fixed_bits} too loose",
        air.name
    );
}

fn p3_composite_level(
    air: &AirShape,
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
) -> u32 {
    let regime = p3_fri_regime(num_queries, query_pow_bits, folding_pow_bits);
    let instance = p3_instance_shape(log_max_height);
    let stark_air = StarkAirParams {
        num_constraints: air.num_composed_constraints as usize,
        max_constraint_degree: air.max_constraint_degree as usize,
        max_combo: 2,
    };

    let logup_air = LogUpAir {
        num_interactions: air.lookup.fractions_per_row as usize,
        max_message_width: air.lookup.max_message_width as usize,
    };
    let logup_extra = logup_security_term(&logup_air, &instance, &GrindingSites::NONE)
        .expect("every AIR shape here has interactions");
    let deep_extra = P3SecurityTerm::new(
        "deep-composition",
        boost(
            composition_error(air.num_deep_terms as usize, 1.0, MODULUS_BITS),
            deep_pow_bits as usize,
        ),
    );

    let report = conjectured_security_report(
        &regime,
        &stark_air,
        &instance,
        &[logup_extra, deep_extra],
        &GrindingSites::NONE,
    );
    report.security_bits().floor() as u32
}

/// The full composite grade, integer-bit for integer-bit, against every pinned reference-vector
/// row this crate's own regression tests carry — the strongest parity claim this file makes.
#[test]
fn composite_matches_reference_vectors() {
    // (air, (queries, query_pow, deep_pow, folding_pow, log_height), expected level)
    const VM_ROWS: &[((u32, u32, u32, u32, u32), u32)] = &[
        ((27, 17, 12, 4, 6), 96),
        ((27, 17, 12, 4, 20), 96),
        ((27, 17, 12, 4, 23), 96),
        ((27, 17, 12, 4, 29), 90),
        ((7, 0, 0, 0, 20), 20),
        ((150, 31, 31, 31, 29), 90),
    ];
    const PVM_ROWS: &[((u32, u32, u32, u32, u32), u32)] = &[
        ((27, 17, 12, 4, 6), 96),
        ((27, 17, 12, 4, 16), 96),
        ((27, 17, 12, 4, 19), 96),
        ((27, 17, 12, 4, 20), 95),
        ((27, 17, 12, 4, 24), 91),
        ((7, 0, 0, 0, 16), 20),
    ];

    for (air, rows) in [(&VM.shape, VM_ROWS), (&PVM.shape, PVM_ROWS)] {
        for &((num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits, log_height), level) in
            rows
        {
            let p3_level = p3_composite_level(
                air,
                num_queries,
                query_pow_bits,
                deep_pow_bits,
                folding_pow_bits,
                log_height,
            );
            assert_eq!(
                p3_level, level,
                "p3 composite moved at h={log_height}, queries={num_queries}"
            );
        }
    }
}

/// Sanity check that the two `InstanceShape`/`ProtocolParams` mappings above actually agree with
/// this crate's own `security_report` for the same reference-vector rows — pins the mapping table
/// itself, not just the arithmetic each side does independently of it.
#[test]
fn mapping_reproduces_this_crates_own_reference_vectors() {
    let params = ProtocolParams {
        log_blowup: LOG_BLOWUP,
        log_folding_arity: LOG_FOLDING_ARITY,
        num_queries: 27,
        query_pow_bits: 17,
        deep_pow_bits: 12,
        folding_pow_bits: 4,
        lookup_pow_bits: 0,
    };
    let instance = InstanceShape {
        log_max_height: 20,
        field_bits: field_bits(),
        collision_resistance: COLLISION_RESISTANCE,
    };
    let report: SecurityReport = miden_security::security_report(&params, &instance, &VM.shape);
    assert_eq!(report.security_level(), 96);
}
