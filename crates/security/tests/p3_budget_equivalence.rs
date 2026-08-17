//! Bit-for-bit equivalence between this crate's `security_report` and `p3_security::budget`'s,
//! given the same inputs (`num_deep_terms` wrapped in `Some`, the only shape difference between
//! the two). This is the direct check Phase 4 of a swap-and-delete migration needs: not just
//! direction/tightness against the `f64` formulas, but that the two `const fn` implementations
//! compute the *same* fixed-point integer for every round, on every reference-vector row from
//! `air/src/security.rs` and `precompiles-prover/src/security.rs`.

use miden_security::{AirShape, InstanceShape, LookupShape, ProtocolParams, fixed};
use p3_security::budget;

fn field_bits() -> u64 {
    2 * fixed::floor_log2(0xFFFF_FFFF_0000_0001)
}

const COLLISION_RESISTANCE: u32 = 127;

struct AirVector {
    num_composed_constraints: u32,
    max_constraint_degree: u32,
    num_deep_terms: u32,
    fractions_per_row: u32,
    max_message_width: u32,
}

const VM: AirVector = AirVector {
    num_composed_constraints: 424,
    max_constraint_degree: 9,
    num_deep_terms: 138,
    fractions_per_row: 28,
    max_message_width: 16,
};

const PVM: AirVector = AirVector {
    num_composed_constraints: 587,
    max_constraint_degree: 5,
    num_deep_terms: 770,
    fractions_per_row: 244,
    max_message_width: 18,
};

fn miden_air(v: &AirVector) -> AirShape {
    AirShape {
        num_composed_constraints: v.num_composed_constraints,
        max_constraint_degree: v.max_constraint_degree,
        num_deep_terms: v.num_deep_terms,
        lookup: LookupShape {
            fractions_per_row: v.fractions_per_row,
            max_message_width: v.max_message_width,
        },
    }
}

fn p3_air(v: &AirVector) -> budget::AirShape {
    budget::AirShape {
        num_composed_constraints: v.num_composed_constraints,
        max_constraint_degree: v.max_constraint_degree,
        num_deep_terms: Some(v.num_deep_terms),
        lookup: budget::LookupShape {
            fractions_per_row: v.fractions_per_row,
            max_message_width: v.max_message_width,
        },
    }
}

/// Every round, bit for bit, across both AIR shapes, every reference-vector parameter row, and
/// every swept height.
#[test]
fn every_round_is_bit_identical() {
    const PARAM_ROWS: &[(u32, u32, u32, u32)] = &[(27, 17, 12, 4), (7, 0, 0, 0), (150, 31, 31, 31)];

    for air_vector in [&VM, &PVM] {
        for &(num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits) in PARAM_ROWS {
            let miden_params = ProtocolParams {
                log_blowup: 3,
                log_folding_arity: 2,
                num_queries,
                query_pow_bits,
                deep_pow_bits,
                folding_pow_bits,
                lookup_pow_bits: 0,
            };
            let p3_params = budget::ProtocolParams {
                log_blowup: 3,
                log_folding_arity: 2,
                num_queries,
                query_pow_bits,
                deep_pow_bits,
                folding_pow_bits,
                lookup_pow_bits: 0,
            };

            for log_max_height in 6..=29u32 {
                let miden_instance = InstanceShape {
                    log_max_height,
                    field_bits: field_bits(),
                    collision_resistance: COLLISION_RESISTANCE,
                };
                let p3_instance = budget::InstanceShape {
                    log_max_height,
                    field_bits: field_bits(),
                    collision_resistance: COLLISION_RESISTANCE,
                };

                let miden_report = miden_security::security_report(
                    &miden_params,
                    &miden_instance,
                    &miden_air(air_vector),
                );
                let p3_report =
                    budget::security_report(&p3_params, &p3_instance, &p3_air(air_vector));

                for (miden_term, p3_term) in miden_report.terms().iter().zip(p3_report.terms()) {
                    assert_eq!(
                        miden_term.bits, p3_term.bits,
                        "round diverged at h={log_max_height}, queries={num_queries}: \
                         miden {} != p3 {} ({} / {})",
                        miden_term.bits, p3_term.bits, miden_term.label, p3_term.label
                    );
                }
                assert_eq!(miden_report.security_level(), p3_report.security_level());
            }
        }
    }
}

/// The pinned reference-vector rows from `air/src/security.rs`, replayed through
/// `p3_security::budget` directly (not through `miden_security` at all), to rule out both crates
/// sharing a bug that a cross-check between them wouldn't surface.
#[test]
fn p3_budget_matches_vm_reference_vectors_directly() {
    const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
        (
            (27, 17, 12, 4, 6),
            [7_407_054, 7_816_613, 7_777_684, 8_323_072, 7_891_517, 6_335_399, 8_323_072],
            96,
        ),
        (
            (27, 17, 12, 4, 20),
            [6_489_550, 7_816_613, 6_860_180, 8_323_072, 6_974_013, 6_335_399, 8_323_072],
            96,
        ),
        (
            (27, 17, 12, 4, 29),
            [5_899_726, 7_816_613, 6_270_356, 8_323_072, 6_384_189, 6_335_399, 8_323_072],
            90,
        ),
    ];

    for &(
        (num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits, log_height),
        rounds,
        level,
    ) in VECTORS
    {
        let params = budget::ProtocolParams {
            log_blowup: 3,
            log_folding_arity: 2,
            num_queries,
            query_pow_bits,
            deep_pow_bits,
            folding_pow_bits,
            lookup_pow_bits: 0,
        };
        let instance = budget::InstanceShape {
            log_max_height: log_height,
            field_bits: field_bits(),
            collision_resistance: COLLISION_RESISTANCE,
        };
        let report = budget::security_report(&params, &instance, &p3_air(&VM));

        assert_eq!((*report.terms()).map(|t| t.bits), rounds);
        assert_eq!(report.security_level(), level);
    }
}
