//! Conjectured security level computation for the Miden VM STARK configuration.
//!
//! Production wrappers in `miden-air` supply generated geometry to the shape-parameterized
//! helpers here. [`derive_air_shape`] and [`num_deep_terms`] independently evaluate authored
//! AIRs for host generation and symbolic validation; no production table feeds these oracles.

use miden_core::{
    field::{BasedVectorSpace, QuadFelt},
    proof::HashFunction,
};
use miden_stark::pcs::PcsParams;
pub use miden_stark::security::*;
#[cfg(test)]
use p3_security::budget::report::{LOOKUP_LABEL, QUERY_LABEL};

use crate::{
    AIRS, ConstraintCounts, ConstraintDegrees, Felt, MidenAir, config,
    constraints::lookup::messages::MIDEN_MAX_MESSAGE_WIDTH,
};

/// Number of out-of-domain points opened per committed column.
///
/// The AIRs use `local` and `next` rotations only.
const NUM_OOD_POINTS: u32 = 2;

/// Base field elements per challenge-field element.
const EXTENSION_DEGREE: usize = <QuadFelt as BasedVectorSpace<Felt>>::DIMENSION;

/// Column alignment of the commitment scheme, in base field elements.
///
/// The commitment sponge absorbs whole rates, so a committed matrix is padded up to a multiple of
/// the rate.
pub const COMMITMENT_ALIGNMENT: usize = config::SPONGE_RATE;

/// Independently compute the full canonical shape from authored schema and symbolic equations.
/// This allocating oracle is for host generation and tests, not production verification.
pub fn derive_air_shape() -> AirShape {
    let mut num_constraints = 0;
    let mut max_constraint_degree = 0;
    let mut num_columns = 0;
    let mut fractions_per_row = 0;

    for air in AIRS {
        let handwritten = air;
        num_constraints += ConstraintCounts::from_air::<Felt, QuadFelt, _>(&handwritten).total();
        max_constraint_degree = max_constraint_degree
            .max(ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&handwritten).max());
        num_columns += column_count(air, COMMITMENT_ALIGNMENT);
        fractions_per_row += air.column_shape().iter().sum::<usize>();
    }
    num_columns += quotient_column_count(max_constraint_degree, COMMITMENT_ALIGNMENT);

    AirShape {
        // One batching slot per AIR beyond the first sits alongside the constraints themselves:
        // constraints are folded by powers of one challenge and the AIRs by a second, so a
        // single-AIR statement needs no cross-AIR batching challenge.
        num_composed_constraints: (num_constraints + AIRS.len() - 1) as u32,
        max_constraint_degree: max_constraint_degree as u32,
        num_quotient_chunks: quotient_chunk_count(max_constraint_degree) as u32,
        max_combo: NUM_OOD_POINTS,
        num_deep_terms: Some(num_columns as u32 + NUM_OOD_POINTS),
        lookup: Some(LookupShape {
            fractions_per_row: fractions_per_row as u32,
            max_message_width: MIDEN_MAX_MESSAGE_WIDTH as u32,
        }),
    }
}

/// Independent full-relation DEEP count from raw source widths and symbolic maximum degree.
/// Production uses generated geometry; this allocating path remains an oracle for each alignment.
pub fn num_deep_terms(alignment: usize) -> u32 {
    let mut num_columns = 0;
    for air in AIRS {
        num_columns += column_count(air, alignment);
    }
    num_columns +=
        quotient_column_count(derive_air_shape().max_constraint_degree as usize, alignment);

    num_columns as u32 + NUM_OOD_POINTS
}

/// Committed base columns for one AIR: preprocessed, main, and auxiliary traces, each its own
/// matrix within its commitment group and so each padded on its own.
fn column_count(air: MidenAir, alignment: usize) -> usize {
    use miden_stark::air::{BaseAir, LiftedAir};

    aligned(BaseAir::<Felt>::preprocessed_width(&air), alignment)
        + aligned(BaseAir::<Felt>::width(&air), alignment)
        + aligned(LiftedAir::<Felt, QuadFelt>::aux_width(&air) * EXTENSION_DEGREE, alignment)
}

/// Committed base columns in the quotient group: one chunk per unit of degree above the vanishing
/// polynomial, rounded up to a power of two, committed as a single extension-valued matrix.
fn quotient_column_count(max_constraint_degree: usize, alignment: usize) -> usize {
    aligned(quotient_chunk_count(max_constraint_degree) * EXTENSION_DEGREE, alignment)
}

/// Committed quotient chunks: one per unit of degree above the vanishing polynomial, rounded up to
/// a power of two.
fn quotient_chunk_count(max_constraint_degree: usize) -> usize {
    max_constraint_degree.saturating_sub(1).max(1).next_power_of_two()
}

/// Pads a committed width up to the commitment scheme's column alignment.
///
/// The DEEP reduction batches every element of each opened, alignment-padded row, so padding also
/// contributes batching slots.
fn aligned(width: usize, alignment: usize) -> usize {
    width.next_multiple_of(alignment)
}

// SECURITY MODEL CONSTANTS
// ================================================================================================
//
// The MASM recursive estimator consumes the raw AIR shape. Tests in
// `crates/lib/core/tests/stark/security.rs` compare it with the native calculation over the ranges
// accepted by the recursive verifiers. Fixed-point tests retain independent rounding references.

/// Fractional bits in the fixed-point representation shared with the MASM estimator.
pub const FIXED_POINT_FRACTIONAL_BITS: u32 = fixed::FRACTIONAL_BITS;

/// Fixed-point representation of one, shared with the MASM estimator.
pub const FIXED_POINT_ONE: u64 = fixed::ONE;

/// Conjectured security contributed per FRI query, in fixed point.
pub const BITS_PER_QUERY: u64 =
    fixed::bits_per_query(config::LOG_BLOWUP as u32, CHALLENGE_FIELD_BITS);

/// Collision resistance of the canonical Eidos commitment hash, in whole bits.
///
/// Eidos exposes a 252-bit packed digest, so birthday collisions cost 126 bits.
pub const COLLISION_RESISTANCE: u32 = HashFunction::Eidos.collision_resistance();

/// Upper bound on every reported level, in fixed point.
pub const SECURITY_CAP: u64 = deployed_instance(0).cap();

/// Q16 upper bound on the log2 of the FRI folding round's error coefficient.
pub const FOLDING_COEFFICIENT: u64 = fixed::ceil_log2(2 * ((1 << config::LOG_FOLDING_ARITY) - 1));

/// The Eidos challenge-support bound less the FRI folding round's coefficient and fixed
/// blowup, in fixed point.
///
/// The common MASM estimator uses the whole-bit floor of this value when proving that FRI folding
/// cannot determine the result. Its `FRI_FOLDING_BASE_BITS` constant must equal that floor.
pub const FOLDING_BASE: u64 =
    EIDOS_CHALLENGE_SAMPLE_BITS - FOLDING_COEFFICIENT - fixed::from_bits(config::LOG_BLOWUP as u32);

/// The instance shape of a deployed Miden VM proof at the given maximum AIR log height.
const fn deployed_instance(log_max_height: u32) -> InstanceShape {
    InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: COLLISION_RESISTANCE,
    }
}

/// `log2(e)`, rounded up, in fixed point. Matches the common MASM estimator's `LOG2_E_FP`.
pub const LOG2_E: u64 = fixed::LOG2_E;

/// Number of lookup fractions `emit_core_boundary` emits unconditionally: the block-hash seed and
/// the two log-deferred-root terminals. Matches `sys::vm::mod.masm`'s
/// `CORE_BOUNDARY_LOOKUP_TERMS`.
pub const CORE_BOUNDARY_LOOKUP_TERMS: u32 = 3;

/// Builds MVM security parameters from values obtained during proof verification.
///
/// `log_max_height` and the supplied aligned `shape` must come from successful STARK verification,
/// `num_kernel_procedures` from the authenticated execution claim, and `hash_fn`
/// from the configuration used to verify the proof, including its challenger.
pub fn proof_security_parameters_with_shape(
    pcs_params: &PcsParams,
    log_max_height: u32,
    num_kernel_procedures: u32,
    shape: AirShape,
    hash_fn: HashFunction,
) -> ProofSecurityParameters {
    mvm_security_parameters_from_protocol(
        protocol_params(pcs_params),
        u32::from(pcs_params.log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        shape,
        hash_fn,
    )
}

fn mvm_security_parameters_from_protocol(
    protocol_params: ProtocolParams,
    log_final_degree: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    shape: AirShape,
    hash_fn: HashFunction,
) -> ProofSecurityParameters {
    ProofSecurityParameters {
        protocol_params,
        log_final_degree,
        instance_shape: InstanceShape {
            log_max_height,
            field_bits: CHALLENGE_FIELD_BITS,
            collision_resistance: hash_fn.collision_resistance(),
        },
        hash_fn,
        air_shape: shape,
        num_ood_points: NUM_OOD_POINTS,
        num_lookup_boundary_terms: CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
    }
}

/// Computes an Eidos Miden VM proof's conjectured security level, in whole bits.
///
/// The Fiat-Shamir transcript binds the PCS parameters and AIR log heights. The authenticated
/// kernel witness determines the kernel procedure count. The remaining inputs are fixed by the
/// deployed AIR and commitment configuration. The result therefore describes the proof and claim
/// that were verified rather than an independently supplied parameter preset.
///
/// Mirrored bit-for-bit by the common MASM estimator when supplied with the MVM descriptor. The
/// recursive verifier admits only 7..=150 queries, 0..=31 query/DEEP/folding grinding bits, fixed
/// zero lookup grinding, log trace height in `6..=29`, and 0..=255 kernel procedures. This function
/// also accepts configurations outside that domain; such inputs are not part of the recursive
/// estimator's contract.
pub fn conjectured_security_level_with_shape(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    shape: AirShape,
) -> u32 {
    let protocol = ProtocolParams {
        log_blowup: config::LOG_BLOWUP as u32,
        log_folding_arity: config::LOG_FOLDING_ARITY as u32,
        num_queries,
        query_pow_bits,
        ood_pow_bits: OOD_POW_BITS,
        deep_pow_bits,
        folding_pow_bits,
        lookup_pow_bits: LOOKUP_POW_BITS,
    };
    mvm_security_parameters_from_protocol(
        protocol,
        u32::from(config::pcs_params().log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        shape,
        HashFunction::Eidos,
    )
    .conjectured_security_level()
}

/// Compute the security level for the supplied aligned relation shape and verified hash choice.
pub fn conjectured_security_level_for_alignment_with_shape(
    num_queries: u32,
    query_pow_bits: u32,
    deep_pow_bits: u32,
    folding_pow_bits: u32,
    log_max_height: u32,
    num_kernel_procedures: u32,
    shape: AirShape,
    hash_fn: HashFunction,
) -> u32 {
    let protocol = ProtocolParams {
        log_blowup: config::LOG_BLOWUP as u32,
        log_folding_arity: config::LOG_FOLDING_ARITY as u32,
        num_queries,
        query_pow_bits,
        ood_pow_bits: OOD_POW_BITS,
        deep_pow_bits,
        folding_pow_bits,
        lookup_pow_bits: LOOKUP_POW_BITS,
    };
    mvm_security_parameters_from_protocol(
        protocol,
        u32::from(config::pcs_params().log_final_degree()),
        log_max_height,
        num_kernel_procedures,
        shape,
        hash_fn,
    )
    .conjectured_security_level()
}

/// Computes the conjectured security level of a Miden VM statement proof, for each protocol
/// round.
///
/// `log_max_height` is the largest AIR trace height in the proof; the Fiat-Shamir transcript binds
/// every AIR's log height, so a prover cannot understate it to inflate the reported level.
/// `hash_fn` selects the commitment collision bound and challenger sampling support.
/// `num_kernel_procedures` is the proof's kernel procedure count, transcript-bound through the
/// kernel witness.
pub fn security_report_with_shape(
    params: &ProtocolParams,
    log_max_height: u32,
    hash_fn: HashFunction,
    num_kernel_procedures: u32,
    shape: AirShape,
) -> SecurityReport {
    let instance = InstanceShape {
        log_max_height,
        field_bits: CHALLENGE_FIELD_BITS,
        collision_resistance: hash_fn.collision_resistance(),
    };
    let report = security_report_with_hash(params, &instance, &shape, hash_fn);
    let correction = lookup_boundary_correction(
        CORE_BOUNDARY_LOOKUP_TERMS + num_kernel_procedures,
        shape.lookup.expect("the relation uses lookup").fractions_per_row,
        log_max_height,
    );
    apply_lookup_correction(report, correction)
}

#[cfg(test)]
mod tests {
    fn shape(alignment: usize) -> AirShape {
        AirShape {
            num_deep_terms: Some(num_deep_terms(alignment)),
            ..derive_air_shape()
        }
    }

    fn proof_security_parameters(
        pcs_params: &PcsParams,
        log_max_height: u32,
        num_kernel_procedures: u32,
        alignment: usize,
        hash_fn: HashFunction,
    ) -> ProofSecurityParameters {
        super::proof_security_parameters_with_shape(
            pcs_params,
            log_max_height,
            num_kernel_procedures,
            shape(alignment),
            hash_fn,
        )
    }

    fn security_report(
        params: &ProtocolParams,
        log_max_height: u32,
        hash_fn: HashFunction,
        num_kernel_procedures: u32,
    ) -> SecurityReport {
        super::security_report_with_shape(
            params,
            log_max_height,
            hash_fn,
            num_kernel_procedures,
            shape(COMMITMENT_ALIGNMENT),
        )
    }

    use super::*;

    /// Power-of-two error coefficients make the root-counting bounds exact without using the
    /// estimator's logarithm implementation. The collision cap must be applied after sampling.
    #[test]
    fn eidos_root_counts_use_the_sampling_support_before_capping() {
        use p3_security::budget::report::{COMPOSITION_LABEL, DEEP_COMPOSITION_LABEL};

        let params = ProtocolParams {
            num_queries: 150,
            query_pow_bits: 31,
            deep_pow_bits: 0,
            ..protocol_params(&config::pcs_params())
        };
        let air = AirShape {
            num_composed_constraints: 1024,
            num_deep_terms: Some(1024),
            lookup: Some(LookupShape {
                max_message_width: 6,
                fractions_per_row: 128,
            }),
            ..derive_air_shape()
        };
        let instance = deployed_instance(20);
        let report = security_report_with_hash(&params, &instance, &air, HashFunction::Eidos);
        for (label, bits) in [
            // The lookup coefficient is (6 + 2) * 128 = 2^10, at height 2^20:
            // error <= 2^30 / 2^126 = 2^-96.
            (LOOKUP_LABEL, 96u32),
            // Each batching coefficient is 2^10, so error <= 2^10 / 2^126 = 2^-116.
            (COMPOSITION_LABEL, 116),
            // DEEP batching also pays the LDE height (20 + 3).
            (DEEP_COMPOSITION_LABEL, 93),
        ] {
            assert_eq!(
                report.terms().iter().find(|term| term.label == label).unwrap().bits,
                u64::from(bits) * 65_536,
                "wrong sampling denominator for {label}"
            );
        }

        // A lower commitment-security assumption caps the 116-bit batching bound at 100.
        // Subtracting two bits from an already capped report would incorrectly give 98.
        let capped = security_report_with_hash(
            &params,
            &InstanceShape { collision_resistance: 100, ..instance },
            &air,
            HashFunction::Eidos,
        );
        assert_eq!(
            capped.terms().iter().find(|term| term.label == COMPOSITION_LABEL).unwrap().bits,
            100 * 65_536
        );

        let full_field = p3_security::budget::security_report(&params, &instance, &air);
        assert_eq!(
            report.terms().iter().find(|term| term.label == QUERY_LABEL),
            full_field.terms().iter().find(|term| term.label == QUERY_LABEL),
            "the FRI query rate must retain the ambient field size"
        );
    }

    #[test]
    fn full_field_challengers_preserve_their_security_bounds() {
        let params = protocol_params(&config::pcs_params());
        for hash_fn in [
            HashFunction::Blake3_256,
            HashFunction::Rpo256,
            HashFunction::Rpx256,
            HashFunction::Poseidon2,
            HashFunction::Keccak,
        ] {
            let parameters = proof_security_parameters(&config::pcs_params(), 20, 0, 8, hash_fn);
            assert_eq!(parameters.hash_fn, hash_fn);
            assert_eq!(
                parameters.instance_shape.collision_resistance,
                hash_fn.collision_resistance()
            );
            assert_eq!(
                security_report_with_hash(
                    &params,
                    &parameters.instance_shape,
                    &derive_air_shape(),
                    hash_fn
                ),
                p3_security::budget::security_report(
                    &params,
                    &parameters.instance_shape,
                    &derive_air_shape()
                ),
                "full-field sampling changed for {hash_fn:?}"
            );
        }
    }

    /// Parameters built for an MVM proof must reproduce the independent MVM security report.
    #[test]
    fn proof_security_parameters_match_mvm_security_report() {
        let pcs_params = config::pcs_params();
        let expected_protocol_params = protocol_params(&pcs_params);
        let security_parameters = proof_security_parameters(
            &pcs_params,
            22,
            255,
            COMMITMENT_ALIGNMENT,
            HashFunction::Eidos,
        );

        assert_eq!(
            security_parameters.conjectured_security_report(),
            security_report(&expected_protocol_params, 22, HashFunction::Eidos, 255)
        );
        assert_eq!(security_parameters.log_final_degree, u32::from(pcs_params.log_final_degree()));
        assert_eq!(security_parameters.num_ood_points, NUM_OOD_POINTS);
    }

    /// Pins the deployed preset's computed security level and binding term at representative trace
    /// heights.
    #[test]
    fn deployed_preset_grades_by_trace_height() {
        let params = protocol_params(&config::pcs_params());

        for (log_height, expected_level, expected_binding) in [
            (18, 96, QUERY_LABEL),
            (20, 95, LOOKUP_LABEL),
            (22, 93, LOOKUP_LABEL),
            (24, 91, LOOKUP_LABEL),
            (29, 86, LOOKUP_LABEL),
        ] {
            let report = security_report(&params, log_height, HashFunction::Eidos, 0);
            assert_eq!(
                report.security_level(),
                expected_level,
                "unexpected level at log height {log_height}"
            );
            assert_eq!(
                report.binding_term().label,
                expected_binding,
                "unexpected binding round at log height {log_height}"
            );
        }
    }

    /// Stable fixed-point representation and rounding references, independent of AIR facts.
    #[test]
    fn fixed_point_constants_match_reference() {
        assert_eq!(FIXED_POINT_FRACTIONAL_BITS, 16);
        assert_eq!(FIXED_POINT_ONE, 65_536);
        assert_eq!(BITS_PER_QUERY, 193_381);
        assert_eq!(SECURITY_CAP, 8_257_536);
        assert_eq!(FOLDING_BASE, 7_891_519);
        assert_eq!(LOOKUP_POW_BITS, 0);
    }

    /// Checks every round against values computed independently from its documented formula.
    ///
    /// Final-level and monotonicity tests do not expose an error in a term that never determines
    /// the minimum. These vectors therefore include parameters that move the query, DEEP, and
    /// FRI folding terms away from the security cap and make their individual values
    /// observable.
    #[test]
    fn security_report_matches_reference_vectors() {
        // (queries, query PoW, DEEP PoW, folding PoW, log height)
        //   -> [lookup, composition, ood, deep, folding, query, collision], level
        const VECTORS: &[((u32, u32, u32, u32, u32), [u64; 7], u32)] = &[
            (
                (27, 17, 12, 4, 6),
                [7_179_062, 7_647_953, 7_645_438, 7_920_710, 7_760_447, 6_335_399, 8_257_536],
                96,
            ),
            (
                (27, 17, 12, 4, 20),
                [6_261_614, 7_647_953, 6_729_109, 7_003_206, 6_842_943, 6_335_399, 8_257_536],
                95,
            ),
            (
                (27, 17, 12, 4, 23),
                [6_065_006, 7_647_953, 6_532_501, 6_806_598, 6_646_335, 6_335_399, 8_257_536],
                92,
            ),
            (
                (27, 17, 12, 4, 29),
                [5_671_790, 7_647_953, 6_139_285, 6_413_382, 6_253_119, 6_335_399, 8_257_536],
                86,
            ),
            (
                (7, 0, 0, 0, 20),
                [6_261_614, 7_647_953, 6_729_109, 6_216_774, 6_580_799, 1_353_667, 8_257_536],
                20,
            ),
            (
                (150, 31, 31, 31, 29),
                [5_671_790, 7_647_953, 6_139_285, 7_658_566, 8_022_591, 8_257_536, 8_257_536],
                86,
            ),
        ];

        let base = protocol_params(&config::pcs_params());
        for &(
            (num_queries, query_pow_bits, deep_pow_bits, folding_pow_bits, log_height),
            rounds,
            level,
        ) in VECTORS
        {
            let params = ProtocolParams {
                num_queries,
                query_pow_bits,
                deep_pow_bits,
                folding_pow_bits,
                ..base
            };
            let report = security_report(&params, log_height, HashFunction::Eidos, 0);

            assert_eq!(
                (*report.terms()).map(|term| term.bits),
                rounds,
                "round-bit mismatch at {params:?}, log height {log_height}"
            );
            assert_eq!(
                report.security_level(),
                level,
                "unexpected level at {params:?}, log height {log_height}"
            );
        }
    }

    /// Pins the height at which lookup overtakes the deployed preset's query bound.
    #[test]
    fn lookup_round_overtakes_the_query_phase_at_height_nineteen() {
        let params = protocol_params(&config::pcs_params());
        let crossover = (6..=30)
            .find(|&log_height| {
                security_report(&params, log_height, HashFunction::Eidos, 0)
                    .binding_term()
                    .label
                    == LOOKUP_LABEL
            })
            .expect("the lookup round must bind at some supported height");

        assert_eq!(crossover, 19, "unexpected lookup/query crossover");
    }

    /// A proof with the maximum kernel witness reports a lower lookup-round bound than a bare one
    /// at the same height, since `emit_chiplets_boundary` adds one lookup fraction per kernel
    /// procedure digest on top of the per-row bus terms `derive_air_shape()` counts.
    #[test]
    fn lookup_boundary_correction_lowers_the_lookup_term_with_a_full_kernel_witness() {
        let lookup_bits = |report: SecurityReport| {
            report.terms().iter().find(|term| term.label == LOOKUP_LABEL).unwrap().bits
        };

        let params = protocol_params(&config::pcs_params());
        let bare = lookup_bits(security_report(&params, 6, HashFunction::Eidos, 0));
        let full_kernel = lookup_bits(security_report(&params, 6, HashFunction::Eidos, 255));
        assert!(
            full_kernel < bare,
            "a full kernel witness should lower the lookup round's bound, got {full_kernel} vs \
             {bare}"
        );
    }
}
