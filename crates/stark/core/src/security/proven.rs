// Derived from p3-security 0.8.0, Plonky3 commit a21e3ed42905040ad49c519e402f018381c12d0c.
// Copyright (c) 2022 The Plonky3 Authors
// SPDX-License-Identifier: MIT OR Apache-2.0
// Adapted for Miden's concrete FRI security calculation; see provenance/README.md.

//! Complete proven bounds for Miden's FRI-backed argument.
//!
//! The same list-decoding parameter must govern the FRI, opening-batching and lookup losses.
//! Each candidate is therefore composed completely before choosing the strongest report. No
//! security-report construction invokes AIR evaluation, witness construction or fixed-table data.

use alloc::vec::Vec;
use core::cmp::Ordering;

use libm::log2;
use miden_core::proof::HashFunction;

use super::{
    EIDOS_CHALLENGE_SAMPLE_BITS, ErrorBits, NumericalInputs, ProvenSecurityReport,
    ProvenSecurityTerm, Regime, RegimeReport, fixed,
    fri::{self, FriRegime},
    labels::{ALI_LABEL, BATCH_LABEL, COLLISION_LABEL, DEEP_LABEL, LDT_LABEL, LOOKUP_LABEL},
    proximity::{batching_error_ldr_m, batching_error_udr, list_size_ldr_m, list_size_udr},
};

/// Numeric relation quantities needed by the floating-point formulas.
///
/// The quotient count is the actual committed allocation, not a degree-derived minimum. These
/// values are resolved from compiled relation metadata; they carry no upstream AIR capability.
#[derive(Clone, Copy, Debug)]
pub struct AirParameters {
    pub num_constraints: usize,
    pub max_constraint_degree: usize,
    pub num_quotient_chunks: usize,
    pub max_combo: usize,
}

/// Concrete instance quantities needed by the floating-point formulas.
///
/// `modulus_bits` is the conservative sampling size selected by Miden for this analysis. It is
/// separate from the actual field cardinality used by the fixed-point FRI query calculation.
#[derive(Clone, Copy, Debug)]
pub struct InstanceParameters {
    pub log_trace_length: usize,
    pub modulus_bits: usize,
    pub collision_resistance: usize,
    pub num_batched_functions: usize,
}

/// `-log2(L * num_constraints / |F|)`, with degenerate inputs reporting zero security.
pub fn composition_error(num_constraints: usize, list_size: f64, modulus_bits: usize) -> ErrorBits {
    if num_constraints == 0 || modulus_bits == 0 || !list_size.is_finite() || list_size <= 0.0 {
        return ErrorBits::from_log2(0.0);
    }
    let bits = modulus_bits as f64 - log2(list_size) - log2(num_constraints as f64);
    ErrorBits::from_log2(bits.max(0.0))
}

/// DEEP-ALI out-of-domain sampling error.
///
/// With trace size `k`, the factor is the maximum of
/// `max_degree * (k + max_combo - 1) + (k - 1)` and `(quotient_chunks + 1) * k + max_combo - 1`.
/// The second expression matters when a conservative committed allocation exceeds the degree.
/// The list size multiplies that factor. Degenerate or unrepresentable inputs report zero bits.
pub fn deep_ali_error(
    air: &AirParameters,
    shape: &InstanceParameters,
    list_size: f64,
) -> ErrorBits {
    if shape.modulus_bits == 0
        || !air.num_quotient_chunks.is_power_of_two()
        || shape.log_trace_length >= u64::BITS as usize
        || !list_size.is_finite()
        || list_size <= 0.0
    {
        return ErrorBits::from_log2(0.0);
    }
    let k = (1u64 << shape.log_trace_length) as f64;
    let max_deg = air.max_constraint_degree.max(1) as f64;
    let combo = air.max_combo as f64;
    let ethstark = max_deg * (k + combo - 1.0) + (k - 1.0);
    let chunks = air.num_quotient_chunks as f64;
    let chunked = (chunks + 1.0) * k + combo - 1.0;
    let factor = ethstark.max(chunked).max(1.0);
    let bits = shape.modulus_bits as f64 - log2(list_size) - log2(factor);
    ErrorBits::from_log2(bits.max(0.0))
}

/// Compose the complete UDR and LDR bounds using the already corrected Q16 lookup round.
pub(super) fn security_report(inputs: &NumericalInputs, lookup_bits: u64) -> ProvenSecurityReport {
    resolved_report(inputs, lookup_bits, true)
}

/// Retained comparison against composing one unchanged lookup term in both regimes.
///
/// This preserves the previous reference's distinction from Miden's candidate-specific lookup
/// loss. It is test support, not another production report mode.
#[cfg(any(test, feature = "testing"))]
pub(super) fn report_without_lookup_list_loss(
    inputs: &NumericalInputs,
    lookup_bits: u64,
) -> ProvenSecurityReport {
    resolved_report(inputs, lookup_bits, false)
}

fn resolved_report(
    inputs: &NumericalInputs,
    lookup_bits: u64,
    scale_lookup: bool,
) -> ProvenSecurityReport {
    let params = &inputs.protocol_params;
    let log_height = inputs.instance_shape.log_max_height as usize;
    let log_blowup = params.log_blowup as usize;
    let log_arity = params.log_folding_arity as usize;
    // Real PCS values establish these conditions. Raw numerical cases can describe impossible
    // shifts/folding schedules; fail closed rather than panic or wrap them into a small domain.
    let Some(lde_log) = log_height.checked_add(log_blowup) else {
        return zero_report();
    };
    if log_arity == 0
        || log_arity >= usize::BITS as usize
        || log_height >= usize::BITS as usize
        || lde_log >= u64::BITS as usize
    {
        return zero_report();
    }
    let num_rounds =
        log_height.saturating_sub(inputs.log_final_degree as usize).div_ceil(log_arity);
    let fri = FriRegime {
        log_blowup,
        num_queries: params.num_queries as usize,
        // Fixed-arity rounds can overshoot the final-degree target. Use the final LDE size
        // after that last partial round, so the FRI formula counts the same folds as the PCS.
        log_final_poly_len: lde_log.saturating_sub(num_rounds * log_arity),
        max_log_arity: if num_rounds == 0 { 0 } else { log_arity },
        commit_pow_bits: params.folding_pow_bits as usize,
        query_pow_bits: params.query_pow_bits as usize,
    };
    let sampling_bits = match inputs.hash_fn {
        HashFunction::Eidos => fixed::to_bits(EIDOS_CHALLENGE_SAMPLE_BITS) - 1,
        _ => fixed::to_bits(inputs.instance_shape.field_bits),
    };
    let shape = InstanceParameters {
        log_trace_length: log_height,
        modulus_bits: sampling_bits as usize,
        collision_resistance: inputs.instance_shape.collision_resistance as usize,
        num_batched_functions: inputs.air_shape.num_deep_terms.unwrap_or(1) as usize,
    };
    let air = AirParameters {
        num_constraints: inputs.air_shape.num_composed_constraints as usize,
        max_constraint_degree: inputs.air_shape.max_constraint_degree as usize,
        num_quotient_chunks: inputs.air_shape.num_quotient_chunks as usize,
        max_combo: inputs.air_shape.max_combo.max(inputs.num_ood_points) as usize,
    };
    let lookup_bits = lookup_bits as f64 / fixed::ONE as f64;
    let lookup = |list_size: f64| {
        let bits = if scale_lookup {
            lookup_bits + ErrorBits::from_prob(list_size).bits()
        } else {
            lookup_bits
        };
        ProvenSecurityTerm::new(LOOKUP_LABEL, ErrorBits::from_log2(bits.max(0.0)))
    };
    let udr = regime_report(
        Regime::UniqueDecoding,
        &fri,
        &air,
        &shape,
        list_size_udr(),
        fri::proven_error_udr(&fri, &air, &shape),
        lookup(list_size_udr()),
        params.ood_pow_bits as usize,
        params.deep_pow_bits as usize,
    );
    let reports = fri::ldr_candidates(&fri, &air, &shape).into_iter().map(|(m, error)| {
        let list_size = list_size_ldr_m(log_blowup, m);
        regime_report(
            Regime::ListDecoding { m },
            &fri,
            &air,
            &shape,
            list_size,
            error,
            lookup(list_size),
            params.ood_pow_bits as usize,
            params.deep_pow_bits as usize,
        )
    });
    // The production candidate search used total_cmp. The prior generic reference selected by
    // partial_cmp with unordered candidates treated as ties; retain that diagnostic behavior too.
    let ldr = if scale_lookup {
        reports.max_by(|a, b| a.security_bits().total_cmp(&b.security_bits()))
    } else {
        reports.max_by(|a, b| {
            a.security_bits().partial_cmp(&b.security_bits()).unwrap_or(Ordering::Equal)
        })
    };
    ProvenSecurityReport { udr, ldr }
}

/// One report in the original ALI, DEEP, FRI, optional batching, lookup, collision order.
#[allow(clippy::too_many_arguments)]
fn regime_report(
    regime: Regime,
    fri: &FriRegime,
    air: &AirParameters,
    shape: &InstanceParameters,
    list_size: f64,
    ldt_error: ErrorBits,
    lookup: ProvenSecurityTerm,
    out_of_domain_grinding: usize,
    batching_grinding: usize,
) -> RegimeReport {
    let ali = composition_error(air.num_constraints, list_size, shape.modulus_bits);
    let deep = boost(deep_ali_error(air, shape, list_size), out_of_domain_grinding);
    let mut terms = Vec::with_capacity(6);
    terms.push(ProvenSecurityTerm::new(ALI_LABEL, ali));
    terms.push(ProvenSecurityTerm::new(DEEP_LABEL, deep));
    terms.push(ProvenSecurityTerm::new(LDT_LABEL, ldt_error));
    if shape.num_batched_functions >= 2 {
        let bits = match regime {
            Regime::ListDecoding { m } => batching_error_ldr_m(
                shape.log_trace_length,
                fri.log_blowup,
                shape.modulus_bits,
                shape.num_batched_functions,
                m,
            ),
            _ => batching_error_udr(
                shape.log_trace_length,
                fri.log_blowup,
                shape.modulus_bits,
                shape.num_batched_functions,
            ),
        };
        terms.push(ProvenSecurityTerm::new(
            BATCH_LABEL,
            boost(ErrorBits::from_log2(bits.max(0.0)), batching_grinding),
        ));
    }
    terms.push(lookup);
    terms.push(ProvenSecurityTerm::new(
        COLLISION_LABEL,
        ErrorBits::from_log2(shape.collision_resistance as f64),
    ));
    RegimeReport::new(regime, terms)
}

/// The exact per-round grinding boost, shared with independent floating-point test references.
pub fn boost(error: ErrorBits, pow_bits: usize) -> ErrorBits {
    ErrorBits::from_log2(error.bits() + pow_bits as f64)
}

pub(super) fn zero_report() -> ProvenSecurityReport {
    let terms = [ALI_LABEL, DEEP_LABEL, LDT_LABEL, LOOKUP_LABEL, COLLISION_LABEL]
        .map(|label| ProvenSecurityTerm::new(label, ErrorBits::from_log2(0.0)));
    ProvenSecurityReport {
        udr: RegimeReport::new(Regime::UniqueDecoding, terms.into()),
        ldr: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trace_length_shift_boundary_is_conservative() {
        let air = AirParameters {
            num_constraints: 1,
            max_constraint_degree: 2,
            num_quotient_chunks: 1,
            max_combo: 2,
        };
        let mut shape = InstanceParameters {
            log_trace_length: 63,
            modulus_bits: 128,
            collision_resistance: 128,
            num_batched_functions: 1,
        };
        let expected = 128.0 - 63.0 - log2(3.0);
        assert!((deep_ali_error(&air, &shape, 1.0).bits() - expected).abs() < 1e-12);
        for log_trace_length in [64, 65, usize::MAX] {
            shape.log_trace_length = log_trace_length;
            assert_eq!(deep_ali_error(&air, &shape, 1.0).bits(), 0.0);
        }
    }
}
