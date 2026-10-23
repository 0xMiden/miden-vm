//! Authored public-input binding and external LogUp closure for the VM relation.
//!
//! Every per-AIR slice follows the canonical instance order in [`super::AIRS`]. The caller
//! initializes the challenger with the accepted relation digest before invoking [`observe`].

use alloc::vec::Vec;

use miden_core::{
    WORD_SIZE,
    field::ExtensionField,
    program::{KernelDescriptor, NUM_CLAIM_ELEMENTS},
};
use miden_stark::{
    air::{LiftedAir, ReductionError},
    lookup::Challenges,
};
use p3_challenger::CanObserve;

use super::{
    AIRS, AUX_DEFERRED_ROOT, AUX_KERNEL_DIGESTS, AUX_PROGRAM_HASH, Felt, MidenAir,
    NUM_PUBLIC_VALUES,
    logup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
    trace,
};

/// Maximum number of statement inputs: program hash, deferred root, and kernel procedure digests.
pub fn max_aux_inputs() -> usize {
    // aux_inputs = program hash (1 word) + deferred root (1 word) + the var-len
    // kernel-digest group: one `Word` per kernel procedure, capped at
    // `KernelDescriptor::MAX_NUM_PROCEDURES`.
    AUX_KERNEL_DIGESTS + KernelDescriptor::MAX_NUM_PROCEDURES * WORD_SIZE
}

/// Absorb statement-owned public inputs into the Fiat-Shamir challenger.
///
/// One complete Eidos block: `[CLAIM_HASH (4) | deferred_root (4)]`, where `CLAIM_HASH` is the
/// canonical execution-claim commitment (see `miden_core::program::ExecutionClaim`) over
/// `program_hash ‖ kernel_H ‖ stack_inputs ‖ stack_outputs`. With the relation digest
/// pre-loaded in the challenger by the caller, the transcript state after this block
/// realizes the factored statement binding `H(RELATION_DIGEST ‖ CLAIM_HASH ‖ D)`.
///
/// The kernel digests enter the transcript only through `kernel_H` (see
/// [`hash_kernel_digests`]); the raw stack I/O and digest list remain public values for
/// constraint evaluation and are not separately absorbed.
pub fn observe<C: CanObserve<Felt>>(
    challenger: &mut C,
    air_inputs: &[Vec<Felt>],
    aux_inputs: &[Felt],
    _log_trace_heights: &[u8],
) {
    let core_inputs = &air_inputs[0];
    assert_eq!(core_inputs.len(), NUM_PUBLIC_VALUES, "unexpected public-value count");
    assert!(
        aux_inputs.len() >= AUX_KERNEL_DIGESTS,
        "aux inputs shorter than the fixed program-hash + deferred-root prefix"
    );

    let kernel_h = hash_kernel_digests(&aux_inputs[AUX_KERNEL_DIGESTS..]);
    let program_hash = &aux_inputs[AUX_PROGRAM_HASH..AUX_PROGRAM_HASH + WORD_SIZE];
    let deferred_root = &aux_inputs[AUX_DEFERRED_ROOT..AUX_DEFERRED_ROOT + WORD_SIZE];

    // Canonical claim encoding P ‖ K ‖ I ‖ O; the offset layout of
    // `ExecutionClaim::to_elements`, pinned by `observe_matches_execution_claim_commitment`.
    let mut claim = [Felt::ZERO; NUM_CLAIM_ELEMENTS];
    claim[0..WORD_SIZE].copy_from_slice(program_hash);
    claim[WORD_SIZE..2 * WORD_SIZE].copy_from_slice(&kernel_h);
    claim[2 * WORD_SIZE..].copy_from_slice(core_inputs);
    let claim_hash = miden_core::program::claim_commitment(&claim);

    for &v in claim_hash.as_elements().iter().chain(deferred_root) {
        challenger.observe(v);
    }
}

/// Cross-AIR LogUp closure: each AIR commits `sigma_prime_i = sigma_i / n_i`, so the
/// trace-length-weighted sum `sum_i(n_i * sigma_prime_i)` plus the per-trace boundary
/// corrections must vanish. Boundary corrections are added once and are not trace-length
/// scaled. `aux_values` and `log_trace_heights` are parallel in instance order. `aux_inputs`
/// carries the program hash and deferred root followed by kernel digests.
pub fn eval_external<EF: ExtensionField<Felt>>(
    challenges: &[EF],
    air_inputs: &[Vec<Felt>],
    aux_inputs: &[Felt],
    aux_values: &[&[EF]],
    log_trace_heights: &[u8],
) -> Result<Vec<EF>, ReductionError> {
    if aux_values.len() != AIRS.len() {
        return Err(format!(
            "expected aux values for {} AIRs, got {}",
            AIRS.len(),
            aux_values.len()
        )
        .into());
    }
    if log_trace_heights.len() != AIRS.len() {
        return Err(format!(
            "expected log heights for {} AIRs, got {}",
            AIRS.len(),
            log_trace_heights.len()
        )
        .into());
    }
    if challenges.len() != trace::AUX_TRACE_RAND_CHALLENGES {
        return Err(format!(
            "expected {} aux trace challenges, got {}",
            trace::AUX_TRACE_RAND_CHALLENGES,
            challenges.len()
        )
        .into());
    }
    if air_inputs[0].len() != NUM_PUBLIC_VALUES {
        return Err(format!(
            "expected {NUM_PUBLIC_VALUES} public values, got {}",
            air_inputs[0].len()
        )
        .into());
    }
    if aux_inputs.len() < AUX_KERNEL_DIGESTS {
        return Err(format!(
            "aux_inputs length {} is shorter than the fixed prefix {AUX_KERNEL_DIGESTS}",
            aux_inputs.len()
        )
        .into());
    }
    let max_aux_inputs = max_aux_inputs();
    if aux_inputs.len() > max_aux_inputs {
        return Err(format!(
            "aux_inputs length {} exceeds maximum {max_aux_inputs}",
            aux_inputs.len()
        )
        .into());
    }
    let challenges =
        Challenges::<EF>::new(challenges[0], challenges[1], MIDEN_MAX_MESSAGE_WIDTH, BusId::COUNT);

    let mut weighted_aux_sum = EF::ZERO;
    let mut boundary_correction = EF::ZERO;
    for ((air, values), &log_height) in
        AIRS.iter().copied().zip(aux_values.iter()).zip(log_trace_heights)
    {
        boundary_correction += air.boundary_correction(&challenges, aux_inputs)?;
        let expected = <MidenAir as LiftedAir<Felt, EF>>::num_aux_values(&air);
        if values.len() != expected {
            return Err(format!(
                "{} expects {expected} aux boundary values, got {}",
                air.name(),
                values.len()
            )
            .into());
        }

        let trace_length = 1_u64.checked_shl(u32::from(log_height)).ok_or_else(|| {
            ReductionError::from(format!(
                "{} log trace height {log_height} does not fit in u64",
                air.name()
            ))
        })?;
        weighted_aux_sum += values.iter().copied().sum::<EF>() * Felt::new_unchecked(trace_length);
    }

    Ok(vec![weighted_aux_sum + boundary_correction])
}

// KERNEL DIGEST SUMMARY HASH
// ================================================================================================

/// Computes `kernel_H`, the fixed-size commitment to the kernel-procedure digests.
///
/// This is the canonical [`KernelDescriptor::commitment`] value expressed over the flattened digest
/// felts: the domain-tagged linear hash (`hash_elements_in_domain` with
/// [`miden_core::program::KERNEL_DOMAIN_TAG`]) of `kernel_felts`. The empty digest list yields
/// the canonical empty-input value under the same domain.
///
/// `kernel_H` is absorbed into the Fiat-Shamir transcript in place of the unbounded kernel
/// digest list, committing to the kernel with a fixed-size value.
pub fn hash_kernel_digests(kernel_felts: &[Felt]) -> [Felt; WORD_SIZE] {
    assert!(
        kernel_felts.len().is_multiple_of(WORD_SIZE),
        "kernel digest felts must be whole words"
    );
    assert!(
        kernel_felts.len() <= KernelDescriptor::MAX_NUM_PROCEDURES * WORD_SIZE,
        "kernel digest felts exceed KernelDescriptor::MAX_NUM_PROCEDURES"
    );

    hash_kernel_input_felts(kernel_felts)
}

fn hash_kernel_input_felts(kernel_felts: &[Felt]) -> [Felt; WORD_SIZE] {
    miden_core::chiplets::hasher::hash_elements_in_domain(
        kernel_felts,
        miden_core::program::domain::KERNEL_COMMITMENT,
    )
    .into()
}
