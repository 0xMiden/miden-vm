//! Miden-specific LogUp pieces consumed by `ProcessorAir`'s trait impls: the combined
//! 7-column fraction stride, the committed-finals count, and the
//! [`emit_miden_boundary`] helper.
//!
//! The `LookupAir` and `AuxBuilder` trait impls themselves live on [`crate::ProcessorAir`]
//! in `air/src/lib.rs`; this module just supplies the constants and the boundary emitter
//! they share.

use alloc::vec::Vec;

use miden_core::{WORD_SIZE, field::PrimeCharacteristicRing};

use super::{
    chiplet_air::CHIPLET_COLUMN_SHAPE,
    main_air::MAIN_COLUMN_SHAPE,
    messages::{BlockHashMsg, KernelRomMsg, LogCapacityMsg},
};
use crate::lookup::BoundaryBuilder;

// COLUMN SHAPE AND COMMITTED-FINALS COUNT
// ================================================================================================

/// Full 7-column fraction stride: 4 main + 3 chiplet, in `ProcessorAir::eval` order (main
/// columns first, then chiplet columns — see the per-half docs in
/// [`super::main_air::MainLookupAir`] and [`super::chiplet_air::ChipletLookupAir`]).
pub(crate) const MIDEN_COLUMN_SHAPE: [usize; 7] = [
    MAIN_COLUMN_SHAPE[0],
    MAIN_COLUMN_SHAPE[1],
    MAIN_COLUMN_SHAPE[2],
    MAIN_COLUMN_SHAPE[3],
    CHIPLET_COLUMN_SHAPE[0],
    CHIPLET_COLUMN_SHAPE[1],
    CHIPLET_COLUMN_SHAPE[2],
];

/// Number of committed final aux values published with a proof.
///
/// Only col 0 is a real committed final; slot 1 is a placeholder forced to zero, kept for
/// forward-compatibility with the MASM recursive verifier (which absorbs 2 boundary
/// values). All paths that emit or consume the pair must preserve the zero in slot 1.
///
/// TODO(#3032): reduce to 1 once trace splitting lands and each sub-trace has its own
/// accumulator.
pub const NUM_LOGUP_COMMITTED_FINALS: usize = 2;

// BOUNDARY EMITTER
// ================================================================================================

/// Emits the three Miden-AIR boundary correction terms (`c_block_hash`,
/// `c_log_precompile`, `c_kernel_rom`) into any [`BoundaryBuilder`].
///
/// Single source of truth shared between:
/// - [`crate::ProcessorAir`]'s `LookupAir::eval_boundary` (consumed by the debug walker), and
/// - [`crate::ProcessorAir::reduced_aux_values`] (verifier scalar check; drives the emissions
///   through a reducer that sums `Σ multiplicity / encode(msg)`).
///
/// See `program_hash_message`, `transcript_messages`, and `kernel_proc_message` in
/// `air/src/lib.rs` for the canonical formulas this mirrors.
pub(crate) fn emit_miden_boundary<B: BoundaryBuilder>(boundary: &mut B) {
    // Snapshot the needed VLPI data up front so the mutable `boundary.add/remove`
    // calls below don't conflict with the immutable borrow taken by
    // `var_len_public_inputs()`. Slot layout (see `PublicInputs::to_air_inputs`):
    //   VLPI[0] = [program_hash]              (length 1, width WORD_SIZE)
    //   VLPI[1] = [pc_transcript_state_final] (length 1, width WORD_SIZE)
    //   VLPI[2] = [kernel_digest_0, ...]      (length N, width WORD_SIZE)
    let [program_hash_slice, transcript_slice, kernel_slice]: [&[B::F]; 3] = boundary
        .var_len_public_inputs()
        .try_into()
        .expect("ProcessorAir requires exactly 3 VLPI slots");
    let program_hash: [B::F; 4] = program_hash_slice
        .try_into()
        .expect("VLPI[0] must hold exactly one program-hash digest");
    let final_state: [B::F; 4] = transcript_slice
        .try_into()
        .expect("VLPI[1] must hold exactly one pc-transcript-state digest");
    let kernel_digests: Vec<[B::F; 4]> =
        kernel_slice.chunks_exact(WORD_SIZE).map(|d| [d[0], d[1], d[2], d[3]]).collect();

    // Block-hash seed: +1 / encode(BLOCK_HASH_TABLE, [ph, 0, 0, 0]).
    boundary.add(
        "block_hash_seed",
        BlockHashMsg::Child {
            parent: B::F::ZERO,
            child_hash: program_hash,
        },
    );

    // Log-precompile transcript terminals: +1 / d_initial − 1 / d_final.
    boundary.add("log_precompile_initial", LogCapacityMsg { capacity: [B::F::ZERO; 4] });
    boundary.remove("log_precompile_final", LogCapacityMsg { capacity: final_state });

    // Kernel ROM init: +Σ 1 / d_kernel_proc_msg_i over VLPI[2].
    for digest in kernel_digests {
        boundary.add("kernel_rom_init", KernelRomMsg::init(digest));
    }
}

// TESTS
// ================================================================================================

#[cfg(all(test, feature = "std"))]
mod tests {
    extern crate std;

    use std::{vec, vec::Vec};

    use miden_core::{
        WORD_SIZE,
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_crypto::stark::air::LiftedAir;

    use super::NUM_LOGUP_COMMITTED_FINALS;
    use crate::{
        Felt, NUM_PUBLIC_VALUES, ProcessorAir,
        constraints::lookup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
        lookup::{
            Challenges,
            debug::{ValidateLayout, ValidateLookupAir, check_trace_balance},
        },
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
    };

    fn num_periodic() -> usize {
        LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len()
    }

    fn validate_layout() -> ValidateLayout {
        ValidateLayout {
            trace_width: TRACE_WIDTH,
            num_public_values: NUM_PUBLIC_VALUES,
            num_periodic_columns: num_periodic(),
            permutation_width: AUX_TRACE_WIDTH,
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: NUM_LOGUP_COMMITTED_FINALS,
        }
    }

    /// One self-check that covers num_columns consistency, per-group / per-column
    /// declared-vs-observed degree, cached-encoding canonical/encoded equivalence,
    /// and simple-group scope (no `insert_encoded` outside cached-encoding groups).
    #[test]
    fn processor_air_lookup_validates() {
        ValidateLookupAir::validate(&ProcessorAir, validate_layout())
            .unwrap_or_else(|err| panic!("ProcessorAir LookupAir validation failed: {err}"));
    }

    /// Smoke test: the trace-balance checker runs to completion on a tiny zero-valued trace
    /// against `ProcessorAir` without panicking. A zero-valued trace is not a valid program
    /// execution so the report is expected to contain unmatched entries; this test only
    /// asserts that the checker produces a report (instead of crashing).
    #[test]
    fn trace_balance_runs_on_zero_trace() {
        const NUM_ROWS: usize = 4;
        let data = vec![Felt::ZERO; TRACE_WIDTH * NUM_ROWS];
        let main_trace = RowMajorMatrix::new(data, TRACE_WIDTH);
        let periodic: Vec<Vec<Felt>> =
            (0..num_periodic()).map(|_| vec![Felt::ZERO; NUM_ROWS]).collect();
        let publics: Vec<Felt> = vec![Felt::ZERO; NUM_PUBLIC_VALUES];
        let challenges = Challenges::<QuadFelt>::new(
            QuadFelt::ONE,
            QuadFelt::ONE,
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        // ProcessorAir requires exactly 3 VLPI slots (program_hash, transcript_state, kernel
        // digests). On a zero trace the kernel slice is empty.
        let zero_word = [Felt::ZERO; WORD_SIZE];
        let vlpi: [&[Felt]; 3] = [&zero_word, &zero_word, &[]];
        let _ = check_trace_balance(
            &ProcessorAir,
            &main_trace,
            &periodic,
            &publics,
            &vlpi,
            &challenges,
        );
    }
}
