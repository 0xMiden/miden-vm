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
    messages::{BlockHashMsg, KernelRomMsg, LogStateMsg},
};
use crate::{PV_PROGRAM_HASH, PV_TRANSCRIPT_STATE, lookup::BoundaryBuilder};

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
    // Snapshot the needed public-input data up front so the mutable
    // `boundary.add/remove` calls below don't conflict with the immutable
    // borrows taken by `public_values()` / `var_len_public_inputs()`.
    let pv = boundary.public_values();
    let program_hash: [B::F; 4] = [
        pv[PV_PROGRAM_HASH],
        pv[PV_PROGRAM_HASH + 1],
        pv[PV_PROGRAM_HASH + 2],
        pv[PV_PROGRAM_HASH + 3],
    ];
    let final_state: [B::F; 4] = [
        pv[PV_TRANSCRIPT_STATE],
        pv[PV_TRANSCRIPT_STATE + 1],
        pv[PV_TRANSCRIPT_STATE + 2],
        pv[PV_TRANSCRIPT_STATE + 3],
    ];
    let kernel_digests: Vec<[B::F; 4]> = boundary
        .var_len_public_inputs()
        .first()
        .map(|felts| felts.chunks_exact(WORD_SIZE).map(|d| [d[0], d[1], d[2], d[3]]).collect())
        .unwrap_or_default();

    // Block-hash seed: +1 / encode(BLOCK_HASH_TABLE, [ph, 0, 0, 0]).
    boundary.add(
        "block_hash_seed",
        BlockHashMsg::Child {
            parent: B::F::ZERO,
            child_hash: program_hash,
        },
    );

    // Log-precompile transcript terminals: +1 / d_initial − 1 / d_final.
    boundary.add("log_precompile_initial", LogStateMsg { state: [B::F::ZERO; 4] });
    boundary.remove("log_precompile_final", LogStateMsg { state: final_state });

    // Kernel ROM init: +Σ 1 / d_kernel_proc_msg_i over VLPI[0].
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

        let _ =
            check_trace_balance(&ProcessorAir, &main_trace, &periodic, &publics, &[], &challenges);
    }
}
