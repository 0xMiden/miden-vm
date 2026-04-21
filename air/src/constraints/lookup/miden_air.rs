//! Aggregator `LookupAir` for the Miden VM processor.
//!
//! [`MidenLookupAir`] is a thin sequencer over [`super::main_air::MainLookupAir`] (four
//! main-trace columns in the order M1, M_2+5, M3, M4) and
//! [`super::chiplet_air::ChipletLookupAir`] (three chiplet-trace columns in the order
//! C1, C2, C3). The aggregated `eval` preserves the legacy `enforce_main` /
//! `enforce_chiplet` column order so downstream consumers can grab the full 7-column
//! picture in a single call.
//!
//! Task #8 will wire `ProcessorAir::eval` into this `eval` via a
//! `ConstraintLookupBuilder::new(builder, &MidenLookupAir)` call. An alternative
//! future path reaching for `MainLookupAir` and `ChipletLookupAir` independently (e.g. for
//! an enum-dispatch wrapper) is also supported and does not require going through the
//! aggregator.

use alloc::vec::Vec;

use miden_core::{WORD_SIZE, field::PrimeCharacteristicRing};

use super::{
    BusId, MIDEN_MAX_MESSAGE_WIDTH,
    chiplet_air::{CHIPLET_COLUMN_SHAPE, ChipletLookupAir, ChipletLookupBuilder},
    main_air::{MAIN_COLUMN_SHAPE, MainLookupAir, MainLookupBuilder},
    messages::{BlockHashMsg, KernelRomMsg, LogCapacityMsg},
};
use crate::{
    PV_PROGRAM_HASH, PV_TRANSCRIPT_STATE,
    lookup::{BoundaryBuilder, LookupAir},
};

// MIDEN LOOKUP AIR
// ================================================================================================

/// Aggregator [`LookupAir`] for the Miden VM's 7-column LogUp argument.
///
/// Zero-sized; `eval` delegates to `MainLookupAir` and `ChipletLookupAir` in sequence.
/// Consumers that want the full 7-column picture in one `eval` call reach for this type;
/// consumers that want to address the main and chiplet halves independently (e.g. a future
/// enum-dispatch wrapper) reach directly for the two sub-AIRs instead.
///
/// Until Task #8 calls `MidenLookupAir::eval` from `ProcessorAir::eval`, the only live
/// consumers are the degree-budget and cached-encoding equivalence tests at the bottom of
/// this file.
#[derive(Copy, Clone, Debug, Default)]
pub struct MidenLookupAir;

/// Full 7-column fraction stride: 4 main + 3 chiplet, in `eval` order.
pub(crate) const MIDEN_COLUMN_SHAPE: [usize; 7] = [
    MAIN_COLUMN_SHAPE[0],
    MAIN_COLUMN_SHAPE[1],
    MAIN_COLUMN_SHAPE[2],
    MAIN_COLUMN_SHAPE[3],
    CHIPLET_COLUMN_SHAPE[0],
    CHIPLET_COLUMN_SHAPE[1],
    CHIPLET_COLUMN_SHAPE[2],
];

// TODO(#3032): The real committed final count is 1 (col 0 only), but we keep 2 for
// forward-compatibility with the MASM recursive verifier which absorbs 2 boundary
// values. The second value is always ZERO. Reduce to 1 once trace splitting lands.
pub const NUM_LOGUP_COMMITTED_FINALS: usize = 2;

impl<LB> LookupAir<LB> for MidenLookupAir
where
    LB: MainLookupBuilder + ChipletLookupBuilder,
{
    fn num_columns(&self) -> usize {
        7
    }

    fn column_shape(&self) -> &[usize] {
        &MIDEN_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // Width of the `beta_powers` table precomputed by `Challenges::new`, also equal
        // to the exponent of `gamma = beta^MIDEN_MAX_MESSAGE_WIDTH` used in the per-bus
        // prefix. Must match the MASM recursive verifier's Poseidon2 absorption loop.
        // `HasherMsg::State` is the widest live payload at 15 slots (label@β⁰, addr@β¹,
        // node_index@β², state[0..12]@β³..β¹⁴); the 16th slot is unused slack kept for
        // MASM transcript alignment.
        MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        MainLookupAir.eval(builder);
        ChipletLookupAir.eval(builder);
    }

    fn eval_boundary<B>(&self, boundary: &mut B)
    where
        B: BoundaryBuilder<F = LB::F, EF = LB::EF>,
    {
        emit_miden_boundary(boundary);
    }
}

/// Emits the three Miden-AIR boundary correction terms (`c_block_hash`,
/// `c_log_precompile`, `c_kernel_rom`) into any [`BoundaryBuilder`].
///
/// Single source of truth shared between:
/// - [`MidenLookupAir`]'s `LookupAir::eval_boundary` (consumed by the debug walker), and
/// - [`crate::ProcessorAir::reduced_aux_values`] (verifier scalar check; drives the
///   emissions through a reducer that sums `Σ multiplicity / encode(msg)`).
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
    boundary.add("log_precompile_initial", LogCapacityMsg { capacity: [B::F::ZERO; 4] });
    boundary.remove("log_precompile_final", LogCapacityMsg { capacity: final_state });

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

    use super::{MidenLookupAir, NUM_LOGUP_COMMITTED_FINALS};
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
    fn miden_lookup_air_validates() {
        MidenLookupAir
            .validate(validate_layout())
            .unwrap_or_else(|err| panic!("MidenLookupAir validation failed: {err}"));
    }

    /// Smoke test: the trace-balance checker runs to completion on a tiny zero-valued trace
    /// against `MidenLookupAir` without panicking. A zero-valued trace is not a valid program
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

        let _ = check_trace_balance(
            &MidenLookupAir,
            &main_trace,
            &periodic,
            &publics,
            &[],
            &challenges,
        );
    }
}
