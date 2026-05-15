//! Per-AIR LogUp boundary emitters ([`emit_core_boundary`], [`emit_chiplets_boundary`])
//! plus the committed-finals count for the multi-AIR proof shape.

use alloc::vec::Vec;

use miden_core::{WORD_SIZE, field::PrimeCharacteristicRing};

use super::messages::{BlockHashMsg, KernelRomMsg, LogCapacityMsg};
use crate::{PV_PROGRAM_HASH, PV_TRANSCRIPT_STATE, lookup::BoundaryBuilder};

// COMMITTED-FINALS COUNT
// ================================================================================================

/// Number of committed final aux values in the multi-AIR proof shape: Core final at slot 0
/// and Chiplets final at slot 1.
pub const NUM_LOGUP_COMMITTED_FINALS: usize = 2;

// BOUNDARY EMITTERS
// ================================================================================================

/// Emits the Core-trace boundary corrections.
///
/// Block-hash seed and log-precompile transcript terminals both cancel against bus
/// accumulators on Core columns:
/// - `BlockHashTable` lives on `MAIN_COLUMN_SHAPE[1]` (block_hash + op_group merged column).
/// - `LogPrecompileTranscript` lives on `MAIN_COLUMN_SHAPE[0]` (block_stack + range + log-cap
///   merged column).
///
/// Both fractions therefore belong to `CoreAir::reduced_aux_values` post-split.
pub(crate) fn emit_core_boundary<B: BoundaryBuilder>(boundary: &mut B) {
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

    // Block-hash seed: +1 / encode(BLOCK_HASH_TABLE, [ph, 0, 0, 0]).
    //
    // The boundary correction emits a `Child` payload while the in-trace removal at the
    // root END row (in `block_hash_and_op_group.rs`) emits an `End` payload — the two
    // collapse to the same denominator by the algebra below, so a single `Child` here
    // cancels the root END's `-1/d`:
    //
    //   - At the root END row, the next op is HALT, so the decoder forces `addr_next = 0`, hence
    //     `parent = addr_next = 0`.
    //   - `halt_next() = 1` ⇒ `is_first_child = 1 - end_next - repeat_next - halt_next = 0`.
    //   - The root block is not a loop body, so `is_loop_body = 0`.
    //   - `child_hash = h_0 = program_hash` by the decoder's program-hash boundary.
    //
    // With `is_first_child = 0` and `is_loop_body = 0`, the `End` payload encodes
    // identically to `Child { parent: 0, child_hash: program_hash }`, so the boundary
    // `+1/d` here matches the in-trace `-1/d` and the bus balances.
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
}

/// Emits the Chiplets-trace boundary corrections.
///
/// Kernel ROM init cancels against the kernel-rom bus on `CHIPLET_COLUMN_SHAPE[0]`
/// (chiplet_responses), so the fraction belongs to `ChipletsAir::reduced_aux_values`
/// post-split.
pub(crate) fn emit_chiplets_boundary<B: BoundaryBuilder>(boundary: &mut B) {
    let kernel_digests: Vec<[B::F; 4]> = boundary
        .var_len_public_inputs()
        .first()
        .map(|felts| felts.chunks_exact(WORD_SIZE).map(|d| [d[0], d[1], d[2], d[3]]).collect())
        .unwrap_or_default();

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

    use crate::{
        ChipletsAir, CoreAir, Felt, NUM_PUBLIC_VALUES,
        constraints::{
            columns::{NUM_CHIPLETS_COLS, NUM_CORE_COLS},
            lookup::{
                BusId, MIDEN_MAX_MESSAGE_WIDTH, chiplet_air::CHIPLET_COLUMN_SHAPE,
                main_air::MAIN_COLUMN_SHAPE,
            },
        },
        lookup::{
            Challenges,
            debug::{ValidateLayout, ValidateLookupAir, check_trace_balance},
        },
        trace::AUX_TRACE_RAND_CHALLENGES,
    };

    /// Pin the `BlockHashMsg::End → Child` boundary collapse: at the root END row, the
    /// algebra forces `is_first_child = 0`, `is_loop_body = 0`, `parent = 0`, and
    /// `child_hash = program_hash`, so the in-trace `End` removal encodes identically to
    /// the boundary `Child` seed. If a future change to either side breaks the collapse
    /// (e.g. flips one of those four conditions), the boundary `+1/d` no longer cancels
    /// the in-trace `-1/d` and this test fires.
    #[test]
    fn block_hash_seed_matches_root_end_removal() {
        use crate::{
            constraints::lookup::messages::BlockHashMsg,
            lookup::{Challenges, LookupMessage},
        };

        let challenges = Challenges::<QuadFelt>::new(
            QuadFelt::from_u32(7),
            QuadFelt::from_u32(11),
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let program_hash: [Felt; 4] = [
            Felt::from_u32(101),
            Felt::from_u32(102),
            Felt::from_u32(103),
            Felt::from_u32(104),
        ];

        // Boundary side: emitted by `emit_core_boundary` for the root program hash seed.
        let seed = BlockHashMsg::Child {
            parent: Felt::ZERO,
            child_hash: program_hash,
        };

        // In-trace side: the root END row's removal, with the four conditions documented in
        // `emit_core_boundary` (addr_next=0 via HALT; halt_next=1 ⇒ is_first_child=0; root
        // not a loop ⇒ is_loop_body=0; child_hash = h_0 = program_hash).
        let root_end = BlockHashMsg::End {
            parent: Felt::ZERO,
            child_hash: program_hash,
            is_first_child: Felt::ZERO,
            is_loop_body: Felt::ZERO,
        };

        assert_eq!(
            <BlockHashMsg<Felt> as LookupMessage<Felt, QuadFelt>>::encode(&seed, &challenges),
            <BlockHashMsg<Felt> as LookupMessage<Felt, QuadFelt>>::encode(&root_end, &challenges),
            "boundary `Child` seed and root-END `End` removal must encode to equal denominators"
        );
    }

    /// Lookup-structure validation for `CoreAir` — the standalone Core-half AIR used by the
    /// multi-AIR proving path.
    #[test]
    fn core_air_lookup_validates() {
        let layout = ValidateLayout {
            trace_width: NUM_CORE_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            // Core has no periodic columns (all serve the chiplets).
            num_periodic_columns: 0,
            permutation_width: MAIN_COLUMN_SHAPE.len(),
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: 1,
        };
        ValidateLookupAir::validate(&CoreAir, layout)
            .unwrap_or_else(|err| panic!("CoreAir LookupAir validation failed: {err}"));
    }

    /// Lookup-structure validation for `ChipletsAir` — the standalone Chiplets-half AIR.
    /// Symmetric to `core_air_lookup_validates`: 21-col main trace, 3 LogUp accumulator
    /// columns, 1 committed final, all periodic columns owned here.
    #[test]
    fn chiplets_air_lookup_validates() {
        let num_periodic = ChipletsAir.periodic_columns().len();
        let layout = ValidateLayout {
            trace_width: NUM_CHIPLETS_COLS,
            num_public_values: NUM_PUBLIC_VALUES,
            num_periodic_columns: num_periodic,
            permutation_width: CHIPLET_COLUMN_SHAPE.len(),
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: 1,
        };
        ValidateLookupAir::validate(&ChipletsAir, layout)
            .unwrap_or_else(|err| panic!("ChipletsAir LookupAir validation failed: {err}"));
    }

    /// Smoke test: the trace-balance checker runs to completion on a tiny zero-valued
    /// Core trace without panicking. A zero-valued trace is not a valid program execution
    /// so the report is expected to contain unmatched entries; this test only asserts that
    /// the checker produces a report (instead of crashing).
    #[test]
    fn trace_balance_runs_on_zero_trace() {
        const NUM_ROWS: usize = 4;
        // CoreAir has no periodic columns.
        let data = vec![Felt::ZERO; NUM_CORE_COLS * NUM_ROWS];
        let main_trace = RowMajorMatrix::new(data, NUM_CORE_COLS);
        let periodic: Vec<Vec<Felt>> = Vec::new();
        let publics: Vec<Felt> = vec![Felt::ZERO; NUM_PUBLIC_VALUES];
        let challenges = Challenges::<QuadFelt>::new(
            QuadFelt::ONE,
            QuadFelt::ONE,
            MIDEN_MAX_MESSAGE_WIDTH,
            BusId::COUNT,
        );

        let _ = check_trace_balance(&CoreAir, &main_trace, &periodic, &publics, &[], &challenges);
    }
}
