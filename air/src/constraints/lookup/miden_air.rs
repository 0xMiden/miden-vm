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

use super::{
    BusId, MIDEN_MAX_MESSAGE_WIDTH,
    chiplet_air::{CHIPLET_COLUMN_SHAPE, ChipletLookupAir, ChipletLookupBuilder},
    main_air::{MAIN_COLUMN_SHAPE, MainLookupAir, MainLookupBuilder},
};
use crate::lookup::LookupAir;

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

/// Indices of running-sum columns: column 0 for main-trace, column 4 for chiplets.
const RUNNING_SUM_COLUMNS: [usize; 2] = [0, 4];

/// Fraction columns accumulated by each running-sum column.
const MAIN_FRACTION_COLS: [usize; 3] = [1, 2, 3];
const CHIPLET_FRACTION_COLS: [usize; 2] = [5, 6];

/// Number of committed final values.
///
/// NOTE: while the internal LogUp accumulation currently uses two running-sum columns
/// (main/chiplet split), we commit only a **single** boundary element for now. This keeps the
/// proof shape aligned with a single-trace setup until the planned dual-trace migration lands.
pub const NUM_LOGUP_COMMITTED_FINALS: usize = 1;

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
        crate::constraints::logup_msg::MIDEN_MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        BusId::COUNT
    }

    fn eval(&self, builder: &mut LB) {
        MainLookupAir.eval(builder);
        ChipletLookupAir.eval(builder);
    }

    fn running_sum_columns(&self) -> &[usize] {
        &RUNNING_SUM_COLUMNS
    }

    fn fraction_columns_for(&self, running_sum_col: usize) -> &[usize] {
        match running_sum_col {
            0 => &MAIN_FRACTION_COLS,
            4 => &CHIPLET_FRACTION_COLS,
            _ => panic!("column {running_sum_col} is not a running-sum column"),
        }
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use std::{fmt::Write as _, println, string::String, vec, vec::Vec};

    use miden_core::{
        field::{PrimeCharacteristicRing, QuadFelt},
        utils::RowMajorMatrix,
    };
    use miden_crypto::{
        rand::random_felt,
        stark::air::{LiftedAir, symbolic::AirLayout},
    };

    use super::{MidenLookupAir, NUM_LOGUP_COMMITTED_FINALS};
    use crate::{
        Felt, NUM_PUBLIC_VALUES, ProcessorAir,
        constraints::lookup::{BusId, MIDEN_MAX_MESSAGE_WIDTH},
        lookup::{
            Challenges,
            debug::{
                check_challenge_scoping, check_encoding_equivalence, check_symbolic_degrees,
                check_trace_balance, collect_inventory,
            },
        },
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
    };

    /// Transition-constraint degree budget enforced on the Miden AIR.
    const DEGREE_BUDGET: usize = 9;

    fn num_periodic() -> usize {
        LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len()
    }

    fn miden_air_layout() -> AirLayout {
        AirLayout {
            preprocessed_width: 0,
            main_width: TRACE_WIDTH,
            num_public_values: NUM_PUBLIC_VALUES,
            permutation_width: AUX_TRACE_WIDTH,
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: NUM_LOGUP_COMMITTED_FINALS,
            num_periodic_columns: num_periodic(),
        }
    }

    /// Exercises every one of the 9 buses `MidenLookupAir::eval` wires up and asserts each
    /// emitted constraint stays within the transition degree budget.
    #[test]
    #[allow(clippy::print_stdout)]
    fn miden_lookup_air_degree_within_budget() {
        let report = check_symbolic_degrees(&MidenLookupAir, miden_air_layout(), DEGREE_BUDGET)
            .unwrap_or_else(|r| {
                panic!(
                    "symbolic degree pass failed: {} mismatches\n{:#?}",
                    r.mismatches.len(),
                    r.mismatches,
                )
            });
        // Both constraint families should have at least one constraint each.
        assert!(report.info.iter().any(|i: &String| i.contains("extension constraints")));
        assert!(report.info.iter().any(|i: &String| i.contains("base constraints")));
        for line in &report.info {
            println!("{line}");
        }
    }

    /// Cached-encoding equivalence check: subsumed by
    /// [`check_encoding_equivalence`](crate::lookup::debug::check_encoding_equivalence).
    /// Runs `MidenLookupAir::eval` through the canonical-vs-encoded equivalence checker on
    /// a batch of random row pairs.
    #[test]
    fn miden_lookup_air_cached_encoding_equivalence() {
        const NUM_SAMPLES: usize = 100;
        for _ in 0..NUM_SAMPLES {
            let current_row: Vec<Felt> = (0..TRACE_WIDTH).map(|_| random_felt()).collect();
            let next_row: Vec<Felt> = (0..TRACE_WIDTH).map(|_| random_felt()).collect();
            let periodic_values: Vec<Felt> = (0..num_periodic()).map(|_| random_felt()).collect();
            let public_values: Vec<Felt> = (0..NUM_PUBLIC_VALUES).map(|_| random_felt()).collect();
            let challenges = Challenges::<QuadFelt>::new(
                QuadFelt::new([random_felt(), random_felt()]),
                QuadFelt::new([random_felt(), random_felt()]),
                MIDEN_MAX_MESSAGE_WIDTH,
                BusId::COUNT,
            );

            let mismatches = check_encoding_equivalence(
                &MidenLookupAir,
                &current_row,
                &next_row,
                &periodic_values,
                &public_values,
                &challenges,
            );
            assert!(mismatches.is_empty(), "cached-encoding equivalence failed: {mismatches:#?}",);
        }
    }

    /// Inventory walk should cover every declared column with at least one group and
    /// report a floor of interactions. Exact counts are brittle (depend on every bus's
    /// structure) so we only assert generous lower bounds.
    #[test]
    fn inventory_is_non_empty() {
        let inv = collect_inventory(
            &MidenLookupAir,
            "MidenLookupAir",
            TRACE_WIDTH,
            num_periodic(),
            NUM_PUBLIC_VALUES,
        );
        assert_eq!(inv.air_name, "MidenLookupAir");
        assert_eq!(inv.columns.len(), 7);
        let groupy = inv.columns.iter().filter(|c| !c.groups.is_empty()).count();
        assert!(
            groupy == 7,
            "expected 7 non-empty columns, got {groupy}: {:#?}",
            inv.columns.iter().map(|c| c.groups.len()).collect::<Vec<_>>(),
        );
        let total = inv.total_interactions();
        assert!(total >= 20, "expected ≥20 interactions, got {total}");
    }

    #[test]
    fn inventory_display_prints_columns() {
        let inv = collect_inventory(
            &MidenLookupAir,
            "MidenLookupAir",
            TRACE_WIDTH,
            num_periodic(),
            NUM_PUBLIC_VALUES,
        );
        let mut out = String::new();
        write!(&mut out, "{inv}").unwrap();
        assert!(out.contains("MidenLookupAir"), "display should contain air name");
        assert!(out.contains("column["), "display should enumerate columns");
    }

    #[test]
    fn scope_check_accepts_current_air() {
        check_challenge_scoping(
            &MidenLookupAir,
            "MidenLookupAir",
            TRACE_WIDTH,
            num_periodic(),
            NUM_PUBLIC_VALUES,
        )
        .expect("MidenLookupAir must not leak manual challenges into simple groups");
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

        let _ = check_trace_balance(&MidenLookupAir, &main_trace, &periodic, &publics, &challenges);
    }
}
