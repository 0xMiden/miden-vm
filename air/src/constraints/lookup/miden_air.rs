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
    LookupAir,
    bus_id::NUM_BUS_IDS,
    chiplet_air::{CHIPLET_COLUMN_SHAPE, ChipletLookupAir, ChipletLookupBuilder},
    main_air::{MAIN_COLUMN_SHAPE, MainLookupAir, MainLookupBuilder},
};

// MIDEN LOOKUP AIR
// ================================================================================================

/// Aggregator [`LookupAir`] for the Miden VM's 7-column LogUp argument.
///
/// Zero-sized; `eval` delegates to [`MainLookupAir`] and [`ChipletLookupAir`] in sequence.
/// Consumers that want the full 7-column picture in one `eval` call reach for this type;
/// consumers that want to address the main and chiplet halves independently (e.g. a future
/// enum-dispatch wrapper) reach directly for the two sub-AIRs instead.
///
/// Until Task #8 calls `MidenLookupAir::eval` from `ProcessorAir::eval`, the only live
/// consumers are the degree-budget and cached-encoding equivalence tests at the bottom of
/// this file.
#[derive(Copy, Clone, Debug, Default)]
pub struct MidenLookupAir;

/// Full 7-column fraction stride: main then chiplet, in `eval` order.
pub(crate) const MIDEN_COLUMN_SHAPE: [usize; 7] = [
    MAIN_COLUMN_SHAPE[0],
    MAIN_COLUMN_SHAPE[1],
    MAIN_COLUMN_SHAPE[2],
    MAIN_COLUMN_SHAPE[3],
    CHIPLET_COLUMN_SHAPE[0],
    CHIPLET_COLUMN_SHAPE[1],
    CHIPLET_COLUMN_SHAPE[2],
];

impl<LB> LookupAir<LB> for MidenLookupAir
where
    LB: MainLookupBuilder + ChipletLookupBuilder,
{
    fn num_columns(&self) -> usize {
        // 4 main-trace columns (M1, M_2+5, M3, M4) + 3 chiplet-trace columns
        // (C1, C2, C3) = 7. Hard-coded rather than computed from the sub-AIRs because
        // the sub-AIR methods live behind the `LookupAir<LB>` trait, and resolving `LB`
        // from inside the aggregator's impl would require a turbofish.
        7
    }

    fn column_shape(&self) -> &[usize] {
        &MIDEN_COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        // `HasherMsg::State` holds the widest payload on both sides: label@β⁰, addr@β¹,
        // node_index@β², state[0..12]@β³..β¹⁴ — 15 slots. Every other message stays within
        // 14 slots. Sized at 15 to leave slack-free accommodation for β¹⁴ without
        // over-allocating. Hard-coded for the same reason as `num_columns`.
        15
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        MainLookupAir.eval(builder);
        ChipletLookupAir.eval(builder);
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use std::{println, vec::Vec};

    use miden_core::field::QuadFelt;
    use miden_crypto::stark::air::{
        LiftedAir, RowWindow,
        symbolic::{AirLayout, SymbolicAirBuilder},
    };

    use super::{LookupAir, MidenLookupAir};
    use crate::{
        Felt, NUM_PUBLIC_VALUES, ProcessorAir,
        constraints::lookup::{
            ConstraintLookupBuilder, DualBuilder, GroupMismatch, LookupChallenges,
        },
        trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH},
    };

    /// Maximum allowed constraint degree (transition degree budget).
    const DEGREE_BUDGET: usize = 9;

    type SB = SymbolicAirBuilder<Felt, QuadFelt>;

    fn make_builder() -> SB {
        let num_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len();
        SymbolicAirBuilder::<Felt, QuadFelt>::new(AirLayout {
            preprocessed_width: 0,
            main_width: TRACE_WIDTH,
            num_public_values: NUM_PUBLIC_VALUES,
            permutation_width: AUX_TRACE_WIDTH,
            num_permutation_challenges: AUX_TRACE_RAND_CHALLENGES,
            num_permutation_values: AUX_TRACE_WIDTH,
            num_periodic_columns: num_periodic,
        })
    }

    /// Degree-budget test: exercises every one of the 9 buses that
    /// [`MidenLookupAir::eval`] wires up (M1..M4 + C1..C3, with M1 hosting block-stack +
    /// u32rc + logpre + range-table and C3 hosting ACE wiring + hasher perm-link) and
    /// asserts each extension constraint stays within the budget.
    #[test]
    #[allow(clippy::print_stdout)]
    fn miden_lookup_air_degree_within_budget() {
        let mut builder = make_builder();
        let air = MidenLookupAir;
        {
            let mut lb = ConstraintLookupBuilder::new(&mut builder, &air);
            air.eval(&mut lb);
            // `lb` is dropped here, but the column finalization runs inside
            // `LookupBuilder::column` when its closure returns, not at drop time, so no
            // explicit drop is needed.
        }

        let ext = builder.extension_constraints();
        println!("miden_lookup_air: {} extension constraints", ext.len());
        for (i, c) in ext.iter().enumerate() {
            let deg = c.degree_multiple();
            println!("  LOOKUP[{i}] degree = {deg}");
            assert!(
                deg <= DEGREE_BUDGET,
                "LOOKUP[{i}] degree {deg} exceeds budget {DEGREE_BUDGET}"
            );
        }

        let base = builder.base_constraints();
        println!("miden_lookup_air: {} base constraints", base.len());
        for (i, c) in base.iter().enumerate() {
            let deg = c.degree_multiple();
            assert!(
                deg <= DEGREE_BUDGET,
                "LOOKUP_BASE[{i}] degree {deg} exceeds budget {DEGREE_BUDGET}"
            );
        }
    }

    /// Cached-encoding equivalence test: runs [`MidenLookupAir::eval`] through the
    /// test-only [`DualBuilder`], which executes BOTH closures of every
    /// `group_with_cached_encoding` call and asserts they produce bit-for-bit identical
    /// `(U_g, V_g)` pairs on every random row pair.
    #[test]
    #[allow(clippy::print_stdout)]
    fn miden_lookup_air_cached_encoding_equivalence() {
        /// Small deterministic PRNG. We don't need cryptographic quality — just a stable
        /// stream of bytes we can feed into `prng_value` to get reproducible `Felt`s
        /// across runs.
        struct SeededRng {
            seed: u64,
            counter: u64,
        }

        impl SeededRng {
            fn new(seed: u64) -> Self {
                Self { seed, counter: 0 }
            }

            fn next_felt(&mut self) -> Felt {
                let counter = self.counter;
                self.counter = self.counter.wrapping_add(1);
                let mix = self.seed ^ counter;
                let sum = self.seed.wrapping_add(counter);
                let mut out = [0u8; 32];
                out[0..8].copy_from_slice(&self.seed.to_le_bytes());
                out[8..16].copy_from_slice(&counter.to_le_bytes());
                out[16..24].copy_from_slice(&mix.to_le_bytes());
                out[24..32].copy_from_slice(&sum.to_le_bytes());
                miden_crypto::rand::test_utils::prng_value::<Felt>(out)
            }

            fn next_quad(&mut self) -> QuadFelt {
                QuadFelt::new([self.next_felt(), self.next_felt()])
            }
        }

        let num_periodic = LiftedAir::<Felt, QuadFelt>::periodic_columns(&ProcessorAir).len();
        let air = MidenLookupAir;
        let mut num_rows_checked = 0usize;
        let mut all_mismatches: Vec<(usize, GroupMismatch)> = Vec::new();

        // 100 random row pairs: each iteration runs `MidenLookupAir::eval` through
        // `DualBuilder`, which compares the canonical vs encoded closure of every
        // `group_with_cached_encoding` call.
        const NUM_SAMPLES: usize = 100;
        const SEED: u64 = 0xdead_beef_cafe_f00d;

        let mut rng = SeededRng::new(SEED);

        for sample_idx in 0..NUM_SAMPLES {
            let current_row: Vec<Felt> = (0..TRACE_WIDTH).map(|_| rng.next_felt()).collect();
            let next_row: Vec<Felt> = (0..TRACE_WIDTH).map(|_| rng.next_felt()).collect();
            let periodic_values: Vec<Felt> = (0..num_periodic).map(|_| rng.next_felt()).collect();
            let public_values: Vec<Felt> =
                (0..NUM_PUBLIC_VALUES).map(|_| rng.next_felt()).collect();

            let alpha = rng.next_quad();
            let beta = rng.next_quad();
            let challenges = LookupChallenges::<QuadFelt>::new(alpha, beta);

            let main_window = RowWindow::from_two_rows(&current_row, &next_row);
            let mut mismatches: Vec<GroupMismatch> = Vec::new();
            {
                let mut db = DualBuilder::new(
                    main_window,
                    &periodic_values,
                    &public_values,
                    &challenges,
                    &mut mismatches,
                );
                air.eval(&mut db);
            }
            num_rows_checked += 1;

            for m in mismatches {
                all_mismatches.push((sample_idx, m));
            }
        }

        println!(
            "miden_lookup_air_cached_encoding_equivalence: {} samples, {} mismatches",
            num_rows_checked,
            all_mismatches.len(),
        );
        for (sample_idx, m) in &all_mismatches {
            println!(
                "  sample {sample_idx}: column {} group {} — canonical ({:?}, {:?}) vs encoded ({:?}, {:?})",
                m.column_idx, m.group_idx, m.u_canonical, m.v_canonical, m.u_encoded, m.v_encoded,
            );
        }
        assert!(
            all_mismatches.is_empty(),
            "cached-encoding equivalence failed: {} mismatches",
            all_mismatches.len(),
        );
    }
}
