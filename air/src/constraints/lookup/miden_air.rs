//! Concrete `LookupAir` for the Miden VM processor.
//!
//! All 8 buses (M1..M5, C1..C3) are wired through the new API in the M1..M5, C1..C3 order
//! that matches the legacy `enforce_main` / `enforce_chiplet` layout. Task #8 will wire
//! `ProcessorAir::eval` into this `eval` via a
//! `ConstraintLookupBuilder::new(builder, &MidenLookupAir)` call.
//!
//! Each per-bus emitter lives in [`super::buses`] as a module-private
//! `pub(super) fn emit_*` so the top-level file stays a thin routing layer. See the
//! individual `buses/*.rs` files for the per-bus algebra.

use core::borrow::Borrow;

use miden_crypto::stark::air::WindowAccess;

use super::{
    LookupAir, LookupBuilder,
    bus_id::NUM_BUS_IDS,
    buses::{
        block_hash_and_op_group::emit_block_hash_and_op_group,
        block_stack::emit_block_stack_and_range_table, chiplet_requests::emit_chiplet_requests,
        chiplet_responses::emit_chiplet_responses, hash_kernel::emit_hash_kernel_table,
        range_logcap::emit_range_stack_and_log_capacity, wiring::emit_ace_wiring,
    },
};
use crate::{Felt, MainCols};

// MIDEN LOOKUP AIR
// ================================================================================================

/// The Miden VM's LogUp lookup argument.
///
/// Zero-sized. A single blanket
/// `impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for MidenLookupAir`
/// serves both the constraint-path
/// [`ConstraintLookupBuilder`](super::constraint::ConstraintLookupBuilder) and
/// the prover-path [`ProverLookupBuilder`](super::prover::ProverLookupBuilder) —
/// the adapter passes `&self` to its constructor, which uses the
/// `A: LookupAir<Self>` bound in §A.6 of the plan to pin the `LB` type parameter
/// to the concrete adapter.
///
/// Task #7 wires all 8 buses (M1..M5, C1..C3) through the new API. Until Task #8
/// calls `MidenLookupAir::eval` from `ProcessorAir::eval`, the struct has no
/// live consumer in `ProcessorAir`, but the comprehensive degree-budget test
/// `miden_lookup_air_degree_within_budget` and the adapter chain around
/// [`ConstraintLookupBuilder`](super::constraint::ConstraintLookupBuilder)
/// exercise it.
#[derive(Copy, Clone, Debug, Default)]
pub struct MidenLookupAir;

impl<LB> LookupAir<LB> for MidenLookupAir
where
    LB: LookupBuilder<F = Felt>,
    // Row access: the two main-trace rows get reinterpreted as `MainCols<LB::Var>` via
    // the blanket `Borrow<MainCols<T>> for [T]` impl in `constraints::columns`.
    [LB::Var]: Borrow<MainCols<LB::Var>>,
{
    fn num_columns(&self) -> usize {
        // M1 (block-stack + range-table response), M_2+5 (block-hash queue ∪ op-group table,
        // merged via ME), M3 (chiplet requests), M4 (range-stack + logpre capacity), plus
        // C1..C3. 4 main + 3 chiplet = 7 columns.
        7
    }

    fn max_message_width(&self) -> usize {
        // `HasherMsg::State` holds the widest payload: label@β⁰, addr@β¹, node_index@β²,
        // and state[0..12]@β³..β¹⁴, i.e. 15 slots. Every other message stays within 14 slots
        // (the widest non-state chiplet message is `HasherMsg::Rate` at 11). Sized at 15 to
        // leave slack-free accommodation for β¹⁴ without over-allocating.
        15
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        // Hold the MainWindow as an owned value so its borrow of the underlying builder is
        // released before we grab the per-column handle. `SymbolicAirBuilder::main` returns
        // `RowMajorMatrix<Var>` by clone, and the lifted-stark prover-side `RowWindow` is
        // `Copy`, so both cases survive the by-value return without extra allocations.
        let main = builder.main();
        let local: &MainCols<LB::Var> = main.current_slice().borrow();
        let next: &MainCols<LB::Var> = main.next_slice().borrow();

        // Main-trace LogUp columns.
        //
        //   M1     = block-stack + range-table response
        //   M_2+5  = block-hash queue ∪ op-group table (merged via the ME
        //            observation that control-flow opcodes are never in-span)
        //   M3     = chiplet requests
        //   M4     = range-stack + logpre capacity
        emit_block_stack_and_range_table::<LB>(builder, local, next);
        emit_block_hash_and_op_group::<LB>(builder, local, next);
        emit_chiplet_requests::<LB>(builder, local, next);
        emit_range_stack_and_log_capacity::<LB>(builder, local, next);

        // Chiplet-trace LogUp columns (C1..C3) — order matches the legacy `enforce_chiplet`.
        emit_chiplet_responses::<LB>(builder, local, next);
        emit_hash_kernel_table::<LB>(builder, local, next);
        emit_ace_wiring::<LB>(builder, local, next);
    }
}

// TESTS
// ================================================================================================

#[cfg(test)]
mod tests {
    extern crate std;

    use std::{borrow::Borrow, println, vec::Vec};

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

    /// Degree-budget test: exercises every one of the 8 buses that
    /// [`MidenLookupAir::eval`] wires up (M1..M5, C1..C3) and asserts each extension
    /// constraint stays within the budget.
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
