//! Poseidon2 permutation chiplet.
//!
//! Standalone Poseidon2-f[12] permutation exposed over the
//! [`BusId::Poseidon2In`](crate::relations::BusId::Poseidon2In) and
//! [`BusId::Poseidon2Out`](crate::relations::BusId::Poseidon2Out) buses.
//! See [`docs/chiplets/poseidon2.md`](../../../docs/chiplets/poseidon2.md)
//! for the design.

pub mod digest;
pub mod math;
pub mod messages;
pub mod program;
pub mod trace;

use core::array;

pub use digest::{P2Cap, P2Digest};
pub use messages::{
    POSEIDON2_IN_TAG_CAP, POSEIDON2_IN_TAG_RATE0, POSEIDON2_IN_TAG_RATE1, Poseidon2InMsg,
    Poseidon2OutMsg,
};
use miden_core::{
    Felt,
    chiplets::hasher::Hasher,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    transcript::poseidon2::{
        math::{
            STATE_WIDTH, apply_init_plus_ext, apply_internal_plus_ext, apply_packed_internals,
            apply_single_ext,
        },
        program::{
            ARK_INT_LAST_IDX, PCOL_ARK_BEGIN, PCOL_IS_EXT, PCOL_IS_INIT_EXT, PCOL_IS_INT_EXT,
            PCOL_IS_PACKED_INT, poseidon2_program,
        },
    },
    utils::{current_main, next_main},
};

// MAIN COLUMN LAYOUT
// ================================================================================================
//
// 19 main witness columns split into three groups:
//
// - Cycle-constant (4): perm_seq_id, in_multiplicity, out_multiplicity, is_absorb.
// - Sponge state (12):  state[0..12] (rate0[4], rate1[4], capacity[4]).
// - S-box witnesses (3): w[0..3], used on packed-internal rows 4..10 and (`w[0]` only) on int+ext
//   row 11.
//
// See `docs/chiplets/poseidon2.md` §"Per-row format".

/// Cycle-constant permutation identifier (increments by 1 per cycle).
pub const COL_PERM_SEQ_ID: usize = 0;
/// Cycle-constant; number of caller-side consumes of the In-side bus
/// messages (InCap / InRate0 / InRate1) per cycle.
pub const COL_IN_MULTIPLICITY: usize = 1;
/// Cycle-constant; number of caller-side consumes of the Out-side bus
/// message (OutRate0) per cycle. For content-addressed-DAG use cases,
/// this can exceed `in_multiplicity` (each digest is referenced by
/// many parents).
pub const COL_OUT_MULTIPLICITY: usize = 2;
/// Cycle-constant binary chain selector. `is_absorb = 1` ⇒ this cycle
/// inherits its input capacity from the previous cycle's row-15 output
/// capacity (no `InCap` consume from the caller).
pub const COL_IS_ABSORB: usize = 3;
/// First column of the 12-lane Poseidon2 state.
pub const COL_STATE_BEGIN: usize = 4;
/// One past the last state column.
pub const COL_STATE_END: usize = COL_STATE_BEGIN + STATE_WIDTH;
/// First column of the 3 S-box witnesses.
pub const COL_WITNESS_BEGIN: usize = COL_STATE_END;
/// Number of S-box witness columns.
pub const NUM_WITNESSES: usize = 3;
/// One past the last witness column.
pub const COL_WITNESS_END: usize = COL_WITNESS_BEGIN + NUM_WITNESSES;

/// Total number of main witness columns.
pub const NUM_MAIN_COLS: usize = COL_WITNESS_END;

/// First state-lane column in the capacity portion (`state[8..12]`).
pub const COL_CAPACITY_BEGIN: usize = COL_STATE_BEGIN + 8;

// AUX / PUBLIC LAYOUT
// ================================================================================================

/// One aux column hosting all bus emissions in a single group with two
/// periodic-disjoint mutex batches:
/// - Batch A (gated by `is_init_ext`): 3 Poseidon2In provides, fires at row 0 of each cycle.
/// - Batch B (gated by `p_last_in_cycle`): 1 Poseidon2Out provide + 2 Range16 requires (for
///   in_multiplicity and out_multiplicity), fires at row 15 of each cycle.
///
/// Both Range16 requires read the cycle-constant multiplicities (same
/// values at any row); placing them at row 15 balances the mutex
/// batches 3+3 for tighter bus column constraint deg.
///
/// Following [`bitwise64`](crate::primitives::bitwise64) and
/// [`keccak::sponge`](crate::hash::keccak::sponge), col 0 is the running σ
/// and hosts the chiplet's only group.
pub const NUM_AUX_COLS: usize = 1;

/// Per-column emission shape: 4 inserts in the single group
/// (3 in batch A + 1 in batch B; batch B lost its two multiplicity
/// `Range16` requires). The periodic-disjoint mutex (A on row 0, B on
/// row 15) still caps the per-row fraction count at the larger batch.
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [4];

// The single exposed σ ([`NUM_SIGMA_VALUES`]) and the shared
// transcript-root public values ([`NUM_PUBLIC_VALUES`]) follow the
// VM-wide LogUp contract in [`crate::logup`]; the natural last-row
// σ-closing needs no `inv_n`, and this chiplet declares the root but
// does not read it. Combining the two mutex batches into one residue
// is the shared shape, not a Poseidon2-specific choice.

// AIR
// ================================================================================================

/// Poseidon2 permutation chiplet AIR. 16-row period (one cycle = one
/// permutation). Provides chunked permutation tuples on
/// [`Poseidon2In`](crate::relations::BusId::Poseidon2In) and
/// [`Poseidon2Out`](crate::relations::BusId::Poseidon2Out); range-checks
/// `multiplicity` via the existing
/// [`Range16`](crate::relations::BusId::Range16) bus.
#[derive(Debug, Default, Clone, Copy)]
pub struct Poseidon2Air;

impl BaseAir<Felt> for Poseidon2Air {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        poseidon2_program().to_vec()
    }
}

// LIFTED AIR
// ================================================================================================

impl LiftedAir<Felt, QuadFelt> for Poseidon2Air {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
    }

    fn num_aux_values(&self) -> usize {
        NUM_SIGMA_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        trace::build_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        // Phase 1: local row constraints.
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let periodic = builder.periodic_values();
        let is_init_ext: AB::Expr = periodic[PCOL_IS_INIT_EXT].into();
        let is_ext: AB::Expr = periodic[PCOL_IS_EXT].into();
        let is_packed_int: AB::Expr = periodic[PCOL_IS_PACKED_INT].into();
        let is_int_ext: AB::Expr = periodic[PCOL_IS_INT_EXT].into();
        // p_last_in_cycle = 1 - (sum of step selectors); fires on row 15.
        let p_last_in_cycle: AB::Expr = AB::Expr::ONE
            - is_init_ext.clone()
            - is_ext.clone()
            - is_packed_int.clone()
            - is_int_ext.clone();

        // ark[0..12] periodic columns.
        let ark: [AB::Expr; STATE_WIDTH] =
            array::from_fn(|lane| periodic[PCOL_ARK_BEGIN + lane].into());

        // State + witnesses + cycle-constant cols, current and next.
        let state: [AB::Expr; STATE_WIDTH] = array::from_fn(|i| local[COL_STATE_BEGIN + i].into());
        let state_next: [AB::Expr; STATE_WIDTH] =
            array::from_fn(|i| next[COL_STATE_BEGIN + i].into());
        let w: [AB::Expr; NUM_WITNESSES] = array::from_fn(|i| local[COL_WITNESS_BEGIN + i].into());
        let perm_seq_id: AB::Expr = local[COL_PERM_SEQ_ID].into();
        let perm_seq_id_next: AB::Expr = next[COL_PERM_SEQ_ID].into();
        let in_multiplicity: AB::Expr = local[COL_IN_MULTIPLICITY].into();
        let in_multiplicity_next: AB::Expr = next[COL_IN_MULTIPLICITY].into();
        let out_multiplicity: AB::Expr = local[COL_OUT_MULTIPLICITY].into();
        let out_multiplicity_next: AB::Expr = next[COL_OUT_MULTIPLICITY].into();
        let is_absorb: AB::Expr = local[COL_IS_ABSORB].into();
        let is_absorb_next: AB::Expr = next[COL_IS_ABSORB].into();

        // Activity gate for step transitions: any cycle with bus
        // emissions on either side runs the permutation. Prevents the
        // `in_mult = 0, out_mult > 0` fake-digest attack — under this
        // gate, every published digest is a real Poseidon2 output of
        // the prover-committed `state[0..12]` at row 0, so forging a
        // specific target digest requires breaking Poseidon2 preimage
        // resistance.
        let activity: AB::Expr = in_multiplicity.clone() + out_multiplicity.clone();

        // --- Boundary (`when_first_row`) -------------------------------
        builder.when_first_row().assert_zero(perm_seq_id.clone());
        // `is_absorb_0 = 0`: cycle 0 must be a fresh perm (or chain
        // head), never a chain continuation. `perm_seq_id` is *not* a torus
        // (it counts 0, 1, …, N−1 then breaks at the wrap), so a chain
        // that spans the row-(N−1) → row-0 wrap would force the caller
        // to encode perm_seq_ids across the discontinuity — awkward and
        // brittle to trace-size changes. Constraining `is_absorb_0`
        // eliminates the wrap-chain mode entirely.
        builder.when_first_row().assert_zero(is_absorb.clone());

        // --- perm_seq_id chain ---------------------------------------------
        // Cycle-constant within cycles (deg 2).
        builder.assert_zero(
            (AB::Expr::ONE - p_last_in_cycle.clone())
                * (perm_seq_id_next.clone() - perm_seq_id.clone()),
        );
        // Cycle-to-cycle increment (`when_transition`, deg 2).
        builder.when_transition().assert_zero(
            p_last_in_cycle.clone() * (perm_seq_id_next - perm_seq_id - AB::Expr::ONE),
        );

        // --- in_multiplicity / out_multiplicity constancy --------------
        builder.assert_zero(
            (AB::Expr::ONE - p_last_in_cycle.clone()) * (in_multiplicity_next - in_multiplicity),
        );
        builder.assert_zero(
            (AB::Expr::ONE - p_last_in_cycle.clone()) * (out_multiplicity_next - out_multiplicity),
        );

        // --- is_absorb structure --------------------------------------
        builder.assert_bool(local[COL_IS_ABSORB]);
        builder.assert_zero(
            (AB::Expr::ONE - p_last_in_cycle.clone()) * (is_absorb_next.clone() - is_absorb),
        );

        // --- Capacity carry (cycle boundary) --------------------------
        // p_last_in_cycle · is_absorb' · (state'[i] - state[i]) = 0 for
        // capacity lanes i ∈ [8, 12). Deg 3.
        for i in 8..STATE_WIDTH {
            builder.assert_zero(
                p_last_in_cycle.clone()
                    * is_absorb_next.clone()
                    * (state_next[i].clone() - state[i].clone()),
            );
        }

        // --- Poseidon2 step transitions -------------------------------
        // Every step constraint is gated by `multiplicity` as well as
        // its row selector. On padding cycles (mult = 0) the constraints
        // vacuate, freeing the prover to zero-fill rather than evaluate
        // a dummy permutation. Total degree: 1 (mult) + 1 (selector) +
        // 7 (sbox) = 9; log_quotient_degree stays at 3.
        let mat_diag: [AB::Expr; STATE_WIDTH] = array::from_fn(|i| Hasher::MAT_DIAG[i].into());
        let ark_int_last: AB::Expr = Hasher::ARK_INT[ARK_INT_LAST_IDX].into();

        // Init + ext1 (row 0).
        let expected_init_ext = apply_init_plus_ext(&state, &ark);
        for i in 0..STATE_WIDTH {
            builder.assert_zero(
                activity.clone()
                    * is_init_ext.clone()
                    * (state_next[i].clone() - expected_init_ext[i].clone()),
            );
        }

        // Single ext (rows 1-3, 12-14).
        let expected_ext = apply_single_ext(&state, &ark);
        for i in 0..STATE_WIDTH {
            builder.assert_zero(
                activity.clone()
                    * is_ext.clone()
                    * (state_next[i].clone() - expected_ext[i].clone()),
            );
        }

        // Packed 3× internal (rows 4-10): 3 witness checks + next-state.
        let ark_int_3: [AB::Expr; 3] = array::from_fn(|i| ark[i].clone());
        let (expected_packed, packed_checks) =
            apply_packed_internals(&state, &w, &ark_int_3, &mat_diag);
        for check in &packed_checks {
            builder.assert_zero(activity.clone() * is_packed_int.clone() * check.clone());
        }
        for i in 0..STATE_WIDTH {
            builder.assert_zero(
                activity.clone()
                    * is_packed_int.clone()
                    * (state_next[i].clone() - expected_packed[i].clone()),
            );
        }

        // Int + ext merged (row 11): 1 witness check + next-state.
        let (expected_int_ext, int_ext_check) =
            apply_internal_plus_ext(&state, &w[0], ark_int_last, &ark, &mat_diag);
        builder.assert_zero(activity.clone() * is_int_ext.clone() * int_ext_check);
        for i in 0..STATE_WIDTH {
            builder.assert_zero(
                activity.clone()
                    * is_int_ext.clone()
                    * (state_next[i].clone() - expected_int_ext[i].clone()),
            );
        }

        // --- Witness zeroing on non-packed rows ----------------------
        // w[0] is unused on rows that are neither packed-int nor int+ext.
        builder.assert_zero((AB::Expr::ONE - is_packed_int.clone() - is_int_ext) * w[0].clone());
        // w[1], w[2] are unused on rows that are not packed-int.
        for witness in w.iter().skip(1) {
            builder.assert_zero((AB::Expr::ONE - is_packed_int.clone()) * witness.clone());
        }

        // Phase 2: LogUp argument via the LogUp adapter.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for Poseidon2Air
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_AUX_COLS
    }

    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, builder: &mut LB) {
        let local: [LB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let periodic = builder.periodic_values();
        let is_init_ext: LB::Expr = periodic[PCOL_IS_INIT_EXT].into();
        let is_ext: LB::Expr = periodic[PCOL_IS_EXT].into();
        let is_packed_int: LB::Expr = periodic[PCOL_IS_PACKED_INT].into();
        let is_int_ext: LB::Expr = periodic[PCOL_IS_INT_EXT].into();
        let p_last_in_cycle: LB::Expr =
            LB::Expr::ONE - is_init_ext.clone() - is_ext - is_packed_int - is_int_ext;

        let perm_seq_id: LB::Expr = local[COL_PERM_SEQ_ID].into();
        let in_multiplicity: LB::Expr = local[COL_IN_MULTIPLICITY].into();
        let out_multiplicity: LB::Expr = local[COL_OUT_MULTIPLICITY].into();
        let is_absorb: LB::Expr = local[COL_IS_ABSORB].into();
        let is_absorb_next: LB::Expr = next[COL_IS_ABSORB].into();
        let state: [LB::Expr; STATE_WIDTH] = array::from_fn(|i| local[COL_STATE_BEGIN + i].into());

        // Chunks of the input state (rate0, rate1, capacity) at row 0.
        let rate0_chunk: [LB::Expr; 4] = array::from_fn(|i| state[i].clone());
        let rate1_chunk: [LB::Expr; 4] = array::from_fn(|i| state[4 + i].clone());
        let cap_chunk: [LB::Expr; 4] = array::from_fn(|i| state[8 + i].clone());
        // Digest = state[0..4] at row 15.
        let digest: [LB::Expr; 4] = array::from_fn(|i| state[i].clone());

        // Per-batch inner multiplicities (row gate pulled out into the
        // outer batch flag). In-side bus emissions use in_multiplicity;
        // out-side uses out_multiplicity. Both are plain counts pinned
        // to their consumer counts by bus balance — not range-checked.
        let neg_in_mult: LB::Expr = LB::Expr::ZERO - in_multiplicity.clone();
        let neg_in_mult_cap: LB::Expr =
            (LB::Expr::ZERO - in_multiplicity) * (LB::Expr::ONE - is_absorb);
        let neg_out_mult: LB::Expr =
            (LB::Expr::ZERO - out_multiplicity) * (LB::Expr::ONE - is_absorb_next);

        let interaction_deg = Deg { v: 1, u: 1 };
        // Batch A (row 0, gated by `is_init_ext`): 3 Poseidon2In provides.
        //   d_A = 3; max inner mult deg = 2 (in_cap); n_A deg = 2 + 2 = 4.
        let row0_batch_deg = Deg { v: 4, u: 3 };
        // Batch B (row 15, gated by `p_last_in_cycle`): out_rate0 + two
        //   Range16 requires (for in_multiplicity and out_multiplicity).
        //   Both multiplicities are cycle-constant so the row choice is
        //   semantically free; placing both Range16s at row 15 balances
        //   the mutex batches 3+3.
        //   d_B = 3; max inner mult deg = 2 (out_rate0); n_B deg = 2 + 2 = 4.
        let row15_batch_deg = Deg { v: 4, u: 3 };
        // Mutex group: f_A · f_B = is_init_ext · p_last_in_cycle = 0.
        //   u_g = 1 + (d_A − 1)·f_A + (d_B − 1)·f_B → deg max(3+1, 3+1) = 4.
        //   v_g = n_A·f_A + n_B·f_B → deg max(4+1, 4+1) = 5.
        // Column constraint = max(1 + u_g, v_g) = 5. Chiplet log_quot
        // stays at 3 (still dominated by the deg-9 step transitions).
        let group_deg = Deg { v: 5, u: 4 };

        builder.next_column(
            |col| {
                col.group(
                    "poseidon2-bus",
                    |g| {
                        // Batch A: row 0 — 3 Poseidon2In provides.
                        g.batch(
                            "row0",
                            is_init_ext.clone(),
                            |b| {
                                b.insert(
                                    "in_rate0",
                                    neg_in_mult.clone(),
                                    Poseidon2InMsg::rate0(perm_seq_id.clone(), rate0_chunk),
                                    interaction_deg,
                                );
                                b.insert(
                                    "in_rate1",
                                    neg_in_mult,
                                    Poseidon2InMsg::rate1(perm_seq_id.clone(), rate1_chunk),
                                    interaction_deg,
                                );
                                b.insert(
                                    "in_cap",
                                    neg_in_mult_cap,
                                    Poseidon2InMsg::cap(perm_seq_id.clone(), cap_chunk),
                                    interaction_deg,
                                );
                            },
                            row0_batch_deg,
                        );
                        // Batch B: row 15 — the OutRate0 digest provide.
                        // (The multiplicities are no longer range-checked:
                        // each is pinned to its consumer count by bus
                        // balance, so the activity gate `in + out` can't
                        // wrap — see `docs/lookup-argument.md`.)
                        g.batch(
                            "row15",
                            p_last_in_cycle.clone(),
                            |b| {
                                b.insert(
                                    "out_rate0",
                                    neg_out_mult,
                                    Poseidon2OutMsg { perm_seq_id: perm_seq_id.clone(), digest },
                                    interaction_deg,
                                );
                            },
                            row15_batch_deg,
                        );
                    },
                    group_deg,
                );
            },
            group_deg,
        );
    }
}
