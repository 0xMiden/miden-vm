//! EcGroups chiplet — the short-Weierstrass **group table**.
//!
//! One row per group, binding the curve context a consumer resolves
//! through one ptr: `group_ptr → (a_ptr, b_ptr, bound_ptr,
//! scalar_bound_ptr)` — the curve params `a`, `b`, the base-field
//! modulus handle (`bound`, fixing `F_p`), and the **scalar-field
//! modulus handle** (`scalar_bound`, fixing `F_s` — the group order's
//! `n − 1`, the modulus future scalar arithmetic
//! (nondeterministic-addition-chain constraints, ladder exponents) runs
//! under). Mathematically `(a, b, p)` determines `F_s`, but the chiplet
//! never computes it: the session records `F_s` when something
//! *constrains* it, and while nothing does, the cell **vacuously
//! defaults to the `F_p` handle** — a well-formed stored uint, consumed
//! by nothing scalar, so the tuple stays total without a none-sentinel
//! special case.
//!
//! The split from the point store keeps each store single-role: no
//! `is_group` mutex, no dead point cells on group rows, and the group
//! table is the natural anchor for future group-scoped data (generator
//! pins, cofactor policy) — extend the tuple here and no point widens.
//!
//! Ptr discipline is the stores' taken to its limit: this chiplet has
//! **no consume fractions** (the one provide self-gates through its
//! `mult` cell, zero on pads), so nothing needs an `act` gate — and
//! with nothing to gate, the ptr chain goes **ungated**:
//! `ptr' = ptr + 1` on every transition, `ptr = 1` on the first row.
//! `ptr = row + 1` is then forced for any prover — pads included, which
//! are simply rows with `mult = 0` — so ptr → tuple is injective by
//! construction, with no booleanity, no monotonicity, no flag column.
//! Tracegen preseeds VM-owned fixed curve slots from `CurveId::ALL` (K1 row 1,
//! R1 row 2, Ed25519 row 3 today).
//! Everything else about a group — `b ≠ 0`, the params being uints
//! under `bound` — is certified at the require layer and transitively
//! by consumers (membership MACs route `a` / `b` through the mul
//! chiplet's views).

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_lifted_air::{AirBuilder, BaseAir, LiftedAir, LiftedAirBuilder};
use p3_matrix::dense::RowMajorMatrix;

use crate::{
    ec::EcGroupMsg,
    logup::{
        CyclicConstraintLookupBuilder, Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn,
        LookupGroup, NUM_PUBLIC_VALUES, NUM_RANDOMNESS, NUM_SIGMA_VALUES,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

// COLUMN LAYOUT
// ================================================================================================

/// Group ptr (allocator-consecutive from 1; 0 is the none-sentinel).
pub const COL_PTR: usize = 0;
/// Curve `a`'s uint ptr.
pub const COL_A_PTR: usize = 1;
/// Curve `b`'s uint ptr (`b ≠ 0` — the EcCreate guard).
pub const COL_B_PTR: usize = 2;
/// The base-field modulus ptr (fixes `F_p`).
pub const COL_BOUND_PTR: usize = 3;
/// The scalar-field modulus ptr (fixes `F_s`); = `bound_ptr` while no
/// scalar arithmetic constrains it.
pub const COL_SBOUND_PTR: usize = 4;
/// `EcGroup` provide multiplicity (= consumer count: every point of the
/// group + every live-case add op); 0 on pad rows — the only liveness
/// signal this chiplet needs.
pub const COL_MULT: usize = 5;
pub const NUM_MAIN_COLS: usize = 6;

// Aux: the single LogUp running-sum column (one fraction).
const NUM_LOGUP_COLS: usize = 1;
const AUX_WIDTH: usize = 1;
const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1];

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct EcGroupsAir;

impl BaseAir<Felt> for EcGroupsAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for EcGroupsAir {
    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        AUX_WIDTH
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
        crate::ec::trace::build_groups_aux(main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);

        let ptr: AB::Expr = local[COL_PTR].into();
        let ptr_next: AB::Expr = next[COL_PTR].into();

        // The ungated chain: ptr = row + 1 for every prover, pads
        // included (they are just mult = 0 rows), so ptr → tuple is
        // injective by construction. The wrap edge is dropped, keeping
        // the cyclic last → first transition free.
        builder.when_transition().assert_zero(ptr_next - ptr.clone() - AB::Expr::ONE);
        builder.when_first_row().assert_zero(ptr - AB::Expr::ONE);

        // Phase 2: LogUp.
        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for EcGroupsAir
where
    LB: LookupBuilder<F = Felt>,
{
    fn num_columns(&self) -> usize {
        NUM_LOGUP_COLS
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

        // Pads zero the mult cell, so the provide needs no act gate.
        let neg_mult: LB::Expr = LB::Expr::ZERO - local[COL_MULT].into();

        let provide_deg = Deg { v: 1, u: 1 };
        let col_deg = Deg { v: 1, u: 1 };

        builder.next_column(
            |col| {
                col.group(
                    "ec-groups",
                    |g| {
                        g.batch(
                            "ec-groups-fractions",
                            LB::Expr::ONE,
                            |b| {
                                b.insert(
                                    "provide-ecgroup",
                                    neg_mult,
                                    EcGroupMsg {
                                        group_ptr: local[COL_PTR].into(),
                                        a_ptr: local[COL_A_PTR].into(),
                                        b_ptr: local[COL_B_PTR].into(),
                                        bound_ptr: local[COL_BOUND_PTR].into(),
                                        scalar_bound_ptr: local[COL_SBOUND_PTR].into(),
                                    },
                                    provide_deg,
                                );
                            },
                            col_deg,
                        );
                    },
                    col_deg,
                );
            },
            col_deg,
        );
    }
}
