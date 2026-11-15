//! EcGroups chiplet — the short-Weierstrass **group table**.
//!
//! One row per group binds
//! `group_ptr → (a_ptr, b_ptr, bound_ptr, scalar_bound_ptr, beta_ptr, lambda_ptr)`. The tuple
//! identifies the curve parameters, the base-field modulus, the scalar-field modulus, and the GLV
//! endomorphism parameters. A group without a separately constrained scalar modulus uses
//! `bound_ptr`; a group without a GLV endomorphism uses the none-sentinel 0 for `beta_ptr` and
//! `lambda_ptr`.
//!
//! The group table and point store have separate row layouts. Point rows name their group through
//! `group_ptr` and recover the complete curve context through the `EcGroup` relation.
//!
//! Each row provides one `EcGroup` message with multiplicity `mult`; padding rows use `mult = 0`.
//! The first row has `ptr = 1`, and every transition enforces `ptr' = ptr + 1`, so every row has a
//! distinct pointer. Trace generation preloads the VM-owned slots from `CurveId::ALL`. The require
//! layer and consuming relations establish parameter validity, including `b ≠ 0` and the uint
//! bindings under `bound_ptr`.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::{
    air::{BaseAir, LiftedAir, LiftedAirBuilder, native},
    lookup::{
        Deg, LookupAir, LookupBatch, LookupBuilder, LookupColumn, LookupGroup,
        native as native_lookup,
    },
};
use native::LiftedAirBuilder as _;
use p3_field::{Algebra, Dup};

use crate::precompiles::{
    ec::EcGroupMsg,
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
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
/// The scalar-field modulus ptr (fixes `F_s`); defaults to `bound_ptr` unless explicitly set.
pub const COL_SBOUND_PTR: usize = 4;
/// `EcGroup` provide multiplicity (the total consumer count); 0 on padding rows — the only
/// liveness signal this chiplet needs.
pub const COL_MULT: usize = 5;
/// The GLV endomorphism base-field constant `β`'s uint ptr (the
/// none-sentinel 0 for a group with no endomorphism).
pub const COL_BETA_PTR: usize = 6;
/// The GLV endomorphism scalar `λ`'s uint ptr (the none-sentinel 0 for a
/// group with no endomorphism).
pub const COL_LAMBDA_PTR: usize = 7;
pub const NUM_MAIN_COLS: usize = 8;

// Aux: the single LogUp running-sum column (one fraction).
pub(crate) const NUM_LOGUP_COLS: usize = 1;
const AUX_WIDTH: usize = 1;
pub(crate) const COLUMN_SHAPE: [usize; NUM_LOGUP_COLS] = [1];

// AIR
// ================================================================================================

#[derive(Debug, Default, Clone, Copy)]
pub struct EcGroupsAir;

impl BaseAir<Felt> for EcGroupsAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }
}

impl LiftedAir<Felt, QuadFelt> for EcGroupsAir {
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        AUX_WIDTH
    }

    fn num_aux_values(&self) -> usize {
        NUM_LOGUP_VALUES
    }

    fn build_aux_trace(
        &self,
        main: &RowMajorMatrix<Felt>,
        air_inputs: &[Felt],
        aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        let aux = <Self as native::ProverAir<QuadFelt>>::build_aux_trace(
            self,
            native::AuxTraceInputs {
                main,
                preprocessed: None,
                public_values: air_inputs,
                statement: aux_inputs,
                challenges,
            },
        )
        .expect("valid EC store auxiliary inputs");
        (aux.columns, aux.exports)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
        native::migration::eval_source(self, builder);
    }
}

impl native::LiftedAir for EcGroupsAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: AUX_WIDTH,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        eval_main(frame, builder, 0);
        native_lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl native::ProverAir<QuadFelt> for EcGroupsAir {
    type Error = native_lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        native_lookup::build_logup_aux_trace(self, inputs)
    }
}

/// Evaluate this component's base constraints in a main-trace column band.
pub(crate) fn eval_main<AB>(frame: &native::Frame<'_, AB>, builder: &mut AB, main_col_offset: usize)
where
    AB: native::LiftedAirBuilder<F = Felt>,
{
    let local: &[AB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("EC store current main row band");
    let next: &[AB::Expr; NUM_MAIN_COLS] = frame.main.next
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("EC store next main row band");

    let ptr: AB::Expr = local[COL_PTR].dup();
    let ptr_next: AB::Expr = next[COL_PTR].dup();

    // The ungated chain: ptr = row + 1 for every prover, pads
    // included (they are just mult = 0 rows), so ptr → tuple is
    // injective by construction. The wrap edge is dropped, keeping
    // the cyclic last → first transition free.
    builder
        .when(frame.transition())
        .assert_zero(ptr_next - ptr.clone() - AB::Expr::ONE);
    builder.when(frame.first_row()).assert_zero(ptr - AB::Expr::ONE);
}

// LOOKUP AIR
// ================================================================================================

impl<LB> LookupAir<LB> for EcGroupsAir
where
    LB: LookupBuilder<F = Felt>,
{
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
        native::migration::eval_lookup(self, builder, 0);
    }
}

impl<LB> native_lookup::LookupAir<LB> for EcGroupsAir
where
    LB: native_lookup::LookupBuilder<F = Felt>,
{
    fn column_shape(&self) -> &[usize] {
        &COLUMN_SHAPE
    }

    fn max_message_width(&self) -> usize {
        MAX_MESSAGE_WIDTH
    }

    fn num_bus_ids(&self) -> usize {
        NUM_BUS_IDS
    }

    fn eval(&self, frame: &native_lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        eval_lookups(frame, builder, 0);
    }
}

/// Evaluate this component's LogUp columns in a main-trace column band.
pub(crate) fn eval_lookups<LB>(
    frame: &native_lookup::LookupFrame<'_, LB::Expr>,
    builder: &mut LB,
    main_col_offset: usize,
) where
    LB: native_lookup::LookupBuilder<F = Felt>,
{
    let local: &[LB::Expr; NUM_MAIN_COLS] = frame.main.current
        [main_col_offset..main_col_offset + NUM_MAIN_COLS]
        .try_into()
        .expect("EC store lookup main row band");

    // Pads zero the mult cell, so the provide needs no act gate.
    let neg_mult: LB::Expr = LB::Expr::ZERO - local[COL_MULT].dup();

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
                                    group_ptr: local[COL_PTR].dup(),
                                    a_ptr: local[COL_A_PTR].dup(),
                                    b_ptr: local[COL_B_PTR].dup(),
                                    bound_ptr: local[COL_BOUND_PTR].dup(),
                                    scalar_bound_ptr: local[COL_SBOUND_PTR].dup(),
                                    beta_ptr: local[COL_BETA_PTR].dup(),
                                    lambda_ptr: local[COL_LAMBDA_PTR].dup(),
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
