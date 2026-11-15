//! Composite AIR for the EC point store and group table.
//!
//! The two components share a row range in disjoint column bands. Their
//! constraints and LogUp interactions delegate to the same offset-aware
//! evaluators used by the standalone component AIRs.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::{
    air::{BaseAir, LiftedAir, LiftedAirBuilder, native},
    lookup::{LookupAir, LookupBuilder, native as native_lookup},
};
use p3_field::{Algebra, Dup};

use crate::precompiles::{
    ec::{self, groups},
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
};

/// First main-trace column of the group-table band.
pub const GROUPS_COL_OFFSET: usize = ec::NUM_MAIN_COLS;

pub const NUM_MAIN_COLS: usize = ec::NUM_MAIN_COLS + groups::NUM_MAIN_COLS;
pub const NUM_AUX_COLS: usize = 4;
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [1, 2, 2, 2];

#[derive(Debug, Default, Clone, Copy)]
pub struct EcPointStoreGroupsAir;

impl BaseAir<Felt> for EcPointStoreGroupsAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }
}

impl LiftedAir<Felt, QuadFelt> for EcPointStoreGroupsAir {
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

    fn num_randomness(&self) -> usize {
        NUM_RANDOMNESS
    }

    fn aux_width(&self) -> usize {
        NUM_AUX_COLS
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

impl native::LiftedAir for EcPointStoreGroupsAir {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
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
        ec::eval_point_store_main(frame, builder, 0);
        groups::eval_main(frame, builder, GROUPS_COL_OFFSET);
        native_lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl native::ProverAir<QuadFelt> for EcPointStoreGroupsAir {
    type Error = native_lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        native_lookup::build_logup_aux_trace(self, inputs)
    }
}

impl<LB> LookupAir<LB> for EcPointStoreGroupsAir
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

impl<LB> native_lookup::LookupAir<LB> for EcPointStoreGroupsAir
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
        let local: &[LB::Expr; groups::NUM_MAIN_COLS] = frame.main.current
            [GROUPS_COL_OFFSET..GROUPS_COL_OFFSET + groups::NUM_MAIN_COLS]
            .try_into()
            .expect("EC group-table main row band");
        let provider = (
            LB::Expr::ZERO - local[groups::COL_MULT].dup(),
            ec::EcGroupMsg {
                group_ptr: local[groups::COL_PTR].dup(),
                a_ptr: local[groups::COL_A_PTR].dup(),
                b_ptr: local[groups::COL_B_PTR].dup(),
                bound_ptr: local[groups::COL_BOUND_PTR].dup(),
                scalar_bound_ptr: local[groups::COL_SBOUND_PTR].dup(),
                beta_ptr: local[groups::COL_BETA_PTR].dup(),
                lambda_ptr: local[groups::COL_LAMBDA_PTR].dup(),
            },
        );
        ec::eval_point_store_lookups(frame, builder, 0, Some(provider));
    }
}
