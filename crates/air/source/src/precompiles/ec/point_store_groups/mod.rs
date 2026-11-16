//! Composite AIR for the EC point store and group table.
//!
//! The two components share a row range in disjoint column bands. Their
//! constraints and LogUp interactions delegate to the same offset-aware
//! evaluators used by the standalone component AIRs.

use alloc::borrow::Cow;

use miden_core::{Felt, field::QuadFelt};
use miden_stark::{air, lookup};
use p3_field::Dup;

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

impl air::LiftedAir for EcPointStoreGroupsAir {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(&[]),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        ec::eval_point_store_main(frame, builder, 0);
        groups::eval_main(frame, builder, GROUPS_COL_OFFSET);
        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for EcPointStoreGroupsAir {
    type Error = lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

impl<LB> lookup::LookupAir<LB> for EcPointStoreGroupsAir
where
    LB: lookup::LookupBuilder<F = Felt>,
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

    fn eval(&self, frame: &lookup::LookupFrame<'_, LB::Expr>, builder: &mut LB) {
        let local: &[LB::Expr; groups::NUM_MAIN_COLS] = frame.main.current
            [GROUPS_COL_OFFSET..GROUPS_COL_OFFSET + groups::NUM_MAIN_COLS]
            .try_into()
            .expect("EC group-table main row band");
        let provider = (
            -local[groups::COL_MULT].dup(),
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
