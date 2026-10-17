//! Composite AIR for the EC point store and group table.
//!
//! The two components share a row range in disjoint column bands. Their
//! constraints and LogUp interactions delegate to the same offset-aware
//! evaluators used by the standalone component AIRs.

use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    ec::{self, groups},
    logup::{
        ConstraintLookupBuilder, LookupAir, LookupBuilder, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES,
        NUM_RANDOMNESS,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::current_main,
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

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }
}

impl LiftedAir<Felt, QuadFelt> for EcPointStoreGroupsAir {
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
        _air_inputs: &[Felt],
        _aux_inputs: &[Felt],
        challenges: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        crate::logup::build_logup_aux_trace(&EcPointStoreGroupsAir, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        ec::eval_point_store_main(builder, 0);
        groups::eval_main(builder, GROUPS_COL_OFFSET);

        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
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
        let local: [LB::Var; groups::NUM_MAIN_COLS] =
            current_main(builder.main(), GROUPS_COL_OFFSET);
        let provider = (
            LB::Expr::ZERO - local[groups::COL_MULT].into(),
            ec::EcGroupMsg {
                group_ptr: local[groups::COL_PTR].into(),
                a_ptr: local[groups::COL_A_PTR].into(),
                b_ptr: local[groups::COL_B_PTR].into(),
                bound_ptr: local[groups::COL_BOUND_PTR].into(),
                scalar_bound_ptr: local[groups::COL_SBOUND_PTR].into(),
                beta_ptr: local[groups::COL_BETA_PTR].into(),
                lambda_ptr: local[groups::COL_LAMBDA_PTR].into(),
            },
        );
        ec::eval_point_store_lookups(builder, 0, Some(provider));
    }
}
