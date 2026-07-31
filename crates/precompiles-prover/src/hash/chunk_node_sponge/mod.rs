//! Composite AIR for the chunk, Keccak-node, and Keccak-sponge chiplets.
//!
//! The three components share a row range in disjoint column bands. Their
//! constraints and LogUp interactions delegate to the same offset-aware
//! evaluators used by the standalone component AIRs.

pub mod trace;

use alloc::vec::Vec;

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};

use crate::{
    hash::{
        chunk_node,
        keccak::sponge::{self, sponge_program},
    },
    logup::{
        CyclicConstraintLookupBuilder, LookupAir, LookupBuilder, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
        NUM_SIGMA_VALUES,
    },
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
};

/// First main-trace column of the sponge band.
pub const SPONGE_COL_OFFSET: usize = chunk_node::NUM_MAIN_COLS;

pub const NUM_MAIN_COLS: usize = chunk_node::NUM_MAIN_COLS + sponge::NUM_MAIN_COLS;
pub const NUM_AUX_COLS: usize = chunk_node::NUM_AUX_COLS + sponge::NUM_AUX_COLS;

const fn column_shape() -> [usize; NUM_AUX_COLS] {
    let mut shape = [0usize; NUM_AUX_COLS];
    let mut i = 0;
    while i < chunk_node::NUM_AUX_COLS {
        shape[i] = chunk_node::COLUMN_SHAPE[i];
        i += 1;
    }
    let mut j = 0;
    while j < sponge::NUM_AUX_COLS {
        shape[chunk_node::NUM_AUX_COLS + j] = sponge::COLUMN_SHAPE[j];
        j += 1;
    }
    shape
}
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = column_shape();

#[derive(Debug, Default, Clone, Copy)]
pub struct ChunkNodeSpongeAir;

impl BaseAir<Felt> for ChunkNodeSpongeAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Vec<Vec<Felt>> {
        sponge_program().to_vec()
    }
}

impl LiftedAir<Felt, QuadFelt> for ChunkNodeSpongeAir {
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
        chunk_node::eval_main(builder, 0);
        sponge::eval_main(builder, SPONGE_COL_OFFSET);

        let mut lb =
            CyclicConstraintLookupBuilder::new(builder, self, self.preprocessed_width() > 0);
        <Self as LookupAir<_>>::eval(self, &mut lb);
    }
}

impl<LB> LookupAir<LB> for ChunkNodeSpongeAir
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
        chunk_node::eval_lookups(builder, 0);
        sponge::eval_lookups(builder, SPONGE_COL_OFFSET);
    }
}
