//! Composite AIR sharing idle sponge cells with chunk and Keccak-node records.
//!
//! Each sponge period carries one node and seven chunks. The component lookup messages
//! retain their standalone meanings; periodic selectors separate the shared payloads.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::{
    air::{BaseAir, LiftedAir, LiftedAirBuilder},
    lookup::{ConstraintLookupBuilder, LookupAir, LookupBuilder},
};
use miden_utils_sync::LazyLock;

use crate::precompiles::{
    hash::{
        chunk_node,
        keccak::sponge::{self, sponge_program},
    },
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    relations::{MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
};

/// First main-trace column of the sponge layout.
pub const SPONGE_COL_OFFSET: usize = 0;

pub const NUM_MAIN_COLS: usize = chunk_node::NUM_MAIN_COLS;
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

static PERIODIC_COLUMNS: LazyLock<Vec<Vec<Felt>>> = LazyLock::new(|| {
    let mut columns = Vec::from(sponge_program());
    columns.extend(chunk_node::periodic_columns());
    columns
});

impl BaseAir<Felt> for ChunkNodeSpongeAir {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

impl LiftedAir<Felt, QuadFelt> for ChunkNodeSpongeAir {
    fn max_periodic_length(&self) -> usize {
        sponge::SPONGE_PERIOD
    }

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
        miden_stark::lookup::build_logup_aux_trace(&ChunkNodeSpongeAir, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        chunk_node::eval_main(builder);
        sponge::eval_main_with_shared_capacity(builder, SPONGE_COL_OFFSET);

        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

impl<LB> LookupAir<LB> for ChunkNodeSpongeAir
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
        chunk_node::eval_lookups(builder);
        sponge::eval_lookups(builder, SPONGE_COL_OFFSET);
    }
}
