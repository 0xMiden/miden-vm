//! SHA-512 AIR sharing compression and IO witnesses across disjoint rows.
//!
//! Each block spans 4096 rows. Its last sixty-four rows (4032..4096) run the IO constraints
//! in cells otherwise used by compression, while the compression block controller stays live.
//! The same row ownership selects between compression and IO lookup batches. IO state crosses
//! the intervening compression rows through [`Sha512IoContinuation`] rather than next-row copies.

pub mod compression;
pub mod io;

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::{
    air::{BaseAir, LiftedAir, LiftedAirBuilder},
    lookup::{ConstraintLookupBuilder, Deg, LookupAir, LookupBuilder, LookupColumn, LookupMessage},
};
use miden_utils_sync::LazyLock;

use crate::precompiles::{
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

pub const IO_PERIODIC_OFFSET: usize = compression::NUM_PERIODIC_COLS;
pub const IO_ROW_START: usize = compression::COMPRESSION_PERIOD - io::IO_PERIOD;
const _: () = {
    assert!(io::IO_PERIOD == 64);
    assert!(IO_ROW_START.is_multiple_of(io::IO_PERIOD));
};
pub const COL_IO_ACT: usize = compression::NUM_MAIN_COLS;
pub const NUM_MAIN_COLS: usize = compression::NUM_MAIN_COLS + 1;
pub const NUM_AUX_COLS: usize = 7;

/// The block controller remains live on IO rows. All other compression cells are reused;
/// only the IO activity selector needs an additional column.
pub const IO_COLUMNS: [usize; io::NUM_MAIN_COLS] = {
    assert!(compression::NUM_MAIN_COLS - compression::COL_META_T == 42);
    let mut columns = [0; io::NUM_MAIN_COLS];
    columns[io::COL_ACT] = COL_IO_ACT;
    columns[io::COL_BLOCK_ID] = compression::COL_BLOCK_ID;
    let mut i = 2;
    assert!(io::NUM_MAIN_COLS <= 44);
    while i < io::NUM_MAIN_COLS {
        columns[i] = compression::COL_META_T + i - 2;
        i += 1;
    }
    columns
};
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [2, 3, 2, 2, 2, 2, 2];

/// Transport the IO state over the compression rows between consecutive blocks.
/// Unique consecutive block ids also bind the first/final flags and invocation endpoints.
/// A non-final block provides the state consumed by the next non-first block. Thus block zero
/// must begin an invocation, and every unfinished invocation must have a successor.
#[derive(Debug, Clone)]
pub struct Sha512IoContinuation<E> {
    pub block_id: E,
    pub len: E,
    pub left: E,
    pub before: E,
    pub input_eidos: E,
    pub input_head: E,
}

impl<E, EF> LookupMessage<E, EF> for Sha512IoContinuation<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &miden_stark::lookup::Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Sha512IoContinuation as usize,
            [
                self.block_id.clone(),
                self.len.clone(),
                self.left.clone(),
                self.before.clone(),
                self.input_eidos.clone(),
                self.input_head.clone(),
            ],
        )
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct Sha512Air;

static PERIODIC_COLUMNS: LazyLock<Vec<Vec<Felt>>> = LazyLock::new(|| {
    let mut columns = Vec::from(compression::compression_program());
    columns.extend(io::io_program());
    columns
});

impl BaseAir<Felt> for Sha512Air {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

impl LiftedAir<Felt, QuadFelt> for Sha512Air {
    fn max_periodic_length(&self) -> usize {
        <compression::Sha512CompressionAir as LiftedAir<Felt, QuadFelt>>::max_periodic_length(
            &compression::Sha512CompressionAir,
        )
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
        miden_stark::lookup::build_logup_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let periods = builder.periodic_values();
        let io_periods = core::array::from_fn(|i| periods[IO_PERIODIC_OFFSET + i].into());
        let io_act: AB::Expr = local[COL_IO_ACT].into();
        builder.assert_bool(local[COL_IO_ACT]);
        // The two padding cycles are exactly the sixty-four-row IO window.
        // Equality fixes IO ownership in both directions: it forbids IO on compression rows
        // and requires all sixty-four IO rows in each active block, so no block can omit binding.
        builder.assert_zero(
            io_act.clone()
                - AB::Expr::from(local[compression::COL_ACT])
                    * local[compression::COL_PHASE_BEGIN + compression::program::PHASE_PADDING]
                        .into(),
        );
        compression::eval_main_with_io(builder, 0, 0, io_act.clone());
        let io_local = IO_COLUMNS.map(|column| local[column]);
        let io_next = IO_COLUMNS.map(|column| next[column]);
        // Adjacent-row copies are valid only within this IO window. Its last row is followed
        // by compression cells, so the continuation bus below must carry state to the next block.
        let carry = io_act.clone() * (AB::Expr::ONE - io_periods[io::program::P_LAST].clone());
        io::eval_main_rows(builder, &io_local, &io_next, &io_periods, io_act, carry);

        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for Sha512Air {
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
        let comp_local = core::array::from_fn(|i| local[i]);
        let io_local = IO_COLUMNS.map(|column| local[column]);
        let next: [LB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let io_next = IO_COLUMNS.map(|column| next[column]);
        let periods = builder.periodic_values();
        let comp_periods = core::array::from_fn(|i| periods[i].into());
        let io_periods: [LB::Expr; io::NUM_PERIODIC_COLS] =
            core::array::from_fn(|i| periods[IO_PERIODIC_OFFSET + i].into());
        let io_act: LB::Expr = local[COL_IO_ACT].into();
        // The ownership equation makes these Boolean, disjoint activity flags. Inactive padding
        // enables neither batch, even though its compression controller continues advancing.
        let exec_act = LB::Expr::from(local[compression::COL_ACT]) - io_act.clone();
        for index in 0..NUM_AUX_COLS {
            let comp = compression::lookup_column_degree(index);
            let io = io::lookup_column_degree(index, true);
            let degree = Deg { v: comp.v.max(io.v), u: comp.u.max(io.u) };
            builder.next_column(
                |column| {
                    column.group(
                        "sha512-phases",
                        |group| {
                            compression::eval_lookup_group(
                                group,
                                index,
                                &comp_local,
                                &comp_periods,
                                exec_act.clone(),
                            );
                            io::eval_lookup_group(
                                group,
                                index,
                                &io_local,
                                &io_next,
                                &io_periods,
                                io_act.clone(),
                                true,
                            );
                        },
                        degree,
                    );
                },
                degree,
            );
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use miden_core::{Felt, field::QuadFelt};
    use miden_stark::{
        air::LiftedAir,
        lookup::{
            LookupAir,
            debug::{ValidateLayout, ValidateLookupAir, ValidationBuilder},
        },
    };

    fn validate_degrees<A>(air: A)
    where
        A: LiftedAir<Felt, QuadFelt>,
        for<'ab, 'r> A: LookupAir<ValidationBuilder<'ab, 'r>>,
    {
        let layout = air.air_layout();
        air.validate(ValidateLayout {
            trace_width: layout.main_width,
            preprocessed_width: layout.preprocessed_width,
            num_public_values: layout.num_public_values,
            num_periodic_columns: layout.num_periodic_columns,
            permutation_width: layout.permutation_width,
            num_permutation_challenges: layout.num_permutation_challenges,
            num_permutation_values: layout.num_permutation_values,
        })
        .expect("SHA-512 lookup degree annotations must match their symbolic expressions");
    }

    #[test]
    fn sha512_compression_lookup_degrees_match_annotations() {
        validate_degrees(super::compression::Sha512CompressionAir);
    }

    #[test]
    fn sha512_io_lookup_degrees_match_annotations() {
        validate_degrees(super::io::Sha512IoAir);
    }

    #[test]
    fn sha512_composite_lookup_degrees_match_annotations() {
        validate_degrees(super::Sha512Air);
    }
}
