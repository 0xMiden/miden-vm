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
};
use miden_stark::{
    air,
    lookup::{self, Deg, LookupColumn, LookupMessage},
};
use miden_utils_sync::LazyLock;
use p3_field::Dup;

use crate::precompiles::{
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
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

impl air::LiftedAir for Sha512Air {
    type F = Felt;

    fn spec(&self) -> air::AirSpec<'_, Felt> {
        air::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(PERIODIC_COLUMNS.as_slice()),
        }
    }

    fn eval<AB: air::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &air::Frame<'_, AB>,
        inputs: air::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let local = frame.main.current;
        let next = frame.main.next;
        let io_periods: &[AB::Expr; io::NUM_PERIODIC_COLS] = frame.periodic
            [IO_PERIODIC_OFFSET..IO_PERIODIC_OFFSET + io::NUM_PERIODIC_COLS]
            .try_into()
            .expect("SHA-512 composed IO periodic band");
        let io_act: AB::Expr = local[COL_IO_ACT].dup();
        builder.assert_bool(local[COL_IO_ACT].dup());
        // The two padding cycles are exactly the sixty-four-row IO window.
        // Equality fixes IO ownership in both directions: it forbids IO on compression rows
        // and requires all sixty-four IO rows in each active block, so no block can omit binding.
        builder.assert_zero(
            io_act.dup()
                - local[compression::COL_ACT].dup()
                    * local[compression::COL_PHASE_BEGIN + compression::program::PHASE_PADDING]
                        .dup(),
        );
        compression::eval_main_with_io(frame, builder, 0, 0, io_act.dup());
        let io_local = IO_COLUMNS.map(|column| local[column].dup());
        let io_next = IO_COLUMNS.map(|column| next[column].dup());
        // Adjacent-row copies are valid only within this IO window. Its last row is followed
        // by compression cells, so the continuation bus below must carry state to the next block.
        let carry = io_act.dup() * (AB::Expr::ONE - io_periods[io::program::P_LAST].dup());
        io::eval_main_rows(frame, builder, &io_local, &io_next, io_periods, io_act, carry);

        lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl air::ProverAir<QuadFelt> for Sha512Air {
    type Error = lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: air::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<air::AuxTrace<QuadFelt>, Self::Error> {
        lookup::build_logup_aux_trace(self, inputs)
    }
}

impl<LB: lookup::LookupBuilder<F = Felt>> lookup::LookupAir<LB> for Sha512Air {
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
        let local = frame.main.current;
        let comp_local: &[LB::Expr; compression::NUM_MAIN_COLS] = local
            [..compression::NUM_MAIN_COLS]
            .try_into()
            .expect("SHA-512 composed compression lookup row band");
        let io_local = IO_COLUMNS.map(|column| local[column].dup());
        let next = frame.main.next;
        let io_next = IO_COLUMNS.map(|column| next[column].dup());
        let comp_periods: &[LB::Expr; compression::NUM_PERIODIC_COLS] = frame.periodic
            [..IO_PERIODIC_OFFSET]
            .try_into()
            .expect("SHA-512 composed compression lookup periodic band");
        let io_periods: &[LB::Expr; io::NUM_PERIODIC_COLS] = frame.periodic
            [IO_PERIODIC_OFFSET..IO_PERIODIC_OFFSET + io::NUM_PERIODIC_COLS]
            .try_into()
            .expect("SHA-512 composed IO lookup periodic band");
        let io_act: LB::Expr = local[COL_IO_ACT].dup();
        // The ownership equation makes these Boolean, disjoint activity flags. Inactive padding
        // enables neither batch, even though its compression controller continues advancing.
        let exec_act = local[compression::COL_ACT].dup() - io_act.dup();
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
                                comp_local,
                                comp_periods,
                                exec_act.dup(),
                            );
                            io::eval_lookup_group(
                                group,
                                index,
                                &io_local,
                                &io_next,
                                io_periods,
                                io_act.dup(),
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
    use alloc::vec::Vec;

    use miden_stark::lookup::Deg;

    use super::super::assert_sha_source;

    #[test]
    fn sha512_sources_preserve_constraint_layout_and_lookup_degrees() {
        assert_sha_source(super::compression::Sha512CompressionAir, 53, 7, 128, 128, 54);
        assert_sha_source(super::io::Sha512IoAir, 37, 6, 23, 64, 68);
        assert_sha_source(super::Sha512Air, 54, 7, 151, 128, 116);
        assert_eq!(super::IO_ROW_START, 4032);
        assert_eq!(super::IO_PERIODIC_OFFSET, 128);
        assert_eq!(super::IO_COLUMNS[super::io::COL_ACT], 53);
        assert_eq!(super::IO_COLUMNS[super::io::COL_BLOCK_ID], 0);
        assert_eq!(&super::IO_COLUMNS[2..], &(11..46).collect::<Vec<_>>());
        assert_eq!(super::compression::COLUMN_SHAPE, [1, 3, 2, 2, 2, 2, 2]);
        assert_eq!(super::io::COLUMN_SHAPE, [2; 6]);
        assert_eq!(super::COLUMN_SHAPE, [2, 3, 2, 2, 2, 2, 2]);
        // The seventh shared column carries only compression interactions.
        assert_eq!(super::io::lookup_column_degree(6, true), Deg { v: 0, u: 0 });
    }
}
