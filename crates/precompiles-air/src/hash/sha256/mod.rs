//! SHA-256 AIR sharing compression and IO witnesses across disjoint rows.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_lifted_air::{BaseAir, LiftedAir, LiftedAirBuilder};
use miden_utils_sync::LazyLock;

use crate::{
    logup::{
        ConstraintLookupBuilder, Deg, LookupAir, LookupBuilder, LookupColumn, LookupGroup,
        LookupMessage, NUM_LOGUP_VALUES, NUM_PUBLIC_VALUES, NUM_RANDOMNESS,
    },
    primitives::byte_pair_lut::Range16Msg,
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
    utils::{current_main, next_main},
};

pub mod compression;
pub mod io;

pub const IO_PERIODIC_OFFSET: usize = compression::NUM_PERIODIC_COLS;
pub const IO_ROW_START: usize = compression::COMPRESSION_PERIOD - io::IO_PERIOD;
// `COL_LANE_LAST8` selects lanes 24..32 of a 32-row cycle, which are the IO rows only while the
// IO band spans eight rows and starts at lane 24.
const _: () = assert!(io::IO_PERIOD == 8 && IO_ROW_START % 32 == 32 - io::IO_PERIOD);
pub const COL_IO_ACT: usize = compression::NUM_MAIN_COLS;
pub const NUM_MAIN_COLS: usize = compression::NUM_MAIN_COLS + 22;
pub const NUM_AUX_COLS: usize = io::NUM_AUX_COLS;

/// The block controller remains live on IO rows. All other compression cells are reused;
/// only the IO activity selector and twenty-one payload cells need additional columns.
pub const IO_COLUMNS: [usize; io::NUM_MAIN_COLS] = {
    assert!(compression::NUM_MAIN_COLS - compression::COL_META_T == 28);
    let mut columns = [0; io::NUM_MAIN_COLS];
    columns[io::COL_ACT] = COL_IO_ACT;
    columns[io::COL_BLOCK_ID] = compression::COL_BLOCK_ID;
    let mut i = 2;
    while i < 30 {
        columns[i] = compression::COL_META_T + i - 2;
        i += 1;
    }
    while i < io::NUM_MAIN_COLS {
        columns[i] = COL_IO_ACT + i - 29;
        i += 1;
    }
    assert!(columns[io::NUM_MAIN_COLS - 1] == NUM_MAIN_COLS - 1);
    columns
};
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = io::COLUMN_SHAPE;

/// Transport the IO state over the compression rows between consecutive blocks.
/// Unique consecutive block ids also bind the first/final flags and invocation endpoints.
#[derive(Debug, Clone)]
pub struct Sha256IoContinuation<E> {
    pub block_id: E,
    pub len: E,
    pub left: E,
    pub before: E,
    pub input_eidos: E,
    pub input_head: E,
}

impl<E, EF> LookupMessage<E, EF> for Sha256IoContinuation<E>
where
    E: Algebra<E>,
    EF: Algebra<E>,
{
    fn encode(&self, challenges: &crate::logup::Challenges<EF>) -> EF {
        challenges.encode(
            BusId::Sha256IoContinuation as usize,
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
pub struct Sha256Air;

static PERIODIC_COLUMNS: LazyLock<Vec<Vec<Felt>>> = LazyLock::new(|| {
    let mut columns = Vec::from(compression::compression_program());
    columns.extend(io::io_program());
    columns
});

impl BaseAir<Felt> for Sha256Air {
    fn width(&self) -> usize {
        NUM_MAIN_COLS
    }

    fn num_public_values(&self) -> usize {
        NUM_PUBLIC_VALUES
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

impl LiftedAir<Felt, QuadFelt> for Sha256Air {
    fn max_periodic_length(&self) -> usize {
        <compression::Sha256CompressionAir as LiftedAir<Felt, QuadFelt>>::max_periodic_length(
            &compression::Sha256CompressionAir,
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
        crate::logup::build_logup_aux_trace(self, main, challenges)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let local: [AB::Var; NUM_MAIN_COLS] = current_main(builder.main(), 0);
        let next: [AB::Var; NUM_MAIN_COLS] = next_main(builder.main(), 0);
        let periods = builder.periodic_values();
        let io_periods = core::array::from_fn(|i| periods[IO_PERIODIC_OFFSET + i].into());
        let lane_last8: AB::Expr = periods[compression::program::COL_LANE_LAST8].into();
        let io_act: AB::Expr = local[COL_IO_ACT].into();
        builder.assert_bool(local[COL_IO_ACT]);
        builder.assert_zero(
            io_act.clone()
                - AB::Expr::from(local[compression::COL_ACT])
                    * local[compression::COL_PHASE_BEGIN + compression::program::PHASE_PADDING]
                        .into()
                    * local[compression::COL_PHASE_END].into()
                    * lane_last8,
        );
        compression::eval_main_with_io(builder, 0, 0, io_act.clone());
        let io_local = IO_COLUMNS.map(|column| local[column]);
        let io_next = IO_COLUMNS.map(|column| next[column]);
        let carry = io_act.clone() * (AB::Expr::ONE - io_periods[io::program::P_LAST].clone());
        io::eval_main_rows(builder, &io_local, &io_next, &io_periods, io_act, carry);

        let mut lb = ConstraintLookupBuilder::new(builder, self);
        <Self as LookupAir<_>>::eval(self, &mut lb);
        lb.finish();
    }
}

impl<LB: LookupBuilder<F = Felt>> LookupAir<LB> for Sha256Air {
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
        let exec_act = LB::Expr::from(local[compression::COL_ACT]) - io_act.clone();
        // One group per column: its two batches are mutually exclusive. Separate groups
        // would multiply denominators, increasing both degree and committed area. IO needs
        // more columns than compression, so the trailing IO columns carry no compression batch.
        for index in 0..io::NUM_AUX_COLS - 1 {
            let kind = compression::SHARED_BATCHES.get(index).copied();
            let io = io::lookup_batch_degree(index, 0);
            let io = Deg { v: io.v + 1, u: io.u + 1 };
            let comp = kind.map(|kind| {
                let comp = compression::lookup_batch_degree(kind, 0);
                Deg { v: comp.v + 1, u: comp.u + 1 }
            });
            let degree = comp.map_or(io, |comp| Deg { v: comp.v.max(io.v), u: comp.u.max(io.u) });
            builder.next_column(
                |column| {
                    column.group(
                        "sha256-phases",
                        |group| {
                            if let (Some(kind), Some(comp)) = (kind, comp) {
                                group.batch(
                                    "compression",
                                    exec_act.clone(),
                                    |batch| {
                                        compression::eval_lookup_batch(
                                            batch,
                                            kind,
                                            &comp_local,
                                            &comp_periods,
                                            LB::Expr::ONE,
                                            0,
                                        );
                                    },
                                    comp,
                                );
                            }
                            group.batch(
                                "io",
                                io_act.clone(),
                                |batch| {
                                    io::eval_lookup_batch(
                                        batch,
                                        index,
                                        &io_local,
                                        &io_next,
                                        &io_periods,
                                        LB::Expr::ONE,
                                        0,
                                    );
                                },
                                io,
                            );
                        },
                        degree,
                    );
                },
                degree,
            );
        }

        let v = |column: usize| -> LB::Expr { io_local[column].into() };
        let last = io_act.clone() * io_periods[io::program::P_LAST].clone();
        let final_block = v(io::COL_FINAL_BLOCK);
        let provide = last.clone() * (LB::Expr::ONE - final_block.clone());
        let consume = io_act
            * io_periods[io::program::P_FIRST].clone()
            * (LB::Expr::ONE - v(io::COL_FIRST_BLOCK));
        let degree = Deg { v: 3, u: 4 };
        // Final length validation and the two continuation endpoints are mutually exclusive.
        // This column is a fraction column, so its degree-four denominator closes at degree five.
        builder.next_column(
            |column| {
                column.group(
                    "sha256-io-boundary",
                    |group| {
                        group.add(
                            "length-high",
                            last * final_block,
                            || Range16Msg { w: v(io::COL_WORD_HI) },
                            degree,
                        );
                        group.remove(
                            "continue",
                            provide,
                            || Sha256IoContinuation {
                                block_id: v(io::COL_BLOCK_ID) + LB::Expr::ONE,
                                len: v(io::COL_LEN),
                                left: v(io::COL_LEFT)
                                    - (0..8).map(|i| v(io::COL_MSG_BEGIN + i)).sum::<LB::Expr>(),
                                before: v(io::COL_MSG_BEGIN + 7),
                                input_eidos: v(io::COL_INPUT_EIDOS),
                                input_head: v(io::COL_INPUT_HEAD),
                            },
                            degree,
                        );
                        group.add(
                            "resume",
                            consume,
                            || Sha256IoContinuation {
                                block_id: v(io::COL_BLOCK_ID),
                                len: v(io::COL_LEN),
                                left: v(io::COL_LEFT),
                                before: v(io::COL_BEFORE),
                                input_eidos: v(io::COL_INPUT_EIDOS) - v(io::COL_CHUNK_ACTIVE),
                                input_head: v(io::COL_INPUT_HEAD),
                            },
                            degree,
                        );
                    },
                    degree,
                );
            },
            degree,
        );
    }
}

#[cfg(all(test, feature = "std"))]
mod tests {
    use miden_air::lookup::{
        LookupAir,
        debug::{ValidateLayout, ValidateLookupAir, ValidationBuilder},
    };
    use miden_core::{Felt, field::QuadFelt};
    use miden_lifted_air::{ConstraintDegrees, LiftedAir};

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
        .expect("SHA-256 lookup degree annotations must match their symbolic expressions");
    }

    #[test]
    fn sha256_compression_lookup_degrees_match_annotations() {
        validate_degrees(super::compression::Sha256CompressionAir);
    }

    #[test]
    fn sha256_io_lookup_degrees_match_annotations() {
        validate_degrees(super::io::Sha256IoAir);
    }

    #[test]
    fn sha256_composite_lookup_degrees_match_annotations() {
        validate_degrees(super::Sha256Air);
    }

    #[test]
    fn sha256_constraints_fit_the_deployed_degree_bound() {
        let bound = crate::security::AIR_SHAPE.max_constraint_degree as usize;
        let degrees = [
            ConstraintDegrees::from_air::<Felt, QuadFelt, _>(
                &super::compression::Sha256CompressionAir,
            )
            .max(),
            ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&super::io::Sha256IoAir).max(),
            ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&super::Sha256Air).max(),
        ];
        assert!(degrees.iter().all(|&degree| degree <= bound), "{degrees:?} exceed {bound}");
    }
}
