//! SHA-256 AIR sharing compression and IO witnesses across disjoint rows.

pub mod compression;
pub mod io;

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{
    Felt,
    field::{Algebra, PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::{
    air::{BaseAir, LiftedAir, LiftedAirBuilder, native},
    lookup::{Deg, LookupAir, LookupBuilder, LookupColumn, LookupMessage, native as native_lookup},
};
use miden_utils_sync::LazyLock;
use p3_field::Dup;

use crate::precompiles::{
    logup::{NUM_LOGUP_VALUES, NUM_RANDOMNESS},
    relations::{BusId, MAX_MESSAGE_WIDTH, NUM_BUS_IDS},
};

pub const IO_PERIODIC_OFFSET: usize = compression::NUM_PERIODIC_COLS;
pub const IO_ROW_START: usize = compression::COMPRESSION_PERIOD - io::IO_PERIOD;
const _: () = assert!(io::IO_PERIOD == 32 && IO_ROW_START.is_multiple_of(32));
pub const COL_IO_ACT: usize = compression::NUM_MAIN_COLS;
pub const NUM_MAIN_COLS: usize = compression::NUM_MAIN_COLS + 1;
pub const NUM_AUX_COLS: usize = 4;
/// The controller stays live; serialized IO fits in compression's inactive payload cells.
pub const IO_COLUMNS: [usize; io::NUM_MAIN_COLS] = {
    let mut columns = [0; io::NUM_MAIN_COLS];
    columns[io::COL_ACT] = COL_IO_ACT;
    columns[io::COL_BLOCK_ID] = compression::COL_BLOCK_ID;
    let mut i = 2;
    while i < io::NUM_MAIN_COLS {
        columns[i] = compression::COL_META_T + i - 2;
        i += 1;
    }
    assert!(columns[io::NUM_MAIN_COLS - 1] < compression::NUM_MAIN_COLS);
    columns
};
const COLUMN_SHAPE: [usize; NUM_AUX_COLS] = [2; NUM_AUX_COLS];

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
    fn encode(&self, challenges: &miden_stark::lookup::Challenges<EF>) -> EF {
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

    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Borrowed(PERIODIC_COLUMNS.as_slice())
    }
}

impl LiftedAir<Felt, QuadFelt> for Sha256Air {
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

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
        .expect("valid SHA-256 auxiliary inputs");
        (aux.columns, aux.exports)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
        native::migration::eval_source(self, builder);
    }
}

impl native::LiftedAir for Sha256Air {
    type F = Felt;

    fn spec(&self) -> native::AirSpec<'_, Felt> {
        native::AirSpec {
            main_width: NUM_MAIN_COLS,
            aux_width: NUM_AUX_COLS,
            num_public_values: 0,
            num_challenges: NUM_RANDOMNESS,
            num_exports: NUM_LOGUP_VALUES,
            preprocessed: None,
            periodic_columns: Cow::Borrowed(PERIODIC_COLUMNS.as_slice()),
        }
    }

    fn eval<AB: native::LiftedAirBuilder<F = Felt>>(
        &self,
        frame: &native::Frame<'_, AB>,
        inputs: native::Inputs<'_, AB>,
        builder: &mut AB,
    ) {
        let local = frame.main.current;
        let next = frame.main.next;
        let io_periods: &[AB::Expr; io::NUM_PERIODIC_COLS] = frame.periodic
            [IO_PERIODIC_OFFSET..IO_PERIODIC_OFFSET + io::NUM_PERIODIC_COLS]
            .try_into()
            .expect("SHA-256 composed IO periodic band");
        let io_act: AB::Expr = local[COL_IO_ACT].dup();
        builder.assert_bool(local[COL_IO_ACT].dup());
        builder.assert_zero(
            io_act.dup()
                - local[compression::COL_ACT].dup()
                    * local[compression::COL_PHASE_BEGIN + compression::program::PHASE_PADDING]
                        .dup()
                    * local[compression::COL_PHASE_END].dup(),
        );
        compression::eval_main_with_io(frame, builder, 0, 0, io_act.dup());
        let io_local = IO_COLUMNS.map(|column| local[column].dup());
        let io_next = IO_COLUMNS.map(|column| next[column].dup());
        let carry = io_act.dup() * (AB::Expr::ONE - io_periods[io::program::P_LAST].dup());
        io::eval_main_rows(frame, builder, &io_local, &io_next, io_periods, io_act, carry);

        native_lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl native::ProverAir<QuadFelt> for Sha256Air {
    type Error = native_lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        native_lookup::build_logup_aux_trace(self, inputs)
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
        native::migration::eval_lookup(self, builder, 0);
    }
}

impl<LB: native_lookup::LookupBuilder<F = Felt>> native_lookup::LookupAir<LB> for Sha256Air {
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
        let local = frame.main.current;
        let comp_local: &[LB::Expr; compression::NUM_MAIN_COLS] = local
            [..compression::NUM_MAIN_COLS]
            .try_into()
            .expect("SHA-256 composed compression lookup row band");
        let io_local = IO_COLUMNS.map(|column| local[column].dup());
        let next = frame.main.next;
        let io_next = IO_COLUMNS.map(|column| next[column].dup());
        let comp_periods: &[LB::Expr; compression::NUM_PERIODIC_COLS] = frame.periodic
            [..IO_PERIODIC_OFFSET]
            .try_into()
            .expect("SHA-256 composed compression lookup periodic band");
        let io_periods: &[LB::Expr; io::NUM_PERIODIC_COLS] = frame.periodic
            [IO_PERIODIC_OFFSET..IO_PERIODIC_OFFSET + io::NUM_PERIODIC_COLS]
            .try_into()
            .expect("SHA-256 composed IO lookup periodic band");
        let io_act: LB::Expr = local[COL_IO_ACT].dup();
        let exec_act = local[compression::COL_ACT].dup() - io_act.dup();
        for index in 0..NUM_AUX_COLS {
            let comp = compression::lookup_column_degree(index);
            let io = io::lookup_column_degree(index, true);
            let degree = Deg { v: comp.v.max(io.v), u: comp.u.max(io.u) };
            builder.next_column(
                |column| {
                    column.group(
                        "sha256-phases",
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

    use miden_core::{
        Felt,
        field::{PrimeCharacteristicRing, QuadFelt},
    };
    use miden_stark::{
        air::{
            ConstraintDegrees, LiftedAir,
            native::{self, AirKernel},
        },
        lookup::{
            LookupAir,
            debug::{ValidateLayout, ValidateLookupAir, ValidationBuilder},
            native as native_lookup,
        },
    };

    fn native_geometry<A>(air: A, main_width: usize, periodic_columns: usize, base_count: usize)
    where
        A: native::ProverAir<QuadFelt, F = Felt, Error = native_lookup::LookupError>,
    {
        // The expected relation comes from the authored source, instantiated with non-Copy trees.
        // Direct execution is the comparison subject, rather than a source of expected metadata.
        let captured = native::capture_with::<_, QuadFelt>(&air).unwrap();
        let descriptor = &captured.descriptor;
        let spec = descriptor.spec();
        assert_eq!((spec.main_width, spec.aux_width), (main_width, 4));
        assert_eq!((spec.num_public_values, spec.num_challenges, spec.num_exports), (0, 2, 1));
        assert_eq!(spec.preprocessed, None);
        assert_eq!(spec.periodic_columns.len(), periodic_columns);
        assert_eq!(spec.max_periodic_length(), if main_width == 28 { 32 } else { 128 });
        assert_eq!(
            descriptor.analysis().counts(),
            native::ConstraintCounts { base: base_count, ext: 5 }
        );
        assert_eq!(
            descriptor.analysis().layout().base_indices(),
            &(0..base_count).collect::<Vec<_>>()
        );
        assert_eq!(
            descriptor.analysis().layout().ext_indices(),
            &(base_count..base_count + 5).collect::<Vec<_>>()
        );
        assert!(descriptor.analysis().raw_degrees().max() <= 5);

        let main = miden_core::utils::RowMajorMatrix::new(
            vec![Felt::ZERO; main_width - 1],
            main_width - 1,
        );
        let challenges = [QuadFelt::from_u8(17), QuadFelt::from_u8(31)];
        let error = native::ProverAir::build_aux_trace(
            &air,
            native::AuxTraceInputs {
                main: &main,
                preprocessed: None,
                public_values: &[],
                statement: &[],
                challenges: &challenges,
            },
        )
        .unwrap_err();
        assert_eq!(
            error,
            native_lookup::LookupError::MainWidth {
                expected: main_width,
                actual: main_width - 1,
            }
        );

        let kernel = native::DirectKernel::new(air).unwrap();
        let direct = native::capture_from_spec::<Felt, QuadFelt>(
            spec.as_borrowed(),
            |frame, inputs, sink| kernel.bind(inputs).unwrap().eval(frame, sink),
        )
        .unwrap();
        assert_eq!(direct.descriptor.fingerprint(), descriptor.fingerprint());
    }

    #[test]
    fn native_sha256_sources_preserve_shape_and_class_order() {
        native_geometry(super::compression::Sha256CompressionAir, 39, 115, 48);
        native_geometry(super::io::Sha256IoAir, 28, 23, 58);
        native_geometry(super::Sha256Air, 40, 138, 100);
        assert_eq!(super::IO_ROW_START, 4064);
        assert_eq!(super::IO_PERIODIC_OFFSET, 115);
        assert_eq!(super::IO_COLUMNS[super::io::COL_ACT], 39);
        assert_eq!(super::IO_COLUMNS[super::io::COL_BLOCK_ID], 0);
        assert_eq!(&super::IO_COLUMNS[2..], &(11..37).collect::<Vec<_>>());
        assert_eq!(super::COLUMN_SHAPE, [2; 4]);
        assert_eq!(super::compression::COLUMN_SHAPE, [2; 4]);
        assert_eq!(super::io::COLUMN_SHAPE, [2; 4]);
    }

    #[test]
    fn native_sha256_lookup_degrees_match_annotations() {
        let compression = super::compression::Sha256CompressionAir;
        native_lookup::validate_native(&compression, &native::LiftedAir::spec(&compression))
            .unwrap();
        let io = super::io::Sha256IoAir;
        native_lookup::validate_native(&io, &native::LiftedAir::spec(&io)).unwrap();
        let composed = super::Sha256Air;
        native_lookup::validate_native(&composed, &native::LiftedAir::spec(&composed)).unwrap();
    }

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
        // Pin the deployed degree independently of the AIRs being measured.
        let bound = 5;
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
