//! Composite AIR sharing idle sponge cells with chunk and Keccak-node records.
//!
//! Each sponge period carries one node and seven chunks. The component lookup messages
//! retain their standalone meanings; periodic selectors separate the shared payloads.

use alloc::{borrow::Cow, vec::Vec};

use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_stark::{
    air::{BaseAir, LiftedAir, LiftedAirBuilder, native},
    lookup::{LookupAir, LookupBuilder, native as native_lookup},
};
use miden_utils_sync::LazyLock;
use p3_field::Algebra;

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
    type EvalData<B: Algebra<Felt>, E: Algebra<B>> = ();

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
        .expect("valid ChunkNodeSpongeAir auxiliary inputs");
        (aux.columns, aux.exports)
    }

    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB, _data: &()) {
        native::migration::eval_source(self, builder);
    }
}

impl native::LiftedAir for ChunkNodeSpongeAir {
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
        chunk_node::eval_main(frame, builder);
        sponge::eval_main_with_shared_capacity(frame, builder, SPONGE_COL_OFFSET);

        native_lookup::eval_lookup(self, frame, inputs, builder);
    }
}

impl native::ProverAir<QuadFelt> for ChunkNodeSpongeAir {
    type Error = native_lookup::LookupError;

    fn build_aux_trace(
        &self,
        inputs: native::AuxTraceInputs<'_, Felt, QuadFelt>,
    ) -> Result<native::AuxTrace<QuadFelt>, Self::Error> {
        native_lookup::build_logup_aux_trace(self, inputs)
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
        native::migration::eval_lookup(self, builder, 0);
    }
}

impl<LB> native_lookup::LookupAir<LB> for ChunkNodeSpongeAir
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
        chunk_node::eval_lookups(frame, builder);
        sponge::eval_lookups(frame, builder, SPONGE_COL_OFFSET);
    }
}

#[cfg(test)]
mod tests {
    use alloc::{vec, vec::Vec};

    use miden_core::{Felt, field::QuadFelt};
    use miden_stark::air::native::{
        self,
        symbolic::{BaseInput, BaseLeaf, RowOffset, SymbolicExpr},
    };

    use super::{ChunkNodeSpongeAir, SPONGE_COL_OFFSET, chunk_node, sponge};
    use crate::precompiles::hash::{chunk::ChunkAir, keccak::node::KeccakNodeAir};

    #[test]
    fn native_components_and_composite_keep_shape_and_assertion_order() {
        // Capturing every component instantiates the borrowed helpers with non-Copy expressions.
        for (captured, main, aux, periodic, base, ext) in [
            (native::capture_with::<_, QuadFelt>(&ChunkAir).unwrap(), 12, 4, 0, 7, 5),
            (native::capture_with::<_, QuadFelt>(&KeccakNodeAir).unwrap(), 32, 10, 0, 11, 11),
            (
                native::capture_with::<_, QuadFelt>(&sponge::KeccakSpongeAir).unwrap(),
                40,
                5,
                11,
                55,
                6,
            ),
            (
                native::capture_with::<_, QuadFelt>(&ChunkNodeSpongeAir).unwrap(),
                47,
                7,
                21,
                84,
                8,
            ),
        ] {
            let spec = captured.descriptor.spec();
            assert_eq!((spec.main_width, spec.aux_width), (main, aux));
            assert_eq!((spec.num_public_values, spec.num_challenges, spec.num_exports), (0, 2, 1));
            assert!(spec.preprocessed.is_none());
            assert_eq!(spec.periodic_columns.len(), periodic);
            assert!(spec.periodic_columns.iter().all(|column| column.len() == 32));
            assert_eq!(captured.assertions.len(), base + ext);
            let layout = captured.descriptor.analysis().layout();
            assert_eq!(layout.base_indices(), (0..base).collect::<Vec<_>>().as_slice());
            assert_eq!(layout.ext_indices(), (base..base + ext).collect::<Vec<_>>().as_slice());
            assert!(
                captured.assertions[..base]
                    .iter()
                    .all(|a| matches!(a, native::Assertion::Base(_)))
            );
            assert!(
                captured.assertions[base..]
                    .iter()
                    .all(|a| matches!(a, native::Assertion::Extension(_)))
            );
        }
        #[cfg(feature = "std")]
        {
            use miden_stark::lookup::native::validate_native;
            use native::LiftedAir as _;
            validate_native(&ChunkAir, &ChunkAir.spec()).unwrap();
            validate_native(&KeccakNodeAir, &KeccakNodeAir.spec()).unwrap();
            validate_native(&sponge::KeccakSpongeAir, &sponge::KeccakSpongeAir.spec()).unwrap();
            validate_native(&ChunkNodeSpongeAir, &ChunkNodeSpongeAir.spec()).unwrap();
        }
    }

    #[derive(Default)]
    struct BaseValues(Vec<Felt>);

    impl native::LiftedAirBuilder for BaseValues {
        type F = Felt;
        type Expr = Felt;
        type ExtExpr = QuadFelt;

        fn emit_base(&mut self, value: Felt, _meta: native::ConstraintMeta<'_>) {
            self.0.push(value);
        }

        fn emit_ext(&mut self, _value: QuadFelt, _meta: native::ConstraintMeta<'_>) {
            panic!("ordinary sponge helper emitted an extension assertion");
        }
    }

    #[test]
    fn shared_capacity_changes_only_the_two_zero_fill_factors() {
        let mut local = [Felt::ZERO; sponge::NUM_MAIN_COLS];
        local[sponge::CHUNK_BYTES_RANGE.start] = Felt::from_u8(3);
        local[sponge::CHUNK_BYTES_RANGE.start + 4] = Felt::from_u8(5);
        let program = sponge::sponge_program();
        // Capacity row, then an extra row: only the first permits shared payload cells.
        for slot in [24, 26] {
            let periodic: [Felt; sponge::NUM_PERIODIC_COLS] =
                core::array::from_fn(|i| program[i][slot]);
            let frame = native::AirFrame {
                main: native::Rows { current: &local, next: &local },
                preprocessed: native::Rows { current: &[], next: &[] },
                aux: native::Rows { current: &[], next: &[] },
                periodic: &periodic,
                selectors: native::Selectors {
                    first: Felt::ZERO,
                    last: Felt::ZERO,
                    transition: Felt::ONE,
                },
            };
            let mut normal = BaseValues::default();
            let mut shared = BaseValues::default();
            sponge::eval_main(&frame, &mut normal, SPONGE_COL_OFFSET);
            sponge::eval_main_with_shared_capacity(&frame, &mut shared, SPONGE_COL_OFFSET);
            assert_eq!(normal.0.len(), 55);
            assert_eq!(shared.0.len(), 55);
            assert_eq!(&normal.0[23..25], &[Felt::from_u8(3), Felt::from_u8(5)]);
            let expected = if slot == 24 {
                [Felt::ZERO, Felt::ZERO]
            } else {
                [Felt::from_u8(3), Felt::from_u8(5)]
            };
            assert_eq!(&shared.0[23..25], &expected);
            for ordinal in (0..55).filter(|i| !(23..25).contains(i)) {
                assert_eq!(normal.0[ordinal], shared.0[ordinal]);
            }
        }
    }

    fn input_addresses(
        expr: &native::symbolic::SymbolicExpression<Felt>,
        out: &mut Vec<BaseInput>,
    ) {
        match expr {
            SymbolicExpr::Leaf(BaseLeaf::Input(input)) => out.push(*input),
            SymbolicExpr::Leaf(_) => {},
            SymbolicExpr::Add { x, y, .. }
            | SymbolicExpr::Sub { x, y, .. }
            | SymbolicExpr::Mul { x, y, .. } => {
                input_addresses(x, out);
                input_addresses(y, out);
            },
            SymbolicExpr::Neg { x, .. } => input_addresses(x, out),
        }
    }

    #[test]
    fn composite_preserves_periodic_concatenation_and_physical_chunk_head_cells() {
        let captured = native::capture_with::<_, QuadFelt>(&ChunkNodeSpongeAir).unwrap();
        let periodic = &captured.descriptor.spec().periodic_columns;
        assert_eq!(&periodic[..11], sponge::sponge_program().as_slice());
        assert_eq!(&periodic[11..], chunk_node::periodic_columns());
        let current = |index| BaseInput::Main { offset: RowOffset::Current, index };
        let next = |index| BaseInput::Main { offset: RowOffset::Next, index };
        // Capacity and late payload rows use different physical cells for logical is_head.
        for (ordinal, expected) in [
            (23, vec![BaseInput::Periodic(18), current(16), current(16)]),
            (25, vec![BaseInput::Periodic(17), next(16), next(44), current(44)]),
            (26, vec![BaseInput::Periodic(19), current(14), current(14)]),
            (
                28,
                vec![
                    BaseInput::Periodic(20),
                    BaseInput::Periodic(17),
                    next(14),
                    next(44),
                    current(44),
                ],
            ),
        ] {
            let native::Assertion::Base(expr) = &captured.assertions[ordinal] else {
                panic!("chunk/node ordinary assertion changed class");
            };
            let mut addresses = Vec::new();
            input_addresses(expr, &mut addresses);
            assert_eq!(addresses, expected);
        }
    }
}
