use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_stark::air::{self, AirFrame, Rows, Selectors, UniformInputs};

use super::{get_periodic_column_values, layout::NUM_COLS};

/// Two-row numerical Eidos fixture shared by the VM and precompile tests.
pub(crate) struct EidosRowEvaluator<'a> {
    current: &'a [Felt; NUM_COLS],
    next: &'a [Felt; NUM_COLS],
    selectors: Selectors<Felt>,
    periodic: Vec<Felt>,
    pub(crate) aux: RowMajorMatrix<QuadFelt>,
    pub(crate) challenges: [QuadFelt; 2],
    pub(crate) exports: [QuadFelt; 1],
    pub(crate) evaluations: Vec<Felt>,
    pub(crate) extension_evaluations: Vec<QuadFelt>,
}

impl<'a> EidosRowEvaluator<'a> {
    pub(crate) fn new(
        current: &'a [Felt; NUM_COLS],
        next: &'a [Felt; NUM_COLS],
        row: usize,
        height: usize,
        aux_width: usize,
    ) -> Self {
        Self {
            current,
            next,
            selectors: Selectors {
                first: Felt::from_bool(row == 0),
                last: Felt::from_bool(row + 1 == height),
                transition: Felt::from_bool(row + 1 != height),
            },
            periodic: get_periodic_column_values()
                .iter()
                .map(|column| column[row % column.len()])
                .collect(),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; 2 * aux_width], aux_width),
            challenges: [QuadFelt::ZERO; 2],
            exports: [QuadFelt::ZERO],
            evaluations: Vec::new(),
            extension_evaluations: Vec::new(),
        }
    }

    pub(crate) fn periodic_values(&self) -> &[Felt] {
        &self.periodic
    }

    pub(crate) fn eval_with(
        &mut self,
        evaluate: impl FnOnce(
            &AirFrame<'_, Felt, QuadFelt>,
            UniformInputs<'_, Felt, QuadFelt>,
            &mut Evaluations<'_>,
        ),
    ) {
        let (current, next) = self.aux.values.split_at(self.aux.width);
        let frame = AirFrame {
            main: Rows { current: self.current, next: self.next },
            preprocessed: Rows { current: &[], next: &[] },
            aux: Rows { current, next },
            periodic: &self.periodic,
            selectors: self.selectors,
        };
        let inputs = UniformInputs {
            public_values: &[],
            challenges: &self.challenges,
            exports: &self.exports,
        };
        evaluate(
            &frame,
            inputs,
            &mut Evaluations {
                base: &mut self.evaluations,
                extension: &mut self.extension_evaluations,
            },
        )
    }

    pub(crate) fn into_base_evaluations(self) -> Vec<Felt> {
        assert!(self.extension_evaluations.is_empty(), "expected only base assertions");
        self.evaluations
    }
}

pub(crate) struct Evaluations<'a> {
    base: &'a mut Vec<Felt>,
    extension: &'a mut Vec<QuadFelt>,
}

impl air::LiftedAirBuilder for Evaluations<'_> {
    type F = Felt;
    type Expr = Felt;
    type ExtExpr = QuadFelt;

    fn emit_base(&mut self, value: Felt, _: air::ConstraintMeta<'_>) {
        self.base.push(value);
    }

    fn emit_ext(&mut self, value: QuadFelt, _: air::ConstraintMeta<'_>) {
        self.extension.push(value);
    }
}
