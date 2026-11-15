use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_stark::air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};
use p3_matrix::dense::RowMajorMatrix;

use crate::vm::trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH};

pub(in crate::vm::constraints) struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    pub(in crate::vm::constraints) evaluations: Vec<QuadFelt>,
    preprocessed_window: RowWindow<'static, Felt>,
    first_row: Felt,
    last_row: Felt,
    transition: Felt,
}

impl ConstraintEvalBuilder {
    pub(in crate::vm::constraints) fn new() -> Self {
        Self {
            main: RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * 2], TRACE_WIDTH),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2], AUX_TRACE_WIDTH),
            randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
            permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
            periodic_values: Vec::new(),
            evaluations: Vec::new(),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
            first_row: Felt::ZERO,
            last_row: Felt::ZERO,
            transition: Felt::ONE,
        }
    }

    pub(in crate::vm::constraints) fn with_row_flags(
        mut self,
        first_row: bool,
        last_row: bool,
        transition: bool,
    ) -> Self {
        self.first_row = Felt::from_bool(first_row);
        self.last_row = Felt::from_bool(last_row);
        self.transition = Felt::from_bool(transition);
        self
    }

    pub(in crate::vm::constraints) fn with_periodic_values(mut self, values: Vec<Felt>) -> Self {
        self.periodic_values = values;
        self
    }
}

impl AirBuilder for ConstraintEvalBuilder {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;
    type PreprocessedWindow = RowWindow<'static, Felt>;
    type MainWindow = RowMajorMatrix<Felt>;
    type PublicVar = Felt;
    type PeriodicVar = Felt;

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        &self.preprocessed_window
    }

    fn is_first_row(&self) -> Self::Expr {
        self.first_row
    }

    fn is_last_row(&self) -> Self::Expr {
        self.last_row
    }

    fn is_transition(&self) -> Self::Expr {
        self.transition
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2, "constraint tests use two-row transition windows");
        self.is_transition()
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.evaluations.push(QuadFelt::from(x.into()));
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &[]
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}

impl ExtensionBuilder for ConstraintEvalBuilder {
    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.evaluations.push(x.into());
    }
}

impl PermutationAirBuilder for ConstraintEvalBuilder {
    type MP = RowMajorMatrix<QuadFelt>;
    type RandomVar = QuadFelt;
    type PermutationVar = QuadFelt;

    fn permutation(&self) -> Self::MP {
        self.aux.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.randomness
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.permutation_values
    }
}

/// Numerical immutable input context for helpers with a separate native assertion sink.
pub(in crate::vm::constraints) struct ConstraintEvalContext {
    selectors: miden_stark::air::native::Selectors<Felt>,
}

impl ConstraintEvalContext {
    pub(in crate::vm::constraints) fn new() -> Self {
        Self {
            selectors: miden_stark::air::native::Selectors {
                first: Felt::ZERO,
                last: Felt::ZERO,
                transition: Felt::ONE,
            },
        }
    }

    pub(in crate::vm::constraints) fn with_row_flags(
        mut self,
        first: bool,
        last: bool,
        transition: bool,
    ) -> Self {
        self.selectors = miden_stark::air::native::Selectors {
            first: Felt::from_bool(first),
            last: Felt::from_bool(last),
            transition: Felt::from_bool(transition),
        };
        self
    }

    pub(in crate::vm::constraints) fn frame<'a>(
        &self,
        local: &'a super::columns::CoreCols<Felt>,
        next: &'a super::columns::CoreCols<Felt>,
    ) -> miden_stark::air::native::AirFrame<'a, Felt, QuadFelt> {
        use miden_stark::air::native::{AirFrame, Rows};
        AirFrame {
            main: Rows {
                current: local.as_slice(),
                next: next.as_slice(),
            },
            preprocessed: Rows { current: &[], next: &[] },
            aux: Rows { current: &[], next: &[] },
            periodic: &[],
            selectors: self.selectors,
        }
    }
}

/// Numerical sink with no row, selector, or uniform input access.
#[derive(Default)]
pub(in crate::vm::constraints) struct NativeConstraintEvalBuilder {
    pub(in crate::vm::constraints) evaluations: Vec<QuadFelt>,
}

impl miden_stark::air::native::LiftedAirBuilder for NativeConstraintEvalBuilder {
    type F = Felt;
    type Expr = Felt;
    type ExtExpr = QuadFelt;

    fn emit_base(&mut self, value: Felt, _: miden_stark::air::native::ConstraintMeta<'_>) {
        self.evaluations.push(value.into());
    }

    fn emit_ext(&mut self, value: QuadFelt, _: miden_stark::air::native::ConstraintMeta<'_>) {
        self.evaluations.push(value);
    }
}
