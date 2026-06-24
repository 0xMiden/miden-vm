use alloc::vec::Vec;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::stark::{
    air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow},
    matrix::RowMajorMatrix,
};

use crate::trace::{AUX_TRACE_RAND_CHALLENGES, AUX_TRACE_WIDTH, TRACE_WIDTH};

pub(super) struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    periodic_values: Vec<Felt>,
    pub(super) evaluations: Vec<QuadFelt>,
    preprocessed_window: RowWindow<'static, Felt>,
}

impl ConstraintEvalBuilder {
    pub(super) fn new() -> Self {
        Self {
            main: RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * 2], TRACE_WIDTH),
            aux: RowMajorMatrix::new(vec![QuadFelt::ZERO; AUX_TRACE_WIDTH * 2], AUX_TRACE_WIDTH),
            randomness: vec![QuadFelt::ZERO; AUX_TRACE_RAND_CHALLENGES],
            permutation_values: vec![QuadFelt::ZERO; AUX_TRACE_WIDTH],
            periodic_values: Vec::new(),
            evaluations: Vec::new(),
            preprocessed_window: RowWindow::from_two_rows(&[], &[]),
        }
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
        Felt::ZERO
    }

    fn is_last_row(&self) -> Self::Expr {
        Felt::ZERO
    }

    fn is_transition(&self) -> Self::Expr {
        Felt::ONE
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
