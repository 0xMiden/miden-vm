//! Recording builder for capturing AIR constraints.
//!
//! `RecordingAirBuilder` feeds symbolic variables into the AIR so we can
//! capture the exact constraint expressions and their ordering. This keeps the
//! generated DAG stable and aligned with the verifier logic.

use core::marker::PhantomData;

use miden_crypto::{
    field::{ExtensionField, Field},
    stark::{
        air::{
            AirBuilder, EmptyWindow, ExtensionBuilder, PeriodicAirBuilder, PermutationAirBuilder,
        },
        matrix::RowMajorMatrix,
    },
};

use crate::symbolic::{Entry, SymExpr, SymVar};

/// Transition constraints are defined over a 2-row window.
const TRANSITION_WINDOW_SIZE: usize = 2;

/// Records constraints in order while providing symbolic inputs.
#[derive(Debug)]
pub struct RecordingAirBuilder<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    _preprocessed: RowMajorMatrix<SymVar<EF>>,
    main: RowMajorMatrix<SymVar<EF>>,
    aux: RowMajorMatrix<SymVar<EF>>,
    aux_randomness: Vec<SymVar<EF>>,
    aux_values: Vec<SymVar<EF>>,
    public_values: Vec<SymVar<EF>>,
    periodic_values: Vec<SymVar<EF>>,
    constraints: Vec<SymExpr<EF>>,
    _phantom: PhantomData<F>,
}

impl<F, EF> RecordingAirBuilder<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    /// Create a recording builder with the given widths and counts.
    pub fn new(
        preprocessed_width: usize,
        width: usize,
        aux_width: usize,
        num_randomness: usize,
        num_public_values: usize,
        num_periodic_values: usize,
        num_aux_values: usize,
    ) -> Self {
        let prep_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..preprocessed_width)
                    .map(move |index| SymVar::new(Entry::Preprocessed { offset }, index))
            })
            .collect();
        let main_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..width).map(move |index| SymVar::new(Entry::Main { offset }, index))
            })
            .collect();
        let aux_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..aux_width).map(move |index| SymVar::new(Entry::Aux { offset }, index))
            })
            .collect();
        let aux = RowMajorMatrix::new(aux_values, aux_width);
        let aux_randomness =
            (0..num_randomness).map(|index| SymVar::new(Entry::Challenge, index)).collect();
        let aux_values = (0..num_aux_values)
            .map(|index| SymVar::new(Entry::AuxBusBoundary, index))
            .collect();
        let public_values =
            (0..num_public_values).map(|index| SymVar::new(Entry::Public, index)).collect();
        let periodic_values = (0..num_periodic_values)
            .map(|index| SymVar::new(Entry::Periodic, index))
            .collect();
        Self {
            _preprocessed: RowMajorMatrix::new(prep_values, preprocessed_width),
            main: RowMajorMatrix::new(main_values, width),
            aux,
            aux_randomness,
            aux_values,
            public_values,
            periodic_values,
            constraints: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Return the recorded constraint list in evaluation order.
    pub fn constraints(&self) -> &[SymExpr<EF>] {
        &self.constraints
    }
}

// --- AirBuilder impl ---

impl<F, EF> AirBuilder for RecordingAirBuilder<F, EF>
where
    F: Field + Sync,
    EF: ExtensionField<F>,
{
    type F = F;
    type Expr = SymExpr<EF>;
    type Var = SymVar<EF>;
    type PreprocessedWindow = EmptyWindow<Self::Var>;
    type MainWindow = RowMajorMatrix<Self::Var>;
    type PublicVar = SymVar<EF>;

    fn main(&self) -> Self::MainWindow {
        self.main.clone()
    }

    fn preprocessed(&self) -> &Self::PreprocessedWindow {
        EmptyWindow::empty_ref()
    }

    fn is_first_row(&self) -> Self::Expr {
        SymExpr::IsFirstRow
    }

    fn is_last_row(&self) -> Self::Expr {
        SymExpr::IsLastRow
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == TRANSITION_WINDOW_SIZE {
            SymExpr::IsTransition
        } else {
            panic!("ace-codegen only supports a window size of {TRANSITION_WINDOW_SIZE}")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        self.constraints.push(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }
}

// --- ExtensionBuilder impl ---

impl<F, EF> ExtensionBuilder for RecordingAirBuilder<F, EF>
where
    F: Field + Sync,
    EF: ExtensionField<F>,
{
    type EF = EF;
    type ExprEF = SymExpr<EF>;
    type VarEF = SymVar<EF>;

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.constraints.push(x.into());
    }
}

// --- PermutationAirBuilder impl ---

impl<F, EF> PermutationAirBuilder for RecordingAirBuilder<F, EF>
where
    F: Field + Sync,
    EF: ExtensionField<F>,
{
    type MP = RowMajorMatrix<Self::VarEF>;
    type RandomVar = SymVar<EF>;
    type PermutationVar = SymVar<EF>;

    fn permutation(&self) -> Self::MP {
        self.aux.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.aux_randomness
    }

    fn permutation_values(&self) -> &[Self::PermutationVar] {
        &self.aux_values
    }
}

// --- PeriodicAirBuilder impl ---

impl<F, EF> PeriodicAirBuilder for RecordingAirBuilder<F, EF>
where
    F: Field + Sync,
    EF: ExtensionField<F>,
{
    type PeriodicVar = SymVar<EF>;

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}
