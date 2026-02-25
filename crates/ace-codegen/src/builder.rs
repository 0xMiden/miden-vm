//! Recording builder for capturing AIR constraints.
//!
//! `RecordingAirBuilder` feeds symbolic variables into the AIR so we can
//! capture the exact constraint expressions and their ordering. This keeps the
//! generated DAG stable and aligned with the verifier logic.

use p3_field::{Algebra, ExtensionField, Field};
use p3_miden_air::{MidenAirBuilder, RowMajorMatrix};
use p3_miden_uni_stark::{Entry, SymbolicExpression, SymbolicVariable};

/// Transition constraints are defined over a 2-row window.
const TRANSITION_WINDOW_SIZE: usize = 2;

/// Records constraints in order while providing symbolic inputs.
#[derive(Debug)]
pub struct RecordingAirBuilder<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
{
    preprocessed: RowMajorMatrix<SymbolicVariable<F>>,
    main: RowMajorMatrix<SymbolicVariable<F>>,
    aux: RowMajorMatrix<SymbolicVariable<F>>,
    aux_randomness: Vec<SymbolicVariable<F>>,
    aux_bus_boundary_values: Vec<SymbolicVariable<F>>,
    public_values: Vec<SymbolicVariable<F>>,
    periodic_values: Vec<SymbolicVariable<F>>,
    constraints: Vec<SymbolicExpression<EF>>,
}

impl<F, EF> RecordingAirBuilder<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    SymbolicExpression<EF>: From<SymbolicExpression<F>>,
{
    /// Create a recording builder with the given widths and counts.
    pub fn new(
        preprocessed_width: usize,
        width: usize,
        aux_width: usize,
        num_randomness: usize,
        num_public_values: usize,
        num_periodic_values: usize,
    ) -> Self {
        let prep_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..preprocessed_width)
                    .map(move |index| SymbolicVariable::new(Entry::Preprocessed { offset }, index))
            })
            .collect();
        let main_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..width).map(move |index| SymbolicVariable::new(Entry::Main { offset }, index))
            })
            .collect();
        let aux_values = [0, 1]
            .into_iter()
            .flat_map(|offset| {
                (0..aux_width).map(move |index| SymbolicVariable::new(Entry::Aux { offset }, index))
            })
            .collect();
        let aux = RowMajorMatrix::new(aux_values, aux_width);
        let aux_randomness = (0..num_randomness)
            .map(|index| SymbolicVariable::new(Entry::Challenge, index))
            .collect();
        let aux_bus_boundary_values = (0..aux_width)
            .map(|index| SymbolicVariable::new(Entry::AuxBusBoundary, index))
            .collect();
        let public_values = (0..num_public_values)
            .map(|index| SymbolicVariable::new(Entry::Public, index))
            .collect();
        let periodic_values = (0..num_periodic_values)
            .map(|index| SymbolicVariable::new(Entry::Periodic, index))
            .collect();
        Self {
            preprocessed: RowMajorMatrix::new(prep_values, preprocessed_width),
            main: RowMajorMatrix::new(main_values, width),
            aux,
            aux_randomness,
            aux_bus_boundary_values,
            public_values,
            periodic_values,
            constraints: Vec::new(),
        }
    }

    /// Return the recorded constraint list in evaluation order.
    pub fn constraints(&self) -> &[SymbolicExpression<EF>] {
        &self.constraints
    }
}

impl<F, EF> MidenAirBuilder for RecordingAirBuilder<F, EF>
where
    F: Field,
    EF: ExtensionField<F>,
    SymbolicExpression<EF>: Algebra<SymbolicExpression<F>> + From<SymbolicExpression<F>>,
{
    type F = F;
    type Expr = SymbolicExpression<F>;
    type Var = SymbolicVariable<F>;
    type M = RowMajorMatrix<Self::Var>;
    type PublicVar = SymbolicVariable<F>;
    type EF = EF;
    type ExprEF = SymbolicExpression<EF>;
    type VarEF = SymbolicVariable<F>;
    type MP = RowMajorMatrix<Self::VarEF>;
    type RandomVar = SymbolicVariable<F>;
    type PeriodicVal = SymbolicVariable<F>;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        SymbolicExpression::IsFirstRow
    }

    fn is_last_row(&self) -> Self::Expr {
        SymbolicExpression::IsLastRow
    }

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        if size == TRANSITION_WINDOW_SIZE {
            SymbolicExpression::IsTransition
        } else {
            panic!("ace-codegen only supports a window size of {TRANSITION_WINDOW_SIZE}")
        }
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, x: I) {
        let expr: SymbolicExpression<F> = x.into();
        let expr_ef: SymbolicExpression<EF> = SymbolicExpression::<EF>::from(expr);
        self.constraints.push(expr_ef);
    }

    fn assert_zero_ext<I>(&mut self, x: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.constraints.push(x.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }

    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }

    fn permutation(&self) -> Self::MP {
        self.aux.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.aux_randomness
    }

    fn aux_bus_boundary_values(&self) -> &[Self::VarEF] {
        &self.aux_bus_boundary_values
    }

    fn periodic_evals(&self) -> &[Self::PeriodicVal] {
        &self.periodic_values
    }
}
