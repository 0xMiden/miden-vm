use std::{vec, vec::Vec};

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
    utils::RowMajorMatrix,
};
use miden_crypto::stark::air::{AirBuilder, ExtensionBuilder, PermutationAirBuilder, RowWindow};
use miden_lifted_air::{BaseAir, LiftedAir};

use super::{EidosCompressionInterfaceAir, NUM_MAIN_COLS};

struct ConstraintEvalBuilder {
    main: RowMajorMatrix<Felt>,
    aux: RowMajorMatrix<QuadFelt>,
    randomness: Vec<QuadFelt>,
    permutation_values: Vec<QuadFelt>,
    public_values: Vec<Felt>,
    periodic_values: Vec<Felt>,
    base_evaluations: Vec<Felt>,
    extension_evaluations: Vec<QuadFelt>,
    preprocessed_window: RowWindow<'static, Felt>,
}

impl ConstraintEvalBuilder {
    fn inactive_row_with_zero_challenges() -> Self {
        let periodic_values = EidosCompressionInterfaceAir
            .periodic_columns()
            .iter()
            .map(|column| column[1])
            .collect();
        let mut aux = vec![QuadFelt::ZERO; 4];
        aux[1] = QuadFelt::ONE;

        Self {
            main: RowMajorMatrix::new(vec![Felt::ZERO; 2 * NUM_MAIN_COLS], NUM_MAIN_COLS),
            aux: RowMajorMatrix::new(aux, 2),
            randomness: vec![QuadFelt::ZERO; 2],
            permutation_values: vec![QuadFelt::ZERO],
            public_values: vec![Felt::ZERO; EidosCompressionInterfaceAir.num_public_values()],
            periodic_values,
            base_evaluations: Vec::new(),
            extension_evaluations: Vec::new(),
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

    fn is_transition_window(&self, size: usize) -> Self::Expr {
        assert_eq!(size, 2);
        Felt::ONE
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, value: I) {
        self.base_evaluations.push(value.into());
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }

    fn periodic_values(&self) -> &[Self::PeriodicVar] {
        &self.periodic_values
    }
}

impl ExtensionBuilder for ConstraintEvalBuilder {
    type EF = QuadFelt;
    type ExprEF = QuadFelt;
    type VarEF = QuadFelt;

    fn assert_zero_ext<I>(&mut self, value: I)
    where
        I: Into<Self::ExprEF>,
    {
        self.extension_evaluations.push(value.into());
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

#[test]
fn aux_column_one_is_pinned_on_inactive_zero_denominator_rows() {
    let mut builder = ConstraintEvalBuilder::inactive_row_with_zero_challenges();
    EidosCompressionInterfaceAir.eval(&mut builder);

    assert!(builder.base_evaluations.iter().all(|&value| value == Felt::ZERO));
    let nonzero: Vec<_> = builder
        .extension_evaluations
        .iter()
        .copied()
        .filter(|&value| value != QuadFelt::ZERO)
        .collect();
    assert_eq!(nonzero, vec![QuadFelt::ONE]);
}

#[test]
fn derived_degree_three_selectors_match_gated_products_on_valid_modes() {
    let bits = [0i32, 1];
    let mut valid_assignments = 0;

    for head in bits {
        for absorb in bits {
            for payload in bits {
                for output in bits {
                    for is_and in bits {
                        for is_chunks in bits {
                            for is_generic in bits {
                                let active = head + absorb;
                                let constraints = [
                                    head * absorb,
                                    is_and + is_chunks + is_generic - active,
                                    payload * (1 - active),
                                    output * (1 - active),
                                    head * (payload - 1),
                                    is_and * (payload - 1),
                                    is_and * (output - 1),
                                    is_chunks * (payload - 1),
                                    is_generic * (payload + output - 1),
                                ];
                                if constraints.into_iter().any(|value| value != 0) {
                                    continue;
                                }

                                valid_assignments += 1;
                                assert_eq!(active - output, active * (1 - output));
                                assert_eq!(active - payload, is_generic * output);
                            }
                        }
                    }
                }
            }
        }
    }

    assert!(valid_assignments > 0);
}
