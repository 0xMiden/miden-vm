use alloc::vec::Vec;
use std::println;

use miden_core::{
    Felt,
    field::{PrimeCharacteristicRing, QuadFelt},
};
use miden_crypto::stark::{
    air::{MidenAir, MidenAirBuilder},
    matrix::RowMajorMatrix,
};

use super::{CURRENT_MAX_ID, EvalRecord, OodEvalAirBuilder, TagRecord, TaggedAirBuilder};
use crate::{
    ProcessorAir,
    trace::{AUX_TRACE_RAND_ELEMENTS, AUX_TRACE_WIDTH, TRACE_WIDTH},
};

/// Minimal `MidenAirBuilder` implementation for tagging tests.
///
/// This is intentionally not semantically meaningful; it only provides the shapes and types
/// needed to exercise the tagging wrappers.
struct DummyAirBuilder {
    main: RowMajorMatrix<Felt>,
    preprocessed: RowMajorMatrix<Felt>,
    permutation: RowMajorMatrix<Felt>,
    permutation_randomness: Vec<Felt>,
    aux_bus_boundary_values: Vec<Felt>,
    public_values: Vec<Felt>,
    periodic_values: Vec<Felt>,
}

impl DummyAirBuilder {
    fn new() -> Self {
        let main = RowMajorMatrix::new(vec![Felt::ZERO; TRACE_WIDTH * 2], TRACE_WIDTH);
        let preprocessed = RowMajorMatrix::new(Vec::new(), 1);
        let permutation =
            RowMajorMatrix::new(vec![Felt::ZERO; AUX_TRACE_WIDTH * 2], AUX_TRACE_WIDTH);
        let permutation_randomness = vec![Felt::ZERO; AUX_TRACE_RAND_ELEMENTS.max(1)];
        Self {
            main,
            preprocessed,
            permutation,
            permutation_randomness,
            aux_bus_boundary_values: Vec::new(),
            public_values: Vec::new(),
            periodic_values: Vec::new(),
        }
    }
}

impl MidenAirBuilder for DummyAirBuilder {
    type F = Felt;
    type Expr = Felt;
    type Var = Felt;
    type M = RowMajorMatrix<Felt>;
    type PublicVar = Felt;
    type PeriodicVal = Felt;
    type EF = Felt;
    type ExprEF = Felt;
    type VarEF = Felt;
    type MP = RowMajorMatrix<Felt>;
    type RandomVar = Felt;

    fn main(&self) -> Self::M {
        self.main.clone()
    }

    fn is_first_row(&self) -> Self::Expr {
        Felt::ONE
    }

    fn is_last_row(&self) -> Self::Expr {
        Felt::ONE
    }

    fn is_transition_window(&self, _size: usize) -> Self::Expr {
        Felt::ONE
    }

    fn assert_zero<I: Into<Self::Expr>>(&mut self, _x: I) {}

    fn assert_zero_ext<I>(&mut self, _x: I)
    where
        I: Into<Self::ExprEF>,
    {
    }

    fn public_values(&self) -> &[Self::PublicVar] {
        &self.public_values
    }

    fn periodic_evals(&self) -> &[Self::PeriodicVal] {
        &self.periodic_values
    }

    fn preprocessed(&self) -> Self::M {
        self.preprocessed.clone()
    }

    fn permutation(&self) -> Self::MP {
        self.permutation.clone()
    }

    fn permutation_randomness(&self) -> &[Self::RandomVar] {
        &self.permutation_randomness
    }

    fn aux_bus_boundary_values(&self) -> &[Self::VarEF] {
        &self.aux_bus_boundary_values
    }
}

#[test]
fn dump_constraint_ids() {
    let inner = DummyAirBuilder::new();
    let mut builder = TaggedAirBuilder::new(inner);
    let air = ProcessorAir::default();
    <ProcessorAir as MidenAir<Felt, Felt>>::eval(&air, &mut builder);

    builder.assert_complete();

    for TagRecord { id, namespace } in builder.records() {
        println!("{id} {namespace}");
    }

    assert_eq!(builder.records().len(), CURRENT_MAX_ID + 1);
}

#[test]
fn dump_constraint_ood_evals() {
    let mut builder = OodEvalAirBuilder::new(0xc0ffee);
    let air = ProcessorAir::default();
    <ProcessorAir as MidenAir<Felt, QuadFelt>>::eval(&air, &mut builder);

    builder.assert_complete();

    for EvalRecord { id, namespace, value } in builder.records() {
        println!("{id} {namespace} {value}");
    }

    assert_eq!(builder.records().len(), CURRENT_MAX_ID + 1);
}
