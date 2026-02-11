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

    let expected = expected_ood_evals();
    assert_eq!(builder.records().len(), expected.len());
    for (record, expected) in builder.records().iter().zip(expected.iter()) {
        assert_eq!(record.id, expected.id);
        assert_eq!(record.namespace, expected.namespace);
        assert_eq!(record.value, expected.value);
    }
    assert_eq!(builder.records().len(), CURRENT_MAX_ID + 1);
}

fn expected_ood_evals() -> [EvalRecord; 8] {
    [
        EvalRecord {
            id: 0,
            namespace: "system.clk.first_row",
            value: QuadFelt::new([Felt::new(1065013626484053923), Felt::ZERO]),
        },
        EvalRecord {
            id: 1,
            namespace: "system.clk.transition",
            value: QuadFelt::new([Felt::new(5561241394822338942), Felt::ZERO]),
        },
        EvalRecord {
            id: 2,
            namespace: "range.main.v.first_row",
            value: QuadFelt::new([Felt::new(1112338059331632069), Felt::ZERO]),
        },
        EvalRecord {
            id: 3,
            namespace: "range.main.v.last_row",
            value: QuadFelt::new([Felt::new(13352757668188868927), Felt::ZERO]),
        },
        EvalRecord {
            id: 4,
            namespace: "range.main.v.transition",
            value: QuadFelt::new([Felt::new(12797082443503681195), Felt::ZERO]),
        },
        EvalRecord {
            id: 5,
            namespace: "range.bus.first_row",
            value: QuadFelt::new([Felt::new(12608813705579209032), Felt::new(3989096837606726344)]),
        },
        EvalRecord {
            id: 6,
            namespace: "range.bus.last_row",
            value: QuadFelt::new([Felt::new(377034121616931435), Felt::new(3703916915744149174)]),
        },
        EvalRecord {
            id: 7,
            namespace: "range.bus.transition",
            value: QuadFelt::new([
                Felt::new(10365289165200035540),
                Felt::new(16469718665506609592),
            ]),
        },
    ]
}
