//! Degree-table expectations come from fresh authored symbolic evaluation, never production tables.

use std::borrow::Cow;

use miden_air::{precompile, vm};
use miden_core::{Felt, field::QuadFelt, utils::RowMajorMatrix};
use miden_crypto::field::PrimeCharacteristicRing;
use miden_stark::{
    air::{BaseAir, ConstraintDegrees, LiftedAir, LiftedAirBuilder, WindowAccess},
    capture::ir::{capture, constraint_degrees},
};

#[test]
fn vm_degrees_match_independent_authored_symbolic_evaluation() {
    for air in vm::AIRS {
        let source = air.source();
        let expected = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&source);
        let (graph, constraints) = capture(&source);
        assert_eq!(constraint_degrees(&graph, &constraints), expected, "{air:?}");
        assert_eq!(air.degrees(), expected, "{air:?}");
        assert_eq!(<vm::Air as LiftedAir<Felt, QuadFelt>>::constraint_degree(&air), expected);
        assert_eq!(<vm::Air as LiftedAir<Felt, Felt>>::constraint_degree(&air), expected);
        assert_eq!(ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air), expected);
    }
    // Keep const-context coverage without a second manually maintained degree snapshot.
    const LOOKUP: ConstraintDegrees = vm::Air::And8Lookup.degrees();
    assert_eq!(
        LOOKUP,
        ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&miden_air_source::vm::Air::And8Lookup,)
    );
}

#[test]
fn pvm_degrees_match_independent_authored_symbolic_evaluation() {
    assert_eq!(
        precompile::Air::all().map(|air| air.source()),
        miden_air_source::precompile::Air::all()
    );
    // Query in a different order: lookup is keyed by canonical identity, not selection position.
    for air in precompile::Air::all().into_iter().rev() {
        let source = air.source();
        let expected = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&source);
        let (graph, constraints) = capture(&source);
        assert_eq!(constraint_degrees(&graph, &constraints), expected, "{air:?}");
        assert_eq!(air.degrees(), expected, "{air:?}");
        assert_eq!(air.constraint_degree(), expected, "{air:?}");
    }
    const KECCAK: ConstraintDegrees = precompile::Air::KeccakRound.degrees();
    assert_eq!(
        KECCAK,
        ConstraintDegrees::from_air::<Felt, QuadFelt, _>(
            &miden_air_source::precompile::Air::KeccakRound,
        )
    );
}

#[test]
fn staged_degree_tables_are_fresh() {
    let tables = miden_air_source::codegen::degrees::generate();
    for ((_, generated), staged) in tables.into_iter().zip([
        include_str!("../artifacts/vm-degrees.rs"),
        include_str!("../artifacts/precompile-degrees.rs"),
    ]) {
        assert_eq!(generated, staged, "run make regenerate-constraints");
    }
}

struct DegreeProbe {
    selector: usize,
    base: bool,
    ext: bool,
    hint: Option<usize>,
}

impl BaseAir<Felt> for DegreeProbe {
    fn width(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<Felt>]> {
        Cow::Owned(vec![vec![Felt::ZERO, Felt::ONE, Felt::ONE, Felt::ZERO]])
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        self.hint
    }
}

impl LiftedAir<Felt, QuadFelt> for DegreeProbe {
    fn aux_width(&self) -> usize {
        1
    }
    fn num_aux_values(&self) -> usize {
        1
    }
    fn num_randomness(&self) -> usize {
        1
    }
    fn build_aux_trace(
        &self,
        _: &RowMajorMatrix<Felt>,
        _: &[Felt],
        _: &[Felt],
        _: &[QuadFelt],
    ) -> (RowMajorMatrix<QuadFelt>, Vec<QuadFelt>) {
        unreachable!("symbolic probe")
    }
    fn eval<AB: LiftedAirBuilder<F = Felt>>(&self, builder: &mut AB) {
        let x: AB::Expr = builder.main().current_slice()[0].into();
        let pre: AB::Expr = builder.preprocessed().next_slice()[0].into();
        let periodic: AB::Expr = builder.periodic_values()[0].into();
        let public: AB::Expr = builder.public_values()[0].into();
        let selector = match self.selector {
            0 => AB::Expr::ONE,
            1 => builder.is_first_row(),
            2 => builder.is_last_row(),
            3 => builder.is_transition(),
            _ => unreachable!(),
        };
        let expression = -(selector * (x * pre * periodic + public - AB::Expr::ONE));
        if self.base {
            builder.assert_zero(expression.clone());
        }
        if self.ext {
            let aux: AB::ExprEF = builder.permutation().current_slice()[0].into();
            let challenge: AB::ExprEF = builder.permutation_randomness()[0].into();
            let boundary: AB::ExprEF = builder.permutation_values()[0].clone().into();
            builder.assert_zero_ext(aux * expression * challenge + boundary - AB::ExprEF::ONE);
        }
    }
}

#[test]
fn captured_degrees_preserve_selectors_periodic_hints_and_empty_classes() {
    for selector in 0..4 {
        for (base, ext) in [(false, false), (true, false), (false, true), (true, true)] {
            for hint in [None, Some(0), Some(99)] {
                let air = DegreeProbe { selector, base, ext, hint };
                let (graph, constraints) = capture(&air);
                let expected = ConstraintDegrees::from_air::<Felt, QuadFelt, _>(&air);
                assert_eq!(constraint_degrees(&graph, &constraints), expected);
                let degree = if selector == 1 || selector == 2 { 4 } else { 3 };
                assert_eq!(
                    expected,
                    ConstraintDegrees {
                        base: if base { degree } else { 0 },
                        ext: if ext { degree + 1 } else { 0 },
                    }
                );
            }
        }
    }
}
