use super::*;
use alloc::collections::BTreeSet;
use p3_field::{
    Algebra, BasedVectorSpace, Dup, PrimeCharacteristicRing, extension::BinomialExtensionField,
};
use p3_goldilocks::Goldilocks;

type F = Goldilocks;
type EF = BinomialExtensionField<F, 2>;
type B = SymbolicExpression<F, EF>;
type E = SymbolicExpressionExt<F, EF>;
fn x() -> B {
    BaseInput::Main { row: RowOffset::Current, column: 0 }.into()
}
fn y() -> B {
    BaseInput::Main { row: RowOffset::Next, column: 1 }.into()
}
fn z() -> E {
    AuxInput::Trace { row: RowOffset::Current, column: 0 }.into()
}
fn evaluate<D: Domain>(expression: &Expr<F, EF, D>) -> EF {
    expression.evaluate(|_, view| match view {
        ExprView::BaseConstant(value) => (*value).into(),
        ExprView::ExtensionConstant(value) => *value,
        ExprView::BaseInput(input) => F::new(input.index() as u64 + 2).into(),
        ExprView::AuxInput(input) => EF::from_basis_coefficients_fn(|i| {
            if i == 0 {
                F::new(input.index() as u64 + 5)
            } else {
                F::ONE
            }
        }),
        ExprView::IsFirstRow | ExprView::IsLastRow | ExprView::IsTransition => EF::ONE,
        _ => panic!("evaluation callback only receives leaves"),
    })
}

fn assert_wire_roundtrip<D: Domain>(expression: &Expr<F, EF, D>, expected: EF) -> Expr<F, EF, D> {
    let wire = serde_json::to_value(expression).unwrap();
    let restored: Expr<F, EF, D> = serde_json::from_value(wire.clone()).unwrap();
    assert_eq!(evaluate(expression), expected);
    assert_eq!(evaluate(&restored), expected);
    assert_eq!(restored.as_ref().domain(), expression.as_ref().domain());
    assert_eq!(restored.degree_multiple(), expression.degree_multiple());
    assert_eq!(serde_json::to_value(&restored).unwrap(), wire);
    restored
}

#[test]
fn ring_overrides_capture_merged_nodes_and_evaluate() {
    let a = x();
    let b = y();
    let av = EF::from(F::new(2));
    let bv = EF::from(F::new(3));
    let cases = [
        (a.dup() + b.dup(), av + bv),
        (a.dup() - b.dup(), av - bv),
        (a.dup() * b.dup(), av * bv),
        (-a.dup(), -av),
        (a.double(), av.double()),
        (a.halve(), av.halve()),
        (a.square(), av.square()),
        (a.cube(), av.cube()),
        (a.exp_u64(7), av.exp_u64(7)),
        (a.exp_const_u64::<7>(), av.exp_u64(7)),
        (a.exp_power_of_2(3), av.exp_u64(8)),
        (a.mul_2exp_u64(5), av * EF::from(F::new(32))),
        (a.div_2exp_u64(5), av / EF::from(F::new(32))),
        (a.bool_check(), av * (av - EF::ONE)),
        (a.xor(&b), av + bv - (av * bv).double()),
        (a.xor3(&b, &a), av.xor(&bv).xor(&av)),
        (a.andn(&b), (EF::ONE - av) * bv),
    ];
    for (expression, expected) in cases {
        assert_wire_roundtrip(&expression, expected);
    }
    assert!(matches!(a.square().view(), ExprView::Exp { power: 2, .. }));
    assert!(matches!(a.cube().view(), ExprView::Exp { power: 3, .. }));
    assert!(matches!(a.double().view(), ExprView::ScalePow2 { exponent: 1, .. }));
    assert!(matches!(a.halve().view(), ExprView::ScalePow2 { exponent: -1, .. }));
    assert!(matches!(a.bool_check().view(), ExprView::BoolCheck { .. }));
}

#[test]
fn reduction_nodes_preserve_operations_and_empty_identities() {
    let values = [x(), y()];
    let sum = B::sum_array::<2>(&values);
    let product: B = values.clone().into_iter().product();
    let homogeneous = B::dot_product(&values, &values);
    let coefficients = [F::new(7), F::new(11)];
    let mixed = <B as Algebra<F>>::mixed_dot_product(&values, &coefficients);
    let batched = <B as Algebra<F>>::batched_linear_combination(&values, &coefficients);
    assert!(matches!(sum.view(), ExprView::Sum { .. }));
    assert!(matches!(product.view(), ExprView::Product { .. }));
    assert!(matches!(homogeneous.view(), ExprView::LinearCombination { .. }));
    for value in [&mixed, &batched] {
        assert!(matches!(value.view(), ExprView::LinearCombination { .. }));
        assert_wire_roundtrip(value, EF::from(F::new(47)));
    }
    assert_wire_roundtrip(&sum, EF::from(F::new(5)));
    assert_wire_roundtrip(&product, EF::from(F::new(6)));
    assert_wire_roundtrip(&homogeneous, EF::from(F::new(13)));
    assert_eq!(evaluate(&core::iter::empty::<B>().sum::<B>()), EF::ZERO);
    assert_eq!(evaluate(&core::iter::empty::<B>().product::<B>()), EF::ONE);
    assert_eq!(evaluate(&B::sum_array::<0>(&[])), EF::ZERO);
}

#[test]
fn mixed_operators_normalize_constants_and_lift_dynamic_base_values() {
    let mut a = z();
    a += x();
    assert!(
        matches!(a.view(), ExprView::Add { y, .. } if matches!(y.view(), ExprView::Lift { value } if value.domain() == ExpressionDomain::Base))
    );
    a *= F::new(3);
    assert!(
        matches!(a.view(), ExprView::Mul { y, .. } if y.domain() == ExpressionDomain::Extension && matches!(y.view(), ExprView::BaseConstant(c) if *c == F::new(3)))
    );
    let extension_scalar = EF::from_basis_coefficients_fn(|i| F::new(i as u64 + 1));
    a -= extension_scalar;
    assert!(
        matches!(a.view(), ExprView::Sub { y, .. } if matches!(y.view(), ExprView::ExtensionConstant(_)))
    );
    assert_eq!(
        evaluate(&a),
        (evaluate(&z()) + evaluate(&x())) * EF::from(F::new(3)) - extension_scalar
    );
    let lifted: E = x().into();
    assert!(matches!(lifted.view(), ExprView::Lift { .. }));
    assert_eq!(evaluate(&lifted.to_base().unwrap()), evaluate(&x()));
    assert!(z().to_base().is_none());
}

#[test]
fn compound_base_only_extension_expressions_recover_base_operations() {
    let a = E::from(x());
    let b = E::from(y());
    let values = [a.clone(), b.clone()];
    let cases = [
        (a.clone() + b.clone(), F::new(5)),
        (a.clone() - b.clone(), -F::ONE),
        (a.clone() * b.clone(), F::new(6)),
        (-a.clone(), -F::new(2)),
        (values.iter().cloned().sum::<E>(), F::new(5)),
        (values.iter().cloned().product::<E>(), F::new(6)),
        (E::dot_product(&values, &values), F::new(13)),
        (a.exp_u64(5), F::new(32)),
        (a.exp_power_of_2(3), F::new(256)),
        (a.mul_2exp_u64(4), F::new(32)),
        (a.div_2exp_u64(3), F::ONE / F::new(4)),
        (a.bool_check(), F::new(2)),
    ];
    for (expression, expected) in cases {
        let recovered = expression.to_base().expect("all leaves belong to the base field");
        assert_eq!(evaluate(&expression), EF::from(expected));
        assert_eq!(evaluate(&recovered), EF::from(expected));
        assert_eq!(recovered.degree_multiple(), expression.degree_multiple());
        recovered.as_ref().fold(|node, view, _: &[()]| {
            assert_eq!(node.domain(), ExpressionDomain::Base);
            assert!(!matches!(view, ExprView::Lift { .. }));
        });
    }

    let shared = a + b;
    let recovered = (shared.clone() * shared).to_base().unwrap();
    match recovered.view() {
        ExprView::Mul { x, y } => {
            assert!(x.identity().is_some());
            assert_eq!(x.identity(), y.identity());
        },
        _ => panic!("expected shared multiplication"),
    }
    let non_base = EF::from_basis_coefficients_fn(|_| F::ONE);
    for expression in [
        z(),
        z() + x(),
        E::extension_constant(non_base),
        E::dot_product(&[E::from(x())], &[E::extension_constant(non_base)]),
    ] {
        assert!(expression.to_base().is_none(), "extension-only leaves cannot be converted");
    }
}

fn assert_same_normal_form<D: Domain>(expressions: &[Expr<F, EF, D>]) {
    let expected = serde_json::to_value(&expressions[0]).unwrap();
    let expected_value = evaluate(&expressions[0]);
    for expression in expressions {
        assert_eq!(serde_json::to_value(expression).unwrap(), expected);
        assert_eq!(evaluate(expression), expected_value);
    }
}

#[test]
fn coefficient_constant_spellings_have_one_normal_form() {
    let c = F::new(7);
    assert_same_normal_form(&[x() * c, x() * B::from(c)]);
    assert_same_normal_form(&[
        z() * c,
        z() * B::from(c),
        z() * E::from(c),
        z() * EF::from(c),
        z() * E::extension_constant(EF::from(c)),
    ]);
    assert_same_normal_form(&[z() * x(), z() * E::from(x())]);
    for expression in [
        E::from(c),
        E::from(B::from(c)),
        E::from(EF::from(c)),
        E::extension_constant(EF::from(c)),
    ] {
        assert_eq!(expression.as_ref().domain(), ExpressionDomain::Extension);
        assert!(matches!(expression.view(), ExprView::BaseConstant(value) if *value == c));
    }
    let genuine = EF::from_basis_coefficients_fn(|i| if i == 0 { c } else { F::ONE });
    assert!(
        matches!(E::extension_constant(genuine).view(), ExprView::ExtensionConstant(value) if *value == genuine)
    );
}

#[test]
fn linear_combination_coefficients_normalize_into_the_result_domain() {
    let constants = [F::new(7), F::new(11)];
    let base_values = [x(), y()];
    let base_constants = constants.map(B::from);
    assert_same_normal_form(&[
        B::dot_product(&base_values, &base_constants),
        <B as Algebra<F>>::mixed_dot_product(&base_values, &constants),
        <B as Algebra<F>>::batched_linear_combination(&base_values, &constants),
    ]);
    let extension_values = [z(), z() + y()];
    assert_same_normal_form(&[
        E::dot_product(&extension_values, &constants.map(E::from)),
        <E as Algebra<F>>::mixed_dot_product(&extension_values, &constants),
        <E as Algebra<B>>::mixed_dot_product(&extension_values, &base_constants),
        <E as Algebra<EF>>::mixed_dot_product(&extension_values, &constants.map(EF::from)),
        <E as Algebra<F>>::batched_linear_combination(&extension_values, &constants),
        <E as Algebra<B>>::batched_linear_combination(&extension_values, &base_constants),
        <E as Algebra<EF>>::batched_linear_combination(&extension_values, &constants.map(EF::from)),
    ]);
    let dynamic = <E as Algebra<B>>::mixed_dot_product(&extension_values, &base_values);
    assert_same_normal_form(&[
        dynamic.clone(),
        E::dot_product(&extension_values, &[E::from(x()), E::from(y())]),
    ]);
    match dynamic.view() {
        ExprView::LinearCombination { values, coefficients } => {
            assert!(values.iter().all(|value| value.domain() == ExpressionDomain::Extension));
            assert!(coefficients.iter().all(|coefficient| matches!(coefficient.view(), ExprView::Lift { value } if value.domain() == ExpressionDomain::Base)));
        },
        _ => panic!("expected linear combination"),
    }
}

#[test]
fn quadratic_square_uses_default_arithmetic_and_symbolic_non_residue_degree() {
    let inputs = [z(), z() + y()];
    let w = x().square();
    let outputs = <E as Algebra<B>>::quadratic_extension_square(&inputs, w.clone());
    assert!(matches!(outputs[0].view(), ExprView::LinearCombination { .. }));
    assert!(matches!(outputs[1].view(), ExprView::Mul { .. }));
    assert_eq!(outputs[0].degree_multiple(), 4);
    assert_eq!(outputs[1].degree_multiple(), 2);
    let a0 = evaluate(&inputs[0]);
    let a1 = evaluate(&inputs[1]);
    assert_eq!(evaluate(&outputs[0]), a0.square() + evaluate(&w) * a1.square());
    assert_eq!(evaluate(&outputs[1]), (a0 * a1).double());

    let other_outputs = <E as Algebra<B>>::quadratic_extension_square(&inputs, x().cube());
    assert_eq!(other_outputs[0].degree_multiple(), 5);
    assert_eq!(other_outputs[1].degree_multiple(), 2);
    assert_eq!(evaluate(&other_outputs[1]), evaluate(&outputs[1]));
    outputs[1].as_ref().fold(|_, view, _: &[()]| {
        assert!(!matches!(view, ExprView::BaseInput(BaseInput::Main { column: 0, .. })));
    });
    assert_eq!(
        serde_json::to_value(&outputs[1]).unwrap(),
        serde_json::to_value(&other_outputs[1]).unwrap()
    );

    let shared = outputs[0].clone() + outputs[1].clone();
    let combined = shared.clone() * shared;
    let wire = serde_json::to_value(&combined).unwrap();
    let restored: E = serde_json::from_value(wire).unwrap();
    match restored.view() {
        ExprView::Mul { x, y, .. } => assert_eq!(x.identity(), y.identity()),
        _ => panic!("expected multiplication of shared scalar expressions"),
    }
    assert_eq!(evaluate(&restored), evaluate(&combined));
}

#[test]
fn full_extension_constants_fold_without_requiring_base_membership() {
    let constant = EF::from_basis_coefficients_fn(|i| F::new(i as u64 + 2));
    let expression = E::extension_constant(constant).square() + E::extension_constant(constant);
    assert!(matches!(
        expression.view(),
        ExprView::ExtensionConstant(_) | ExprView::BaseConstant(_)
    ));
    assert_eq!(evaluate(&expression), constant.square() + constant);
    assert_eq!(expression.degree_multiple(), 0);
}

#[test]
fn degree_profiles_use_checked_multiplication_and_source_domains() {
    assert_eq!(x().checked_poly_degree(8, &[]), Ok(7));
    assert_eq!(x().square().checked_poly_degree(8, &[]), Ok(14));
    assert_eq!(x().exp_u64(8).checked_poly_degree(8, &[]), Ok(56));
    assert_eq!(x().exp_power_of_2(3).checked_poly_degree(8, &[]), Ok(56));
    let expression = (x() + B::is_transition()).square();
    assert_eq!(expression.degree_multiple(), 2);
    assert_eq!(expression.poly_degree(8, &[]), 14);
    assert_eq!(B::is_transition().degree_multiple_with_transition(1), 1);
    let large = x().exp_power_of_2(usize::BITS as usize - 1);
    assert_eq!(large.checked_poly_degree(3, &[]), Err(ExpressionError::DegreeOverflow));
    let public: B = BaseInput::Public { index: 0 }.into();
    assert_eq!(public.checked_poly_degree(8, &[]), Ok(0));
    assert_eq!(public.exp_power_of_2(usize::MAX).degree_multiple(), 0);
    assert_eq!(public.exp_power_of_2(usize::MAX).checked_poly_degree(8, &[]), Ok(0));
    assert_eq!(public.exp_u64(u64::MAX).checked_poly_degree(8, &[]), Ok(0));
    let expression = E::from(x()).square();
    assert_eq!(expression.as_ref().domain(), ExpressionDomain::Extension);
    assert_eq!(evaluate(&expression), EF::from(F::new(4)));
}

#[test]
fn checked_degree_reuses_shared_subtrees_and_propagates_leaf_errors() {
    let shared = x().square();
    let expression = shared.clone() + shared;
    let mut visits = 0;
    assert_eq!(
        expression.as_ref().checked_degree_with(|_, _| {
            visits += 1;
            Ok(3)
        }),
        Ok(6)
    );
    assert_eq!(visits, 1);
    assert_eq!(
        expression
            .as_ref()
            .checked_degree_with(|_, _| Err(ExpressionError::DegreeOverflow)),
        Err(ExpressionError::DegreeOverflow)
    );
}

#[test]
fn fold_and_wire_preserve_sharing_at_the_operation_root() {
    let shared = x() * y();
    let root = shared.clone() + shared;
    let mut ids = BTreeSet::new();
    root.as_ref().fold(|expression, _, _: &[()]| {
        if let Some(id) = expression.identity() {
            assert!(ids.insert(id));
        }
    });
    assert_eq!(ids.len(), 2);
    let wire = serde_json::to_value(&root).unwrap();
    assert_eq!(wire["version"], 2);
    assert!(!serde_json::to_string(&wire).unwrap().contains("degree_multiple"));
    let restored: B = serde_json::from_value(wire).unwrap();
    match restored.view() {
        ExprView::Add { x, y, .. } => assert_eq!(x.identity(), y.identity()),
        _ => panic!("expected addition"),
    }
    assert_eq!(evaluate(&restored), evaluate(&root));
}

#[test]
fn current_wire_preserves_extension_domains_leaves_and_shared_operations() {
    let base_value = EF::from(F::new(2));
    let extension_value =
        EF::from_basis_coefficients_fn(|i| if i == 0 { F::new(5) } else { F::ONE });
    let constant = EF::from_basis_coefficients_fn(|i| F::new(i as u64 + 7));
    let a = z();
    let b = E::from(x());
    let values = [a.clone(), b.clone()];
    let cases = [
        (b.clone(), base_value),
        (a.clone() + b.clone(), extension_value + base_value),
        (a.clone() - b.clone(), extension_value - base_value),
        (a.clone() * b.clone(), extension_value * base_value),
        (-a.clone(), -extension_value),
        (values.iter().cloned().sum::<E>(), extension_value + base_value),
        (values.iter().cloned().product::<E>(), extension_value * base_value),
        (E::dot_product(&values, &values), extension_value.square() + base_value.square()),
        (a.exp_u64(5), extension_value.exp_u64(5)),
        (a.exp_power_of_2(3), extension_value.exp_u64(8)),
        (a.mul_2exp_u64(4), extension_value * EF::from(F::new(16))),
        (a.div_2exp_u64(3), extension_value / EF::from(F::new(8))),
        (a.bool_check(), extension_value * (extension_value - EF::ONE)),
    ];
    for (operation, expected) in cases {
        let root = operation.clone() + operation;
        let restored = assert_wire_roundtrip(&root, expected.double());
        match restored.view() {
            ExprView::Add { x, y } => {
                assert_eq!(x.domain(), ExpressionDomain::Extension);
                assert_eq!(y.domain(), ExpressionDomain::Extension);
                assert!(x.identity().is_some());
                assert_eq!(x.identity(), y.identity());
            },
            _ => panic!("expected two references to a shared operation"),
        }
    }
    for (expression, expected) in [
        (E::from(F::new(7)), EF::from(F::new(7))),
        (E::extension_constant(constant), constant),
        (z(), extension_value),
        (E::from(B::is_first_row()), EF::ONE),
        (E::from(B::is_last_row()), EF::ONE),
        (E::from(B::is_transition()), EF::ONE),
    ] {
        assert_wire_roundtrip(&expression, expected);
    }
}

#[test]
fn version_two_wire_rejects_bad_domains_references_lengths_and_degrees() {
    let original = serde_json::to_value(x() + y()).unwrap();
    let mut old = original.clone();
    old["version"] = 1.into();
    assert!(serde_json::from_value::<B>(old).is_err());
    let mut forward = original.clone();
    let root = forward["root"].as_u64().unwrap();
    forward["nodes"][root as usize]["op"]["Add"]["x"] = root.into();
    assert!(serde_json::from_value::<B>(forward).is_err());
    let mut domain = original;
    domain["nodes"][root as usize]["domain"] = "Extension".into();
    assert!(serde_json::from_value::<B>(domain).is_err());
    let values = [x(), y()];
    let mut lengths = serde_json::to_value(B::dot_product(&values, &values)).unwrap();
    let root = lengths["root"].as_u64().unwrap() as usize;
    lengths["nodes"][root]["op"]["LinearCombination"]["coefficients"]
        .as_array_mut()
        .unwrap()
        .pop();
    assert!(serde_json::from_value::<B>(lengths).is_err());
    let mut overflow = serde_json::to_value(x().exp_power_of_2(2)).unwrap();
    let root = overflow["root"].as_u64().unwrap() as usize;
    overflow["nodes"][root]["op"]["ExpPowerOf2"]["power_log"] = u64::from(usize::BITS).into();
    assert!(serde_json::from_value::<B>(overflow).is_err());
}

#[test]
fn signed_scaling_preserves_the_full_u64_magnitude() {
    for expression in [x().mul_2exp_u64(u64::MAX), x().div_2exp_u64(u64::MAX)] {
        let serialized = serde_json::to_string(&expression).unwrap();
        let restored: B = serde_json::from_str(&serialized).unwrap();
        assert_eq!(evaluate(&restored), evaluate(&expression));
        match restored.view() {
            ExprView::ScalePow2 { exponent, .. } => {
                assert_eq!(exponent.unsigned_abs(), u128::from(u64::MAX))
            },
            _ => panic!("expected scaling"),
        }
    }
}

#[test]
fn algebra_trait_matrix_remains_available() {
    fn algebra<A: Algebra<S>, S>() {}
    algebra::<B, F>();
    algebra::<E, F>();
    algebra::<E, B>();
    algebra::<E, EF>();
    algebra::<B, B>();
    algebra::<E, E>();
    let _: B = B::ZERO;
    let _: E = E::ONE;
    let values = [z(), z()];
    let mixed = <E as Algebra<B>>::mixed_dot_product(&values, &[x(), y()]);
    assert!(
        matches!(mixed.view(), ExprView::LinearCombination { coefficients, .. } if coefficients.iter().all(|value| matches!(value.view(), ExprView::Lift { .. })))
    );
    let literal = <E as Algebra<EF>>::mixed_dot_product(&values, &[EF::ONE, EF::TWO]);
    assert!(
        matches!(literal.view(), ExprView::LinearCombination { coefficients, .. } if coefficients.iter().all(|value| value.domain() == ExpressionDomain::Extension && matches!(value.view(), ExprView::BaseConstant(_))))
    );
    let _: [E; 2] = <E as Algebra<F>>::quadratic_extension_square(&values, F::new(7));
}

#[test]
fn wire_normalizes_constant_embeddings_after_validating_domains() {
    let c = F::new(7);
    let expected = E::from(c);
    let lift = serde_json::json!({
        "version": 2, "root": 1,
        "nodes": [
            { "domain": "Base", "op": { "BaseConstant": c } },
            { "domain": "Extension", "op": { "Lift": { "value": 0 } } }
        ]
    });
    let decoded: E = serde_json::from_value(lift.clone()).unwrap();
    assert_same_normal_form(&[expected.clone(), decoded]);
    let embedded = serde_json::json!({
        "version": 2, "root": 0,
        "nodes": [{ "domain": "Extension", "op": { "ExtensionConstant": EF::from(c) } }]
    });
    let decoded: E = serde_json::from_value(embedded.clone()).unwrap();
    assert_same_normal_form(&[expected.clone(), decoded]);

    let mut invalid_lift = lift;
    invalid_lift["nodes"][1]["domain"] = "Base".into();
    assert!(serde_json::from_value::<B>(invalid_lift).is_err());
    let mut invalid_embed = embedded;
    invalid_embed["nodes"][0]["domain"] = "Base".into();
    assert!(serde_json::from_value::<B>(invalid_embed).is_err());
    // A constant operation cannot erase an illegal extension-to-base edge.
    let invalid_binary = serde_json::json!({
        "version": 2, "root": 2,
        "nodes": [
            { "domain": "Base", "op": { "BaseConstant": F::ZERO } },
            { "domain": "Extension", "op": { "ExtensionConstant": EF::from(c) } },
            { "domain": "Base", "op": { "Add": { "x": 0, "y": 1 } } }
        ]
    });
    assert!(serde_json::from_value::<B>(invalid_binary).is_err());

    let expression = z() * c;
    let mut wire = serde_json::to_value(&expression).unwrap();
    let root = wire["root"].as_u64().unwrap() as usize;
    let scalar = wire["nodes"][root]["op"]["Mul"]["y"].as_u64().unwrap() as usize;
    wire["nodes"][scalar]["op"] = serde_json::json!({ "ExtensionConstant": EF::from(c) });
    let decoded: E = serde_json::from_value(wire).unwrap();
    assert_same_normal_form(&[expression, decoded]);
}

#[test]
fn wire_scalar_domains_cannot_bypass_typed_handles() {
    let expression = x() + F::new(3);
    let mut wire = serde_json::to_value(&expression).unwrap();
    let root = wire["root"].as_u64().unwrap() as usize;
    let scalar = wire["nodes"][root]["op"]["Add"]["y"].as_u64().unwrap() as usize;
    wire["nodes"][scalar]["domain"] = serde_json::json!("Extension");
    assert!(serde_json::from_value::<B>(wire).is_err());

    let expression = z() + EF::from(F::new(3));
    let mut wire = serde_json::to_value(&expression).unwrap();
    let root = wire["root"].as_u64().unwrap() as usize;
    let scalar = wire["nodes"][root]["op"]["Add"]["y"].as_u64().unwrap() as usize;
    wire["nodes"][scalar]["domain"] = serde_json::json!("Base");
    wire["nodes"][scalar]["op"] = serde_json::json!({ "BaseConstant": F::new(3) });
    assert!(serde_json::from_value::<E>(wire).is_err());

    let mut wire = serde_json::to_value(x()).unwrap();
    wire["nodes"][0]["degree_multiple"] = serde_json::json!(0);
    assert!(serde_json::from_value::<B>(wire).is_err());
}

#[test]
fn constant_aggregates_and_formal_identities_fold_before_emission() {
    for expression in [B::ZERO + x(), x() + B::ZERO, B::ONE * x(), x() * B::ONE] {
        assert!(matches!(expression.view(), ExprView::BaseInput(_)));
    }
    assert!(matches!((B::ZERO - x()).view(), ExprView::Neg { .. }));
    assert!(matches!((E::ZERO + x()).view(), ExprView::Lift { .. }));
    let values = [B::from_u64(2), B::from_u64(3)];
    for (expression, expected) in [
        (values.iter().cloned().sum::<B>(), 5),
        (values.iter().cloned().product::<B>(), 6),
        (B::dot_product(&values, &values), 13),
    ] {
        assert!(matches!(expression.view(), ExprView::BaseConstant(c) if *c == F::new(expected)));
    }
    let [c0, c1] = <B as Algebra<F>>::quadratic_extension_square(&values, F::new(7));
    assert!(matches!(c0.view(), ExprView::BaseConstant(c) if *c == F::new(67)));
    assert!(matches!(c1.view(), ExprView::BaseConstant(c) if *c == F::new(12)));
}
