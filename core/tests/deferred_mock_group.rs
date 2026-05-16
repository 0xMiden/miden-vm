//! End-to-end integration: two-app `PrecompileSchema` exercising the mint capability.
//!
//! Composes `Uint256` and `MockGroup<Uint256>` into a single schema, builds two group elements
//! from registered field leaves, evaluates `add` on them, and asserts the canonical references
//! freshly-minted field-leaf digests in the DAG. Also verifies the `eq` predicate against a
//! hand-built expected group element.

use miden_core::deferred::{
    App, DeferredState, Digest, MockGroup, Node, PrecompileSchema, Uint256,
};

type Group = MockGroup<Uint256>;

fn leaf(low: u64) -> Node {
    let mut limbs = [0u32; 8];
    limbs[0] = low as u32;
    limbs[1] = (low >> 32) as u32;
    Uint256::leaf_node(limbs)
}

fn schema_and_state() -> (PrecompileSchema, DeferredState) {
    let schema = PrecompileSchema::new([
        Box::new(Uint256) as Box<dyn App>,
        Box::new(Group::default()) as Box<dyn App>,
    ]);
    let mut state = DeferredState::new();
    schema.boot(&mut state);
    (schema, state)
}

fn register_group(
    schema: &PrecompileSchema,
    state: &mut DeferredState,
    x: u64,
    y: u64,
) -> Digest {
    let h_x = state.register(schema, leaf(x)).unwrap();
    let h_y = state.register(schema, leaf(y)).unwrap();
    state.register(schema, Group::combine_node(h_x, h_y)).unwrap()
}

#[test]
fn add_produces_minted_combine_and_passes_eq_against_expected() {
    let (schema, mut state) = schema_and_state();

    let h_g1 = register_group(&schema, &mut state, 3, 4);
    let h_g2 = register_group(&schema, &mut state, 10, 20);

    // Evaluate add: returns combine(h_x3_leaf, h_y3_leaf) where leaves are minted.
    let add_canonical = state.evaluate(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let expected = Group::combine_node(leaf(13).digest(), leaf(24).digest());
    assert_eq!(add_canonical, expected);

    // Both minted field leaves must be in the DAG.
    assert!(state.contains(&leaf(13).digest()));
    assert!(state.contains(&leaf(24).digest()));

    // Build expected group element via registration, then assert eq.
    let h_expected = register_group(&schema, &mut state, 13, 24);
    let h_add = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let eq_result = state.evaluate(&schema, Group::eq_node(h_add, h_expected)).unwrap();
    assert!(eq_result.is_true_node());
}

#[test]
fn sub_chains_through_add_with_mint_at_every_step() {
    let (schema, mut state) = schema_and_state();

    // ((g1 + g2) - g1)  should equal g2 under coord-wise mock arithmetic.
    let h_g1 = register_group(&schema, &mut state, 7, 11);
    let h_g2 = register_group(&schema, &mut state, 100, 200);

    let h_sum = state.register(&schema, Group::add_node(h_g1, h_g2)).unwrap();
    let h_diff = state.register(&schema, Group::sub_node(h_sum, h_g1)).unwrap();

    let canonical = state.evaluate(&schema, state.get(&h_diff).unwrap().clone()).unwrap();
    assert_eq!(canonical, Group::combine_node(leaf(100).digest(), leaf(200).digest()));
}

#[test]
fn combine_canonicalises_field_expression_children_end_to_end() {
    let (schema, mut state) = schema_and_state();
    // x as field expression leaf(3)+leaf(4), y as a plain leaf.
    use miden_core::deferred::Payload;
    let h_3 = state.register(&schema, leaf(3)).unwrap();
    let h_4 = state.register(&schema, leaf(4)).unwrap();
    let h_x_expr = state
        .register(&schema, Node::expression(Uint256::add_tag(), Payload::binary_op(h_3, h_4)))
        .unwrap();
    let h_y = state.register(&schema, leaf(5)).unwrap();
    let h_combine = state.register(&schema, Group::combine_node(h_x_expr, h_y)).unwrap();

    let canonical = state.evaluate(&schema, state.get(&h_combine).unwrap().clone()).unwrap();
    let expected = Group::combine_node(leaf(7).digest(), leaf(5).digest());
    assert_eq!(canonical, expected);
}
